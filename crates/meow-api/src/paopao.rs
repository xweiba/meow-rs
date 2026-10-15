//! PaoPao's config generation over the API (see `meow-paopao`):
//!
//! - `POST /paopao/parse`: a subscription body → `{nodes, skipped, split,
//!   usage}`, what the app's `paopao_parse` returns.
//! - `POST /paopao/build`: the app's build input (JSON) → `{config, pool,
//!   tree, rules, routePolicies}`, what `paopao_build` returns.
//! - `POST /paopao/fetch`: `{url, user_agent?, via?: "direct" | "proxy"}` →
//!   the subscription fetched and parsed: the parse result plus `status`,
//!   `final_url` and `content_disposition`; `usage` is the
//!   `subscription-userinfo` header's when it has one. `proxy` goes through
//!   this core's own `mixed-port` on loopback.
//!
//! None of it runs in the core. Each call runs this binary again as a
//! short-lived child (`meow paopao parse|build|fetch`, input on stdin,
//! the answer on stdout): what a parse or a build allocates is given back
//! when the child exits, and the core only pipes bytes. A small answer
//! (every error is one) is read whole and answered with the status the
//! child's exit code calls for; a big one can only be a success and is
//! streamed through as it comes, never held. At most [`SLOTS`] children
//! run at once; a call beyond that is refused (`503`), not queued.
//!
//! Errors are `{"error": "..."}`: `422` the input (or the subscription)
//! is not usable, `502` the subscription server could not be reached or
//! did not answer 200, `503` busy, `504` the child ran out of time, `500`
//! the child failed, `501` where the core runs inside an app (Android,
//! iOS) and has no binary to run.
//!
//! The core also keeps the subscriptions current itself ([`service`],
//! state on disk in [`store`]):
//!
//! - `PUT /paopao/input` (`?apply=true`: rebuilt and run now): the build
//!   input to keep → `{subscriptions}` (their count), with `apply` the
//!   job's report; `400` not a JSON object. `GET`: the input as kept
//!   (`404` none yet).
//! - `GET /paopao/subscriptions` (`?nodes=true`: the lines too): `{
//!   subscriptions: [{id, url, name, refreshed}] }`, `refreshed` the last
//!   refresh's record (`{via, checked, updated, usage, last_error,
//!   body_sha, node_count, skipped, …}`) or null.
//! - `POST /paopao/subscriptions/refresh` (`?id=`: that one): refreshes,
//!   merges, rebuilds and reloads → the job's report `{refreshed: [{id,
//!   error?}], input_changed, rebuilt, reloaded, error?}`; `409` no input
//!   yet, `404` no such subscription, `503` a job runs.
//! - `PUT /paopao/schedule` `{enabled?, minutes?}` (0 minutes = none; 720
//!   until set, off until enabled) and `GET` → `{enabled, minutes,
//!   last_run, next_run, last_error, running}`.

use axum::{
    body::{Body, Bytes},
    extract::{DefaultBodyLimit, Query, Request, State},
    http::{header, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Json, Response},
    routing::{get, post},
    Router,
};
use futures::StreamExt as _;
use serde_json::json;
use std::collections::HashMap;
use std::ffi::OsString;
use std::io;
use std::path::PathBuf;
use std::process::Stdio;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::process::{Child, ChildStdout};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio::time::{timeout_at, Instant};

pub mod service;
pub mod store;

pub use service::{run_schedule, JobError, Reload, Report, Service};

/// The child's exit codes: its answer is the result.
pub const EXIT_OK: i32 = 0;
/// The answer is `{"error": ...}` about the input (or the subscription's
/// content).
pub const EXIT_INVALID: i32 = 2;
/// The answer is `{"error": ...}`: the subscription server could not be
/// reached or did not answer 200.
pub const EXIT_UPSTREAM: i32 = 3;

/// Largest request body (a subscription, a build input).
pub const MAX_INPUT: usize = 16 * 1024 * 1024;
/// Largest answer a child may write.
pub const MAX_OUTPUT: usize = 64 * 1024 * 1024;
/// Children at once.
pub const SLOTS: usize = 2;
/// Time for a parse or a build.
const WORK_TIMEOUT: Duration = Duration::from_secs(30);
/// Time for a fetch: the child's own 30 s for the download, then the parse.
const FETCH_TIMEOUT: Duration = Duration::from_secs(45);
/// Answers up to this size are read whole before answering; anything
/// longer is streamed.
const HEAD: usize = 64 * 1024;
/// Read size while streaming.
const CHUNK: usize = 32 * 1024;
/// What is kept of a failed child's stderr.
const STDERR_KEEP: usize = 2048;

/// Runs `<program> <prefix…> paopao <op>` children, [`SLOTS`] at a time.
pub struct Runner {
    program: PathBuf,
    prefix: Vec<OsString>,
    slots: Arc<Semaphore>,
    max_output: usize,
}

/// What a child answered.
pub enum Output {
    /// The whole answer, with the child's exit code ([`EXIT_OK`],
    /// [`EXIT_INVALID`] or [`EXIT_UPSTREAM`]).
    Whole { code: i32, body: Vec<u8> },
    /// A long answer as it comes (the child exited 0 when it ends; an
    /// error item when the child failed, ran out of time or wrote too
    /// much — it has been killed then).
    Stream(futures::stream::BoxStream<'static, io::Result<Bytes>>),
}

/// Why a child gave no answer.
#[derive(Debug)]
pub enum RunError {
    /// [`SLOTS`] children are running.
    Busy,
    /// The child did not finish in time (killed).
    Timeout,
    /// The child wrote more than the cap (killed).
    TooLarge,
    /// The child could not start, or ended without an answer (crashed,
    /// an unknown exit code): what it said.
    Failed(String),
}

impl std::fmt::Display for RunError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Busy => f.write_str("another PaoPao job is running; try again shortly"),
            Self::Timeout => f.write_str("the PaoPao job ran out of time"),
            Self::TooLarge => f.write_str("the PaoPao job's answer is too large"),
            Self::Failed(why) => write!(f, "the PaoPao job failed: {why}"),
        }
    }
}

impl Runner {
    /// Children of `program` (`program paopao <op>`).
    pub fn new(program: impl Into<PathBuf>) -> Self {
        Self {
            program: program.into(),
            prefix: Vec::new(),
            slots: Arc::new(Semaphore::new(SLOTS)),
            max_output: MAX_OUTPUT,
        }
    }

    /// Children of this binary; None where the core runs inside an app
    /// (Android, iOS: the process is the app's, with no `paopao`
    /// subcommand). On Linux `/proc/self/exe`, which still runs this
    /// binary after an update replaced the file.
    pub fn current_exe() -> Option<Self> {
        if cfg!(any(target_os = "android", target_os = "ios")) {
            return None;
        }
        if cfg!(target_os = "linux") {
            return Some(Self::new("/proc/self/exe"));
        }
        std::env::current_exe().ok().map(Self::new)
    }

    /// Arguments before `paopao <op>` (tests run a shell).
    pub fn with_prefix(mut self, prefix: impl IntoIterator<Item = impl Into<OsString>>) -> Self {
        self.prefix = prefix.into_iter().map(Into::into).collect();
        self
    }

    /// The answer cap instead of [`MAX_OUTPUT`].
    pub fn with_max_output(mut self, max_output: usize) -> Self {
        self.max_output = max_output;
        self
    }

    /// Runs `paopao <op>` with `input` on its stdin; killed after `limit`
    /// (streaming included), or when the answer passes the cap or is
    /// dropped. Refused at once when [`SLOTS`] children run.
    pub async fn run(&self, op: &str, input: Bytes, limit: Duration) -> Result<Output, RunError> {
        let permit = Arc::clone(&self.slots)
            .try_acquire_owned()
            .map_err(|_| RunError::Busy)?;
        self.run_with(permit, op, input, limit).await
    }

    /// [`Self::run`], waiting for a free slot instead (the core's own
    /// jobs: a request answered meanwhile is no reason to fail).
    pub async fn run_queued(
        &self,
        op: &str,
        input: Bytes,
        limit: Duration,
    ) -> Result<Output, RunError> {
        let permit = Arc::clone(&self.slots)
            .acquire_owned()
            .await
            .map_err(|_| RunError::Busy)?;
        self.run_with(permit, op, input, limit).await
    }

    async fn run_with(
        &self,
        permit: OwnedSemaphorePermit,
        op: &str,
        input: Bytes,
        limit: Duration,
    ) -> Result<Output, RunError> {
        let deadline = Instant::now() + limit;
        let mut command = tokio::process::Command::new(&self.program);
        command
            .args(&self.prefix)
            .arg("paopao")
            .arg(op)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true);
        // A core without a console (started by the app) must not open one
        // for its child.
        #[cfg(windows)]
        command.creation_flags(0x0800_0000); // CREATE_NO_WINDOW
        let mut child = command.spawn().map_err(|e| {
            RunError::Failed(format!("cannot start {}: {e}", self.program.display()))
        })?;
        let (Some(mut stdin), Some(mut stdout), Some(stderr)) =
            (child.stdin.take(), child.stdout.take(), child.stderr.take())
        else {
            return Err(RunError::Failed("no pipes to the child".into()));
        };
        // Fed beside the reading, so a child that answers before it has
        // read everything cannot stall on a full pipe. A child that does
        // not read at all fails the write; it is judged by its exit.
        tokio::spawn(async move {
            let _ = stdin.write_all(&input).await;
        });
        let stderr = tokio::spawn(keep_head(stderr, STDERR_KEEP));

        let mut head = Vec::new();
        let eof = match timeout_at(deadline, read_head(&mut stdout, &mut head)).await {
            Err(_) => return Err(RunError::Timeout),
            Ok(Err(e)) => return Err(RunError::Failed(format!("reading its answer: {e}"))),
            Ok(Ok(eof)) => eof,
        };
        if head.len() > self.max_output {
            return Err(RunError::TooLarge);
        }
        if eof {
            let code = exit_code(&mut child, deadline, stderr).await?;
            return Ok(Output::Whole { code, body: head });
        }
        let job = Job {
            child,
            stdout,
            stderr,
            deadline,
            left: self.max_output - head.len(),
            _permit: permit,
        };
        let rest = futures::stream::try_unfold(job, Job::next);
        let first = futures::stream::once(async move { Ok(Bytes::from(head)) });
        Ok(Output::Stream(first.chain(rest).boxed()))
    }
}

/// A child whose answer is being streamed; dropping it kills the child.
struct Job {
    child: Child,
    stdout: ChildStdout,
    stderr: tokio::task::JoinHandle<String>,
    deadline: Instant,
    left: usize,
    _permit: OwnedSemaphorePermit,
}

impl Job {
    async fn next(mut self) -> io::Result<Option<(Bytes, Self)>> {
        let mut buf = vec![0u8; CHUNK];
        let n = match timeout_at(self.deadline, self.stdout.read(&mut buf)).await {
            Err(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    RunError::Timeout.to_string(),
                ))
            }
            Ok(r) => r?,
        };
        if n == 0 {
            return match exit_code(&mut self.child, self.deadline, self.stderr).await {
                Ok(EXIT_OK) => Ok(None),
                Ok(code) => Err(io::Error::other(format!("the PaoPao job exited {code}"))),
                Err(e) => Err(io::Error::other(e.to_string())),
            };
        }
        if n > self.left {
            return Err(io::Error::other(RunError::TooLarge.to_string()));
        }
        self.left -= n;
        buf.truncate(n);
        Ok(Some((Bytes::from(buf), self)))
    }
}

/// Reads up to [`HEAD`] bytes (one read past it to tell a longer answer);
/// true at the end of the answer.
async fn read_head(stdout: &mut ChildStdout, head: &mut Vec<u8>) -> io::Result<bool> {
    let mut buf = [0u8; 8192];
    while head.len() <= HEAD {
        let n = stdout.read(&mut buf).await?;
        if n == 0 {
            return Ok(true);
        }
        head.extend_from_slice(&buf[..n]);
    }
    Ok(false)
}

/// The first `keep` bytes of `r` as text; the rest is drained so the child
/// never blocks on it.
async fn keep_head(mut r: impl AsyncRead + Unpin, keep: usize) -> String {
    let mut kept = Vec::new();
    let mut buf = [0u8; 1024];
    while let Ok(n) = r.read(&mut buf).await {
        if n == 0 {
            break;
        }
        let room = keep.saturating_sub(kept.len()).min(n);
        kept.extend_from_slice(&buf[..room]);
    }
    String::from_utf8_lossy(&kept).trim().to_owned()
}

/// The child's exit code when it is one of the answer codes; otherwise
/// what it said on stderr. Killed when it does not exit by `deadline`.
async fn exit_code(
    child: &mut Child,
    deadline: Instant,
    stderr: tokio::task::JoinHandle<String>,
) -> Result<i32, RunError> {
    let status = match timeout_at(deadline, child.wait()).await {
        Err(_) => {
            let _ = child.start_kill();
            return Err(RunError::Timeout);
        }
        Ok(r) => r.map_err(|e| RunError::Failed(e.to_string()))?,
    };
    match status.code() {
        Some(code @ (EXIT_OK | EXIT_INVALID | EXIT_UPSTREAM)) => Ok(code),
        _ => {
            let said = stderr.await.unwrap_or_default();
            Err(RunError::Failed(if said.is_empty() {
                status.to_string()
            } else {
                format!("{status}: {said}")
            }))
        }
    }
}

type PaoPao = Arc<Service>;

/// The routes over `service` (without a runner every child's call answers
/// `501`). Closed to other web pages like 签到助手's routes.
pub fn router<S: Clone + Send + Sync + 'static>(service: Arc<Service>) -> Router<S> {
    Router::new()
        .route("/paopao/parse", post(parse))
        .route("/paopao/build", post(build))
        .route("/paopao/fetch", post(fetch))
        .route("/paopao/input", get(get_input).put(put_input))
        .route("/paopao/subscriptions", get(subscriptions))
        .route("/paopao/subscriptions/refresh", post(refresh))
        .route("/paopao/schedule", get(get_schedule).put(put_schedule))
        .with_state(service)
        .layer(DefaultBodyLimit::max(MAX_INPUT))
        .layer(middleware::from_fn(same_origin_only))
}

/// Refuses what a browser says comes from another web page
/// ([`crate::checkin::from_other_page`]): a fetch from here reaches
/// whatever this machine can.
async fn same_origin_only(req: Request, next: Next) -> Response {
    if crate::checkin::from_other_page(&req) {
        return refuse(StatusCode::FORBIDDEN, "not accepted from another web page");
    }
    next.run(req).await
}

fn refuse(status: StatusCode, error: impl std::fmt::Display) -> Response {
    (status, Json(json!({ "error": error.to_string() }))).into_response()
}

async fn parse(State(p): State<PaoPao>, body: Bytes) -> Response {
    answer(&p, "parse", body, WORK_TIMEOUT).await
}

async fn build(State(p): State<PaoPao>, body: Bytes) -> Response {
    answer(&p, "build", body, WORK_TIMEOUT).await
}

#[derive(serde::Deserialize)]
struct FetchRequest {
    url: String,
    #[serde(default)]
    user_agent: Option<String>,
    #[serde(default)]
    via: Option<String>,
}

async fn fetch(State(p): State<PaoPao>, body: Bytes) -> Response {
    let req: FetchRequest = match serde_json::from_slice(&body) {
        Ok(req) => req,
        Err(e) => return refuse(StatusCode::BAD_REQUEST, format!("bad fetch request: {e}")),
    };
    let proxy = match req.via.as_deref().unwrap_or("direct") {
        "direct" => None,
        "proxy" => match p.raw_config.read().mixed_port.filter(|&port| port != 0) {
            Some(port) => Some(format!("127.0.0.1:{port}")),
            None => {
                return refuse(
                    StatusCode::CONFLICT,
                    "the core has no mixed-port to fetch through",
                )
            }
        },
        other => {
            return refuse(
                StatusCode::BAD_REQUEST,
                format!("via must be \"direct\" or \"proxy\", not {other:?}"),
            )
        }
    };
    let input = json!({ "url": req.url, "user_agent": req.user_agent, "proxy": proxy });
    answer(&p, "fetch", Bytes::from(input.to_string()), FETCH_TIMEOUT).await
}

async fn answer(p: &PaoPao, op: &str, input: Bytes, limit: Duration) -> Response {
    let Some(runner) = &p.runner else {
        return refuse(
            StatusCode::NOT_IMPLEMENTED,
            "not available where the core runs inside an app",
        );
    };
    match runner.run(op, input, limit).await {
        Ok(Output::Whole { code, body }) => {
            let status = match code {
                EXIT_OK => StatusCode::OK,
                EXIT_UPSTREAM => StatusCode::BAD_GATEWAY,
                _ => StatusCode::UNPROCESSABLE_ENTITY,
            };
            let whole = futures::stream::once(async move { Ok(Bytes::from(body)) });
            json_body(status, giving_back(whole.boxed()))
        }
        Ok(Output::Stream(stream)) => json_body(StatusCode::OK, giving_back(stream)),
        Err(e) => {
            let status = match e {
                RunError::Busy => StatusCode::SERVICE_UNAVAILABLE,
                RunError::Timeout => StatusCode::GATEWAY_TIMEOUT,
                RunError::TooLarge | RunError::Failed(_) => StatusCode::INTERNAL_SERVER_ERROR,
            };
            if let RunError::Failed(why) = &e {
                tracing::warn!("paopao {op}: {why}");
            }
            refuse(status, e)
        }
    }
}

/// `?name=true` (or `1`).
fn flag(q: &HashMap<String, String>, name: &str) -> bool {
    q.get(name).is_some_and(|v| v == "true" || v == "1")
}

fn job_refusal(e: JobError) -> Response {
    let status = match e {
        JobError::Busy => StatusCode::SERVICE_UNAVAILABLE,
        JobError::Unavailable => StatusCode::NOT_IMPLEMENTED,
        JobError::NoInput => StatusCode::CONFLICT,
        JobError::UnknownId => StatusCode::NOT_FOUND,
        JobError::Invalid(_) => StatusCode::BAD_REQUEST,
        JobError::Failed(_) => StatusCode::INTERNAL_SERVER_ERROR,
    };
    refuse(status, e)
}

async fn put_input(
    State(p): State<PaoPao>,
    Query(q): Query<HashMap<String, String>>,
    body: Bytes,
) -> Response {
    let n = match p.store_input(body).await {
        Ok(n) => n,
        Err(e) => return job_refusal(e),
    };
    give_back();
    if !flag(&q, "apply") {
        return Json(json!({ "subscriptions": n })).into_response();
    }
    match p.apply().await {
        Ok(report) => Json(json!({ "subscriptions": n, "apply": report })).into_response(),
        Err(e) => job_refusal(e),
    }
}

async fn get_input(State(p): State<PaoPao>) -> Response {
    match tokio::fs::File::open(p.store().input()).await {
        Ok(f) => json_body(StatusCode::OK, giving_back(file_stream(f))),
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            refuse(StatusCode::NOT_FOUND, JobError::NoInput)
        }
        Err(e) => refuse(StatusCode::INTERNAL_SERVER_ERROR, e),
    }
}

/// `f` read as it is sent.
fn file_stream(f: tokio::fs::File) -> futures::stream::BoxStream<'static, io::Result<Bytes>> {
    futures::stream::try_unfold(f, |mut f| async move {
        let mut buf = vec![0u8; CHUNK];
        let n = f.read(&mut buf).await?;
        if n == 0 {
            return Ok(None);
        }
        buf.truncate(n);
        Ok(Some((Bytes::from(buf), f)))
    })
    .boxed()
}

async fn subscriptions(
    State(p): State<PaoPao>,
    Query(q): Query<HashMap<String, String>>,
) -> Response {
    let head = match p.input_head().await {
        Ok(head) => head,
        Err(JobError::NoInput) => store::InputHead::default(),
        Err(e) => return job_refusal(e),
    };
    let store = p.store().clone();
    let nodes = flag(&q, "nodes");
    match tokio::task::spawn_blocking(move || listing(&store, &head, nodes)).await {
        Ok(body) => {
            let whole = futures::stream::once(async move { Ok(Bytes::from(body)) });
            json_body(StatusCode::OK, giving_back(whole.boxed()))
        }
        Err(e) => refuse(StatusCode::INTERNAL_SERVER_ERROR, e),
    }
}

/// `{"subscriptions": [{id, url, name, refreshed}]}`: `refreshed` the
/// record as it is with `nodes`, else its status alone; null without one.
fn listing(store: &store::Store, head: &store::InputHead, nodes: bool) -> Vec<u8> {
    let mut out = b"{\"subscriptions\":[".to_vec();
    for (i, s) in head.subscriptions.iter().enumerate() {
        if i > 0 {
            out.push(b',');
        }
        let mut entry = json!({ "id": s.id, "url": s.url, "name": s.name }).to_string();
        entry.pop();
        out.extend_from_slice(entry.as_bytes());
        out.extend_from_slice(b",\"refreshed\":");
        let record = std::fs::read(store.subscription(&s.id)).ok();
        let status = record
            .as_deref()
            .and_then(|b| serde_json::from_slice::<store::SubStatus>(b).ok())
            .filter(|st| st.id == s.id);
        match (record, status) {
            (Some(bytes), Some(_)) if nodes => out.extend_from_slice(&bytes),
            (_, Some(st)) => out.extend_from_slice(json!(st).to_string().as_bytes()),
            _ => out.extend_from_slice(b"null"),
        }
        out.push(b'}');
    }
    out.extend_from_slice(b"]}");
    out
}

async fn refresh(State(p): State<PaoPao>, Query(q): Query<HashMap<String, String>>) -> Response {
    match p.refresh(q.get("id").map(String::as_str)).await {
        Ok(report) => Json(report).into_response(),
        Err(e) => job_refusal(e),
    }
}

#[derive(serde::Deserialize)]
struct ScheduleBody {
    #[serde(default)]
    enabled: Option<bool>,
    #[serde(default)]
    minutes: Option<u32>,
}

async fn put_schedule(State(p): State<PaoPao>, body: Bytes) -> Response {
    let b: ScheduleBody = match serde_json::from_slice(&body) {
        Ok(b) => b,
        Err(e) => return refuse(StatusCode::BAD_REQUEST, format!("bad schedule: {e}")),
    };
    match p.set_schedule(b.enabled, b.minutes).await {
        Ok(s) => schedule_answer(&p, &s),
        Err(e) => refuse(StatusCode::INTERNAL_SERVER_ERROR, e),
    }
}

async fn get_schedule(State(p): State<PaoPao>) -> Response {
    let s = p.schedule().await;
    schedule_answer(&p, &s)
}

fn schedule_answer(p: &Service, s: &store::Schedule) -> Response {
    Json(json!({
        "enabled": s.enabled,
        "minutes": s.minutes,
        "last_run": s.last_run,
        "next_run": p.next_run(s),
        "last_error": s.last_error,
        "running": p.running(),
        // False where the core runs inside an app: nothing runs then.
        "available": p.can_run(),
    }))
    .into_response()
}

/// `answer` as a body that, once sent (or dropped), hands what the
/// request and the answer's buffers left free in the allocator back to
/// the system: glibc keeps freed memory in each worker thread's arena,
/// about a megabyte that would otherwise stay resident after a call.
fn giving_back(answer: futures::stream::BoxStream<'static, io::Result<Bytes>>) -> Body {
    struct GiveBack;
    impl Drop for GiveBack {
        fn drop(&mut self) {
            give_back();
        }
    }
    let guard = GiveBack;
    Body::from_stream(answer.chain(futures::stream::poll_fn(move |_| {
        let _held = &guard;
        std::task::Poll::Ready(None)
    })))
}

/// Hands what the allocator holds free back to the system (glibc keeps
/// freed memory in each thread's arena).
pub(crate) fn give_back() {
    #[cfg(all(target_os = "linux", target_env = "gnu"))]
    // SAFETY: no arguments to get wrong; only returns free memory.
    unsafe {
        libc::malloc_trim(0);
    }
}

/// The child's answer as it is: already JSON.
fn json_body(status: StatusCode, body: Body) -> Response {
    (status, [(header::CONTENT_TYPE, "application/json")], body).into_response()
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use meow_config::raw::RawConfig;
    use parking_lot::RwLock;
    use tower::ServiceExt as _;

    /// A runner whose child is `sh -c script` (`$1` = `paopao`, `$2` =
    /// the op).
    fn sh(script: &str) -> Runner {
        Runner::new("sh").with_prefix(["-c", script, "sh"])
    }

    async fn collect(out: Output) -> Result<(i32, Vec<u8>), String> {
        match out {
            Output::Whole { code, body } => Ok((code, body)),
            Output::Stream(mut s) => {
                let mut all = Vec::new();
                while let Some(item) = s.next().await {
                    all.extend_from_slice(&item.map_err(|e| e.to_string())?);
                }
                Ok((EXIT_OK, all))
            }
        }
    }

    #[tokio::test]
    async fn pipes_stdin_to_stdout_with_the_exit_code() {
        let r = sh(r#"[ "$1 $2" = "paopao parse" ] || exit 9; cat; exit 2"#);
        let out = r.run(
            "parse",
            Bytes::from_static(b"{\"error\":\"x\"}"),
            WORK_TIMEOUT,
        );
        let (code, body) = collect(out.await.unwrap()).await.unwrap();
        assert_eq!(code, EXIT_INVALID);
        assert_eq!(body, b"{\"error\":\"x\"}");
    }

    #[tokio::test]
    async fn a_long_answer_streams_through_whole() {
        let r = sh("head -c 300000 /dev/zero");
        let out = r.run("build", Bytes::new(), WORK_TIMEOUT).await.unwrap();
        assert!(matches!(out, Output::Stream(_)));
        let (_, body) = collect(out).await.unwrap();
        assert_eq!(body.len(), 300_000);
    }

    #[tokio::test]
    async fn a_crash_is_a_failure_with_what_it_said() {
        let r = sh("echo boom >&2; exit 7");
        match r.run("parse", Bytes::new(), WORK_TIMEOUT).await {
            Err(RunError::Failed(why)) => assert!(why.contains("boom"), "{why}"),
            _ => panic!("expected a failure"),
        }
    }

    /// The child's pid, written by the script to `file`, and whether it
    /// still runs.
    fn alive(file: &std::path::Path) -> bool {
        let pid = std::fs::read_to_string(file).unwrap();
        // SAFETY: signal 0 only checks the process exists.
        unsafe { libc::kill(pid.trim().parse().unwrap(), 0) == 0 }
    }

    async fn gone(file: &std::path::Path) -> bool {
        for _ in 0..100 {
            if !alive(file) {
                return true;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        false
    }

    #[tokio::test]
    async fn the_timeout_kills_the_child() {
        let dir = tempfile::tempdir().unwrap();
        let pid = dir.path().join("pid");
        let r = sh(&format!("echo $$ > {}; exec sleep 30", pid.display()));
        let started = Instant::now();
        let out = r
            .run("parse", Bytes::new(), Duration::from_millis(300))
            .await;
        assert!(matches!(out, Err(RunError::Timeout)));
        assert!(started.elapsed() < Duration::from_secs(5));
        assert!(gone(&pid).await, "the child still runs");
    }

    #[tokio::test]
    async fn the_timeout_kills_a_streaming_child() {
        let dir = tempfile::tempdir().unwrap();
        let pid = dir.path().join("pid");
        let r = sh(&format!(
            "echo $$ > {}; head -c 100000 /dev/zero; exec sleep 30",
            pid.display()
        ));
        let out = r
            .run("parse", Bytes::new(), Duration::from_millis(500))
            .await;
        let err = collect(out.unwrap()).await.unwrap_err();
        assert!(err.contains("ran out of time"), "{err}");
        assert!(gone(&pid).await, "the child still runs");
    }

    #[tokio::test]
    async fn the_output_cap_kills_the_child() {
        let r = sh("head -c 1000 /dev/zero").with_max_output(500);
        assert!(matches!(
            r.run("parse", Bytes::new(), WORK_TIMEOUT).await,
            Err(RunError::TooLarge)
        ));
        let r = sh("head -c 1000000 /dev/zero").with_max_output(200_000);
        let out = r.run("parse", Bytes::new(), WORK_TIMEOUT).await.unwrap();
        let err = collect(out).await.unwrap_err();
        assert!(err.contains("too large"), "{err}");
    }

    async fn call(app: Router, path: &str, body: &'static str) -> (StatusCode, Value) {
        let req = axum::http::Request::post(path)
            .body(Body::from(body))
            .unwrap();
        let res = app.oneshot(req).await.unwrap();
        let status = res.status();
        let bytes = axum::body::to_bytes(res.into_body(), usize::MAX)
            .await
            .unwrap();
        (
            status,
            serde_json::from_slice(&bytes).unwrap_or(Value::Null),
        )
    }

    use serde_json::Value;

    /// A reload that is never asked for.
    fn no_reload() -> Reload {
        Arc::new(|_| Box::pin(async { Err("not expected".to_owned()) }))
    }

    /// A service over `runner` and `raw`, its store in a directory gone
    /// with the test process.
    fn service(runner: Option<Arc<Runner>>, raw: RawConfig) -> Arc<Service> {
        let dir = tempfile::tempdir().unwrap().keep();
        Arc::new(Service::new(
            runner,
            Arc::new(RwLock::new(raw)),
            dir,
            None,
            no_reload(),
        ))
    }

    fn app(runner: Option<Runner>, raw: RawConfig) -> Router {
        router(service(runner.map(Arc::new), raw))
    }

    #[tokio::test]
    async fn busy_answers_503_without_queueing() {
        let runner = Arc::new(sh("sleep 2; echo '{}'"));
        let app: Router = router(service(Some(Arc::clone(&runner)), RawConfig::default()));
        let slow: Vec<_> = (0..SLOTS)
            .map(|_| tokio::spawn(call(app.clone(), "/paopao/parse", "x")))
            .collect();
        tokio::time::sleep(Duration::from_millis(300)).await;
        let started = Instant::now();
        let (status, body) = call(app.clone(), "/paopao/build", "{}").await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert!(body["error"].is_string());
        assert!(started.elapsed() < Duration::from_secs(1));
        for s in slow {
            assert_eq!(s.await.unwrap().0, StatusCode::OK);
        }
    }

    #[tokio::test]
    async fn statuses_follow_the_childs_exit() {
        let r = || {
            Some(sh(
                r#"echo '{"error":"e"}'; case $2 in parse) exit 2;; fetch) exit 3;; esac"#,
            ))
        };
        let raw = || RawConfig::default();
        let (s, body) = call(app(r(), raw()), "/paopao/parse", "x").await;
        assert_eq!(
            (s, body["error"].as_str()),
            (StatusCode::UNPROCESSABLE_ENTITY, Some("e"))
        );
        let (s, _) = call(app(r(), raw()), "/paopao/build", "{}").await;
        assert_eq!(s, StatusCode::OK);
        let (s, _) = call(app(r(), raw()), "/paopao/fetch", r#"{"url":"http://x/"}"#).await;
        assert_eq!(s, StatusCode::BAD_GATEWAY);
    }

    #[tokio::test]
    async fn fetch_hands_the_child_the_mixed_port() {
        let echo = || Some(sh("cat"));
        let raw = RawConfig {
            mixed_port: Some(7890),
            ..RawConfig::default()
        };
        let req = r#"{"url":"http://x/","user_agent":"ua","via":"proxy"}"#;
        let (s, body) = call(app(echo(), raw), "/paopao/fetch", req).await;
        assert_eq!(s, StatusCode::OK);
        assert_eq!(
            body,
            json!({"url": "http://x/", "user_agent": "ua", "proxy": "127.0.0.1:7890"})
        );
        let (s, body) = call(
            app(echo(), RawConfig::default()),
            "/paopao/fetch",
            r#"{"url":"http://x/"}"#,
        )
        .await;
        assert_eq!(s, StatusCode::OK);
        assert_eq!(body["proxy"], Value::Null);

        let req = r#"{"url":"http://x/","via":"proxy"}"#;
        let (s, _) = call(app(echo(), RawConfig::default()), "/paopao/fetch", req).await;
        assert_eq!(s, StatusCode::CONFLICT);
        let req = r#"{"url":"http://x/","via":"tor"}"#;
        let (s, _) = call(app(echo(), RawConfig::default()), "/paopao/fetch", req).await;
        assert_eq!(s, StatusCode::BAD_REQUEST);
        let (s, _) = call(app(echo(), RawConfig::default()), "/paopao/fetch", "{}").await;
        assert_eq!(s, StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn a_missing_runner_and_a_crash_have_their_statuses() {
        let (s, body) = call(app(None, RawConfig::default()), "/paopao/parse", "x").await;
        assert_eq!(s, StatusCode::NOT_IMPLEMENTED);
        assert!(body["error"].is_string());
        let (s, _) = call(
            app(Some(sh("exit 7")), RawConfig::default()),
            "/paopao/parse",
            "x",
        )
        .await;
        assert_eq!(s, StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[tokio::test]
    async fn other_web_pages_are_refused() {
        let req = axum::http::Request::post("/paopao/parse")
            .header(header::ORIGIN, "https://evil.example")
            .header(header::HOST, "127.0.0.1:9090")
            .body(Body::from("x"))
            .unwrap();
        let res = app(Some(sh("cat")), RawConfig::default())
            .oneshot(req)
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::FORBIDDEN);
    }
}
