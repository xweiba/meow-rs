//! The core keeping PaoPao's subscriptions current by itself: the build
//! input it was handed ([`super::store`]), refreshed on a schedule or when
//! asked, rebuilt and run when that changed anything — with or without the
//! app.
//!
//! One job at a time ([`Service::refresh`], [`Service::apply`]); a second
//! is refused, not queued. A refresh runs `meow paopao refresh` children
//! one subscription after another (each downloads directly, then through
//! this core's `mixed-port` when that gets no answer, and writes the
//! subscription's record), then one `meow paopao apply` that merges the
//! records into `input.json` as the app would and, when the lines changed,
//! builds the config and writes it beside the running one when it differs.
//! The core then runs it the way `PUT /configs` runs a config ([`Reload`]);
//! only once that succeeded does it replace the config file. Anything
//! failing leaves the running config and its file as they were; a
//! subscription's problem is kept in its record, a build's or reload's in
//! the job's report and `schedule.json`.
//!
//! The scheduler ([`run_schedule`]) is one task asleep until the next run,
//! holding only the schedule's few numbers; it starts working only once
//! told to (`PUT /paopao/schedule`).

use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use axum::body::Bytes;
use futures::future::BoxFuture;
use meow_config::raw::RawConfig;
use parking_lot::RwLock;
use serde::Serialize;
use serde_json::{json, Value};
use tokio::sync::{Mutex, Notify};

use super::store::{InputHead, Schedule, Store, SubHead};
use super::{Output, Runner, EXIT_OK};

/// Time for one subscription: up to four downloads (directly, through the
/// core, each once more with a last `/`) of 30 s each, and the parse.
const REFRESH_TIMEOUT: Duration = Duration::from_secs(150);
/// Time for merging and building.
const APPLY_TIMEOUT: Duration = Duration::from_secs(60);
/// The scheduler looks at the clock again at least this often (a suspend,
/// the clock set).
const MAX_NAP: Duration = Duration::from_secs(3600);

/// Runs the config file at the path as the running config (`PUT /configs`
/// with `path`); the reason when the core refuses it.
pub type Reload = Arc<dyn Fn(PathBuf) -> BoxFuture<'static, Result<(), String>> + Send + Sync>;

/// PaoPao's jobs over the store.
pub struct Service {
    pub(super) runner: Option<Arc<Runner>>,
    pub(super) raw_config: Arc<RwLock<RawConfig>>,
    store: Store,
    /// The file the core runs from; None when it was given its config
    /// as a string.
    config_path: Option<PathBuf>,
    reload: Reload,
    /// Held through a whole job.
    job: Mutex<()>,
    /// Held while `input.json` is written.
    input: Mutex<()>,
    /// The schedule changed.
    wake: Notify,
    /// A schedule minute (tests make it shorter).
    minute: Duration,
}

/// Why a job did not run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JobError {
    /// Another job runs.
    Busy,
    /// No children here (the core inside an app).
    Unavailable,
    /// Nothing handed over yet.
    NoInput,
    /// No such subscription in the input.
    UnknownId,
    /// What was handed over is no build input.
    Invalid(String),
    /// The stored input could not be read.
    Failed(String),
}

impl std::fmt::Display for JobError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Busy => f.write_str("a PaoPao refresh or rebuild is running"),
            Self::Unavailable => f.write_str("not available where the core runs inside an app"),
            Self::NoInput => f.write_str("no build input has been handed over yet"),
            Self::UnknownId => f.write_str("no such subscription"),
            Self::Invalid(why) | Self::Failed(why) => f.write_str(why),
        }
    }
}

/// What a job did.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct Report {
    /// Each subscription refreshed, with its problem.
    pub refreshed: Vec<Refreshed>,
    /// `input.json` changed (lines, or only a problem shown).
    pub input_changed: bool,
    /// A config was built.
    pub rebuilt: bool,
    /// The core runs a new config.
    pub reloaded: bool,
    /// Why the build or the reload did not happen; the running config is
    /// as it was.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Refreshed {
    pub id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_millis()).unwrap_or(i64::MAX))
}

impl Service {
    /// Jobs over the store in `dir`, run by `runner` (None: none run);
    /// `raw_config` gives the `mixed-port` a refresh falls back to,
    /// `config_path` the file a new config replaces once `reload` ran it.
    pub fn new(
        runner: Option<Arc<Runner>>,
        raw_config: Arc<RwLock<RawConfig>>,
        dir: impl Into<PathBuf>,
        config_path: Option<PathBuf>,
        reload: Reload,
    ) -> Self {
        Self {
            runner,
            raw_config,
            store: Store::new(dir),
            config_path,
            reload,
            job: Mutex::new(()),
            input: Mutex::new(()),
            wake: Notify::new(),
            minute: Duration::from_secs(60),
        }
    }

    /// A schedule minute of `minute` instead (tests).
    pub fn with_minute(mut self, minute: Duration) -> Self {
        self.minute = minute;
        self
    }

    pub fn store(&self) -> &Store {
        &self.store
    }

    /// Jobs can run here.
    pub fn can_run(&self) -> bool {
        self.runner.is_some()
    }

    /// A job runs now.
    pub fn running(&self) -> bool {
        self.job.try_lock().is_err()
    }

    fn minute_ms(&self) -> i64 {
        i64::try_from(self.minute.as_millis()).unwrap_or(i64::MAX)
    }

    /// Keeps `body` as the build input: checked to be one, written whole,
    /// the records of subscriptions it no longer has removed. Its
    /// subscriptions' count.
    pub async fn store_input(&self, body: Bytes) -> Result<usize, JobError> {
        let head = InputHead::parse(&body).map_err(JobError::Invalid)?;
        let _input = self.input.lock().await;
        let store = self.store.clone();
        tokio::task::spawn_blocking(move || {
            super::store::write_atomic(&store.input(), &body, true)
                .map_err(|e| JobError::Failed(format!("cannot keep the build input: {e}")))?;
            let keep: std::collections::HashSet<String> = head
                .subscriptions
                .iter()
                .map(|s| format!("{}.json", super::store::file_name_for(&s.id)))
                .collect();
            if let Ok(dir) = std::fs::read_dir(store.subscriptions()) {
                for e in dir.flatten() {
                    let name = e.file_name().to_string_lossy().into_owned();
                    if name.ends_with(".json") && !keep.contains(&name) {
                        let _ = std::fs::remove_file(e.path());
                    }
                }
            }
            Ok(head.subscriptions.len())
        })
        .await
        .map_err(|e| JobError::Failed(e.to_string()))?
    }

    /// The stored input's subscriptions.
    pub async fn input_head(&self) -> Result<InputHead, JobError> {
        match tokio::fs::read(self.store.input()).await {
            Ok(bytes) => InputHead::parse(&bytes).map_err(JobError::Failed),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Err(JobError::NoInput),
            Err(e) => Err(JobError::Failed(format!(
                "cannot read the build input: {e}"
            ))),
        }
    }

    pub async fn schedule(&self) -> Schedule {
        let store = self.store.clone();
        tokio::task::spawn_blocking(move || Schedule::read(&store))
            .await
            .unwrap_or_default()
    }

    /// Sets the schedule (`None`: as it is) and wakes the scheduler.
    pub async fn set_schedule(
        &self,
        enabled: Option<bool>,
        minutes: Option<u32>,
    ) -> Result<Schedule, String> {
        let mut s = self.schedule().await;
        if let Some(e) = enabled {
            s.enabled = e;
        }
        if let Some(m) = minutes {
            s.minutes = m;
        }
        let store = self.store.clone();
        let written = s.clone();
        tokio::task::spawn_blocking(move || written.write(&store))
            .await
            .map_err(|e| e.to_string())?
            .map_err(|e| format!("cannot keep the schedule: {e}"))?;
        self.wake.notify_one();
        Ok(s)
    }

    /// The next scheduled run, Unix ms; None while off.
    pub fn next_run(&self, s: &Schedule) -> Option<i64> {
        s.next_run(now_ms(), self.minute_ms())
    }

    /// Refreshes the input's subscriptions (`only`: that one), one at a
    /// time, then merges, rebuilds and reloads as described above. A
    /// refresh of all of them counts as the schedule's run.
    pub async fn refresh(&self, only: Option<&str>) -> Result<Report, JobError> {
        let runner = self.runner.clone().ok_or(JobError::Unavailable)?;
        let _job = self.job.try_lock().map_err(|_| JobError::Busy)?;
        let mut subs = self.input_head().await?.subscriptions;
        if let Some(id) = only {
            subs.retain(|s| s.id == id);
            if subs.is_empty() {
                return Err(JobError::UnknownId);
            }
        }
        let proxy = self
            .raw_config
            .read()
            .mixed_port
            .filter(|&p| p != 0)
            .map(|p| format!("127.0.0.1:{p}"));
        let mut report = Report::default();
        let mut recorded = Vec::new();
        for s in &subs {
            match self.refresh_one(&runner, s, proxy.as_deref()).await {
                Ok(error) => {
                    recorded.push(s.id.clone());
                    report.refreshed.push(Refreshed {
                        id: s.id.clone(),
                        error,
                    });
                }
                Err(why) => {
                    tracing::warn!("paopao refresh {}: {why}", s.id);
                    report.refreshed.push(Refreshed {
                        id: s.id.clone(),
                        error: Some(why),
                    });
                }
            }
        }
        if !recorded.is_empty() {
            self.rebuild(&runner, &recorded, false, &mut report).await;
        }
        if only.is_none() {
            self.ran(report.error.clone()).await;
        }
        super::give_back();
        Ok(report)
    }

    /// Rebuilds from the stored input as it is and runs the config when it
    /// differs from the running one (`PUT /paopao/input?apply=true`).
    pub async fn apply(&self) -> Result<Report, JobError> {
        let runner = self.runner.clone().ok_or(JobError::Unavailable)?;
        let _job = self.job.try_lock().map_err(|_| JobError::Busy)?;
        let mut report = Report::default();
        self.rebuild(&runner, &[], true, &mut report).await;
        super::give_back();
        Ok(report)
    }

    /// One subscription refreshed by a child, which writes its record; the
    /// subscription's problem (None: it worked), or why no record was
    /// written.
    async fn refresh_one(
        &self,
        runner: &Runner,
        s: &SubHead,
        proxy: Option<&str>,
    ) -> Result<Option<String>, String> {
        let req = json!({
            "dir": self.store.dir(),
            "id": s.id,
            "url": s.url,
            "user_agent": s.user_agent,
            "proxy": proxy,
        });
        let v = small(runner, "refresh", req, REFRESH_TIMEOUT).await?;
        Ok(v.get("error").and_then(Value::as_str).map(str::to_owned))
    }

    /// Merges the records of `ids` into the input, builds when lines
    /// changed (`always`: in any case), runs the config when it differs.
    async fn rebuild(&self, runner: &Runner, ids: &[String], always: bool, report: &mut Report) {
        let req = json!({
            "dir": self.store.dir(),
            "ids": ids,
            "config": self.config_path,
            "now": now_ms(),
            "build": always,
        });
        let applied = {
            let _input = self.input.lock().await;
            small(runner, "apply", req, APPLY_TIMEOUT).await
        };
        let v = match applied {
            Ok(v) => v,
            Err(why) => {
                tracing::warn!("paopao rebuild: {why}");
                report.error = Some(why);
                return;
            }
        };
        let flag = |k: &str| v.get(k).and_then(Value::as_bool).unwrap_or(false);
        report.input_changed = flag("input_changed");
        report.rebuilt = flag("rebuilt");
        if !flag("next") {
            return;
        }
        let next = self.store.next_config();
        match (self.reload)(next.clone()).await {
            Ok(()) => {
                report.reloaded = true;
                if let Some(path) = &self.config_path {
                    if let Err(e) = replace(&next, path).await {
                        tracing::warn!("paopao: the new config runs but is not saved: {e}");
                        report.error = Some(format!("the new config runs but is not saved: {e}"));
                    }
                } else {
                    let _ = tokio::fs::remove_file(&next).await;
                }
            }
            Err(why) => {
                let _ = tokio::fs::remove_file(&next).await;
                tracing::warn!("paopao: the core refused the new config: {why}");
                report.error = Some(format!("the core refused the new config: {why}"));
            }
        }
    }

    /// The schedule's run is done (now), with its problem.
    async fn ran(&self, error: Option<String>) {
        let mut s = self.schedule().await;
        s.last_run = Some(now_ms());
        s.last_error = error;
        let store = self.store.clone();
        let _ = tokio::task::spawn_blocking(move || s.write(&store)).await;
    }
}

/// `next` over `path`: renamed, or copied where a rename cannot (another
/// file system).
async fn replace(next: &std::path::Path, path: &std::path::Path) -> std::io::Result<()> {
    if tokio::fs::rename(next, path).await.is_ok() {
        return Ok(());
    }
    let bytes = tokio::fs::read(next).await?;
    let path = path.to_owned();
    tokio::task::spawn_blocking(move || super::store::write_atomic(&path, &bytes, false))
        .await
        .map_err(std::io::Error::other)??;
    let _ = tokio::fs::remove_file(next).await;
    Ok(())
}

/// A child's small JSON answer; its `error` (or why there is none) when it
/// did not succeed. Waits for a free slot.
async fn small(runner: &Runner, op: &str, req: Value, limit: Duration) -> Result<Value, String> {
    let out = runner
        .run_queued(op, Bytes::from(req.to_string()), limit)
        .await
        .map_err(|e| e.to_string())?;
    let Output::Whole { code, body } = out else {
        return Err(format!("the PaoPao {op} job answered too much"));
    };
    let v: Value = serde_json::from_slice(&body)
        .map_err(|_| format!("the PaoPao {op} job answered no JSON"))?;
    if code == EXIT_OK {
        return Ok(v);
    }
    Err(v
        .get("error")
        .and_then(Value::as_str)
        .unwrap_or("the PaoPao job failed")
        .to_owned())
}

/// Refreshes on the schedule while it is on; sleeps otherwise (woken by
/// [`Service::set_schedule`]). Runs for good: spawn it.
pub async fn run_schedule(svc: Arc<Service>) {
    loop {
        let s = svc.schedule().await;
        let wait = svc.next_run(&s).map(|at| {
            Duration::from_millis(u64::try_from(at.saturating_sub(now_ms())).unwrap_or(0))
        });
        if wait != Some(Duration::ZERO) {
            let nap = wait.unwrap_or(MAX_NAP).min(MAX_NAP);
            tokio::select! {
                () = tokio::time::sleep(nap) => {}
                () = svc.wake.notified() => {}
            }
            continue;
        }
        match svc.refresh(None).await {
            Ok(_) => {}
            // A refresh asked for runs: the next look is soon.
            Err(JobError::Busy) => {
                tokio::select! {
                    () = tokio::time::sleep(svc.minute) => {}
                    () = svc.wake.notified() => {}
                }
            }
            // Nothing to refresh (yet): counted as a run, so it is not
            // tried again at once.
            Err(e) => svc.ran(Some(e.to_string())).await,
        }
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use std::path::Path;
    use tower::ServiceExt as _;

    /// Children that are `sh -c script` (`$2` = the op).
    fn sh(script: &str) -> Arc<Runner> {
        Arc::new(Runner::new("sh").with_prefix(["-c", script, "sh"]))
    }

    /// `refresh` and `apply` children doing `refresh` / `apply` (shell).
    fn children(refresh: &str, apply: &str) -> Arc<Runner> {
        sh(&format!(
            "case $2 in refresh) {refresh};; apply) {apply};; *) exit 9;; esac"
        ))
    }

    /// A reload that reads the file it is given and answers `answer`; what
    /// it read, in order.
    fn reload(answer: Result<(), String>) -> (Reload, Arc<parking_lot::Mutex<Vec<String>>>) {
        let seen = Arc::new(parking_lot::Mutex::new(Vec::new()));
        let log = Arc::clone(&seen);
        let r: Reload = Arc::new(move |path: PathBuf| {
            log.lock()
                .push(std::fs::read_to_string(path).unwrap_or_default());
            let answer = answer.clone();
            Box::pin(async move { answer })
        });
        (r, seen)
    }

    struct Rig {
        dir: tempfile::TempDir,
        svc: Arc<Service>,
        seen: Arc<parking_lot::Mutex<Vec<String>>>,
    }

    impl Rig {
        fn config(&self) -> PathBuf {
            self.dir.path().join("config.yaml")
        }
        fn store(&self) -> &Path {
            self.svc.store().dir()
        }
    }

    /// A service over `runner`, the core running `config.yaml` ("OLD"),
    /// its reload answering `answer`; mixed port 7890.
    fn rig(runner: Option<Arc<Runner>>, answer: Result<(), String>) -> Rig {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("config.yaml"), "OLD").unwrap();
        let (r, seen) = reload(answer);
        let raw = RawConfig {
            mixed_port: Some(7890),
            ..RawConfig::default()
        };
        let svc = Service::new(
            runner,
            Arc::new(RwLock::new(raw)),
            dir.path().join("paopao"),
            Some(dir.path().join("config.yaml")),
            r,
        );
        Rig {
            dir,
            svc: Arc::new(svc),
            seen,
        }
    }

    const INPUT: &str = r#"{"subscriptions": [
        {"id": "a1", "url": "http://a/", "nodes": [{"name": "n", "outbound": {"type": "trojan"}}]},
        {"id": "b2", "url": "http://b/", "user_agent": "ua"}
    ], "settings": {}}"#;

    async fn call(rig: &Rig, method: &str, path: &str, body: &str) -> (StatusCode, Vec<u8>) {
        let req = Request::builder()
            .method(method)
            .uri(path)
            .body(Body::from(body.to_owned()))
            .unwrap();
        let res = super::super::router::<()>(Arc::clone(&rig.svc))
            .oneshot(req)
            .await
            .unwrap();
        let status = res.status();
        let bytes = axum::body::to_bytes(res.into_body(), usize::MAX)
            .await
            .unwrap();
        (status, bytes.to_vec())
    }

    fn json_of(b: &[u8]) -> Value {
        serde_json::from_slice(b).unwrap()
    }

    #[tokio::test]
    async fn the_input_is_kept_as_handed_over_and_listed() {
        let rig = rig(None, Ok(()));
        let records = rig.store().join("subscriptions");
        std::fs::create_dir_all(&records).unwrap();
        let record = r#"{"id":"a1","url":"http://a/","via":"direct","checked":5,"updated":5,"node_count":1,"skipped":0,"nodes":[{"name":"n"}]}"#;
        std::fs::write(records.join("a1.json"), record).unwrap();
        std::fs::write(records.join("gone.json"), "{}").unwrap();

        let (s, _) = call(&rig, "GET", "/paopao/input", "").await;
        assert_eq!(s, StatusCode::NOT_FOUND);
        let (s, body) = call(&rig, "GET", "/paopao/subscriptions", "").await;
        assert_eq!(
            (s, json_of(&body)),
            (StatusCode::OK, json!({"subscriptions": []}))
        );

        let (s, body) = call(&rig, "PUT", "/paopao/input", INPUT).await;
        assert_eq!(
            (s, json_of(&body)),
            (StatusCode::OK, json!({"subscriptions": 2}))
        );
        let (s, body) = call(&rig, "GET", "/paopao/input", "").await;
        assert_eq!((s, body.as_slice()), (StatusCode::OK, INPUT.as_bytes()));
        // The record of a subscription no longer handed over is gone.
        assert!(records.join("a1.json").exists());
        assert!(!records.join("gone.json").exists());

        let (_, body) = call(&rig, "GET", "/paopao/subscriptions", "").await;
        assert_eq!(
            json_of(&body),
            json!({"subscriptions": [
                {"id": "a1", "url": "http://a/", "name": null, "refreshed": {
                    "id": "a1", "url": "http://a/", "via": "direct", "checked": 5,
                    "updated": 5, "node_count": 1, "skipped": 0}},
                {"id": "b2", "url": "http://b/", "name": null, "refreshed": null},
            ]})
        );
        let (_, body) = call(&rig, "GET", "/paopao/subscriptions?nodes=true", "").await;
        assert_eq!(
            json_of(&body)["subscriptions"][0]["refreshed"]["nodes"],
            json!([{"name": "n"}])
        );

        for bad in ["[1]", "nope", ""] {
            let (s, body) = call(&rig, "PUT", "/paopao/input", bad).await;
            assert_eq!(s, StatusCode::BAD_REQUEST, "{bad}");
            assert!(json_of(&body)["error"].is_string());
        }
        // Still the good one.
        let (_, body) = call(&rig, "GET", "/paopao/input", "").await;
        assert_eq!(body, INPUT.as_bytes());

        // No children here: jobs answer 501, the rest works.
        let (s, _) = call(&rig, "POST", "/paopao/subscriptions/refresh", "").await;
        assert_eq!(s, StatusCode::NOT_IMPLEMENTED);
        let (s, _) = call(&rig, "PUT", "/paopao/input?apply=true", INPUT).await;
        assert_eq!(s, StatusCode::NOT_IMPLEMENTED);
    }

    #[tokio::test]
    async fn a_refresh_rebuilds_and_the_new_config_replaces_the_file_once_it_runs() {
        let rig_dir = tempfile::tempdir().unwrap();
        let req = rig_dir.path().join("req");
        let runner = children(
            &format!(
                r#"cat >> {req}; echo '{{"id":"x","error":null}}'"#,
                req = req.display()
            ),
            &format!(
                r#"cat > {req}.apply; d=$(sed 's/.*"dir":"\([^"]*\)".*/\1/' {req}.apply); echo NEW > "$d/config.next.yaml"; echo '{{"input_changed":true,"rebuilt":true,"next":true}}'"#,
                req = req.display()
            ),
        );
        let rig = rig(Some(runner), Ok(()));
        assert_eq!(
            call(&rig, "PUT", "/paopao/input", INPUT).await.0,
            StatusCode::OK
        );
        let (s, body) = call(&rig, "POST", "/paopao/subscriptions/refresh", "").await;
        assert_eq!(s, StatusCode::OK);
        assert_eq!(
            json_of(&body),
            json!({"refreshed": [{"id": "a1"}, {"id": "b2"}], "input_changed": true,
                   "rebuilt": true, "reloaded": true})
        );
        assert_eq!(*rig.seen.lock(), ["NEW\n"]);
        assert_eq!(std::fs::read_to_string(rig.config()).unwrap(), "NEW\n");
        assert!(!rig.store().join("config.next.yaml").exists());

        // What the children were asked: each subscription with the core's
        // port, then the merge of both.
        let asked: Vec<Value> = std::fs::read_to_string(&req)
            .unwrap()
            .split_inclusive('}')
            .map(|j| serde_json::from_str(j).unwrap())
            .collect();
        assert_eq!(asked[0]["id"], "a1");
        assert_eq!(asked[0]["proxy"], "127.0.0.1:7890");
        assert_eq!(asked[1]["user_agent"], "ua");
        let apply: Value =
            serde_json::from_str(&std::fs::read_to_string(req.with_extension("apply")).unwrap())
                .unwrap();
        assert_eq!(apply["ids"], json!(["a1", "b2"]));
        assert_eq!(apply["build"], false);
        assert_eq!(apply["config"], json!(rig.config()));

        // A refresh of all counts as the schedule's run.
        let (_, body) = call(&rig, "GET", "/paopao/schedule", "").await;
        assert!(json_of(&body)["last_run"].is_i64());
        assert_eq!(json_of(&body)["last_error"], Value::Null);
    }

    #[tokio::test]
    async fn a_refused_config_leaves_the_running_one_and_its_file() {
        let runner = children(
            r#"cat >/dev/null; echo '{"id":"a1","error":"订阅已失效，请向机场索取新的订阅链接"}'"#,
            r#"d=$(sed 's/.*"dir":"\([^"]*\)".*/\1/'); echo NEW > "$d/config.next.yaml"; echo '{"input_changed":true,"rebuilt":true,"next":true}'"#,
        );
        let rig = rig(Some(runner), Err("config parse error: x".into()));
        rig.svc
            .store_input(Bytes::from_static(INPUT.as_bytes()))
            .await
            .unwrap();
        let report = rig.svc.refresh(Some("a1")).await.unwrap();
        assert_eq!(
            report.refreshed,
            [Refreshed {
                id: "a1".into(),
                error: Some("订阅已失效，请向机场索取新的订阅链接".into())
            }]
        );
        assert!(!report.reloaded);
        assert!(report.error.unwrap().contains("config parse error: x"));
        assert_eq!(std::fs::read_to_string(rig.config()).unwrap(), "OLD");
        assert!(!rig.store().join("config.next.yaml").exists());
        // One subscription asked for: not the schedule's run.
        assert_eq!(rig.svc.schedule().await.last_run, None);
    }

    #[tokio::test]
    async fn a_failed_build_or_child_reloads_nothing() {
        let rig = rig(
            Some(children(
                r#"cat >/dev/null; echo '{"id":"a1","error":null}'"#,
                r#"cat >/dev/null; echo '{"error":"boom"}'; exit 2"#,
            )),
            Ok(()),
        );
        rig.svc
            .store_input(Bytes::from_static(INPUT.as_bytes()))
            .await
            .unwrap();
        let report = rig.svc.refresh(None).await.unwrap();
        assert_eq!(report.error.as_deref(), Some("boom"));
        assert!(!report.reloaded && !report.rebuilt);
        assert!(rig.seen.lock().is_empty());
        assert_eq!(std::fs::read_to_string(rig.config()).unwrap(), "OLD");
        assert_eq!(rig.svc.schedule().await.last_error.as_deref(), Some("boom"));

        // A refresh child that crashes writes no record: nothing to merge.
        let marker = rig.dir.path().join("applied");
        let rig2 = self::rig(
            Some(children(
                "echo dead >&2; exit 7",
                &format!("touch {}; echo '{{}}'", marker.display()),
            )),
            Ok(()),
        );
        rig2.svc
            .store_input(Bytes::from_static(INPUT.as_bytes()))
            .await
            .unwrap();
        let report = rig2.svc.refresh(None).await.unwrap();
        assert!(report.refreshed[0]
            .error
            .as_deref()
            .unwrap()
            .contains("dead"));
        assert!(!marker.exists());
        assert!(rig2.seen.lock().is_empty());
    }

    #[tokio::test]
    async fn one_job_at_a_time() {
        let rig = rig(
            Some(children(
                r#"cat >/dev/null; sleep 1; echo '{"id":"a1","error":null}'"#,
                r#"cat >/dev/null; echo '{"input_changed":false,"rebuilt":false,"next":false}'"#,
            )),
            Ok(()),
        );
        rig.svc
            .store_input(Bytes::from_static(INPUT.as_bytes()))
            .await
            .unwrap();
        let svc = Arc::clone(&rig.svc);
        let first = tokio::spawn(async move { svc.refresh(None).await });
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert!(rig.svc.running());
        let (s, _) = call(&rig, "POST", "/paopao/subscriptions/refresh", "").await;
        assert_eq!(s, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(rig.svc.apply().await, Err(JobError::Busy));
        let (_, body) = call(&rig, "GET", "/paopao/schedule", "").await;
        assert_eq!(json_of(&body)["running"], true);
        assert!(first.await.unwrap().is_ok());
        assert!(!rig.svc.running());
    }

    #[tokio::test]
    async fn refresh_needs_an_input_and_a_known_subscription() {
        let rig = rig(Some(children("exit 9", "exit 9")), Ok(()));
        let (s, _) = call(&rig, "POST", "/paopao/subscriptions/refresh", "").await;
        assert_eq!(s, StatusCode::CONFLICT);
        rig.svc
            .store_input(Bytes::from_static(INPUT.as_bytes()))
            .await
            .unwrap();
        let (s, _) = call(&rig, "POST", "/paopao/subscriptions/refresh?id=zz", "").await;
        assert_eq!(s, StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn the_scheduler_runs_only_once_told_and_then_on_time() {
        let dir = tempfile::tempdir().unwrap();
        let runs = dir.path().join("runs");
        let rig = rig(
            Some(children(
                &format!(
                    r#"cat >/dev/null; echo x >> {}; echo '{{"id":"a1","error":null}}'"#,
                    runs.display()
                ),
                r#"cat >/dev/null; echo '{"input_changed":false,"rebuilt":false,"next":false}'"#,
            )),
            Ok(()),
        );
        let rig = Rig {
            svc: Arc::new(
                Arc::try_unwrap(rig.svc)
                    .ok()
                    .unwrap()
                    .with_minute(Duration::from_millis(200)),
            ),
            ..rig
        };
        rig.svc
            .store_input(Bytes::from_static(INPUT.as_bytes()))
            .await
            .unwrap();
        let count = || std::fs::read_to_string(&runs).map_or(0, |s| s.lines().count());
        let task = tokio::spawn(run_schedule(Arc::clone(&rig.svc)));
        tokio::time::sleep(Duration::from_millis(600)).await;
        assert_eq!(count(), 0, "ran while off");

        let (s, body) = call(
            &rig,
            "PUT",
            "/paopao/schedule",
            r#"{"enabled": true, "minutes": 1}"#,
        )
        .await;
        assert_eq!(s, StatusCode::OK);
        assert_eq!(json_of(&body)["enabled"], true);
        // Never run: at once (two subscriptions a run), then every 200 ms.
        let started = tokio::time::Instant::now();
        while count() < 6 {
            assert!(
                started.elapsed() < Duration::from_secs(10),
                "{} runs",
                count()
            );
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        let s = rig.svc.schedule().await;
        assert!(s.last_run.is_some());
        assert_eq!(rig.svc.next_run(&s), Some(s.last_run.unwrap() + 200));

        let (s, _) = call(&rig, "PUT", "/paopao/schedule", r#"{"minutes": 0}"#).await;
        assert_eq!(s, StatusCode::OK);
        tokio::time::sleep(Duration::from_millis(400)).await;
        let stopped = count();
        tokio::time::sleep(Duration::from_millis(600)).await;
        assert_eq!(count(), stopped, "ran after it was turned off");
        let (_, body) = call(&rig, "GET", "/paopao/schedule", "").await;
        assert_eq!(json_of(&body)["next_run"], Value::Null);
        assert_eq!(json_of(&body)["enabled"], true);

        let (s, _) = call(&rig, "PUT", "/paopao/schedule", r#"{"minutes": -1}"#).await;
        assert_eq!(s, StatusCode::BAD_REQUEST);
        task.abort();
    }
}
