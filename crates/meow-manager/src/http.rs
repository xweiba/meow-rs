//! The manager's API: HTTP+JSON, `Authorization: Bearer <token>` on every
//! request. The desktop daemon listens on 127.0.0.1 (a free port) and
//! writes where in its token file (`{port, token, pid}`, readable by the
//! user alone); a router build may listen on the LAN with the same API.
//!
//! - `GET /manager/status` → `{manager, running, same_core, core,
//!   system_proxy, launch_at_login, tun, can_tun, config, dir, controller,
//!   secret, mixed_port}` ([`crate::Manager::status`]).
//! - `POST /manager/core/start` `{config?, dir?, system_proxy?}`: `config`
//!   the config itself (an object: written where the core runs it, with or
//!   without 虚拟网卡), or its path with `dir`; neither: what it ran last →
//!   the status.
//! - `POST /manager/core/stop`, `POST /manager/core/restart` → the status.
//! - `PATCH /manager/settings` `{system_proxy?, tun?, launch_at_login?}` →
//!   the status.
//!
//! Refusals are `{error, code, log?}`: `400 bad_request`, `409 no_run` /
//! `needs_authorization`, `500 failed`; `401` without the token.

use axum::{
    extract::{Request, State},
    http::{header, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Json, Response},
    routing::{get, patch, post},
    Router,
};
use serde::Deserialize;
use serde_json::{json, Value};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use crate::manager::{Manager, Patch, Refusal, Run};

pub type Shared = Arc<Mutex<Manager>>;

#[derive(Clone)]
struct Api {
    manager: Shared,
    token: Arc<str>,
}

pub fn router(manager: Shared, token: &str) -> Router {
    let api = Api {
        manager,
        token: token.into(),
    };
    Router::new()
        .route("/manager/status", get(status))
        .route("/manager/core/start", post(start))
        .route("/manager/core/stop", post(stop))
        .route("/manager/core/restart", post(restart))
        .route("/manager/settings", patch(settings))
        .layer(middleware::from_fn_with_state(api.clone(), authorized))
        .with_state(api)
}

async fn authorized(State(api): State<Api>, req: Request, next: Next) -> Response {
    let given = req
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "));
    if !given.is_some_and(|t| same(t.as_bytes(), api.token.as_bytes())) {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({"error": "unauthorized"})),
        )
            .into_response();
    }
    next.run(req).await
}

/// Equal, in a time that does not depend on where they differ.
fn same(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |d, (x, y)| d | (x ^ y)) == 0
}

/// `f` on the manager, off the async threads (it waits for the core).
async fn with<F>(api: &Api, f: F) -> Response
where
    F: FnOnce(&mut Manager) -> Result<Value, Refusal> + Send + 'static,
{
    let manager = Arc::clone(&api.manager);
    let done = tokio::task::spawn_blocking(move || {
        let mut m = manager
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        f(&mut m)
    })
    .await;
    match done {
        Ok(Ok(v)) => Json(v).into_response(),
        Ok(Err(r)) => {
            let status = match r {
                Refusal::Bad(_) => StatusCode::BAD_REQUEST,
                Refusal::NoRun | Refusal::NeedsAuthorization => StatusCode::CONFLICT,
                Refusal::Failed(_) => StatusCode::INTERNAL_SERVER_ERROR,
            };
            (status, Json(r.to_json())).into_response()
        }
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": e.to_string(), "code": "failed"})),
        )
            .into_response(),
    }
}

fn body<T: for<'de> Deserialize<'de> + Default>(bytes: &[u8]) -> Result<T, Refusal> {
    if bytes.iter().all(u8::is_ascii_whitespace) {
        return Ok(T::default());
    }
    serde_json::from_slice(bytes).map_err(|e| Refusal::Bad(format!("bad request: {e}")))
}

async fn status(State(api): State<Api>) -> Response {
    with(&api, |m| Ok(m.status())).await
}

#[derive(Default, Deserialize)]
struct Start {
    /// The config itself (placed by the manager), or its path with `dir`.
    #[serde(default)]
    config: Option<Value>,
    #[serde(default)]
    dir: Option<PathBuf>,
    #[serde(default)]
    system_proxy: Option<bool>,
}

async fn start(State(api): State<Api>, bytes: axum::body::Bytes) -> Response {
    let req: Start = match body(&bytes) {
        Ok(r) => r,
        Err(r) => return (StatusCode::BAD_REQUEST, Json(r.to_json())).into_response(),
    };
    with(&api, move |m| {
        let run = match (req.config, req.dir) {
            (Some(config @ Value::Object(_)), None) => {
                return m.start_config(&config, req.system_proxy);
            }
            (Some(Value::String(config)), Some(dir)) => Some(Run {
                config: config.into(),
                dir,
            }),
            (None, None) => None,
            _ => {
                return Err(Refusal::Bad(
                    "config (an object), or config and dir (paths)".into(),
                ))
            }
        };
        m.start(run, req.system_proxy)
    })
    .await
}

async fn stop(State(api): State<Api>) -> Response {
    with(&api, |m| Ok(m.stop())).await
}

async fn restart(State(api): State<Api>) -> Response {
    with(&api, Manager::restart).await
}

async fn settings(State(api): State<Api>, bytes: axum::body::Bytes) -> Response {
    let p: Patch = match body(&bytes) {
        Ok(p) => p,
        Err(r) => return (StatusCode::BAD_REQUEST, Json(r.to_json())).into_response(),
    };
    with(&api, move |m| m.set(p)).await
}

/// 32 random hex digits.
pub fn new_token() -> String {
    let bytes: [u8; 16] = rand::random();
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// `{port, token, pid}` at `path`, readable by its owner alone; written
/// whole (a temporary file renamed over it).
pub fn write_token_file(path: &Path, port: u16, token: &str) -> std::io::Result<()> {
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let tmp = path.with_extension("json.tmp");
    let text = json!({"port": port, "token": token, "pid": std::process::id()}).to_string();
    #[cfg(unix)]
    {
        use std::io::Write as _;
        use std::os::unix::fs::OpenOptionsExt as _;
        let _ = std::fs::remove_file(&tmp);
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&tmp)?;
        f.write_all(text.as_bytes())?;
    }
    #[cfg(not(unix))]
    std::fs::write(&tmp, text)?;
    std::fs::rename(&tmp, path)
}

/// The token file goes, when it is still this process's.
pub fn forget_token_file(path: &Path) {
    let mine = std::fs::read(path)
        .ok()
        .and_then(|b| serde_json::from_slice::<Value>(&b).ok())
        .and_then(|v| v.get("pid").and_then(Value::as_u64))
        == Some(u64::from(std::process::id()));
    if mine {
        let _ = std::fs::remove_file(path);
    }
}

/// Listens on `addr` (port 0: a free one), writes the token file, serves
/// until `stop` resolves.
pub async fn serve(
    manager: Shared,
    addr: SocketAddr,
    token_file: &Path,
    stop: impl std::future::Future<Output = ()> + Send + 'static,
) -> std::io::Result<()> {
    let listener = tokio::net::TcpListener::bind(addr).await?;
    let port = listener.local_addr()?.port();
    let token = new_token();
    write_token_file(token_file, port, &token)?;
    let app = router(manager, &token);
    let served = axum::serve(listener, app)
        .with_graceful_shutdown(stop)
        .await;
    forget_token_file(token_file);
    served
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manager::tests::Rig;
    use axum::body::Body;
    use tower::ServiceExt as _;

    async fn call(app: &Router, method: &str, path: &str, token: &str, body: &str) -> (u16, Value) {
        let req = Request::builder()
            .method(method)
            .uri(path)
            .header("authorization", format!("Bearer {token}"))
            .body(Body::from(body.to_owned()))
            .unwrap();
        let res = app.clone().oneshot(req).await.unwrap();
        let status = res.status().as_u16();
        let bytes = axum::body::to_bytes(res.into_body(), 1 << 20)
            .await
            .unwrap();
        (
            status,
            serde_json::from_slice(&bytes).unwrap_or(Value::Null),
        )
    }

    #[tokio::test]
    async fn the_api_over_the_manager() {
        let rig = Rig::new();
        let app = router(Arc::new(Mutex::new(rig.manager())), "t0k");
        assert_eq!(
            call(&app, "GET", "/manager/status", "nope", "").await.0,
            401
        );
        let (s, v) = call(&app, "GET", "/manager/status", "t0k", "").await;
        assert_eq!((s, &v["running"]), (200, &json!(false)));
        let (s, v) = call(&app, "POST", "/manager/core/restart", "t0k", "").await;
        assert_eq!((s, v["code"].as_str()), (409, Some("no_run")));
        let run = rig.run();
        let start = json!({"config": run.config, "dir": run.dir, "system_proxy": true}).to_string();
        let (s, v) = call(&app, "POST", "/manager/core/start", "t0k", &start).await;
        assert_eq!(s, 200, "{v}");
        assert_eq!(v["running"], true);
        assert_eq!(v["system_proxy"], true);
        assert_eq!(rig.proxy.take(), ["proxy on 7890"]);
        let (s, _) = call(
            &app,
            "POST",
            "/manager/core/start",
            "t0k",
            r#"{"config":"/a"}"#,
        )
        .await;
        assert_eq!(s, 400);
        let (s, v) = call(
            &app,
            "PATCH",
            "/manager/settings",
            "t0k",
            r#"{"launch_at_login":true,"system_proxy":false}"#,
        )
        .await;
        assert_eq!(s, 200);
        assert_eq!(
            (&v["launch_at_login"], &v["system_proxy"]),
            (&json!(true), &json!(false))
        );
        *rig.can_tun.lock().unwrap() = false;
        let (s, v) = call(&app, "PATCH", "/manager/settings", "t0k", r#"{"tun":true}"#).await;
        assert_eq!((s, v["code"].as_str()), (409, Some("needs_authorization")));
        let (s, _) = call(&app, "PATCH", "/manager/settings", "t0k", "{bad").await;
        assert_eq!(s, 400);
        let (s, v) = call(&app, "POST", "/manager/core/stop", "t0k", "").await;
        assert_eq!((s, &v["running"]), (200, &json!(false)));
    }

    #[tokio::test]
    async fn serves_on_loopback_and_writes_the_token_file() {
        let rig = Rig::new();
        let file = rig.dir.path().join("manager-api.json");
        let (tx, rx) = tokio::sync::oneshot::channel::<()>();
        let m = Arc::new(Mutex::new(rig.manager()));
        let f = file.clone();
        let task = tokio::spawn(async move {
            serve(m, "127.0.0.1:0".parse().unwrap(), &f, async {
                let _ = rx.await;
            })
            .await
        });
        for _ in 0..200 {
            if file.exists() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        let v: Value = serde_json::from_slice(&std::fs::read(&file).unwrap()).unwrap();
        assert_eq!(v["token"].as_str().unwrap().len(), 32);
        assert!(v["port"].as_u64().unwrap() > 0);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            assert_eq!(
                std::fs::metadata(&file).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
        tx.send(()).unwrap();
        task.await.unwrap().unwrap();
        assert!(!file.exists());
        assert!(same(b"abc", b"abc") && !same(b"abc", b"abd") && !same(b"ab", b"abc"));
    }
}
