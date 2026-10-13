//! 签到助手 over the API: `/checkin…` (see `meow-checkin`).
//!
//! Authenticated like every other route, and on top of that closed to
//! other origins: a request a browser marks as coming from another web
//! page is refused (`403`) whatever the secret says, so a page the user
//! happens to visit cannot drive these routes when the controller has no
//! secret, nor read a manual value back. The app is not a browser and
//! sends no `Origin`. Bodies are JSON with snake_case
//! keys; a refused call answers a non-2xx status with
//! `{"error": "<one sentence for the user>"}`; calls without a result
//! answer `204`.
//!
//! Variable values: an `auto` value (cookie, token) is write-only — it
//! comes in through `POST …/variables/values` and is never in any answer.
//! A `manual` value is masked in answers unless the call carries
//! `?manual_values=1`.

use axum::{
    body::{Body, Bytes},
    extract::ws::{Message, WebSocket, WebSocketUpgrade},
    extract::{FromRequestParts, Path, Query, Request, State},
    http::{header, request::Parts, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Json, Response},
    routing::{get, post, put},
    Router,
};
use meow_checkin::clicks::ClickSubscription;
use meow_checkin::http::{refused_private, unknown_policy, BoxStream, Connector};
use meow_checkin::{Access, CheckinError, Engine, EngineConfig, ErrorKind, SystemClock};
use meow_common::public_only::{PRIVATE_ALLOWED_INBOUND, PUBLIC_ONLY_INBOUND};
use meow_common::{ConnType, MeowError, Metadata, Network};
use meow_tunnel::Tunnel;
use serde::Deserialize;
use serde_json::Value;
use smol_str::SmolStr;
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

/// Idle streams send an empty line (or a WebSocket ping) this often, so a
/// client that went away is noticed.
const KEEP_ALIVE: Duration = Duration::from_secs(10);

/// Requests of 签到助手 leave through the core like any connection made
/// from inside it: `proxy` goes through the rules and lines (and shows in
/// the connection list), `direct` goes out through `DIRECT`. A `proxy`
/// task that names a proxy or group goes through that one whatever the
/// rules and the mode say (the connection's special proxy); a name that
/// is not there is refused, not handed to the rules.
///
/// Unless private addresses are allowed, the connection carries the
/// inbound name [`PUBLIC_ONLY_INBOUND`]: `DIRECT` then refuses to dial an
/// address on this machine or a private network, on either path, checking
/// the address it resolved and is about to dial. A line (a proxy server)
/// resolves the name on its own side; what that reaches is not this
/// machine's network.
pub struct TunnelConnector {
    tunnel: Tunnel,
}

impl TunnelConnector {
    pub fn new(tunnel: Tunnel) -> Self {
        Self { tunnel }
    }
}

#[async_trait::async_trait]
impl Connector for TunnelConnector {
    async fn connect(
        &self,
        access: Access,
        policy: Option<&str>,
        host: &str,
        port: u16,
        allow_private: bool,
    ) -> std::io::Result<BoxStream> {
        let literal = host.parse::<IpAddr>().ok();
        if !allow_private && literal.is_some_and(meow_common::public_only::is_non_public_ip) {
            return Err(refused_private());
        }
        let metadata = Metadata {
            network: Network::Tcp,
            conn_type: ConnType::Inner,
            host: if literal.is_none() {
                SmolStr::from(host)
            } else {
                SmolStr::default()
            },
            dst_ip: literal,
            dst_port: port,
            in_name: SmolStr::new_static(if allow_private {
                PRIVATE_ALLOWED_INBOUND
            } else {
                PUBLIC_ONLY_INBOUND
            }),
            ..Metadata::default()
        };
        match access {
            Access::Direct => {
                use meow_common::adapter::ProxyAdapter as _;
                let direct = Arc::clone(&self.tunnel.inner().direct);
                let conn = meow_common::with_dial_timeout("DIRECT", direct.dial_tcp(&metadata))
                    .await
                    .map_err(|e| match e {
                        MeowError::Io(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
                            refused_private()
                        }
                        other => std::io::Error::other(other),
                    })?;
                Ok(Box::new(conn))
            }
            Access::Proxy => {
                let mut metadata = metadata;
                if let Some(policy) = policy {
                    // Said here, in words the run can show: past this
                    // point a refusal is only a closed stream.
                    if !self.tunnel.inner().has_proxy(policy) {
                        return Err(unknown_policy());
                    }
                    metadata.special_proxy = SmolStr::from(policy);
                }
                // The same path a listener hands a connection to: rule
                // match (or the named proxy), tracking, dial, relay. A failed dial closes our
                // end.
                let (ours, mut theirs) = tokio::io::duplex(64 * 1024);
                let inner = Arc::clone(self.tunnel.inner());
                tokio::spawn(async move {
                    meow_tunnel::route_inbound_tcp(&inner, &mut theirs, metadata, &[]).await;
                });
                Ok(Box::new(ours))
            }
        }
    }
}

/// Opens the engine on `dir` with requests leaving through `tunnel`. The
/// caller starts it ([`Engine::start`]) and keeps the returned tasks.
pub fn open_engine(tunnel: &Tunnel, dir: PathBuf) -> Arc<Engine> {
    Engine::open(
        dir,
        Arc::new(TunnelConnector::new(tunnel.clone())),
        Arc::new(SystemClock),
        EngineConfig::default(),
    )
}

/// The `/checkin…` routes over `engine`.
pub fn router<S: Clone + Send + Sync + 'static>(engine: Arc<Engine>) -> Router<S> {
    Router::new()
        .route("/checkin", get(snapshot))
        .route("/checkin/events", get(events))
        .route("/checkin/run", post(run_all))
        .route("/checkin/clicks", get(clicks))
        .route("/checkin/clicks/{request_id}", post(report_click))
        .route("/checkin/rules/check", post(check_rule))
        .route("/checkin/rules/import", post(import_rule))
        .route("/checkin/tasks", post(create_task))
        .route("/checkin/tasks/order", put(reorder_tasks))
        .route(
            "/checkin/tasks/{id}",
            axum::routing::patch(update_task).delete(delete_task),
        )
        .route("/checkin/tasks/{id}/steps", put(save_steps))
        .route("/checkin/tasks/{id}/run", post(run_task))
        .route("/checkin/tasks/{id}/rule", get(export_rule))
        // One route for the three: `POST …/variables/values` is the push,
        // and a variable may itself be called `values`.
        .route(
            "/checkin/tasks/{id}/variables/{name}",
            put(save_variable)
                .delete(delete_variable)
                .post(push_variables),
        )
        .layer(middleware::from_fn(same_origin_only))
        .with_state(engine)
}

/// Refuses what a browser says comes from another web page: an `Origin`
/// that is not this server's own, or `Sec-Fetch-Site` other than
/// `same-origin` / `none`. Requests without either (the app, `curl`) pass
/// and are judged by the secret alone.
async fn same_origin_only(req: Request, next: Next) -> Response {
    let headers = req.headers();
    let text = |name: header::HeaderName| headers.get(name).map(|v| v.to_str().unwrap_or(""));
    let own = text(header::HOST)
        .or_else(|| {
            req.uri()
                .authority()
                .map(axum::http::uri::Authority::as_str)
        })
        .unwrap_or("");
    let foreign_origin = text(header::ORIGIN).is_some_and(|origin| {
        !origin
            .split_once("://")
            .is_some_and(|(_, authority)| !own.is_empty() && authority.eq_ignore_ascii_case(own))
    });
    let foreign_fetch = text(header::HeaderName::from_static("sec-fetch-site"))
        .is_some_and(|site| !matches!(site, "same-origin" | "none"));
    if foreign_origin || foreign_fetch {
        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({ "error": "签到助手不接受来自其他网页的请求。" })),
        )
            .into_response();
    }
    next.run(req).await
}

type Checkin = State<Arc<Engine>>;

fn refuse(e: &CheckinError) -> Response {
    let status = match e.kind {
        ErrorKind::NotFound => StatusCode::NOT_FOUND,
        ErrorKind::Invalid => StatusCode::BAD_REQUEST,
        ErrorKind::Conflict => StatusCode::CONFLICT,
        ErrorKind::TooLarge => StatusCode::PAYLOAD_TOO_LARGE,
        ErrorKind::Storage => StatusCode::INTERNAL_SERVER_ERROR,
    };
    (status, Json(serde_json::json!({ "error": e.message }))).into_response()
}

fn answer<T: serde::Serialize>(result: Result<T, CheckinError>) -> Response {
    match result {
        Ok(value) => Json(value).into_response(),
        Err(e) => refuse(&e),
    }
}

fn done(result: Result<(), CheckinError>) -> Response {
    match result {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(e) => refuse(&e),
    }
}

/// The body as JSON; an empty body is `{}`.
fn json(body: &Bytes) -> Result<Value, CheckinError> {
    if body.iter().all(u8::is_ascii_whitespace) {
        return Ok(Value::Object(serde_json::Map::new()));
    }
    serde_json::from_slice(body).map_err(|_| CheckinError::invalid("请求内容不是有效的 JSON。"))
}

#[derive(Deserialize, Default)]
struct Reveal {
    manual_values: Option<String>,
}

impl Reveal {
    fn on(&self) -> bool {
        matches!(self.manual_values.as_deref(), Some("1" | "true"))
    }
}

async fn snapshot(State(engine): Checkin, Query(reveal): Query<Reveal>) -> Response {
    Json(engine.snapshot(reveal.on())).into_response()
}

async fn create_task(
    State(engine): Checkin,
    Query(reveal): Query<Reveal>,
    body: Bytes,
) -> Response {
    answer(json(&body).and_then(|body| engine.create_task(&body, reveal.on())))
}

async fn update_task(
    State(engine): Checkin,
    Path(id): Path<String>,
    Query(reveal): Query<Reveal>,
    body: Bytes,
) -> Response {
    answer(json(&body).and_then(|body| engine.update_task(&id, &body, reveal.on())))
}

async fn delete_task(State(engine): Checkin, Path(id): Path<String>) -> Response {
    done(engine.delete_task(&id))
}

async fn reorder_tasks(State(engine): Checkin, body: Bytes) -> Response {
    done(json(&body).and_then(|body| engine.reorder_tasks(&body)))
}

async fn save_steps(
    State(engine): Checkin,
    Path(id): Path<String>,
    Query(reveal): Query<Reveal>,
    body: Bytes,
) -> Response {
    answer(json(&body).and_then(|body| engine.save_steps(&id, &body, reveal.on())))
}

async fn save_variable(
    State(engine): Checkin,
    Path((id, name)): Path<(String, String)>,
    Query(reveal): Query<Reveal>,
    body: Bytes,
) -> Response {
    answer(json(&body).and_then(|body| engine.save_variable(&id, &name, &body, reveal.on())))
}

async fn delete_variable(
    State(engine): Checkin,
    Path((id, name)): Path<(String, String)>,
    Query(reveal): Query<Reveal>,
) -> Response {
    answer(engine.delete_variable(&id, &name, reveal.on()))
}

async fn push_variables(
    State(engine): Checkin,
    Path((id, name)): Path<(String, String)>,
    body: Bytes,
) -> Response {
    if name != "values" {
        return StatusCode::METHOD_NOT_ALLOWED.into_response();
    }
    done(json(&body).and_then(|body| engine.push_variables(&id, &body)))
}

async fn run_task(State(engine): Checkin, Path(id): Path<String>, body: Bytes) -> Response {
    done(json(&body).and_then(|body| {
        let trial = body.get("trial").and_then(Value::as_bool).unwrap_or(false);
        engine.run_task(&id, trial)
    }))
}

async fn run_all(State(engine): Checkin) -> Response {
    engine.run_all();
    StatusCode::NO_CONTENT.into_response()
}

async fn report_click(
    State(engine): Checkin,
    Path(request_id): Path<String>,
    body: Bytes,
) -> Response {
    done(json(&body).and_then(|body| engine.report_click(&request_id, &body)))
}

async fn export_rule(State(engine): Checkin, Path(id): Path<String>) -> Response {
    answer(engine.export_rule(&id))
}

fn rule_text(body: &Bytes) -> Result<String, CheckinError> {
    json(body)?
        .get("text")
        .and_then(Value::as_str)
        .map(str::to_string)
        .ok_or_else(|| CheckinError::invalid("请求里没有规则内容。"))
}

async fn check_rule(State(engine): Checkin, body: Bytes) -> Response {
    answer(rule_text(&body).map(|text| engine.check_rule(&text)))
}

async fn import_rule(
    State(engine): Checkin,
    Query(reveal): Query<Reveal>,
    body: Bytes,
) -> Response {
    answer(rule_text(&body).and_then(|text| engine.import_rule(&text, reveal.on())))
}

// ---- streams ----

/// `Some` when the request asks for a WebSocket.
struct MaybeWs(Option<WebSocketUpgrade>);

impl<S: Send + Sync> FromRequestParts<S> for MaybeWs {
    type Rejection = std::convert::Infallible;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let wanted = parts
            .headers
            .get(header::UPGRADE)
            .and_then(|v| v.to_str().ok())
            .is_some_and(|v| v.eq_ignore_ascii_case("websocket"));
        if !wanted {
            return Ok(Self(None));
        }
        Ok(Self(
            WebSocketUpgrade::from_request_parts(parts, state)
                .await
                .ok(),
        ))
    }
}

fn line<T: serde::Serialize>(value: &T) -> String {
    let mut text = serde_json::to_string(value).unwrap_or_else(|_| "{}".to_string());
    text.push('\n');
    text
}

fn ndjson(
    stream: impl futures::Stream<Item = Result<String, std::convert::Infallible>> + Send + 'static,
) -> Response {
    Response::builder()
        .header(header::CONTENT_TYPE, "application/x-ndjson")
        .header(header::CACHE_CONTROL, "no-store")
        .body(Body::from_stream(stream))
        .expect("valid stream response")
}

/// The snapshot now, then again after every change. WebSocket text frames,
/// or one JSON object per line (empty lines are keep-alives).
async fn events(
    State(engine): Checkin,
    Query(reveal): Query<Reveal>,
    MaybeWs(ws): MaybeWs,
) -> Response {
    let reveal = reveal.on();
    let mut changes = engine.changes();
    changes.mark_unchanged();
    if let Some(ws) = ws {
        return ws.on_upgrade(move |mut socket| async move {
            let mut first = true;
            loop {
                if !first {
                    tokio::select! {
                        changed = changes.changed() => if changed.is_err() { break },
                        alive = idle(&mut socket) => if alive { continue } else { break },
                    }
                }
                first = false;
                let text = serde_json::to_string(&engine.snapshot(reveal)).unwrap_or_default();
                if socket.send(Message::Text(text.into())).await.is_err() {
                    break;
                }
            }
        });
    }
    let stream = futures::stream::unfold(
        (engine, changes, true),
        move |(engine, mut changes, first)| async move {
            if !first {
                match tokio::time::timeout(KEEP_ALIVE, changes.changed()).await {
                    Ok(Ok(())) => {}
                    Ok(Err(_)) => return None,
                    Err(_) => return Some((Ok("\n".to_string()), (engine, changes, false))),
                }
            }
            let text = line(&engine.snapshot(reveal));
            Some((Ok(text), (engine, changes, false)))
        },
    );
    ndjson(stream)
}

/// Waits on an idle WebSocket: `true` after a quiet [`KEEP_ALIVE`] (a ping
/// was sent) or a frame from the client, `false` once the client is gone.
async fn idle(socket: &mut WebSocket) -> bool {
    match tokio::time::timeout(KEEP_ALIVE, socket.recv()).await {
        Ok(Some(Ok(Message::Close(_))) | Some(Err(_)) | None) => false,
        Ok(Some(Ok(_))) => true,
        Err(_) => socket.send(Message::Ping(Vec::new().into())).await.is_ok(),
    }
}

/// Click requests for the app. Holding this stream open is what "an app
/// is attached" means: without one, click steps are `needs_app`.
async fn clicks(State(engine): Checkin, MaybeWs(ws): MaybeWs) -> Response {
    let mut sub: ClickSubscription = engine.clicks().subscribe();
    if let Some(ws) = ws {
        return ws.on_upgrade(move |mut socket| async move {
            loop {
                tokio::select! {
                    request = sub.next() => {
                        let Some(request) = request else { break };
                        let text = serde_json::to_string(&request).unwrap_or_default();
                        if socket.send(Message::Text(text.into())).await.is_err() {
                            break;
                        }
                    }
                    alive = idle(&mut socket) => if !alive { break },
                }
            }
        });
    }
    let stream = futures::stream::unfold(sub, |mut sub| async move {
        match tokio::time::timeout(KEEP_ALIVE, sub.next()).await {
            Ok(Some(request)) => Some((Ok(line(&request)), sub)),
            Ok(None) => None,
            Err(_) => Some((Ok("\n".to_string()), sub)),
        }
    });
    ndjson(stream)
}
