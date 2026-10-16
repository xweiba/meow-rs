//! PaoPao's route API in the core (Dart `RouteApiServer`), so programs and
//! phones keep reaching it with the app closed. Same address, key and
//! answers as the app's:
//!
//! - `GET /v1/policies` → `{"running": true, "policies": [{id, name,
//!   kind}]}`;
//! - `GET /v1/proxy?policy=<id>` → `{policy, host, port, username,
//!   password, socks5, http}` (the core's `mixed-port`, the policy as the
//!   proxy user); `404` an unknown id, `409` no port;
//! - both with `Authorization: Bearer <key>` (`401` without, `405` for
//!   anything but GET);
//! - `/v1/location.json?key=<key>`: 虚拟定位's config for the location
//!   script (the point the scripts' store holds, `enabled` as the module
//!   is); `404` while there is none;
//! - `/ca.mobileconfig`, `/ca.crt`, `/ca.pem`: the MITM certificate for
//!   phones, no key (`404` before there is one).
//!
//! `PUT /paopao/route` `{port, key, lan, policies?}` hands it over: kept in
//! `route.json` (owner-only: the key), listened on at once (loopback, or
//! every address with `lan`) and again whenever the core starts. The
//! policies are those of the config built last (`policies.json`: the app's,
//! then each one built here). `DELETE` stops it and forgets it.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;

use axum::{
    body::Body,
    extract::{Query, Request, State},
    http::{header, Method, StatusCode},
    response::{IntoResponse, Response},
    Router,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::HashMap;

use super::service::Service;
use super::store::{write_atomic, Store};
use super::track;

/// `route.json`: where the API listens and its key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RouteConf {
    pub port: u16,
    pub key: String,
    #[serde(default)]
    pub lan: bool,
}

impl RouteConf {
    pub fn read(store: &Store) -> Option<Self> {
        std::fs::read(store.route())
            .ok()
            .and_then(|b| serde_json::from_slice(&b).ok())
    }

    pub fn write(&self, store: &Store) -> std::io::Result<()> {
        let bytes = serde_json::to_vec(self).map_err(std::io::Error::other)?;
        write_atomic(&store.route(), &bytes, true)
    }

    fn addr(&self) -> SocketAddr {
        let ip = if self.lan {
            IpAddr::V4(Ipv4Addr::UNSPECIFIED)
        } else {
            IpAddr::V4(Ipv4Addr::LOCALHOST)
        };
        SocketAddr::new(ip, self.port)
    }
}

/// The route API listening now.
pub(super) struct Listening {
    pub conf: RouteConf,
    pub addr: SocketAddr,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for Listening {
    fn drop(&mut self) {
        self.task.abort();
    }
}

/// The policies offered (`policies.json`, `{id, name, target, kind}`).
pub fn policies(store: &Store) -> Vec<Value> {
    std::fs::read(store.policies())
        .ok()
        .and_then(|b| serde_json::from_slice::<Vec<Value>>(&b).ok())
        .unwrap_or_default()
}

impl Service {
    /// Listens as `conf` says (an older listener stopped first). The
    /// address it took, or why it could not.
    pub async fn listen_route(self: &Arc<Self>, conf: RouteConf) -> Result<SocketAddr, String> {
        // The same port again: the old one must let go first; another
        // port is taken before the old one is given up.
        let same_port = self
            .route_listener()
            .lock()
            .as_ref()
            .is_some_and(|l| l.addr.port() == conf.port);
        if same_port {
            self.route_listener().lock().take();
        }
        let listener = tokio::net::TcpListener::bind(conf.addr())
            .await
            .map_err(|e| format!("cannot listen on {}: {e}", conf.addr()))?;
        let addr = listener.local_addr().map_err(|e| e.to_string())?;
        let app = Router::new().fallback(handle).with_state(Arc::clone(self));
        let task = tokio::spawn(async move {
            if let Err(e) = axum::serve(listener, app).await {
                tracing::warn!("paopao route API: {e}");
            }
        });
        tracing::info!("PaoPao route API listening on {addr}");
        *self.route_listener().lock() = Some(Listening { conf, addr, task });
        Ok(addr)
    }

    /// Stops the route API.
    pub fn stop_route(&self) {
        self.route_listener().lock().take();
    }

    /// Where it listens and with what, if it does.
    pub fn route_now(&self) -> Option<(RouteConf, SocketAddr)> {
        self.route_listener()
            .lock()
            .as_ref()
            .map(|l| (l.conf.clone(), l.addr))
    }
}

/// Listens as `route.json` says, when it says anything (the core's start).
pub async fn start_route(svc: Arc<Service>) {
    if let Some(conf) = RouteConf::read(svc.store()) {
        if let Err(e) = svc.listen_route(conf).await {
            tracing::warn!("paopao route API: {e}");
        }
    }
}

fn send(status: StatusCode, body: &Value) -> Response {
    (
        status,
        [(header::CONTENT_TYPE, "application/json; charset=utf-8")],
        body.to_string(),
    )
        .into_response()
}

fn error(status: StatusCode, why: &str) -> Response {
    send(status, &json!({ "error": why }))
}

/// The first certificate of `pem` in DER (Dart `pemToDer`).
pub fn pem_to_der(pem: &str) -> Vec<u8> {
    use base64::Engine as _;
    let body = pem
        .split_once("-----BEGIN CERTIFICATE-----")
        .and_then(|(_, rest)| rest.split_once("-----END CERTIFICATE-----"))
        .map_or("", |(b, _)| b);
    let clean: String = body.chars().filter(|c| !c.is_whitespace()).collect();
    base64::engine::general_purpose::STANDARD
        .decode(clean)
        .unwrap_or_default()
}

fn uuid_upper() -> String {
    uuid::Uuid::new_v4().to_string().to_uppercase()
}

/// An iOS configuration profile carrying the CA certificate `der` (Dart
/// `mobileConfig`).
pub fn mobile_config(der: &[u8]) -> String {
    use base64::Engine as _;
    let data = base64::engine::general_purpose::STANDARD.encode(der);
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>PayloadContent</key>
  <array>
    <dict>
      <key>PayloadCertificateFileName</key><string>PaoPao-CA.cer</string>
      <key>PayloadContent</key><data>{data}</data>
      <key>PayloadDescription</key><string>PaoPao 根证书</string>
      <key>PayloadDisplayName</key><string>PaoPao CA</string>
      <key>PayloadIdentifier</key><string>app.paopao.ca.cert</string>
      <key>PayloadType</key><string>com.apple.security.root</string>
      <key>PayloadUUID</key><string>{}</string>
      <key>PayloadVersion</key><integer>1</integer>
    </dict>
  </array>
  <key>PayloadDescription</key><string>让虚拟定位和脚本模块能处理这台设备的 HTTPS 请求</string>
  <key>PayloadDisplayName</key><string>PaoPao 证书</string>
  <key>PayloadIdentifier</key><string>app.paopao.ca</string>
  <key>PayloadOrganization</key><string>PaoPao</string>
  <key>PayloadRemovalDisallowed</key><false/>
  <key>PayloadType</key><string>Configuration</string>
  <key>PayloadUUID</key><string>{}</string>
  <key>PayloadVersion</key><integer>1</integer>
</dict>
</plist>
"#,
        uuid_upper(),
        uuid_upper()
    )
}

/// One policy as programs see it (`RoutePolicy.toJson`: no target).
fn public(p: &Value) -> Value {
    json!({ "id": p.get("id"), "name": p.get("name"), "kind": p.get("kind") })
}

async fn handle(State(svc): State<Arc<Service>>, req: Request) -> Response {
    let path = req.uri().path().to_owned();
    let q: HashMap<String, String> =
        Query::try_from_uri(req.uri()).map_or_else(|_| HashMap::new(), |Query(q)| q);
    let headers = req.headers();
    let Some((conf, _)) = svc.route_now() else {
        return error(StatusCode::SERVICE_UNAVAILABLE, "not listening");
    };
    let key = conf.key.as_str();
    if matches!(path.as_str(), "/ca.mobileconfig" | "/ca.crt" | "/ca.pem") {
        let pem = tokio::fs::read_to_string(svc.store().home().join("mitm-ca.pem")).await;
        let Ok(pem) = pem else {
            return error(StatusCode::NOT_FOUND, "no certificate yet");
        };
        let der = pem_to_der(&pem);
        let (kind, body): (&str, Vec<u8>) = match path.as_str() {
            "/ca.mobileconfig" => (
                "application/x-apple-aspen-config",
                mobile_config(&der).into_bytes(),
            ),
            "/ca.crt" => ("application/x-x509-ca-cert", der),
            _ => ("application/x-pem-file", pem.into_bytes()),
        };
        let disposition = format!("attachment; filename=\"PaoPao-CA{}\"", &path[3..]);
        return (
            StatusCode::OK,
            [
                (header::CONTENT_TYPE, kind.to_owned()),
                (header::CONTENT_DISPOSITION, disposition),
            ],
            Body::from(body),
        )
            .into_response();
    }
    // loc.json is fetched by a script that can only give a URL.
    if path == "/v1/location.json"
        && !key.is_empty()
        && q.get("key").map(String::as_str) == Some(key)
    {
        return match track::location_config(&svc).await {
            Some(v) => send(StatusCode::OK, &v),
            None => error(StatusCode::NOT_FOUND, "virtual location is off"),
        };
    }
    let auth = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    if auth != format!("Bearer {key}") {
        return error(StatusCode::UNAUTHORIZED, "bad or missing key");
    }
    if req.method() != Method::GET {
        return error(StatusCode::METHOD_NOT_ALLOWED, "GET only");
    }
    let store = svc.store().clone();
    let all = tokio::task::spawn_blocking(move || policies(&store))
        .await
        .unwrap_or_default();
    match path.as_str() {
        "/v1/policies" => send(
            StatusCode::OK,
            &json!({ "running": true, "policies": all.iter().map(public).collect::<Vec<_>>() }),
        ),
        "/v1/proxy" => {
            let id = q.get("policy").cloned().unwrap_or_default();
            let Some(p) = all
                .iter()
                .find(|p| p.get("id").and_then(Value::as_str) == Some(id.as_str()))
            else {
                return error(StatusCode::NOT_FOUND, &format!("no policy \"{id}\""));
            };
            let Some(port) = svc.mixed_port() else {
                return error(StatusCode::CONFLICT, "the proxy is off");
            };
            let host = "127.0.0.1";
            send(
                StatusCode::OK,
                &json!({
                    "policy": public(p),
                    "host": host,
                    "port": port,
                    "username": id,
                    "password": key,
                    "socks5": format!("socks5://{id}:{key}@{host}:{port}"),
                    "http": format!("http://{id}:{key}@{host}:{port}"),
                }),
            )
        }
        _ => error(StatusCode::NOT_FOUND, "unknown path"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_certificate_as_der_and_as_a_profile() {
        use base64::Engine as _;
        let der = b"\x30\x82\x01\x02certificate";
        let b64 = base64::engine::general_purpose::STANDARD.encode(der);
        let pem = format!(
            "-----BEGIN CERTIFICATE-----\n{}\n{}\n-----END CERTIFICATE-----\n",
            &b64[..10],
            &b64[10..]
        );
        assert_eq!(pem_to_der(&pem), der);
        assert!(pem_to_der("junk").is_empty());
        let profile = mobile_config(der);
        assert!(profile.contains(&format!("<data>{b64}</data>")));
        assert!(profile.contains("<key>PayloadType</key><string>Configuration</string>"));
    }
}
