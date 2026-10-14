//! `/checkin/web` and the listener behind it: the built-in page of 签到助手
//! leaves through one loopback listener whose connections all take the
//! route the app last set. The only network is loopback.

use axum::body::Body;
use axum::http::{Method, Request, StatusCode};
use dashmap::DashMap;
use http_body_util::BodyExt;
use meow_api::checkin::{TunnelConnector, WebRoute, WEB_INBOUND};
use meow_api::routes::{create_router_with_checkin, AppState};
use meow_checkin::{Engine, EngineConfig, SystemClock};
use meow_common::DnsMode;
use meow_config::raw::RawConfig;
use meow_dns::Resolver;
use meow_listener::MixedListener;
use meow_trie::DomainTrie;
use meow_tunnel::Tunnel;
use parking_lot::RwLock;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::broadcast;
use tower::ServiceExt;

struct Rig {
    app: axum::Router,
    web: Arc<WebRoute>,
    tunnel: Tunnel,
    _dir: tempfile::TempDir,
}

/// The API over a tunnel with the built-in proxies (`DIRECT`, `REJECT`, …)
/// and `rules`. The listener is not started: see [`Rig::listen`].
fn rig_with(secret: Option<&str>, rules: &[&str]) -> Rig {
    let resolver = Arc::new(Resolver::new(
        vec!["8.8.8.8:53".parse().unwrap()],
        vec![],
        DnsMode::Normal,
        DomainTrie::new(),
        true,
        true,
    ));
    let tunnel = Tunnel::new(resolver);
    let raw = RawConfig {
        mode: Some("rule".into()),
        rules: Some(rules.iter().map(|r| (*r).to_string()).collect()),
        ..Default::default()
    };
    let meow_config::RebuildResult { proxies, rules, .. } =
        meow_config::rebuild_from_raw(&raw).unwrap();
    tunnel.update_proxies(proxies, Default::default());
    tunnel.update_rules(rules);

    let dir = tempfile::tempdir().unwrap();
    let engine = Engine::open(
        dir.path().join("checkin"),
        Arc::new(TunnelConnector::new(tunnel.clone())),
        Arc::new(SystemClock),
        EngineConfig::default(),
    );
    let state = Arc::new(AppState {
        tunnel: tunnel.clone(),
        secret: secret.map(str::to_string),
        config_path: None,
        raw_config: Arc::new(RwLock::new(raw)),
        log_tx: broadcast::channel(16).0,
        proxy_providers: Arc::new(DashMap::new()),
        provider_dialer_registry: Default::default(),
        rule_providers: Arc::new(RwLock::new(HashMap::new())),
        rule_provider_refresh: Default::default(),
        proxy_provider_refresh: Default::default(),
        listeners: vec![],
        external_ui: None,
        traffic_feed: Default::default(),
        config_commits: Default::default(),
        dns_server: Default::default(),
    });
    let web = WebRoute::new();
    Rig {
        app: create_router_with_checkin(state, Some(engine), Some(Arc::clone(&web))),
        web,
        tunnel,
        _dir: dir,
    }
}

impl Rig {
    /// Starts the listener the way the app binary does (`start_checkin_web`
    /// in `meow-app`): loopback, a port the system picks, stamped.
    async fn listen(&self) -> SocketAddr {
        let socket = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let bound = socket.local_addr().unwrap();
        let route = Arc::clone(&self.web);
        let listener = MixedListener::new(self.tunnel.clone(), bound, WEB_INBOUND.to_string())
            .loopback_only()
            .with_stamp(Arc::new(move |metadata| route.stamp(metadata)));
        self.web.set_address(bound);
        tokio::spawn(async move {
            let _ = listener.run_on(socket).await;
        });
        bound
    }

    async fn call_as(
        &self,
        method: Method,
        body: Option<Value>,
        headers: &[(&str, &str)],
    ) -> (StatusCode, Value) {
        let mut req = Request::builder().method(method).uri("/checkin/web");
        for (name, value) in headers {
            req = req.header(*name, *value);
        }
        let req = req
            .body(body.map_or_else(Body::empty, |b| Body::from(b.to_string())))
            .unwrap();
        let resp = self.app.clone().oneshot(req).await.unwrap();
        let status = resp.status();
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        (
            status,
            serde_json::from_slice(&bytes).unwrap_or(Value::Null),
        )
    }

    async fn get(&self) -> Value {
        let (status, value) = self.call_as(Method::GET, None, &[]).await;
        assert_eq!(status, StatusCode::OK, "{value}");
        value
    }

    async fn put(&self, body: Value) -> Value {
        let (status, value) = self.call_as(Method::PUT, Some(body), &[]).await;
        assert_eq!(status, StatusCode::OK, "{value}");
        value
    }
}

/// Echoes every connection until the client closes.
async fn echo_server() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                let (mut r, mut w) = stream.split();
                let _ = tokio::io::copy(&mut r, &mut w).await;
            });
        }
    });
    addr
}

/// Answers every request `200` with the body `hello`, then closes.
async fn http_server() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut buf = [0u8; 2048];
                let _ = stream.read(&mut buf).await;
                let _ = stream
                    .write_all(
                        b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\nhello",
                    )
                    .await;
            });
        }
    });
    addr
}

/// `CONNECT target` through the listener, then one `ping`: whether it came
/// back. A refused route answers the `CONNECT` and then closes.
async fn echoes(proxy: SocketAddr, target: SocketAddr) -> bool {
    let work = async {
        let mut stream = TcpStream::connect(proxy).await.unwrap();
        stream
            .write_all(format!("CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n").as_bytes())
            .await
            .unwrap();
        let mut head = Vec::new();
        let mut byte = [0u8; 1];
        while !head.ends_with(b"\r\n\r\n") {
            match stream.read(&mut byte).await {
                Ok(1) => head.push(byte[0]),
                _ => return false,
            }
        }
        if !head.starts_with(b"HTTP/1.1 200") {
            return false;
        }
        if stream.write_all(b"ping").await.is_err() {
            return false;
        }
        let mut back = [0u8; 4];
        stream.read_exact(&mut back).await.is_ok() && &back == b"ping"
    };
    tokio::time::timeout(Duration::from_secs(10), work)
        .await
        .expect("the listener neither relayed nor closed")
}

/// A plain `GET http://target/` through the listener: the whole answer.
async fn plain_get(proxy: SocketAddr, target: SocketAddr) -> String {
    let work = async {
        let mut stream = TcpStream::connect(proxy).await.unwrap();
        stream
            .write_all(
                format!("GET http://{target}/ HTTP/1.1\r\nHost: {target}\r\n\r\n").as_bytes(),
            )
            .await
            .unwrap();
        let mut answer = Vec::new();
        let _ = stream.read_to_end(&mut answer).await;
        String::from_utf8_lossy(&answer).into_owned()
    };
    tokio::time::timeout(Duration::from_secs(10), work)
        .await
        .expect("the listener neither answered nor closed")
}

#[tokio::test]
async fn the_route_starts_as_the_rules_and_reports_the_listener() {
    let rig = rig_with(None, &["MATCH,DIRECT"]);
    assert_eq!(
        rig.get().await,
        json!({"address": null, "access": "proxy", "policy": null, "policy_known": true})
    );
    let addr = rig.listen().await;
    assert!(addr.ip().is_loopback());
    assert_eq!(rig.get().await["address"], json!(addr.to_string()));
}

#[tokio::test]
async fn put_sets_the_route_and_says_whether_the_policy_exists() {
    let rig = rig_with(None, &["MATCH,DIRECT"]);
    assert_eq!(
        rig.put(json!({"access": "proxy", "policy": "REJECT"}))
            .await,
        json!({"address": null, "access": "proxy", "policy": "REJECT", "policy_known": true})
    );
    assert_eq!(rig.get().await["policy"], "REJECT");
    // An unknown name is taken, and said to be unknown.
    let answer = rig
        .put(json!({"access": "proxy", "policy": "没有这条"}))
        .await;
    assert_eq!(answer["policy"], "没有这条");
    assert_eq!(answer["policy_known"], false);
    // Direct drops the policy; an empty name is no policy.
    assert_eq!(
        rig.put(json!({"access": "direct", "policy": "REJECT"}))
            .await,
        json!({"address": null, "access": "direct", "policy": null, "policy_known": true})
    );
    assert_eq!(
        rig.put(json!({"access": "proxy", "policy": "  "})).await,
        json!({"address": null, "access": "proxy", "policy": null, "policy_known": true})
    );
}

#[tokio::test]
async fn put_refuses_what_is_not_a_route() {
    let rig = rig_with(None, &["MATCH,DIRECT"]);
    rig.put(json!({"access": "proxy", "policy": "REJECT"}))
        .await;
    for body in [
        json!({}),
        json!({"access": "tun"}),
        json!({"access": "proxy", "policy": 7}),
    ] {
        let (status, value) = rig.call_as(Method::PUT, Some(body), &[]).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{value}");
        assert!(value["error"].is_string());
    }
    // A refused call changed nothing.
    assert_eq!(rig.get().await["policy"], "REJECT");
}

#[tokio::test]
async fn the_route_is_behind_the_secret_and_closed_to_other_pages() {
    let rig = rig_with(Some("s3cret"), &["MATCH,DIRECT"]);
    let (status, _) = rig.call_as(Method::GET, None, &[]).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let auth = ("authorization", "Bearer s3cret");
    let (status, _) = rig.call_as(Method::GET, None, &[auth]).await;
    assert_eq!(status, StatusCode::OK);
    let (status, _) = rig
        .call_as(
            Method::PUT,
            Some(json!({"access": "direct"})),
            &[auth, ("origin", "https://evil.example")],
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let (_, value) = rig.call_as(Method::GET, None, &[auth]).await;
    assert_eq!(value["access"], "proxy");
}

#[tokio::test]
async fn rules_route_goes_through_rule_matching() {
    let echo = echo_server().await;
    let direct = rig_with(None, &["MATCH,DIRECT"]);
    assert!(echoes(direct.listen().await, echo).await);
    let reject = rig_with(None, &["MATCH,REJECT"]);
    assert!(!echoes(reject.listen().await, echo).await);
}

#[tokio::test]
async fn direct_route_connects_whatever_the_rules_say() {
    let echo = echo_server().await;
    let rig = rig_with(None, &["MATCH,REJECT"]);
    let proxy = rig.listen().await;
    assert!(!echoes(proxy, echo).await);
    rig.put(json!({"access": "direct"})).await;
    assert!(echoes(proxy, echo).await);
    // The plain-HTTP path of the listener is stamped as well.
    let answer = plain_get(proxy, http_server().await).await;
    assert!(answer.ends_with("hello"), "{answer}");
    // Back to the rules: the next connection is refused again.
    rig.put(json!({"access": "proxy"})).await;
    assert!(!echoes(proxy, echo).await);
}

#[tokio::test]
async fn policy_route_uses_the_named_proxy_and_refuses_an_unknown_one() {
    let echo = echo_server().await;
    let rig = rig_with(None, &["MATCH,DIRECT"]);
    let proxy = rig.listen().await;
    assert!(echoes(proxy, echo).await);

    rig.put(json!({"access": "proxy", "policy": "REJECT"}))
        .await;
    assert!(!echoes(proxy, echo).await);
    let answer = plain_get(proxy, http_server().await).await;
    assert!(!answer.contains("hello"), "{answer}");

    // Not handed to the rules (which would connect).
    rig.put(json!({"access": "proxy", "policy": "nope"})).await;
    assert!(!echoes(proxy, echo).await);

    rig.put(json!({"access": "proxy", "policy": "DIRECT"}))
        .await;
    assert!(echoes(proxy, echo).await);
}

#[tokio::test]
async fn the_listener_serves_loopback_only() {
    let rig = rig_with(None, &["MATCH,DIRECT"]);
    let socket = TcpListener::bind("0.0.0.0:0").await.unwrap();
    let bound = socket.local_addr().unwrap();
    let listener =
        MixedListener::new(rig.tunnel.clone(), bound, WEB_INBOUND.to_string()).loopback_only();
    let refused = tokio::time::timeout(Duration::from_secs(5), listener.run_on(socket))
        .await
        .expect("a loopback-only listener must not serve a wildcard socket");
    assert!(refused.is_err());
}
