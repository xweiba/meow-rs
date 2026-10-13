//! `/checkin…`: the 签到助手 routes end to end — auth, JSON shapes, the
//! event and click streams, and requests leaving through the tunnel. The
//! only network is loopback: a scripted server on `127.0.0.1`.

use axum::body::Body;
use axum::http::{Method, Request, StatusCode};
use dashmap::DashMap;
use futures::StreamExt;
use http_body_util::BodyExt;
use meow_api::checkin::TunnelConnector;
use meow_api::routes::{create_router, create_router_with_checkin, AppState};
use meow_checkin::{Engine, EngineConfig, SystemClock};
use meow_common::DnsMode;
use meow_config::raw::RawConfig;
use meow_dns::Resolver;
use meow_trie::DomainTrie;
use meow_tunnel::Tunnel;
use parking_lot::{Mutex, RwLock};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::broadcast;
use tower::ServiceExt;

struct Rig {
    app: axum::Router,
    engine: Arc<Engine>,
    state: Arc<AppState>,
    _dir: tempfile::TempDir,
}

fn rig_with(secret: Option<&str>, rules: &[&str]) -> Rig {
    rig_full(secret, rules, true)
}

fn rig_full(secret: Option<&str>, rules: &[&str], allow_private: bool) -> Rig {
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
        EngineConfig {
            attach_wait: Duration::from_millis(80),
            click_timeout_ms: 500,
            // Generous: the reporting side of a test must never lose a race
            // against this on a busy machine.
            click_report_grace: Duration::from_secs(20),
            // The scripted site is on loopback.
            allow_private,
            ..EngineConfig::default()
        },
    );
    let state = Arc::new(AppState {
        tunnel,
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
    Rig {
        app: create_router_with_checkin(Arc::clone(&state), Some(Arc::clone(&engine))),
        engine,
        state,
        _dir: dir,
    }
}

fn rig() -> Rig {
    rig_with(None, &["MATCH,DIRECT"])
}

impl Rig {
    async fn call(&self, method: Method, path: &str, body: Option<Value>) -> (StatusCode, Value) {
        self.call_as(method, path, body, None).await
    }

    async fn call_as(
        &self,
        method: Method,
        path: &str,
        body: Option<Value>,
        bearer: Option<&str>,
    ) -> (StatusCode, Value) {
        let mut req = Request::builder().method(method).uri(path);
        if let Some(token) = bearer {
            req = req.header("authorization", format!("Bearer {token}"));
        }
        let req = req
            .body(body.map_or_else(Body::empty, |b| Body::from(b.to_string())))
            .unwrap();
        let resp = self.app.clone().oneshot(req).await.unwrap();
        let status = resp.status();
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        let value = if bytes.is_empty() {
            Value::Null
        } else {
            serde_json::from_slice(&bytes).unwrap_or_else(|_| {
                panic!("not JSON: {}", String::from_utf8_lossy(&bytes));
            })
        };
        (status, value)
    }

    async fn ok(&self, method: Method, path: &str, body: Option<Value>) -> Value {
        let (status, value) = self.call(method, path, body).await;
        assert!(status.is_success(), "{path}: {status} {value}");
        value
    }

    async fn new_task(&self, home: &str) -> String {
        let task = self
            .ok(
                Method::POST,
                "/checkin/tasks",
                Some(json!({"name": "主力机场", "home": home, "access": "direct",
                            "minute_of_day": 510, "enabled": true, "subscription_id": null})),
            )
            .await;
        task["id"].as_str().unwrap().to_string()
    }
}

/// A scripted site on loopback: answers `{"ret":1,"msg":"ok"}` and
/// remembers each request's first line and cookie.
async fn site() -> (SocketAddr, Arc<Mutex<Vec<(String, String)>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let log = Arc::clone(&seen);
    tokio::spawn(async move {
        loop {
            let Ok((mut sock, _)) = listener.accept().await else {
                return;
            };
            let log = Arc::clone(&log);
            tokio::spawn(async move {
                let mut buf = Vec::new();
                let mut tmp = [0u8; 4096];
                while !buf.windows(4).any(|w| w == b"\r\n\r\n") {
                    match sock.read(&mut tmp).await {
                        Ok(n) if n > 0 => buf.extend_from_slice(&tmp[..n]),
                        _ => return,
                    }
                }
                let head = String::from_utf8_lossy(&buf).to_string();
                let first = head.lines().next().unwrap_or("").to_string();
                let cookie = head
                    .lines()
                    .find_map(|l| l.strip_prefix("cookie: "))
                    .unwrap_or("")
                    .to_string();
                log.lock().push((first, cookie));
                let body = r#"{"ret":1,"msg":"ok"}"#;
                let reply = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
                    body.len()
                );
                let _ = sock.write_all(reply.as_bytes()).await;
                let _ = sock.shutdown().await;
            });
        }
    });
    (addr, seen)
}

fn api_step(url: &str, page: &str) -> Value {
    json!({"id": "", "kind": "api", "name": "签到", "method": "POST", "url": url,
           "headers": {"cookie": "{cookie}"}, "body": "a=1", "body_base64": false,
           "page": page, "recorded_status": 200,
           "recorded_content_type": "application/json"})
}

async fn finished_run(rig: &Rig, task_id: &str) -> Value {
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let snap = rig.ok(Method::GET, "/checkin", None).await;
            let run = snap["runs"]
                .as_array()
                .unwrap()
                .iter()
                .find(|r| r["task_id"] == task_id && !r["finished_at"].is_null())
                .cloned();
            if let Some(run) = run {
                return run;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("the run did not finish")
}

#[tokio::test]
async fn the_routes_exist_only_when_an_engine_is_given() {
    let r = rig();
    let plain = create_router(Arc::clone(&r.state));
    let resp = plain
        .oneshot(Request::get("/checkin").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    let (status, snap) = r.call(Method::GET, "/checkin", None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        snap,
        json!({"tasks": [], "runs": [], "running_task_id": null, "queued_task_ids": []})
    );
}

#[tokio::test]
async fn every_route_needs_the_secret() {
    let r = rig_with(Some("hunter2"), &["MATCH,DIRECT"]);
    let cases: Vec<(Method, &str)> = vec![
        (Method::GET, "/checkin"),
        (Method::GET, "/checkin/events"),
        (Method::GET, "/checkin/clicks"),
        (Method::POST, "/checkin/tasks"),
        (Method::PATCH, "/checkin/tasks/t1"),
        (Method::DELETE, "/checkin/tasks/t1"),
        (Method::PUT, "/checkin/tasks/order"),
        (Method::PUT, "/checkin/tasks/t1/steps"),
        (Method::PUT, "/checkin/tasks/t1/variables/cookie"),
        (Method::DELETE, "/checkin/tasks/t1/variables/cookie"),
        (Method::POST, "/checkin/tasks/t1/variables/values"),
        (Method::POST, "/checkin/tasks/t1/run"),
        (Method::POST, "/checkin/run"),
        (Method::POST, "/checkin/clicks/c1"),
        (Method::GET, "/checkin/tasks/t1/rule"),
        (Method::POST, "/checkin/rules/check"),
        (Method::POST, "/checkin/rules/import"),
    ];
    for (method, path) in cases {
        let (status, _) = r.call(method.clone(), path, Some(json!({}))).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "{method} {path}");
        let (status, _) = r
            .call_as(method.clone(), path, Some(json!({})), Some("wrong"))
            .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "{method} {path}");
    }
    // Nothing was created or attached by the refused calls.
    assert!(r.engine.snapshot(false).tasks.is_empty());
    assert_eq!(r.engine.clicks().attached(), 0);
    let (status, _) = r
        .call_as(Method::GET, "/checkin", None, Some("hunter2"))
        .await;
    assert_eq!(status, StatusCode::OK);
}

#[tokio::test]
async fn tasks_steps_and_variables_through_the_api() {
    let r = rig();
    let id = r.new_task("https://main.example.com/user").await;

    let task = r
        .ok(
            Method::PATCH,
            &format!("/checkin/tasks/{id}"),
            Some(json!({"access": "proxy", "minute_of_day": 600})),
        )
        .await;
    assert_eq!(task["access"], "proxy");
    assert_eq!(task["minute_of_day"], 600);
    assert_eq!(task["name"], "主力机场");
    assert_eq!(task["enabled"], true);

    let task = r
        .ok(
            Method::PUT,
            &format!("/checkin/tasks/{id}/variables/cookie"),
            Some(
                json!({"name": "cookie", "source": "auto", "from": "cookie_header",
                        "key": null, "url": "https://main.example.com/"}),
            ),
        )
        .await;
    assert_eq!(
        task["variables"],
        json!([{"name": "cookie", "source": "auto", "from": "cookie_header", "key": null,
                "url": "https://main.example.com/", "has_value": false, "updated_at": null}])
    );
    // A variable may be called `values`: PUT and DELETE on that name are
    // the variable, POST is the push.
    r.ok(
        Method::PUT,
        &format!("/checkin/tasks/{id}/variables/values"),
        Some(json!({"name": "values", "source": "manual", "value": "MANUALSECRET"})),
    )
    .await;
    let (status, _) = r
        .call(
            Method::POST,
            &format!("/checkin/tasks/{id}/variables/values"),
            Some(
                json!({"task_id": id, "values": {"cookie": "sid=COOKIESECRET"},
                        "user_agent": "Mozilla/5.0 Test"}),
            ),
        )
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let (status, _) = r
        .call(
            Method::POST,
            &format!("/checkin/tasks/{id}/variables/cookie"),
            Some(json!({})),
        )
        .await;
    assert_eq!(status, StatusCode::METHOD_NOT_ALLOWED);

    // Read back: no auto value anywhere, the manual one masked…
    let snap = r.ok(Method::GET, "/checkin", None).await;
    let text = snap.to_string();
    assert!(!text.contains("COOKIESECRET"));
    assert!(!text.contains("MANUALSECRET"));
    assert!(!text.contains("Mozilla/5.0 Test"));
    let vars = &snap["tasks"][0]["variables"];
    assert_eq!(vars[0]["has_value"], true);
    assert!(vars[0].get("value").is_none());
    assert_eq!(vars[1]["value"], "••••••");
    assert_eq!(vars[1]["masked"], true);
    // …unless asked for; an auto value still never.
    let snap = r.ok(Method::GET, "/checkin?manual_values=1", None).await;
    assert_eq!(snap["tasks"][0]["variables"][1]["value"], "MANUALSECRET");
    assert!(!snap.to_string().contains("COOKIESECRET"));

    let task = r
        .ok(
            Method::DELETE,
            &format!("/checkin/tasks/{id}/variables/values"),
            None,
        )
        .await;
    assert_eq!(task["variables"].as_array().unwrap().len(), 1);

    let task = r
        .ok(
            Method::PUT,
            &format!("/checkin/tasks/{id}/steps"),
            Some(json!({"steps": [
                api_step("https://main.example.com/user/checkin", "https://main.example.com/user"),
                {"id": "", "kind": "click", "name": "领取流量包",
                 "page": "https://main.example.com/user",
                 "locators": [{"kind": "role_text", "value": "领取流量包"}],
                 "text": "领取流量包", "tag": "button"},
                {"id": "", "kind": "from_the_future"}
            ]})),
        )
        .await;
    let steps = task["steps"].as_array().unwrap();
    assert_eq!(steps.len(), 2);
    assert!(steps.iter().all(|s| !s["id"].as_str().unwrap().is_empty()));
    assert_eq!(steps[0]["headers"], json!({"cookie": "{cookie}"}));

    // Order.
    let second = r.new_task("https://second.example.com/").await;
    let (status, _) = r
        .call(
            Method::PUT,
            "/checkin/tasks/order",
            Some(json!({"task_ids": [second, id]})),
        )
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let snap = r.ok(Method::GET, "/checkin", None).await;
    assert_eq!(snap["tasks"][0]["id"], second.as_str());

    let (status, _) = r
        .call(Method::DELETE, &format!("/checkin/tasks/{second}"), None)
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let snap = r.ok(Method::GET, "/checkin", None).await;
    assert_eq!(snap["tasks"].as_array().unwrap().len(), 1);
}

#[tokio::test]
async fn refusals_are_a_status_and_one_sentence() {
    let r = rig();
    let id = r.new_task("https://main.example.com/user").await;
    let cases: Vec<(Method, String, Option<Value>, StatusCode)> = vec![
        (
            Method::PATCH,
            "/checkin/tasks/nope".into(),
            Some(json!({"name": "x"})),
            StatusCode::NOT_FOUND,
        ),
        (
            Method::POST,
            "/checkin/tasks".into(),
            Some(json!({"name": "x", "home": "javascript:alert(1)"})),
            StatusCode::BAD_REQUEST,
        ),
        (
            Method::POST,
            "/checkin/tasks".into(),
            Some(json!([1, 2])),
            StatusCode::BAD_REQUEST,
        ),
        (
            Method::PATCH,
            format!("/checkin/tasks/{id}"),
            Some(json!({"minute_of_day": 5000})),
            StatusCode::BAD_REQUEST,
        ),
        (
            Method::PUT,
            format!("/checkin/tasks/{id}/variables/x"),
            Some(json!({"name": "bad name", "source": "manual"})),
            StatusCode::BAD_REQUEST,
        ),
        (
            Method::PUT,
            format!("/checkin/tasks/{id}/steps"),
            Some(json!({"steps": [{"kind": "api", "method": "GET",
                "url": "https://a.example/", "page": "https://a.example/",
                "headers": {"x-a": "1\r\nx-evil: 1"}}]})),
            StatusCode::BAD_REQUEST,
        ),
        (
            Method::PUT,
            format!("/checkin/tasks/{id}/steps"),
            Some(
                json!({"steps": vec![json!({"kind": "click", "page": "https://a.example/"}); 51]}),
            ),
            StatusCode::PAYLOAD_TOO_LARGE,
        ),
        (
            Method::POST,
            "/checkin/clicks/c404".into(),
            Some(json!({"request_id": "c404", "step_id": "s1", "found": true})),
            StatusCode::NOT_FOUND,
        ),
        (
            Method::POST,
            "/checkin/rules/import".into(),
            Some(json!({"text": "not a rule"})),
            StatusCode::BAD_REQUEST,
        ),
        (
            Method::POST,
            "/checkin/rules/import".into(),
            Some(json!({})),
            StatusCode::BAD_REQUEST,
        ),
        (
            Method::GET,
            "/checkin/tasks/nope/rule".into(),
            None,
            StatusCode::NOT_FOUND,
        ),
    ];
    for (method, path, body, expected) in cases {
        let (status, value) = r.call(method.clone(), &path, body).await;
        assert_eq!(status, expected, "{method} {path}: {value}");
        let sentence = value["error"].as_str().unwrap_or_else(|| {
            panic!("{method} {path}: no error sentence in {value}");
        });
        assert!(!sentence.is_empty());
    }
    // A body that is not JSON at all.
    let resp = r
        .app
        .clone()
        .oneshot(
            Request::post("/checkin/tasks")
                .body(Body::from("{not json"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let value: Value = serde_json::from_slice(&bytes).unwrap();
    assert!(value["error"].is_string());

    // An unfilled manual variable refuses the run with the sentence.
    r.ok(
        Method::PUT,
        &format!("/checkin/tasks/{id}/variables/uid"),
        Some(json!({"name": "uid", "source": "manual"})),
    )
    .await;
    let (status, value) = r
        .call(
            Method::POST,
            &format!("/checkin/tasks/{id}/run"),
            Some(json!({"trial": false})),
        )
        .await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert!(value["error"].as_str().unwrap().contains("uid"));
}

#[tokio::test]
async fn rules_through_the_api() {
    let r = rig();
    let rule = json!({
        "paopao_checkin_rule": 1, "name": "主力机场",
        "home": "https://main.example.com/user", "access": "proxy", "minute_of_day": 510,
        "enabled": true, "surprise": 1,
        "variables": [
            {"name": "cookie", "source": "auto", "from": "cookie_header",
             "url": "https://main.example.com/", "value": "sid=planted"},
            {"name": "uid", "source": "manual"}
        ],
        "steps": [
            {"kind": "api", "name": "签到", "method": "POST",
             "url": "https://main.example.com/user/checkin?u={uid}",
             "headers": {"cookie": "{cookie}"}, "body": null, "body_base64": false,
             "page": "https://main.example.com/user", "recorded_status": 200,
             "recorded_content_type": "application/json"},
            {"kind": "api", "name": "上报", "method": "GET",
             "url": "https://collector.example/c", "page": "https://main.example.com/user"}
        ]
    });
    let check = r
        .ok(
            Method::POST,
            "/checkin/rules/check",
            Some(json!({"text": rule.to_string()})),
        )
        .await;
    assert_eq!(check["ok"], true);
    assert_eq!(check["error"], Value::Null);
    assert_eq!(check["name"], "主力机场");
    assert_eq!(check["home"], "https://main.example.com/user");
    assert_eq!(check["steps"].as_array().unwrap().len(), 2);
    assert_eq!(check["steps"][0]["id"], "");
    let codes: Vec<&str> = check["warnings"]
        .as_array()
        .unwrap()
        .iter()
        .map(|w| w["code"].as_str().unwrap())
        .collect();
    assert_eq!(codes, ["unknown_field", "cross_site", "manual_variables"]);
    assert_eq!(check["warnings"][0]["detail"], "surprise");
    assert_eq!(check["warnings"][1]["detail"], "collector.example");
    assert!(check["warnings"][1]["message"]
        .as_str()
        .unwrap()
        .contains("collector.example"));
    // Checking creates nothing.
    assert!(r.engine.snapshot(false).tasks.is_empty());

    // Something that is not a rule: 200 with ok false and a sentence.
    let (status, bad) = r
        .call(
            Method::POST,
            "/checkin/rules/check",
            Some(json!({"text": "{\"paopao_checkin_rule\": 1, \"home\": \"file:///etc\"}"})),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(bad["ok"], false);
    assert!(bad["error"].is_string());

    let task = r
        .ok(
            Method::POST,
            "/checkin/rules/import",
            Some(json!({"text": rule.to_string()})),
        )
        .await;
    assert_eq!(task["enabled"], false);
    assert_eq!(task["access"], "proxy");
    assert_eq!(task["variables"][0]["has_value"], false);
    let id = task["id"].as_str().unwrap();

    let export = r
        .ok(Method::GET, &format!("/checkin/tasks/{id}/rule"), None)
        .await;
    assert_eq!(export["file_name"], "主力机场.checkin.json");
    assert!(export["link"]
        .as_str()
        .unwrap()
        .starts_with("paopao://checkin/rule?d="));
    let text: Value = serde_json::from_str(export["text"].as_str().unwrap()).unwrap();
    assert_eq!(text["paopao_checkin_rule"], 1);
    assert!(text.get("enabled").is_none() && text.get("surprise").is_none());
    assert!(!export.to_string().contains("planted"));
    // The link reads back as the same rule.
    let again = r
        .ok(
            Method::POST,
            "/checkin/rules/check",
            Some(json!({"text": export["link"]})),
        )
        .await;
    assert_eq!(again["ok"], true);
    assert_eq!(again["steps"], check["steps"]);
}

#[tokio::test]
async fn a_direct_task_goes_out_whatever_the_rules_say() {
    // Every rule says REJECT; `direct` does not ask the rules.
    let r = rig_with(None, &["MATCH,REJECT"]);
    let _tasks = r.engine.start();
    let (addr, seen) = site().await;
    let home = format!("http://{addr}/user");
    let id = r.new_task(&home).await;
    r.ok(
        Method::PUT,
        &format!("/checkin/tasks/{id}/variables/cookie"),
        Some(json!({"name": "cookie", "source": "auto", "from": "cookie_header"})),
    )
    .await;
    r.ok(
        Method::POST,
        &format!("/checkin/tasks/{id}/variables/values"),
        Some(json!({"values": {"cookie": "sid=abc"}})),
    )
    .await;
    r.ok(
        Method::PUT,
        &format!("/checkin/tasks/{id}/steps"),
        Some(json!({"steps": [api_step(&format!("http://{addr}/user/checkin"), &home)]})),
    )
    .await;
    let (status, _) = r
        .call(
            Method::POST,
            &format!("/checkin/tasks/{id}/run"),
            Some(json!({"trial": true})),
        )
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let run = finished_run(&r, &id).await;
    assert_eq!(run["trigger"], "trial");
    assert_eq!(run["error"], Value::Null);
    assert_eq!(
        run["steps"],
        json!([{"step_id": run["steps"][0]["step_id"], "status": "ok",
                "http_status": 200, "summary": "200 · ret 1 · ok"}])
    );
    assert!(run["day"].as_str().unwrap().len() == 10);
    assert!(run["started_at"].as_str().unwrap().ends_with('Z'));
    assert_eq!(
        seen.lock().clone(),
        [(
            "POST /user/checkin HTTP/1.1".to_string(),
            "sid=abc".to_string()
        )]
    );

    // The same task through the rules: refused by them, nothing arrives.
    r.ok(
        Method::PATCH,
        &format!("/checkin/tasks/{id}"),
        Some(json!({"access": "proxy"})),
    )
    .await;
    r.ok(Method::POST, "/checkin/run", None).await;
    // The run before was a trial: this one is told apart by its trigger.
    let run = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            let run = finished_run(&r, &id).await;
            if run["trigger"] == "manual" {
                return run;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    assert_eq!(run["steps"][0]["status"], "failed");
    assert_eq!(run["steps"][0]["http_status"], Value::Null);
    assert_eq!(seen.lock().len(), 1);
}

#[tokio::test]
async fn a_proxy_task_goes_through_the_rules_like_any_connection() {
    let r = rig_with(None, &["MATCH,DIRECT"]);
    let _tasks = r.engine.start();
    let (addr, seen) = site().await;
    let home = format!("http://{addr}/user");
    let id = r.new_task(&home).await;
    r.ok(
        Method::PATCH,
        &format!("/checkin/tasks/{id}"),
        Some(json!({"access": "proxy"})),
    )
    .await;
    r.ok(
        Method::PUT,
        &format!("/checkin/tasks/{id}/steps"),
        Some(
            json!({"steps": [{"id": "", "kind": "api", "name": "签到", "method": "GET",
            "url": format!("http://{addr}/user/checkin"), "page": home}]}),
        ),
    )
    .await;
    let before = r.state.tunnel.statistics().snapshot().1;
    r.ok(
        Method::POST,
        &format!("/checkin/tasks/{id}/run"),
        Some(json!({})),
    )
    .await;
    let run = finished_run(&r, &id).await;
    assert_eq!(run["steps"][0]["status"], "ok", "{run}");
    assert_eq!(seen.lock().len(), 1);
    // Counted by the tunnel: it went through the relay, not around it.
    let after = r.state.tunnel.statistics().snapshot().1;
    assert!(after > before, "download total {before} -> {after}");
}

/// A proxy task with one request step at `site`, through the API.
async fn proxy_task(r: &Rig, addr: SocketAddr) -> String {
    let home = format!("http://{addr}/user");
    let id = r.new_task(&home).await;
    r.ok(
        Method::PATCH,
        &format!("/checkin/tasks/{id}"),
        Some(json!({"access": "proxy"})),
    )
    .await;
    r.ok(
        Method::PUT,
        &format!("/checkin/tasks/{id}/steps"),
        Some(
            json!({"steps": [{"id": "", "kind": "api", "name": "签到", "method": "GET",
            "url": format!("http://{addr}/user/checkin"), "page": home}]}),
        ),
    )
    .await;
    id
}

/// Runs the task once more and answers that run: the one on record once
/// nothing is queued or running any more. Each run must differ from the
/// one before it (trigger or outcome), which is how the two are told
/// apart.
async fn run_again(r: &Rig, id: &str, trial: bool) -> Value {
    let before = r.ok(Method::GET, "/checkin", None).await["runs"]
        .as_array()
        .unwrap()
        .iter()
        .find(|run| run["task_id"] == id)
        .cloned();
    r.ok(
        Method::POST,
        &format!("/checkin/tasks/{id}/run"),
        Some(json!({"trial": trial})),
    )
    .await;
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            let snap = r.ok(Method::GET, "/checkin", None).await;
            if snap["running_task_id"].is_null()
                && snap["queued_task_ids"].as_array().unwrap().is_empty()
            {
                let run = finished_run(r, id).await;
                if Some(&run) != before.as_ref() {
                    return run;
                }
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("the next run did not finish")
}

#[tokio::test]
async fn a_task_with_a_policy_goes_through_it_whatever_the_rules_say() {
    // Every rule says REJECT.
    let r = rig_with(None, &["MATCH,REJECT"]);
    let _tasks = r.engine.start();
    let (addr, seen) = site().await;
    let id = proxy_task(&r, addr).await;

    // By the rules: refused, nothing arrives.
    let run = run_again(&r, &id, true).await;
    assert_eq!(run["steps"][0]["status"], "failed", "{run}");
    assert!(seen.lock().is_empty());

    // Through the policy it names: out, and through the relay.
    let task = r
        .ok(
            Method::PATCH,
            &format!("/checkin/tasks/{id}"),
            Some(json!({"policy": "DIRECT"})),
        )
        .await;
    assert_eq!(task["policy"], "DIRECT");
    assert_eq!(
        r.ok(Method::GET, "/checkin", None).await["tasks"][0]["policy"],
        "DIRECT"
    );
    let before = r.state.tunnel.statistics().snapshot().1;
    let run = run_again(&r, &id, false).await;
    assert_eq!(run["steps"][0]["status"], "ok", "{run}");
    assert_eq!(seen.lock().len(), 1);
    assert!(r.state.tunnel.statistics().snapshot().1 > before);

    // Cleared: the rules again.
    let task = r
        .ok(
            Method::PATCH,
            &format!("/checkin/tasks/{id}"),
            Some(json!({"policy": null})),
        )
        .await;
    assert_eq!(task["policy"], Value::Null);
    let run = run_again(&r, &id, true).await;
    assert_eq!(run["steps"][0]["status"], "failed", "{run}");
    assert_eq!(seen.lock().len(), 1);
}

#[tokio::test]
async fn a_policy_wins_over_the_rules_in_both_directions() {
    // The rules would let it out; the policy the task names refuses.
    let r = rig_with(None, &["MATCH,DIRECT"]);
    let _tasks = r.engine.start();
    let (addr, seen) = site().await;
    let id = proxy_task(&r, addr).await;
    r.ok(
        Method::PATCH,
        &format!("/checkin/tasks/{id}"),
        Some(json!({"policy": "REJECT"})),
    )
    .await;
    let run = run_again(&r, &id, true).await;
    assert_eq!(run["steps"][0]["status"], "failed", "{run}");
    assert!(seen.lock().is_empty());

    // A direct task does not use the name it keeps.
    let task = r
        .ok(
            Method::PATCH,
            &format!("/checkin/tasks/{id}"),
            Some(json!({"access": "direct"})),
        )
        .await;
    assert_eq!(task["policy"], "REJECT");
    let run = run_again(&r, &id, false).await;
    assert_eq!(run["steps"][0]["status"], "ok", "{run}");
    assert_eq!(seen.lock().len(), 1);
}

#[tokio::test]
async fn a_policy_that_does_not_exist_fails_the_run_in_words() {
    // The rules would let it out: it must not fall back to them.
    let r = rig_with(None, &["MATCH,DIRECT"]);
    let _tasks = r.engine.start();
    let (addr, seen) = site().await;
    let id = proxy_task(&r, addr).await;
    r.ok(
        Method::PATCH,
        &format!("/checkin/tasks/{id}"),
        Some(json!({"policy": "已删除的节点"})),
    )
    .await;
    let run = run_again(&r, &id, false).await;
    assert_eq!(run["steps"][0]["status"], "failed", "{run}");
    assert_eq!(
        run["steps"][0]["summary"],
        "指定的代理策略「已删除的节点」已不存在，请重新选择。"
    );
    assert!(seen.lock().is_empty());

    // The connector says so itself, before anything is dialled.
    use meow_checkin::Connector as _;
    let connector = TunnelConnector::new(r.state.tunnel.clone());
    let refused = connector
        .connect(
            meow_checkin::Access::Proxy,
            Some("已删除的节点"),
            "127.0.0.1",
            addr.port(),
            true,
        )
        .await;
    assert_eq!(
        refused.err().map(|e| e.kind()),
        Some(std::io::ErrorKind::NotFound)
    );
    assert!(seen.lock().is_empty());

    let (status, body) = r
        .call(
            Method::PATCH,
            &format!("/checkin/tasks/{id}"),
            Some(json!({"policy": 7})),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "「policy」的内容格式不对。");
}

/// Reads NDJSON lines off a streaming response, skipping keep-alives.
struct Lines {
    body: axum::body::BodyDataStream,
    buf: String,
}

impl Lines {
    async fn open(app: &axum::Router, path: &str) -> Self {
        let resp = app
            .clone()
            .oneshot(Request::get(path).body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(resp.headers()["content-type"], "application/x-ndjson");
        Self {
            body: resp.into_body().into_data_stream(),
            buf: String::new(),
        }
    }

    async fn next(&mut self) -> Value {
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                if let Some(at) = self.buf.find('\n') {
                    let line: String = self.buf.drain(..=at).collect();
                    if line.trim().is_empty() {
                        continue;
                    }
                    return serde_json::from_str(&line).unwrap();
                }
                let chunk = self.body.next().await.expect("stream ended").unwrap();
                self.buf.push_str(&String::from_utf8_lossy(&chunk));
            }
        })
        .await
        .expect("no line within 5 s")
    }
}

#[tokio::test]
async fn the_event_stream_sends_the_snapshot_now_and_after_every_change() {
    let r = rig();
    let mut events = Lines::open(&r.app, "/checkin/events").await;
    let first = events.next().await;
    assert_eq!(first["tasks"], json!([]));
    assert_eq!(first["queued_task_ids"], json!([]));

    let id = r.new_task("https://main.example.com/user").await;
    let next = events.next().await;
    assert_eq!(next["tasks"][0]["id"], id.as_str());

    r.ok(
        Method::PUT,
        &format!("/checkin/tasks/{id}/variables/cookie"),
        Some(json!({"name": "cookie", "source": "auto", "from": "cookie_header"})),
    )
    .await;
    let next = events.next().await;
    assert_eq!(next["tasks"][0]["variables"][0]["has_value"], false);
    r.ok(
        Method::POST,
        &format!("/checkin/tasks/{id}/variables/values"),
        Some(json!({"values": {"cookie": "sid=COOKIESECRET"}})),
    )
    .await;
    let next = events.next().await;
    assert_eq!(next["tasks"][0]["variables"][0]["has_value"], true);
    assert!(!next.to_string().contains("COOKIESECRET"));

    // Queueing shows; the queue is not being run in this test.
    r.ok(
        Method::POST,
        &format!("/checkin/tasks/{id}/run"),
        Some(json!({"trial": true})),
    )
    .await;
    let next = events.next().await;
    assert_eq!(next["queued_task_ids"], json!([id]));
}

#[tokio::test]
async fn click_requests_reach_the_stream_and_the_report_decides_the_step() {
    let r = rig();
    let _tasks = r.engine.start();
    let id = r.new_task("https://main.example.com/user").await;
    let task = r
        .ok(
            Method::PUT,
            &format!("/checkin/tasks/{id}/steps"),
            Some(
                json!({"steps": [{"id": "", "kind": "click", "name": "领取流量包",
                "page": "https://main.example.com/user",
                "locators": [{"kind": "attribute", "value": "button[data-testid=\"claim\"]"},
                             {"kind": "xpath", "value": "/html[1]/body[1]/button[2]"}],
                "text": "领取流量包", "tag": "button"}]}),
            ),
        )
        .await;
    let step_id = task["steps"][0]["id"].as_str().unwrap().to_string();

    // No app: needs_app.
    r.ok(Method::POST, &format!("/checkin/tasks/{id}/run"), None)
        .await;
    let run = finished_run(&r, &id).await;
    assert_eq!(
        run["steps"],
        json!([{"step_id": step_id, "status": "needs_app", "http_status": null, "summary": ""}])
    );

    // The app opens the stream: it is attached, and today's step left for
    // it arrives.
    assert_eq!(r.engine.clicks().attached(), 0);
    let mut clicks = Lines::open(&r.app, "/checkin/clicks").await;
    assert_eq!(r.engine.clicks().attached(), 1);
    let request = clicks.next().await;
    assert_eq!(request["task_id"], id.as_str());
    assert_eq!(request["access"], "direct");
    assert_eq!(request["timeout_ms"], 500);
    assert_eq!(request["steps"].as_array().unwrap().len(), 1);
    assert_eq!(request["steps"][0]["id"], step_id.as_str());
    assert_eq!(request["steps"][0]["kind"], "click");
    assert_eq!(request["steps"][0]["locators"][1]["kind"], "xpath");
    let request_id = request["id"].as_str().unwrap();

    let (status, _) = r
        .call(
            Method::POST,
            &format!("/checkin/clicks/{request_id}"),
            Some(
                json!({"request_id": request_id, "step_id": step_id, "found": true,
                        "final_url": "https://main.example.com/user",
                        "password_field": false, "error": null}),
            ),
        )
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let run = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let run = finished_run(&r, &id).await;
            if run["steps"][0]["status"] == "ok" {
                return run;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("the click step was not judged");
    assert_eq!(run["trigger"], "manual");
    // Reported once.
    let (status, _) = r
        .call(
            Method::POST,
            &format!("/checkin/clicks/{request_id}"),
            Some(json!({"step_id": step_id, "found": true})),
        )
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    // The stream closes: detached.
    drop(clicks);
    tokio::time::timeout(Duration::from_secs(2), async {
        while r.engine.clicks().attached() != 0 {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("still attached after the stream was dropped");
}

type Ws =
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>;

async fn next_frame(ws: &mut Ws) -> Value {
    let frame = tokio::time::timeout(Duration::from_secs(5), ws.next())
        .await
        .expect("no frame")
        .expect("closed")
        .unwrap();
    serde_json::from_str(&frame.into_text().unwrap()).unwrap()
}

#[tokio::test]
async fn the_streams_also_speak_websocket() {
    let r = rig_with(Some("hunter2"), &["MATCH,DIRECT"]);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let app = r.app.clone();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

    // Without the token: refused before the upgrade.
    assert!(
        tokio_tungstenite::connect_async(format!("ws://{addr}/checkin/events"))
            .await
            .is_err()
    );
    let (mut events, _) =
        tokio_tungstenite::connect_async(format!("ws://{addr}/checkin/events?token=hunter2"))
            .await
            .unwrap();
    assert_eq!(next_frame(&mut events).await["tasks"], json!([]));
    r.engine
        .create_task(&json!({"home": "https://main.example.com/"}), false)
        .unwrap();
    assert_eq!(
        next_frame(&mut events).await["tasks"][0]["home"],
        "https://main.example.com/"
    );

    let (clicks, _) =
        tokio_tungstenite::connect_async(format!("ws://{addr}/checkin/clicks?token=hunter2"))
            .await
            .unwrap();
    tokio::time::timeout(Duration::from_secs(2), async {
        while r.engine.clicks().attached() != 1 {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("not attached");
    drop(clicks);
    tokio::time::timeout(Duration::from_secs(2), async {
        while r.engine.clicks().attached() != 0 {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("still attached after the socket closed");
}

/// As [`Rig::call`], with request headers.
async fn call_with(
    rig: &Rig,
    method: Method,
    path: &str,
    headers: &[(&str, &str)],
) -> (StatusCode, Value) {
    let mut req = Request::builder().method(method).uri(path);
    for (name, value) in headers {
        req = req.header(*name, *value);
    }
    let resp = rig
        .app
        .clone()
        .oneshot(req.body(Body::from("{}")).unwrap())
        .await
        .unwrap();
    let status = resp.status();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

#[tokio::test]
async fn another_web_page_cannot_drive_the_routes() {
    // No secret: the controller's own policy lets every caller in, and
    // its CORS answers any origin. These routes still refuse a browser
    // that says the request comes from another page.
    let r = rig();
    let id = r.new_task("https://main.example.com/user").await;
    r.ok(
        Method::PUT,
        &format!("/checkin/tasks/{id}/variables/uid"),
        Some(json!({"name": "uid", "source": "manual", "value": "PRIVATE-VALUE"})),
    )
    .await;
    let host = ("host", "127.0.0.1:9090");
    let foreign: [&[(&str, &str)]; 5] = [
        &[host, ("origin", "https://evil.example")],
        &[host, ("origin", "null")],
        // Same machine, another port: another origin.
        &[host, ("origin", "http://127.0.0.1:8080")],
        &[host, ("sec-fetch-site", "cross-site")],
        // A name pointed at this machine: the browser's origin is that
        // name, and the page's requests say same-site at best.
        &[host, ("sec-fetch-site", "same-site")],
    ];
    let routes: [(Method, String); 6] = [
        (Method::GET, "/checkin?manual_values=1".to_string()),
        (Method::GET, "/checkin/events".to_string()),
        (Method::GET, "/checkin/clicks".to_string()),
        (Method::POST, "/checkin/rules/import".to_string()),
        (Method::POST, "/checkin/run".to_string()),
        (Method::DELETE, format!("/checkin/tasks/{id}")),
    ];
    for headers in foreign {
        for (method, path) in &routes {
            let (status, body) = call_with(&r, method.clone(), path, headers).await;
            assert_eq!(status, StatusCode::FORBIDDEN, "{method} {path} {headers:?}");
            assert!(!body.to_string().contains("PRIVATE-VALUE"));
            assert!(body["error"].is_string());
        }
    }
    // Nothing happened, and nobody counts as an attached app.
    assert_eq!(r.engine.snapshot(false).tasks.len(), 1);
    assert_eq!(r.engine.clicks().attached(), 0);

    // The server's own origin, and callers that are not browsers, pass.
    for headers in [
        &[host, ("origin", "http://127.0.0.1:9090")][..],
        &[host, ("sec-fetch-site", "same-origin")][..],
        &[host][..],
        &[][..],
    ] {
        let (status, body) = call_with(&r, Method::GET, "/checkin?manual_values=1", headers).await;
        assert_eq!(status, StatusCode::OK, "{headers:?}");
        assert_eq!(body["tasks"][0]["variables"][0]["value"], "PRIVATE-VALUE");
    }

    // With a secret the answer to a foreign page is the same, secret or not.
    let r = rig_with(Some("hunter2"), &["MATCH,DIRECT"]);
    let (status, _) = call_with(
        &r,
        Method::GET,
        "/checkin",
        &[
            host,
            ("origin", "https://evil.example"),
            ("authorization", "Bearer hunter2"),
        ],
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let (status, _) = call_with(
        &r,
        Method::GET,
        "/checkin",
        &[host, ("origin", "https://evil.example")],
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn a_body_beyond_the_limit_is_refused_before_it_is_read() {
    let r = rig();
    let huge = "x".repeat(3 * 1024 * 1024);
    let req = Request::builder()
        .method(Method::POST)
        .uri("/checkin/rules/import")
        .body(Body::from(format!(r#"{{"text": "{huge}"}}"#)))
        .unwrap();
    let resp = r.app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE);
    assert!(r.engine.snapshot(false).tasks.is_empty());
}

#[tokio::test]
async fn by_default_nothing_is_sent_to_this_machine_on_either_path() {
    // The engine as the core opens it: private addresses not allowed.
    let r = rig_full(None, &["MATCH,DIRECT"], false);
    let _tasks = r.engine.start();
    let (addr, seen) = site().await;
    let home = "https://main.example.com/user";
    let id = r.new_task(home).await;
    let step = |url: String| {
        json!({"id": "", "kind": "api", "name": "x", "method": "POST", "url": url,
               "headers": {}, "body": "a=1", "page": home})
    };
    r.ok(
        Method::PUT,
        &format!("/checkin/tasks/{id}/steps"),
        Some(json!({"steps": [
            step(format!("http://{addr}/configs")),
            step(format!("http://localhost:{}/configs", addr.port())),
            step(format!("http://[::ffff:127.0.0.1]:{}/configs", addr.port())),
        ]})),
    )
    .await;
    for access in ["direct", "proxy"] {
        r.ok(
            Method::PATCH,
            &format!("/checkin/tasks/{id}"),
            Some(json!({"access": access})),
        )
        .await;
        // One trial, one manual: told apart by the trigger.
        let trial = access == "direct";
        r.ok(
            Method::POST,
            &format!("/checkin/tasks/{id}/run"),
            Some(json!({"trial": trial})),
        )
        .await;
        let run = tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                let run = finished_run(&r, &id).await;
                if run["trigger"] == if trial { "trial" } else { "manual" } {
                    return run;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();
        for step in run["steps"].as_array().unwrap() {
            assert_eq!(step["status"], "failed", "{access}");
            assert_eq!(
                step["summary"], "这个地址指向本机或内网，签到助手不会访问。",
                "{access}"
            );
        }
    }
    assert!(seen.lock().is_empty());
}

#[tokio::test]
async fn the_connector_refuses_a_private_address_itself() {
    use meow_checkin::Connector as _;
    let r = rig_full(None, &["MATCH,DIRECT"], false);
    let (addr, seen) = site().await;
    let connector = TunnelConnector::new(r.state.tunnel.clone());
    for access in [meow_checkin::Access::Direct, meow_checkin::Access::Proxy] {
        let refused = connector
            .connect(access, None, "127.0.0.1", addr.port(), false)
            .await;
        assert_eq!(
            refused.err().map(|e| e.kind()),
            Some(std::io::ErrorKind::PermissionDenied),
            "{access:?}"
        );
    }
    // Allowed on request: the same dial goes through.
    let mut stream = connector
        .connect(
            meow_checkin::Access::Direct,
            None,
            "127.0.0.1",
            addr.port(),
            true,
        )
        .await
        .unwrap();
    stream
        .write_all(b"GET /x HTTP/1.1\r\nHost: a\r\n\r\n")
        .await
        .unwrap();
    let mut answer = Vec::new();
    stream.read_to_end(&mut answer).await.unwrap();
    assert!(answer.starts_with(b"HTTP/1.1 200"));
    assert_eq!(seen.lock().len(), 1);
}
