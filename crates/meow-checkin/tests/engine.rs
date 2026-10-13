//! The engine end to end against a scripted local server: replay, 登录失效,
//! the serial runner, click steps with and without an app, the schedule.

mod support;

use meow_checkin::clock::Clock;
use meow_checkin::model::{Run, Snapshot, StepStatus, Trigger};
use meow_checkin::{Access, Engine, EngineConfig, ErrorKind, SystemClock};
use serde_json::{json, Value};
use std::sync::Arc;
use std::time::Duration;
use support::{
    add_task, api_step, click_step, quick_config, FakeClock, LocalConnector, Reply, Server,
};
use time::macros::datetime;

const HOME: &str = "http://main.example.com/user";

struct Rig {
    server: Server,
    connector: Arc<LocalConnector>,
    engine: Arc<Engine>,
    _dir: tempfile::TempDir,
}

async fn rig_with(
    clock: Arc<dyn Clock>,
    config: EngineConfig,
    handler: impl Fn(&support::Seen) -> Reply + Send + Sync + 'static,
) -> Rig {
    let server = Server::start(handler).await;
    let connector = LocalConnector::new(server.addr);
    let dir = tempfile::tempdir().unwrap();
    let engine = Engine::open(dir.path(), connector.shared(), clock, config);
    Rig {
        server,
        connector,
        engine,
        _dir: dir,
    }
}

async fn rig(handler: impl Fn(&support::Seen) -> Reply + Send + Sync + 'static) -> Rig {
    rig_with(Arc::new(SystemClock), quick_config(), handler).await
}

fn run_of(snapshot: &Snapshot, task_id: &str) -> Run {
    snapshot
        .runs
        .iter()
        .find(|r| r.task_id == task_id)
        .cloned()
        .unwrap_or_else(|| panic!("no run for {task_id}"))
}

fn statuses(run: &Run) -> Vec<StepStatus> {
    run.steps.iter().map(|s| s.status).collect()
}

#[tokio::test]
async fn an_api_step_is_resent_with_the_login_of_now() {
    let r = rig(|_| Reply::json(200, r#"{"ret":1,"msg":"获得了 312 MB 流量"}"#)).await;
    let id = add_task(
        &r.engine,
        "主力机场",
        HOME,
        json!([api_step(
            "签到",
            "http://main.example.com/user/checkin",
            HOME
        )]),
    );
    r.engine.run_task(&id, false).unwrap();
    r.engine.run_pending().await;

    let seen = r.server.seen();
    assert_eq!(seen.len(), 1);
    let req = &seen[0];
    assert_eq!(req.method, "POST");
    assert_eq!(req.path, "/user/checkin");
    assert_eq!(req.host(), "main.example.com");
    assert_eq!(req.header("cookie"), Some("sid=abc==; uid=7"));
    assert_eq!(req.header("user-agent"), Some("Mozilla/5.0 Test"));
    assert_eq!(req.header("origin"), Some("http://main.example.com"));
    assert_eq!(req.header("referer"), Some(HOME));
    assert_eq!(req.header("x-requested-with"), Some("XMLHttpRequest"));
    assert_eq!(req.header("content-length"), Some("3"));
    assert_eq!(req.body, "a=1");
    assert_eq!(
        r.connector.dialed.lock().clone(),
        [(Access::Direct, "main.example.com".to_string(), 80)]
    );

    let run = run_of(&r.engine.snapshot(false), &id);
    assert_eq!(run.trigger, Trigger::Manual);
    assert!(run.finished_at.is_some());
    assert_eq!(run.error, None);
    assert_eq!(statuses(&run), [StepStatus::Ok]);
    assert_eq!(run.steps[0].http_status, Some(200));
    assert_eq!(run.steps[0].summary, "200 · ret 1 · 获得了 312 MB 流量");
}

#[tokio::test]
async fn the_access_mode_reaches_the_connector() {
    let r = rig(|_| Reply::json(200, "{}")).await;
    let id = add_task(
        &r.engine,
        "a",
        HOME,
        json!([api_step("签到", "http://main.example.com:8080/x", HOME)]),
    );
    r.engine
        .update_task(&id, &json!({"access": "proxy"}), false)
        .unwrap();
    r.engine.run_task(&id, true).unwrap();
    r.engine.run_pending().await;
    assert_eq!(
        r.connector.dialed.lock().clone(),
        [(Access::Proxy, "main.example.com".to_string(), 8080)]
    );
    assert_eq!(r.server.seen()[0].host(), "main.example.com:8080");
}

#[tokio::test]
async fn the_policy_reaches_the_connector_on_every_step() {
    let r = rig(|_| Reply::json(200, "{}")).await;
    let id = add_task(
        &r.engine,
        "a",
        HOME,
        json!([
            api_step("登录", "http://main.example.com/a", HOME),
            api_step("签到", "http://other.example.com/b", HOME),
        ]),
    );
    let (rig, task_id) = (&r, &id);
    let run = |trial| async move {
        rig.connector.policies.lock().clear();
        rig.engine.run_task(task_id, trial).unwrap();
        rig.engine.run_pending().await;
        rig.connector.policies.lock().clone()
    };
    let task = r
        .engine
        .update_task(
            &id,
            &json!({"access": "proxy", "policy": "region:US"}),
            false,
        )
        .unwrap();
    assert_eq!(task.policy.as_deref(), Some("region:US"));
    let named = Some("region:US".to_string());
    assert_eq!(run(true).await, [named.clone(), named.clone()]);

    // A direct task keeps the name and does not use it.
    let task = r
        .engine
        .update_task(&id, &json!({"access": "direct"}), false)
        .unwrap();
    assert_eq!(task.policy.as_deref(), Some("region:US"));
    assert_eq!(run(true).await, [None, None]);
    assert_eq!(r.connector.dialed.lock().last().unwrap().0, Access::Direct);

    // A change that does not mention it leaves it.
    let task = r
        .engine
        .update_task(&id, &json!({"access": "proxy", "minute_of_day": 1}), false)
        .unwrap();
    assert_eq!(task.policy.as_deref(), Some("region:US"));
    assert_eq!(run(true).await, [named.clone(), named]);

    // Cleared, by null or by an empty name: the rules decide, as before.
    for (set, cleared) in [("auto", json!(null)), ("proxy", json!(""))] {
        r.engine
            .update_task(&id, &json!({"policy": set}), false)
            .unwrap();
        let task = r
            .engine
            .update_task(&id, &json!({"policy": cleared}), false)
            .unwrap();
        assert_eq!(task.policy, None);
        assert_eq!(serde_json::to_value(&task).unwrap()["policy"], Value::Null);
    }
    assert_eq!(run(true).await, [None, None]);
    assert_eq!(r.connector.dialed.lock().last().unwrap().0, Access::Proxy);
}

#[tokio::test]
async fn a_policy_that_is_gone_fails_the_step_in_words() {
    let r = rig(|_| Reply::json(200, "{}")).await;
    let id = add_task(
        &r.engine,
        "a",
        HOME,
        json!([api_step("签到", "http://main.example.com/x", HOME)]),
    );
    r.engine
        .update_task(&id, &json!({"access": "proxy", "policy": "香港 01"}), false)
        .unwrap();
    r.connector.unknown.lock().push("香港 01".to_string());
    r.engine.run_task(&id, false).unwrap();
    r.engine.run_pending().await;
    let run = run_of(&r.engine.snapshot(false), &id);
    assert_eq!(statuses(&run), [StepStatus::Failed]);
    assert_eq!(run.steps[0].http_status, None);
    assert_eq!(
        run.steps[0].summary,
        "指定的代理策略「香港 01」已不存在，请重新选择。"
    );
    // Asked for by name once, and nothing was sent any other way.
    assert_eq!(
        r.connector.policies.lock().clone(),
        [Some("香港 01".to_string())]
    );
    assert!(r.server.seen().is_empty());
}

#[tokio::test]
async fn a_policy_is_a_name_or_nothing() {
    let r = rig(|_| Reply::json(200, "{}")).await;
    let made = r
        .engine
        .create_task(
            &json!({"home": HOME, "access": "proxy", "policy": "auto"}),
            false,
        )
        .unwrap();
    assert_eq!(made.policy.as_deref(), Some("auto"));
    for bad in [
        json!(1),
        json!(["auto"]),
        json!("a\nb"),
        json!("x".repeat(300)),
    ] {
        let refused = r
            .engine
            .update_task(&made.id, &json!({"policy": bad}), false)
            .unwrap_err();
        assert_eq!(refused.kind, ErrorKind::Invalid, "{bad}");
    }
    assert_eq!(
        r.engine.snapshot(false).tasks[0].policy.as_deref(),
        Some("auto")
    );
}

#[tokio::test]
async fn a_pushed_value_with_a_line_break_is_never_sent() {
    let r = rig(|_| Reply::json(200, "{}")).await;
    let id = add_task(
        &r.engine,
        "a",
        HOME,
        json!([api_step("签到", "http://main.example.com/x", HOME)]),
    );
    r.engine
        .push_variables(
            &id,
            &json!({"values": {"cookie": "sid=1\r\nX-Injected: yes\r\n\r\nGET /evil HTTP/1.1"},
                    "user_agent": "UA\r\nX-Injected: yes"}),
        )
        .unwrap();
    r.engine.run_task(&id, false).unwrap();
    r.engine.run_pending().await;
    // Not sent at all: the step fails with a sentence.
    assert!(r.server.seen().is_empty());
    let run = run_of(&r.engine.snapshot(false), &id);
    assert_eq!(statuses(&run), [StepStatus::Failed]);
    assert!(run.steps[0].summary.contains("cookie"));
    assert!(!run.steps[0].summary.contains("sid=1"));
}

#[tokio::test]
async fn a_summary_never_holds_a_value() {
    // The site echoes the cookie back in its message.
    let r = rig(|seen| {
        Reply::json(
            200,
            &json!({"ret": 1, "msg": format!("hello {}", seen.header("cookie").unwrap_or(""))})
                .to_string(),
        )
    })
    .await;
    let id = add_task(
        &r.engine,
        "a",
        HOME,
        json!([api_step("签到", "http://main.example.com/x", HOME)]),
    );
    r.engine.run_task(&id, false).unwrap();
    r.engine.run_pending().await;
    let run = run_of(&r.engine.snapshot(true), &id);
    assert_eq!(run.steps[0].summary, "200 · ret 1 · hello •••");
    let everything = serde_json::to_string(&r.engine.snapshot(true)).unwrap();
    assert!(!everything.contains("sid=abc"));
}

#[tokio::test]
async fn a_lost_login_stops_the_task_and_skips_the_rest() {
    for reply in [
        Reply::json(401, r#"{"message":"Unauthenticated."}"#),
        Reply::json(403, "{}"),
        Reply::redirect(302, "/auth/login"),
        Reply::html(200, "<html><input type=\"password\"></html>"),
        Reply::json(200, r#"{"ret":0,"msg":"请先登录"}"#),
    ] {
        let script = reply.clone();
        let r = rig(move |_| script.clone()).await;
        let id = add_task(
            &r.engine,
            "a",
            HOME,
            json!([
                api_step("签到", "http://main.example.com/user/checkin", HOME),
                api_step("第二步", "http://main.example.com/user/second", HOME),
                click_step("领取", HOME),
            ]),
        );
        r.engine.run_task(&id, false).unwrap();
        r.engine.run_pending().await;
        let run = run_of(&r.engine.snapshot(false), &id);
        assert_eq!(
            statuses(&run),
            [
                StepStatus::LoggedOut,
                StepStatus::Skipped,
                StepStatus::Skipped
            ],
            "{reply:?}"
        );
        // The login page is not fetched and the second step is not sent.
        assert_eq!(r.server.paths(), ["/user/checkin"], "{reply:?}");
    }
}

#[tokio::test]
async fn other_failures_do_not_stop_the_task() {
    let r = rig(|seen| {
        if seen.path == "/one" {
            Reply::json(500, r#"{"msg":"boom"}"#)
        } else {
            Reply::json(200, "{}")
        }
    })
    .await;
    let id = add_task(
        &r.engine,
        "a",
        HOME,
        json!([
            api_step("一", "http://main.example.com/one", HOME),
            api_step("二", "http://main.example.com/two", HOME),
        ]),
    );
    r.engine.run_task(&id, false).unwrap();
    r.engine.run_pending().await;
    let run = run_of(&r.engine.snapshot(false), &id);
    assert_eq!(statuses(&run), [StepStatus::Failed, StepStatus::Ok]);
    assert_eq!(run.steps[0].summary, "500 · boom");
}

#[tokio::test]
async fn redirects_keep_the_login_inside_the_origin() {
    let r = rig(|seen| match (seen.host(), seen.path.as_str()) {
        ("main.example.com", "/same") => Reply::redirect(302, "/landed"),
        ("main.example.com", "/sibling") => Reply::redirect(302, "http://cdn.example.com/landed"),
        ("main.example.com", "/away") => Reply::redirect(302, "http://collector.example/steal"),
        ("main.example.com", "/inward") => Reply::redirect(302, "http://127.0.0.1:9090/configs"),
        ("main.example.com", "/loop") => Reply::redirect(302, "/loop"),
        _ => Reply::json(200, r#"{"ok":true}"#),
    })
    .await;
    let id = add_task(
        &r.engine,
        "a",
        HOME,
        json!([
            api_step("同源", "http://main.example.com/same", HOME),
            api_step("同站", "http://main.example.com/sibling", HOME),
            api_step("外站", "http://main.example.com/away", HOME),
            api_step("内网", "http://main.example.com/inward", HOME),
            api_step("循环", "http://main.example.com/loop", HOME),
        ]),
    );
    r.engine.run_task(&id, false).unwrap();
    r.engine.run_pending().await;
    let seen = r.server.seen();
    let at = |host: &str, path: &str| {
        seen.iter()
            .filter(|s| s.host() == host && s.path == path)
            .cloned()
            .collect::<Vec<_>>()
    };
    // Same origin: followed, login kept; a POST becomes a GET without body.
    let landed = at("main.example.com", "/landed");
    assert_eq!(landed.len(), 1);
    assert_eq!(landed[0].method, "GET");
    assert_eq!(landed[0].body, "");
    assert_eq!(landed[0].header("cookie"), Some("sid=abc==; uid=7"));
    // Another host of the site: followed without the login.
    let sibling = at("cdn.example.com", "/landed");
    assert_eq!(sibling.len(), 1);
    assert_eq!(sibling[0].header("cookie"), None);
    assert_eq!(
        sibling[0].header("x-requested-with"),
        Some("XMLHttpRequest")
    );
    // Another site, this machine: never contacted.
    assert!(!r.connector.hosts().iter().any(|h| h == "collector.example"));
    assert!(!r.connector.hosts().iter().any(|h| h == "127.0.0.1"));
    // The loop ends: the first request plus five redirects.
    assert_eq!(at("main.example.com", "/loop").len(), 6);

    let run = run_of(&r.engine.snapshot(false), &id);
    assert_eq!(
        statuses(&run),
        [
            StepStatus::Ok,
            StepStatus::Ok,
            StepStatus::Failed,
            StepStatus::Failed,
            StepStatus::Failed
        ]
    );
    assert!(run.steps[2].summary.contains("collector.example"));
    assert_eq!(run.steps[2].http_status, Some(302));
    assert!(run.steps[4].summary.contains("跳转次数太多"));
}

#[tokio::test]
async fn a_cookie_set_by_one_step_is_sent_by_the_next() {
    let r = rig(|seen| {
        if seen.path == "/refresh" {
            Reply::json(200, "{}").with_header("Set-Cookie", "sid=fresh; Path=/; HttpOnly")
        } else {
            Reply::json(200, "{}")
        }
    })
    .await;
    let id = add_task(
        &r.engine,
        "a",
        HOME,
        json!([
            api_step("刷新", "http://main.example.com/refresh", HOME),
            api_step("签到", "http://main.example.com/checkin", HOME),
        ]),
    );
    r.engine.run_task(&id, false).unwrap();
    r.engine.run_pending().await;
    let seen = r.server.seen();
    assert_eq!(seen[0].header("cookie"), Some("sid=abc==; uid=7"));
    assert_eq!(seen[1].header("cookie"), Some("sid=fresh; uid=7"));
    // For that run only: the stored value is the app's.
    r.engine.run_task(&id, true).unwrap();
    r.engine.run_pending().await;
    assert_eq!(
        r.server.seen()[2].header("cookie"),
        Some("sid=abc==; uid=7")
    );
}

#[tokio::test]
async fn a_long_answer_is_cut_off_not_kept() {
    let config = EngineConfig {
        limits: meow_checkin::http::Limits {
            max_body: 1024,
            ..Default::default()
        },
        ..quick_config()
    };
    let r = rig_with(Arc::new(SystemClock), config, |_| Reply {
        status: 200,
        headers: vec![("Content-Type".into(), "text/plain".into())],
        body: vec![b'x'; 300_000],
        delay: Duration::ZERO,
    })
    .await;
    let id = add_task(
        &r.engine,
        "a",
        HOME,
        json!([api_step("签到", "http://main.example.com/x", HOME)]),
    );
    r.engine.run_task(&id, false).unwrap();
    r.engine.run_pending().await;
    let run = run_of(&r.engine.snapshot(false), &id);
    assert_eq!(statuses(&run), [StepStatus::Ok]);
    assert!(run.steps[0].summary.chars().count() < 100);
}

#[tokio::test]
async fn a_site_that_does_not_answer_fails_the_step() {
    let config = EngineConfig {
        limits: meow_checkin::http::Limits {
            exchange_timeout: Duration::from_millis(100),
            ..Default::default()
        },
        ..quick_config()
    };
    let r = rig_with(Arc::new(SystemClock), config, |_| {
        Reply::json(200, "{}").after(Duration::from_secs(5))
    })
    .await;
    let id = add_task(
        &r.engine,
        "a",
        HOME,
        json!([api_step("签到", "http://main.example.com/x", HOME)]),
    );
    r.engine.run_task(&id, false).unwrap();
    r.engine.run_pending().await;
    let run = run_of(&r.engine.snapshot(false), &id);
    assert_eq!(statuses(&run), [StepStatus::Failed]);
    assert_eq!(run.steps[0].http_status, None);
    assert!(!run.steps[0].summary.is_empty());
}

#[tokio::test]
async fn tasks_run_strictly_one_after_another() {
    let r = rig(|_| Reply::json(200, "{}").after(Duration::from_millis(40))).await;
    let mut ids = Vec::new();
    for name in ["a", "b", "c"] {
        ids.push(add_task(
            &r.engine,
            name,
            HOME,
            json!([
                api_step("一", &format!("http://main.example.com/{name}/1"), HOME),
                api_step("二", &format!("http://main.example.com/{name}/2"), HOME),
            ]),
        ));
    }
    // Tab order is the order of 全部执行.
    r.engine
        .reorder_tasks(&json!({"task_ids": [ids[2], ids[0]]}))
        .unwrap();
    assert_eq!(r.engine.run_all(), 3);
    // Asked again while queued: nothing is queued twice.
    assert_eq!(r.engine.run_all(), 0);
    r.engine.run_task(&ids[0], false).unwrap();
    assert_eq!(
        r.engine.snapshot(false).queued_task_ids,
        [ids[2].clone(), ids[0].clone(), ids[1].clone()]
    );

    // Several drains at once still run one task at a time.
    let mut changes = r.engine.changes();
    let watcher = {
        let engine = Arc::clone(&r.engine);
        tokio::spawn(async move {
            let mut running = Vec::new();
            while changes.changed().await.is_ok() {
                let snap = engine.snapshot(false);
                if let Some(id) = snap.running_task_id {
                    if running.last() != Some(&id) {
                        running.push(id);
                    }
                }
                if running.len() == 3 && snap.queued_task_ids.is_empty() {
                    break;
                }
            }
            running
        })
    };
    tokio::join!(
        r.engine.run_pending(),
        r.engine.run_pending(),
        r.engine.run_pending()
    );
    assert_eq!(r.server.max_active(), 1);
    assert_eq!(
        r.server.paths(),
        ["/c/1", "/c/2", "/a/1", "/a/2", "/b/1", "/b/2"]
    );
    let running = tokio::time::timeout(Duration::from_secs(2), watcher)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(running, [ids[2].clone(), ids[0].clone(), ids[1].clone()]);
    let snap = r.engine.snapshot(false);
    assert_eq!(snap.running_task_id, None);
    assert!(snap.queued_task_ids.is_empty());
    assert_eq!(snap.runs.len(), 3);
    assert!(snap.runs.iter().all(|r| r.finished_at.is_some()));
}

#[tokio::test]
async fn without_an_app_a_click_step_needs_the_app_and_the_run_goes_on() {
    let r = rig(|_| Reply::json(200, "{}")).await;
    let id = add_task(
        &r.engine,
        "a",
        HOME,
        json!([
            click_step("领取", HOME),
            api_step("签到", "http://main.example.com/checkin", HOME),
        ]),
    );
    r.engine.run_task(&id, false).unwrap();
    r.engine.run_pending().await;
    let run = run_of(&r.engine.snapshot(false), &id);
    assert_eq!(statuses(&run), [StepStatus::NeedsApp, StepStatus::Ok]);
    assert_eq!(run.error, None);
    assert!(run.finished_at.is_some());
    assert_eq!(r.server.paths(), ["/checkin"]);
    let v = serde_json::to_value(&run).unwrap();
    assert_eq!(v["steps"][0]["status"], "needs_app");
    assert_eq!(v["steps"][0]["http_status"], Value::Null);
}

/// An app: performs every click request with `answer`.
fn attach_app(
    engine: &Arc<Engine>,
    answer: impl Fn(&Value) -> Option<Value> + Send + 'static,
) -> tokio::task::JoinHandle<Vec<Value>> {
    let mut sub = engine.clicks().subscribe();
    let engine = Arc::clone(engine);
    tokio::spawn(async move {
        let mut got = Vec::new();
        while let Some(request) = sub.next().await {
            let request = serde_json::to_value(&request).unwrap();
            got.push(request.clone());
            if let Some(mut report) = answer(&request) {
                report["step_id"] = request["steps"][0]["id"].clone();
                engine
                    .report_click(request["id"].as_str().unwrap(), &report)
                    .unwrap();
            }
            if got.len() >= 8 {
                break;
            }
        }
        got
    })
}

#[tokio::test]
async fn an_attached_app_performs_click_steps_and_the_core_judges() {
    let r = rig(|_| Reply::json(200, "{}")).await;
    let id = add_task(
        &r.engine,
        "a",
        HOME,
        json!([
            click_step("点到", HOME),
            click_step("没有", HOME),
            click_step("出错", HOME),
            click_step("密码", HOME),
            click_step("之后", HOME),
        ]),
    );
    r.engine
        .update_task(&id, &json!({"access": "proxy"}), false)
        .unwrap();
    let app = attach_app(&r.engine, |request| {
        Some(match request["steps"][0]["name"].as_str().unwrap() {
            "点到" => json!({"found": true, "final_url": HOME}),
            "没有" => json!({"found": false, "final_url": HOME}),
            "出错" => json!({"found": false, "error": "这台设备上没有可用的网页组件。"}),
            _ => json!({"found": false, "password_field": true}),
        })
    });
    r.engine.run_task(&id, false).unwrap();
    r.engine.run_pending().await;
    let run = run_of(&r.engine.snapshot(false), &id);
    assert_eq!(
        statuses(&run),
        [
            StepStatus::Ok,
            StepStatus::NotFound,
            StepStatus::Failed,
            StepStatus::LoggedOut,
            StepStatus::Skipped
        ]
    );
    assert_eq!(run.steps[2].summary, "这台设备上没有可用的网页组件。");
    app.abort();
    let _ = app.await;

    // What the app was sent.
    r.engine
        .update_task(&id, &json!({"policy": "auto"}), false)
        .unwrap();
    let mut sub = r.engine.clicks().subscribe();
    r.engine.run_task(&id, true).unwrap();
    let engine = Arc::clone(&r.engine);
    let running = tokio::spawn(async move { engine.run_pending().await });
    let request = serde_json::to_value(sub.next().await.unwrap()).unwrap();
    assert_eq!(request["task_id"], id.as_str());
    assert_eq!(request["access"], "proxy");
    assert_eq!(request["policy"], "auto");
    assert_eq!(request["timeout_ms"], 300);
    assert_eq!(request["steps"].as_array().unwrap().len(), 1);
    assert_eq!(request["steps"][0]["kind"], "click");
    assert_eq!(request["steps"][0]["locators"][0]["kind"], "role_text");
    // A login-looking address ends the task as logged out.
    r.engine
        .report_click(
            request["id"].as_str().unwrap(),
            &json!({"step_id": request["steps"][0]["id"], "found": false,
                    "final_url": "http://main.example.com/auth/login"}),
        )
        .unwrap();
    running.await.unwrap();
    let run = run_of(&r.engine.snapshot(false), &id);
    assert_eq!(run.trigger, Trigger::Trial);
    assert_eq!(run.steps[0].status, StepStatus::LoggedOut);
    // A report for a request that is over is refused.
    let late = r
        .engine
        .report_click(request["id"].as_str().unwrap(), &json!({"step_id": "x"}));
    assert_eq!(late.unwrap_err().kind, ErrorKind::NotFound);
}

#[tokio::test]
async fn an_app_that_never_reports_fails_the_step_after_the_timeout() {
    let config = EngineConfig {
        click_report_grace: Duration::from_millis(100),
        ..quick_config()
    };
    let r = rig_with(Arc::new(SystemClock), config, |_| Reply::json(200, "{}")).await;
    let id = add_task(&r.engine, "a", HOME, json!([click_step("领取", HOME)]));
    let _app = attach_app(&r.engine, |_| None);
    let start = std::time::Instant::now();
    r.engine.run_task(&id, false).unwrap();
    r.engine.run_pending().await;
    // timeout_ms + grace.
    assert!(start.elapsed() >= Duration::from_millis(400));
    let run = run_of(&r.engine.snapshot(false), &id);
    assert_eq!(statuses(&run), [StepStatus::Failed]);
    assert!(!run.steps[0].summary.is_empty());
}

#[tokio::test]
async fn click_steps_left_for_the_app_are_done_when_it_attaches() {
    let r = rig(|_| Reply::json(200, "{}")).await;
    let _tasks = r.engine.start();
    let id = add_task(
        &r.engine,
        "a",
        HOME,
        json!([
            api_step("签到", "http://main.example.com/checkin", HOME),
            click_step("领取", HOME),
        ]),
    );
    r.engine.run_task(&id, false).unwrap();
    let changes = r.engine.changes();
    let wait_for = |want: Vec<StepStatus>| {
        let engine = Arc::clone(&r.engine);
        let id = id.clone();
        let mut changes = changes.clone();
        async move {
            tokio::time::timeout(Duration::from_secs(5), async {
                loop {
                    let snap = engine.snapshot(false);
                    if let Some(run) = snap.runs.iter().find(|r| r.task_id == id) {
                        if run.finished_at.is_some() && statuses(run) == want {
                            return run.clone();
                        }
                    }
                    changes.changed().await.unwrap();
                }
            })
            .await
            .expect("the run did not get there")
        }
    };
    let first = wait_for(vec![StepStatus::Ok, StepStatus::NeedsApp]).await;

    // The app opens: only the click step is done; the request is not sent
    // again.
    let _app = attach_app(&r.engine, |_| Some(json!({"found": true})));
    let second = wait_for(vec![StepStatus::Ok, StepStatus::Ok]).await;
    assert_eq!(second.started_at, first.started_at);
    assert_eq!(second.trigger, Trigger::Manual);
    assert_eq!(r.server.paths(), ["/checkin"]);
}

#[tokio::test]
async fn a_task_with_an_unfilled_manual_variable_does_not_run() {
    let r = rig(|_| Reply::json(200, "{}")).await;
    let id = add_task(
        &r.engine,
        "a",
        HOME,
        json!([api_step("签到", "http://main.example.com/x?u={uid}", HOME)]),
    );
    r.engine
        .save_variable(
            &id,
            "uid",
            &json!({"name": "uid", "source": "manual"}),
            false,
        )
        .unwrap();
    let refused = r.engine.run_task(&id, false).unwrap_err();
    assert_eq!(refused.kind, ErrorKind::Conflict);
    assert!(refused.message.contains("uid"));
    assert_eq!(
        r.engine.run_task(&id, true).unwrap_err().kind,
        ErrorKind::Conflict
    );
    assert_eq!(r.engine.run_all(), 0);
    r.engine.run_pending().await;
    assert!(r.server.seen().is_empty());

    r.engine
        .save_variable(
            &id,
            "uid",
            &json!({"name": "uid", "source": "manual", "value": "10 293"}),
            false,
        )
        .unwrap();
    r.engine.run_task(&id, false).unwrap();
    r.engine.run_pending().await;
    assert_eq!(r.server.paths(), ["/x?u=10%20293"]);

    // Emptied again: unfilled again.
    r.engine
        .save_variable(
            &id,
            "uid",
            &json!({"name": "uid", "source": "manual", "value": ""}),
            false,
        )
        .unwrap();
    assert!(r.engine.run_task(&id, false).is_err());
}

#[tokio::test]
async fn an_auto_variable_never_pushed_fails_its_step_with_a_sentence() {
    let r = rig(|_| Reply::json(200, "{}")).await;
    let id = add_task(
        &r.engine,
        "a",
        HOME,
        json!([{
            "id": "", "kind": "api", "name": "签到", "method": "GET",
            "url": "http://main.example.com/x", "page": HOME,
            "headers": {"authorization": "Bearer {token}"}
        }]),
    );
    r.engine
        .save_variable(
            &id,
            "token",
            &json!({"name": "token", "source": "auto", "from": "request_header",
                    "key": "authorization", "url": "http://main.example.com/"}),
            false,
        )
        .unwrap();
    // An auto variable without a value does not block the run…
    r.engine.run_task(&id, false).unwrap();
    r.engine.run_pending().await;
    // …but nothing with a literal `{token}` is sent.
    assert!(r.server.seen().is_empty());
    let run = run_of(&r.engine.snapshot(false), &id);
    assert_eq!(statuses(&run), [StepStatus::Failed]);
    assert!(run.steps[0].summary.contains("token"));
}

// ---- variables ----

#[tokio::test]
async fn values_are_write_only_or_masked() {
    let r = rig(|_| Reply::json(200, "{}")).await;
    let id = add_task(&r.engine, "a", HOME, json!([]));
    r.engine
        .save_variable(
            &id,
            "uid",
            &json!({"name": "uid", "source": "manual", "value": "MANUALSECRET"}),
            false,
        )
        .unwrap();
    // Names that are not auto variables of the task are ignored.
    r.engine
        .push_variables(
            &id,
            &json!({"values": {"cookie": "sid=COOKIESECRET", "uid": "overwritten",
                               "nobody": "x", "bad": 5}}),
        )
        .unwrap();

    let masked = serde_json::to_value(r.engine.snapshot(false)).unwrap();
    let text = masked.to_string();
    assert!(!text.contains("COOKIESECRET"));
    assert!(!text.contains("MANUALSECRET"));
    assert!(!text.contains("Mozilla/5.0 Test"));
    let vars = masked["tasks"][0]["variables"].as_array().unwrap();
    assert_eq!(vars[0]["name"], "cookie");
    assert_eq!(vars[0]["has_value"], true);
    assert!(vars[0].get("value").is_none());
    assert!(vars[0]["updated_at"].as_str().unwrap().ends_with('Z'));
    assert_eq!(vars[1]["value"], "••••••");
    assert_eq!(vars[1]["masked"], true);
    assert_eq!(vars[1]["has_value"], true);

    // On request the manual value is shown; an auto value never is.
    let revealed = serde_json::to_value(r.engine.snapshot(true)).unwrap();
    assert_eq!(
        revealed["tasks"][0]["variables"][1]["value"],
        "MANUALSECRET"
    );
    assert_eq!(revealed["tasks"][0]["variables"][1]["masked"], false);
    assert!(!revealed.to_string().contains("COOKIESECRET"));

    // Saving the mask back, or no value at all, keeps the value.
    for body in [
        json!({"name": "uid", "source": "manual", "value": "••••••"}),
        json!({"name": "uid", "source": "manual"}),
    ] {
        r.engine.save_variable(&id, "uid", &body, false).unwrap();
        let revealed = serde_json::to_value(r.engine.snapshot(true)).unwrap();
        assert_eq!(
            revealed["tasks"][0]["variables"][1]["value"],
            "MANUALSECRET"
        );
    }
}

#[tokio::test]
async fn renaming_keeps_the_value_and_the_references() {
    let r = rig(|_| Reply::json(200, "{}")).await;
    let id = add_task(
        &r.engine,
        "a",
        HOME,
        json!([api_step("签到", "http://main.example.com/x", HOME)]),
    );
    let task = r
        .engine
        .save_variable(
            &id,
            "cookie",
            &json!({"name": "session", "source": "auto", "from": "cookie_header"}),
            false,
        )
        .unwrap();
    let task = serde_json::to_value(task).unwrap();
    assert_eq!(task["variables"].as_array().unwrap().len(), 1);
    assert_eq!(task["variables"][0]["name"], "session");
    assert_eq!(task["variables"][0]["has_value"], true);
    assert_eq!(task["steps"][0]["headers"]["cookie"], "{session}");
    r.engine.run_task(&id, false).unwrap();
    r.engine.run_pending().await;
    assert_eq!(
        r.server.seen()[0].header("cookie"),
        Some("sid=abc==; uid=7")
    );

    // Read from somewhere else now: the old value is not its value.
    let task = r
        .engine
        .save_variable(
            &id,
            "session",
            &json!({"name": "session", "source": "auto", "from": "cookie", "key": "sid"}),
            false,
        )
        .unwrap();
    assert!(!task.variables[0].has_value);

    // A taken name is refused; a bad one too.
    r.engine
        .save_variable(
            &id,
            "uid",
            &json!({"name": "uid", "source": "manual"}),
            false,
        )
        .unwrap();
    let taken = r.engine.save_variable(
        &id,
        "uid",
        &json!({"name": "session", "source": "manual"}),
        false,
    );
    assert_eq!(taken.unwrap_err().kind, ErrorKind::Conflict);
    let bad = r
        .engine
        .save_variable(&id, "x", &json!({"name": "1x", "source": "manual"}), false);
    assert_eq!(bad.unwrap_err().kind, ErrorKind::Invalid);

    let task = r.engine.delete_variable(&id, "uid", false).unwrap();
    assert_eq!(task.variables.len(), 1);
    // Deleting what is not there is not an error.
    r.engine.delete_variable(&id, "uid", false).unwrap();
}

#[tokio::test]
async fn steps_get_ids_and_keep_them() {
    let r = rig(|_| Reply::json(200, "{}")).await;
    let id = add_task(&r.engine, "a", HOME, json!([click_step("一", HOME)]));
    let first = serde_json::to_value(&r.engine.snapshot(false).tasks[0].steps).unwrap();
    let first_id = first[0]["id"].as_str().unwrap().to_string();
    assert!(!first_id.is_empty());
    let mut kept = first[0].clone();
    kept["name"] = json!("改名");
    let task = r
        .engine
        .save_steps(
            &id,
            &json!({"steps": [click_step("新", HOME), kept.clone(), kept,
                              {"kind": "teleport", "id": "s9"}]}),
            false,
        )
        .unwrap();
    let ids: Vec<&str> = task
        .steps
        .iter()
        .map(meow_checkin::model::Step::id)
        .collect();
    // The unknown kind is left out; the duplicate gets an id of its own.
    assert_eq!(ids.len(), 3);
    assert_eq!(ids[1], first_id);
    assert!(ids[0] != first_id && ids[2] != first_id && ids[0] != ids[2]);
    assert!(ids.iter().all(|i| !i.is_empty()));

    let bad = r.engine.save_steps(
        &id,
        &json!({"steps": [{"kind": "api", "method": "GET", "url": "file:///etc/passwd",
                           "page": HOME}]}),
        false,
    );
    assert_eq!(bad.unwrap_err().kind, ErrorKind::Invalid);
    assert_eq!(r.engine.snapshot(false).tasks[0].steps.len(), 3);
    assert_eq!(
        r.engine
            .save_steps("nope", &json!({"steps": []}), false)
            .unwrap_err()
            .kind,
        ErrorKind::NotFound
    );
}

// ---- the schedule ----

fn scheduled_rig_task(r: &Rig, minute: u16) -> String {
    let id = add_task(
        &r.engine,
        "a",
        HOME,
        json!([api_step("签到", "http://main.example.com/checkin", HOME)]),
    );
    r.engine
        .update_task(&id, &json!({"minute_of_day": minute}), false)
        .unwrap();
    id
}

#[tokio::test]
async fn the_daily_run_happens_once_when_its_time_comes() {
    // 08:00 local (UTC+8); the task is for 08:30.
    let clock = FakeClock::at(datetime!(2026-10-12 08:00:00 +8));
    let r = rig_with(clock.shared(), quick_config(), |_| Reply::json(200, "{}")).await;
    let id = scheduled_rig_task(&r, 510);

    assert!(r.engine.tick().is_empty());
    clock.set(datetime!(2026-10-12 08:29:59 +8));
    assert!(r.engine.tick().is_empty());
    clock.set(datetime!(2026-10-12 08:30:05 +8));
    assert_eq!(r.engine.tick(), std::slice::from_ref(&id));
    // Queued: not queued again.
    assert!(r.engine.tick().is_empty());
    r.engine.run_pending().await;
    let run = run_of(&r.engine.snapshot(false), &id);
    assert_eq!(run.trigger, Trigger::Scheduled);
    assert_eq!(run.day, "2026-10-12");
    assert_eq!(run.started_at, "2026-10-12T00:30:05Z");

    // Done for today, however often the schedule looks.
    for later in [
        datetime!(2026-10-12 08:31:00 +8),
        datetime!(2026-10-12 12:00:00 +8),
        datetime!(2026-10-12 23:59:59 +8),
    ] {
        clock.set(later);
        assert!(r.engine.tick().is_empty());
    }
    // The next day: not before its time, then once.
    clock.set(datetime!(2026-10-13 00:00:01 +8));
    assert!(r.engine.tick().is_empty());
    clock.set(datetime!(2026-10-13 08:30:00 +8));
    assert_eq!(r.engine.tick(), std::slice::from_ref(&id));
    r.engine.run_pending().await;
    assert_eq!(run_of(&r.engine.snapshot(false), &id).day, "2026-10-13");
    assert_eq!(r.server.seen().len(), 2);
}

#[tokio::test]
async fn a_run_missed_while_the_core_was_off_is_caught_up_once() {
    // The core starts at 10:00; the task was for 08:30.
    let clock = FakeClock::at(datetime!(2026-10-12 10:00:00 +8));
    let r = rig_with(clock.shared(), quick_config(), |_| Reply::json(200, "{}")).await;
    let id = scheduled_rig_task(&r, 510);
    clock.advance(time::Duration::seconds(20));
    assert_eq!(r.engine.tick(), std::slice::from_ref(&id));
    r.engine.run_pending().await;
    let run = run_of(&r.engine.snapshot(false), &id);
    assert_eq!(run.trigger, Trigger::CatchUp);
    assert!(r.engine.tick().is_empty());
    assert_eq!(r.server.seen().len(), 1);
}

#[tokio::test]
async fn todays_run_is_remembered_across_a_restart() {
    let clock = FakeClock::at(datetime!(2026-10-12 09:00:00 +8));
    let server = Server::start(|_| Reply::json(200, "{}")).await;
    let connector = LocalConnector::new(server.addr);
    let dir = tempfile::tempdir().unwrap();
    let id = {
        let engine = Engine::open(
            dir.path(),
            connector.shared(),
            clock.shared(),
            quick_config(),
        );
        let id = add_task(
            &engine,
            "a",
            HOME,
            json!([api_step("签到", "http://main.example.com/checkin", HOME)]),
        );
        assert_eq!(engine.tick(), std::slice::from_ref(&id));
        engine.run_pending().await;
        id
    };
    // Restarted the same day: no second run.
    clock.set(datetime!(2026-10-12 21:00:00 +8));
    let engine = Engine::open(
        dir.path(),
        connector.shared(),
        clock.shared(),
        quick_config(),
    );
    assert!(engine.tick().is_empty());
    assert_eq!(run_of(&engine.snapshot(false), &id).day, "2026-10-12");
    // Restarted the next day after its time: the missed run, once.
    clock.set(datetime!(2026-10-13 21:00:00 +8));
    let engine = Engine::open(dir.path(), connector, clock.shared(), quick_config());
    assert_eq!(engine.tick(), std::slice::from_ref(&id));
    engine.run_pending().await;
    assert_eq!(
        run_of(&engine.snapshot(false), &id).trigger,
        Trigger::CatchUp
    );
    assert!(engine.tick().is_empty());
    assert_eq!(server.seen().len(), 2);
}

#[tokio::test]
async fn a_trial_run_does_not_count_as_todays_run_and_a_manual_one_does() {
    let clock = FakeClock::at(datetime!(2026-10-12 07:00:00 +8));
    let r = rig_with(clock.shared(), quick_config(), |_| Reply::json(200, "{}")).await;
    let id = scheduled_rig_task(&r, 510);
    r.engine.run_task(&id, true).unwrap();
    r.engine.run_pending().await;
    assert_eq!(
        run_of(&r.engine.snapshot(false), &id).trigger,
        Trigger::Trial
    );
    clock.set(datetime!(2026-10-12 08:30:00 +8));
    assert_eq!(r.engine.tick(), std::slice::from_ref(&id));
    r.engine.run_pending().await;

    // The next day the user runs it by hand before its time: that is the
    // day's run.
    clock.set(datetime!(2026-10-13 07:00:00 +8));
    r.engine.run_task(&id, false).unwrap();
    r.engine.run_pending().await;
    clock.set(datetime!(2026-10-13 08:30:00 +8));
    assert!(r.engine.tick().is_empty());
}

#[tokio::test]
async fn the_schedule_leaves_out_what_cannot_or_should_not_run() {
    let clock = FakeClock::at(datetime!(2026-10-12 09:00:00 +8));
    let r = rig_with(clock.shared(), quick_config(), |_| Reply::json(200, "{}")).await;
    let off = scheduled_rig_task(&r, 510);
    r.engine
        .update_task(&off, &json!({"enabled": false}), false)
        .unwrap();
    let unfilled = scheduled_rig_task(&r, 510);
    r.engine
        .save_variable(
            &unfilled,
            "uid",
            &json!({"name": "uid", "source": "manual"}),
            false,
        )
        .unwrap();
    let empty = add_task(&r.engine, "空", HOME, json!([]));
    let later = scheduled_rig_task(&r, 23 * 60);
    let due = scheduled_rig_task(&r, 0);
    assert_eq!(r.engine.tick(), std::slice::from_ref(&due));
    let _ = (empty, later);
    r.engine.run_pending().await;

    // Filled in and switched on later the same day: they run then.
    r.engine
        .update_task(&off, &json!({"enabled": true}), false)
        .unwrap();
    r.engine
        .save_variable(
            &unfilled,
            "uid",
            &json!({"name": "uid", "source": "manual", "value": "1"}),
            false,
        )
        .unwrap();
    assert_eq!(r.engine.tick(), [off, unfilled]);
}

#[tokio::test]
async fn a_clock_that_jumps_does_not_strand_or_repeat_the_run() {
    let clock = FakeClock::at(datetime!(2026-10-12 08:00:00 +8));
    let r = rig_with(clock.shared(), quick_config(), |_| Reply::json(200, "{}")).await;
    let id = scheduled_rig_task(&r, 510);
    // Forward over the time (suspend, NTP): the run is due.
    clock.set(datetime!(2026-10-12 15:00:00 +8));
    assert_eq!(r.engine.tick(), std::slice::from_ref(&id));
    r.engine.run_pending().await;
    // Back to before the time, then over it again: not twice.
    clock.set(datetime!(2026-10-12 08:00:00 +8));
    assert!(r.engine.tick().is_empty());
    clock.set(datetime!(2026-10-12 08:31:00 +8));
    assert!(r.engine.tick().is_empty());
    // Days ahead and back: each day it lands on gets its run, none is
    // waited for forever.
    clock.set(datetime!(2026-10-20 09:00:00 +8));
    assert_eq!(r.engine.tick(), std::slice::from_ref(&id));
    r.engine.run_pending().await;
    clock.set(datetime!(2026-10-13 09:00:00 +8));
    assert_eq!(r.engine.tick(), std::slice::from_ref(&id));
    r.engine.run_pending().await;
    assert!(r.engine.tick().is_empty());
    // Back on a day that already had its run (the clock stepped back a
    // day and forward again): not a second time, on any of them.
    for day in [
        datetime!(2026-10-20 23:00:00 +8),
        datetime!(2026-10-12 23:00:00 +8),
        datetime!(2026-10-13 23:00:00 +8),
    ] {
        clock.set(day);
        assert!(r.engine.tick().is_empty(), "{day}");
    }
    assert_eq!(r.server.seen().len(), 3);
}

#[tokio::test]
async fn the_started_engine_runs_what_is_due_by_itself() {
    let clock = FakeClock::at(datetime!(2026-10-12 10:00:00 +8));
    let config = EngineConfig {
        start_delay: Duration::from_millis(30),
        tick: Duration::from_millis(30),
        ..quick_config()
    };
    let r = rig_with(clock, config, |_| Reply::json(200, "{}")).await;
    let id = scheduled_rig_task(&r, 510);
    let tasks = r.engine.start();
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let snap = r.engine.snapshot(false);
            if snap.runs.iter().any(|run| run.finished_at.is_some()) {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    // Several more looks at the clock: still one run.
    tokio::time::sleep(Duration::from_millis(150)).await;
    assert_eq!(r.server.seen().len(), 1);
    assert_eq!(
        run_of(&r.engine.snapshot(false), &id).trigger,
        Trigger::CatchUp
    );
    // Stopped: a manual run stays queued.
    drop(tasks);
    tokio::time::sleep(Duration::from_millis(20)).await;
    r.engine.run_task(&id, false).unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(r.server.seen().len(), 1);
}

#[tokio::test]
async fn deleting_a_task_takes_its_queue_entry_and_its_run() {
    let r = rig(|_| Reply::json(200, "{}")).await;
    let a = add_task(
        &r.engine,
        "a",
        HOME,
        json!([api_step("签到", "http://main.example.com/a", HOME)]),
    );
    let b = add_task(
        &r.engine,
        "b",
        HOME,
        json!([api_step("签到", "http://main.example.com/b", HOME)]),
    );
    r.engine.run_all();
    r.engine.delete_task(&a).unwrap();
    assert_eq!(
        r.engine.snapshot(false).queued_task_ids,
        std::slice::from_ref(&b)
    );
    r.engine.run_pending().await;
    assert_eq!(r.server.paths(), ["/b"]);
    let snap = r.engine.snapshot(false);
    assert_eq!(snap.tasks.len(), 1);
    assert_eq!(snap.runs.len(), 1);
    assert_eq!(
        r.engine.delete_task(&a).unwrap_err().kind,
        ErrorKind::NotFound
    );
    assert_eq!(
        r.engine.run_task(&a, false).unwrap_err().kind,
        ErrorKind::NotFound
    );
}

// ---- where a request may go ----

const PRIVATE: &str = "这个地址指向本机或内网，签到助手不会访问。";

#[tokio::test]
async fn a_step_never_reaches_this_machine_or_a_private_network() {
    let r = rig(|_| Reply::json(200, "{}")).await;
    let targets = [
        "http://127.0.0.1:9090/configs",
        "http://localhost:9090/configs",
        "http://[::1]:9090/configs",
        "http://[::ffff:127.0.0.1]/",
        // Other spellings of 127.0.0.1.
        "http://0x7f.0.0.1/",
        "http://2130706433/",
        "http://127.1/",
        "http://192.168.1.1/cgi-bin/reboot",
        "http://10.0.0.1/",
        "http://169.254.169.254/latest/meta-data/",
        "http://metadata.google.internal/",
        "http://router/",
        "http://nas.lan/",
        "http://0.0.0.0/",
    ];
    let steps: Vec<Value> = targets
        .iter()
        .map(|url| {
            json!({"id": "", "kind": "api", "name": "x", "method": "POST", "url": url,
                   "headers": {}, "body": "a=1", "page": HOME})
        })
        .collect();
    let id = add_task(&r.engine, "a", HOME, json!(steps));
    r.engine.run_task(&id, false).unwrap();
    r.engine.run_pending().await;
    let run = run_of(&r.engine.snapshot(false), &id);
    assert_eq!(run.steps.len(), targets.len());
    for (step, url) in run.steps.iter().zip(targets) {
        assert_eq!(step.status, StepStatus::Failed, "{url}");
        assert_eq!(step.summary, PRIVATE, "{url}");
        assert_eq!(step.http_status, None, "{url}");
    }
    // Refused before any connection was asked for.
    assert!(r.connector.hosts().is_empty());
    assert!(r.server.seen().is_empty());
    assert!(!r.engine.allow_private());
}

#[tokio::test]
async fn private_addresses_are_reachable_only_when_allowed() {
    let config = EngineConfig {
        allow_private: true,
        ..quick_config()
    };
    let r = rig_with(Arc::new(SystemClock), config, |_| Reply::json(200, "{}")).await;
    let id = add_task(
        &r.engine,
        "nas",
        "http://192.168.1.10/",
        json!([api_step(
            "签到",
            "http://192.168.1.10/checkin",
            "http://192.168.1.10/"
        )]),
    );
    r.engine.run_task(&id, false).unwrap();
    r.engine.run_pending().await;
    assert_eq!(
        statuses(&run_of(&r.engine.snapshot(false), &id)),
        [StepStatus::Ok]
    );
    assert_eq!(r.connector.hosts(), ["192.168.1.10"]);
    assert!(r.engine.allow_private());
}

/// A connector whose every name turns out to be a private address, as the
/// core's is for a name that resolves to one.
struct ResolvesInward(std::sync::atomic::AtomicUsize);

#[async_trait::async_trait]
impl meow_checkin::Connector for ResolvesInward {
    async fn connect(
        &self,
        _access: Access,
        _policy: Option<&str>,
        _host: &str,
        _port: u16,
        allow_private: bool,
    ) -> std::io::Result<meow_checkin::BoxStream> {
        self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        assert!(!allow_private);
        Err(meow_checkin::http::refused_private())
    }
}

#[tokio::test]
async fn a_name_that_resolves_inward_is_refused_where_it_is_dialled() {
    let dir = tempfile::tempdir().unwrap();
    let connector = Arc::new(ResolvesInward(std::sync::atomic::AtomicUsize::new(0)));
    let engine = Engine::open(
        dir.path(),
        Arc::<ResolvesInward>::clone(&connector),
        Arc::new(SystemClock),
        quick_config(),
    );
    let id = add_task(
        &engine,
        "a",
        HOME,
        json!([api_step("签到", "http://rebind.example.com/x", HOME)]),
    );
    engine.run_task(&id, false).unwrap();
    engine.run_pending().await;
    let run = run_of(&engine.snapshot(false), &id);
    assert_eq!(statuses(&run), [StepStatus::Failed]);
    assert_eq!(run.steps[0].summary, PRIVATE);
    assert_eq!(connector.0.load(std::sync::atomic::Ordering::SeqCst), 1);
}

#[tokio::test]
async fn a_redirect_does_not_carry_a_value_to_another_host() {
    let r = rig(|seen| match (seen.host(), seen.path.as_str()) {
        ("main.example.com", "/keep" | "/plain") => {
            Reply::redirect(307, "http://cdn.example.com/landed")
        }
        ("main.example.com", "/inward") => Reply::redirect(302, "http://printer.local/x"),
        _ => Reply::json(200, "{}"),
    })
    .await;
    let step = |path: &str, body: &str| {
        json!({"id": "", "kind": "api", "name": path, "method": "POST",
               "url": format!("http://main.example.com{path}"),
               "headers": {"cookie": "{cookie}"}, "body": body, "page": HOME})
    };
    let id = add_task(
        &r.engine,
        "a",
        HOME,
        json!([
            step("/keep", "c={cookie}"),
            step("/plain", "a=1"),
            step("/inward", "a=1")
        ]),
    );
    r.engine.run_task(&id, false).unwrap();
    r.engine.run_pending().await;
    let run = run_of(&r.engine.snapshot(false), &id);
    // 307 keeps the body: with a value in it the hop is not made.
    assert_eq!(run.steps[0].status, StepStatus::Failed);
    assert_eq!(run.steps[0].http_status, Some(307));
    assert!(run.steps[0].summary.contains("cdn.example.com"));
    // Without one it is, minus the login.
    assert_eq!(run.steps[1].status, StepStatus::Ok);
    let landed: Vec<_> = r
        .server
        .seen()
        .into_iter()
        .filter(|s| s.host() == "cdn.example.com")
        .collect();
    assert_eq!(landed.len(), 1);
    assert_eq!(landed[0].body, "a=1");
    assert_eq!(landed[0].header("cookie"), None);
    // A redirect to a private name is not followed.
    assert_eq!(run.steps[2].status, StepStatus::Failed);
    assert!(!r.connector.hosts().iter().any(|h| h == "printer.local"));
}

#[tokio::test]
async fn moving_a_task_to_another_site_drops_the_login_read_for_the_old_one() {
    let r = rig(|_| Reply::json(200, "{}")).await;
    let id = add_task(
        &r.engine,
        "a",
        HOME,
        json!([api_step("签到", "http://collector.example/x", HOME)]),
    );
    r.engine
        .save_variable(
            &id,
            "pinned",
            &json!({"name": "pinned", "source": "auto", "from": "cookie",
                    "key": "sid", "url": "http://main.example.com/"}),
            false,
        )
        .unwrap();
    r.engine
        .save_variable(
            &id,
            "note",
            &json!({"name": "note", "source": "manual", "value": "mine"}),
            false,
        )
        .unwrap();
    r.engine
        .push_variables(&id, &json!({"values": {"pinned": "abc"}}))
        .unwrap();
    // Another host of the same site: nothing is lost.
    let task = r
        .engine
        .update_task(&id, &json!({"home": "http://www.example.com/user"}), true)
        .unwrap();
    assert!(task.variables.iter().all(|v| v.has_value));
    // Another site: the cookie read for "home" is not that site's.
    let task = r
        .engine
        .update_task(&id, &json!({"home": "http://collector.example/"}), true)
        .unwrap();
    let has = |name: &str| {
        task.variables
            .iter()
            .find(|v| v.name == name)
            .unwrap()
            .has_value
    };
    assert!(!has("cookie"));
    // Bound to its own address, and a manual value: kept.
    assert!(has("pinned"));
    assert!(has("note"));
    r.engine.run_task(&id, false).unwrap();
    r.engine.run_pending().await;
    let run = run_of(&r.engine.snapshot(false), &id);
    assert_eq!(statuses(&run), [StepStatus::Failed]);
    assert!(r.server.seen().is_empty());
    // Gone from the file too.
    let secrets = std::fs::read_to_string(r._dir.path().join("checkin-secrets.json")).unwrap();
    assert!(!secrets.contains("sid=abc=="));
}

#[tokio::test]
async fn a_task_deleted_while_it_runs_sends_nothing_more() {
    let r = rig(|_| Reply::json(200, "{}")).await;
    let id = add_task(
        &r.engine,
        "a",
        HOME,
        json!([
            api_step("一", "http://main.example.com/1", HOME),
            click_step("点", HOME),
            api_step("二", "http://main.example.com/2", HOME),
        ]),
    );
    // The app is there and holds the click step until the task is gone.
    let mut sub = r.engine.clicks().subscribe();
    r.engine.run_task(&id, false).unwrap();
    let running = {
        let engine = Arc::clone(&r.engine);
        tokio::spawn(async move { engine.run_pending().await })
    };
    let request = sub.next().await.unwrap();
    r.engine.delete_task(&id).unwrap();
    r.engine
        .report_click(
            &request.id,
            &json!({"step_id": request.steps[0].id(), "found": true}),
        )
        .unwrap();
    tokio::time::timeout(Duration::from_secs(10), running)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(r.server.paths(), ["/1"]);
    let snap = r.engine.snapshot(false);
    assert!(snap.tasks.is_empty() && snap.runs.is_empty());
    assert_eq!(snap.running_task_id, None);
}
