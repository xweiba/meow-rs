//! Settings older apps wrote (`tests/fixtures/settings/`, reconstructed
//! from the commits; the app's `test/fixtures/settings/` holds the same
//! files): brought to the current format once, and the names that depend
//! on the lines read on every build. Nothing the user saved is lost.

use std::path::Path;

use meow_paopao::{build, migrate_json, migrate_settings, BuildInput, BuildOutput, ProxySettings};
use serde_json::{json, Value};

fn fixtures() -> Vec<(String, Value)> {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/settings");
    let mut out: Vec<(String, Value)> = std::fs::read_dir(&dir)
        .expect("fixtures")
        .map(|e| e.expect("entry").path())
        .filter(|p| p.extension().is_some_and(|x| x == "json"))
        .map(|p| {
            let text = std::fs::read_to_string(&p).expect("read");
            let name = p.file_name().unwrap().to_string_lossy().into_owned();
            (name, serde_json::from_str(&text).expect("json"))
        })
        .collect();
    out.sort_by(|a, b| a.0.cmp(&b.0));
    assert!(out.len() >= 4, "fixtures missing");
    out
}

#[test]
fn old_settings_come_out_in_the_current_format() {
    for (name, f) in fixtures() {
        let m = migrate_settings(&f["settings"]);
        if let Some(want) = f.get("migrated") {
            assert_eq!(&m.settings, want, "{name}");
            assert!(!m.changes.is_empty(), "{name}: no change noted");
        }
        // Idempotent: the current format comes out as it went in.
        let again = migrate_settings(&m.settings);
        assert_eq!(again.settings, m.settings, "{name}: second run");
        assert!(again.changes.is_empty(), "{name}: {:?}", again.changes);
        // Readable, and builds.
        let _ = ProxySettings::from_json(&m.settings);
        let _ = build(&BuildInput::from_json(&input(&m.settings)));
    }
}

#[test]
fn migrate_json_is_the_ffi_shape() {
    let out = migrate_json(r#"{"settings": {"selected": "auto~fastest"}}"#);
    assert_eq!(out["version"], 1);
    assert_eq!(out["settings"]["selected"], "auto");
    assert_eq!(
        out["settings"]["group_use"]["proxy"]["members"]["auto"]["use"],
        "fastest"
    );
    assert!(out["changes"].as_array().is_some_and(|c| !c.is_empty()));
    assert!(migrate_json("[]")["error"].is_string());
    assert!(migrate_json("{").get("error").is_some());
}

#[test]
fn a_build_input_from_an_older_app_is_migrated_too() {
    // A core keeps the input an older app gave it.
    let out =
        run(&json!({"selected": "auto~fastest", "policies": {"policy:youtube": "auto~balance"}}));
    let proxy = out.tree.by_tag("proxy").expect("proxy");
    assert_eq!(proxy.pick.as_deref(), Some("proxy@auto~fastest"));
    assert_eq!(proxy.stale, None);
    let yt = out.tree.by_tag("policy:youtube").expect("youtube");
    assert_eq!(yt.pick.as_deref(), Some("policy:youtube@auto~balance"));
}

fn vless(name: &str, server: &str) -> Value {
    json!({"name": name, "outbound": {"type": "vless", "server": server, "server_port": 443, "uuid": "u"}})
}

/// 美国 with three lines, 日本 with two, 香港 with one (in 其他地区).
fn input(settings: &Value) -> Value {
    let nodes = vec![
        vless("美国 1", "u1"),
        vless("美国 2", "u2"),
        vless("美国 3", "u3"),
        vless("日本 1", "j1"),
        vless("日本 2", "j2"),
        vless("香港 1", "h1"),
    ];
    let mut s = json!({"mode": "smart", "selected": "auto", "mixed_port": 7890, "rules": []});
    if let (Some(s), Some(extra)) = (s.as_object_mut(), settings.as_object()) {
        for (k, v) in extra {
            s.insert(k.clone(), v.clone());
        }
    }
    json!({
        "subscriptions": [{"id": "s", "url": "https://a.example", "name": "a", "nodes": nodes, "split": {}}],
        "settings": s,
        "network": {"kind": "wifi", "ssid": "home", "addresses": []},
        "now": 1_791_563_444_034_i64,
        "runtime": {"controllerPort": 1, "secret": "x", "speedTestPort": 2},
    })
}

fn run(settings: &Value) -> BuildOutput {
    build(&BuildInput::from_json(&input(settings)))
}

fn rule_for<'a>(out: &'a BuildOutput, site: &str) -> Option<&'a String> {
    out.rules.iter().find(|r| r.contains(site))
}

#[test]
fn rules_to_old_names_lead_where_they_meant_and_say_so() {
    let out = run(&json!({"rules": [
        {"match": "domain", "value": "hk.com", "target": "line:region:HK"},
        {"match": "domain", "value": "ai.com", "target": "line:policy:ai~sticky"},
        {"match": "domain", "value": "steam.com", "target": "line:policy:steam"},
        {"match": "domain", "value": "copy.com", "target": "line:policy:ai@region:US~fastest~sticky"},
        {"match": "domain", "value": "gone.com", "target": "line:韩国 9"},
        {"match": "domain", "value": "later.com", "target": "policy:x"},
        {"match": "domain", "value": "ok.com", "target": "line:region:US"},
    ]}));
    let t = out.to_json();
    let states = &t["ruleTargets"];
    assert_eq!(
        states["line:region:HK"],
        json!({"state": "moved", "to": "region:other"})
    );
    assert_eq!(
        states["line:policy:ai~sticky"],
        json!({"state": "moved", "to": "policy:ai"})
    );
    assert_eq!(
        states["line:policy:steam"],
        json!({"state": "moved", "to": "policy:games"})
    );
    assert_eq!(states["line:韩国 9"], json!({"state": "gone"}));
    assert_eq!(states["policy:x"], json!({"state": "unknown"}));
    assert!(states.get("line:region:US").is_none());
    assert!(rule_for(&out, "hk.com").is_some_and(|r| r.ends_with(",region:other")));
    assert!(rule_for(&out, "ai.com").is_some_and(|r| r.ends_with(",policy:ai")));
    assert!(rule_for(&out, "steam.com").is_some_and(|r| r.ends_with(",policy:games")));
    assert!(rule_for(&out, "gone.com").is_some_and(|r| r.ends_with(",REJECT")));
    // Not understood: no rule, never 代理; the rules after it decide.
    assert!(rule_for(&out, "later.com").is_none());
    assert!(rule_for(&out, "ok.com").is_some_and(|r| r.ends_with(",region:US")));
}

#[test]
fn picks_of_a_region_now_in_other_regions_follow_it() {
    let out = run(&json!({
        "selected": "region:HK",
        "policies": {"policy:social": "region:HK"},
        "group_pick": {"region:HK": "香港 1"},
    }));
    assert_eq!(
        out.tree.by_tag("proxy").unwrap().pick.as_deref(),
        Some("region:other")
    );
    let social = out.tree.by_tag("policy:social").unwrap();
    assert_eq!(social.pick.as_deref(), Some("region:other"));
    assert_eq!(social.stale, None);
    assert_eq!(
        out.tree.by_tag("region:other").unwrap().pick.as_deref(),
        Some("香港 1")
    );
}

#[test]
fn a_pick_no_group_offers_is_marked_stale_not_dropped() {
    let s = json!({
        "policies": {"policy:ai": "kind:relay", "policy:telegram": "region:KR"},
        "custom_groups": [{"id": "g1", "name": "x", "pick": "region:KR"}],
    });
    let out = run(&s);
    let ai = out.tree.by_tag("policy:ai").unwrap();
    assert_eq!(ai.stale.as_deref(), Some("kind:relay"));
    assert_ne!(ai.pick.as_deref(), Some("kind:relay"));
    assert_eq!(
        out.tree.by_tag("policy:telegram").unwrap().stale.as_deref(),
        Some("region:KR")
    );
    assert_eq!(
        out.tree.by_tag("group:g1").unwrap().stale.as_deref(),
        Some("region:KR")
    );
    assert_eq!(
        out.to_json()["tree"]["groups"]
            .as_array()
            .unwrap()
            .iter()
            .find(|g| g["tag"] == "policy:ai")
            .unwrap()["stale"],
        "kind:relay"
    );
    // The settings keep it.
    let p = ProxySettings::from_json(&s);
    assert_eq!(p.policies["policy:ai"], "kind:relay");
}

#[test]
fn unreadable_rule_targets_are_kept_as_saved() {
    let s = json!({"rules": [{"match": "domain", "value": "x.com", "target": "policy:x"}]});
    let p = ProxySettings::from_json(&s);
    assert_eq!(p.to_json()["rules"][0]["target"], "policy:x");
}
