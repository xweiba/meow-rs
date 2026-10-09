//! Whole build (L5 + L6): for every `tests/golden/build/*.json`, the
//! facade's output for the case's input must equal what the Dart
//! controller produced — the config it started the core with (map order
//! and int / double typing included), the pool and the screen's tree.

mod common;

use meow_paopao::{build, BuildInput};

#[test]
fn config_pool_and_tree_match_dart() {
    let files = common::golden_files("build");
    assert!(!files.is_empty(), "no build goldens");
    let mut failures = Vec::new();
    let mut not_started = 0;
    let update = common::updating();
    for path in &files {
        let mut case = common::read_json(path);
        let name = path.file_name().unwrap_or_default().to_string_lossy();
        let input = BuildInput::from_json(&case["input"]);
        let out = build(&input).to_json();
        if update {
            // A case the controller did not start the core in keeps no config.
            let e = &mut case["expected"];
            if !e["config"].is_null() {
                e["config"] = out["config"].clone();
            }
            e["pool"] = out["pool"].clone();
            e["tree"] = out["tree"].clone();
            common::write_json(path, &case);
            continue;
        }
        let expected = &case["expected"];
        if expected["config"].is_null() {
            // The controller did not start the core: nothing to compare,
            // and its status must say so.
            not_started += 1;
            if expected["status"] == "on" {
                failures.push(format!("{name}: no config but status on"));
            }
        } else if let Some(d) = common::first_diff(&out["config"], &expected["config"]) {
            failures.push(format!("{name}: config {d}"));
        }
        if let Some(d) = common::first_diff(&out["pool"], &expected["pool"]) {
            failures.push(format!("{name}: pool {d}"));
        }
        if let Some(d) = common::first_diff(&out["tree"], &expected["tree"]) {
            failures.push(format!("{name}: tree {d}"));
        }
    }
    assert!(
        failures.is_empty(),
        "{} differences in {} cases:\n{}",
        failures.len(),
        files.len(),
        failures.join("\n")
    );
    eprintln!(
        "config / pool / tree: {} passed ({not_started} without a config)",
        files.len()
    );
}

/// The rule list beside the config: the config's rules without the route
/// API's and the speed test's; the modules' MITM rules stay (B28).
#[test]
fn rules_follow_the_config() {
    for path in common::golden_files("build") {
        let case = common::read_json(&path);
        let input = BuildInput::from_json(&case["input"]);
        let out = build(&input);
        let config_rules: Vec<&str> = out.config["rules"]
            .as_array()
            .expect("rules")
            .iter()
            .filter_map(|r| r.as_str())
            .filter(|r| !r.starts_with("IN-USER,") && !r.starts_with("IN-NAME,"))
            .collect();
        assert_eq!(out.rules, config_rules, "{}", path.display());
        assert!(out.rules.last().is_some_and(|r| r.starts_with("MATCH,")));
    }
}

/// Branches the corpus never takes (the controller always passes a speed
/// test port and a route key): without them, and with another log level.
#[test]
fn runtime_variants() {
    let files = common::golden_files("build");
    let case = common::read_json(&files[0]);
    let mut v = case["input"].clone();
    let rt = v["runtime"].as_object_mut().expect("runtime");
    rt.remove("route");
    rt.remove("speedTestPort");
    rt.insert("logLevel".into(), "info".into());
    rt.insert("findProcess".into(), false.into());
    let out = build(&BuildInput::from_json(&v));
    let c = &out.config;
    let keys: Vec<&str> = c.keys().map(String::as_str).collect();
    assert_eq!(
        &keys[..6],
        [
            "mixed-port",
            "bind-address",
            "allow-lan",
            "mode",
            "log-level",
            "ipv6"
        ]
    );
    assert_eq!(c["bind-address"], "127.0.0.1");
    assert_eq!(c["log-level"], "info");
    let rules = c["rules"].as_array().expect("rules");
    assert!(rules
        .iter()
        .all(|r| !r.as_str().unwrap_or_default().starts_with("IN-")));
    let groups = c["proxy-groups"].as_array().expect("groups");
    assert!(groups.iter().all(|g| g["name"] != "speedtest"));
    // The route policies are listed either way.
    assert!(out.route_policies.iter().any(|p| p.id == "rule"));
}

/// A rule to a device (not on the meow path) or to a line that is gone
/// sends its sites nowhere: REJECT.
#[test]
fn missing_targets_reject() {
    let files = common::golden_files("build");
    let case = common::read_json(&files[0]);
    let mut v = case["input"].clone();
    let rules = serde_json::json!([
        {"match": "domain", "value": "a.example", "target": "device:phone"},
        {"match": "domain", "value": "b.example", "target": "line:gone"},
    ]);
    v["settings"]["rules"] = rules;
    let out = build(&BuildInput::from_json(&v));
    for site in ["a.example", "b.example"] {
        let want = format!("DOMAIN-SUFFIX,{site},REJECT");
        assert!(out.rules.contains(&want), "{want} in {:?}", out.rules);
    }
}

/// B2: the screen's tree is the config's: same groups, same order, same
/// members (the config's selectors list their pick first).
#[test]
fn tree_is_the_config_tree() {
    for path in common::golden_files("build") {
        let case = common::read_json(&path);
        let out = build(&BuildInput::from_json(&case["input"]));
        let groups: Vec<&serde_json::Value> = out.config["proxy-groups"]
            .as_array()
            .expect("groups")
            .iter()
            .filter(|g| g["name"] != "speedtest")
            .collect();
        assert_eq!(groups.len(), out.tree.groups.len(), "{}", path.display());
        for (c, t) in groups.iter().zip(&out.tree.groups) {
            assert_eq!(c["name"], t.tag.as_str(), "{}", path.display());
            let mut got: Vec<&str> = c["proxies"]
                .as_array()
                .expect("proxies")
                .iter()
                .filter_map(|m| m.as_str())
                .collect();
            let mut want: Vec<&str> = t.members.iter().map(String::as_str).collect();
            got.sort_unstable();
            want.sort_unstable();
            assert_eq!(got, want, "{} {}", path.display(), t.tag);
        }
    }
}
