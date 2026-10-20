//! Settings reach emitted automatic groups without changing saved preferences.
use meow_paopao::{build, build_json, parse_json, BuildInput, SubRules};
use serde_json::{json, Value};

const AUTOMATIC: [&str; 4] = ["smart", "url-test", "fallback", "load-balance"];

fn subscription(id: &str) -> Value {
    let mut groups =
        vec![json!({"n": "Main", "t": "select", "m": ["HK 1", "HK 2"], "interval": 99})];
    let mut rules = Vec::new();
    for (i, kind) in AUTOMATIC.iter().enumerate() {
        groups.push(json!({"n": kind, "t": kind, "m": ["HK 1", "HK 2"], "interval": 41 + i}));
        rules.push(format!(
            "DOMAIN,probe-{i}.example.invalid,{kind},no-resolve"
        ));
    }
    rules.push("DOMAIN,main.example.invalid,Main".into());
    rules.push("MATCH,fallback".into());
    json!({
        "id": id, "name": id, "url": "",
        "nodes": [
            {"name": "HK 1", "outbound": {"type": "socks", "version": "5", "server": "node1.example.invalid", "server_port": 1080}},
            {"name": "HK 2", "outbound": {"type": "socks", "version": "5", "server": "node2.example.invalid", "server_port": 1080}}
        ],
        "split": {"groups": groups, "rules": rules},
    })
}

fn input(raw: bool) -> Value {
    json!({"subscriptions": [subscription("first")],
        "settings": {"group_mode": if raw {"subscription"} else {"layered"}}})
}

fn built(request: &Value) -> Value {
    let out = build_json(&request.to_string());
    assert!(
        out.get("configError").is_none(),
        "{:?}",
        out.get("configError")
    );
    out
}

fn group<'a>(out: &'a Value, name: &str) -> &'a Value {
    out["config"]["proxy-groups"]
        .as_array()
        .unwrap()
        .iter()
        .find(|g| g["name"] == name)
        .unwrap_or_else(|| panic!("missing group {name}"))
}

#[test]
fn global_probe_override_reaches_all_raw_automatic_types() {
    for strategy in ["smart", "urlTest"] {
        let mut request = input(true);
        request["strategy"] = strategy.into();
        request["runtime"] = json!({"probeInterval": 3600});
        let out = built(&request);
        for kind in AUTOMATIC {
            let g = group(&out, &format!("sub:{kind}"));
            assert_eq!(g["type"], kind);
            assert_eq!(g["interval"], 3600);
        }
        assert!(group(&out, "proxy").get("interval").is_none());
    }
}

#[test]
fn global_probe_override_reaches_layered_smart_and_url_test_strategies() {
    for strategy in ["smart", "urlTest"] {
        let mut request = input(false);
        request["strategy"] = strategy.into();
        request["runtime"] = json!({"probeInterval": 7200});
        request["settings"]["policies"] = json!({"policy:foreign": "auto"});
        request["settings"]["group_use"] = json!({"policy:foreign": {"sticky": true}});
        let out = built(&request);
        let mut seen = std::collections::BTreeSet::new();
        for g in out["config"]["proxy-groups"].as_array().unwrap() {
            let kind = g["type"].as_str().unwrap();
            if AUTOMATIC.contains(&kind) {
                seen.insert(kind);
                assert_eq!(g["interval"], 7200, "{}", g["name"]);
            } else {
                assert!(g.get("interval").is_none());
            }
        }
        let expected = if strategy == "smart" {
            vec!["smart"]
        } else {
            vec!["fallback", "load-balance", "url-test"]
        };
        assert_eq!(seen.into_iter().collect::<Vec<_>>(), expected);
    }
}

#[test]
fn absent_or_invalid_global_override_preserves_imported_intervals_including_zero() {
    for runtime in [
        json!({}),
        json!({"probeInterval": null}),
        json!({"probeInterval": 0}),
        json!({"probeInterval": -1}),
    ] {
        let mut request = input(true);
        request["runtime"] = runtime;
        request["subscriptions"][0]["split"]["groups"][1]["interval"] = 0.into();
        let out = built(&request);
        for (i, kind) in AUTOMATIC.iter().enumerate() {
            assert_eq!(
                group(&out, &format!("sub:{kind}"))["interval"],
                if i == 0 { 0 } else { 41 + i }
            );
        }
        assert!(group(&out, "proxy").get("interval").is_none());
    }
}

#[test]
fn legacy_groups_without_intervals_keep_existing_generated_defaults() {
    for raw in [false, true] {
        for strategy in ["smart", "urlTest"] {
            let mut request = input(raw);
            request["strategy"] = strategy.into();
            for g in request["subscriptions"][0]["split"]["groups"]
                .as_array_mut()
                .unwrap()
            {
                g.as_object_mut().unwrap().remove("interval");
            }
            let out = built(&request);
            for g in out["config"]["proxy-groups"].as_array().unwrap() {
                match g["type"].as_str().unwrap() {
                    "smart" if !raw => assert!(g.get("interval").is_none()),
                    "smart" | "url-test" | "fallback" | "load-balance" => {
                        assert_eq!(g["interval"], 300);
                    }
                    _ => assert!(g.get("interval").is_none()),
                }
            }
        }
    }
}

#[test]
fn merged_group_interval_and_type_follow_subscription_priority() {
    let mut request = input(true);
    let mut second = subscription("second");
    second["split"]["groups"][2]["interval"] = 901.into();
    second["split"]["groups"][2]["t"] = "load-balance".into();
    request["subscriptions"]
        .as_array_mut()
        .unwrap()
        .push(second);
    assert_eq!(group(&built(&request), "sub:url-test")["interval"], 42);
    request["subscriptions"].as_array_mut().unwrap().reverse();
    let out = built(&request);
    assert_eq!(group(&out, "sub:url-test")["interval"], 901);
    assert_eq!(group(&out, "sub:url-test")["type"], "load-balance");
    request["subscriptions"][0]["split"]["groups"][2]
        .as_object_mut()
        .unwrap()
        .remove("interval");
    assert_eq!(
        group(&built(&request), "sub:url-test")["interval"],
        300,
        "a lower-priority definition must not supply metadata for the winning type"
    );
}

#[test]
fn raw_split_is_effective_without_changing_saved_layered_preference() {
    let mut request = input(false);
    request["subscriptions"][0]["use_split"] = false.into();
    let mut parsed = BuildInput::from_json(&request);
    let saved = parsed.subscriptions.clone();
    let layered = build(&parsed).to_json();
    assert!(!layered["config"]["rules"]
        .as_array()
        .unwrap()
        .iter()
        .any(|r| r.as_str().unwrap().contains("probe-0.example.invalid")));
    parsed.settings.group_mode = meow_paopao::model::settings::GroupMode::Subscription;
    let raw = build(&parsed).to_json();
    assert_eq!(group(&raw, "sub:url-test")["type"], "url-test");
    assert!(raw["config"]["rules"].as_array().unwrap().contains(&json!(
        "DOMAIN,probe-0.example.invalid,sub:smart,no-resolve"
    )));
    assert_eq!(
        raw["config"]["rules"].as_array().unwrap().last().unwrap(),
        "MATCH,sub:fallback"
    );
    assert_eq!(parsed.subscriptions, saved);
    parsed.settings.group_mode = meow_paopao::model::settings::GroupMode::Layered;
    assert_eq!(build(&parsed).to_json(), layered);
}

#[test]
fn raw_split_retains_rule_priority_across_saved_disabled_subscriptions() {
    let mut request = input(true);
    request["subscriptions"][0]["use_split"] = false.into();
    let mut second = subscription("second");
    second["split"]["rules"][0] = "DOMAIN,probe-0.example.invalid,DIRECT".into();
    second["split"]["rules"][5] = "MATCH,DIRECT".into();
    request["subscriptions"]
        .as_array_mut()
        .unwrap()
        .push(second);
    let out = built(&request);
    let rules = out["config"]["rules"].as_array().unwrap();
    let matching: Vec<_> = rules
        .iter()
        .filter(|r| {
            r.as_str()
                .unwrap()
                .contains("DOMAIN,probe-0.example.invalid,")
        })
        .collect();
    assert_eq!(
        matching,
        vec![&json!(
            "DOMAIN,probe-0.example.invalid,sub:smart,no-resolve"
        )]
    );
    assert_eq!(rules.last().unwrap(), "MATCH,sub:fallback");
}

#[test]
fn imported_interval_survives_clash_parse_and_persistence() {
    for interval in [0_u64, 86400] {
        let parsed = parse_json(&json!({
            "proxies": [{"name": "sample", "type": "socks5", "server": "node.example.invalid", "port": 1080}],
            "proxy-groups": [{"name": "Auto", "type": "url-test", "proxies": ["sample"], "interval": interval}],
            "rules": ["MATCH,Auto"]
        }).to_string());
        assert_eq!(parsed["split"]["groups"][0]["interval"], interval);
        let persisted: SubRules = serde_json::from_value(parsed["split"].clone()).unwrap();
        assert_eq!(serde_json::to_value(persisted).unwrap(), parsed["split"]);
    }
    let legacy = json!({"groups": [{"n": "Old", "t": "select", "m": []}], "rules": []});
    let persisted: SubRules = serde_json::from_value(legacy.clone()).unwrap();
    assert_eq!(serde_json::to_value(persisted).unwrap(), legacy);
}
