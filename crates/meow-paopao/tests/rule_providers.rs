//! Credential-free parse → persistence → merge → final config regression.
use meow_paopao::{build_json, parse_json, rule_profile::RuleProfile};
use serde_json::{json, Value};

const FIXTURE: &str = include_str!("fixtures/rule-providers.yaml");

#[test]
fn sing_formats_and_background_fetch_survive_import_validation() {
    for format in ["srs", "json"] {
        let mut request = input(false);
        request["subscriptions"][0]["split"]["providers"]["ranges"]["format"] = format.into();
        request["subscriptions"][0]["split"]["providers"]["ranges"]["background-fetch"] =
            true.into();
        let out = built(&request);
        assert!(out["config"]["rule-providers"]
            .as_object()
            .unwrap()
            .values()
            .any(|p| p["format"] == format && p["background-fetch"] == true));
    }
    let mut request = input(false);
    request["subscriptions"][0]["split"]["providers"]["common"]["background-fetch"] = "yes".into();
    let out = build_json(&request.to_string());
    assert!(out["config"].is_null());
    assert!(out["configError"]
        .as_str()
        .unwrap()
        .contains("background-fetch"));
}

fn subscription(id: &str) -> Value {
    let parsed = parse_json(FIXTURE);
    json!({"id": id, "url": "", "name": id, "nodes": parsed["nodes"], "split": parsed["split"]})
}

fn input(raw: bool) -> Value {
    json!({
        "subscriptions": [subscription("first"), subscription("second")],
        "settings": {"group_mode": if raw {"subscription"} else {"layered"}},
    })
}

fn built(input: &Value) -> Value {
    let out = build_json(&input.to_string());
    assert!(
        out.get("configError").is_none(),
        "{:?}",
        out.get("configError")
    );
    out
}

#[test]
fn parser_and_persistence_retain_every_provider_field() {
    let parsed = parse_json(FIXTURE);
    assert_eq!(parsed["nodes"].as_array().unwrap().len(), 1);
    let split: meow_paopao::SubRules = serde_json::from_value(parsed["split"].clone()).unwrap();
    assert_eq!(serde_json::to_value(&split).unwrap(), parsed["split"]);
    assert_eq!(split.providers["common"]["x-metadata"]["enabled"], true);
    assert_eq!(
        split.providers["ranges"]["header"]["User-Agent"],
        json!(["paopao-fixture"])
    );
    assert_eq!(
        split.providers["ranges"]["path"],
        "/etc/router/../../rules.txt"
    );
}

#[test]
fn clash_json_retains_providers_too() {
    let parsed = parse_json(&json!({
        "proxies": [{"name": "sample", "type": "socks5", "server": "proxy.example.invalid", "port": 1080}],
        "rule-providers": {"domains": {"type": "inline", "behavior": "domain", "payload": ["+.example.test"]}},
        "rules": ["RULE-SET,domains,DIRECT"],
    }).to_string());
    assert_eq!(parsed["nodes"].as_array().unwrap().len(), 1);
    assert_eq!(
        parsed["split"]["providers"]["domains"]["payload"],
        json!(["+.example.test"])
    );
    assert_eq!(parsed["split"]["rules"], json!(["RULE-SET,domains,DIRECT"]));
}

#[test]
fn collisions_options_nested_rules_and_groups_survive_both_modes() {
    for raw in [false, true] {
        let out = built(&input(raw));
        let config = &out["config"];
        let providers = config["rule-providers"].as_object().unwrap();
        assert_eq!(
            providers
                .keys()
                .filter(|k| k.starts_with("sub-provider:"))
                .count(),
            6,
            "same spelling in two subscriptions stays independent"
        );
        let rules = config["rules"].as_array().unwrap();
        assert_eq!(
            rules
                .iter()
                .filter(|r| r.as_str().unwrap().contains("DOMAIN,priority.example,"))
                .count(),
            1
        );
        assert_eq!(
            rules
                .iter()
                .filter(|r| r.as_str().unwrap().starts_with("RULE-SET,sub-provider:"))
                .count(),
            4
        );
        assert_eq!(
            rules
                .iter()
                .filter(|r| r.as_str().unwrap().contains("(RULE-SET,"))
                .count(),
            2
        );
        assert_eq!(
            rules
                .iter()
                .filter(|r| r.as_str().unwrap().ends_with(",No-Resolve,src"))
                .count(),
            2
        );
        let groups = config["proxy-groups"].as_array().unwrap();
        for (name, provider) in providers {
            assert!(rules.iter().any(|r| {
                let r = r.as_str().unwrap();
                r.contains(&format!("RULE-SET,{name},")) || r.contains(&format!("RULE-SET,{name})"))
            }));
            if !name.starts_with("sub-provider:") {
                continue;
            }
            match provider["type"].as_str().unwrap() {
                "http" => {
                    let path = provider["path"].as_str().unwrap();
                    assert!(path.starts_with("rule-providers/paopao-") && path.ends_with(".text"));
                    assert!(!path.contains("..") && !path.contains("router"));
                    assert_eq!(provider["proxy"], "proxy");
                    assert!(groups.iter().any(|g| g["name"] == provider["proxy"]));
                    assert_eq!(provider["interval"], 3600);
                    assert_eq!(provider["header"]["User-Agent"], json!(["paopao-fixture"]));
                }
                "inline" => assert_eq!(provider["payload"], json!(["+.service.example"])),
                "file" => assert_eq!(provider["path"], "rules/local.yaml"),
                _ => panic!("unexpected provider"),
            }
        }
        assert_eq!(
            rules.last().unwrap(),
            if raw {
                "MATCH,sub:Fallback"
            } else {
                "MATCH,policy:final"
            }
        );
    }
}

#[test]
fn stable_ids_keep_names_and_caches_when_priority_changes() {
    let mut input = input(false);
    let before = built(&input);
    input["subscriptions"].as_array_mut().unwrap().reverse();
    let after = built(&input);
    let a = before["config"]["rule-providers"].as_object().unwrap();
    let b = after["config"]["rule-providers"].as_object().unwrap();
    for (name, definition) in a {
        assert_eq!(&b[name], definition);
    }
    let paths: std::collections::HashSet<_> = a
        .iter()
        .filter(|(name, _)| name.starts_with("sub-provider:"))
        .filter_map(|(_, p)| p["path"].as_str())
        .filter(|p| p.starts_with("rule-providers/"))
        .collect();
    assert_eq!(paths.len(), 2);
}

#[test]
fn undefined_providers_refuse_application_but_keep_the_tree() {
    let mut input = input(false);
    input["subscriptions"][0]["split"]["providers"]
        .as_object_mut()
        .unwrap()
        .remove("common");
    let out = build_json(&input.to_string());
    assert!(out["config"].is_null());
    assert!(out["configError"]
        .as_str()
        .unwrap()
        .contains("undefined rule provider"));
    assert!(out["configError"]
        .as_str()
        .unwrap()
        .contains("common (subscription first)"));
    assert!(out["tree"].is_object() && out["pool"].is_object());
}

#[test]
fn unsafe_file_paths_are_rejected_on_every_platform() {
    for path in [
        "../rules.yaml",
        "rules/../../private",
        "/etc/rules",
        "C:/rules",
        "C:\\rules",
        "rules\\..\\private",
        "//host/share",
        "rules/\nlocal",
    ] {
        let mut input = input(false);
        input["subscriptions"][0]["split"]["providers"]["local"]["path"] = path.into();
        let out = build_json(&input.to_string());
        assert!(out["config"].is_null(), "accepted unsafe path");
        assert!(out["configError"].as_str().unwrap().contains("relative"));
    }
}

#[test]
fn final_mode_and_enabled_filters_omit_unused_providers() {
    for mode in ["direct", "global"] {
        let mut input = input(false);
        input["settings"]["mode"] = mode.into();
        // An invalid descriptor unused in this mode must not break it.
        input["subscriptions"][0]["split"]["providers"]["local"]["path"] = "../bad".into();
        let out = built(&input);
        assert!(out["config"].get("rule-providers").is_none());
        assert_eq!(
            out["config"]["rules"].as_array().unwrap().last().unwrap(),
            if mode == "direct" {
                "MATCH,DIRECT"
            } else {
                "MATCH,proxy"
            }
        );
    }
    let mut input = input(false);
    for sub in input["subscriptions"].as_array_mut().unwrap() {
        sub["use_split"] = false.into();
    }
    let out = built(&input);
    assert!(out["config"]["rule-providers"]
        .as_object()
        .unwrap()
        .keys()
        .all(|name| !name.starts_with("sub-provider:")));
}

#[test]
fn profile_descriptors_are_optional_pass_through_and_only_emitted_when_referenced() {
    let mut profile: Value =
        serde_json::from_str(include_str!("../defaults/routing-rules.json")).unwrap();
    profile.as_object_mut().unwrap().remove("ruleProviders");
    let legacy: RuleProfile = serde_json::from_value(profile.clone()).unwrap();
    assert!(legacy.rule_providers.is_empty());
    assert!(legacy.validate().is_ok());
    profile["ruleProviders"] = json!({"custom": {"type": "inline", "behavior": "classical", "payload": ["DOMAIN,profile.example"], "x-extra": {"enabled": true}}});
    profile["privateRules"] = json!(["RULE-SET,custom,DIRECT,no-resolve"]);
    let input = json!({"settings": {"mode": "direct"}, "runtime": {"rulesProfile": profile}});
    let out = built(&input);
    assert_eq!(
        out["config"]["rule-providers"]["custom"]["x-extra"]["enabled"],
        true
    );
    assert_eq!(
        out["config"]["rule-providers"]["custom"]["payload"],
        json!(["DOMAIN,profile.example"])
    );
    let mut bad = input;
    bad["runtime"]["rulesProfile"]["ruleProviders"] = json!({});
    assert!(build_json(&bad.to_string())["configError"]
        .as_str()
        .unwrap()
        .contains("undefined rule provider: custom"));
}

#[test]
fn profile_rule_exclusions_keep_provider_references_and_source_flags() {
    let mut profile: Value =
        serde_json::from_str(include_str!("../defaults/routing-rules.json")).unwrap();
    profile["ruleProviders"]["ranges"] =
        json!({"type": "inline", "behavior": "ipcidr", "payload": ["192.0.2.0/24"]});
    profile["policies"][0]["rules"] = json!(["RULE-SET,ranges,policy:ai,No-Resolve,src"]);
    profile["policies"][0]["group"] = "policy:ai".into();
    // Avoid duplicate policy ids if the shipped catalog puts AI elsewhere.
    let policies = profile["policies"].as_array_mut().unwrap();
    let first = policies.remove(0);
    policies.retain(|p| p["group"] != "policy:ai");
    policies.insert(0, first);
    let input = json!({
        "subscriptions": [subscription("first")],
        "settings": {"group_edits": {"policy:ai": {"exclude": ["skip.example"]}}},
        "runtime": {"rulesProfile": profile},
    });
    let out = built(&input);
    assert!(out["config"]["rule-providers"].get("ranges").is_some());
    assert!(out["config"]["rules"].as_array().unwrap().contains(&json!(
        "AND,((RULE-SET,ranges,No-Resolve,src),(NOT,((DOMAIN-SUFFIX,skip.example)))),policy:ai"
    )));
}

#[test]
fn shipped_cn_private_and_ai_use_managed_providers_without_duplicate_geosite_references() {
    let out = built(&input(false));
    let rules = out["config"]["rules"].as_array().unwrap();
    let providers = out["config"]["rule-providers"].as_object().unwrap();
    for (name, category, format, target) in [
        ("geosite-cn", "cn", "mrs", "policy:china"),
        ("geosite-private", "private", "text", "DIRECT"),
        ("geosite-ai", "category-ai-!cn", "yaml", "policy:ai"),
        ("geosite-openai", "openai", "mrs", "policy:ai"),
        ("geosite-anthropic", "anthropic", "mrs", "policy:ai"),
        ("geosite-perplexity", "perplexity", "mrs", "policy:ai"),
        ("geosite-xai", "xai", "mrs", "policy:ai"),
    ] {
        assert!(rules.contains(&json!(format!("RULE-SET,{name},{target}"))));
        assert!(!rules.iter().any(|r| {
            r.as_str()
                .unwrap()
                .contains(&format!("GEOSITE,{category},"))
        }));
        assert_eq!(providers[name]["format"], format);
        assert_eq!(providers[name]["behavior"], "domain");
        assert!(providers[name]["url"]
            .as_str()
            .unwrap()
            .starts_with("https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/"));
    }
}

#[test]
fn inline_profile_api_input_rejects_defective_definitions_even_when_unused() {
    let cases = [
        json!(false),
        json!({"type": "unknown", "behavior": "domain"}),
        json!({"type": "http", "url": "https://rules.example.invalid/rules"}),
        json!({"type": "http", "behavior": "unsupported", "url": "https://rules.example.invalid/rules"}),
        json!({"type": "http", "behavior": "domain"}),
        json!({"type": "http", "behavior": "domain", "url": "malformed:opaque-marker"}),
        json!({"type": "http", "behavior": "domain", "url": "https:///rules"}),
        json!({"type": "http", "behavior": "domain", "url": "https://rules.example.invalid/rules", "format": "unknown"}),
        json!({"type": "http", "behavior": "domain", "url": "https://rules.example.invalid/rules", "interval": -1}),
        json!({"type": "http", "behavior": "domain", "url": "https://rules.example.invalid/rules", "header": {"User-Agent": 42}}),
        json!({"type": "inline", "behavior": "classical", "format": "mrs", "payload": []}),
        json!({"type": "inline", "behavior": "domain", "payload": [42]}),
        json!({"type": "inline", "behavior": "domain", "payload": [], "interval": 10}),
        json!({"type": "file", "behavior": "domain", "path": "../rules.yaml"}),
    ];
    for definition in cases {
        let mut profile: Value =
            serde_json::from_str(include_str!("../defaults/routing-rules.json")).unwrap();
        profile["ruleProviders"]["unused"] = definition;
        // Matches the native PUT runner: inline profile, no rulesFile.
        let out = build_json(&json!({"runtime": {"rulesProfile": profile}}).to_string());
        assert!(out["config"].is_null());
        let error = out["configError"].as_str().unwrap();
        assert!(error.contains("rule provider definition"));
        assert!(!error.contains("opaque-marker") && !error.contains("rules.example.invalid"));
    }
}

#[test]
fn undefined_profile_rule_targets_and_download_groups_are_rejected() {
    for (target, proxy, reason) in [
        ("missing-group", "DIRECT", "rule target is undefined"),
        (
            "DIRECT",
            "missing-group",
            "download proxy/group is undefined",
        ),
    ] {
        let mut profile: Value =
            serde_json::from_str(include_str!("../defaults/routing-rules.json")).unwrap();
        profile["ruleProviders"]["custom"] =
            json!({"type": "inline", "behavior": "domain", "payload": [], "proxy": proxy});
        profile["privateRules"] = json!([format!("RULE-SET,custom,{target}")]);
        let out = build_json(&json!({"runtime": {"rulesProfile": profile}}).to_string());
        assert!(out["config"].is_null());
        assert!(out["configError"].as_str().unwrap().contains(reason));
    }
}

#[test]
fn debug_summaries_hide_provider_urls_and_headers() {
    let mut sub = subscription("debug");
    sub["split"]["providers"]["ranges"]["header"]["User-Agent"] = "opaque-header-marker".into();
    sub["split"]["providers"]["ranges"]["url"] =
        "https://rules.example.invalid/opaque-url-marker".into();
    let split: meow_paopao::SubRules = serde_json::from_value(sub["split"].clone()).unwrap();
    let input = meow_paopao::BuildInput::from_json(&json!({"subscriptions": [sub]}));
    let pool = meow_paopao::build_pool(&input.pool_input());
    let imported = meow_paopao::plan::imported_split(&input, &pool, &input.effective());
    let debug = format!("{split:?} {imported:?} {:?}", RuleProfile::shipped());
    assert!(!debug.contains("opaque-header-marker") && !debug.contains("opaque-url-marker"));
}

#[test]
fn hostile_and_long_provider_names_produce_bounded_distinct_local_cache_paths() {
    let names = ["../../outside".to_owned(), "规则".repeat(300)];
    let mut definitions = serde_json::Map::new();
    for name in &names {
        definitions.insert(
            name.clone(),
            json!({
                "type": "http", "behavior": "domain", "format": "YAML",
                "url": "https://rules.example.invalid/payload", "path": "C:\\outside.yaml",
            }),
        );
    }
    let input = json!({"subscriptions": [{
        "id": "../../subscription", "url": "", "nodes": [],
        "split": {"providers": definitions, "rules": names.iter().map(|n| format!("RULE-SET,{n},DIRECT")).collect::<Vec<_>>()},
    }]});
    let out = built(&input);
    let providers = out["config"]["rule-providers"].as_object().unwrap();
    let mut paths = std::collections::HashSet::new();
    for (name, provider) in providers
        .iter()
        .filter(|(name, _)| name.starts_with("sub-provider:"))
    {
        assert!(!name.contains(['/', '\\', ',']));
        let path = provider["path"].as_str().unwrap();
        assert!(path.starts_with("rule-providers/paopao-") && path.ends_with(".yaml"));
        assert!(path.len() < 80 && !path.contains(".."));
        assert!(paths.insert(path));
    }
    assert_eq!(paths.len(), 2);
}
