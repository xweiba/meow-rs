//! Editing a profile changes every category through the real JSON build
//! boundary, without changing/recompiling the planner.
use meow_paopao::build_json;
use serde_json::{json, Value};

#[test]
fn file_edits_replace_defaults_and_invalid_files_refuse_application() {
    let case: Value =
        serde_json::from_str(include_str!("golden/build/regions--default--v4.json")).unwrap();
    let mut input = case["input"].clone();
    let path = std::env::temp_dir().join(format!(
        "paopao-profile-{}-{}.json",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    input["runtime"]["rulesFile"] = path.to_str().unwrap().into();
    let seeded = build_json(&input.to_string());
    let mut profile = seeded["rulesProfile"].clone();
    assert!(profile.is_object());
    profile["defaultDnsPolicy"] = "policy:google".into();
    profile["dns"]["nameserver"] = json!(["https://192.0.2.53/dns-query#{dnsPolicy}"]);
    profile["privateRules"] = json!(["IP-CIDR,192.0.2.0/24,REJECT,no-resolve"]);
    profile["encryptedDnsRules"] = json!(["DOMAIN-SUFFIX,resolver.example,{dnsPolicy}"]);
    profile["stunRules"] = json!(["AND,((NETWORK,UDP),(DST-PORT,45678)),{dnsPolicy}"]);
    profile["fakeIp"]["fake-ip-filter"] = json!(["+.real.example"]);
    profile["fakeIpFilterIfDirect"] = json!({});
    profile["sniffer"]["skip-domain"] = json!(["+.sniff.example"]);
    profile["policies"][3]["rules"] = json!(["DOMAIN,custom-ai.example,policy:ai"]);
    input["settings"]["tun"] = true.into();
    std::fs::write(&path, profile.to_string()).unwrap();
    let out = build_json(&input.to_string());
    assert!(
        out.get("configError").is_none(),
        "{:?}",
        out.get("configError")
    );
    let rules = out["config"]["rules"].as_array().unwrap();
    for line in [
        "IP-CIDR,192.0.2.0/24,REJECT,no-resolve",
        "DOMAIN-SUFFIX,resolver.example,policy:google",
        "AND,((NETWORK,UDP),(DST-PORT,45678)),policy:google",
        "DOMAIN,custom-ai.example,policy:ai",
    ] {
        assert!(rules.contains(&json!(line)), "missing {line}");
    }
    assert!(!rules
        .iter()
        .any(|r| r.as_str().unwrap().contains("DOMAIN-SUFFIX,ipinfo.io,")));
    assert!(!rules.contains(&json!("IP-CIDR,10.0.0.0/8,DIRECT,no-resolve")));
    assert_eq!(
        out["config"]["dns"]["nameserver"],
        json!(["https://192.0.2.53/dns-query#policy:google"])
    );
    assert_eq!(
        out["config"]["dns"]["fake-ip-filter"],
        json!(["+.real.example"])
    );
    assert_eq!(
        out["config"]["sniffer"]["skip-domain"],
        json!(["+.sniff.example"])
    );
    // A second save changes behavior using the very same loaded library.
    profile["stunRules"] = json!([]);
    profile["policies"][3]["rules"] = json!([]);
    std::fs::write(&path, profile.to_string()).unwrap();
    let out = build_json(&input.to_string());
    let rules = out["config"]["rules"].as_array().unwrap();
    assert!(!rules.iter().any(|r| r.as_str().unwrap().contains("45678")));
    assert!(!rules.contains(&json!("DOMAIN,custom-ai.example,policy:ai")));
    std::fs::write(&path, "{ broken save").unwrap();
    let refused = build_json(&input.to_string());
    assert!(refused["config"].is_null());
    assert!(refused["configError"].is_string());
    assert!(refused["pool"]["nodes"].is_array());
    std::fs::remove_file(path).unwrap();
}

#[test]
fn unknown_fields_versions_and_stages_are_not_silently_ignored() {
    let input = json!({"runtime": {"rulesFile": "/unused/paopao-profile-test.json"}});
    let seeded = build_json(&input.to_string())["rulesProfile"].clone();
    for edit in [
        json!({"version":2}),
        json!({"stunPortz":[]}),
        json!({"order":["match"]}),
        json!({"stunRules":["DST-PORT,{typo},DIRECT"]}),
    ] {
        let mut profile = seeded.clone();
        profile
            .as_object_mut()
            .unwrap()
            .extend(edit.as_object().unwrap().clone());
        let out = build_json(&json!({"runtime":{"rulesProfile":profile}}).to_string());
        assert!(out["config"].is_null());
        assert!(out["configError"].is_string());
    }
}
