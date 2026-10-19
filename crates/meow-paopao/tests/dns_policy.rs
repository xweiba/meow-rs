//! Privacy egress must bind internal DNS, encrypted DNS rules and STUN to
//! the same selected group; an ordinary site rule cannot bind core DNS.
use meow_paopao::{build, BuildInput};
use serde_json::{json, Value};

fn input() -> Value {
    let case: Value =
        serde_json::from_str(include_str!("golden/build/regions--default--v4.json")).unwrap();
    case["input"].clone()
}

fn assert_policy(value: &Value, expected: &str) {
    let out = build(&BuildInput::from_json(value));
    let dns = &out.config["dns"];
    let servers = dns["nameserver"].as_array().unwrap();
    assert_eq!(servers.len(), 2);
    for server in servers {
        let server = server.as_str().unwrap();
        assert!(server.starts_with("https://"));
        assert!(server.ends_with(&format!("#{expected}")), "{server}");
    }
    assert!(dns["proxy-server-nameserver"].as_array().is_some());
    assert!(out.rules.contains(&format!(
        "AND,((NETWORK,UDP),(DST-PORT,3478/5349/19302-19309)),{expected}"
    )));
}

#[test]
fn dns_and_stun_default_to_ai_in_all_modes() {
    let mut value = input();
    for mode in ["smart", "global", "direct"] {
        value["settings"]["mode"] = mode.into();
        assert_policy(&value, "policy:ai");
    }
}

#[test]
fn selected_group_applies_to_core_dns_external_dns_and_stun() {
    let mut value = input();
    value["settings"]["dns_policy"] = "policy:google".into();
    value["runtime"]["encryptedDnsRules"] =
        json!({"domains": ["dns.google"], "addresses": [], "ports": [853]});
    assert_policy(&value, "policy:google");
    let out = build(&BuildInput::from_json(&value));
    assert!(out
        .rules
        .contains(&"DOMAIN-SUFFIX,dns.google,policy:google".into()));
}

#[test]
fn removed_group_falls_back_to_ai_without_direct_upstream() {
    let mut value = input();
    value["settings"]["dns_policy"] = "group:removed".into();
    assert_policy(&value, "policy:ai");
}
