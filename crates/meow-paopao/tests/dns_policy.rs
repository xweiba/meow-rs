//! Business DNS follows domain routing. External encrypted DNS and STUN
//! remain separately configurable instead of overriding business egress.
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
        assert!(
            server.starts_with("tcp://"),
            "proxy-tagged DoH/DoT is unsupported by the DNS client: {server}"
        );
        assert!(
            server.ends_with(&format!("#{expected}")),
            "IP-rule pre-resolution must use the configured protected DNS exit: {server}"
        );
    }
    assert!(dns["proxy-server-nameserver"].as_array().is_some());
    assert_eq!(dns["direct-nameserver"], json!(["system"]));
    assert_eq!(dns["follow-domain-rules"], true);
    let stun = format!("AND,((NETWORK,UDP),(DST-PORT,3478/5349/19302-19309)),{expected}");
    let index = out.rules.iter().position(|r| r == &stun).unwrap();
    // A TCP-only selected leaf is skipped by Clash-compatible routing.
    // Fail closed here instead of sending STUN through a later policy.
    assert_eq!(
        out.rules[index + 1],
        "AND,((NETWORK,UDP),(DST-PORT,3478/5349/19302-19309)),REJECT"
    );
}

#[test]
fn domain_dns_follows_rules_while_external_dns_and_stun_use_policy() {
    let mut value = input();
    for mode in ["smart", "global", "direct"] {
        value["settings"]["mode"] = mode.into();
        assert_policy(&value, "policy:ai");
    }
}

#[test]
fn selected_group_changes_external_dns_and_stun_without_overriding_domain_dns() {
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
