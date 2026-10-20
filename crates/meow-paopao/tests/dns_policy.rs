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
        if expected == "DIRECT" {
            assert!(!server.contains('#'), "direct needs no adapter: {server}");
        } else {
            assert!(
                server.ends_with(&format!("#{expected}")),
                "IP-rule pre-resolution must use the DNS exit {expected}: {server}"
            );
        }
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

/// Where `MATCH` sends in this build.
fn catch_all(value: &Value) -> String {
    let out = build(&BuildInput::from_json(value));
    let last = out.rules.last().unwrap();
    last.strip_prefix("MATCH,").unwrap().to_owned()
}

#[test]
fn unplaced_names_and_stun_follow_where_match_sends_in_each_mode() {
    let mut value = input();
    value["settings"]["mode"] = "smart".into();
    let smart = catch_all(&value);
    assert_ne!(smart, "DIRECT");
    assert_policy(&value, &smart);
    value["settings"]["mode"] = "global".into();
    let global = catch_all(&value);
    assert_policy(&value, &global);
    // Direct mode: nothing through a proxy, DNS included.
    value["settings"]["mode"] = "direct".into();
    assert_policy(&value, "DIRECT");
}

#[test]
fn selected_group_changes_external_dns_and_stun_except_in_direct_mode() {
    let mut value = input();
    value["settings"]["dns_policy"] = "policy:google".into();
    value["runtime"]["encryptedDnsRules"] =
        json!({"domains": ["dns.google"], "addresses": [], "ports": [853]});
    for mode in ["smart", "global"] {
        value["settings"]["mode"] = mode.into();
        assert_policy(&value, "policy:google");
        let out = build(&BuildInput::from_json(&value));
        assert!(out
            .rules
            .contains(&"DOMAIN-SUFFIX,dns.google,policy:google".into()));
    }
    value["settings"]["mode"] = "direct".into();
    assert_policy(&value, "DIRECT");
}

#[test]
fn removed_group_falls_back_without_direct_upstream() {
    let mut value = input();
    value["settings"]["dns_policy"] = "group:removed".into();
    assert_policy(&value, "policy:ai");
}

#[test]
fn mainland_encrypted_dns_goes_direct() {
    let out = build(&BuildInput::from_json(&input()));
    for rule in [
        "DOMAIN-SUFFIX,doh.pub,DIRECT",
        "DOMAIN-SUFFIX,dns.alidns.com,DIRECT",
        "AND,((DST-PORT,443),(IP-CIDR,223.5.5.5/32,no-resolve)),DIRECT",
        "AND,((DST-PORT,443),(IP-CIDR,119.29.29.29/32,no-resolve)),DIRECT",
    ] {
        assert!(out.rules.contains(&rule.into()), "{rule}");
    }
}
