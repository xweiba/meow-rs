use meow_common::{Metadata, RuleMatchHelper};
use meow_rules::{geosite::GeositeDB, sing_rule_set, RuleSetBehavior};
use std::collections::HashSet;

#[test]
fn published_metacubex_domain_json_and_srs_are_equivalent() {
    let json = include_bytes!("fixtures/sing/0x0.json");
    let srs = include_bytes!("fixtures/sing/0x0.srs");
    let sets = [
        sing_rule_set::from_json(json, RuleSetBehavior::Domain).unwrap(),
        sing_rule_set::from_srs(srs, RuleSetBehavior::Domain).unwrap(),
    ];
    for set in sets {
        for (host, yes) in [
            ("0x0.st", true),
            ("www.0x0.st", true),
            ("0x0.st.evil", false),
            ("other.example", false),
        ] {
            assert_eq!(set.matches_domain(host), yes, "{host}");
        }
        assert!(!set.should_resolve_ip());
    }
    assert!(sing_rule_set::from_srs(srs, RuleSetBehavior::IpCidr).is_err());
}

#[test]
fn published_metacubex_ip_json_and_srs_are_equivalent() {
    let json = include_bytes!("fixtures/sing/private.json");
    let srs = include_bytes!("fixtures/sing/private.srs");
    let sets = [
        sing_rule_set::from_json(json, RuleSetBehavior::IpCidr).unwrap(),
        sing_rule_set::from_srs(srs, RuleSetBehavior::IpCidr).unwrap(),
    ];
    for set in sets {
        assert!(set.should_resolve_ip());
        for (ip, yes) in [
            ("10.2.3.4", true),
            ("192.168.1.1", true),
            ("fc00::1", true),
            ("::1", true),
            ("8.8.8.8", false),
            ("2606:4700::1111", false),
        ] {
            let m = Metadata {
                dst_ip: Some(ip.parse().unwrap()),
                ..Metadata::default()
            };
            assert_eq!(set.matches(&m, &RuleMatchHelper), yes, "{ip}");
        }
    }
    assert!(sing_rule_set::from_json(json, RuleSetBehavior::Domain).is_err());
}

#[test]
fn published_legacy_geosite_db_loads_only_allowlisted_category() {
    let bytes = include_bytes!("fixtures/sing/geosite-lite.db");
    let allowed = HashSet::from(["apple".into()]);
    let db = GeositeDB::from_bytes(bytes, Some(&allowed)).unwrap();
    assert_eq!(db.category_count(), 1);
    assert!(db.domain_count("apple").unwrap() > 100);
    assert!(db.lookup("apple", "apple.com"));
    assert!(db.lookup("apple", "www.apple.com"));
    assert!(!db.lookup("cn", "baidu.com"));
    assert_eq!(
        GeositeDB::from_bytes(bytes, Some(&HashSet::new()))
            .unwrap()
            .category_count(),
        0
    );
    assert!(GeositeDB::from_bytes(&bytes[..bytes.len() - 1], Some(&allowed)).is_err());
    assert_eq!(
        GeositeDB::from_bytes(bytes, None).unwrap().category_count(),
        24
    );
}

#[test]
fn upstream_legacy_writer_all_four_item_types_and_suffix_semantics() {
    let bytes = include_bytes!("fixtures/sing/legacy-semantics.db");
    let db = GeositeDB::from_bytes(bytes, Some(&HashSet::from(["test".into()]))).unwrap();
    for (host, yes) in [
        ("exact.example", true),
        ("www.exact.example", false),
        ("both.example", true),
        ("www.both.example", true),
        ("sub.example", false),
        ("www.sub.example", true),
        ("needle.example", true),
        ("regex.example", true),
        ("other.example", false),
    ] {
        assert_eq!(db.lookup("test", host), yes, "{host}");
    }
    assert!(!db.lookup("ignored", "ignored.example"));
    assert_eq!(db.category_count(), 1);
}

#[test]
fn current_upstream_encoder_all_five_srs_versions_preserve_nested_semantics() {
    let json = include_bytes!("fixtures/sing/headless.json");
    let mut sets = vec![sing_rule_set::from_json(json, RuleSetBehavior::Classical).unwrap()];
    for srs in [
        include_bytes!("fixtures/sing/headless-v1.srs").as_slice(),
        include_bytes!("fixtures/sing/headless-v2.srs"),
        include_bytes!("fixtures/sing/headless-v3.srs"),
        include_bytes!("fixtures/sing/headless-v4.srs"),
        include_bytes!("fixtures/sing/headless-v5.srs"),
    ] {
        sets.push(sing_rule_set::from_srs(srs, RuleSetBehavior::Classical).unwrap());
    }
    for set in sets {
        for (host, source, dest, yes) in [
            ("exact.example", "192.168.1.1", "203.0.113.1", true),
            ("exact.example", "172.16.1.1", "203.0.113.1", false),
            ("both.example", "192.168.1.1", "203.0.113.1", true),
            ("sub.example", "192.168.1.1", "203.0.113.1", false),
            ("www.sub.example", "192.168.1.1", "203.0.113.1", true),
            ("aneedle.example", "192.168.1.1", "203.0.113.1", true),
            ("regex.example", "192.168.1.1", "203.0.113.1", true),
            ("logic.example", "172.16.1.1", "203.0.113.1", true),
            ("blocked.logic.example", "172.16.1.1", "203.0.113.1", false),
            ("deny.example", "192.168.1.1", "10.1.1.1", true),
            ("deny.example", "172.16.1.1", "10.1.1.1", false),
            ("deny.example", "172.16.1.1", "8.8.8.8", false),
            ("other.example", "172.16.1.1", "8.8.8.8", true),
            ("deny.example", "192.168.1.1", "2001:db8::1", true),
        ] {
            let m = Metadata {
                host: host.into(),
                src_ip: Some(source.parse().unwrap()),
                dst_ip: Some(dest.parse().unwrap()),
                ..Metadata::default()
            };
            assert_eq!(
                set.matches(&m, &RuleMatchHelper),
                yes,
                "{host}/{source}/{dest}"
            );
        }
    }
}

#[test]
fn json_preserves_default_or_groups_and_logical_and_invert() {
    let json = br#"{"version":5,"rules":[{"type":"logical","mode":"and","rules":[{"domain_suffix":"both.example","ip_cidr":"10.0.0.0/8","source_ip_cidr":"192.168.0.0/16"},{"domain":"blocked.both.example","invert":true}]}]}"#;
    let set = sing_rule_set::from_json(json, RuleSetBehavior::Classical).unwrap();
    for (host, source, dest, yes) in [
        ("both.example", "192.168.1.1", "8.8.8.8", true),
        ("other.example", "192.168.1.1", "10.1.1.1", true),
        ("other.example", "192.168.1.1", "8.8.8.8", false),
        ("both.example", "172.16.1.1", "10.1.1.1", false),
        ("blocked.both.example", "192.168.1.1", "10.1.1.1", false),
    ] {
        let m = Metadata {
            host: host.into(),
            src_ip: Some(source.parse().unwrap()),
            dst_ip: Some(dest.parse().unwrap()),
            ..Metadata::default()
        };
        assert_eq!(
            set.matches(&m, &RuleMatchHelper),
            yes,
            "{host}/{source}/{dest}"
        );
    }
    assert!(sing_rule_set::from_json(json, RuleSetBehavior::Domain).is_err());
    assert!(sing_rule_set::from_json(json, RuleSetBehavior::IpCidr).is_err());
}

#[test]
fn strict_json_rejects_unknown_fields_types_versions_and_malformed_rules() {
    for json in [
        r#"{"version":6,"rules":[]}"#,
        r#"{"version":2,"rules":[],"future":true}"#,
        r#"{"version":2,"rules":[{"domain":"a.example","process_name":"curl"}]}"#,
        r#"{"version":2,"rules":[{"domain":"a.example","future":true}]}"#,
        r#"{"version":2,"rules":[{"type":"logical","mode":"xor","rules":[]}] }"#,
        r#"{"version":2,"rules":[{"type":"logical","mode":"and","rules":[]}] }"#,
        r#"{"version":2,"rules":[{"domain":"a.example","mode":"or"}]}"#,
        r#"{"version":2,"rules":[{"domain":null}]}"#,
        r#"{"version":2,"rules":[{"domain_regex":"("}]}"#,
        r#"{"version":2,"rules":[{"ip_cidr":"999.0.0.1/9"}]}"#,
        r#"{"version":2,"rules":[{"domain":"a.example","domain":"b.example"}]}"#,
    ] {
        assert!(
            sing_rule_set::from_json(json.as_bytes(), RuleSetBehavior::Classical).is_err(),
            "{json}"
        );
    }
}

#[test]
fn future_srs_and_invalid_legacy_directory_fail() {
    for bytes in [b"SRS\x06data".as_slice(), b"SRS\0data", b"SRSMnative-cache"] {
        assert!(sing_rule_set::from_srs(bytes, RuleSetBehavior::Classical).is_err());
    }
    for bytes in [
        b"\0\xff\xff\xff\xff\xff\xff\xff\xff\xff\x7f".as_slice(),
        b"\0\x01\x01a\0\x01\x05\x01x",
        b"\0\x01\x01a\x7f\x01",
    ] {
        assert!(GeositeDB::from_bytes(bytes, None).is_err());
    }
}
