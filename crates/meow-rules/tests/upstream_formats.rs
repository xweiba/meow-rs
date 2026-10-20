//! Offline interoperability against byte-exact published upstream data.
use meow_common::{Metadata, RuleMatchHelper};
use meow_rules::{build_rule_set_from_mrs_with_behavior, ParserContext, RuleSetBehavior};
use meow_rules::{country_index::CountryIndex, geodata_format};
use std::collections::HashSet;

const DOMAIN: &[u8] = include_bytes!("fixtures/upstream/github.mrs");
const IP: &[u8] = include_bytes!("fixtures/upstream/private.mrs");
const DAT: &[u8] = include_bytes!("fixtures/upstream/private.dat");
const COUNTRY: &[u8] = include_bytes!("fixtures/upstream/GeoIP2-Country-Test.mmdb");
const ASN: &[u8] = include_bytes!("fixtures/upstream/GeoLite2-ASN-Test.mmdb");

#[test]
fn published_maxmind_country_and_asn_are_distinguished() {
    geodata_format::validate_country(COUNTRY).unwrap();
    geodata_format::validate_asn(ASN).unwrap();
    assert!(geodata_format::validate_country(ASN).is_err());
    assert!(geodata_format::validate_asn(COUNTRY).is_err());
    let allowed = HashSet::from(["GB".to_string()]);
    let index = CountryIndex::from_bytes(COUNTRY, &allowed).unwrap();
    assert!(index
        .ranges_for("GB")
        .contains("81.2.69.142".parse().unwrap()));
}

#[test]
fn published_metacubex_domain_mrs() {
    let set = build_rule_set_from_mrs_with_behavior(
        DOMAIN,
        &ParserContext::empty(),
        Some(RuleSetBehavior::Domain),
        true,
    )
    .unwrap();
    assert!(set.len() > 10);
    assert!(set.matches_domain("github.com"));
    assert!(set.matches_domain("www.github.com"));
    assert!(set.matches_domain("github-api.arkoselabs.com"));
    assert!(!set.matches_domain("www.github-api.arkoselabs.com"));
    assert!(!set.matches_domain("github.com.example"));
    assert!(build_rule_set_from_mrs_with_behavior(
        DOMAIN,
        &ParserContext::empty(),
        Some(RuleSetBehavior::IpCidr),
        true
    )
    .is_err());
}

#[test]
fn upstream_encoder_suffix_only_unicode_and_wildcard_semantics() {
    let bytes = include_bytes!("fixtures/upstream/domain-semantics.mrs");
    let set = build_rule_set_from_mrs_with_behavior(
        bytes,
        &ParserContext::empty(),
        Some(RuleSetBehavior::Domain),
        true,
    )
    .unwrap();
    for (host, expected) in [
        ("suffix.example", false),
        ("www.suffix.example", true),
        ("both.example", true),
        ("www.both.example", true),
        ("exact.example", true),
        ("www.exact.example", false),
        ("x.wild.example", true),
        ("wild.example", false),
        ("x.y.wild.example", false),
        ("中文.example", true),
        ("www.中文.example", false),
        ("测试.example", true),
        ("www.测试.example", true),
    ] {
        assert_eq!(set.matches_domain(host), expected, "{host}");
    }
}

#[test]
fn published_metacubex_ipcidr_mrs() {
    let set = build_rule_set_from_mrs_with_behavior(
        IP,
        &ParserContext::empty(),
        Some(RuleSetBehavior::IpCidr),
        true,
    )
    .unwrap();
    for (addr, expected) in [
        ("10.2.3.4", true),
        ("192.168.1.1", true),
        ("fd00::42", true),
        ("::1", true),
        ("8.8.8.8", false),
        ("2606:4700::1111", false),
    ] {
        let metadata = Metadata {
            dst_ip: Some(addr.parse().unwrap()),
            ..Metadata::default()
        };
        assert_eq!(set.matches(&metadata, &RuleMatchHelper), expected, "{addr}");
    }
}

#[test]
fn published_v2ray_private_dat() {
    geodata_format::validate_country(DAT).unwrap();
    assert!(geodata_format::validate_asn(DAT).is_err());
    let allowed = HashSet::from(["private".to_string()]);
    let index = CountryIndex::from_bytes(DAT, &allowed).unwrap();
    assert_eq!(index.country_count(), 1);
    let ranges = index.ranges_for("PRIVATE");
    for addr in ["10.1.2.3", "127.0.0.1", "192.168.1.1", "fc00::1"] {
        assert!(ranges.contains(addr.parse().unwrap()), "{addr}");
    }
    assert!(!ranges.contains("8.8.8.8".parse().unwrap()));
    assert_eq!(
        CountryIndex::from_bytes(DAT, &HashSet::new())
            .unwrap()
            .country_count(),
        0
    );
    assert!(CountryIndex::from_bytes(&DAT[..DAT.len() - 1], &allowed).is_err());
}

#[test]
fn unsupported_or_mismatched_containers_are_errors() {
    for bytes in [
        b"SRS\x01anything".as_slice(),
        b"\x00\x01old-sing-geosite",
        b"<html>error</html>",
        b"",
        b"\x0a\x0e\x0a\x02cn\x12\x08\x08\x02\x12\x04test",
    ] {
        assert!(
            geodata_format::validate_country(bytes).is_err(),
            "{bytes:?}"
        );
    }
}
