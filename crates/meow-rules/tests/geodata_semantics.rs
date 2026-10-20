use meow_rules::{country_index::CountryIndex, geodata_format};
use std::collections::HashSet;

// A one-node MMDB with a caller-supplied typed data record. Unlike a metadata
// label check, the validator must distinguish what the actual records contain.
fn mmdb(kind: &str, record: &[u8]) -> Vec<u8> {
    fn string(out: &mut Vec<u8>, s: &str) {
        assert!(s.len() < 29);
        out.push(0x40 | s.len() as u8);
        out.extend_from_slice(s.as_bytes());
    }
    let mut db = vec![0, 0, 17, 0, 0, 1];
    db.extend_from_slice(&[0; 16]);
    db.extend_from_slice(record);
    db.extend_from_slice(b"\xab\xcd\xefMaxMind.com");
    db.push(0xe9);
    string(&mut db, "node_count");
    db.extend_from_slice(&[0xc1, 1]);
    string(&mut db, "record_size");
    db.extend_from_slice(&[0xa1, 24]);
    string(&mut db, "ip_version");
    db.extend_from_slice(&[0xa1, 4]);
    string(&mut db, "database_type");
    string(&mut db, kind);
    string(&mut db, "languages");
    db.extend_from_slice(&[0, 4]);
    string(&mut db, "binary_format_major_version");
    db.extend_from_slice(&[0xa1, 2]);
    string(&mut db, "binary_format_minor_version");
    db.push(0xa0);
    string(&mut db, "build_epoch");
    db.extend_from_slice(&[1, 2, 1]);
    string(&mut db, "description");
    db.push(0xe0);
    db
}

#[test]
fn sing_geoip_country_strings_are_indexed_case_insensitively() {
    let bytes = mmdb("sing-geoip", b"\x42cn");
    geodata_format::validate_country(&bytes).unwrap();
    assert!(geodata_format::validate_asn(&bytes).is_err());
    let index = CountryIndex::from_bytes(&bytes, &HashSet::from(["cn".into()])).unwrap();
    assert!(index.ranges_for("CN").contains("1.2.3.4".parse().unwrap()));
    assert!(!index
        .ranges_for("CN")
        .contains("200.2.3.4".parse().unwrap()));
    assert!(index.ranges_for("US").is_empty());
}

#[test]
fn metadata_label_alone_does_not_validate_an_asn_package() {
    let empty = mmdb("GeoLite2-ASN", b"\xe0");
    assert!(geodata_format::validate_asn(&empty).is_err());
    assert!(geodata_format::validate_country(&empty).is_err());
    let mut asn_record = vec![0xe1, 0x58];
    asn_record.extend_from_slice(b"autonomous_system_number");
    asn_record.extend_from_slice(&[0xc2, 0x19, 0x3a]);
    let asn = mmdb("Country", &asn_record);
    geodata_format::validate_asn(&asn).unwrap();
    assert!(geodata_format::validate_country(&asn).is_err());
}

#[test]
fn dat_inverse_preserves_complement_and_rejects_invalid_unselected_cidrs() {
    let mut dat = vec![10, 14, 10, 2, b'z', b'z', 18, 8, 10, 4, 10, 0, 0, 0, 16, 8];
    geodata_format::validate_country(&dat).unwrap();
    // The empty allowlist must still validate, without retaining any ranges.
    let last = dat.len() - 1;
    dat[last] = 33;
    assert!(CountryIndex::from_bytes(&dat, &HashSet::new()).is_err());
    dat[last] = 8;
    dat[1] = 16;
    dat.extend_from_slice(&[24, 1]);
    geodata_format::validate_country(&dat).unwrap();
    let index = CountryIndex::from_bytes(&dat, &HashSet::from(["ZZ".into()])).unwrap();
    let ranges = index.ranges_for("ZZ");
    assert!(!ranges.contains("10.1.2.3".parse().unwrap()));
    assert!(ranges.contains("8.8.8.8".parse().unwrap()));
    assert!(ranges.contains("2001:db8::1".parse().unwrap()));
    assert!(!ranges.is_empty());
    assert!(ranges.has_v4() && ranges.has_v6());
    assert!(ranges.covers("8.8.8.0/24".parse().unwrap()));
    assert!(!ranges.covers("10.0.0.0/8".parse().unwrap()));
}

#[test]
fn published_private_dat_inverse_reaches_source_and_destination_geoip_rules() {
    use meow_common::{Metadata, Rule, RuleMatchHelper};
    use meow_rules::{geoip::GeoIpRule, src_geoip::SrcGeoIpRule};
    use std::sync::Arc;
    let bytes = include_bytes!("fixtures/upstream/private.dat");
    // This published fixture contains one GeoIP entry. Set its protobuf
    // inverse_match field, preserving all actual upstream private ranges.
    let mut cursor = 1usize;
    let mut length = 0usize;
    let mut shift = 0;
    loop {
        let b = bytes[cursor];
        cursor += 1;
        length |= usize::from(b & 127) << shift;
        if b < 128 {
            break;
        }
        shift += 7;
    }
    assert_eq!(cursor + length, bytes.len());
    let mut inverse = vec![10];
    let mut n = length + 2;
    while n >= 128 {
        inverse.push((n as u8 & 127) | 128);
        n >>= 7;
    }
    inverse.push(n as u8);
    inverse.extend_from_slice(&bytes[cursor..]);
    inverse.extend_from_slice(&[24, 1]);
    let index = CountryIndex::from_bytes(&inverse, &HashSet::from(["PRIVATE".into()])).unwrap();
    let ranges = index.ranges_for("PRIVATE");
    let destination = GeoIpRule::new("PRIVATE", "DIRECT", false, Arc::clone(&ranges));
    let source = SrcGeoIpRule::new("PRIVATE", "DIRECT", ranges);
    let mut metadata = Metadata {
        src_ip: Some("10.0.0.1".parse().unwrap()),
        dst_ip: Some("8.8.8.8".parse().unwrap()),
        ..Metadata::default()
    };
    assert!(destination.match_metadata(&metadata, &RuleMatchHelper));
    assert!(!source.match_metadata(&metadata, &RuleMatchHelper));
    metadata.swap_src_dst();
    assert!(!destination.match_metadata(&metadata, &RuleMatchHelper));
    assert!(source.match_metadata(&metadata, &RuleMatchHelper));
    assert!(!destination.never_matches());
    assert!(!source.never_matches());
    assert!(!destination.match_metadata(&Metadata::default(), &RuleMatchHelper));
    assert!(index.ranges_for("ABSENT").is_empty());
}

#[test]
fn inverse_all_exclusions_and_empty_exclusions_keep_both_address_families() {
    use meow_rules::ip_set::IpRangeSet;
    let all = IpRangeSet::default().complement();
    assert!(!all.is_empty());
    assert!(all.has_v4() && all.has_v6());
    assert!(all.contains("0.0.0.0".parse().unwrap()));
    assert!(all.contains("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff".parse().unwrap()));
    let none =
        IpRangeSet::from_nets(["0.0.0.0/0".parse().unwrap(), "::/0".parse().unwrap()]).complement();
    assert!(none.is_empty());
    assert!(!none.has_v4() && !none.has_v6());
    assert!(!none.covers("0.0.0.0/0".parse().unwrap()));
    assert!(!none.contains("::1".parse().unwrap()));
    let inverse_empty_dat = [10, 6, 10, 2, b'z', b'z', 24, 1];
    geodata_format::validate_country(&inverse_empty_dat).unwrap();
    let index =
        CountryIndex::from_bytes(&inverse_empty_dat, &HashSet::from(["ZZ".into()])).unwrap();
    assert!(index.ranges_for("ZZ").contains("8.8.8.8".parse().unwrap()));
}
