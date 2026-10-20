//! Semantic validation before downloaded geodata can replace the last good file.

use maxminddb::PathElement;
use std::collections::HashSet;

/// Recognise the country container by its MMDB metadata marker. DAT has no magic.
pub fn is_mmdb(bytes: &[u8]) -> bool {
    bytes
        .windows(14)
        .rev()
        .take(128 * 1024)
        .any(|w| w == b"\xab\xcd\xefMaxMind.com")
}

/// Accept country-record MMDB, sing-box `sing-geoip` string MMDB, or V2Ray GeoIP DAT.
/// ASN-only MMDBs, GeoSite DAT, SRS and legacy sing-box GeoSite DB are errors.
pub fn validate_country(bytes: &[u8]) -> Result<(), String> {
    if is_mmdb(bytes) {
        validate_mmdb(bytes, false)
    } else {
        crate::geoip_dat::read(bytes, &HashSet::new()).map(|_| ())
    }
}

/// Accept only an MMDB containing actual `autonomous_system_number` records.
pub fn validate_asn(bytes: &[u8]) -> Result<(), String> {
    validate_mmdb(bytes, true)
}

fn validate_mmdb(bytes: &[u8], asn: bool) -> Result<(), String> {
    let reader = maxminddb::Reader::from_source(bytes).map_err(|e| format!("invalid MMDB: {e}"))?;
    let sing = reader.metadata.database_type == "sing-geoip";
    let mut seen = HashSet::new();
    let mut usable = false;
    for entry in reader
        .networks(Default::default())
        .map_err(|e| e.to_string())?
    {
        let entry = entry.map_err(|e| format!("invalid MMDB network: {e}"))?;
        if let Some(offset) = entry.offset() {
            if !seen.insert(offset) {
                continue;
            }
        } else {
            continue;
        }
        entry.network().map_err(|e| e.to_string())?;
        if asn {
            usable |= entry
                .decode_path::<u32>(&[PathElement::Key("autonomous_system_number")])
                .map_err(|e| format!("invalid ASN MMDB record: {e}"))?
                .is_some_and(|n| n != 0);
        } else {
            let code = if sing {
                entry.decode::<&str>()
            } else {
                entry.decode_path::<&str>(&[
                    PathElement::Key("country"),
                    PathElement::Key("iso_code"),
                ])
            };
            usable |= code
                .map_err(|e| format!("invalid country MMDB record: {e}"))?
                .is_some_and(|s| !s.is_empty());
        }
    }
    if usable {
        Ok(())
    } else {
        Err(format!(
            "MMDB contains no usable {} records (wrong geodata package)",
            if asn { "ASN" } else { "country" }
        ))
    }
}
