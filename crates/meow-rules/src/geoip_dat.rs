//! V2Ray GeoIPList protobuf, as defined by v2fly's routercommon/common.proto.
//! Walk borrowed messages and allocate ranges only for referenced country codes.

use std::collections::{HashMap, HashSet};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::Arc;

use crate::geosite_dat::PbReader;
use crate::ip_set::{IpRangeSet, IpRangeSetBuilder};

pub(crate) fn read(
    data: &[u8],
    allowed: &HashSet<String>,
) -> Result<HashMap<String, Arc<IpRangeSet>>, String> {
    if data.len() > crate::data_reader::MAX_BYTES {
        return Err("GeoIP DAT exceeds 64 MiB".into());
    }
    read_inner(data, allowed).map_err(|e| format!("GeoIP DAT: {e}"))
}

fn read_inner(
    data: &[u8],
    allowed: &HashSet<String>,
) -> Result<HashMap<String, Arc<IpRangeSet>>, String> {
    let allowed: HashSet<String> = allowed.iter().map(|s| s.to_ascii_uppercase()).collect();
    let mut buckets: HashMap<String, IpRangeSetBuilder> = HashMap::new();
    let mut top = PbReader::new(data);
    let mut total_cidrs = 0usize;
    let mut inverse_flags = HashMap::new();
    let mut any_inverse = false;
    while !top.is_at_end() {
        let (field, wire) = top.read_tag().map_err(|e| e.to_string())?;
        if field != 1 || wire != 2 {
            return Err("expected GeoIPList entry (not GeoSite DAT, sing-box DB or SRS)".into());
        }
        let entry = top.read_length_delimited().map_err(|e| e.to_string())?;
        // Protobuf field order is arbitrary: find the code before visiting CIDRs.
        let mut meta = PbReader::new(entry);
        let mut code = "";
        let mut inverse = false;
        while !meta.is_at_end() {
            match meta.read_tag().map_err(|e| e.to_string())? {
                (1, 2) => {
                    code = std::str::from_utf8(
                        meta.read_length_delimited().map_err(|e| e.to_string())?,
                    )
                    .map_err(|e| e.to_string())?;
                }
                (3, 0) => {
                    inverse = meta.read_varint().map_err(|e| e.to_string())? != 0;
                }
                (0, _) => return Err("invalid protobuf field zero".into()),
                (_, wire) => meta.skip_field(wire).map_err(|e| e.to_string())?,
            }
        }
        if code.is_empty()
            || code.len() > 64
            || !code
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        {
            return Err("invalid country/category code".into());
        }
        let key = code.to_ascii_uppercase();
        any_inverse |= inverse;
        if allowed.contains(&key)
            && inverse_flags
                .insert(key.clone(), inverse)
                .is_some_and(|old| old != inverse)
        {
            return Err("duplicate GeoIP country has inconsistent inverse_match flags".into());
        }
        let mut bucket = if allowed.contains(&key) {
            Some(buckets.entry(key).or_default())
        } else {
            None
        };
        let mut fields = PbReader::new(entry);
        while !fields.is_at_end() {
            let (field, wire) = fields.read_tag().map_err(|e| e.to_string())?;
            if field != 2 || wire != 2 {
                fields.skip_field(wire).map_err(|e| e.to_string())?;
                continue;
            }
            let mut cidr =
                PbReader::new(fields.read_length_delimited().map_err(|e| e.to_string())?);
            let mut ip: &[u8] = &[];
            let mut prefix = 0u64;
            while !cidr.is_at_end() {
                match cidr.read_tag().map_err(|e| e.to_string())? {
                    (1, 2) => ip = cidr.read_length_delimited().map_err(|e| e.to_string())?,
                    (2, 0) => prefix = cidr.read_varint().map_err(|e| e.to_string())?,
                    (0, _) => return Err("invalid CIDR protobuf field zero".into()),
                    (_, wire) => cidr.skip_field(wire).map_err(|e| e.to_string())?,
                }
            }
            match ip.len() {
                4 if prefix <= 32 => {
                    let net = ipnet::Ipv4Net::new(
                        Ipv4Addr::new(ip[0], ip[1], ip[2], ip[3]),
                        prefix as u8,
                    )
                    .map_err(|e| e.to_string())?;
                    if let Some(b) = bucket.as_mut() {
                        b.add_v4(net);
                    }
                }
                16 if prefix <= 128 => {
                    let net = ipnet::Ipv6Net::new(
                        Ipv6Addr::from(<[u8; 16]>::try_from(ip).map_err(|e| e.to_string())?),
                        prefix as u8,
                    )
                    .map_err(|e| e.to_string())?;
                    if let Some(b) = bucket.as_mut() {
                        b.add_v6(net);
                    }
                }
                _ => {
                    return Err(
                        "CIDR requires 4/16-byte IP and a valid prefix (not GeoSite DAT)".into(),
                    );
                }
            }
            total_cidrs += 1;
            if total_cidrs > 4 * crate::data_reader::MAX_ITEMS {
                return Err("GeoIP DAT CIDR count exceeds limit".into());
            }
        }
    }
    if total_cidrs == 0 && !any_inverse {
        return Err("no GeoIP CIDRs found".into());
    }
    Ok(buckets
        .into_iter()
        .map(|(k, b)| {
            let ranges = b.build();
            let ranges = if inverse_flags.get(&k) == Some(&true) {
                ranges.complement()
            } else {
                ranges
            };
            (k, Arc::new(ranges))
        })
        .collect())
}
