//! Hosts entries as meow's `paopao-hosts` (Dart: `paopaoHosts` in
//! `hosts.dart`).

use serde_json::{Map, Value};

use crate::model::settings::{HostEntry, HostMatch};

/// meow-rs `paopao-hosts`: the entries in order (the first match wins),
/// each `{type, value, address?}` with type `exact` / `suffix` / `keyword`
/// / `regex` / `wildcard`; no `address` = let the name through unchanged.
///
/// Pass the hosts of the settings in effect on the current network
/// ([`crate::effective_settings`]). The config carries the key only when
/// there are entries; they are not repeated in `hosts:`.
pub fn paopao_hosts(hosts: &[HostEntry]) -> Vec<Value> {
    hosts
        .iter()
        .map(|h| {
            let mut m = Map::new();
            let kind = match h.matches {
                HostMatch::Exact => "exact",
                HostMatch::Domain => "suffix",
                HostMatch::Keyword => "keyword",
                HostMatch::Regex => "regex",
                HostMatch::Wildcard => "wildcard",
            };
            m.insert("type".into(), kind.into());
            m.insert("value".into(), h.pattern.clone().into());
            if let Some(a) = &h.address {
                m.insert("address".into(), a.clone().into());
            }
            Value::Object(m)
        })
        .collect()
}
