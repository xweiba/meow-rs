//! The config's fixed sections (Dart: the literals in `buildClashConfig`):
//! profile, rule data, DNS, sniffer and the virtual adapter.

use serde_json::{json, Value};

use crate::plan::{OutboundOptions, VpnOptions};

/// The core keeps selector picks between runs.
pub fn profile() -> Value {
    json!({ "store-selected": true })
}

/// Business DNS and all matching exceptions come from editable data.
pub fn dns(
    ipv6: bool,
    tun: bool,
    policy: &str,
    profile: &crate::rule_profile::RuleProfile,
    direct_pick: impl Fn(&str) -> bool,
) -> Value {
    let mut d = profile.dns.clone();
    // Upstream tags apply to the internal DNS client, not ordinary rules.
    if let Some(servers) = d.get_mut("nameserver").and_then(Value::as_array_mut) {
        for server in servers {
            if let Some(s) = server.as_str() {
                // Direct: a plain upstream, no adapter tag.
                let s = if policy == "DIRECT" {
                    s.replace("#{dnsPolicy}", "")
                } else {
                    s.to_owned()
                };
                *server =
                    crate::rule_profile::RuleProfile::expand(&s, &[("dnsPolicy", policy)]).into();
            }
        }
    }
    d["ipv6"] = ipv6.into();
    if tun {
        if let (Some(d), Some(fake)) = (d.as_object_mut(), profile.fake_ip.as_object()) {
            d.extend(fake.clone());
        }
        if let Some(filter) = d.get_mut("fake-ip-filter").and_then(Value::as_array_mut) {
            for (group, names) in &profile.fake_ip_filter_if_direct {
                if direct_pick(group) {
                    filter.extend(names.iter().cloned().map(Value::String));
                }
            }
        }
    }
    d
}

/// The virtual adapter (desktop): every program's traffic into the device,
/// DNS answered inside. IPv6 into it too while the network reaches IPv6;
/// direct traffic leaves by `outbound_interface` when the user chose one,
/// else the core picks a physical uplink. `vpn` (`runtime.vpn`): how to
/// live beside another VPN — the core does the work at run time (its
/// routes, DNS, client processes), these keys carry the user's choices and
/// hand-entered fallbacks; without it the section is the one before.
/// `outbound` (`runtime.outbound`): the interfaces the user chose — one
/// replaces `outbound_interface`, two or more are spread over by the core
/// (`outbound-interfaces`; the default interface stays automatic as the
/// fallback and for local destinations).
pub fn tun(
    ipv6: bool,
    outbound_interface: Option<&str>,
    vpn: Option<&VpnOptions>,
    outbound: Option<&OutboundOptions>,
    known_vpn_clients: &[String],
) -> Value {
    let mut t = serde_json::Map::new();
    t.insert("enable".into(), true.into());
    t.insert("auto-route".into(), "global".into());
    if ipv6 {
        t.insert("inet6-address".into(), json!(["fdfe:dcba:9876::1/126"]));
    }
    t.insert("auto-detect-interface".into(), true.into());
    match outbound.map(|o| o.interfaces.as_slice()) {
        Some([one]) => {
            t.insert("outbound-interface".into(), one.as_str().into());
        }
        Some(many) if many.len() >= 2 => {
            t.insert("outbound-interfaces".into(), many.to_vec().into());
            if outbound.is_some_and(|o| !o.sticky) {
                t.insert("outbound-sticky".into(), false.into());
            }
        }
        _ => {
            if let Some(i) = outbound_interface {
                t.insert("outbound-interface".into(), i.into());
            }
        }
    }
    t.insert("dns-hijack".into(), json!(["any:53"]));
    if let Some(v) = vpn {
        t.insert("follow-system-routes".into(), v.follow_routes.into());
        if let Some(via) = &v.default_via {
            t.insert("default-via".into(), via.as_str().into());
        }
        if !v.exclude_nets.is_empty() {
            t.insert(
                "route-exclude-address".into(),
                v.exclude_nets.clone().into(),
            );
        }
        if !v.internal_domains.is_empty() {
            let domains: Vec<Value> = v
                .internal_domains
                .iter()
                .map(|d| {
                    let mut m = serde_json::Map::new();
                    m.insert("suffix".into(), d.suffix.as_str().into());
                    if !d.servers.is_empty() {
                        m.insert("servers".into(), d.servers.clone().into());
                    }
                    if let Some(i) = &d.iface {
                        m.insert("iface".into(), i.as_str().into());
                    }
                    Value::Object(m)
                })
                .collect();
            t.insert("vpn-domains".into(), domains.into());
        }
        if !v.gateway_domains.is_empty() {
            t.insert(
                "vpn-gateway-domains".into(),
                v.gateway_domains.clone().into(),
            );
        }
        if !v.client_apps.is_empty() {
            t.insert("vpn-client-apps".into(), v.client_apps.clone().into());
        }
        // The rule file's well-known clients: in force while one runs, so
        // listing them costs nothing to those who have none.
        if !known_vpn_clients.is_empty() {
            t.insert(
                "vpn-known-clients".into(),
                known_vpn_clients.to_vec().into(),
            );
        }
    }
    Value::Object(t)
}
