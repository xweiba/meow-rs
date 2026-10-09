//! Clash YAML subscriptions: `proxies:`, plus the provider's own
//! `proxy-groups:` and `rules:` (Dart: `_parseClash` / `clashProxy`).

use serde_json::{Map, Value};

use crate::dart::{trim, Dv, NULL};
use crate::ingest::outbound::{
    list, need, port, tls_block, transport_block, truthy, Fail, Outbound, Res, Tls,
};
use crate::ingest::yaml;
use crate::model::node::name_or_server;
use crate::model::node::{ParseResult, ProxyNode};
use crate::model::subscription::{SubGroup, SubRules};

/// Keys whose plain YAML scalars are read as written: providers write
/// Clash configs for mihomo, which reads these as strings, so
/// `password: 0123` is `0123` (YAML 1.2 makes it the int 123, `1e3` the
/// float 1000.0, `0x10` 16; B10), and a port as written is checked as
/// decimal (B12).
const AS_WRITTEN: [&str; 10] = [
    "password",
    "uuid",
    "short-id",
    "public-key",
    "psk",
    "auth",
    "auth-str",
    "obfs-password",
    "username",
    "port",
];

/// A Clash config. Not YAML (or no `proxies:` list): nothing, without the
/// split either.
pub(crate) fn parse_clash(text: &str) -> ParseResult {
    let Ok(doc) = yaml::load_keeping_text(text, &AS_WRITTEN) else {
        return ParseResult::default();
    };
    let Dv::List(proxies) = doc.get("proxies") else {
        return ParseResult::default();
    };
    let mut groups = Vec::new();
    if let Dv::List(raw) = doc.get("proxy-groups") {
        for g in raw {
            if !matches!(g, Dv::Map(_)) || g.get("name").is_null() {
                continue;
            }
            let members = match g.get("proxies") {
                Dv::Null => Vec::new(),
                Dv::List(m) => m.iter().map(Dv::dart_string).collect(),
                // Not a list: a broken group, left out (B9: Dart failed
                // the whole subscription).
                _ => continue,
            };
            groups.push(SubGroup {
                name: g.get("name").dart_string(),
                kind: g.get("type").or(&Dv::Str("select".into())).dart_string(),
                members,
            });
        }
    }
    let rules = match doc.get("rules") {
        Dv::List(r) => r.iter().map(Dv::dart_string).collect(),
        _ => Vec::new(),
    };
    let mut out = ParseResult {
        split: SubRules { groups, rules },
        ..ParseResult::default()
    };
    for p in proxies {
        if !matches!(p, Dv::Map(_)) {
            continue;
        }
        // A mistyped field skips its entry only (B9).
        match clash_proxy(p) {
            Ok(Some(n)) => out.nodes.push(n),
            Ok(None) | Err(_) => out.skipped += 1,
        }
    }
    out
}

/// A hysteria2 bandwidth (`up` / `down`) in Mbps, as mihomo reads it: a
/// number with an optional unit — none or `Mbps` is Mbps, `bps` / `Kbps`
/// / `Gbps` / `Tbps` (prefix in any case), a capital `B` for bytes
/// (`10 MBps` = 80 Mbps). Rounded; at least 1 when above zero. None when
/// missing, zero or not a bandwidth. Dart took the first run of digits,
/// so "1 Gbps" was 1 Mbps (B8 / D12).
fn mbps(v: &Dv) -> Option<i64> {
    let s = match v {
        Dv::Int(_) | Dv::Double(_) | Dv::Str(_) => v.dart_string(),
        _ => return None,
    };
    let s = trim(&s);
    let num_end = s
        .find(|c: char| !(c.is_ascii_digit() || c == '.'))
        .unwrap_or(s.len());
    let n: f64 = s[..num_end].parse().ok()?;
    let unit = trim(&s[num_end..]);
    let mut chars = unit.chars();
    let scale = match chars.clone().next() {
        None => return to_mbps(n),
        Some('b' | 'B') => 1e-6,
        Some('k' | 'K') => 1e-3,
        Some('m' | 'M') => 1.0,
        Some('g' | 'G') => 1e3,
        Some('t' | 'T') => 1e6,
        Some(_) => return None,
    };
    if !matches!(unit.as_bytes()[0], b'b' | b'B') {
        chars.next();
    }
    let rest = chars.as_str();
    let bytes = match rest {
        "bps" | "b" | "bit" | "bits" | "" => false,
        "Bps" | "B" => true,
        _ => return None,
    };
    to_mbps(n * scale * if bytes { 8.0 } else { 1.0 })
}

/// Mbps as an int: rounded, at least 1 when above zero, None for zero,
/// not finite or beyond 1 Pbps.
fn to_mbps(v: f64) -> Option<i64> {
    if !(v > 0.0 && v <= 1e9) {
        return None;
    }
    // In 0..=1e9: fits.
    #[allow(clippy::cast_possible_truncation)]
    Some((v.round() as i64).max(1))
}

/// `v is Map ? v : const {}`.
fn map_or_empty(v: &Dv) -> &Dv {
    if matches!(v, Dv::Map(_)) {
        v
    } else {
        &NULL
    }
}

/// One `proxies:` entry; None for an unsupported type.
fn clash_proxy(p: &Dv) -> Res<Option<ProxyNode>> {
    let get = |k: &str| p.get(k);
    let kind = get("type").dart_string_or_empty();
    let name = name_or_server(get("name"), get("server"));
    let server = need(get("server"))?;
    let server_port = port(get("port"))?;
    let sni = get("servername")
        .or(get("sni"))
        .as_str_opt()?
        .map(str::to_owned);
    let insecure = truthy(get("skip-cert-verify"));
    let fp = get("client-fingerprint").as_str_opt()?.map(str::to_owned);
    let alpn = list(get("alpn"));
    let network = get("network").as_str_opt()?;
    let ws = map_or_empty(get("ws-opts"));
    let h2 = map_or_empty(get("h2-opts"));
    let grpc = map_or_empty(get("grpc-opts"));
    let headers = map_or_empty(ws.get("headers"));
    let transport = || -> Res<Option<Value>> {
        let path = ws.get("path").or(h2.get("path")).as_str_opt()?;
        let h2_host = list(h2.get("host")).and_then(|l| l.into_iter().next());
        let host = match headers.get("Host") {
            Dv::Null => h2_host,
            h => h.as_str_opt()?.map(str::to_owned),
        };
        let service = grpc.get("grpc-service-name").as_str_opt()?;
        transport_block(network, path, host.as_deref(), service)
    };
    let tls = |enabled: bool| Tls {
        enabled,
        sni: sni.clone(),
        insecure,
        fingerprint: fp.clone(),
        alpn: alpn.clone(),
        ..Tls::default()
    };
    let base = |kind: &str| {
        let mut o = Outbound::new(kind);
        o.put("server", server.clone());
        o.put("server_port", server_port);
        o
    };
    let o = match kind.as_str() {
        "ss" => {
            let plugin = get("plugin").as_str_opt()?;
            let opts = map_or_empty(get("plugin-opts"));
            let (plugin_name, plugin_opts) = match plugin {
                Some("obfs") => (
                    Some("obfs-local"),
                    Some(format!(
                        "obfs={};obfs-host={}",
                        opts.get("mode").or(&Dv::Str("http".into())).dart_string(),
                        opts.get("host").dart_string_or_empty()
                    )),
                ),
                Some("v2ray-plugin") => {
                    let mut parts = vec![format!(
                        "mode={}",
                        opts.get("mode")
                            .or(&Dv::Str("websocket".into()))
                            .dart_string()
                    )];
                    if !opts.get("host").is_null() {
                        parts.push(format!("host={}", opts.get("host").dart_string()));
                    }
                    if !opts.get("path").is_null() {
                        parts.push(format!("path={}", opts.get("path").dart_string()));
                    }
                    if truthy(opts.get("tls")) {
                        parts.push("tls".into());
                    }
                    (Some("v2ray-plugin"), Some(parts.join(";")))
                }
                Some(p) if !p.is_empty() => return Err(Fail::Format),
                _ => (None, None),
            };
            let mut o = base("shadowsocks");
            o.put("method", need(get("cipher"))?);
            o.put("password", need(get("password"))?);
            o.put_opt("plugin", plugin_name);
            o.put_opt("plugin_opts", plugin_opts);
            o
        }
        "vmess" => {
            let mut o = base("vmess");
            o.put("uuid", need(get("uuid"))?);
            o.put_raw("security", get("cipher").or(&Dv::Str("auto".into())));
            o.put("alter_id", get("alterId").as_int_opt()?.unwrap_or(0));
            o.put_opt("tls", tls_block(tls(truthy(get("tls")))));
            o.put_opt("transport", transport()?);
            o.put("packet_encoding", "xudp");
            o
        }
        "vless" => {
            let reality = get("reality-opts");
            let reality = matches!(reality, Dv::Map(_)).then_some(reality);
            let mut o = base("vless");
            o.put("uuid", need(get("uuid"))?);
            if get("flow").as_str_opt()?.is_some_and(|f| !f.is_empty()) {
                o.put_raw("flow", get("flow"));
            }
            let reality_key = match reality {
                Some(r) => r.get("public-key").as_str_opt()?.map(str::to_owned),
                None => None,
            };
            let short_id = reality
                .map(|r| r.get("short-id"))
                .filter(|v| !v.is_null())
                .map(Dv::dart_string);
            let t = Tls {
                reality_key,
                reality_short_id: short_id,
                ..tls(truthy(get("tls")))
            };
            o.put_opt("tls", tls_block(t));
            o.put_opt("transport", transport()?);
            o.put("packet_encoding", "xudp");
            o
        }
        "trojan" => {
            let mut o = base("trojan");
            o.put("password", need(get("password"))?);
            o.put_opt("tls", tls_block(tls(true)));
            o.put_opt("transport", transport()?);
            o
        }
        "hysteria2" => {
            let obfs = get("obfs").as_str_opt()?;
            let mut o = base("hysteria2");
            o.put("password", need(get("password").or(get("auth")))?);
            o.put_opt("up_mbps", mbps(get("up")));
            o.put_opt("down_mbps", mbps(get("down")));
            if let Some(obfs) = obfs.filter(|s| !s.is_empty()) {
                let mut m = Map::new();
                m.insert("type".into(), obfs.into());
                m.insert(
                    "password".into(),
                    get("obfs-password").dart_string_or_empty().into(),
                );
                o.put("obfs", Value::Object(m));
            }
            let t = Tls {
                fingerprint: None,
                ..tls(true)
            };
            o.put_opt("tls", tls_block(t));
            o
        }
        "tuic" => {
            let mut o = base("tuic");
            o.put("uuid", need(get("uuid"))?);
            o.put("password", need(get("password"))?);
            o.put_raw("congestion_control", get("congestion-controller"));
            o.put_raw("udp_relay_mode", get("udp-relay-mode"));
            let t = Tls {
                fingerprint: None,
                alpn: alpn.clone().or_else(|| Some(vec!["h3".into()])),
                ..tls(true)
            };
            o.put_opt("tls", tls_block(t));
            o
        }
        "socks5" => {
            let mut o = base("socks");
            o.put("version", "5");
            o.put_raw("username", get("username"));
            o.put_raw("password", get("password"));
            o
        }
        "http" => {
            let mut o = base("http");
            o.put_raw("username", get("username"));
            o.put_raw("password", get("password"));
            let t = Tls {
                fingerprint: None,
                alpn: None,
                ..tls(truthy(get("tls")))
            };
            o.put_opt("tls", tls_block(t));
            o
        }
        "anytls" => {
            let mut o = base("anytls");
            o.put("password", need(get("password"))?);
            let t = Tls {
                alpn: None,
                ..tls(true)
            };
            o.put_opt("tls", tls_block(t));
            o
        }
        _ => return Ok(None),
    };
    Ok(Some(ProxyNode {
        name,
        outbound: o.0,
    }))
}
