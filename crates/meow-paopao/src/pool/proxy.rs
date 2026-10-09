//! Nodes as meow `proxies:` entries (Dart: `clashProxyFor`). The pool
//! takes only nodes this can convert, so a line's tag is its proxy name.

use serde_json::{Map, Value};

use crate::dart::Dv;
use crate::model::node::ProxyNode;

/// One node as a meow `proxies:` entry named `name`; None when the core
/// can't take it (plain HTTP, transports other than ws / grpc / h2, h2 for
/// trojan). Keys come in Dart's order: `name`, `server`, `port`, `type`,
/// the protocol's fields, then the transport's.
///
/// As in Dart, optional fields left unset are dropped, except for plain
/// shadowsocks (`cipher` / `password` stay, possibly null) and nested maps
/// (`plugin-opts`, `reality-opts` keep their nulls); hysteria2 always has
/// `skip-cert-verify`.
///
/// Divergence: where a field has a type Dart's casts reject (a non-string
/// `plugin` or `server_name`, a non-numeric `server_port`, `alpn` that is
/// not a list of strings where it is written, non-string ws headers, a
/// non-map hysteria2 `obfs`), Dart throws and the whole config fails; here
/// the node is not converted. The app's own parser never writes those.
pub fn clash_proxy_for(node: &ProxyNode, name: &str) -> Option<Map<String, Value>> {
    let o = &node.outbound;
    let tls = obj(o.get("tls"));
    let transport = obj(o.get("transport"));
    let reality = tls.and_then(|t| obj(t.get("reality")));
    let utls = tls.and_then(|t| obj(t.get("utls")));
    let field = |m: Option<&Map<String, Value>>, k: &str| -> Value {
        m.and_then(|m| m.get(k)).cloned().unwrap_or(Value::Null)
    };
    let get = |k: &str| field(Some(o), k);

    let mut p = Map::new();
    p.insert("name".into(), name.into());
    p.insert(
        "server".into(),
        Dv::from_json(&get("server")).dart_string_or_empty().into(),
    );
    // `(server_port as num?)?.toInt() ?? 0`.
    let port = match get("server_port") {
        Value::Null => 0,
        v => Dv::from_json(&v).as_int_opt().ok().flatten()?,
    };
    p.insert("port".into(), port.into());
    // `tls?['server_name'] as String?`, `tls?['alpn'] as List?`: evaluated
    // (and cast) for every type.
    let sni = match field(tls, "server_name") {
        Value::Null => Value::Null,
        v @ Value::String(_) => v,
        _ => return None,
    };
    let alpn = match field(tls, "alpn") {
        Value::Null => None,
        Value::Array(a) => Some(a),
        _ => return None,
    };
    // `.cast<String>()` is lazy: it only fails where the list is written.
    let alpn_value = || -> Option<Value> {
        match &alpn {
            None => Some(Value::Null),
            Some(a) if a.iter().all(Value::is_string) => Some(Value::Array(a.clone())),
            Some(_) => None,
        }
    };
    let insecure = field(tls, "insecure") == Value::Bool(true);
    let insecure_or_null = || {
        if insecure {
            Value::Bool(true)
        } else {
            Value::Null
        }
    };
    let fingerprint = || field(utls, "fingerprint");

    match node.kind() {
        "shadowsocks" => {
            let plugin = match get("plugin") {
                Value::Null => None,
                Value::String(s) => Some(s),
                _ => return None,
            };
            p.insert("type".into(), "ss".into());
            p.insert("cipher".into(), get("method"));
            p.insert("password".into(), get("password"));
            let Some(plugin) = plugin else {
                return Some(p);
            };
            let mut opts = Map::new();
            let raw = Dv::from_json(&get("plugin_opts")).dart_string_or_empty();
            for part in raw.split(';') {
                let (k, v) = match part.split_once('=') {
                    Some((k, v)) => (k, Value::String(v.into())),
                    None => (part, Value::Bool(true)),
                };
                if !k.is_empty() {
                    opts.insert(k.into(), v);
                }
            }
            let obfs = plugin == "obfs-local";
            p.insert(
                "plugin".into(),
                if obfs { "obfs".into() } else { plugin.into() },
            );
            let opts = if obfs {
                let mut m = Map::new();
                m.insert("mode".into(), field(Some(&opts), "obfs"));
                m.insert("host".into(), field(Some(&opts), "obfs-host"));
                m
            } else {
                opts
            };
            p.insert("plugin-opts".into(), Value::Object(opts));
        }
        kind @ ("vmess" | "vless") => {
            let n = net(transport)?;
            p.insert("type".into(), kind.into());
            p.insert("uuid".into(), get("uuid"));
            if kind == "vmess" {
                p.insert("alterId".into(), or(get("alter_id"), 0.into()));
                p.insert("cipher".into(), or(get("security"), "auto".into()));
            } else {
                p.insert("flow".into(), get("flow"));
            }
            p.insert("tls".into(), tls.is_some().into());
            p.insert("servername".into(), sni);
            p.insert("skip-cert-verify".into(), insecure_or_null());
            if kind == "vless" {
                p.insert("client-fingerprint".into(), fingerprint());
                if let Some(r) = reality {
                    let mut m = Map::new();
                    m.insert("public-key".into(), field(Some(r), "public_key"));
                    m.insert("short-id".into(), or(field(Some(r), "short_id"), "".into()));
                    p.insert("reality-opts".into(), Value::Object(m));
                }
            }
            p.extend(n);
        }
        "trojan" => {
            let n = net(transport)?;
            if n.get("network").and_then(Value::as_str) == Some("h2") {
                return None;
            }
            p.insert("type".into(), "trojan".into());
            p.insert("password".into(), get("password"));
            p.insert("sni".into(), sni);
            p.insert("alpn".into(), alpn_value()?);
            p.insert("skip-cert-verify".into(), insecure_or_null());
            p.extend(n);
        }
        "anytls" => {
            p.insert("type".into(), "anytls".into());
            p.insert("password".into(), get("password"));
            p.insert("sni".into(), sni);
            p.insert("alpn".into(), alpn_value()?);
            p.insert("skip-cert-verify".into(), insecure_or_null());
            p.insert("client-fingerprint".into(), fingerprint());
        }
        "hysteria2" => {
            let obfs = match get("obfs") {
                Value::Null => None,
                Value::Object(m) => Some(m),
                _ => return None,
            };
            p.insert("type".into(), "hysteria2".into());
            p.insert("password".into(), get("password"));
            p.insert("obfs".into(), field(obfs.as_ref(), "type"));
            p.insert("obfs-password".into(), field(obfs.as_ref(), "password"));
            p.insert("sni".into(), sni);
            p.insert("alpn".into(), alpn_value()?);
            p.insert("skip-cert-verify".into(), insecure.into());
            p.insert("up".into(), get("up_mbps"));
            p.insert("down".into(), get("down_mbps"));
        }
        "tuic" => {
            p.insert("type".into(), "tuic".into());
            p.insert("uuid".into(), get("uuid"));
            p.insert("password".into(), get("password"));
            p.insert("sni".into(), sni);
            p.insert("alpn".into(), alpn_value()?);
            p.insert("skip-cert-verify".into(), insecure_or_null());
            p.insert("congestion-controller".into(), get("congestion_control"));
            p.insert("udp-relay-mode".into(), get("udp_relay_mode"));
        }
        "socks" => {
            p.insert("type".into(), "socks5".into());
            p.insert("username".into(), get("username"));
            p.insert("password".into(), get("password"));
        }
        // The core has no plain HTTP proxy outbound.
        _ => return None,
    }
    // Dart's `clean()`: top-level nulls go (nested maps keep theirs).
    p.retain(|_, v| !v.is_null());
    Some(p)
}

/// `v is Map ? v as Map : null`.
fn obj(v: Option<&Value>) -> Option<&Map<String, Value>> {
    v.and_then(Value::as_object)
}

/// `a ?? b`.
fn or(a: Value, b: Value) -> Value {
    if a.is_null() {
        b
    } else {
        a
    }
}

/// The transport's Clash fields (`network` and its options); empty without
/// a transport, None for one the core can't do.
fn net(transport: Option<&Map<String, Value>>) -> Option<Map<String, Value>> {
    let mut out = Map::new();
    let Some(t) = transport else {
        return Some(out);
    };
    // `?t[k]`: only when present and not null.
    let put = |m: &mut Map<String, Value>, to: &str, from: &str| {
        if let Some(v) = t.get(from).filter(|v| !v.is_null()) {
            m.insert(to.into(), v.clone());
        }
    };
    let mut opts = Map::new();
    let (network, opts_key) = match t.get("type").and_then(Value::as_str) {
        Some("ws") => {
            put(&mut opts, "path", "path");
            match t.get("headers") {
                None | Some(Value::Null) => {}
                // `Map<String, String>.from(headers)`.
                Some(Value::Object(h)) if h.values().all(Value::is_string) => {
                    opts.insert("headers".into(), Value::Object(h.clone()));
                }
                Some(_) => return None,
            }
            ("ws", "ws-opts")
        }
        Some("grpc") => {
            put(&mut opts, "grpc-service-name", "service_name");
            ("grpc", "grpc-opts")
        }
        Some("http") => {
            put(&mut opts, "host", "host");
            put(&mut opts, "path", "path");
            ("h2", "h2-opts")
        }
        _ => return None,
    };
    out.insert("network".into(), network.into());
    out.insert(opts_key.into(), Value::Object(opts));
    Some(out)
}
