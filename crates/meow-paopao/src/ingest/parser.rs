//! Subscription bodies and share links → nodes (Dart: `parser.dart`).
//!
//! Accepted: sing-box JSON, SIP008 JSON, Clash YAML (see [`super::clash`]),
//! and lists of share links, optionally base64-encoded.

use base64::Engine;
use serde_json::{Map, Value};

use crate::dart::{is_regex_space, trim, utf8_decode, Dv};
use crate::ingest::clash::parse_clash;
use crate::ingest::outbound::{
    decode, decode_name, dv, list, need, port, tls_block, transport_block, truthy, Fail, Outbound,
    Res, Tls,
};
use crate::ingest::uri::Uri;
use crate::ingest::ParseError;
use crate::model::node::name_or_server;
use crate::model::node::{is_supported_type, ParseResult, ProxyNode};

/// Turns whatever a subscription link returns into nodes.
///
/// An entry that can't be used (unsupported, missing fields, a field of an
/// unexpected type such as `alterId: "0"`) is counted in
/// [`ParseResult::skipped`] and the rest are kept; Dart failed the whole
/// subscription on a mistyped field (B9). A body that is not a
/// subscription at all gives no nodes.
pub fn parse_subscription(body: &str) -> Result<ParseResult, ParseError> {
    let text = trim(body).replacen('\u{feff}', "", 1);
    if text.is_empty() {
        return Ok(ParseResult::default());
    }
    if text.starts_with('{') || text.starts_with('[') {
        if let Some(json) = try_json(&text) {
            return Ok(parse_json(&json));
        }
    }
    if has_proxies_line(&text) {
        return Ok(parse_clash(&text));
    }
    if let Some(decoded) = try_base64(&text) {
        if decoded.contains("://") {
            return parse_subscription(&decoded);
        }
    }
    parse_share_links(&text)
}

/// One share link per line (`ss://`, `vmess://`, `vless://`, ...); lines
/// without `://` are ignored, broken ones skipped.
pub fn parse_share_links(text: &str) -> Result<ParseResult, ParseError> {
    let mut out = ParseResult::default();
    for raw in lines(text) {
        let line = trim(raw);
        if line.is_empty() || !line.contains("://") {
            continue;
        }
        match parse_share_link(line) {
            Ok(Some(node)) => out.nodes.push(node),
            Ok(None) | Err(_) => out.skipped += 1,
        }
    }
    Ok(out)
}

/// A single share link; None when unsupported or broken, an error where
/// Dart threw (a field of an unexpected type).
pub fn parse_share_link(link: &str) -> Result<Option<ProxyNode>, ParseError> {
    let scheme = link.split("://").next().unwrap_or_default().to_lowercase();
    let node = match scheme.as_str() {
        "ss" => ss(link),
        "vmess" => vmess(link),
        "vless" => vless_or_trojan(link, "vless"),
        "trojan" => vless_or_trojan(link, "trojan"),
        "hysteria2" | "hy2" => hysteria2(link),
        "tuic" => tuic(link),
        "socks" | "socks5" => socks(link),
        "anytls" => anytls(link),
        _ => return Ok(None),
    };
    match node {
        Ok(n) => Ok(Some(n)),
        Err(Fail::Format) => Ok(None),
        Err(Fail::Crash(c)) => Err(ParseError::from(c)),
    }
}

// ------------------------------------------------------------------ helpers

/// `LineSplitter`: lines end at `\n`, `\r\n` or `\r`.
fn lines(text: &str) -> impl Iterator<Item = &str> {
    text.split('\n')
        .flat_map(|l| l.strip_suffix('\r').unwrap_or(l).split('\r'))
}

/// `RegExp(r'^proxies\s*:', multiLine: true)`: a line (after `\n`, `\r`,
/// U+2028 or U+2029) starting with `proxies`, optional spaces, `:`.
fn has_proxies_line(text: &str) -> bool {
    let starts = std::iter::once(0).chain(
        text.char_indices()
            .filter(|(_, c)| matches!(c, '\n' | '\r' | '\u{2028}' | '\u{2029}'))
            .map(|(i, c)| i + c.len_utf8()),
    );
    starts.into_iter().any(|i| {
        text[i..]
            .strip_prefix("proxies")
            .is_some_and(|rest| rest.trim_start_matches(is_regex_space).starts_with(':'))
    })
}

fn try_json(text: &str) -> Option<Dv> {
    serde_json::from_str::<Value>(text)
        .ok()
        .map(|v| Dv::from_json(&v))
}

/// `_tryBase64`: whitespace dropped, URL-safe letters mapped, padding added;
/// the result must be valid UTF-8 (a leading BOM is dropped, as Dart does).
pub(crate) fn try_base64(text: &str) -> Option<String> {
    let compact: String = text.chars().filter(|c| !is_regex_space(*c)).collect();
    if compact.is_empty()
        || !compact
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'+' | b'/' | b'=' | b'_' | b'-'))
    {
        return None;
    }
    let mut normal = compact.replace('-', "+").replace('_', "/");
    let width = normal.len().div_ceil(4) * 4;
    normal.extend(std::iter::repeat_n('=', width - normal.len()));
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(normal)
        .ok()?;
    utf8_decode(bytes)
}

/// The decoded fragment ([`decode_name`]), else `fallback` (the host).
fn name_of(uri: &Uri, fallback: &str) -> String {
    let name = decode_name(uri.fragment());
    if trim(&name).is_empty() {
        fallback.to_owned()
    } else {
        name
    }
}

fn parse_uri(s: &str) -> Res<Uri> {
    Uri::parse(s).map_err(|_| Fail::Format)
}

fn query(uri: &Uri) -> Res<std::collections::HashMap<String, String>> {
    use crate::ingest::uri::DecodeError;
    uri.query_parameters().map_err(|e| match e {
        DecodeError::Format => Fail::Format,
        DecodeError::Argument => Fail::Crash(crate::dart::Crash("query decoding".into())),
    })
}

fn node(name: String, o: Outbound) -> ProxyNode {
    ProxyNode {
        name,
        outbound: o.0,
    }
}

// ------------------------------------------------------------------ links

fn ss(link: &str) -> Res<ProxyNode> {
    let mut body = link
        .get(5..)
        .ok_or_else(|| Fail::Crash(crate::dart::Crash("substring".into())))?
        .to_owned();
    let mut name = String::new();
    if let Some(hash) = body.find('#') {
        name = decode_name(&body[hash + 1..]);
        body.truncate(hash);
    }
    // Legacy: ss://base64(method:password@host:port)
    if !body.contains('@') {
        body = try_base64(body.split('?').next().unwrap_or_default()).ok_or(Fail::Format)?;
    }
    let uri = parse_uri(&format!("ss://{body}"))?;
    let mut user_info = decode(uri.user_info())?;
    if !user_info.contains(':') {
        user_info = try_base64(uri.user_info()).unwrap_or_default();
    }
    let colon = match user_info.find(':') {
        Some(c) if c > 0 => c,
        _ => return Err(Fail::Format),
    };
    let q = query(&uri)?;
    let (mut plugin_name, mut plugin_opts) = (None, None);
    if let Some(plugin) = q.get("plugin").filter(|p| !p.is_empty()) {
        let mut parts = plugin.split(';');
        let first = parts.next().unwrap_or_default();
        plugin_name = Some(
            if first == "simple-obfs" {
                "obfs-local"
            } else {
                first
            }
            .to_owned(),
        );
        plugin_opts = Some(parts.collect::<Vec<_>>().join(";"));
    }
    let name = if trim(&name).is_empty() {
        uri.host().to_owned()
    } else {
        name
    };
    let mut o = Outbound::new("shadowsocks");
    o.put("server", need(&Dv::Str(uri.host().into()))?);
    o.put("server_port", port(&Dv::Int(uri.port()))?);
    o.put("method", &user_info[..colon]);
    o.put("password", &user_info[colon + 1..]);
    if plugin_name.is_some() {
        o.put_opt("plugin", plugin_name);
        o.put_opt("plugin_opts", plugin_opts);
    }
    Ok(node(name, o))
}

fn vmess(link: &str) -> Res<ProxyNode> {
    let encoded = link
        .get(8..)
        .ok_or_else(|| Fail::Crash(crate::dart::Crash("substring".into())))?;
    let json = try_base64(encoded.split('#').next().unwrap_or_default());
    let v = json.as_deref().and_then(try_json).unwrap_or(Dv::Null);
    if !matches!(v, Dv::Map(_)) {
        return Err(Fail::Format);
    }
    let get = |k: &str| v.get(k);
    let net = get("net").or(&Dv::Str("tcp".into())).dart_string();
    let header_type = get("type").dart_string_or_empty();
    let name = name_or_server(get("ps"), get("add"));
    let mut o = Outbound::new("vmess");
    o.put("server", need(get("add"))?);
    o.put("server_port", port(get("port"))?);
    o.put("uuid", need(get("id"))?);
    let scy = get("scy").dart_string_or_empty();
    o.put(
        "security",
        if scy.is_empty() {
            "auto".to_owned()
        } else {
            scy
        },
    );
    let aid = get("aid").or(&Dv::Int(0)).dart_string();
    o.put("alter_id", crate::dart::int_try_parse(&aid).unwrap_or(0));
    let sni = get("sni").dart_string_or_empty();
    let tls = Tls {
        enabled: get("tls").dart_string() == "tls",
        sni: Some(if sni.is_empty() {
            get("host").dart_string_or_empty()
        } else {
            sni
        }),
        fingerprint: get("fp").as_str_opt()?.map(str::to_owned),
        alpn: list(get("alpn")),
        insecure: truthy(get("allowInsecure")) || truthy(get("skip-cert-verify")),
        ..Tls::default()
    };
    o.put_opt("tls", tls_block(tls));
    let path = get("path").as_str_opt()?;
    let host = get("host").as_str_opt()?;
    let transport = if net == "tcp" && header_type == "http" {
        transport_block(Some("http"), path, host, None)?
    } else {
        transport_block(Some(&net), path, host, path)?
    };
    o.put_opt("transport", transport);
    o.put("packet_encoding", "xudp");
    Ok(node(name, o))
}

fn vless_or_trojan(link: &str, kind: &str) -> Res<ProxyNode> {
    let uri = parse_uri(link)?;
    let q = query(&uri)?;
    let vless = kind == "vless";
    let security = q
        .get("security")
        .map_or(if vless { "none" } else { "tls" }, String::as_str);
    let secret = need(&Dv::Str(decode(uri.user_info())?))?;
    let name = name_of(&uri, uri.host());
    let mut o = Outbound::new(kind);
    o.put("server", need(&Dv::Str(uri.host().into()))?);
    o.put("server_port", port(&Dv::Int(uri.port()))?);
    o.put(if vless { "uuid" } else { "password" }, secret);
    if vless {
        o.put_opt("flow", q.get("flow").filter(|f| !f.is_empty()).cloned());
    }
    let reality = security == "reality";
    let tls = Tls {
        enabled: security == "tls" || reality,
        sni: q.get("sni").or_else(|| q.get("peer")).cloned(),
        insecure: truthy(&dv(q.get("allowInsecure"))) || truthy(&dv(q.get("insecure"))),
        fingerprint: q.get("fp").cloned(),
        alpn: list(&dv(q.get("alpn"))),
        reality_key: if reality {
            Some(need(&dv(q.get("pbk")))?)
        } else {
            None
        },
        reality_short_id: if reality { q.get("sid").cloned() } else { None },
    };
    o.put_opt("tls", tls_block(tls));
    let transport = transport_block(
        q.get("type").map(String::as_str),
        q.get("path").map(String::as_str),
        q.get("host").map(String::as_str),
        q.get("serviceName").map(String::as_str),
    )?;
    o.put_opt("transport", transport);
    if vless {
        o.put("packet_encoding", "xudp");
    }
    Ok(node(name, o))
}

fn hysteria2(link: &str) -> Res<ProxyNode> {
    let uri = parse_uri(link)?;
    let q = query(&uri)?;
    let name = name_of(&uri, uri.host());
    let mut o = Outbound::new("hysteria2");
    o.put("server", need(&Dv::Str(uri.host().into()))?);
    // A port written as 0 is a broken link, not "unset" (B12).
    let p = if uri.has_port() {
        port(&Dv::Int(uri.port()))?
    } else {
        443
    };
    o.put("server_port", p);
    o.put("password", decode(uri.user_info())?);
    if let Some(obfs) = q.get("obfs").filter(|s| !s.is_empty()) {
        let mut m = Map::new();
        m.insert("type".into(), obfs.clone().into());
        m.insert(
            "password".into(),
            q.get("obfs-password").cloned().unwrap_or_default().into(),
        );
        o.put("obfs", Value::Object(m));
    }
    let tls = Tls {
        enabled: true,
        sni: q.get("sni").cloned(),
        insecure: truthy(&dv(q.get("insecure"))),
        alpn: list(&dv(q.get("alpn"))),
        ..Tls::default()
    };
    o.put_opt("tls", tls_block(tls));
    Ok(node(name, o))
}

fn tuic(link: &str) -> Res<ProxyNode> {
    let uri = parse_uri(link)?;
    let q = query(&uri)?;
    let user = decode(uri.user_info())?;
    let colon = match user.find(':') {
        Some(c) if c > 0 => c,
        _ => return Err(Fail::Format),
    };
    let name = name_of(&uri, uri.host());
    let mut o = Outbound::new("tuic");
    o.put("server", need(&Dv::Str(uri.host().into()))?);
    o.put("server_port", port(&Dv::Int(uri.port()))?);
    o.put("uuid", &user[..colon]);
    o.put("password", &user[colon + 1..]);
    o.put_opt("congestion_control", q.get("congestion_control").cloned());
    o.put_opt("udp_relay_mode", q.get("udp_relay_mode").cloned());
    let tls = Tls {
        enabled: true,
        sni: q.get("sni").cloned(),
        insecure: truthy(&dv(q.get("allow_insecure"))) || truthy(&dv(q.get("insecure"))),
        alpn: list(&dv(q.get("alpn"))).or_else(|| Some(vec!["h3".into()])),
        ..Tls::default()
    };
    o.put_opt("tls", tls_block(tls));
    Ok(node(name, o))
}

fn socks(link: &str) -> Res<ProxyNode> {
    // `replaceFirst(RegExp('^socks5?://'), 'socks://')`: case-sensitive.
    let link = match link.strip_prefix("socks5://") {
        Some(rest) => format!("socks://{rest}"),
        None => link.to_owned(),
    };
    let uri = parse_uri(&link)?;
    let mut user = decode(uri.user_info())?;
    if !user.is_empty() && !user.contains(':') {
        user = try_base64(uri.user_info()).unwrap_or(user);
    }
    let colon = user.find(':').filter(|c| *c > 0);
    let name = name_of(&uri, uri.host());
    let mut o = Outbound::new("socks");
    o.put("server", need(&Dv::Str(uri.host().into()))?);
    o.put("server_port", port(&Dv::Int(uri.port()))?);
    o.put("version", "5");
    if let Some(c) = colon {
        o.put("username", &user[..c]);
        o.put("password", &user[c + 1..]);
    }
    Ok(node(name, o))
}

fn anytls(link: &str) -> Res<ProxyNode> {
    let uri = parse_uri(link)?;
    let q = query(&uri)?;
    let name = name_of(&uri, uri.host());
    let mut o = Outbound::new("anytls");
    o.put("server", need(&Dv::Str(uri.host().into()))?);
    o.put("server_port", port(&Dv::Int(uri.port()))?);
    o.put("password", need(&Dv::Str(decode(uri.user_info())?))?);
    let tls = Tls {
        enabled: true,
        sni: q.get("sni").cloned(),
        insecure: truthy(&dv(q.get("insecure"))),
        fingerprint: q.get("fp").cloned(),
        ..Tls::default()
    };
    o.put_opt("tls", tls_block(tls));
    Ok(node(name, o))
}

// ------------------------------------------------------------------ JSON

/// Groups and built-ins in sing-box JSON: the provider's routing, not servers.
const SING_BOX_ROUTING: [&str; 5] = ["selector", "urltest", "direct", "block", "dns"];

fn parse_json(json: &Dv) -> ParseResult {
    let mut out = ParseResult::default();
    if let Dv::List(outbounds) = json.get("outbounds") {
        for o in outbounds {
            let Dv::Map(entries) = o else { continue };
            let kind = o.get("type").as_str();
            if kind.is_some_and(|t| SING_BOX_ROUTING.contains(&t)) {
                continue;
            }
            if !kind.is_some_and(is_supported_type) || o.get("server").is_null() {
                out.skipped += 1;
                continue;
            }
            // Provider-specific detours point at tags we don't keep.
            let outbound: Map<String, Value> = entries
                .iter()
                .filter(|(k, _)| !matches!(k.as_str(), Some("tag" | "detour")))
                .map(|(k, v)| (k.dart_string(), v.to_json()))
                .collect();
            let name = name_or_server(o.get("tag"), o.get("server"));
            out.nodes.push(ProxyNode { name, outbound });
        }
    } else if let Dv::List(servers) = json.get("servers") {
        // SIP008.
        for s in servers {
            if !matches!(s, Dv::Map(_)) {
                continue;
            }
            match sip008_server(s) {
                Ok(n) => out.nodes.push(n),
                Err(_) => out.skipped += 1,
            }
        }
    }
    out
}

fn sip008_server(s: &Dv) -> Res<ProxyNode> {
    let name = name_or_server(s.get("remarks"), s.get("server"));
    let mut o = Outbound::new("shadowsocks");
    o.put("server", need(s.get("server"))?);
    o.put("server_port", port(s.get("server_port"))?);
    o.put("method", need(s.get("method"))?);
    o.put("password", need(s.get("password"))?);
    let no_plugin = s.get("plugin").as_str_opt()?.is_none_or(str::is_empty);
    if !no_plugin {
        o.put_raw("plugin", s.get("plugin"));
        o.put_raw("plugin_opts", s.get("plugin_opts"));
    }
    Ok(node(name, o))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn line_splitting_like_dart() {
        let got: Vec<_> = lines("a\r\nb\rc\n\nd").collect();
        assert_eq!(got, ["a", "b", "c", "", "d"]);
    }

    #[test]
    fn proxies_line_detection() {
        assert!(has_proxies_line("proxies:"));
        assert!(has_proxies_line("port: 1\rproxies \u{3000}:"));
        assert!(!has_proxies_line(" proxies:"));
        assert!(!has_proxies_line("x-proxies:"));
    }

    fn one(body: &str) -> Option<ProxyNode> {
        let r = parse_subscription(body).expect("parsed");
        r.nodes.into_iter().next()
    }

    fn outbound(n: &ProxyNode, k: &str) -> Value {
        n.outbound.get(k).cloned().unwrap_or(Value::Null)
    }

    /// B10: credentials as written (mihomo reads them as strings); Dart's
    /// YAML 1.2 made `0123` 123, `1e3` 1000.0, `0x10` 16.
    #[test]
    fn credentials_keep_their_text() {
        let ss = |pw: &str| {
            one(&format!(
                "proxies:\n  - {{name: a, type: ss, server: s, port: 1, cipher: aes-128-gcm, password: {pw}}}\n"
            ))
        };
        for (pw, want) in [
            ("0123", "0123"),
            ("1e3", "1e3"),
            ("0x10", "0x10"),
            ("true", "true"),
            ("+5", "+5"),
            ("\"0123\"", "0123"),
            ("abc", "abc"),
        ] {
            assert_eq!(outbound(&ss(pw).expect(pw), "password"), want, "{pw}");
        }
        // Null is still missing.
        assert!(ss("~").is_none());
        let vless = one(
            "proxies:\n  - {name: v, type: vless, server: s, port: 1, uuid: 0123, tls: true, reality-opts: {public-key: 1e3, short-id: 0011}}\n",
        )
        .expect("vless");
        assert_eq!(outbound(&vless, "uuid"), "0123");
        let reality = &vless.outbound["tls"]["reality"];
        assert_eq!(reality["public_key"], "1e3");
        assert_eq!(reality["short_id"], "0011");
    }

    /// B11: names are UTF-8 with escapes; Dart left `%20` in a name with
    /// Chinese in it and dropped the node for `#%FF`.
    #[test]
    fn link_names_decode_leniently() {
        let ss = "ss://YWVzLTEyOC1nY206cA@1.2.3.4:443";
        let name = |frag: &str| {
            parse_share_link(&format!("{ss}#{frag}"))
                .expect("no crash")
                .expect("node")
                .name
        };
        assert_eq!(name("香港%20HK"), "香港 HK");
        assert_eq!(name("%E9%A6%99%E6%B8%AF%2001"), "香港 01");
        assert_eq!(name("%FF"), "%FF");
        assert_eq!(name("100%"), "100%");
        let vless = |frag: &str| {
            parse_share_link(&format!("vless://u@h.example:443?security=tls#{frag}"))
                .expect("no crash")
                .expect("node")
                .name
        };
        assert_eq!(vless("%FF"), "%FF");
        assert_eq!(vless("%E6%97%A5%E6%9C%AC"), "日本");
        // Blank: the host.
        assert_eq!(vless("%20"), "h.example");
    }

    /// B12: ports are decimal 1–65535; hy2's `:0` is broken, not "unset".
    #[test]
    fn ports_are_decimal() {
        let clash = |port: &str| {
            one(&format!(
                "proxies:\n  - {{name: a, type: trojan, server: s, port: {port}, password: p}}\n"
            ))
            .map(|n| outbound(&n, "server_port"))
        };
        assert_eq!(clash("443"), Some(443.into()));
        assert_eq!(clash("\"8388\""), Some(8388.into()));
        assert_eq!(clash("0x1BB"), None);
        assert_eq!(clash("+443"), None);
        assert_eq!(clash("\"+443\""), None);
        assert_eq!(clash("443.0"), None);
        assert_eq!(clash("0"), None);
        assert_eq!(clash("65536"), None);
        let link = |l: &str| parse_share_link(l).expect("no crash");
        assert!(link("trojan://p@h:+443").is_none());
        assert!(link("trojan://p@h:0x1BB").is_none());
        assert!(link("trojan://p@h:443").is_some());
        assert!(link("hy2://p@h:0").is_none());
        let hy2 = link("hy2://p@h").expect("default port");
        assert_eq!(outbound(&hy2, "server_port"), 443);
        // sing-box JSON keeps whole numbers.
        let r = parse_subscription(
            r#"{"servers":[{"server":"s","server_port":"+443","method":"m","password":"p"},{"server":"s","server_port":8388,"method":"m","password":"p"}]}"#,
        )
        .expect("sip008");
        assert_eq!(r.nodes.len(), 1);
        assert_eq!(r.skipped, 1);
    }

    /// B16: a node without a name is called by its server (Dart: "null").
    #[test]
    fn missing_names_take_the_server() {
        let n = one("proxies:\n  - {type: trojan, server: s.example, port: 1, password: p}\n")
            .expect("node");
        assert_eq!(n.name, "s.example");
        let n = one(
            "proxies:\n  - {name: \" \", type: trojan, server: s.example, port: 1, password: p}\n",
        )
        .expect("node");
        assert_eq!(n.name, "s.example");
        let r = parse_subscription(r#"{"outbounds":[{"type":"trojan","tag":"","server":"t.example","server_port":1,"password":"p"}]}"#)
            .expect("sing-box");
        assert_eq!(r.nodes[0].name, "t.example");
        let persisted = |v: Value| ProxyNode::from_json(&v).expect("node").name;
        assert_eq!(
            persisted(serde_json::json!({"outbound": {"type": "trojan", "server": "u.example"}})),
            "u.example"
        );
        assert_eq!(
            persisted(serde_json::json!({"name": null, "outbound": {"type": "trojan"}})),
            ""
        );
        use crate::model::subscription::SubGroup;
        assert_eq!(SubGroup::from_json(&serde_json::json!({"m": ["a"]})), None);
        assert_eq!(
            SubGroup::from_json(&serde_json::json!({"n": "G"})).map(|g| g.kind),
            Some("select".to_owned())
        );
    }

    /// B8 / D12: bandwidth with units, as mihomo reads it (Dart took the
    /// first digits: "1 Gbps" was 1 Mbps).
    #[test]
    fn bandwidth_units() {
        let hy2 = |down: &str| {
            one(&format!(
                "proxies:\n  - {{name: h, type: hysteria2, server: s, port: 1, password: p, down: {down}}}\n"
            ))
            .map(|n| outbound(&n, "down_mbps"))
            .expect("node")
        };
        for (down, want) in [
            ("100", Value::from(100)),
            ("\"100\"", 100.into()),
            ("100 Mbps", 100.into()),
            ("100mbps", 100.into()),
            ("1 Gbps", 1000.into()),
            ("1.5 Gbps", 1500.into()),
            ("500 Kbps", 1.into()),
            ("200 Kbps", 1.into()),
            ("10 MBps", 80.into()),
            ("1 Tbps", 1_000_000.into()),
            ("8000000 bps", 8.into()),
            ("0", Value::Null),
            ("fast", Value::Null),
            ("100 furlongs", Value::Null),
        ] {
            assert_eq!(hy2(down), want, "{down}");
        }
    }

    /// B9: Dart's `(p['alterId'] as num?)` threw past the per-proxy
    /// catch and the whole subscription failed; now that entry is skipped.
    #[test]
    fn a_mistyped_entry_is_skipped() {
        let body = "proxies:\n  - {name: a, type: vmess, server: s, port: 1, uuid: u, alterId: \"0\"}\n  - {name: b, type: trojan, server: t, port: 2, password: p, sni: 5}\n  - {name: c, type: trojan, server: t, port: 3, password: p}\nproxy-groups:\n  - {name: G, type: select, proxies: x}\n  - {name: H, type: select, proxies: [c]}\n";
        let r = parse_subscription(body).expect("parsed");
        let names: Vec<&str> = r.nodes.iter().map(|n| n.name.as_str()).collect();
        assert_eq!(names, ["c"]);
        assert_eq!(r.skipped, 2);
        // A group whose `proxies` is not a list is left out.
        let groups: Vec<&str> = r.split.groups.iter().map(|g| g.name.as_str()).collect();
        assert_eq!(groups, ["H"]);
    }
}
