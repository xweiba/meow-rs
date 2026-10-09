//! Field readers shared by every format, and the sing-box `tls` /
//! `transport` blocks (Dart: the helpers at the top of `parser.dart`).

use serde_json::{Map, Value};

use crate::dart::{double_to_int, int_try_parse, trim, Crash, Dv};
use crate::ingest::uri::{decode_component, DecodeError};

/// Why a node could not be read.
pub(crate) enum Fail {
    /// Dart's `FormatException`: the parser catches it and skips the entry.
    Format,
    /// Anything else Dart throws: nothing catches it, the whole parse fails.
    Crash(Crash),
}

impl From<Crash> for Fail {
    fn from(c: Crash) -> Self {
        Fail::Crash(c)
    }
}

pub(crate) type Res<T> = Result<T, Fail>;

/// `_port`: a number (truncated) or a string holding an int, in 1..=65535.
pub(crate) fn port(v: &Dv) -> Res<i64> {
    let p = match v {
        Dv::Int(i) => Some(*i),
        Dv::Double(d) => Some(double_to_int(*d)?),
        other => int_try_parse(trim(&other.dart_string_or_empty())),
    };
    p.filter(|p| (1..=65535).contains(p)).ok_or(Fail::Format)
}

/// `_need`: the value as a trimmed string; missing, empty or `"null"` fails.
pub(crate) fn need(v: &Dv) -> Res<String> {
    let s = v.dart_string_or_empty();
    let s = trim(&s);
    if s.is_empty() || s == "null" {
        return Err(Fail::Format);
    }
    Ok(s.to_owned())
}

/// `_truthy`: `true`, `1` (or `1.0`), or the strings `1` / `true` / `yes`.
pub(crate) fn truthy(v: &Dv) -> bool {
    matches!(v, Dv::Bool(true))
        || v.equals_one()
        || matches!(v.dart_string().as_str(), "1" | "true" | "yes")
}

/// `_list`: a list's items as strings, or a comma-separated string split and
/// trimmed; empty items dropped, None when nothing is left.
pub(crate) fn list(v: &Dv) -> Option<Vec<String>> {
    let items: Vec<String> = match v {
        Dv::Null => return None,
        Dv::List(items) => items.iter().map(Dv::dart_string).collect(),
        other => other
            .dart_string()
            .split(',')
            .map(|e| trim(e).to_owned())
            .collect(),
    };
    let out: Vec<String> = items.into_iter().filter(|e| !e.is_empty()).collect();
    (!out.is_empty()).then_some(out)
}

/// `_decode`: `Uri.decodeComponent`, the raw string when that throws an
/// `ArgumentError`; invalid UTF-8 is a `FormatException`.
pub(crate) fn decode(s: &str) -> Res<String> {
    match decode_component(s) {
        Ok(d) => Ok(d),
        Err(DecodeError::Argument) => Ok(s.to_owned()),
        Err(DecodeError::Format) => Err(Fail::Format),
    }
}

/// A query parameter (or any optional string) as a value.
pub(crate) fn dv(v: Option<&String>) -> Dv {
    v.map_or(Dv::Null, |s| Dv::Str(s.clone()))
}

/// The arguments of Dart's `tlsBlock`.
#[derive(Default)]
pub(crate) struct Tls {
    pub enabled: bool,
    pub sni: Option<String>,
    pub insecure: bool,
    pub fingerprint: Option<String>,
    pub alpn: Option<Vec<String>>,
    pub reality_key: Option<String>,
    pub reality_short_id: Option<String>,
}

/// sing-box `tls` block; None when TLS is off.
pub(crate) fn tls_block(t: Tls) -> Option<Value> {
    if !t.enabled && t.reality_key.is_none() {
        return None;
    }
    let fp = trim(t.fingerprint.as_deref().unwrap_or_default()).to_owned();
    let mut m = Map::new();
    m.insert("enabled".into(), true.into());
    if let Some(sni) = t.sni.filter(|s| !s.is_empty()) {
        m.insert("server_name".into(), sni.into());
    }
    if t.insecure {
        m.insert("insecure".into(), true.into());
    }
    if let Some(alpn) = t.alpn {
        m.insert("alpn".into(), alpn.into());
    }
    // Reality needs uTLS; default to Chrome like other clients.
    if !fp.is_empty() || t.reality_key.is_some() {
        let mut u = Map::new();
        u.insert("enabled".into(), true.into());
        u.insert(
            "fingerprint".into(),
            if fp.is_empty() { "chrome".into() } else { fp }.into(),
        );
        m.insert("utls".into(), Value::Object(u));
    }
    if let Some(key) = t.reality_key {
        let mut r = Map::new();
        r.insert("enabled".into(), true.into());
        r.insert("public_key".into(), key.into());
        if let Some(id) = t.reality_short_id {
            r.insert("short_id".into(), id.into());
        }
        m.insert("reality".into(), Value::Object(r));
    }
    Some(Value::Object(m))
}

/// sing-box `transport` block; None for plain TCP, an error for a network
/// it does not know.
pub(crate) fn transport_block(
    network: Option<&str>,
    path: Option<&str>,
    host: Option<&str>,
    service_name: Option<&str>,
) -> Res<Option<Value>> {
    let h = trim(host.unwrap_or_default());
    let p = trim(path.unwrap_or_default());
    let mut m = Map::new();
    match network.unwrap_or("tcp").to_lowercase().as_str() {
        "ws" | "websocket" => {
            m.insert("type".into(), "ws".into());
            if !p.is_empty() {
                m.insert("path".into(), p.into());
            }
            if !h.is_empty() {
                let mut headers = Map::new();
                headers.insert("Host".into(), h.into());
                m.insert("headers".into(), Value::Object(headers));
            }
        }
        "grpc" => {
            m.insert("type".into(), "grpc".into());
            if let Some(s) = service_name.filter(|s| !s.is_empty()) {
                m.insert("service_name".into(), s.into());
            }
        }
        "h2" | "http" => {
            m.insert("type".into(), "http".into());
            if !h.is_empty() {
                m.insert("host".into(), vec![h].into());
            }
            if !p.is_empty() {
                m.insert("path".into(), p.into());
            }
        }
        "httpupgrade" => {
            m.insert("type".into(), "httpupgrade".into());
            if !p.is_empty() {
                m.insert("path".into(), p.into());
            }
            if !h.is_empty() {
                m.insert("host".into(), h.into());
            }
        }
        "tcp" | "" | "none" => return Ok(None),
        _ => return Err(Fail::Format),
    }
    Ok(Some(Value::Object(m)))
}

/// An outbound map under construction; like Dart's `_clean`, null values
/// are left out.
#[derive(Default)]
pub(crate) struct Outbound(pub Map<String, Value>);

impl Outbound {
    pub(crate) fn new(kind: &str) -> Self {
        let mut o = Self::default();
        o.put("type", kind);
        o
    }

    pub(crate) fn put(&mut self, key: &str, v: impl Into<Value>) {
        let v = v.into();
        if !v.is_null() {
            self.0.insert(key.into(), v);
        }
    }

    pub(crate) fn put_opt(&mut self, key: &str, v: Option<impl Into<Value>>) {
        if let Some(v) = v {
            self.put(key, v);
        }
    }

    /// A value taken as is from the subscription.
    pub(crate) fn put_raw(&mut self, key: &str, v: &Dv) {
        self.put(key, v.to_json());
    }
}
