//! A proxy server ("线路") as PaoPao keeps it, and what a subscription parses
//! to (Dart: `node.dart`).

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::{Map, Value};

use crate::dart::Dv;
use crate::model::subscription::SubRules;

/// Outbound types PaoPao accepts from subscriptions (sing-box names).
pub const SUPPORTED_NODE_TYPES: [&str; 9] = [
    "shadowsocks",
    "vmess",
    "vless",
    "trojan",
    "hysteria2",
    "tuic",
    "socks",
    "http",
    "anytls",
];

/// Whether `type` is one of [`SUPPORTED_NODE_TYPES`].
pub fn is_supported_type(t: &str) -> bool {
    SUPPORTED_NODE_TYPES.contains(&t)
}

/// One proxy server, kept as the sing-box outbound it becomes.
///
/// Every subscription format is translated into this one shape, so the
/// config generator never needs to know where a node came from. Its JSON
/// (`{"name", "outbound"}`) is what the app persists; the outbound's key
/// order is part of that contract and matches the Dart parser's.
#[derive(Debug, Clone, PartialEq)]
pub struct ProxyNode {
    /// What the user sees; also the outbound tag (made unique on generation).
    pub name: String,
    /// The sing-box outbound without `tag`, in the parser's key order.
    pub outbound: Map<String, Value>,
}

impl ProxyNode {
    /// The outbound `type` (empty when missing).
    pub fn kind(&self) -> &str {
        self.outbound
            .get("type")
            .and_then(Value::as_str)
            .unwrap_or_default()
    }

    /// `{"name": .., "outbound": {..}}`.
    pub fn to_json(&self) -> Value {
        let mut m = Map::new();
        m.insert("name".into(), Value::String(self.name.clone()));
        m.insert("outbound".into(), Value::Object(self.outbound.clone()));
        Value::Object(m)
    }

    /// Reads [`ProxyNode::to_json`]; None when `outbound` is missing or of an
    /// unsupported type. A missing name falls back to the server (as Dart's
    /// `'${name ?? outbound['server']}'`, so possibly `"null"`).
    pub fn from_json(v: &Value) -> Option<Self> {
        let outbound = v.get("outbound")?.as_object()?;
        if !outbound
            .get("type")
            .and_then(Value::as_str)
            .is_some_and(is_supported_type)
        {
            return None;
        }
        let name = match v.get("name") {
            Some(n) if !n.is_null() => Dv::from_json(n).dart_string(),
            _ => Dv::from_json(outbound.get("server").unwrap_or(&Value::Null)).dart_string(),
        };
        Some(Self {
            name,
            outbound: outbound.clone(),
        })
    }
}

impl Serialize for ProxyNode {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        self.to_json().serialize(s)
    }
}

impl<'de> Deserialize<'de> for ProxyNode {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let v = Value::deserialize(d)?;
        Self::from_json(&v).ok_or_else(|| serde::de::Error::custom("not a supported node"))
    }
}

/// What came out of a subscription body.
#[derive(Debug, Clone, Default, PartialEq, Serialize)]
pub struct ParseResult {
    /// The servers, in the subscription's order.
    pub nodes: Vec<ProxyNode>,
    /// Entries recognised as nodes but not usable (unsupported protocol or
    /// missing fields); shown as one line, never as an error.
    pub skipped: usize,
    /// The provider's own groups and rules (Clash subscriptions); empty for
    /// other formats.
    pub split: SubRules,
}
