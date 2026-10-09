//! A Clash subscription's own split: its groups and rules, as the provider
//! wrote them (Dart: `SubGroup` / `SubRules` in `sub_rules.dart`).

use serde::{Deserialize, Deserializer, Serialize};
use serde_json::Value;

use crate::dart::Dv;

/// One `proxy-groups:` entry of a Clash subscription. JSON: `{n, t, m}`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SubGroup {
    /// The provider's name ("🎥 NETFLIX").
    #[serde(rename = "n")]
    pub name: String,
    /// select | url-test | fallback | load-balance | relay …
    #[serde(rename = "t")]
    pub kind: String,
    /// Node names, other group names, DIRECT / REJECT.
    #[serde(rename = "m")]
    pub members: Vec<String>,
}

impl SubGroup {
    /// Dart `SubGroup.fromJson`: every field read with `'$v'` (a missing
    /// name or type becomes `"null"`); None when not an object.
    pub fn from_json(v: &Value) -> Option<Self> {
        let o = v.as_object()?;
        let field = |k: &str| Dv::from_json(o.get(k).unwrap_or(&Value::Null)).dart_string();
        Some(Self {
            name: field("n"),
            kind: field("t"),
            members: dart_strings(o.get("m")),
        })
    }
}

/// The split a provider ships with its subscription (ACL4SSR-style configs
/// carry thousands of rules and groups such as "🎥 NETFLIX").
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct SubRules {
    pub groups: Vec<SubGroup>,
    /// Clash rule lines ("DOMAIN-SUFFIX,netflix.com,🎥 NETFLIX").
    pub rules: Vec<String>,
}

impl SubRules {
    pub fn is_empty(&self) -> bool {
        self.groups.is_empty() && self.rules.is_empty()
    }

    /// Dart `SubRules.fromJson`: empty when not an object.
    pub fn from_json(v: &Value) -> Self {
        let Some(o) = v.as_object() else {
            return Self::default();
        };
        Self {
            groups: o
                .get("groups")
                .and_then(Value::as_array)
                .map(|a| a.iter().filter_map(SubGroup::from_json).collect())
                .unwrap_or_default(),
            rules: dart_strings(o.get("rules")),
        }
    }
}

/// `[for (final x in (v as List?) ?? const []) '$x']`; a non-list reads as
/// empty (Dart's cast would throw).
fn dart_strings(v: Option<&Value>) -> Vec<String> {
    v.and_then(Value::as_array)
        .map(|a| a.iter().map(|x| Dv::from_json(x).dart_string()).collect())
        .unwrap_or_default()
}

impl<'de> Deserialize<'de> for SubRules {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        Ok(Self::from_json(&Value::deserialize(d)?))
    }
}

/// A subscription as the app persists it (Dart `Subscription.toJson`,
/// without `updated`): its parsed lines, traffic and split.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Subscription {
    /// Stable id.
    pub id: String,
    /// As pasted.
    pub url: String,
    /// What the user calls it.
    pub name: String,
    /// The lines, in the subscription's order (unsupported types left out
    /// on load, as Dart does).
    pub nodes: Vec<crate::model::node::ProxyNode>,
    /// Entries the parser could not use.
    pub skipped: i64,
    /// Traffic left on the account; None = unknown.
    pub usage: Option<crate::model::usage::Usage>,
    /// Last refresh problem; None when fine.
    pub error: Option<String>,
    /// The provider's own groups and rules.
    pub split: SubRules,
    /// Use them (default true; persisted only when false).
    pub use_split: bool,
}

impl Subscription {
    /// Dart `Subscription.fromJson`: None unless an object with a string
    /// `id` and `url`; other fields lenient.
    pub fn from_json(v: &Value) -> Option<Self> {
        let o = v.as_object()?;
        let id = o.get("id")?.as_str()?.to_owned();
        let url = o.get("url")?.as_str()?.to_owned();
        Some(Self {
            id,
            url,
            name: o
                .get("name")
                .map(|n| Dv::from_json(n).dart_string_or_empty())
                .unwrap_or_default(),
            nodes: o
                .get("nodes")
                .and_then(Value::as_array)
                .map(|a| {
                    a.iter()
                        .filter_map(crate::model::node::ProxyNode::from_json)
                        .collect()
                })
                .unwrap_or_default(),
            skipped: o
                .get("skipped")
                .and_then(|n| Dv::from_json(n).as_int_opt().ok().flatten())
                .unwrap_or(0),
            usage: o
                .get("usage")
                .and_then(crate::model::usage::Usage::from_json),
            error: o.get("error").and_then(Value::as_str).map(str::to_owned),
            split: SubRules::from_json(o.get("split").unwrap_or(&Value::Null)),
            use_split: o.get("use_split") != Some(&Value::Bool(false)),
        })
    }
}
