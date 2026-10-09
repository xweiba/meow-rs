//! The route API's policies (Dart: `RoutePolicy` and `routeCatalog` in
//! `route_api.dart`): what other programs may ask for by proxy user name,
//! e.g. `socks5://hk:<key>@127.0.0.1:7890`.

use serde_json::{Map, Value};

use crate::dart::to_lower_case;
use crate::model::settings::SshChain;
use crate::plan::outbound_tags;
use crate::plan::policies::POLICIES;
use crate::pool::NodeGroup;

/// A policy other programs can ask for by name: their traffic, sent through
/// the proxy URL for [`RoutePolicy::id`], leaves the way
/// [`RoutePolicy::target`] says.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoutePolicy {
    /// Short ASCII word, the proxy URL's user name (`hk`, `auto`, `ai`).
    pub id: String,
    /// What people see ("🇭🇰 香港").
    pub name: String,
    /// The outbound or group tag it maps to; empty for `rule` (through the
    /// rules, like this machine's own traffic).
    pub target: String,
    /// `auto`, `rule`, `select`, `direct`, `region`, `kind`, `policy`,
    /// `ssh` or `device`.
    pub kind: &'static str,
}

impl RoutePolicy {
    fn new(id: &str, name: &str, target: &str, kind: &'static str) -> Self {
        Self {
            id: id.to_owned(),
            name: name.to_owned(),
            target: target.to_owned(),
            kind,
        }
    }

    /// `{"id", "name", "target", "kind"}`. Dart's own `toJson` (the route
    /// API's answer) leaves `target` out; the app needs it to rebuild the
    /// policy.
    pub fn to_json(&self) -> Value {
        let mut m = Map::new();
        m.insert("id".into(), self.id.clone().into());
        m.insert("name".into(), self.name.clone().into());
        m.insert("target".into(), self.target.clone().into());
        m.insert("kind".into(), self.kind.into());
        Value::Object(m)
    }
}

/// The policies on offer now (Dart: `routeCatalog`, as
/// `ProxyController.routePolicies` calls it: no device exits). Regions and
/// kinds come from the pool's `groups`, so the list follows the
/// subscriptions; the automatic ones only when there are lines.
pub fn route_catalog(
    groups: &[NodeGroup],
    has_lines: bool,
    ssh_chains: &[SshChain],
) -> Vec<RoutePolicy> {
    let mut out = Vec::new();
    if has_lines {
        out.push(RoutePolicy::new(
            "auto",
            "♻️ 自动选择",
            outbound_tags::AUTO,
            "auto",
        ));
        out.push(RoutePolicy::new(
            "fastest",
            "速度最快",
            outbound_tags::FASTEST,
            "auto",
        ));
    }
    out.push(RoutePolicy::new("rule", "按规则分流", "", "rule"));
    out.push(RoutePolicy::new(
        "proxy",
        "🚀 节点选择",
        outbound_tags::PROXY,
        "select",
    ));
    out.push(RoutePolicy::new(
        "direct",
        "直连",
        outbound_tags::DIRECT,
        "direct",
    ));
    for g in groups {
        // `tag.split(':').last.toLowerCase()`.
        let id = to_lower_case(g.tag.rsplit(':').next().unwrap_or_default());
        let kind = if g.tag.starts_with("region:") {
            "region"
        } else {
            "kind"
        };
        out.push(RoutePolicy::new(&id, &g.label, &g.tag, kind));
    }
    for p in POLICIES.iter().filter(|p| !p.blockable && p.id != "final") {
        out.push(RoutePolicy::new(p.id, &p.label(), &p.tag(), "policy"));
    }
    for c in ssh_chains {
        out.push(RoutePolicy::new(
            &format!("ssh-{}", c.id),
            &c.name,
            &c.tag(),
            "ssh",
        ));
    }
    out
}
