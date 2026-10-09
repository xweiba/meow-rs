//! L2: every subscription's lines as one pool, their outbound tags and the
//! groups the user sees (Dart: `pool.dart`, `regions.dart`, `groups.dart`,
//! `nodeTagsFor` in `config.dart` and `ProxyController._pool`).

mod groups;
mod proxy;
mod regions;

use indexmap::IndexMap;
use serde::{Deserialize, Deserializer};
use serde_json::{Map, Value};

use crate::dart::{internet_address_try_parse, to_lower_case, trim, Dv, IpKind};
use crate::model::node::ProxyNode;
use crate::model::usage::Usage;

pub use groups::{classify, group_names, LineKind, NodeGroup, LINE_KINDS};
pub use proxy::clash_proxy_for;
pub use regions::{
    is_flagged_node, is_usable_node, region_for_code, region_of, region_of_node, Region, REGIONS,
};

/// One subscription as the pool sees it: its lines and its account's
/// traffic.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct PoolSource {
    /// The subscription's lines, in its order.
    pub nodes: Vec<ProxyNode>,
    /// Traffic left on the account; None = unknown.
    pub usage: Option<Usage>,
}

impl PoolSource {
    /// From a persisted subscription (`Subscription.toJson`): None when it is
    /// not an object or lacks a string `id` / `url` (Dart drops those on
    /// load). Nodes of unsupported types are left out.
    pub fn from_json(v: &Value) -> Option<Self> {
        let o = v.as_object()?;
        if !o.get("id").is_some_and(Value::is_string) || !o.get("url").is_some_and(Value::is_string)
        {
            return None;
        }
        Some(Self {
            nodes: o
                .get("nodes")
                .and_then(Value::as_array)
                .map(|a| a.iter().filter_map(ProxyNode::from_json).collect())
                .unwrap_or_default(),
            usage: o.get("usage").and_then(Usage::from_json),
        })
    }
}

/// What the pool is built from: the parts of the build input
/// (`ProxyController.configInput()`) it reads.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct PoolInput {
    /// The subscriptions in the user's priority order.
    pub subscriptions: Vec<PoolSource>,
    /// Measured exit country (ISO code) by server address and port:
    /// `"1.2.3.4:443"` or `"[2001:db8::1]:443"`.
    pub exits: IndexMap<String, String>,
    /// Server domains (lowercase) resolved to an IP address.
    pub resolved: IndexMap<String, String>,
    /// The network can reach IPv6; without it IPv6-only lines are left out.
    pub ipv6: bool,
    /// Current time, Unix milliseconds (expired accounts count as used up).
    pub now: i64,
}

impl PoolInput {
    /// Reads the build input JSON; missing or mistyped fields read as empty
    /// / false / 0.
    pub fn from_json(v: &Value) -> Self {
        let strings = |k: &str| -> IndexMap<String, String> {
            v.get(k)
                .and_then(Value::as_object)
                .map(|o| {
                    o.iter()
                        .filter_map(|(k, v)| Some((k.clone(), v.as_str()?.to_owned())))
                        .collect()
                })
                .unwrap_or_default()
        };
        Self {
            subscriptions: v
                .get("subscriptions")
                .and_then(Value::as_array)
                .map(|a| a.iter().filter_map(PoolSource::from_json).collect())
                .unwrap_or_default(),
            exits: strings("exits"),
            resolved: strings("resolved"),
            ipv6: v.get("ipv6").and_then(Value::as_bool).unwrap_or(false),
            now: v
                .get("now")
                .and_then(|n| Dv::from_json(n).as_int_opt().ok().flatten())
                .unwrap_or(0),
        }
    }
}

impl<'de> Deserialize<'de> for PoolInput {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        Ok(Self::from_json(&Value::deserialize(d)?))
    }
}

/// A pooled line with its measured exit.
#[derive(Debug, Clone, PartialEq)]
pub struct PoolNode {
    pub node: ProxyNode,
    /// Measured exit country (ISO code); None when not measured.
    pub exit: Option<String>,
}

impl PoolNode {
    /// `{"name", "outbound", "exit"?}`.
    pub fn to_json(&self) -> Value {
        let mut v = self.node.to_json();
        if let (Some(e), Some(o)) = (&self.exit, v.as_object_mut()) {
            o.insert("exit".into(), Value::String(e.clone()));
        }
        v
    }
}

/// The line pool and what screens derive from it.
///
/// One tag scheme (B1): a line's tag is assigned here once, and the same
/// name is its `proxies:` entry in the config, its member name in every
/// group and what the subscriptions' rules point at.
#[derive(Debug, Clone, PartialEq)]
pub struct Pool {
    /// One line per server, in priority order, with measured exits; only
    /// lines the core can run ([`can_output`]).
    pub nodes: Vec<PoolNode>,
    /// Each node's outbound tag (same order as `nodes`), see [`node_tags_for`].
    pub tags: Vec<String>,
    /// Region and kind groups, see [`classify`].
    pub groups: Vec<NodeGroup>,
    /// Each tag's region (name first, else measured exit); None = unknown.
    pub region_by_tag: IndexMap<String, Option<Region>>,
    /// Usable lines left out because the core can't run them (plain HTTP,
    /// an unsupported transport …), before de-duplication.
    pub unsupported: usize,
}

impl Pool {
    /// `{"tags", "nodes", "groups"}`, the shape of the build output's `pool`.
    pub fn to_json(&self) -> Value {
        let mut m = Map::new();
        m.insert("tags".into(), self.tags.clone().into());
        m.insert(
            "nodes".into(),
            Value::Array(self.nodes.iter().map(PoolNode::to_json).collect()),
        );
        m.insert(
            "groups".into(),
            serde_json::to_value(&self.groups).unwrap_or(Value::Null),
        );
        Value::Object(m)
    }
}

/// Builds the pool (Dart: `ProxyController._pool`): [`pool_nodes`], minus
/// IPv6-only lines when the network has no IPv6, with measured exits
/// attached by [`exit_key`]; then tags, groups and regions.
///
/// Dart parity: the controller asks `poolNodes` with the wall clock; here
/// the input's `now` is used.
pub fn build_pool(input: &PoolInput) -> Pool {
    let (lines, unsupported) = pool_nodes_counted(&input.subscriptions, input.now);
    let nodes: Vec<PoolNode> = lines
        .into_iter()
        .filter(|n| input.ipv6 || !needs_ipv6(n))
        .map(|n| {
            let exit = exit_key(n, &input.resolved).and_then(|k| input.exits.get(&k).cloned());
            PoolNode {
                node: n.clone(),
                exit,
            }
        })
        .collect();
    let plain: Vec<&ProxyNode> = nodes.iter().map(|n| &n.node).collect();
    let tags = node_tags_for(&plain);
    let with_exit: Vec<(&ProxyNode, Option<&str>)> =
        nodes.iter().map(|n| (&n.node, n.exit.as_deref())).collect();
    let groups = classify(&with_exit, &tags);
    let region_by_tag = tags
        .iter()
        .zip(&with_exit)
        .map(|(t, (n, exit))| (t.clone(), region_of_node(n, *exit)))
        .collect();
    Pool {
        nodes,
        tags,
        groups,
        region_by_tag,
        unsupported,
    }
}

/// `'${outbound['server'] ?? ''}'`.
fn server(n: &ProxyNode) -> String {
    Dv::from_json(n.outbound.get("server").unwrap_or(&Value::Null)).dart_string_or_empty()
}

/// `(outbound['server_port'] as num?)?.toInt() ?? 0`. A non-numeric port
/// makes Dart throw; it reads as 0 here.
fn port(n: &ProxyNode) -> i64 {
    n.outbound
        .get("server_port")
        .and_then(|p| Dv::from_json(p).as_int_opt().ok().flatten())
        .unwrap_or(0)
}

/// The server itself, `type|server (lowercase)|port`: two accounts of one
/// provider share it (different credentials, same machine).
pub fn endpoint(n: &ProxyNode) -> String {
    format!("{}|{}|{}", n.kind(), to_lower_case(&server(n)), port(n))
}

/// Bytes the account can still use: None when unknown, 0 when used up or
/// expired at `now` (Unix ms).
pub fn remaining_of(u: Option<&Usage>, now: i64) -> Option<i64> {
    let u = u?;
    if u.expire.is_some_and(|e| e < now) {
        return Some(0);
    }
    if u.total <= 0 {
        return None;
    }
    Some(u.total.wrapping_sub(u.used()).max(0))
}

/// Whether the core can run `n` (B4): only these get a tag and enter the
/// groups; the rest stay in their subscription, shown as not supported.
pub fn can_output(n: &ProxyNode) -> bool {
    clash_proxy_for(n, "").is_some()
}

/// All subscriptions' lines as one pool: one line per server
/// ([`endpoint`]). Sources come in the user's priority order; where several
/// reach the same server the earlier one serves it. Used-up or expired
/// accounts (at `now`, Unix ms) only count when no account is left with
/// traffic or unknown traffic. Info rows ("剩余流量…") and lines the core
/// can't run ([`can_output`]) are left out; the latter before
/// de-duplication, so a runnable line of the same server still serves it.
pub fn pool_nodes(sources: &[PoolSource], now: i64) -> Vec<&ProxyNode> {
    pool_nodes_counted(sources, now).0
}

/// [`pool_nodes`] and how many usable lines it left out as unsupported.
fn pool_nodes_counted(sources: &[PoolSource], now: i64) -> (Vec<&ProxyNode>, usize) {
    // Dart sorts alive (≥ 0 left or unknown) before used-up, each by index,
    // then keeps the alive ones unless there are none: the index order
    // either way.
    let dead = |s: &PoolSource| remaining_of(s.usage.as_ref(), now) == Some(0);
    let any_alive = sources.iter().any(|s| !dead(s));
    let mut seen = std::collections::HashSet::new();
    let mut unsupported = 0;
    let lines = sources
        .iter()
        .filter(|s| !any_alive || !dead(s))
        .flat_map(|s| &s.nodes)
        .filter(|n| is_usable_node(n))
        .filter(|n| {
            let ok = can_output(n);
            unsupported += usize::from(!ok);
            ok
        })
        .filter(|n| seen.insert(endpoint(n)))
        .collect();
    (lines, unsupported)
}

/// The line only works over IPv6: its server is an IPv6 address (brackets
/// allowed), or the provider names it an IPv6 line.
pub fn needs_ipv6(n: &ProxyNode) -> bool {
    let host: String = server(n)
        .chars()
        .filter(|c| !matches!(c, '[' | ']'))
        .collect();
    match internet_address_try_parse(&host) {
        Some(kind) => kind == IpKind::V6,
        None => groups::is_ipv6_named(&n.name),
    }
}

/// The node's key in the measured exits (Dart: `_exitKey`): its server's IP
/// and port, `ip:port` or `[v6]:port`; a domain goes through `resolved`
/// (lowercase domain → IP). None while a domain is unresolved.
pub fn exit_key(n: &ProxyNode, resolved: &IndexMap<String, String>) -> Option<String> {
    let host = to_lower_case(&server(n));
    let ip = if internet_address_try_parse(&host).is_some() {
        host
    } else {
        resolved.get(&host)?.clone()
    };
    let port = port(n);
    Some(if ip.contains(':') {
        format!("[{ip}]:{port}")
    } else {
        format!("{ip}:{port}")
    })
}

/// Names a line never takes: our own groups and outbounds (as the
/// settings and the route API write them, and as the config does), the
/// core's built-in outbounds, and the rewrite modules' proxies.
const RESERVED_TAGS: [&str; 15] = [
    "proxy",
    "auto",
    "auto~smart",
    "auto~balance",
    "auto~fastest",
    "speedtest",
    "direct",
    "block",
    "DIRECT",
    "REJECT",
    "REJECT-DROP",
    "PASS",
    "COMPATIBLE",
    "paopao-mitm",
    "paopao-mitm-return",
];

/// Prefixes of our own tags (`region:…`, a user group's `group:…`, …).
const OUR_PREFIXES: [&str; 8] = [
    "device:", "region:", "kind:", "ssh:", "group:", "policy:", "sub:", "iface:",
];

/// A name starting like one of our own tags.
pub fn clashes_with_our_tags(name: &str) -> bool {
    OUR_PREFIXES.iter().any(|p| name.starts_with(p))
}

/// The tag each line gets, which is also its proxy name in the config
/// (Dart had two schemes, `nodeTagsFor` and `unique()`; B1): its trimmed
/// name (`node` when blank), a leading space when it starts like one of
/// our own tags, then ` 2`, ` 3`, … until unique among the earlier tags
/// and [`RESERVED_TAGS`]. `nodes` are the pool's lines (all runnable).
pub fn node_tags_for(nodes: &[&ProxyNode]) -> Vec<String> {
    let mut used: std::collections::HashSet<String> =
        RESERVED_TAGS.iter().map(|s| (*s).to_owned()).collect();
    nodes
        .iter()
        .map(|n| {
            let name = trim(&n.name);
            let mut tag = if name.is_empty() {
                "node".to_owned()
            } else {
                name.to_owned()
            };
            if clashes_with_our_tags(&tag) {
                tag.insert(0, ' ');
            }
            let mut candidate = tag.clone();
            let mut i = 2;
            while used.contains(&candidate) {
                candidate = format!("{tag} {i}");
                i += 1;
            }
            used.insert(candidate.clone());
            candidate
        })
        .collect()
}

#[cfg(test)]
mod tests;
