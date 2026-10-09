//! Sorting the pool's lines into the groups the user sees (Dart:
//! `groups.dart`): one per region, then one per kind of line.

use indexmap::IndexMap;
use serde::Serialize;

use crate::dart::{contains_ignore_ascii_case, find_ignore_ascii_case, is_regex_space};
use crate::model::node::ProxyNode;
use crate::pool::regions::{is_usable_node, rank, region_of_node, Region};

/// The built-in groups' names, one source for every screen.
pub mod group_names {
    /// The main selector.
    pub const SELECT: &str = "🚀 节点选择";
    /// Automatic choice over the region groups.
    pub const AUTO: &str = "♻️ 自动选择";
    /// Lowest latency.
    pub const FASTEST: &str = "⚡ 自动测速";
}

/// A kind of line, read from the provider's names ("IEPL", "0.5x", …).
#[derive(Debug, Clone, Copy)]
pub struct LineKind {
    /// Stable id; the group tag is `kind:<id>`.
    pub id: &'static str,
    /// Chinese name ("中转").
    pub name: &'static str,
    /// Emoji shown before the name.
    pub icon: &'static str,
    matcher: fn(&str) -> bool,
}

/// Kinds are the same when their ids are.
impl PartialEq for LineKind {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id
    }
}

impl Eq for LineKind {}

impl LineKind {
    /// The group tag, `kind:<id>`.
    pub fn tag(&self) -> String {
        format!("kind:{}", self.id)
    }

    /// What the user sees, `<icon> <name>`.
    pub fn label(&self) -> String {
        format!("{} {}", self.icon, self.name)
    }

    /// Whether a node named `name` is of this kind.
    pub fn matches(&self, name: &str) -> bool {
        (self.matcher)(name)
    }
}

/// The kinds, in group order. Dart patterns (all case-insensitive):
///
/// - relay: `中转|中轉|转发|relay|transit`
/// - dedicated: `IEPL|IPLC|专线|專線`
/// - ipv6: `IPv6|(?<![A-Za-z])v6(?![A-Za-z0-9])`
/// - lowrate: `低倍|0\.\d+\s*[x×倍]|[x×]\s*0\.\d+`
pub const LINE_KINDS: [LineKind; 4] = [
    LineKind {
        id: "relay",
        name: "中转",
        icon: "🔀",
        matcher: is_relay,
    },
    LineKind {
        id: "dedicated",
        name: "专线",
        icon: "⚡",
        matcher: is_dedicated,
    },
    LineKind {
        id: "ipv6",
        name: "IPv6",
        icon: "6️⃣",
        matcher: is_ipv6_named,
    },
    LineKind {
        id: "lowrate",
        name: "低倍率",
        icon: "💰",
        matcher: is_low_rate,
    },
];

fn any_word(name: &str, words: &[&str]) -> bool {
    words.iter().any(|w| contains_ignore_ascii_case(name, w))
}

fn is_relay(name: &str) -> bool {
    any_word(name, &["中转", "中轉", "转发", "relay", "transit"])
}

fn is_dedicated(name: &str) -> bool {
    any_word(name, &["IEPL", "IPLC", "专线", "專線"])
}

/// `IPv6|(?<![A-Za-z])v6(?![A-Za-z0-9])`, case-insensitive.
pub(crate) fn is_ipv6_named(name: &str) -> bool {
    if contains_ignore_ascii_case(name, "IPv6") {
        return true;
    }
    let b = name.as_bytes();
    let mut from = 0;
    while let Some(i) = find_ignore_ascii_case(name, "v6", from) {
        let before_ok = i == 0 || !b[i - 1].is_ascii_alphabetic();
        let after_ok = b.get(i + 2).is_none_or(|c| !c.is_ascii_alphanumeric());
        if before_ok && after_ok {
            return true;
        }
        from = i + 1;
    }
    false
}

/// `低倍|0\.\d+\s*[x×倍]|[x×]\s*0\.\d+`, case-insensitive (`\d` is ASCII,
/// `\s` JavaScript's whitespace).
fn is_low_rate(name: &str) -> bool {
    if name.contains("低倍") {
        return true;
    }
    // Digits, spaces and the sign are disjoint, so greedy runs decide.
    let rate_then_sign = name.match_indices("0.").any(|(i, _)| {
        let rest = &name[i + 2..];
        let digits = rest.len() - rest.trim_start_matches(|c: char| c.is_ascii_digit()).len();
        digits > 0
            && rest[digits..]
                .trim_start_matches(is_regex_space)
                .starts_with(['x', 'X', '×', '倍'])
    });
    rate_then_sign
        || name.match_indices(['x', 'X', '×']).any(|(i, s)| {
            name[i + s.len()..]
                .trim_start_matches(is_regex_space)
                .strip_prefix("0.")
                .is_some_and(|r| r.starts_with(|c: char| c.is_ascii_digit()))
        })
}

/// One group the user sees in the line list.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct NodeGroup {
    /// `region:<code>` or `kind:<id>`.
    pub tag: String,
    /// `<flag> <name>` / `<icon> <name>`.
    pub label: String,
    /// Outbound tags of the usable lines in it, in pool order.
    pub members: Vec<String>,
}

/// Sorts usable lines into groups: by region (name, else measured exit),
/// then by kind. `nodes` pairs each node with its measured exit country;
/// `tags` are their outbound tags (same order). Regions come in
/// [`crate::pool::REGIONS`] order, then other places by code; a kind needs
/// two lines to be worth a group.
pub fn classify(nodes: &[(&ProxyNode, Option<&str>)], tags: &[String]) -> Vec<NodeGroup> {
    let mut by_region: IndexMap<String, (Region, Vec<String>)> = IndexMap::new();
    for ((n, exit), tag) in nodes.iter().zip(tags) {
        if !is_usable_node(n) {
            continue;
        }
        if let Some(r) = region_of_node(n, *exit) {
            by_region
                .entry(r.code.to_string())
                .or_insert_with(|| (r, Vec::new()))
                .1
                .push(tag.clone());
        }
    }
    let mut regions: Vec<(Region, Vec<String>)> = by_region.into_values().collect();
    // Codes are unique, so the order is total (Dart's sort is not stable).
    regions.sort_by(|(a, _), (b, _)| rank(a).cmp(&rank(b)).then_with(|| a.code.cmp(&b.code)));
    let mut out: Vec<NodeGroup> = regions
        .into_iter()
        .map(|(r, members)| NodeGroup {
            tag: r.tag(),
            label: r.label(),
            members,
        })
        .collect();
    for k in &LINE_KINDS {
        let members: Vec<String> = nodes
            .iter()
            .zip(tags)
            .filter(|((n, _), _)| is_usable_node(n) && k.matches(&n.name))
            .map(|(_, t)| t.clone())
            .collect();
        if members.len() >= 2 {
            out.push(NodeGroup {
                tag: k.tag(),
                label: k.label(),
                members,
            });
        }
    }
    out
}
