//! L3: the plan — the built-in policies, the subscriptions' merged split
//! and the group tree (Dart: `policies.dart`, `group_defaults.dart`,
//! `custom_groups.dart`, `sub_rules.dart`, `group_tree.dart`, and how
//! `ProxyController` assembles them).
//!
//! [`tree_for`] is the one group tree: the screen shows it and the config
//! runs it (B2).
//!
//! The split, the tree and the route policies all read the settings in
//! force, passed in once (B3, B30).
//!
//! - B5 / B6 live in the controller (rough rule matching, label cache) and
//!   are not ported here.

pub mod custom_groups;
pub mod group_defaults;
pub mod group_tree;
mod input;
pub mod policies;
mod route;
pub mod sub_rules;

#[cfg(test)]
mod tests;

use indexmap::IndexMap;

use crate::dart::contains_ignore_ascii_case;
use crate::model::settings::{GroupMode, ProxyMode, ProxySettings, SshChain};
use crate::pool::{endpoint, is_usable_node, region_of, NodeGroup, Pool};

pub use group_tree::{build_group_tree, GroupKind, GroupSpec, GroupTree, TreeInput};
pub use input::{AutoStrategy, BuildInput, RouteAccess, RuntimeOptions};
pub use policies::{final_policy, policy_by_tag, Policy, POLICIES};
pub use route::{offered_route_policies, route_catalog, RoutePolicy};
pub use sub_rules::{
    merge_subscription_splits, ImportedGroup, ImportedSplit, MergeTargets, SubSplit,
};

/// Our own outbound tags (Dart `OutboundTags`).
pub mod outbound_tags {
    /// 🚀 节点选择.
    pub const PROXY: &str = "proxy";
    /// ♻️ 自动选择.
    pub const AUTO: &str = "auto";
    /// ♻️ 自动选择's 智能选择.
    pub const SMART: &str = "auto~smart";
    /// ♻️ 自动选择's 负载均衡.
    pub const BALANCE: &str = "auto~balance";
    /// ♻️ 自动选择's 速度最快.
    pub const FASTEST: &str = "auto~fastest";
    /// The selector the download speed test switches line by line.
    pub const SPEED_TEST: &str = "speedtest";
    /// Direct (Clash's DIRECT), as stored in settings.
    pub const DIRECT: &str = "direct";
    /// Refuse (Clash's REJECT), as stored in settings.
    pub const BLOCK: &str = "block";
}

/// `节点选择|选择节点|手动切换|^\W*(proxy|proxies)\W*$`, case-insensitive
/// (`\W` is ASCII: anything but `[A-Za-z0-9_]`).
fn is_select_name(name: &str) -> bool {
    if ["节点选择", "选择节点", "手动切换"]
        .iter()
        .any(|w| name.contains(w))
    {
        return true;
    }
    let core = name.trim_matches(|c: char| !(c.is_ascii_alphanumeric() || c == '_'));
    core.eq_ignore_ascii_case("proxy") || core.eq_ignore_ascii_case("proxies")
}

/// Our group a provider's group `name` means, if any (Dart
/// `ProxyController._ourGroupFor`): the provider's own 节点选择 → `proxy`;
/// a built-in service by alias (when built-in groups are on); a region we
/// have lines in (`groups` of the pool); else 其他地区 for "其他 / other".
pub fn our_group_for(name: &str, settings: &ProxySettings, groups: &[NodeGroup]) -> Option<String> {
    if is_select_name(name) {
        return Some(outbound_tags::PROXY.into());
    }
    if settings.built_in_groups {
        if let Some(p) = POLICIES.iter().find(|p| !p.base && p.alias_matches(name)) {
            return Some(p.tag());
        }
    }
    if let Some(r) = region_of(name) {
        let tag = r.tag();
        if groups.iter().any(|g| g.tag == tag) {
            return Some(tag);
        }
    }
    ["其他", "其它", "other"]
        .iter()
        .any(|w| contains_ignore_ascii_case(name, w))
        .then(|| group_tree::OTHER_REGION_TAG.into())
}

/// The subscriptions' own groups and rules, merged by priority and mapped
/// onto the pooled lines (Dart `ProxyController.importedSplit`). Only
/// subscriptions with `use_split` and a non-empty split take part.
///
/// `settings` are the ones in force (`group_mode` for following the
/// subscription exactly, `built_in_groups` for aliases), the same the tree
/// is built from; Dart read the raw saved ones here (B3).
pub fn imported_split(input: &BuildInput, pool: &Pool, settings: &ProxySettings) -> ImportedSplit {
    let tag_of: IndexMap<String, &String> = pool
        .nodes
        .iter()
        .zip(&pool.tags)
        .map(|(n, t)| (endpoint(&n.node), t))
        .collect();
    let used: Vec<_> = input
        .subscriptions
        .iter()
        .filter(|s| s.use_split && !s.split.is_empty())
        .collect();
    // `{for n in nodes: n.name: ?tagOf[endpoint]}`: a name with no line is
    // left out; a repeated name takes the later line.
    let line_maps: Vec<IndexMap<String, String>> = used
        .iter()
        .map(|s| {
            let mut m = IndexMap::new();
            for n in &s.nodes {
                if let Some(t) = tag_of.get(&endpoint(n)) {
                    m.insert(n.name.clone(), (*t).clone());
                }
            }
            m
        })
        .collect();
    let splits: Vec<SubSplit<'_>> = used
        .iter()
        .zip(&line_maps)
        .map(|(s, l)| SubSplit {
            rules: &s.split,
            line_of: l,
        })
        .collect();
    let built_in_of = |name: &str| our_group_for(name, settings, &pool.groups);
    merge_subscription_splits(
        &splits,
        MergeTargets {
            select: outbound_tags::PROXY,
            auto: outbound_tags::AUTO,
            fallback: &policies::final_policy().tag(),
        },
        Some(&built_in_of),
        settings.group_mode == GroupMode::Subscription,
    )
}

/// The group tree of a build ([`tree_for`] with the effective settings
/// and the subscriptions' split).
pub fn build_tree(input: &BuildInput, pool: &Pool) -> GroupTree {
    let s = input.effective();
    tree_for(&s, pool, &imported_split(input, pool, &s))
}

/// The one group tree (B2): what the screen shows and the config runs,
/// over the pool with the settings in force `s`, the subscriptions' merged
/// `split` and the SSH chains as extra outlets.
///
/// Dart built it twice: the screen's left the split out outside smart mode
/// (so with `group_mode = subscription` it showed our layers while the
/// core ran the provider's groups).
pub fn tree_for(s: &ProxySettings, pool: &Pool, split: &ImportedSplit) -> GroupTree {
    let usable: Vec<String> = pool
        .nodes
        .iter()
        .zip(&pool.tags)
        .filter(|(n, _)| is_usable_node(&n.node))
        .map(|(_, t)| t.clone())
        .collect();
    let extras: Vec<String> = s.ssh_chains.iter().map(SshChain::tag).collect();
    build_group_tree(&TreeInput {
        lines: &pool.tags,
        usable: &usable,
        base: &pool.groups,
        settings: s,
        split,
        extras: &extras,
        smart_mode: s.mode == ProxyMode::Smart,
    })
}
