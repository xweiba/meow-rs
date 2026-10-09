//! The group tree (Dart: `group_tree.dart`): lines → region groups →
//! ♻️ 自动选择 → 🚀 节点选择 and the service groups, as the core runs them
//! and the screen lists them.

use std::collections::{HashMap, HashSet};

use serde_json::{Map, Value};

use crate::model::settings::{GroupEdit, GroupMode, GroupStrategy, ProxySettings};
use crate::plan::outbound_tags;
use crate::plan::policies::{Policy, POLICIES};
use crate::plan::sub_rules::ImportedSplit;
use crate::pool::{group_names, NodeGroup};

/// How a group picks among its members.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum GroupKind {
    /// The user's choice (Clash `select`).
    Select,
    /// Per site, learning which line works (PaoPao's `smart`).
    Smart,
    /// Sites spread over the members, one site one member.
    Balance,
    /// The lowest latency member (`url-test`).
    Fastest,
    /// One member for every site, kept until it fails or slows (固定出口).
    Sticky,
}

impl GroupKind {
    /// The Dart enum name (`select`, `smart` …).
    pub fn name(self) -> &'static str {
        match self {
            Self::Select => "select",
            Self::Smart => "smart",
            Self::Balance => "balance",
            Self::Fastest => "fastest",
            Self::Sticky => "sticky",
        }
    }

    /// A Clash group type as ours: url-test / fallback → fastest,
    /// load-balance → balance, smart → smart, anything else → select.
    pub fn of_type(t: &str) -> Self {
        match t {
            "url-test" | "fallback" => Self::Fastest,
            "load-balance" => Self::Balance,
            "smart" => Self::Smart,
            _ => Self::Select,
        }
    }
}

/// The automatic members every group carries, as tag suffixes.
pub mod group_child {
    /// 自动选择 (智能选择 for a region).
    pub const AUTO: &str = "~auto";
    /// 负载均衡.
    pub const BALANCE: &str = "~balance";
    /// 速度最快.
    pub const FASTEST: &str = "~fastest";
    /// 固定出口.
    pub const STICKY: &str = "~sticky";

    /// Whether `tag` is an automatic child (it has a `~`).
    pub fn is_child(tag: &str) -> bool {
        tag.contains('~')
    }

    /// The group a child belongs to (`region:HK~fastest` → `region:HK`).
    pub fn parent_of(tag: &str) -> &str {
        tag.split_once('~').map_or(tag, |(p, _)| p)
    }
}

/// The children's names by suffix.
fn child_name(suffix: &str) -> &'static str {
    match suffix {
        group_child::AUTO => "自动选择",
        group_child::BALANCE => "负载均衡",
        group_child::FASTEST => "速度最快",
        _ => "固定出口",
    }
}

/// Badge of PaoPao's built-in service groups.
pub const BADGE_BUILT_IN: &str = "内置";
/// Badge of the subscriptions' own groups.
pub const BADGE_SUBSCRIPTION: &str = "订阅";
/// Badge of the user's own groups (策略组).
pub const BADGE_CUSTOM: &str = "自定义";

/// The ♻️ 自动选择 group's own way of choosing (and a region's).
pub const SMART_CHILD_NAME: &str = "智能选择";

/// Lines with no known region: a base group of their own.
pub const OTHER_REGION_TAG: &str = "region:other";
/// What [`OTHER_REGION_TAG`] is shown as.
pub const OTHER_REGION_LABEL: &str = "🏳️ 其他地区";

/// One group of the tree, as the core and the screen see it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroupSpec {
    pub tag: String,
    /// Full name ("🇭🇰 香港 · 速度最快").
    pub label: String,
    /// Name inside its parent ("速度最快"); [`GroupSpec::label`] when None.
    pub short: Option<String>,
    pub kind: GroupKind,
    /// Tags: lines, other groups, DIRECT, REJECT.
    pub members: Vec<String>,
    /// [`GroupKind::Select`]: the member in use.
    pub pick: Option<String>,
    /// Shown as a card of its own (the automatic children are not).
    pub card: bool,
    /// Where it comes from when not PaoPao's layers ([`BADGE_BUILT_IN`],
    /// [`BADGE_SUBSCRIPTION`], [`BADGE_CUSTOM`]).
    pub badge: Option<&'static str>,
    /// 完全按订阅: the provider's own type, written back as is.
    pub raw_type: Option<String>,
    /// A built-in policy the user changed (`ProxySettings::group_edits`).
    pub edited: bool,
}

impl GroupSpec {
    /// A card with no badge, short name or raw type.
    fn new(tag: &str, label: &str, kind: GroupKind, members: Vec<String>) -> Self {
        Self {
            tag: tag.to_owned(),
            label: label.to_owned(),
            short: None,
            kind,
            members,
            pick: None,
            card: true,
            badge: None,
            raw_type: None,
            edited: false,
        }
    }

    /// The golden corpus' shape (Dart `treeJson`): `tag`, `label`,
    /// `short?`, `kind`, `members`, `pick?`, `card`, `badge?`, `rawType?`,
    /// `edited?` (only when true).
    pub fn to_json(&self) -> Value {
        let mut m = Map::new();
        m.insert("tag".into(), self.tag.clone().into());
        m.insert("label".into(), self.label.clone().into());
        if let Some(s) = &self.short {
            m.insert("short".into(), s.clone().into());
        }
        m.insert("kind".into(), self.kind.name().into());
        m.insert("members".into(), self.members.clone().into());
        if let Some(p) = &self.pick {
            m.insert("pick".into(), p.clone().into());
        }
        m.insert("card".into(), self.card.into());
        if let Some(b) = self.badge {
            m.insert("badge".into(), b.into());
        }
        if let Some(t) = &self.raw_type {
            m.insert("rawType".into(), t.clone().into());
        }
        if self.edited {
            m.insert("edited".into(), true.into());
        }
        Value::Object(m)
    }
}

/// Every group, in the order the screen lists them, children after the
/// cards (the core resolves references in any order).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct GroupTree {
    pub groups: Vec<GroupSpec>,
    /// Members cut because they led back round (group, member).
    pub loops: Vec<(String, String)>,
    /// Tag → index in `groups` (a repeated tag: the last).
    index: HashMap<String, usize>,
}

impl GroupTree {
    /// A tree over `groups` with the loops cut from them.
    pub fn new(groups: Vec<GroupSpec>, loops: Vec<(String, String)>) -> Self {
        let index = groups
            .iter()
            .enumerate()
            .map(|(i, g)| (g.tag.clone(), i))
            .collect();
        Self {
            groups,
            loops,
            index,
        }
    }

    /// The group tagged `tag`.
    pub fn by_tag(&self, tag: &str) -> Option<&GroupSpec> {
        self.index.get(tag).map(|i| &self.groups[*i])
    }

    /// The groups shown as cards.
    pub fn cards(&self) -> impl Iterator<Item = &GroupSpec> {
        self.groups.iter().filter(|g| g.card)
    }

    /// The lines a group can reach, each once, in order (DIRECT / REJECT
    /// are not lines).
    pub fn leaves(&self, tag: &str) -> Vec<String> {
        fn walk(t: &GroupTree, tag: &str, seen: &mut HashSet<String>, out: &mut Vec<String>) {
            if !seen.insert(tag.to_owned()) {
                return;
            }
            match t.by_tag(tag) {
                None => {
                    if tag != "DIRECT" && tag != "REJECT" {
                        out.push(tag.to_owned());
                    }
                }
                Some(g) => {
                    for m in &g.members {
                        walk(t, m, seen, out);
                    }
                }
            }
        }
        let mut out = Vec::new();
        let mut seen = HashSet::new();
        if let Some(g) = self.by_tag(tag) {
            seen.insert(tag.to_owned());
            for m in &g.members {
                walk(self, m, &mut seen, &mut out);
            }
        }
        out
    }

    /// `{"groups": [...]}` as [`GroupSpec::to_json`].
    pub fn to_json(&self) -> Value {
        let mut m = Map::new();
        m.insert(
            "groups".into(),
            Value::Array(self.groups.iter().map(GroupSpec::to_json).collect()),
        );
        Value::Object(m)
    }
}

/// What [`build_group_tree`] builds from (Dart `buildGroupTree`'s
/// parameters).
#[derive(Debug, Clone, Copy)]
pub struct TreeInput<'a> {
    /// Every line's tag, in pool order (the pool holds no info rows).
    pub lines: &'a [String],
    /// Region and kind groups of the pool.
    pub base: &'a [NodeGroup],
    pub settings: &'a ProxySettings,
    /// The subscriptions' merged split.
    pub split: &'a ImportedSplit,
    /// Extra outlets offered everywhere (SSH chains).
    pub extras: &'a [String],
    /// Smart mode: the service groups and the subscriptions' groups.
    pub smart_mode: bool,
}

fn strings(xs: &[&str]) -> Vec<String> {
    xs.iter().map(|x| (*x).to_owned()).collect()
}

/// A group's pick: the user's (`group_picks`) when offered, else the
/// region strategy saved before picks were general, else `fallback`.
fn pick_of(s: &ProxySettings, tag: &str, members: &[String], fallback: &str) -> String {
    if let Some(want) = s.group_picks.get(tag) {
        if members.contains(want) {
            return want.clone();
        }
    }
    let legacy = match s.group_strategies.get(tag) {
        Some(GroupStrategy::Fastest) => Some(format!("{tag}{}", group_child::FASTEST)),
        Some(GroupStrategy::Balance) => Some(format!("{tag}{}", group_child::BALANCE)),
        _ => None,
    };
    match legacy {
        Some(l) if members.contains(&l) => l,
        _ => fallback.to_owned(),
    }
}

/// Builds the groups in layers, as in Clash:
///
/// 1. lines, sorted into region groups (the base) and kind groups;
/// 2. ♻️ 自动选择 over every region group, and 🚀 节点选择;
/// 3. the service groups over the region groups too, and the
///    subscriptions' own groups.
///
/// Every group carries 负载均衡 and 速度最快 over its members (two or
/// more enabled lines); those that are not automatic themselves also
/// 自动选择. Children over the same members are shared.
///
/// Without lines: 节点选择 over the extras (or DIRECT) and the user's own
/// groups. With [`GroupMode::Subscription`] and a split that has its own
/// 节点选择: the subscription's groups as written, then the user's own.
pub fn build_group_tree(input: &TreeInput<'_>) -> GroupTree {
    let s = input.settings;
    let extras = input.extras;
    let own_base = |extras: &[String]| {
        let mut m = strings(&["DIRECT", "REJECT", outbound_tags::PROXY]);
        m.extend(extras.iter().cloned());
        m
    };
    let outlet_there = |m: &str| m.starts_with("iface:") || extras.iter().any(|e| e == m);

    // No lines yet: 节点选择 over what there is, and the user's own groups.
    if input.lines.is_empty() {
        let members = if extras.is_empty() {
            strings(&["DIRECT"])
        } else {
            extras.to_vec()
        };
        let pick = if extras.contains(&s.selected) {
            s.selected.clone()
        } else {
            extras.first().cloned().unwrap_or_else(|| "DIRECT".into())
        };
        let mut select = GroupSpec::new(
            outbound_tags::PROXY,
            group_names::SELECT,
            GroupKind::Select,
            members,
        );
        select.pick = Some(pick);
        let mut all = vec![select];
        all.extend(custom_groups(s, &own_base(extras), &outlet_there));
        return tree_without_loops(all);
    }

    // Exactly as the subscriptions wrote it (when they wrote any groups).
    if s.group_mode == GroupMode::Subscription
        && input
            .split
            .groups
            .iter()
            .any(|g| g.tag == outbound_tags::PROXY)
    {
        let mut all: Vec<GroupSpec> = input
            .split
            .groups
            .iter()
            // A group with no members can't run (B24).
            .filter(|g| !g.members.is_empty())
            .map(|g| {
                let kind = GroupKind::of_type(&g.kind);
                let mut spec = GroupSpec::new(&g.tag, &g.name, kind, g.members.clone());
                if kind == GroupKind::Select {
                    let first = g.members[0].clone();
                    spec.pick = Some(pick_of(s, &g.tag, &g.members, &first));
                }
                spec.badge = Some(BADGE_SUBSCRIPTION);
                spec.raw_type = Some(g.kind.clone());
                spec
            })
            .collect();
        all.extend(custom_groups(s, &own_base(extras), &outlet_there));
        return tree_without_loops(all);
    }

    let mut b = Layers {
        off: s.disabled_lines.iter().cloned().collect(),
        children: Vec::new(),
    };

    // 1. Base: regions (every usable line in one), kinds.
    let mut placed: HashSet<&str> = HashSet::new();
    let mut region_groups: Vec<NodeGroup> = Vec::new();
    let mut kind_groups: Vec<&NodeGroup> = Vec::new();
    for g in input.base {
        if g.tag.starts_with("region:") {
            region_groups.push(g.clone());
            placed.extend(g.members.iter().map(String::as_str));
        } else {
            kind_groups.push(g);
        }
    }
    let unplaced: Vec<String> = input
        .lines
        .iter()
        .filter(|l| !placed.contains(l.as_str()))
        .cloned()
        .collect();
    if !unplaced.is_empty() {
        region_groups.push(NodeGroup {
            tag: OTHER_REGION_TAG.into(),
            label: OTHER_REGION_LABEL.into(),
            members: unplaced,
        });
    }
    // A single line chosen in 🚀 节点选择 (before it listed lines): now its
    // region group, on that line.
    let wanted = s.selected.clone();
    let line_home: Option<String> = if input.lines.contains(&wanted) {
        region_groups
            .iter()
            .find(|g| g.members.contains(&wanted))
            .map(|g| g.tag.clone())
    } else {
        None
    };
    let mut base_specs = Vec::new();
    for g in region_groups.iter().chain(kind_groups.iter().copied()) {
        // A region chooses by itself (智能选择), not "自动选择".
        let mut members = b.children_of(&g.tag, &g.label, &g.members, true, Some(SMART_CHILD_NAME));
        members.extend(g.members.iter().cloned());
        let fallback = if line_home.as_deref() == Some(g.tag.as_str()) {
            wanted.clone()
        } else {
            members[0].clone()
        };
        let mut spec = GroupSpec::new(&g.tag, &g.label, GroupKind::Select, members);
        spec.pick = Some(pick_of(s, &g.tag, &spec.members, &fallback));
        base_specs.push(spec);
    }
    let region_tags: Vec<String> = region_groups.iter().map(|g| g.tag.clone()).collect();
    let kind_tags: Vec<String> = kind_groups.iter().map(|g| g.tag.clone()).collect();
    // The automatic children choose among the lines themselves, not the
    // region groups (one layer of racing).
    let lines_of = |tags: &[String]| -> Vec<String> {
        region_groups
            .iter()
            .filter(|g| tags.contains(&g.tag))
            .flat_map(|g| g.members.iter().cloned())
            .collect()
    };
    let all_lines = lines_of(&region_tags);
    let auto_lines = b.enabled(&all_lines);

    // 2. ♻️ 自动选择 over the regions; its 智能选择 is how it chooses.
    let mut auto_members = Vec::new();
    if auto_lines.len() >= 2 {
        let mut smart = GroupSpec::new(
            outbound_tags::SMART,
            &format!("{} · {SMART_CHILD_NAME}", group_names::AUTO),
            GroupKind::Smart,
            auto_lines.clone(),
        );
        smart.short = Some(SMART_CHILD_NAME.into());
        smart.card = false;
        b.children.push(smart);
        auto_members.push(outbound_tags::SMART.to_owned());
    }
    auto_members.extend(b.children_of(
        outbound_tags::AUTO,
        group_names::AUTO,
        &all_lines,
        false,
        None,
    ));
    auto_members.extend(region_tags.iter().cloned());
    let mut out = Vec::new();
    let mut auto = GroupSpec::new(
        outbound_tags::AUTO,
        group_names::AUTO,
        GroupKind::Select,
        auto_members,
    );
    auto.pick = Some(pick_of(
        s,
        outbound_tags::AUTO,
        &auto.members,
        &auto.members[0],
    ));
    out.push(auto);
    // What "all regions" offers above the base.
    let mut over_all = strings(&[outbound_tags::AUTO]);
    if auto_lines.len() >= 2 {
        over_all.extend(strings(&[outbound_tags::BALANCE, outbound_tags::FASTEST]));
    }

    // 🚀 节点选择: 直连 first, then the automatic ones, each region, kind,
    // chain.
    let mut select_members = strings(&["DIRECT"]);
    select_members.extend(over_all.iter().cloned());
    select_members.extend(region_tags.iter().cloned());
    select_members.extend(kind_tags.iter().cloned());
    select_members.extend(extras.iter().cloned());
    let select_pick = if select_members.contains(&wanted) {
        wanted
    } else {
        line_home.unwrap_or_else(|| outbound_tags::AUTO.into())
    };
    let mut select = GroupSpec::new(
        outbound_tags::PROXY,
        group_names::SELECT,
        GroupKind::Select,
        select_members,
    );
    select.pick = Some(select_pick);
    out.insert(0, select);

    // 3. Service groups.
    if input.smart_mode {
        for p in &POLICIES {
            if !p.base && !s.built_in_groups {
                continue;
            }
            out.push(b.policy_group(
                p,
                s,
                &PolicyContext {
                    region_groups: &region_groups,
                    region_tags: &region_tags,
                    kind_tags: &kind_tags,
                    over_all: &over_all,
                    extras,
                },
            ));
        }
        // The subscriptions' own groups, with their own automatic children.
        let line_set: HashSet<&str> = input.lines.iter().map(String::as_str).collect();
        // A group with no members can't run (B24).
        for g in input.split.groups.iter().filter(|g| !g.members.is_empty()) {
            let own: Vec<String> = g
                .members
                .iter()
                .filter(|m| line_set.contains(m.as_str()))
                .cloned()
                .collect();
            let kids = b.children_of(&g.tag, &g.name, &own, true, None);
            let is_fixed = |m: &String| m == "DIRECT" || m == "REJECT";
            // 直连 / 拦截 first, as everywhere.
            let mut members: Vec<String> =
                g.members.iter().filter(|m| is_fixed(m)).cloned().collect();
            members.extend(kids);
            members.extend(g.members.iter().filter(|m| !is_fixed(m)).cloned());
            // The provider's own default comes first in its list.
            let fallback = g.members[0].clone();
            let mut spec = GroupSpec::new(&g.tag, &g.name, GroupKind::Select, members);
            spec.pick = Some(pick_of(s, &g.tag, &spec.members, &fallback));
            spec.badge = Some(BADGE_SUBSCRIPTION);
            out.push(spec);
        }
    }
    out.extend(base_specs);
    let built = edited(s, out, &outlet_there);
    // The user's own policies: over what every business policy is over.
    let mut own_members = strings(&["DIRECT", "REJECT", outbound_tags::PROXY]);
    own_members.extend(over_all.iter().cloned());
    own_members.extend(region_tags.iter().cloned());
    own_members.extend(kind_tags.iter().cloned());
    own_members.extend(extras.iter().cloned());
    let own = custom_groups(s, &own_members, &outlet_there);
    let mut all = built;
    all.extend(own);
    all.extend(b.children);
    tree_without_loops(all)
}

/// The layered build's shared state: lines switched off, and the automatic
/// children made so far (they go last).
struct Layers {
    /// Lines switched off: kept where the user picks by hand, left out of
    /// every automatic choice.
    off: HashSet<String>,
    children: Vec<GroupSpec>,
}

/// What a service group is built over.
struct PolicyContext<'a> {
    region_groups: &'a [NodeGroup],
    region_tags: &'a [String],
    kind_tags: &'a [String],
    over_all: &'a [String],
    extras: &'a [String],
}

impl Layers {
    fn enabled(&self, lines: &[String]) -> Vec<String> {
        lines
            .iter()
            .filter(|l| !self.off.contains(*l))
            .cloned()
            .collect()
    }

    /// `tag`'s children over the enabled ones of `all` (none for fewer than
    /// two): 自动选择 (named `auto_name` when given, with `with_auto`),
    /// 负载均衡, 速度最快. Returns their tags.
    fn children_of(
        &mut self,
        tag: &str,
        label: &str,
        all: &[String],
        with_auto: bool,
        auto_name: Option<&str>,
    ) -> Vec<String> {
        let members = self.enabled(all);
        if members.len() < 2 {
            return Vec::new();
        }
        let mut kinds = Vec::new();
        if with_auto {
            kinds.push((group_child::AUTO, GroupKind::Smart));
        }
        kinds.push((group_child::BALANCE, GroupKind::Balance));
        kinds.push((group_child::FASTEST, GroupKind::Fastest));
        kinds
            .into_iter()
            .map(|(suffix, kind)| {
                let name = match auto_name {
                    Some(n) if suffix == group_child::AUTO => n,
                    _ => child_name(suffix),
                };
                let child_tag = format!("{tag}{suffix}");
                let mut spec = GroupSpec::new(
                    &child_tag,
                    &format!("{label} · {name}"),
                    kind,
                    members.clone(),
                );
                spec.short = Some(name.to_owned());
                spec.card = false;
                self.children.push(spec);
                child_tag
            })
            .collect()
    }

    /// A built-in service group: 拦截 / 直连 for a blockable one; else
    /// over the regions it serves (its own children when it leaves some
    /// out), 固定出口 for a sticky one.
    fn policy_group(&mut self, p: &Policy, s: &ProxySettings, c: &PolicyContext<'_>) -> GroupSpec {
        let tag = p.tag();
        let label = p.label();
        let badge = if p.base { None } else { Some(BADGE_BUILT_IN) };
        if p.blockable {
            let members = strings(&["REJECT", "DIRECT"]);
            let pick = policy_pick(p, s, &members, p.fallback);
            let mut spec = GroupSpec::new(&tag, &label, GroupKind::Select, members);
            spec.pick = Some(pick);
            spec.badge = badge;
            return spec;
        }
        // `g.tag.substring(7)`: the code after `region:`.
        let allowed: Vec<String> = c
            .region_groups
            .iter()
            .filter(|g| !p.avoid_regions.contains(&&g.tag[7..]))
            .map(|g| g.tag.clone())
            .collect();
        let lines_of = |tags: &[String]| -> Vec<String> {
            c.region_groups
                .iter()
                .filter(|g| tags.contains(&g.tag))
                .flat_map(|g| g.members.iter().cloned())
                .collect()
        };
        let mut members = strings(&["DIRECT", "REJECT"]);
        if allowed.len() == c.region_tags.len() {
            members.push(outbound_tags::PROXY.into());
            members.extend(c.over_all.iter().cloned());
            members.extend(c.region_tags.iter().cloned());
            members.extend(c.kind_tags.iter().cloned());
        } else {
            members.extend(self.children_of(&tag, &label, &lines_of(&allowed), true, None));
            members.push(outbound_tags::PROXY.into());
            members.extend(allowed.iter().cloned());
        }
        members.extend(c.extras.iter().cloned());
        // 分组默认 naming a region it has lines in (and does not refuse) is
        // its preferred region: 固定出口 goes over that region's lines.
        let in_allowed = |code: &str| {
            let t = format!("region:{code}");
            allowed.iter().find(|a| **a == t).cloned()
        };
        let chosen_region = s
            .group_defaults
            .get(&tag)
            .filter(|d| d.region.is_some() && d.allowed_for(p))
            .and_then(|d| in_allowed(d.region.as_deref().unwrap_or_default()));
        let preferred = chosen_region.or_else(|| p.prefer_region.and_then(in_allowed));
        // 固定出口: one line for all of the service, first among the members
        // and the default.
        let mut sticky = None;
        if p.sticky_exit {
            let over = match &preferred {
                Some(r) => std::slice::from_ref(r).to_vec(),
                None => allowed.clone(),
            };
            let lines = self.enabled(&lines_of(&over));
            if !lines.is_empty() {
                let t = format!("{tag}{}", group_child::STICKY);
                let name = child_name(group_child::STICKY);
                let mut spec =
                    GroupSpec::new(&t, &format!("{label} · {name}"), GroupKind::Sticky, lines);
                spec.short = Some(name.into());
                spec.card = false;
                self.children.push(spec);
                members.insert(2, t.clone());
                sticky = Some(t);
            }
        }
        let fallback = if p.fallback == outbound_tags::PROXY {
            sticky
                .or_else(|| {
                    p.prefer_pick
                        .filter(|pp| members.iter().any(|m| m == pp))
                        .map(str::to_owned)
                })
                .or_else(|| preferred.clone())
                .unwrap_or_else(|| {
                    if allowed.len() == c.region_tags.len() {
                        return p.fallback.to_owned();
                    }
                    // Serving only some regions: its own 自动选择 over them;
                    // without one (fewer than two lines on), the region of
                    // the first line on there; else 节点选择. Dart named the
                    // missing 自动选择, so the pick fell to the first member,
                    // DIRECT: Google / AI went direct unseen (B22).
                    let auto = format!("{tag}{}", group_child::AUTO);
                    if members.contains(&auto) {
                        return auto;
                    }
                    allowed
                        .iter()
                        .find(|r| !self.enabled(&lines_of(std::slice::from_ref(r))).is_empty())
                        .cloned()
                        .unwrap_or_else(|| outbound_tags::PROXY.to_owned())
                })
        } else {
            p.fallback.to_owned()
        };
        let pick = policy_pick(p, s, &members, &fallback);
        let mut spec = GroupSpec::new(&tag, &label, GroupKind::Select, members);
        spec.pick = Some(pick);
        spec.badge = badge;
        spec
    }
}

/// Our outbound names as the core's: `direct` → DIRECT, `block` → REJECT.
fn clash_name(tag: &str) -> &str {
    match tag {
        outbound_tags::DIRECT => "DIRECT",
        outbound_tags::BLOCK => "REJECT",
        _ => tag,
    }
}

/// [`clash_name`] when offered, else the first member.
fn clash(tag: &str, members: &[String]) -> String {
    let t = clash_name(tag);
    if members.iter().any(|m| m == t) {
        t.to_owned()
    } else {
        members.first().cloned().unwrap_or_default()
    }
}

/// A built-in group's pick: the user's own (proxies page, `policies`) >
/// its 分组默认 > `built_in`; each only when the group offers it.
fn policy_pick(p: &Policy, s: &ProxySettings, members: &[String], built_in: &str) -> String {
    let tag = p.tag();
    if let Some(manual) = s.policies.get(&tag) {
        let t = clash(manual, members);
        if t == clash_name(manual) {
            return t;
        }
    }
    if let Some(d) = s
        .group_defaults
        .get(&tag)
        .and_then(|d| d.member_in(p, members))
    {
        return d;
    }
    clash(built_in, members)
}

/// The groups with the user's edits (`group_edits`) applied to the ones
/// that take edits ([`GroupEdit::editable`]): extra outlets that are there
/// after their members, marked edited; the proxies page's choice
/// (`policies`, then `group_picks`) may now be one of them.
fn edited(
    s: &ProxySettings,
    groups: Vec<GroupSpec>,
    exists: &dyn Fn(&str) -> bool,
) -> Vec<GroupSpec> {
    if s.group_edits.is_empty() {
        return groups;
    }
    groups
        .into_iter()
        .map(|mut g| {
            let Some(e) = s
                .group_edits
                .get(&g.tag)
                .filter(|e| !e.is_empty() && GroupEdit::editable(&g.tag))
            else {
                return g;
            };
            let there = GroupEdit {
                extras: e.extras.iter().filter(|m| exists(m)).cloned().collect(),
                exclude: Vec::new(),
            };
            let members = there.apply(&g.members);
            let chosen = s
                .policies
                .get(&g.tag)
                .map(|p| clash_name(p).to_owned())
                .into_iter()
                .chain(s.group_picks.get(&g.tag).cloned())
                .find(|c| members.contains(c));
            g.members = members;
            if chosen.is_some() {
                g.pick = chosen;
            }
            g.edited = true;
            g
        })
        .collect()
}

/// The user's own business policies (`custom_groups`): `members` plus
/// their extra outlets that are there. Default: theirs, else 节点选择.
fn custom_groups(
    s: &ProxySettings,
    members: &[String],
    exists: &dyn Fn(&str) -> bool,
) -> Vec<GroupSpec> {
    s.custom_groups
        .iter()
        .map(|c| {
            let mut all = members.to_vec();
            // Each outlet once (B25).
            for m in c.extras.iter().filter(|m| exists(m)) {
                if !all.contains(m) {
                    all.push(m.clone());
                }
            }
            let fallback = match &c.pick {
                Some(p) if all.contains(p) => p.clone(),
                _ if all.iter().any(|m| m == outbound_tags::PROXY) => outbound_tags::PROXY.into(),
                _ => all.first().cloned().unwrap_or_default(),
            };
            let tag = c.tag();
            let pick = pick_of(s, &tag, &all, &fallback);
            let mut spec = GroupSpec::new(&tag, &c.name, GroupKind::Select, all);
            spec.pick = Some(pick);
            spec.badge = Some(BADGE_CUSTOM);
            spec
        })
        .collect()
}

/// Drops any member that leads back to a group already on the way (a
/// subscription's groups can point at each other): a loop would send
/// connections round in circles. A group whose pick was cut picks its
/// first remaining member; one left with no member goes DIRECT, as an
/// imported group with none does (the core refuses an empty group). Dart
/// kept the cut pick there (`copyWith(pick: null)` keeps it, B23), which
/// put the loop back.
fn tree_without_loops(groups: Vec<GroupSpec>) -> GroupTree {
    let by_tag: HashMap<&str, &GroupSpec> = groups.iter().map(|g| (g.tag.as_str(), g)).collect();
    let mut cut: HashMap<String, HashSet<String>> = HashMap::new();
    let mut loops = Vec::new();
    let mut done: HashSet<String> = HashSet::new();

    fn visit<'a>(
        tag: &'a str,
        path: &mut Vec<&'a str>,
        by_tag: &HashMap<&'a str, &'a GroupSpec>,
        done: &mut HashSet<String>,
        cut: &mut HashMap<String, HashSet<String>>,
        loops: &mut Vec<(String, String)>,
    ) {
        if done.contains(tag) {
            return;
        }
        let Some(g) = by_tag.get(tag) else { return };
        path.push(tag);
        for m in &g.members {
            if path.contains(&m.as_str()) {
                cut.entry(tag.to_owned()).or_default().insert(m.clone());
                loops.push((tag.to_owned(), m.clone()));
            } else if by_tag.contains_key(m.as_str()) {
                visit(m, path, by_tag, done, cut, loops);
            }
        }
        path.pop();
        done.insert(tag.to_owned());
    }

    for g in &groups {
        visit(
            &g.tag,
            &mut Vec::new(),
            &by_tag,
            &mut done,
            &mut cut,
            &mut loops,
        );
    }
    if cut.is_empty() {
        return GroupTree::new(groups, loops);
    }
    let groups = groups
        .into_iter()
        .map(|mut g| {
            let Some(drop) = cut.get(&g.tag) else {
                return g;
            };
            let mut kept: Vec<String> = g
                .members
                .iter()
                .filter(|m| !drop.contains(*m))
                .cloned()
                .collect();
            if kept.is_empty() {
                kept.push("DIRECT".into());
            }
            if g.pick.as_ref().is_some_and(|p| drop.contains(p)) {
                g.pick = Some(kept[0].clone());
            }
            g.members = kept;
            g
        })
        .collect();
    GroupTree::new(groups, loops)
}
