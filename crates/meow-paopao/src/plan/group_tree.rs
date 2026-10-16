//! The group tree (Dart: `group_tree.dart`): lines → region groups →
//! ♻️ 自动选择 → 🚀 节点选择 and the service groups, as the core runs them
//! and the screen lists them.

use std::collections::{HashMap, HashSet};

use serde_json::{Map, Value};

use crate::model::settings::{
    copy_origin, is_policy_tag, GroupDefault, GroupDefaultKind, GroupEdit, GroupMode,
    GroupStrategy, MemberUse, ProxySettings, COPY_MARK,
};
use crate::plan::outbound_tags;
use crate::plan::policies::{policy_by_tag, Policy, POLICIES};
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
    /// One member for every site, kept until it fails or slows (a
    /// policy's 固定出口, see [`with_group_use`]).
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
    /// 固定出口 (a policy's copy only, [`super::with_group_use`]).
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
        _ => "固定节点",
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

/// Lines with no known region, and those of regions with fewer than
/// [`MIN_REGION_LINES`]: a base group of their own.
pub const OTHER_REGION_TAG: &str = "region:other";
/// What [`OTHER_REGION_TAG`] is shown as.
pub const OTHER_REGION_LABEL: &str = "🌐 其他地区";
/// Lines a region needs for a group of its own; fewer go to 其他地区.
pub const MIN_REGION_LINES: usize = 2;

/// Whether the pool's region group `g` is a group of its own in the tree
/// (else its lines are in [`OTHER_REGION_TAG`]).
pub fn has_own_group(g: &NodeGroup) -> bool {
    g.members.len() >= MIN_REGION_LINES
}

/// One group of the tree, as the core and the screen see it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroupSpec {
    pub tag: String,
    /// Full name ("🇭🇰 香港 · 速度最快").
    pub label: String,
    /// Name inside its parent ("速度最快"); [`GroupSpec::label`] when None.
    pub short: Option<String>,
    pub kind: GroupKind,
    /// Tags: lines, other groups, DIRECT, REJECT — what a user picks
    /// between.
    pub members: Vec<String>,
    /// A shared group's own automatic ways of choosing (its hidden
    /// children `<tag>~auto` / `~smart` / `~balance` / `~fastest`, not
    /// cards): only its own pick may be one, no other group lists them.
    pub modes: Vec<String>,
    /// [`GroupKind::Select`]: the member (or mode) in use.
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
    /// A group's own copy of a member ([`with_group_use`]): the member
    /// it stands for in that group.
    pub origin: Option<String>,
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
            modes: Vec::new(),
            pick: None,
            card: true,
            badge: None,
            raw_type: None,
            edited: false,
            origin: None,
        }
    }

    /// Its modes, then its members: everything its selector holds.
    pub fn choices(&self) -> impl Iterator<Item = &String> {
        self.modes.iter().chain(&self.members)
    }

    /// The golden corpus' shape (Dart `treeJson`): `tag`, `label`,
    /// `short?`, `kind`, `members`, `modes?` (only when any), `pick?`,
    /// `card`, `badge?`, `rawType?`, `edited?` (only when true), `origin?`.
    pub fn to_json(&self) -> Value {
        let mut m = Map::new();
        m.insert("tag".into(), self.tag.clone().into());
        m.insert("label".into(), self.label.clone().into());
        if let Some(s) = &self.short {
            m.insert("short".into(), s.clone().into());
        }
        m.insert("kind".into(), self.kind.name().into());
        m.insert("members".into(), self.members.clone().into());
        if !self.modes.is_empty() {
            m.insert("modes".into(), self.modes.clone().into());
        }
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
        if let Some(o) = &self.origin {
            m.insert("origin".into(), o.clone().into());
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
                    for m in g.choices() {
                        walk(t, m, seen, out);
                    }
                }
            }
        }
        let mut out = Vec::new();
        let mut seen = HashSet::new();
        if let Some(g) = self.by_tag(tag) {
            seen.insert(tag.to_owned());
            for m in g.choices() {
                walk(self, m, &mut seen, &mut out);
            }
        }
        out
    }

    /// `tag`'s members as the policy offers them: its copies
    /// ([`GroupSpec::origin`]) as the members they stand for.
    pub fn plain_members(&self, tag: &str) -> Vec<String> {
        self.by_tag(tag).map_or_else(Vec::new, |g| {
            g.members
                .iter()
                .map(|m| {
                    self.by_tag(m)
                        .and_then(|c| c.origin.clone())
                        .unwrap_or_else(|| m.clone())
                })
                .collect()
        })
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
/// 2. ♻️ 自动选择 (its modes only), and 🚀 节点选择;
/// 3. the service groups over the region groups too, and the
///    subscriptions' own groups.
///
/// A region needs [`MIN_REGION_LINES`] for a group of its own; the rest
/// share 其他地区. A shared group (♻️ 自动选择, a region, a kind, a
/// subscription's group) carries 智能选择, 负载均衡 and 速度最快 over its
/// lines (two or more enabled) as [`GroupSpec::modes`]: its own pick may
/// be one, no other group lists them. Members are the groups themselves;
/// how a user uses one (a mode, a line) is its copy ([`with_group_use`]).
/// 🚀 节点选择 has no 直连; a policy refusing regions (AI, Google) has no
/// 节点选择 and its own copies of 自动选择 / 其他地区 without them.
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
        return tree_without_loops(with_group_use(s, all));
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
        return tree_without_loops(with_group_use(s, all));
    }

    let mut b = Layers {
        off: s.disabled_lines.iter().cloned().collect(),
        children: Vec::new(),
    };

    // 1. Base: regions with two lines or more (every usable line in one,
    // the rest in 其他地区), kinds.
    let mut line_region: HashMap<String, String> = HashMap::new();
    let mut region_groups: Vec<NodeGroup> = Vec::new();
    let mut kind_groups: Vec<&NodeGroup> = Vec::new();
    for g in input.base {
        if let Some(code) = g.tag.strip_prefix("region:") {
            for m in &g.members {
                line_region.insert(m.clone(), code.to_owned());
            }
            if has_own_group(g) {
                region_groups.push(g.clone());
            }
        } else {
            kind_groups.push(g);
        }
    }
    let in_own: HashSet<&str> = region_groups
        .iter()
        .flat_map(|g| g.members.iter().map(String::as_str))
        .collect();
    let other: Vec<String> = input
        .lines
        .iter()
        .filter(|l| !in_own.contains(l.as_str()))
        .cloned()
        .collect();
    if !other.is_empty() {
        region_groups.push(NodeGroup {
            tag: OTHER_REGION_TAG.into(),
            label: OTHER_REGION_LABEL.into(),
            members: other,
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
    // Each region / kind: its lines, and its own ways of choosing among
    // them (智能选择, 负载均衡, 速度最快) as modes only its pick may be.
    let mut base_specs = Vec::new();
    for g in region_groups.iter().chain(kind_groups.iter().copied()) {
        let modes = b.children_of(&g.tag, &g.label, &g.members, true, Some(SMART_CHILD_NAME));
        let mut spec = GroupSpec::new(&g.tag, &g.label, GroupKind::Select, g.members.clone());
        spec.modes = modes;
        let fallback = if line_home.as_deref() == Some(g.tag.as_str()) {
            wanted.clone()
        } else {
            spec.choices().next().cloned().unwrap_or_default()
        };
        let choices: Vec<String> = spec.choices().cloned().collect();
        spec.pick = Some(pick_of(s, &g.tag, &choices, &fallback));
        base_specs.push(spec);
    }
    let region_tags: Vec<String> = region_groups.iter().map(|g| g.tag.clone()).collect();
    let kind_tags: Vec<String> = kind_groups.iter().map(|g| g.tag.clone()).collect();
    // The automatic children choose among the lines themselves, not the
    // region groups (one layer of racing).
    let all_lines: Vec<String> = region_groups
        .iter()
        .flat_map(|g| g.members.iter().cloned())
        .collect();
    let auto_lines = b.enabled(&all_lines);

    // 2. ♻️ 自动选择: its modes only (智能选择, 负载均衡, 速度最快), never a
    // line or a region to pick by hand (picking one is 节点选择's, a
    // policy's or the user's own group's). Fewer than two lines on: no
    // modes, the regions stand in.
    let mut auto_modes = Vec::new();
    if auto_lines.len() >= 2 {
        let mut smart = GroupSpec::new(
            outbound_tags::SMART,
            &format!("{} · {SMART_CHILD_NAME}", group_names::AUTO),
            GroupKind::Smart,
            auto_lines,
        );
        smart.short = Some(SMART_CHILD_NAME.into());
        smart.card = false;
        b.children.push(smart);
        auto_modes.push(outbound_tags::SMART.to_owned());
    }
    auto_modes.extend(b.children_of(
        outbound_tags::AUTO,
        group_names::AUTO,
        &all_lines,
        false,
        None,
    ));
    let auto_members = if auto_modes.is_empty() {
        region_tags.clone()
    } else {
        Vec::new()
    };
    let mut out = Vec::new();
    let mut auto = GroupSpec::new(
        outbound_tags::AUTO,
        group_names::AUTO,
        GroupKind::Select,
        auto_members,
    );
    auto.modes = auto_modes;
    let auto_choices: Vec<String> = auto.choices().cloned().collect();
    auto.pick = Some(pick_of(
        s,
        outbound_tags::AUTO,
        &auto_choices,
        &auto_choices[0],
    ));

    // 🚀 节点选择: 自动选择, each region, kind, chain (直连 is a policy's).
    let mut select_members = strings(&[outbound_tags::AUTO]);
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
    out.push(select);

    // 3. Service groups.
    if input.smart_mode {
        let shared: HashMap<String, GroupSpec> = std::iter::once(&auto)
            .chain(&base_specs)
            .map(|g| (g.tag.clone(), g.clone()))
            .collect();
        let c = PolicyContext {
            region_groups: &region_groups,
            region_tags: &region_tags,
            kind_tags: &kind_tags,
            all_lines: &all_lines,
            line_region: &line_region,
            shared: &shared,
            extras,
        };
        for p in &POLICIES {
            if !p.base && !s.built_in_groups {
                continue;
            }
            let g = b.policy_group(p, s, &c);
            out.push(g);
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
            let modes = b.children_of(&g.tag, &g.name, &own, true, None);
            let is_fixed = |m: &String| m == "DIRECT" || m == "REJECT";
            // 直连 / 拦截 first, as everywhere.
            let mut members: Vec<String> =
                g.members.iter().filter(|m| is_fixed(m)).cloned().collect();
            members.extend(g.members.iter().filter(|m| !is_fixed(m)).cloned());
            // The provider's own default comes first in its list.
            let fallback = g.members[0].clone();
            let mut spec = GroupSpec::new(&g.tag, &g.name, GroupKind::Select, members);
            spec.modes = modes;
            let choices: Vec<String> = spec.choices().cloned().collect();
            spec.pick = Some(pick_of(s, &g.tag, &choices, &fallback));
            spec.badge = Some(BADGE_SUBSCRIPTION);
            out.push(spec);
        }
    }
    out.insert(1, auto);
    out.extend(base_specs);
    let built = edited(s, out, &outlet_there);
    // The user's own policies: over what every business policy is over.
    let mut own_members = strings(&[
        "DIRECT",
        "REJECT",
        outbound_tags::PROXY,
        outbound_tags::AUTO,
    ]);
    own_members.extend(region_tags.iter().cloned());
    own_members.extend(kind_tags.iter().cloned());
    own_members.extend(extras.iter().cloned());
    let own = custom_groups(s, &own_members, &outlet_there);
    let mut all = built;
    all.extend(own);
    all.extend(b.children);
    tree_without_loops(with_group_use(s, all))
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
    /// Every line in a region group, in their order.
    all_lines: &'a [String],
    /// Line → the code of the region it is in (those in 其他地区 too).
    line_region: &'a HashMap<String, String>,
    /// ♻️ 自动选择 and the region / kind groups, by tag.
    shared: &'a HashMap<String, GroupSpec>,
    extras: &'a [String],
}

/// How group `user` uses its member `member`: the saved use
/// ([`ProxySettings::member_use`]); a built-in policy's ♻️ 自动选择 with
/// none saved: its 分组默认's mode when that is 自动选择 in a mode, else
/// its own ([`Policy::auto_mode`], YouTube: 速度最快). None = as `member`
/// decides.
fn use_of(s: &ProxySettings, user: &str, member: &str) -> Option<MemberUse> {
    if let Some(u) = s.member_use(user, member) {
        return Some(u.clone());
    }
    if member != outbound_tags::AUTO {
        return None;
    }
    let p = policy_by_tag(user)?;
    // A 分组默认 that is 自动选择 in some mode says how; any other (a
    // region, 直连 …) leaves the built-in way as it is.
    let kind = match s.group_defaults.get(user).map(|d| d.kind) {
        Some(
            k @ (GroupDefaultKind::Fastest | GroupDefaultKind::Auto | GroupDefaultKind::Balance),
        ) => k,
        _ => p.auto_mode?,
    };
    GroupDefault::auto_use(kind)
}

/// A shared group's own pick as a use: one of its modes, or a line.
fn own_use(g: &GroupSpec) -> Option<MemberUse> {
    let pick = g.pick.as_deref()?;
    let mode = pick
        .strip_prefix(g.tag.as_str())
        .and_then(|suffix| match suffix {
            "~auto" | "~smart" => Some(MemberUse::Smart),
            "~balance" => Some(MemberUse::Balance),
            "~fastest" => Some(MemberUse::Fastest),
            _ => None,
        });
    mode.or_else(|| {
        g.members
            .iter()
            .any(|m| m == pick)
            .then(|| MemberUse::Line(pick.to_owned()))
    })
}

/// The member of `members` that is `want` in group `user`: `want` itself
/// or `user`'s own copy of it.
fn offered(user: &str, members: &[String], want: &str) -> Option<String> {
    members
        .iter()
        .find(|m| *m == want || copy_origin(user, m) == Some(want))
        .cloned()
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

    /// Group `user`'s own copy of shared group `g` over only `lines` (those
    /// of `g`'s it does not refuse): `<user>@<g>~auto|~balance|~fastest`
    /// in the mode it uses `g` in (`use_`, else `g`'s own pick, else
    /// 智能选择) over the enabled ones; with a line chosen or fewer than two
    /// on, `<user>@<g>` on one line (only when `lines_ok`: ♻️ 自动选择 has
    /// no line to pick, none then). None without lines.
    fn narrowed(
        &mut self,
        user: &str,
        g: &GroupSpec,
        lines: &[String],
        use_: Option<MemberUse>,
        lines_ok: bool,
    ) -> Option<String> {
        if lines.is_empty() {
            return None;
        }
        let on = self.enabled(lines);
        let want = use_.or_else(|| own_use(g)).unwrap_or(MemberUse::Smart);
        let base = format!("{user}{COPY_MARK}{}", g.tag);
        let mode = match &want {
            MemberUse::Smart => Some((group_child::AUTO, GroupKind::Smart, SMART_CHILD_NAME)),
            MemberUse::Balance => Some((
                group_child::BALANCE,
                GroupKind::Balance,
                child_name(group_child::BALANCE),
            )),
            MemberUse::Fastest => Some((
                group_child::FASTEST,
                GroupKind::Fastest,
                child_name(group_child::FASTEST),
            )),
            MemberUse::Line(_) => None,
        };
        let mut copy = match mode {
            Some((suffix, kind, name)) if on.len() >= 2 => GroupSpec::new(
                &format!("{base}{suffix}"),
                &format!("{} · {name}", g.label),
                kind,
                on,
            ),
            _ if !lines_ok => return None,
            _ => {
                let pick = match &want {
                    MemberUse::Line(l) if lines.contains(l) => l.clone(),
                    _ => on.first().unwrap_or(&lines[0]).clone(),
                };
                let mut c = GroupSpec::new(
                    &base,
                    &format!("{} · {pick}", g.label),
                    GroupKind::Select,
                    lines.to_vec(),
                );
                c.pick = Some(pick);
                c
            }
        };
        copy.card = false;
        copy.origin = Some(g.tag.clone());
        let tag = copy.tag.clone();
        self.children.push(copy);
        Some(tag)
    }

    /// A built-in service group: 拦截 / 直连 for a blockable one; else
    /// 直连, 拦截, 节点选择, 自动选择, the regions and kinds; one that
    /// refuses some regions has no 节点选择 or kind (they may lead there)
    /// and its own copies of 自动选择 and of a region holding lines it
    /// refuses (其他地区), over the rest ([`Layers::narrowed`]).
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
        let refused = |l: &String| {
            c.line_region
                .get(l)
                .is_some_and(|code| p.avoid_regions.contains(&code.as_str()))
        };
        let restricted = c.all_lines.iter().any(refused);
        let mut members = strings(&["DIRECT", "REJECT"]);
        // Each region member with the lines it goes over.
        let mut regions: Vec<(String, Vec<String>)> = Vec::new();
        if restricted {
            let usable: Vec<String> = c
                .all_lines
                .iter()
                .filter(|l| !refused(l))
                .cloned()
                .collect();
            if let Some(auto) = c.shared.get(outbound_tags::AUTO) {
                let use_ = use_of(s, &tag, outbound_tags::AUTO);
                members.extend(self.narrowed(&tag, auto, &usable, use_, false));
            }
            for g in c.region_groups {
                let lines: Vec<String> =
                    g.members.iter().filter(|l| !refused(l)).cloned().collect();
                if lines.len() == g.members.len() {
                    members.push(g.tag.clone());
                    regions.push((g.tag.clone(), lines));
                    continue;
                }
                let Some(spec) = c.shared.get(&g.tag) else {
                    continue;
                };
                let use_ = s.member_use(&tag, &g.tag).cloned();
                if let Some(t) = self.narrowed(&tag, spec, &lines, use_, true) {
                    members.push(t.clone());
                    regions.push((t, lines));
                }
            }
        } else {
            members.extend(strings(&[outbound_tags::PROXY, outbound_tags::AUTO]));
            members.extend(c.region_tags.iter().cloned());
            members.extend(c.kind_tags.iter().cloned());
            regions.extend(
                c.region_groups
                    .iter()
                    .map(|g| (g.tag.clone(), g.members.clone())),
            );
        }
        members.extend(c.extras.iter().cloned());
        // 分组默认 naming a region it has a group of its own for (and does
        // not refuse) is its preferred region.
        let in_members = |code: &str| {
            let t = format!("region:{code}");
            members.iter().find(|m| **m == t).cloned()
        };
        let chosen_region = s
            .group_defaults
            .get(&tag)
            .filter(|d| d.region.is_some() && d.allowed_for(p))
            .and_then(|d| in_members(d.region.as_deref().unwrap_or_default()));
        let preferred = chosen_region.or_else(|| p.prefer_region.and_then(in_members));
        let auto_member = offered(&tag, &members, outbound_tags::AUTO);
        // 固定出口 (a sticky policy) over all its lines when no region is
        // preferred: 自动选择 decides them all ([`with_group_use`] keeps it
        // on one).
        let all_lines_auto = || auto_member.clone().filter(|_| p.sticky_exit);
        let fallback = if p.fallback == outbound_tags::PROXY {
            p.prefer_pick
                .and_then(|pp| offered(&tag, &members, pp))
                .or_else(|| preferred.clone())
                .or_else(all_lines_auto)
                .unwrap_or_else(|| {
                    if !restricted {
                        return p.fallback.to_owned();
                    }
                    // Refusing some regions: its own 自动选择 over the rest;
                    // without one (fewer than two lines on), the first region
                    // with a line on there, else any of its regions, else an
                    // outlet, else 直连 — never 节点选择, which may lead to a
                    // refused region (B22: Google / AI went direct unseen
                    // when Dart named a missing 自动选择).
                    if let Some(a) = &auto_member {
                        return a.clone();
                    }
                    regions
                        .iter()
                        .find(|(_, lines)| !self.enabled(lines).is_empty())
                        .or(regions.first())
                        .map(|(t, _)| t.clone())
                        .or_else(|| c.extras.first().cloned())
                        .unwrap_or_else(|| "DIRECT".to_owned())
                })
        } else {
            p.fallback.to_owned()
        };
        // 固定出口 picked when it was a member of its own: the lines it
        // went over, the switch keeping it (`built_in_sticky`).
        let old_sticky = format!("{tag}{}", group_child::STICKY);
        let pick = if s.policies.get(&tag) == Some(&old_sticky) {
            preferred
                .or_else(all_lines_auto)
                .filter(|t| members.contains(t))
                .unwrap_or_else(|| policy_pick(p, s, &members, &fallback))
        } else {
            policy_pick(p, s, &members, &fallback)
        };
        let mut spec = GroupSpec::new(&tag, &label, GroupKind::Select, members);
        spec.pick = Some(pick);
        spec.badge = badge;
        spec
    }
}

/// Each 策略组's own use of the shared groups among its members
/// (`ProxySettings::group_use`) and a policy's 固定出口: a member it uses
/// otherwise than as the member itself decides is replaced, in that group
/// only, by a copy of its own ([`member_copy`]: tagged `<user>@<member>…`,
/// [`GroupSpec::origin`] naming the member, not a card); the pick follows.
/// Any selector card may use its members so (节点选择, 自动选择, a policy,
/// the user's 策略组, a subscription's group in PaoPao's layers), never a
/// subscription's group written as is or a copy. Members go first
/// (♻️ 自动选择 before 🚀 节点选择 before a policy), so a copy over a
/// member that uses its own members its own way, and 固定出口 following
/// the picks down, see what that member really uses. Without any, the
/// groups are as they were.
fn with_group_use(s: &ProxySettings, mut groups: Vec<GroupSpec>) -> Vec<GroupSpec> {
    let mut by_tag: HashMap<String, GroupSpec> =
        groups.iter().map(|g| (g.tag.clone(), g.clone())).collect();
    let mut copies = Vec::new();
    for i in members_first(&groups) {
        let g = &mut groups[i];
        if g.kind != GroupKind::Select || !g.card || g.raw_type.is_some() || g.origin.is_some() {
            continue;
        }
        let sticky = s.sticky_of(&g.tag);
        for k in 0..g.members.len() {
            let m = g.members[k].clone();
            let Some(member) = by_tag.get(&m) else {
                continue;
            };
            let picked = g.pick.as_deref() == Some(m.as_str());
            // The group's own copy (one leaving regions out) already is
            // how it uses the member.
            let use_ = if member.origin.is_some() {
                None
            } else {
                use_of(s, &g.tag, &m)
            };
            if use_.is_none() && !(sticky && picked) {
                continue;
            }
            let Some(copy) = member_copy(&g.tag, member, use_.as_ref(), sticky && picked, &by_tag)
            else {
                continue;
            };
            if picked {
                g.pick = Some(copy.tag.clone());
            }
            g.members[k] = copy.tag.clone();
            by_tag.insert(copy.tag.clone(), copy.clone());
            copies.push(copy);
        }
        by_tag.insert(g.tag.clone(), g.clone());
    }
    groups.extend(copies);
    // A copy another one replaced is used by nobody.
    let used: HashSet<String> = groups
        .iter()
        .flat_map(GroupSpec::choices)
        .cloned()
        .collect();
    groups.retain(|g| g.origin.is_none() || used.contains(&g.tag));
    groups
}

/// The groups' indexes, each group after the groups among its members
/// (in list order otherwise; a loop is entered once, where first met).
fn members_first(groups: &[GroupSpec]) -> Vec<usize> {
    fn visit(
        i: usize,
        groups: &[GroupSpec],
        index: &HashMap<&str, usize>,
        seen: &mut [bool],
        out: &mut Vec<usize>,
    ) {
        if seen[i] {
            return;
        }
        seen[i] = true;
        for m in groups[i].choices() {
            if let Some(&j) = index.get(m.as_str()) {
                visit(j, groups, index, seen, out);
            }
        }
        out.push(i);
    }
    let index: HashMap<&str, usize> = groups
        .iter()
        .enumerate()
        .map(|(i, g)| (g.tag.as_str(), i))
        .collect();
    let mut seen = vec![false; groups.len()];
    let mut out = Vec::with_capacity(groups.len());
    for i in 0..groups.len() {
        visit(i, groups, &index, &mut seen, &mut out);
    }
    out
}

/// The automatic modes a shared group offers, by its children: 智能选择
/// (`~auto`, ♻️ 自动选择's `~smart`), 负载均衡, 速度最快.
fn mode_child<'a>(
    group: &GroupSpec,
    use_: &MemberUse,
    by_tag: &'a HashMap<String, GroupSpec>,
) -> Option<(&'static str, &'a GroupSpec)> {
    let (suffix, tags): (&str, &[&str]) = match use_ {
        MemberUse::Smart => (group_child::AUTO, &["~auto", "~smart"]),
        MemberUse::Balance => (group_child::BALANCE, &["~balance"]),
        MemberUse::Fastest => (group_child::FASTEST, &["~fastest"]),
        MemberUse::Line(_) => return None,
    };
    tags.iter()
        .map(|t| format!("{}{t}", group.tag))
        .find(|t| group.modes.contains(t))
        .and_then(|t| by_tag.get(&t))
        .map(|c| (suffix, c))
}

fn is_auto_kind(k: GroupKind) -> bool {
    matches!(
        k,
        GroupKind::Smart | GroupKind::Balance | GroupKind::Fastest
    )
}

/// Group `user`'s copy of its member `member`, when it needs one:
///
/// - a shared group (a select over automatic children or lines, not a
///   policy, not 🚀 节点选择) `user` uses in a mode of its own (`use_`):
///   that child's kind over its lines (`@<group>~fastest` …), or a
///   selector over the group's members (as it has them, its own copies
///   included) on the line chosen (`@<group>`); a mode or line the group
///   does not offer now: none (its default);
/// - `sticky` (the policy picks this member and has 固定出口 on) and the
///   member ends on an automatic group — the mode chosen, an automatic
///   group itself, or where the selectors' picks lead from the member
///   ([`automatic_in_use`]: 🚀 节点选择 → ♻️ 自动选择 → its 智能选择, a
///   region → its 速度最快 …): meow's sticky smart group over that
///   group's lines (`<policy>@<member>~sticky`). The core keeps one line
///   for all of the policy's sites and moves it only when it fails or
///   slows; it has no sticky 速度最快 / 负载均衡 (one `strategy`), so the
///   automatic group gives the lines, the smart group chooses among them.
///   Ending on one line, DIRECT or REJECT: no copy (nothing to keep).
fn member_copy(
    user: &str,
    member: &GroupSpec,
    use_: Option<&MemberUse>,
    sticky: bool,
    by_tag: &HashMap<String, GroupSpec>,
) -> Option<GroupSpec> {
    // A copy of `user`'s own copy stands for the same member.
    let origin = member.origin.as_deref().unwrap_or(&member.tag);
    let base = format!("{user}{COPY_MARK}{origin}");
    let copy = |suffix: &str, kind: GroupKind, members: &[String], name: &str| {
        let mut c = GroupSpec::new(
            &format!("{base}{suffix}"),
            &format!("{} · {name}", member.label),
            kind,
            members.to_vec(),
        );
        c.card = false;
        c.origin = Some(origin.to_owned());
        c
    };
    let sticky_name = child_name(group_child::STICKY);
    if is_auto_kind(member.kind) {
        if !sticky {
            return None;
        }
        let mut c = copy(
            group_child::STICKY,
            GroupKind::Sticky,
            &member.members,
            sticky_name,
        );
        c.short = member
            .short
            .as_ref()
            .map(|n| format!("{n} · {sticky_name}"));
        return Some(c);
    }
    if member.kind != GroupKind::Select {
        return None;
    }
    // Modes and lines of its own only in a shared group; 固定出口 anywhere.
    let shared = !is_policy_tag(&member.tag)
        && member.tag != outbound_tags::PROXY
        && member.origin.is_none();
    let short = |c: &GroupSpec| c.short.clone().unwrap_or_else(|| c.label.clone());
    let chosen = use_.filter(|_| shared).and_then(|u| match u {
        MemberUse::Line(l) => member
            .members
            .iter()
            .any(|m| m == l && !by_tag.contains_key(m) && m != "DIRECT" && m != "REJECT")
            .then_some(Err(l)),
        mode => mode_child(member, mode, by_tag).map(Ok),
    });
    if sticky {
        // The automatic group in force: the mode chosen, else where the
        // member's own pick leads.
        let path = match chosen {
            Some(Ok((_, c))) => Some(vec![member, c]),
            Some(Err(_)) => None,
            None => automatic_in_use(member, by_tag),
        };
        if let Some(path) = path {
            // Named by the way down: a child by its short name, any other
            // group by its own ("🚀 节点选择 · ♻️ 自动选择 · 智能选择").
            let mut name: Vec<String> = path
                .windows(2)
                .map(|w| {
                    if group_child::parent_of(&w[1].tag) == w[0].tag {
                        short(w[1])
                    } else {
                        w[1].label.clone()
                    }
                })
                .collect();
            name.push(sticky_name.to_owned());
            let lines = &path[path.len() - 1].members;
            return Some(copy(
                group_child::STICKY,
                GroupKind::Sticky,
                lines,
                &name.join(" · "),
            ));
        }
    }
    match chosen? {
        Ok((suffix, c)) => Some(copy(suffix, c.kind, &c.members, &short(c))),
        Err(line) => {
            let mut c = copy("", GroupKind::Select, &member.members, line);
            c.modes = member.modes.clone();
            c.pick = Some(line.clone());
            Some(c)
        }
    }
}

/// Where `member`'s traffic ends, following the selectors' picks down from
/// it: the groups on the way, `member` first, to the automatic one it ends
/// on (智能选择, 负载均衡, 速度最快); None when it ends on one line, DIRECT
/// or REJECT, or goes round. Dart `ProxyController.usesAutomatic` follows
/// the same way.
fn automatic_in_use<'a>(
    member: &'a GroupSpec,
    by_tag: &'a HashMap<String, GroupSpec>,
) -> Option<Vec<&'a GroupSpec>> {
    let mut path = vec![member];
    let mut g = member;
    while !is_auto_kind(g.kind) {
        if g.kind != GroupKind::Select {
            return None;
        }
        let next = by_tag.get(g.pick.as_deref()?)?;
        if path.iter().any(|p| p.tag == next.tag) {
            return None;
        }
        path.push(next);
        g = next;
    }
    Some(path)
}

/// Our outbound names as the core's: `direct` → DIRECT, `block` → REJECT.
fn clash_name(tag: &str) -> &str {
    match tag {
        outbound_tags::DIRECT => "DIRECT",
        outbound_tags::BLOCK => "REJECT",
        _ => tag,
    }
}

/// A built-in group's pick: the user's own (proxies page, `policies`) >
/// its 分组默认 > `built_in`; each only when the group offers it.
fn policy_pick(p: &Policy, s: &ProxySettings, members: &[String], built_in: &str) -> String {
    let tag = p.tag();
    if let Some(t) = s
        .policies
        .get(&tag)
        .and_then(|manual| offered(&tag, members, clash_name(manual)))
    {
        return t;
    }
    if let Some(d) = s
        .group_defaults
        .get(&tag)
        .and_then(|d| d.member_in(p, members))
    {
        return d;
    }
    offered(&tag, members, clash_name(built_in))
        .or_else(|| members.first().cloned())
        .unwrap_or_default()
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
                .find_map(|c| offered(&g.tag, &members, &c));
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
        for m in g.choices() {
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
            g.modes.retain(|m| !drop.contains(m));
            let mut kept: Vec<String> = g
                .members
                .iter()
                .filter(|m| !drop.contains(*m))
                .cloned()
                .collect();
            if kept.is_empty() && g.modes.is_empty() {
                kept.push("DIRECT".into());
            }
            g.members = kept;
            if g.pick.as_ref().is_some_and(|p| drop.contains(p)) {
                let first = g.choices().next().cloned();
                g.pick = first;
            }
            g
        })
        .collect();
    GroupTree::new(groups, loops)
}
