//! Merging the subscriptions' own splits into one (Dart:
//! `mergeSubscriptionSplits` and friends in `sub_rules.dart`).

use std::collections::HashMap;

use indexmap::IndexMap;

use crate::dart::{to_lower_case, trim};
use crate::model::subscription::{SubGroup, SubRules};

/// One subscription's split, ready to merge: its rules, and how its node
/// names map onto the pooled lines' tags (a node another account already
/// serves maps to that line; info rows map to nothing).
#[derive(Debug, Clone, Copy)]
pub struct SubSplit<'a> {
    /// The provider's groups and rules.
    pub rules: &'a SubRules,
    /// Node name → line tag in the pool.
    pub line_of: &'a IndexMap<String, String>,
}

/// A provider group as it lands in the config.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImportedGroup {
    /// `sub:<name>` (never clashes with lines or our own groups); the
    /// provider's own 节点选择 is our `proxy` when following the
    /// subscription exactly.
    pub tag: String,
    /// The provider's name ("🎥 NETFLIX").
    pub name: String,
    /// Config names: lines, our groups / policies, DIRECT, REJECT, other
    /// imported groups.
    pub members: Vec<String>,
    /// The provider's type, lower-cased (select, url-test, fallback,
    /// load-balance …); `select` unless following the subscription
    /// exactly.
    pub kind: String,
}

impl ImportedGroup {
    /// A `select` group.
    pub fn new(tag: &str, name: &str, members: &[&str]) -> Self {
        Self {
            tag: tag.to_owned(),
            name: name.to_owned(),
            members: members.iter().map(|m| (*m).to_owned()).collect(),
            kind: "select".to_owned(),
        }
    }
}

/// What the subscriptions' splits add to a Clash config.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ImportedSplit {
    /// Groups in the order they were first made.
    pub groups: Vec<ImportedGroup>,
    /// Rewritten to our names, de-duplicated (the first subscription that
    /// matches something decides), MATCH and RULE-SET left out.
    pub rules: Vec<String>,
    /// Exactly as written: where MATCH sends the rest.
    pub final_target: Option<String>,
}

/// Where provider groups that mean one of ours go.
#[derive(Debug, Clone, Copy)]
pub struct MergeTargets<'a> {
    /// The provider's own 节点选择 (our `proxy`).
    pub select: &'a str,
    /// url-test / fallback / load-balance groups (our `auto`).
    pub auto: &'a str,
    /// The MATCH target (our 漏网之鱼).
    pub fallback: &'a str,
}

const DIRECT: &str = "DIRECT";
const REJECT: &str = "REJECT";

/// Our group for a provider group that means the same, by its name.
pub type BuiltInOf<'a> = &'a dyn Fn(&str) -> Option<String>;

/// Merges the subscriptions' splits, highest priority first.
///
/// Provider groups are mapped onto ours where they mean the same thing:
/// the first select over most of the lines → `select`, the MATCH target →
/// `fallback`, one [`BuiltInOf`] names → ours, one starting with DIRECT →
/// DIRECT, with REJECT → REJECT, any other non-select (url-test …) →
/// `auto`. The rest come in as selectors of their own (`sub:<name>`). A
/// group name two subscriptions share becomes one group with both one's
/// members; a rule matcher two share is the higher one's, and when both
/// send it to groups of their own those merge too.
///
/// `raw`: exactly as written — every group kept with its type (the
/// provider's own 节点选择 as `select`), MATCH's target as
/// [`ImportedSplit::final_target`].
pub fn merge_subscription_splits(
    splits: &[SubSplit<'_>],
    targets: MergeTargets<'_>,
    built_in_of: Option<BuiltInOf<'_>>,
    raw: bool,
) -> ImportedSplit {
    let mut groups: IndexMap<String, ImportedGroup> = IndexMap::new();
    let mut final_target: Option<String> = None;
    let mut rules = Vec::new();
    // Matcher → where the first subscription sent it.
    let mut seen_matchers: HashMap<String, String> = HashMap::new();

    for split in splits {
        let match_target = split
            .rules
            .rules
            .iter()
            .filter_map(|l| parse_rule(l))
            .find(|r| r.kind == "MATCH")
            .map(|r| r.target);
        // The provider's own "节点选择": by convention the first select
        // group that lists most of the lines.
        let primary = split
            .rules
            .groups
            .iter()
            .find(|g| {
                to_lower_case(&g.kind) == "select"
                    && !split.line_of.is_empty()
                    && g.members
                        .iter()
                        .filter(|m| split.line_of.contains_key(*m))
                        .count()
                        * 2
                        >= split.line_of.len()
            })
            .map(|g| g.name.clone());
        let mut m = Merger {
            // A repeated name: the last one counts (Dart map literal).
            by_name: split
                .rules
                .groups
                .iter()
                .map(|g| (g.name.as_str(), g))
                .collect(),
            line_of: split.line_of,
            match_target,
            primary,
            resolved: HashMap::new(),
            groups: &mut groups,
            targets,
            built_in_of,
            raw,
        };
        if raw && final_target.is_none() {
            if let Some(t) = m.match_target.clone() {
                final_target = m.resolve(&t, &mut Vec::new());
            }
        }
        for line in &split.rules.rules {
            let Some(r) = parse_rule(line) else { continue };
            if r.kind == "MATCH" || r.kind == "RULE-SET" {
                continue;
            }
            let Some(target) = m.resolve(&r.target, &mut Vec::new()) else {
                continue;
            };
            let matcher = format!("{},{}", r.kind, r.value);
            if let Some(first) = seen_matchers.get(&matcher) {
                // Claimed by a higher-priority subscription: its rule
                // stays; two groups of their own for one thing become one.
                if *first != target && first.starts_with("sub:") && target.starts_with("sub:") {
                    let members = m
                        .groups
                        .get(&target)
                        .map(|g| g.members.clone())
                        .unwrap_or_default();
                    merge_into(m.groups, first, &members);
                }
                continue;
            }
            seen_matchers.insert(matcher, target.clone());
            let mut parts = vec![r.kind];
            if !r.value.is_empty() {
                parts.push(r.value);
            }
            parts.push(target);
            parts.extend(r.options);
            rules.push(parts.join(","));
        }
    }
    ImportedSplit {
        groups: groups.into_values().collect(),
        rules,
        final_target,
    }
}

/// Adds `members` to group `tag` (if there), each once, never itself.
fn merge_into(groups: &mut IndexMap<String, ImportedGroup>, tag: &str, members: &[String]) {
    let Some(g) = groups.get_mut(tag) else { return };
    for m in members {
        if m != tag && !g.members.contains(m) {
            g.members.push(m.clone());
        }
    }
}

/// One subscription's merge state (Dart: `resolve`'s closure).
struct Merger<'a, 'g> {
    by_name: HashMap<&'a str, &'a SubGroup>,
    line_of: &'a IndexMap<String, String>,
    match_target: Option<String>,
    primary: Option<String>,
    /// Provider name → our name (None: leads nowhere).
    resolved: HashMap<String, Option<String>>,
    groups: &'g mut IndexMap<String, ImportedGroup>,
    targets: MergeTargets<'a>,
    built_in_of: Option<BuiltInOf<'a>>,
    raw: bool,
}

impl Merger<'_, '_> {
    /// What the provider's `name` (a line, group or built-in) is in the
    /// config; None when it leads nowhere (unknown, or a loop on `path`).
    fn resolve(&mut self, name: &str, path: &mut Vec<String>) -> Option<String> {
        if matches!(name, "DIRECT" | "COMPATIBLE" | "PASS") {
            return Some(DIRECT.into());
        }
        if matches!(name, "REJECT" | "REJECT-DROP") {
            return Some(REJECT.into());
        }
        if let Some(r) = self.resolved.get(name) {
            return r.clone();
        }
        if let Some(line) = self.line_of.get(name) {
            return Some(line.clone());
        }
        let g = *self.by_name.get(name)?;
        if path.iter().any(|p| p == name) {
            return None;
        }
        path.push(name.to_owned());
        let kind = to_lower_case(&g.kind);
        let sub_tag = format!("sub:{name}");
        let out = if self.groups.contains_key(&sub_tag) {
            // Same name in a higher-priority subscription: one group, both
            // members.
            self.resolved.insert(name.to_owned(), Some(sub_tag.clone()));
            let members: Vec<String> = g
                .members
                .iter()
                .filter_map(|m| self.resolve(m, path))
                .collect();
            merge_into(self.groups, &sub_tag, &members);
            Some(sub_tag)
        } else if self.raw {
            // As written: every group itself, its own type.
            let tag = if self.primary.as_deref() == Some(name) {
                self.targets.select.to_owned()
            } else {
                sub_tag
            };
            // Another subscription's own 节点选择 is already there: one
            // group with both's members (B24: Dart replaced the first's).
            self.groups
                .entry(tag.clone())
                .or_insert_with(|| ImportedGroup {
                    tag: tag.clone(),
                    name: name.to_owned(),
                    members: Vec::new(),
                    kind,
                });
            self.resolved.insert(name.to_owned(), Some(tag.clone()));
            for m in &g.members {
                if let Some(r) = self.resolve(m, path) {
                    if let Some(g0) = self.groups.get_mut(&tag) {
                        if !g0.members.contains(&r) {
                            g0.members.push(r);
                        }
                    }
                }
            }
            if let Some(g0) = self.groups.get_mut(&tag) {
                if g0.members.is_empty() {
                    g0.members.push(DIRECT.into());
                }
            }
            Some(tag)
        } else if self.primary.as_deref() == Some(name) {
            Some(self.targets.select.to_owned())
        } else if self.match_target.as_deref() == Some(name) {
            Some(self.targets.fallback.to_owned())
        } else if let Some(ours) = self.built_in_of.and_then(|f| f(name)) {
            // Ours means the same: its rules supplement ours.
            Some(ours)
        } else if g.members.first().is_some_and(|m| m == DIRECT) {
            Some(DIRECT.into())
        } else if g
            .members
            .first()
            .is_some_and(|m| m == REJECT || m == "REJECT-DROP")
        {
            Some(REJECT.into())
        } else if kind != "select" && kind != "relay" {
            Some(self.targets.auto.to_owned())
        } else {
            let mut members: Vec<String> = Vec::new();
            for m in &g.members {
                if let Some(r) = self.resolve(m, path) {
                    if !members.contains(&r) {
                        members.push(r);
                    }
                }
            }
            if members.is_empty() {
                Some(self.targets.select.to_owned())
            } else {
                self.groups.insert(
                    sub_tag.clone(),
                    ImportedGroup {
                        tag: sub_tag.clone(),
                        name: name.to_owned(),
                        members,
                        kind: "select".into(),
                    },
                );
                Some(sub_tag)
            }
        };
        path.retain(|p| p != name);
        self.resolved.insert(name.to_owned(), out.clone());
        out
    }
}

/// A Clash rule line taken apart.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedRule {
    /// Upper-cased type; `FINAL` reads as `MATCH`.
    pub kind: String,
    /// Everything between the type and the target (logic rules keep their
    /// parenthesised value whole); empty for MATCH.
    pub value: String,
    pub target: String,
    /// Trailing `no-resolve` / `src`, as written.
    pub options: Vec<String>,
}

/// `TYPE,value,target[,options]`; None for blanks, comments and lines
/// without a target.
pub fn parse_rule(line: &str) -> Option<ParsedRule> {
    let s = trim(line);
    if s.is_empty() || s.starts_with('#') {
        return None;
    }
    let comma = s.find(',')?;
    let kind = trim(&s[..comma]).to_uppercase();
    let mut rest: Vec<String> = s[comma + 1..]
        .split(',')
        .map(|x| trim(x).to_owned())
        .collect();
    let mut options = Vec::new();
    while rest.len() > 1
        && rest
            .last()
            .is_some_and(|l| matches!(to_lower_case(l).as_str(), "no-resolve" | "src"))
    {
        options.insert(0, rest.pop().unwrap_or_default());
    }
    if kind == "MATCH" || kind == "FINAL" {
        return Some(ParsedRule {
            kind: "MATCH".into(),
            value: String::new(),
            target: rest.swap_remove(0),
            options: Vec::new(),
        });
    }
    if rest.len() < 2 {
        return None;
    }
    let target = rest.pop().unwrap_or_default();
    Some(ParsedRule {
        kind,
        value: rest.join(","),
        target,
        options,
    })
}
