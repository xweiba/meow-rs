//! What a built-in group's 分组默认 means (Dart: `group_defaults.dart`):
//! which of its members it picks, whether it may have it, how it is named.
//! The data type itself is [`GroupDefault`] in the settings model.

use crate::model::settings::{GroupDefault, GroupDefaultKind};
use crate::plan::group_tree::group_child;
use crate::plan::outbound_tags;
use crate::plan::policies::Policy;
use crate::pool::{region_for_code, Region};

/// The non-region choices, in the order the picker lists them.
pub const GROUP_DEFAULT_MODES: [GroupDefaultKind; 6] = [
    GroupDefaultKind::Fastest,
    GroupDefaultKind::Auto,
    GroupDefaultKind::Balance,
    GroupDefaultKind::Select,
    GroupDefaultKind::Direct,
    GroupDefaultKind::Block,
];

impl GroupDefault {
    /// A non-region default.
    pub fn of(kind: GroupDefaultKind) -> Self {
        Self { kind, region: None }
    }

    /// The lines of region `code` (`US`, `JP` …).
    pub fn region(code: &str) -> Self {
        Self {
            kind: GroupDefaultKind::Region,
            region: Some(code.to_owned()),
        }
    }

    /// Whether `p`'s group may have it at all (lines or not): 广告拦截 only
    /// 拦截 / 直连; never a region the service refuses.
    pub fn allowed_for(&self, p: &Policy) -> bool {
        if p.blockable {
            return matches!(
                self.kind,
                GroupDefaultKind::Direct | GroupDefaultKind::Block
            );
        }
        self.region
            .as_deref()
            .is_none_or(|r| !p.avoid_regions.contains(&r))
    }

    /// The member of `p`'s group this means, among `members`; None when
    /// the group does not offer it now (no lines there, too few to race …).
    pub fn member_in(&self, p: &Policy, members: &[String]) -> Option<String> {
        if !self.allowed_for(p) {
            return None;
        }
        let has = |t: &str| members.iter().any(|m| m == t);
        let own = |suffix: &str| format!("{}{suffix}", p.tag());
        let either = |shared: &str, suffix: &str| {
            if has(shared) {
                Some(shared.to_owned())
            } else {
                Some(own(suffix)).filter(|t| has(t))
            }
        };
        let t = match self.kind {
            GroupDefaultKind::Region => {
                let region = format!("region:{}", self.region.as_deref().unwrap_or_default());
                let sticky = own(group_child::STICKY);
                if !has(&region) {
                    None
                } else if p.sticky_exit && has(&sticky) {
                    Some(sticky)
                } else {
                    Some(region)
                }
            }
            GroupDefaultKind::Fastest => either(outbound_tags::FASTEST, group_child::FASTEST),
            GroupDefaultKind::Auto => either(outbound_tags::AUTO, group_child::AUTO),
            GroupDefaultKind::Balance => either(outbound_tags::BALANCE, group_child::BALANCE),
            GroupDefaultKind::Select => Some(outbound_tags::PROXY.to_owned()),
            GroupDefaultKind::Direct => Some("DIRECT".to_owned()),
            GroupDefaultKind::Block => Some("REJECT".to_owned()),
        };
        t.filter(|t| has(t))
    }

    /// As the screen names it for `p` ("固定出口 · 美国", "🇯🇵 日本",
    /// "速度最快").
    pub fn name_for(&self, p: &Policy) -> String {
        match self.kind {
            GroupDefaultKind::Region => {
                let code = self.region.as_deref().unwrap_or_default();
                let r = region_for_code(Some(code));
                let name = r.as_ref().map_or(code, |r| &r.name);
                if p.sticky_exit {
                    format!("固定出口 · {name}")
                } else {
                    r.as_ref().map_or_else(|| name.to_owned(), Region::label)
                }
            }
            GroupDefaultKind::Fastest => "速度最快".into(),
            GroupDefaultKind::Auto => "自动选择".into(),
            GroupDefaultKind::Balance => "负载均衡".into(),
            GroupDefaultKind::Select => "节点选择".into(),
            GroupDefaultKind::Direct => "直连".into(),
            GroupDefaultKind::Block => "拦截".into(),
        }
    }
}

/// `^region:[A-Z]{2}$`.
fn is_region_code_tag(m: &str) -> bool {
    m.strip_prefix("region:")
        .is_some_and(|c| c.len() == 2 && c.bytes().all(|b| b.is_ascii_uppercase()))
}

/// What `p`'s group (offering `members`) can default to: regions with
/// lines first, in `members`' order, then the rest it offers in
/// [`GROUP_DEFAULT_MODES`] order.
pub fn group_default_choices_in(p: &Policy, members: &[String]) -> Vec<GroupDefault> {
    let regions = members
        .iter()
        .filter(|m| is_region_code_tag(m))
        .map(|m| GroupDefault::region(&m[7..]));
    let modes = GROUP_DEFAULT_MODES.iter().map(|k| GroupDefault::of(*k));
    regions
        .chain(modes)
        .filter(|d| d.member_in(p, members).is_some())
        .collect()
}
