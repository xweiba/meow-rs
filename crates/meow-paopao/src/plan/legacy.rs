//! Saved names that point at a group the lines of the moment do not make
//! any more, read as the group that holds it now. Only for the build: the
//! settings keep the name, so it comes back when the lines do (a region
//! with one line is in 🌐 其他地区 until it has two again).
//!
//! The renames that never come back are rewritten once, on load
//! ([`crate::model::migrate`]).

use crate::model::settings::ProxySettings;
use crate::plan::group_tree::{has_own_group, OTHER_REGION_TAG};
use crate::pool::Pool;

/// The pool's regions without a group of their own (their lines are in
/// 其他地区).
fn merged(pool: &Pool) -> Vec<String> {
    pool.groups
        .iter()
        .filter(|g| g.tag.starts_with("region:") && g.tag != OTHER_REGION_TAG && !has_own_group(g))
        .map(|g| g.tag.clone())
        .collect()
}

/// `tag` (`region:XX` or one of its modes `region:XX~fastest`) as
/// 其他地区 when XX is in it now.
fn regional(tag: &str, merged: &[String]) -> Option<String> {
    merged.iter().find_map(|m| {
        let rest = tag.strip_prefix(m.as_str())?;
        (rest.is_empty() || rest.starts_with('~')).then(|| format!("{OTHER_REGION_TAG}{rest}"))
    })
}

/// `tag` as 其他地区 when it names a region of `pool` now in it.
pub fn moved_region(tag: &str, pool: &Pool) -> Option<String> {
    regional(tag, &merged(pool))
}

/// The settings with every pick and use naming a region now in
/// 其他地区 naming 其他地区 instead (a pick or use already saved for
/// 其他地区 wins).
pub fn for_lines(mut s: ProxySettings, pool: &Pool) -> ProxySettings {
    let merged = merged(pool);
    if merged.is_empty() {
        return s;
    }
    let map = |v: &mut String| {
        if let Some(n) = regional(v, &merged) {
            *v = n;
        }
    };
    map(&mut s.selected);
    s.policies.values_mut().for_each(map);
    s.group_picks.values_mut().for_each(map);
    for g in &mut s.custom_groups {
        if let Some(p) = &mut g.pick {
            map(p);
        }
    }
    // Rules: on emit ([`moved_region`]), so the rules page is told.
    // 其他地区's own pick: a merged region's, when it has none.
    for m in &merged {
        if let Some(p) = s.group_picks.get(m).cloned() {
            if !s.group_picks.contains_key(OTHER_REGION_TAG) {
                let p = regional(&p, &merged).unwrap_or(p);
                s.group_picks.insert(OTHER_REGION_TAG.into(), p);
            }
        }
    }
    for u in s.group_use.values_mut() {
        let keys: Vec<String> = u.members.keys().cloned().collect();
        for k in keys {
            if let Some(n) = regional(&k, &merged) {
                if let Some(v) = u.members.shift_remove(&k) {
                    u.members.entry(n).or_insert(v);
                }
            }
        }
    }
    s
}

/// What a rule's saved `line:` target may have been called before, newest
/// first, for one the tree does not have: the group's own copy or 固定节点
/// (`<user>@<member>`, `<group>~sticky`) as what it was made of, a group's
/// old automatic child (`<group>~fastest`) as the group, the top-level
/// 速度最快 (before ♻️ 自动选择's modes) as 自动选择, 🎮 Steam as 游戏平台.
pub fn line_candidates(tag: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let mut push = |t: &str| {
        if !t.is_empty() && t != tag && !out.iter().any(|o| o == t) {
            out.push(t.to_owned());
        }
    };
    let mut t = tag.strip_suffix("~sticky").unwrap_or(tag).to_owned();
    push(&t);
    if let Some((_, origin)) = t.split_once('@') {
        t = origin.to_owned();
        push(&t);
    }
    for mode in ["~auto", "~smart", "~balance", "~fastest"] {
        if let Some(base) = t.strip_suffix(mode) {
            push(base);
        }
    }
    match t.as_str() {
        "fastest" => push(crate::model::outbound_tags::AUTO),
        "policy:steam" => push("policy:games"),
        _ => {}
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn line_candidates_are_what_the_tag_was_made_of() {
        assert_eq!(
            line_candidates("policy:ai@region:US~fastest~sticky"),
            [
                "policy:ai@region:US~fastest",
                "region:US~fastest",
                "region:US"
            ]
        );
        assert_eq!(line_candidates("policy:ai~sticky"), ["policy:ai"]);
        assert_eq!(line_candidates("group:g1~balance"), ["group:g1"]);
        assert_eq!(line_candidates("fastest"), ["auto"]);
        assert_eq!(line_candidates("policy:steam"), ["policy:games"]);
        assert!(line_candidates("HK 1").is_empty());
    }

    #[test]
    fn regional_is_other_for_a_merged_region_and_its_modes() {
        let merged = vec!["region:JP".to_owned()];
        assert_eq!(
            regional("region:JP", &merged).as_deref(),
            Some("region:other")
        );
        assert_eq!(
            regional("region:JP~fastest", &merged).as_deref(),
            Some("region:other~fastest")
        );
        assert_eq!(regional("region:JPX", &merged), None);
        assert_eq!(regional("region:US", &merged), None);
    }
}
