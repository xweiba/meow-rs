//! The logic over the user's own policies and edits to the built-in ones
//! (Dart: `custom_groups.dart`); the data types are in the settings model.
//!
//! Not ported: `CustomGroup.newId` (random; ids are made by the app).

use crate::dart::{internet_address_try_parse, is_regex_space, trim};
use crate::model::settings::{CustomGroup, GroupEdit, RuleMatch, CUSTOM_GROUP_PREFIX};
use crate::plan::policies::policy_by_tag;

impl CustomGroup {
    /// Whether `tag` is a user group's (`group:<id>`).
    pub fn is_custom(tag: &str) -> bool {
        tag.starts_with(CUSTOM_GROUP_PREFIX)
    }
}

impl GroupEdit {
    /// Whether the group tagged `tag` takes edits (Dart
    /// `ProxyController.canEdit`): a user's own group, or a built-in
    /// service group (not the basic split, not 广告拦截). Edits saved for
    /// any other group (a region …) are ignored (B25).
    pub fn editable(tag: &str) -> bool {
        CustomGroup::is_custom(tag) || policy_by_tag(tag).is_some_and(|p| !p.base && !p.blockable)
    }

    /// `members` with the extra outlets after them, each once (B25: Dart
    /// repeated an outlet listed twice).
    pub fn apply(&self, members: &[String]) -> Vec<String> {
        let mut out = members.to_vec();
        for m in &self.extras {
            if !out.contains(m) {
                out.push(m.clone());
            }
        }
        out
    }
}

/// One entry of [`GroupEdit::exclude`]: a domain with its subdomains, or a
/// single address, as is; the other matches prefixed: `exact:host`,
/// `keyword:word`, `ip:range`, `process:name`.
pub fn exclude_entry(m: RuleMatch, value: &str) -> String {
    match m {
        RuleMatch::Domain => value.to_owned(),
        RuleMatch::Ip if !value.contains('/') => value.to_owned(),
        _ => format!("{}:{value}", m.name()),
    }
}

/// The match and value of an [`exclude_entry`]: a prefixed entry by its
/// prefix, else an address ([`RuleMatch::Ip`]) or a domain.
pub fn exclude_match(entry: &str) -> (RuleMatch, String) {
    for m in [
        RuleMatch::Exact,
        RuleMatch::Keyword,
        RuleMatch::Ip,
        RuleMatch::Process,
    ] {
        if let Some(v) = entry
            .strip_prefix(m.name())
            .and_then(|r| r.strip_prefix(':'))
        {
            return (m, v.to_owned());
        }
    }
    let m = if internet_address_try_parse(entry).is_some() {
        RuleMatch::Ip
    } else {
        RuleMatch::Domain
    };
    (m, entry.to_owned())
}

/// Sites typed in one go: split on whitespace, commas (also Chinese ones),
/// `、` and semicolons; trimmed, empty and repeated ones dropped.
pub fn split_sites(text: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for s in text.split(|c: char| is_regex_space(c) || ",，、;；".contains(c)) {
        let s = trim(s);
        if !s.is_empty() && !out.iter().any(|x| x == s) {
            out.push(s.to_owned());
        }
    }
    out
}
