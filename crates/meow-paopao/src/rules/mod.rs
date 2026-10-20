//! L4: the config pieces that need no group tree (Dart: `hosts.dart`,
//! `ssh.dart`, `moduleConfig` in `script_module.dart`, and the helpers of
//! `clash_config.dart`): SSH chains as proxies, hosts entries, what the rewrite modules add, and
//! rule lines built from the user's rules, and whether a rule line takes a
//! connection ([`matcher`]).
//!
//! Everything here returns the meow (Clash) shapes key for key; L5
//! assembles them into the config.

mod hosts;
pub mod matcher;
mod modules;
mod ssh;

pub use hosts::paopao_hosts;
pub use modules::{
    host_condition, module_config, module_script_path, ModuleConfig, ModuleRewrite, ModuleScript,
    ModuleSpec, ScriptModule, BUILTIN_SCRIPT_PATH, MITM_PROXY_NAME, MITM_RETURN_IN,
    MITM_RETURN_PROXY, MODULE_NOTIFICATIONS_PATH, MODULE_STORE_PATH,
};
pub use ssh::{ssh_proxies, SshProxy, SshSecrets};

use crate::model::settings::{AppMatcher, CustomRule, RuleMatch, RuleTarget};
use crate::plan::custom_groups::exclude_match;

/// Distribution private-range rules. Runtime emission reads the selected
/// profile directly; this helper preserves the public defaults API.
pub fn private_cidr_rules() -> Vec<String> {
    crate::rule_profile::RuleProfile::shipped()
        .private_rules
        .clone()
}

/// Distribution local-name rule-set label, for legacy helper callers.
pub const PRIVATE_RULE_SET: &str = "geosite-private";

/// `IP-CIDR6` for an address or range with a `:`, else `IP-CIDR`.
fn ip_cidr_type(v: &str) -> &'static str {
    if v.contains(':') {
        "IP-CIDR6"
    } else {
        "IP-CIDR"
    }
}

/// The direct outbound leaving by interface `name`: `iface:<name>`.
pub fn iface_tag(name: &str) -> String {
    format!("iface:{name}")
}

/// Where a user rule sends its sites, as the core names it (Dart:
/// `ruleTargetTag`); whether that outbound exists is the config's business.
pub fn rule_target_tag(t: &RuleTarget) -> String {
    match t {
        RuleTarget::Direct => "DIRECT".into(),
        RuleTarget::Block => "REJECT".into(),
        RuleTarget::Device(id) => format!("device:{id}"),
        RuleTarget::Line(tag) => tag.clone(),
        RuleTarget::Iface(name) => iface_tag(name),
        RuleTarget::Proxy => "proxy".into(),
        // Never a rule line (the builder leaves the rule out).
        RuleTarget::Unknown(raw) => raw.clone(),
    }
}

/// A user rule as a rule line sending its sites to `target` (Dart:
/// `customRule` in `buildClashConfig`, after the target is resolved). A
/// single address gets `/32` or `/128`; an app becomes its
/// [`AppMatcher::condition`]. None for an app this version can't read: it
/// makes no rule.
pub fn custom_rule_line(r: &CustomRule, target: &str) -> Option<String> {
    let v = &r.value;
    Some(match r.matches {
        RuleMatch::Domain => format!("DOMAIN-SUFFIX,{v},{target}"),
        RuleMatch::Exact => format!("DOMAIN,{v},{target}"),
        RuleMatch::Keyword => format!("DOMAIN-KEYWORD,{v},{target}"),
        RuleMatch::Ip => {
            let cidr = if v.contains('/') {
                v.clone()
            } else {
                format!("{v}/{}", if v.contains(':') { 128 } else { 32 })
            };
            format!("{},{cidr},{target},no-resolve", ip_cidr_type(v))
        }
        RuleMatch::Process => format!("PROCESS-NAME,{v},{target}"),
        RuleMatch::App => format!("{},{target}", AppMatcher::parse(v)?.condition()),
    })
}

/// A rule set (`geoip-cn`, `geosite-google`) as a rule to `target`:
/// `GEOIP,cn,…` for `geoip-…`, else `GEOSITE,…` (Dart: `clashRule`).
///
/// Dart parity: anything not starting with `geoip-` loses its first eight
/// characters, as if it started with `geosite-`.
pub fn geo_rule(rule_set: &str, target: &str) -> String {
    match rule_set.strip_prefix("geoip-") {
        Some(code) => format!("GEOIP,{code},{target}"),
        None => format!("GEOSITE,{},{target}", rule_set.get(8..).unwrap_or_default()),
    }
}

/// Where a rule line sends traffic: its last part that is not an option
/// (`no-resolve`, `src`); empty when there is none (Dart: `ruleTarget` in
/// `buildClashConfig`).
pub fn rule_target(rule: &str) -> &str {
    rule.rsplit(',')
        .map(str::trim)
        .find(|x| !x.eq_ignore_ascii_case("no-resolve") && !x.eq_ignore_ascii_case("src"))
        .unwrap_or_default()
}

/// What a rule line matches, without its target: its first two parts
/// (Dart: `matcher`). The user's matchers drop the subscriptions' same
/// ones.
pub fn rule_matcher(rule: &str) -> String {
    rule.split(',').take(2).collect::<Vec<_>>().join(",")
}

/// `rule` (`TYPE,payload,target[,no-resolve]`, or `AND,(…),target`)
/// matching everything it did except `sites` (a business policy's
/// exclusions: domains with their subdomains, `exact:` hosts, `keyword:`
/// words, addresses or `ip:` ranges, `process:` programs, `app:` apps):
/// those skip it and the rules after decide (Dart: `withoutSites`). An app
/// this version can't read is ignored; with nothing left, `rule` as is.
pub fn without_sites(rule: &str, sites: &[String]) -> String {
    let not: Vec<String> = sites
        .iter()
        .filter_map(|s| {
            let (m, v) = exclude_match(s);
            Some(match m {
                RuleMatch::Domain => format!("(DOMAIN-SUFFIX,{v})"),
                RuleMatch::Exact => format!("(DOMAIN,{v})"),
                RuleMatch::Keyword => format!("(DOMAIN-KEYWORD,{v})"),
                RuleMatch::Process => format!("(PROCESS-NAME,{v})"),
                RuleMatch::Ip => {
                    let v6 = v.contains(':');
                    let cidr = if v.contains('/') {
                        v.clone()
                    } else {
                        format!("{v}/{}", if v6 { 128 } else { 32 })
                    };
                    format!("({},{cidr},no-resolve)", ip_cidr_type(&v))
                }
                // Brackets in a name would end the `NOT` early.
                RuleMatch::App if v.contains(['(', ')']) => return None,
                RuleMatch::App => format!("({})", AppMatcher::parse(&v)?.condition()),
            })
        })
        .collect();
    let skip = match not.as_slice() {
        [] => return rule.to_owned(),
        [one] => format!("(NOT,({one}))"),
        _ => format!("(NOT,((OR,({}))))", not.join(",")),
    };
    if rule.starts_with("AND,(") {
        // `AND,((a),(b)),target`: one more condition inside.
        if let Some(cut) = rule.rfind("),") {
            return format!("{},{skip}){}", &rule[..cut], &rule[cut + 1..]);
        }
    }
    let Some(parsed) = crate::plan::sub_rules::parse_rule(rule) else {
        return rule.to_owned();
    };
    let mut condition = format!("{},{}", parsed.kind, parsed.value);
    // Flags belong to the inner predicate when wrapping a rule with
    // exclusions, including source-IP matching and the original flag case.
    for option in parsed.options {
        condition.push(',');
        condition.push_str(&option);
    }
    format!("AND,(({condition}),{skip}),{}", parsed.target)
}

#[cfg(test)]
mod tests;
