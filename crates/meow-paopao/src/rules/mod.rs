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

use crate::model::settings::{CustomRule, RuleMatch, RuleTarget};
use crate::plan::custom_groups::exclude_match;

/// Private and loopback ranges: they always go direct (the first rules).
pub const PRIVATE_CIDRS: [&str; 9] = [
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "127.0.0.0/8",
    "169.254.0.0/16",
    "100.64.0.0/10",
    "fc00::/7",
    "fe80::/10",
    "::1/128",
];

/// The rule set of local names (`geosite:private`), sent direct by the
/// basic split.
pub const PRIVATE_RULE_SET: &str = "geosite-private";

/// [`PRIVATE_CIDRS`] as rules: `IP-CIDR[6],<range>,DIRECT,no-resolve`.
pub fn private_cidr_rules() -> Vec<String> {
    PRIVATE_CIDRS
        .iter()
        .map(|c| format!("{},{c},DIRECT,no-resolve", ip_cidr_type(c)))
        .collect()
}

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
    }
}

/// A user rule as a rule line sending its sites to `target` (Dart:
/// `customRule` in `buildClashConfig`, after the target is resolved). A
/// single address gets `/32` or `/128`.
pub fn custom_rule_line(r: &CustomRule, target: &str) -> String {
    let v = &r.value;
    match r.matches {
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
    }
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
        .find(|x| *x != "no-resolve" && *x != "src")
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
/// words, addresses or `ip:` ranges, `process:` programs): those skip it
/// and the rules after decide (Dart: `withoutSites`). `sites` must not be
/// empty.
pub fn without_sites(rule: &str, sites: &[String]) -> String {
    let not: Vec<String> = sites
        .iter()
        .map(|s| {
            let (m, v) = exclude_match(s);
            match m {
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
            }
        })
        .collect();
    let skip = match not.as_slice() {
        [one] => format!("(NOT,({one}))"),
        _ => format!("(NOT,((OR,({}))))", not.join(",")),
    };
    if rule.starts_with("AND,(") {
        // `AND,((a),(b)),target`: one more condition inside.
        if let Some(cut) = rule.rfind("),") {
            return format!("{},{skip}){}", &rule[..cut], &rule[cut + 1..]);
        }
    }
    let parts: Vec<&str> = rule.split(',').collect();
    let resolve = parts.last() == Some(&"no-resolve");
    let n = parts.len().saturating_sub(if resolve { 2 } else { 1 });
    let target = parts.get(n).copied().unwrap_or_default();
    let mut cond = parts[..n].join(",");
    if resolve {
        cond.push_str(",no-resolve");
    }
    format!("AND,(({cond}),{skip}),{target}")
}

#[cfg(test)]
mod tests;
