//! Editable routing data. IO is confined to JSON/CLI boundaries; the
//! planner receives an immutable profile and performs no file access.

use std::io::Read;
use std::sync::LazyLock;

use indexmap::IndexMap;
use serde::Deserialize;
use serde_json::Value;

const DEFAULTS: &str = include_str!("../defaults/routing-rules.json");
const MAX_BYTES: u64 = 512 * 1024;

/// A policy's ordered rules. Empty rules disable matching for this group.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyRules {
    /// Existing group tag to which exclusions and group availability apply.
    pub group: String,
    /// Basic split runs after subscription rules; services run before them.
    pub base: bool,
    /// Clash rule lines; `{domesticPolicy}` follows the domestic group.
    pub rules: Vec<String>,
}

/// All shipped network matching data. Fields are required so a truncated
/// or misspelled file cannot silently remove a user's privacy policy.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RuleProfile {
    /// Schema version, currently 1.
    pub version: u32,
    /// Default group when settings do not specify a DNS/WebRTC policy.
    pub default_dns_policy: String,
    /// Panel-only proxy hostname metadata lookups before a core is ready.
    /// URL templates accept `{host}`; empty disables pre-resolution.
    pub bootstrap_json_urls: Vec<String>,
    /// Group used by domestic exceptions within a service block.
    pub domestic_policy: String,
    /// Target if that domestic group is unavailable.
    pub domestic_fallback: String,
    /// Ordered alternatives when the selected group disappeared.
    pub dns_fallbacks: Vec<String>,
    /// Ordered stages understood by the emitter; each must occur once.
    pub order: Vec<String>,
    /// Runtime rule templates: speedtest, ownApp, inUser and match.
    pub templates: IndexMap<String, String>,
    /// Literal private network rules, before user rules by default.
    pub private_rules: Vec<String>,
    /// Local-name rules in the smart-mode basic split.
    pub private_sites: Vec<String>,
    /// Known encrypted resolvers, using `{dnsPolicy}` as the target.
    pub encrypted_dns_rules: Vec<String>,
    /// WebRTC/STUN rules, using `{dnsPolicy}` as the target.
    pub stun_rules: Vec<String>,
    /// Business categories in match order, including their target tags.
    pub policies: Vec<PolicyRules>,
    /// Catch-all target for each mode (smart, global, direct).
    pub final_targets: IndexMap<String, String>,
    /// Core DNS options; business upstream URLs carry `#{dnsPolicy}`.
    pub dns: Value,
    /// Additional DNS options when TUN is enabled, including fake-IP filters.
    pub fake_ip: Value,
    /// Extra real-IP domains, enabled while the keyed group selects DIRECT.
    pub fake_ip_filter_if_direct: IndexMap<String, Vec<String>>,
    /// Sniffer protocols, ports and exclusions in native config format.
    pub sniffer: Value,
    /// Rule-data source URLs and update settings in native config format.
    pub geodata: Value,
}

impl RuleProfile {
    /// The distribution template. It seeds a missing user file; existing
    /// files replace it in full and are never overwritten on upgrades.
    pub fn shipped() -> &'static Self {
        static PROFILE: LazyLock<RuleProfile> = LazyLock::new(|| {
            serde_json::from_str(DEFAULTS).expect("valid shipped routing profile")
        });
        &PROFILE
    }

    /// Expand only named runtime values. Matching conditions and targets
    /// remain file data; callers supply the current ports/users/groups.
    pub fn expand(line: &str, values: &[(&str, &str)]) -> String {
        values.iter().fold(line.to_owned(), |line, (key, value)| {
            line.replace(&format!("{{{key}}}"), value)
        })
    }

    /// Render an entry-point rule from its configured template.
    pub fn template(&self, name: &str, values: &[(&str, &str)]) -> Option<String> {
        self.templates
            .get(name)
            .filter(|s| !s.is_empty())
            .map(|s| Self::expand(s, values))
    }

    /// Structural checks run before any new config can replace a live one.
    pub fn validate(&self) -> Result<(), String> {
        if self.version != 1 {
            return Err("unsupported routing profile version".into());
        }
        let stages = crate::emit::RULE_ORDER;
        if self.order.len() != stages.len()
            || stages
                .iter()
                .any(|s| self.order.iter().filter(|x| x.as_str() == *s).count() != 1)
        {
            return Err("routing order must contain each supported stage exactly once".into());
        }
        for name in ["speedtest", "ownApp", "inUser", "match"] {
            if !self.templates.contains_key(name) {
                return Err(format!("missing rule template: {name}"));
            }
        }
        for mode in ["smart", "global", "direct"] {
            if self.final_targets.get(mode).is_none_or(String::is_empty) {
                return Err(format!("missing final target: {mode}"));
            }
        }
        for (name, object) in [
            ("dns", &self.dns),
            ("fakeIp", &self.fake_ip),
            ("sniffer", &self.sniffer),
            ("geodata", &self.geodata),
        ] {
            if !object.is_object() {
                return Err(format!("{name} must be an object"));
            }
        }
        for key in [
            "nameserver",
            "default-nameserver",
            "proxy-server-nameserver",
        ] {
            let Some(servers) = self.dns[key].as_array().filter(|s| !s.is_empty()) else {
                return Err(format!("dns.{key} must contain at least one upstream"));
            };
            if servers.iter().any(|s| {
                s.as_str()
                    .is_none_or(|s| s.is_empty() || s.chars().any(char::is_control))
            }) {
                return Err(format!("invalid dns.{key} upstream"));
            }
        }
        let mut groups = std::collections::HashSet::new();
        for p in &self.policies {
            if p.group.is_empty() || !groups.insert(&p.group) {
                return Err("empty or duplicate policy group".into());
            }
        }
        let lines = self
            .private_rules
            .iter()
            .chain(&self.private_sites)
            .chain(&self.encrypted_dns_rules)
            .chain(&self.stun_rules)
            .chain(self.policies.iter().flat_map(|p| &p.rules))
            .chain(self.templates.values().filter(|s| !s.is_empty()));
        for line in lines {
            if !line.contains(',') || line.chars().any(char::is_control) {
                return Err("routing rules must be single Clash rule lines".into());
            }
            let expanded = Self::expand(
                line,
                &[
                    ("dnsPolicy", "target"),
                    ("domesticPolicy", "target"),
                    ("inbound", "inbound"),
                    ("target", "target"),
                    ("app", "PROCESS-NAME,app"),
                    ("user", "user"),
                ],
            );
            if expanded.contains(['{', '}']) {
                return Err("unknown routing rule placeholder".into());
            }
        }
        Ok(())
    }
}

/// Read at most the configured bound, including pipes and changing files.
pub(crate) fn read_document(path: &str, limit: u64) -> Result<Option<Value>, String> {
    let file = match std::fs::File::open(path) {
        Ok(file) => file,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(format!("cannot read rule file: {e}")),
    };
    let mut bytes = Vec::new();
    file.take(limit + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| format!("cannot read rule file: {e}"))?;
    if bytes.len() as u64 > limit {
        return Err("rule file exceeds size limit".into());
    }
    serde_json::from_slice(&bytes)
        .map(Some)
        .map_err(|e| format!("invalid rule file JSON: {e}"))
}

/// Load a whole profile; absence seeds defaults, invalid files refuse the
/// rebuild. Only the unprivileged panel persists the returned document.
pub fn materialize(input: &mut Value) -> Result<Option<Value>, String> {
    let Some(path) = input.pointer("/runtime/rulesFile").and_then(Value::as_str) else {
        return Ok(None);
    };
    let mut document = match read_document(path, MAX_BYTES)? {
        Some(document) => document,
        None => {
            let mut document: Value = serde_json::from_str(DEFAULTS).map_err(|e| e.to_string())?;
            // One-time migration of the formerly separate encrypted DNS file.
            if let Some(old) = input
                .pointer("/runtime/encryptedDnsRulesFile")
                .and_then(Value::as_str)
            {
                if let Some(old) = read_document(old, 128 * 1024)? {
                    let rules: crate::dns_rules::EncryptedDnsRules = serde_json::from_value(old)
                        .map_err(|e| format!("invalid legacy DNS rules: {e}"))?;
                    document["encryptedDnsRules"] = serde_json::json!(rules.lines("{dnsPolicy}"));
                }
            }
            document
        }
    };
    let profile: RuleProfile = serde_json::from_value(document.clone())
        .map_err(|e| format!("invalid routing profile: {e}"))?;
    profile.validate()?;
    input["runtime"]["rulesProfile"] = document.take();
    Ok(Some(input["runtime"]["rulesProfile"].clone()))
}

/// Shared boundary for the FFI and resident core's rebuild child. The
/// legacy resolver-only file remains readable for older controllers.
pub fn load(input: &mut Value) -> Result<Option<(&'static str, Value)>, String> {
    if input.pointer("/runtime/rulesFile").is_some() {
        return materialize(input).map(|v| v.map(|v| ("rulesProfile", v)));
    }
    if let Some(document) = input.pointer("/runtime/rulesProfile") {
        let profile: RuleProfile = serde_json::from_value(document.clone())
            .map_err(|e| format!("invalid routing profile: {e}"))?;
        profile.validate()?;
    }
    crate::dns_rules::materialize(input).map(|v| v.map(|v| ("encryptedDnsRules", v)))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn distribution_profile_is_complete() {
        RuleProfile::shipped().validate().unwrap();
    }
}
