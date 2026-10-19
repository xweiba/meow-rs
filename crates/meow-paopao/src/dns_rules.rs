//! File-backed encrypted DNS defaults, materialized at the JSON/CLI IO
//! boundary. The actual planner receives plain data and remains pure.

use serde::Deserialize;
use serde_json::Value;

const DEFAULTS: &str = include_str!("../defaults/encrypted-dns.json");

/// Known resolver domains/IPs and dedicated encrypted DNS ports. An empty
/// list disables that class; normal HTTPS is never classified by port alone.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(default)]
pub struct EncryptedDnsRules {
    /// Resolver suffixes, including their subdomains; empty disables them.
    pub domains: Vec<String>,
    /// Resolver hosts, matched only on the configured HTTPS ports.
    pub addresses: Vec<std::net::IpAddr>,
    /// Dedicated encrypted DNS destination ports; empty disables them.
    pub ports: Vec<u16>,
    /// HTTPS ports used for address rules in the legacy file format.
    #[serde(rename = "httpsPorts", default = "default_https_ports")]
    pub https_ports: Vec<u16>,
}

fn default_https_ports() -> Vec<u16> {
    serde_json::from_str::<Value>(DEFAULTS)
        .ok()
        .and_then(|v| serde_json::from_value(v["httpsPorts"].clone()).ok())
        .unwrap_or_default()
}

impl Default for EncryptedDnsRules {
    fn default() -> Self {
        Self {
            domains: Vec::new(),
            addresses: Vec::new(),
            ports: Vec::new(),
            https_ports: default_https_ports(),
        }
    }
}

impl EncryptedDnsRules {
    /// Convert the legacy resolver lists into profile-compatible rule lines.
    pub fn lines(&self, target: &str) -> Vec<String> {
        let mut out = Vec::new();
        for domain in &self.domains {
            let domain = domain.trim().trim_end_matches('.').to_ascii_lowercase();
            if !domain.is_empty()
                && domain
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-')
            {
                out.push(format!("DOMAIN-SUFFIX,{domain},{target}"));
            }
        }
        let https_ports = self
            .https_ports
            .iter()
            .filter(|p| **p != 0)
            .map(u16::to_string)
            .collect::<Vec<_>>()
            .join("/");
        for ip in self.addresses.iter().filter(|_| !https_ports.is_empty()) {
            let (kind, prefix) = if ip.is_ipv4() {
                ("IP-CIDR", 32)
            } else {
                ("IP-CIDR6", 128)
            };
            out.push(format!(
                "AND,((DST-PORT,{https_ports}),({kind},{ip}/{prefix},no-resolve)),{target}"
            ));
        }
        let ports: Vec<_> = self
            .ports
            .iter()
            .filter(|&&port| port != 0)
            .map(u16::to_string)
            .collect();
        if !ports.is_empty() {
            out.push(format!("DST-PORT,{},{}", ports.join("/"), target));
        }
        out
    }
}

/// Load an optional explicit file; missing files use shipped defaults.
/// Never writes files as the privileged core. Bad files refuse a rebuild
/// rather than silently losing the user's routing policy.
pub fn materialize(input: &mut Value) -> Result<Option<Value>, String> {
    let Some(path) = input
        .pointer("/runtime/encryptedDnsRulesFile")
        .and_then(Value::as_str)
    else {
        return Ok(None);
    };
    let document = match crate::rule_profile::read_document(path, 128 * 1024)? {
        Some(document) => document,
        None => serde_json::from_str(DEFAULTS)
            .map_err(|e| format!("invalid shipped DNS defaults: {e}"))?,
    };
    serde_json::from_value::<EncryptedDnsRules>(document.clone())
        .map_err(|e| format!("invalid encrypted DNS rules: {e}"))?;
    input["runtime"]["encryptedDnsRules"] = document.clone();
    Ok(Some(document))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn known_https_endpoints_and_dedicated_ports_only() {
        let data: EncryptedDnsRules = serde_json::from_str(DEFAULTS).unwrap();
        let lines = data.lines("policy:ai");
        assert!(lines.contains(&"DOMAIN-SUFFIX,dns.google,policy:ai".into()));
        assert!(lines.contains(&"DST-PORT,853,policy:ai".into()));
        assert!(!lines.contains(&"DST-PORT,443,policy:ai".into()));
        assert!(lines.iter().any(|l| l.contains("IP-CIDR,1.1.1.1/32")));
    }
}
