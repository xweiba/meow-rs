//! PaoPao ordered hosts (`paopao-hosts:`) — a PaoPao extension, not part of
//! mihomo.
//!
//! mihomo's `hosts:` is a [`meow_trie::DomainTrie`]: the most specific
//! pattern wins, there are no mid-label wildcards and no way to exempt a
//! subset of names. `paopao-hosts:` is an **ordered list** instead: the
//! first entry whose pattern matches the queried name decides.
//!
//! - an entry with an `address` rewrites the name to that address (DNS
//!   answers it; the tunnel dials it, and routes LAN addresses DIRECT);
//! - an entry without an `address` is a *pass-through*: the name is
//!   resolved and routed exactly as if `paopao-hosts:` did not exist, and
//!   later entries are not consulted.
//!
//! Names are compared lower-case, without a trailing dot; internationalised
//! names in their punycode form (via [`meow_trie::to_ascii`]), the form
//! connections carry. Matching a plain lower-case ASCII name allocates
//! nothing.

use regex::Regex;
use std::borrow::Cow;
use std::net::IpAddr;

/// Outcome of a [`PaopaoHosts`] lookup for a name some entry matched.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PaopaoHostsMatch {
    /// The first matching entry pins the name to this address.
    Address(IpAddr),
    /// The first matching entry has no address: resolve and route the name
    /// as usual.
    PassThrough,
}

#[derive(Debug)]
enum Pattern {
    /// The whole name.
    Exact(Box<str>),
    /// The name itself and every subdomain.
    Suffix(Box<str>),
    /// Substring.
    Keyword(Box<str>),
    Regex(Regex),
    /// Glob over the whole name: `*` = any run (dots included), `?` = one
    /// character.
    Wildcard(Box<str>),
}

/// One `paopao-hosts:` entry.
#[derive(Debug)]
pub struct PaopaoHostRule {
    pattern: Pattern,
    address: Option<IpAddr>,
}

impl PaopaoHostRule {
    /// Build an entry. `kind` is `exact` | `suffix` | `keyword` | `regex` |
    /// `wildcard` (case-insensitive). Errors carry a human-readable reason.
    pub fn new(kind: &str, value: &str, address: Option<IpAddr>) -> Result<Self, String> {
        let value = value.trim();
        if value.is_empty() {
            return Err("empty value".to_owned());
        }
        let pattern = match kind.trim().to_ascii_lowercase().as_str() {
            "exact" => Pattern::Exact(normalize_name(value)?),
            "suffix" => {
                let v = value.trim_start_matches("+.").trim_start_matches('.');
                Pattern::Suffix(normalize_name(v)?)
            }
            "keyword" => Pattern::Keyword(normalize_name(value)?),
            "regex" => Pattern::Regex(
                regex::RegexBuilder::new(value)
                    .case_insensitive(true)
                    .build()
                    .map_err(|e| format!("invalid regex: {e}"))?,
            ),
            "wildcard" => Pattern::Wildcard(normalize_wildcard(value)?),
            other => {
                return Err(format!(
                    "unknown type '{other}' (expected exact, suffix, keyword, regex or wildcard)"
                ))
            }
        };
        Ok(Self { pattern, address })
    }

    /// The address this entry pins its names to; `None` = pass-through.
    pub fn address(&self) -> Option<IpAddr> {
        self.address
    }

    /// `name` must already be normalised (lower-case ASCII, no trailing dot).
    fn matches(&self, name: &str) -> bool {
        match &self.pattern {
            Pattern::Exact(v) => name == &**v,
            Pattern::Suffix(v) => {
                name == &**v
                    || (name.len() > v.len()
                        && name.ends_with(&**v)
                        && name.as_bytes()[name.len() - v.len() - 1] == b'.')
            }
            Pattern::Keyword(v) => name.contains(&**v),
            Pattern::Regex(re) => re.is_match(name),
            Pattern::Wildcard(p) => glob_match(p.as_bytes(), name.as_bytes()),
        }
    }
}

/// The ordered `paopao-hosts:` list — first match wins. Build once per
/// config and share it (`Arc`) between the DNS resolver and the tunnel.
#[derive(Debug, Default)]
pub struct PaopaoHosts {
    rules: Vec<PaopaoHostRule>,
}

impl PaopaoHosts {
    pub fn new() -> Self {
        Self::default()
    }

    /// Append an entry (lowest priority so far).
    pub fn push(&mut self, rule: PaopaoHostRule) {
        self.rules.push(rule);
    }

    pub fn len(&self) -> usize {
        self.rules.len()
    }

    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }

    /// The first entry matching `host`, if any. `None` = no entry matched
    /// (behaviour must be unchanged, same as [`PaopaoHostsMatch::PassThrough`]).
    pub fn lookup(&self, host: &str) -> Option<PaopaoHostsMatch> {
        if self.rules.is_empty() {
            return None;
        }
        let name = normalize_query(host)?;
        self.rules.iter().find(|r| r.matches(&name)).map(|r| {
            r.address
                .map_or(PaopaoHostsMatch::PassThrough, PaopaoHostsMatch::Address)
        })
    }

    /// The address `host` is rewritten to, or `None` when the name is
    /// passed through or matches no entry.
    pub fn address_for(&self, host: &str) -> Option<IpAddr> {
        match self.lookup(host)? {
            PaopaoHostsMatch::Address(ip) => Some(ip),
            PaopaoHostsMatch::PassThrough => None,
        }
    }
}

/// `true` for addresses that must never be sent to a remote proxy: RFC 1918
/// private, loopback, link-local, CGNAT (100.64.0.0/10), IPv6 ULA
/// (fc00::/7) and unspecified. IPv4-mapped IPv6 is judged as IPv4.
pub fn is_lan_address(ip: IpAddr) -> bool {
    match ip.to_canonical() {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            v4.is_private()
                || v4.is_loopback()
                || v4.is_link_local()
                || v4.is_unspecified()
                || (o[0] == 100 && (o[1] & 0xc0) == 64)
        }
        IpAddr::V6(v6) => {
            let s = v6.segments();
            v6.is_loopback()
                || v6.is_unspecified()
                || (s[0] & 0xfe00) == 0xfc00
                || (s[0] & 0xffc0) == 0xfe80
        }
    }
}

/// Normalise a queried name: trim, drop the trailing dot, lower-case,
/// punycode. Borrows (no allocation) for plain lower-case ASCII names.
fn normalize_query(host: &str) -> Option<Cow<'_, str>> {
    let name = host.trim().trim_end_matches('.');
    if name.is_empty() {
        return None;
    }
    if !name.is_ascii() {
        return Some(Cow::Owned(meow_trie::to_ascii(name)));
    }
    if name.bytes().any(|b| b.is_ascii_uppercase()) {
        return Some(Cow::Owned(name.to_ascii_lowercase()));
    }
    Some(Cow::Borrowed(name))
}

fn normalize_name(value: &str) -> Result<Box<str>, String> {
    let v = value.trim_end_matches('.');
    if v.is_empty() {
        return Err("empty value".to_owned());
    }
    Ok(if v.is_ascii() {
        v.to_ascii_lowercase()
    } else {
        meow_trie::to_ascii(v)
    }
    .into_boxed_str())
}

/// Lower-case a glob; non-ASCII labels without glob characters are
/// punycoded so they compare against the punycode form of queried names.
fn normalize_wildcard(value: &str) -> Result<Box<str>, String> {
    let v = value.trim_end_matches('.');
    if v.is_empty() {
        return Err("empty value".to_owned());
    }
    if v.is_ascii() {
        return Ok(v.to_ascii_lowercase().into_boxed_str());
    }
    let labels: Vec<String> = v
        .split('.')
        .map(|label| {
            if label.is_ascii() {
                label.to_ascii_lowercase()
            } else if label.contains(['*', '?']) {
                label.to_lowercase()
            } else {
                meow_trie::to_ascii(label)
            }
        })
        .collect();
    Ok(labels.join(".").into_boxed_str())
}

/// Iterative glob match with single-star backtracking: linear in practice,
/// no allocation.
fn glob_match(pattern: &[u8], name: &[u8]) -> bool {
    let (mut pi, mut ni) = (0, 0);
    let mut star: Option<usize> = None;
    let mut mark = 0;
    while ni < name.len() {
        if pi < pattern.len() && (pattern[pi] == b'?' || pattern[pi] == name[ni]) {
            pi += 1;
            ni += 1;
        } else if pi < pattern.len() && pattern[pi] == b'*' {
            star = Some(pi);
            pi += 1;
            mark = ni;
        } else if let Some(sp) = star {
            pi = sp + 1;
            mark += 1;
            ni = mark;
        } else {
            return false;
        }
    }
    while pi < pattern.len() && pattern[pi] == b'*' {
        pi += 1;
    }
    pi == pattern.len()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    fn rule(kind: &str, value: &str, address: Option<&str>) -> PaopaoHostRule {
        PaopaoHostRule::new(kind, value, address.map(ip)).unwrap()
    }

    fn weiba() -> PaopaoHosts {
        let mut h = PaopaoHosts::new();
        h.push(rule("wildcard", "node*.weiba.pp.ua", None));
        h.push(rule("exact", "pve.weiba.pp.ua", Some("192.168.186.215")));
        h.push(rule("wildcard", "*.weiba.pp.ua", Some("192.168.186.230")));
        h
    }

    #[test]
    fn weiba_example_first_match_wins() {
        let h = weiba();
        assert_eq!(
            h.lookup("node1.weiba.pp.ua"),
            Some(PaopaoHostsMatch::PassThrough)
        );
        assert_eq!(h.address_for("node1.weiba.pp.ua"), None);
        assert_eq!(
            h.address_for("pve.weiba.pp.ua"),
            Some(ip("192.168.186.215"))
        );
        assert_eq!(
            h.address_for("PVE.Weiba.pp.ua."),
            Some(ip("192.168.186.215"))
        );
        assert_eq!(h.address_for("x.weiba.pp.ua"), Some(ip("192.168.186.230")));
        assert_eq!(
            h.address_for("a.b.weiba.pp.ua"),
            Some(ip("192.168.186.230"))
        );
        // `*.` needs at least the dot: the apex is not matched.
        assert_eq!(h.lookup("weiba.pp.ua"), None);
        assert_eq!(h.lookup("example.com"), None);
    }

    #[test]
    fn order_decides_not_specificity() {
        let mut h = PaopaoHosts::new();
        h.push(rule("suffix", "example.com", Some("10.0.0.1")));
        h.push(rule("exact", "a.example.com", Some("10.0.0.2")));
        assert_eq!(h.address_for("a.example.com"), Some(ip("10.0.0.1")));
    }

    #[test]
    fn each_type_matches() {
        let exact = rule("exact", "Example.COM.", Some("1.1.1.1"));
        assert!(exact.matches("example.com"));
        assert!(!exact.matches("a.example.com"));

        let suffix = rule("suffix", "example.com", None);
        assert!(suffix.matches("example.com"));
        assert!(suffix.matches("a.b.example.com"));
        assert!(!suffix.matches("badexample.com"));
        assert!(!suffix.matches("example.com.cn"));
        let dotted = rule("suffix", ".example.com", None);
        assert!(dotted.matches("example.com"));

        let keyword = rule("keyword", "tube", None);
        assert!(keyword.matches("www.youtube.com"));
        assert!(!keyword.matches("example.com"));

        let regex = rule("regex", r"^nas\d+\.lan$", None);
        assert!(regex.matches("nas12.lan"));
        assert!(!regex.matches("nas.lan"));

        let wildcard = rule("wildcard", "a?c.*.test", None);
        assert!(wildcard.matches("abc.x.test"));
        assert!(wildcard.matches("abc.x.y.test"));
        assert!(!wildcard.matches("abbc.x.test"));
        assert!(!wildcard.matches("abc.test"));
        let star = rule("wildcard", "*", None);
        assert!(star.matches("anything.at.all"));
    }

    #[test]
    fn idn_names_compare_in_punycode() {
        let mut h = PaopaoHosts::new();
        h.push(rule("suffix", "例子.测试", Some("10.1.2.3")));
        h.push(rule("wildcard", "*.bücher.de", Some("10.1.2.4")));
        assert_eq!(h.address_for("www.例子.测试"), Some(ip("10.1.2.3")));
        let puny = meow_trie::to_ascii("www.例子.测试");
        assert_eq!(h.address_for(&puny), Some(ip("10.1.2.3")));
        assert_eq!(h.address_for("shop.bücher.de"), Some(ip("10.1.2.4")));
    }

    #[test]
    fn invalid_entries_are_rejected() {
        assert!(PaopaoHostRule::new("glob", "x", None).is_err());
        assert!(PaopaoHostRule::new("exact", "  ", None).is_err());
        assert!(PaopaoHostRule::new("regex", "(", None).is_err());
        assert!(PaopaoHostRule::new("EXACT", "x.test", None).is_ok());
    }

    #[test]
    fn empty_list_matches_nothing() {
        let h = PaopaoHosts::new();
        assert!(h.is_empty());
        assert_eq!(h.lookup("anything.test"), None);
    }

    #[test]
    fn lowercase_ascii_query_borrows() {
        assert!(matches!(
            normalize_query("pve.weiba.pp.ua."),
            Some(Cow::Borrowed("pve.weiba.pp.ua"))
        ));
        assert!(matches!(normalize_query("PVE.x"), Some(Cow::Owned(_))));
        assert!(normalize_query(".").is_none());
    }

    #[test]
    fn lan_address_classes() {
        for lan in [
            "10.1.2.3",
            "172.16.0.1",
            "192.168.186.230",
            "127.0.0.1",
            "169.254.1.1",
            "100.64.0.1",
            "100.127.255.254",
            "0.0.0.0",
            "::1",
            "fd00::1",
            "fe80::1",
            "::ffff:192.168.1.1",
        ] {
            assert!(is_lan_address(ip(lan)), "{lan} should be LAN");
        }
        for public in ["8.8.8.8", "100.128.0.1", "172.32.0.1", "2001:4860::8888"] {
            assert!(!is_lan_address(ip(public)), "{public} should be public");
        }
        assert!(is_lan_address(IpAddr::V4(Ipv4Addr::LOCALHOST)));
        assert!(!is_lan_address(IpAddr::V6(Ipv6Addr::new(
            0x2606, 0x4700, 0, 0, 0, 0, 0, 0x1111
        ))));
    }
}
