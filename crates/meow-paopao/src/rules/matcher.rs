//! Whether a config rule line takes a connection, as far as that can be
//! told without the core (B5 / D6): rule sets (`GEOSITE`, `GEOIP`), a
//! domain that would have to be resolved, and rule types not modelled here
//! are "can't tell".

use std::net::IpAddr;

/// What a [`Rule::check`] says about one connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// The rule takes it.
    Yes,
    /// The rule does not.
    No,
    /// Only the core can tell (a rule set, a lookup, an unknown type).
    Unknown,
}

impl Verdict {
    fn of(b: bool) -> Self {
        if b {
            Self::Yes
        } else {
            Self::No
        }
    }

    fn not(self) -> Self {
        match self {
            Self::Yes => Self::No,
            Self::No => Self::Yes,
            Self::Unknown => Self::Unknown,
        }
    }
}

/// The connection asked about.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Connection {
    /// A domain (any case, a trailing dot ignored) or an IP address
    /// (IPv6 with or without brackets).
    pub host: String,
    /// Destination port; None = not known (port rules can't tell).
    pub port: Option<u16>,
    /// The program making it; None = not known: `PROCESS-NAME` rules don't
    /// take it (the question is about the site, from any other program).
    pub process: Option<String>,
    /// The program's full path (`/Applications/X.app/Contents/MacOS/X`);
    /// None = not known: `PROCESS-PATH` rules don't take it.
    pub process_path: Option<String>,
    /// UDP rather than TCP (a site is visited over TCP by default).
    pub udp: bool,
}

/// [`Connection`] with its host read once.
struct Conn<'a> {
    c: &'a Connection,
    /// Lowercase, without a trailing dot; empty for an address.
    domain: String,
    ip: Option<IpAddr>,
}

impl<'a> Conn<'a> {
    fn new(c: &'a Connection) -> Self {
        let h = c.host.trim();
        let bare = h
            .strip_prefix('[')
            .and_then(|x| x.strip_suffix(']'))
            .unwrap_or(h);
        match bare.parse::<IpAddr>() {
            Ok(ip) => Self {
                c,
                domain: String::new(),
                ip: Some(ip),
            },
            Err(_) => Self {
                c,
                domain: h.trim_end_matches('.').to_ascii_lowercase(),
                ip: None,
            },
        }
    }
}

/// A config rule line taken apart: `TYPE,payload,target[,options]`,
/// `MATCH,target`, or a logic rule `AND,((…),(…)),target`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rule<'a> {
    /// `DOMAIN-SUFFIX`, `AND`, `MATCH` … (as written).
    pub kind: &'a str,
    /// What it matches; empty for `MATCH`.
    pub payload: &'a str,
    /// Where it sends a connection.
    pub target: &'a str,
    /// Trailing options (`no-resolve`, `src`).
    pub options: Vec<&'a str>,
}

impl<'a> Rule<'a> {
    /// Takes `line` apart; None when it has no target.
    pub fn parse(line: &'a str) -> Option<Self> {
        let parts = split_top(line);
        let kind = parts.first()?.trim();
        if kind.eq_ignore_ascii_case("MATCH") || kind.eq_ignore_ascii_case("FINAL") {
            return Some(Self {
                kind,
                payload: "",
                target: parts.get(1)?.trim(),
                options: Vec::new(),
            });
        }
        Some(Self {
            kind,
            payload: parts.get(1)?.trim(),
            target: parts.get(2)?.trim(),
            options: parts[3..].iter().map(|o| o.trim()).collect(),
        })
    }

    /// Whether this rule takes connection `c`.
    pub fn check(&self, c: &Connection) -> Verdict {
        condition(self.kind, self.payload, &self.options, &Conn::new(c), 0)
    }
}

/// Logic rules nest; deeper than this is not a rule anyone writes.
const MAX_DEPTH: usize = 32;

/// `s` split at the commas outside parentheses.
fn split_top(s: &str) -> Vec<&str> {
    let mut out = Vec::new();
    let mut depth = 0usize;
    let mut start = 0;
    for (i, b) in s.bytes().enumerate() {
        match b {
            b'(' => depth += 1,
            b')' => depth = depth.saturating_sub(1),
            b',' if depth == 0 => {
                out.push(&s[start..i]);
                start = i + 1;
            }
            _ => {}
        }
    }
    out.push(&s[start..]);
    out
}

/// `(x)` → `x`; None without the parentheses.
fn unwrap_parens(s: &str) -> Option<&str> {
    s.trim().strip_prefix('(')?.strip_suffix(')')
}

/// The conditions of a logic rule's payload `((a),(b))`.
fn sub_conditions(payload: &str) -> Option<Vec<&str>> {
    split_top(unwrap_parens(payload)?)
        .into_iter()
        .map(unwrap_parens)
        .collect()
}

/// One condition `TYPE,payload[,options]` (inside a logic rule, without a
/// target).
fn sub_condition(text: &str, c: &Conn<'_>, depth: usize) -> Verdict {
    let parts = split_top(text);
    let kind = parts[0].trim();
    let payload = parts.get(1).map_or("", |p| p.trim());
    let options: Vec<&str> = parts.iter().skip(2).map(|o| o.trim()).collect();
    condition(kind, payload, &options, c, depth)
}

fn condition(kind: &str, payload: &str, options: &[&str], c: &Conn<'_>, depth: usize) -> Verdict {
    if depth > MAX_DEPTH {
        return Verdict::Unknown;
    }
    let no_resolve = options.iter().any(|o| o.eq_ignore_ascii_case("no-resolve"));
    let src = options.iter().any(|o| o.eq_ignore_ascii_case("src"));
    let domain = |f: &dyn Fn(&str, &str) -> bool| {
        Verdict::of(!c.domain.is_empty() && f(&c.domain, &payload.to_ascii_lowercase()))
    };
    match kind.to_ascii_uppercase().as_str() {
        "MATCH" | "FINAL" => Verdict::Yes,
        "DOMAIN" => domain(&|h, p| h == p),
        "DOMAIN-SUFFIX" => domain(&|h, p| {
            let p = p.trim_start_matches('.');
            h == p || h.strip_suffix(p).is_some_and(|rest| rest.ends_with('.'))
        }),
        "DOMAIN-KEYWORD" => domain(&|h, p| h.contains(p)),
        "IP-CIDR" | "IP-CIDR6" if src => Verdict::Unknown,
        "IP-CIDR" | "IP-CIDR6" => match c.ip {
            Some(ip) => cidr_contains(payload, ip).map_or(Verdict::Unknown, Verdict::of),
            // A domain: the core would look it up first.
            None if no_resolve => Verdict::No,
            None => Verdict::Unknown,
        },
        "GEOIP" if c.ip.is_none() && no_resolve => Verdict::No,
        // As the core: the name ignoring ASCII case, the path as
        // [`process_path_matches`].
        "PROCESS-NAME" => Verdict::of(
            c.c.process
                .as_deref()
                .is_some_and(|p| p.eq_ignore_ascii_case(payload)),
        ),
        "PROCESS-PATH" if payload.contains('*') => Verdict::Unknown,
        "PROCESS-PATH" => Verdict::of(
            c.c.process_path
                .as_deref()
                .is_some_and(|p| process_path_matches(payload, p)),
        ),
        "NETWORK" => Verdict::of(payload.eq_ignore_ascii_case(if c.c.udp { "udp" } else { "tcp" })),
        "DST-PORT" => match c.c.port {
            Some(p) => port_in(payload, p).map_or(Verdict::Unknown, Verdict::of),
            None => Verdict::Unknown,
        },
        // No inbound name or proxy user: the user's own traffic.
        "IN-NAME" | "IN-USER" | "IN-TYPE" | "IN-PORT" => Verdict::No,
        "AND" | "OR" => {
            let Some(subs) = sub_conditions(payload) else {
                return Verdict::Unknown;
            };
            let (stop, other) = if kind.eq_ignore_ascii_case("AND") {
                (Verdict::No, Verdict::Yes)
            } else {
                (Verdict::Yes, Verdict::No)
            };
            let mut unknown = false;
            for s in subs {
                match sub_condition(s, c, depth + 1) {
                    v if v == stop => return stop,
                    Verdict::Unknown => unknown = true,
                    _ => {}
                }
            }
            if unknown {
                Verdict::Unknown
            } else {
                other
            }
        }
        "NOT" => match sub_conditions(payload).as_deref() {
            Some([one]) => sub_condition(one, c, depth + 1).not(),
            _ => Verdict::Unknown,
        },
        // GEOSITE, GEOIP, rule sets, source rules, regexes, …
        _ => Verdict::Unknown,
    }
}

/// A `PROCESS-PATH` payload without `*` against a program's path, as
/// meow-rules does: one starting with `/` or `\` is a directory (the path
/// itself or anything under it, on whole parts); else the file name alone.
fn process_path_matches(payload: &str, path: &str) -> bool {
    if path.is_empty() {
        return false;
    }
    if payload.starts_with(['/', '\\']) {
        return path == payload
            || path
                .strip_prefix(payload)
                .is_some_and(|rest| rest.starts_with(['/', '\\']));
    }
    path.rsplit(['/', '\\']).next() == Some(payload)
}

/// Whether `ip` is in `cidr` (`1.2.3.0/24`, `2001:db8::/32`, an address
/// alone); None when `cidr` is not one.
fn cidr_contains(cidr: &str, ip: IpAddr) -> Option<bool> {
    let (addr, bits) = match cidr.split_once('/') {
        Some((a, b)) => (a, Some(b.parse::<u32>().ok()?)),
        None => (cidr, None),
    };
    let net: IpAddr = addr.parse().ok()?;
    let (n, i, width) = match (net, ip) {
        (IpAddr::V4(n), IpAddr::V4(i)) => (u128::from(u32::from(n)), u128::from(u32::from(i)), 32),
        (IpAddr::V6(n), IpAddr::V6(i)) => (u128::from(n), u128::from(i), 128),
        (IpAddr::V6(n), IpAddr::V4(i)) => (u128::from(n), u128::from(i.to_ipv6_mapped()), 128),
        (IpAddr::V4(_), IpAddr::V6(i)) => match i.to_ipv4_mapped() {
            Some(v4) => return cidr_contains(cidr, IpAddr::V4(v4)),
            None => return Some(false),
        },
    };
    let bits = bits.unwrap_or(width);
    if bits > width {
        return None;
    }
    let shift = width - bits;
    // `checked_shr`: a shift by the full width (a /0) leaves nothing.
    let mask = |x: u128| x.checked_shr(shift).unwrap_or(0);
    Some(mask(n) == mask(i))
}

/// Whether `port` is in `ports` (`443`, `3478/5349/19302-19309`); None
/// when `ports` is not a port list.
fn port_in(ports: &str, port: u16) -> Option<bool> {
    let mut hit = false;
    for part in ports.split('/') {
        let (lo, hi) = match part.split_once('-') {
            Some((a, b)) => (a.trim().parse::<u16>().ok()?, b.trim().parse::<u16>().ok()?),
            None => {
                let p = part.trim().parse::<u16>().ok()?;
                (p, p)
            }
        };
        hit |= (lo..=hi).contains(&port);
    }
    Some(hit)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn site(host: &str) -> Connection {
        Connection {
            host: host.into(),
            ..Connection::default()
        }
    }

    fn check(line: &str, c: &Connection) -> Verdict {
        Rule::parse(line).expect("rule").check(c)
    }

    use Verdict::{No, Unknown, Yes};

    #[test]
    fn domains() {
        let g = site("WWW.Google.com.");
        assert_eq!(check("DOMAIN-SUFFIX,google.com,x", &g), Yes);
        assert_eq!(check("DOMAIN-SUFFIX,oogle.com,x", &g), No);
        assert_eq!(check("DOMAIN-SUFFIX,www.google.com,x", &g), Yes);
        assert_eq!(check("DOMAIN,google.com,x", &g), No);
        assert_eq!(check("DOMAIN,www.google.com,x", &g), Yes);
        assert_eq!(check("DOMAIN-KEYWORD,goog,x", &g), Yes);
        assert_eq!(check("DOMAIN-SUFFIX,google.com,x", &site("8.8.8.8")), No);
        assert_eq!(check("GEOSITE,google,x", &g), Unknown);
        assert_eq!(check("MATCH,x", &g), Yes);
        assert_eq!(check("RULE-SET,foo,x", &g), Unknown);
    }

    #[test]
    fn addresses() {
        let ip = site("10.1.2.3");
        assert_eq!(check("IP-CIDR,10.0.0.0/8,DIRECT,no-resolve", &ip), Yes);
        assert_eq!(check("IP-CIDR,11.0.0.0/8,DIRECT,no-resolve", &ip), No);
        assert_eq!(check("IP-CIDR,10.1.2.3/32,DIRECT", &ip), Yes);
        assert_eq!(check("IP-CIDR,0.0.0.0/0,DIRECT", &ip), Yes);
        assert_eq!(check("IP-CIDR,10.0.0.0/33,DIRECT", &ip), Unknown);
        assert_eq!(check("IP-CIDR,10.0.0.0/8,DIRECT,src", &ip), Unknown);
        let v6 = site("[2001:db8::1]");
        assert_eq!(check("IP-CIDR6,2001:db8::/32,x,no-resolve", &v6), Yes);
        assert_eq!(check("IP-CIDR6,fc00::/7,x,no-resolve", &v6), No);
        assert_eq!(check("IP-CIDR,10.0.0.0/8,x,no-resolve", &v6), No);
        // A domain: no-resolve skips, else only the lookup can tell.
        let d = site("a.example");
        assert_eq!(check("IP-CIDR,10.0.0.0/8,x,no-resolve", &d), No);
        assert_eq!(check("IP-CIDR,10.0.0.0/8,x", &d), Unknown);
        assert_eq!(check("GEOIP,cn,x", &d), Unknown);
        assert_eq!(check("GEOIP,cn,x,no-resolve", &d), No);
        assert_eq!(check("GEOIP,cn,x", &ip), Unknown);
    }

    #[test]
    fn programs_ports_networks() {
        let mut c = site("a.example");
        assert_eq!(check("PROCESS-NAME,WeChat,x", &c), No);
        c.process = Some("WeChat".into());
        assert_eq!(check("PROCESS-NAME,WeChat,x", &c), Yes);
        assert_eq!(check("PROCESS-NAME,wechat,x", &c), Yes);
        // An app bundle: every program inside it, on whole path parts.
        let mut c = site("a.com");
        assert_eq!(check("PROCESS-PATH,/Applications/X.app,x", &c), No);
        c.process_path = Some(
            "/Applications/X.app/Contents/Frameworks/X Helper.app/Contents/MacOS/X Helper".into(),
        );
        assert_eq!(check("PROCESS-PATH,/Applications/X.app,x", &c), Yes);
        assert_eq!(check("PROCESS-PATH,/Applications/X,x", &c), No);
        assert_eq!(check("PROCESS-PATH,X Helper,x", &c), Yes);
        assert_eq!(check("PROCESS-PATH,/Applications/*.app,x", &c), Unknown);
        assert_eq!(
            check(
                "AND,((DOMAIN,a.com),(NOT,((PROCESS-PATH,/Applications/X.app)))),x",
                &c
            ),
            No
        );
        assert_eq!(check("DST-PORT,443,x", &c), Unknown);
        c.port = Some(5349);
        assert_eq!(check("DST-PORT,3478/5349/19302-19309,x", &c), Yes);
        c.port = Some(19305);
        assert_eq!(check("DST-PORT,3478/5349/19302-19309,x", &c), Yes);
        c.port = Some(443);
        assert_eq!(check("DST-PORT,3478/5349/19302-19309,x", &c), No);
        assert_eq!(check("NETWORK,TCP,x", &c), Yes);
        assert_eq!(check("NETWORK,UDP,x", &c), No);
    }

    #[test]
    fn logic() {
        let c = site("api.example.com");
        // The modules' MITM rule: not from the MITM return inbound.
        let mitm = "AND,((DOMAIN,api.example.com),(NOT,((IN-NAME,mitm-return)))),paopao-mitm";
        assert_eq!(check(mitm, &c), Yes);
        assert_eq!(Rule::parse(mitm).expect("rule").target, "paopao-mitm");
        // QUIC refused: a site over TCP is not.
        let quic = "AND,((NETWORK,UDP),(DST-PORT,443),(GEOSITE,youtube)),REJECT";
        assert_eq!(check(quic, &c), No);
        // A business policy minus the sites left out of it.
        let r = "AND,((DOMAIN-SUFFIX,example.com),(NOT,((OR,((DOMAIN,api.example.com),(DOMAIN-SUFFIX,b.example)))))),policy:x";
        assert_eq!(check(r, &c), No);
        assert_eq!(check(r, &site("www.example.com")), Yes);
        let g = "AND,((GEOSITE,google),(NOT,((DOMAIN-SUFFIX,a.example)))),policy:google";
        assert_eq!(check(g, &site("a.example")), No);
        assert_eq!(check(g, &site("b.example")), Unknown);
        assert_eq!(
            check("OR,((GEOSITE,x),(DOMAIN,api.example.com)),y", &c),
            Yes
        );
        assert_eq!(check("OR,((GEOSITE,x),(DOMAIN,b.example)),y", &c), Unknown);
        assert_eq!(check("AND,(broken),y", &c), Unknown);
        assert_eq!(check("NOT,((DOMAIN,a),(DOMAIN,b)),y", &c), Unknown);
    }

    #[test]
    fn odd_lines_never_panic() {
        for line in [
            "",
            ",",
            "AND",
            "AND,",
            "AND,(,x",
            "NOT,((((",
            "IP-CIDR,/,x",
            "DST-PORT,-,x",
            "))),((,x",
        ] {
            if let Some(r) = Rule::parse(line) {
                let _ = r.check(&site("a"));
            }
        }
        let deep = format!("{}DOMAIN,a{},x", "NOT,((".repeat(100), "))".repeat(100));
        let r = Rule::parse(&deep).expect("rule");
        assert_eq!(r.check(&site("a")), Unknown);
    }
}
