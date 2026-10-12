//! Addresses: what is acceptable, and which hosts are the same site.

use std::net::IpAddr;
use url::Url;

pub const URL_MAX: usize = 4096;

/// An `http(s)` address with a host, no user:password part, no control
/// characters, within [`URL_MAX`], written the plain way: `scheme://host`.
/// The forms a browser also tolerates (`https:/host`, `https:\\host`,
/// extra slashes) are refused, so the host is where it reads to be.
pub fn parse_http_url(text: &str) -> Option<Url> {
    if text.len() > URL_MAX || text.chars().any(char::is_control) || text.trim() != text {
        return None;
    }
    let lower = text.get(..8).unwrap_or(text).to_ascii_lowercase();
    let rest = if lower.starts_with("https://") {
        &text[8..]
    } else if lower.starts_with("http://") {
        &text[7..]
    } else {
        return None;
    };
    let authority = &rest[..rest.find(['/', '?', '#']).unwrap_or(rest.len())];
    // ASCII only: an international name must come as its `xn--` form, so a
    // look-alike letter cannot pass for the name it imitates.
    if authority.is_empty() || !authority.is_ascii() || authority.contains(['\\', '@']) {
        return None;
    }
    let url = Url::parse(text).ok()?;
    if !matches!(url.scheme(), "http" | "https") {
        return None;
    }
    // Punycode for international names, so plain ASCII here; no `{name}`.
    let plain = |host: &str| {
        !host.is_empty()
            && host.bytes().all(|b| {
                b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_' | b':' | b'[' | b']')
            })
    };
    if !url.host_str().is_some_and(plain) {
        return None;
    }
    if !url.username().is_empty() || url.password().is_some() {
        return None;
    }
    Some(url)
}

/// The host of an address, lower-case, without IPv6 brackets.
pub fn host_of(url: &Url) -> String {
    url.host_str()
        .unwrap_or("")
        .trim_start_matches('[')
        .trim_end_matches(']')
        .to_ascii_lowercase()
}

/// The registrable domain of `host` by the public-suffix list
/// (`a.b.example.co.uk` → `example.co.uk`); the host itself for an IP
/// address or a name the list has nothing for.
pub fn registrable(host: &str) -> String {
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    if host.parse::<IpAddr>().is_ok() {
        return host;
    }
    psl::domain_str(&host).map_or_else(|| host.clone(), str::to_string)
}

/// Same site: same registrable domain.
pub fn same_site(a: &str, b: &str) -> bool {
    !a.is_empty() && !b.is_empty() && registrable(a) == registrable(b)
}

/// An address on this machine or a network that is not the internet (see
/// [`meow_common::public_only::is_non_public_ip`]).
pub fn is_internal_ip(ip: IpAddr) -> bool {
    meow_common::public_only::is_non_public_ip(ip)
}

/// A host that names this machine or a private network: an address
/// [`is_internal_ip`] says so of, or a name that only means something
/// inside a network (`localhost`, `router`, `nas.lan`, `printer.local`).
///
/// A public-looking name can still resolve to such an address; the
/// connector checks the address it actually dials.
pub fn is_internal_host(host: &str) -> bool {
    let host = host
        .trim_start_matches('[')
        .trim_end_matches(']')
        .trim_end_matches('.')
        .to_ascii_lowercase();
    if let Ok(ip) = host.parse::<IpAddr>() {
        return is_internal_ip(ip);
    }
    if !host.contains('.') {
        return true;
    }
    [
        ".localhost",
        ".local",
        ".localdomain",
        ".lan",
        ".internal",
        ".intranet",
        ".home.arpa",
        ".home",
        ".corp",
    ]
    .iter()
    .any(|suffix| host.ends_with(suffix))
}

/// `scheme://host[:port]` of an address, as a browser writes `Origin`.
pub fn origin_of(url: &Url) -> String {
    url.origin().ascii_serialization()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn acceptable_addresses() {
        assert!(parse_http_url("https://main.example.com/user").is_some());
        assert!(parse_http_url("http://127.0.0.1:8080/").is_some());
        for bad in [
            "",
            "ftp://a.example/",
            "javascript:alert(1)",
            "file:///etc/passwd",
            "https:///nohost",
            "https://user:pw@a.example/",
            "https://user@a.example/",
            "https://a.example/\r\nHost: b",
            "not a url",
            "https:/a.example/",
            "https:a.example/",
            "https:\\\\a.example/",
            "http://a.example\\@b.example/",
            " https://a.example/",
            "https://{host}/x",
            // A Cyrillic "а": must be written as xn--.
            "https://ex\u{430}mple.com/",
        ] {
            assert!(parse_http_url(bad).is_none(), "{bad:?}");
        }
        assert!(parse_http_url(&format!("https://a.example/{}", "a".repeat(URL_MAX))).is_none());
        // The spellings of an address a browser folds are folded here too,
        // so the checks see what would be dialled.
        for (text, host) in [
            ("http://0x7f.0.0.1/", "127.0.0.1"),
            ("http://2130706433/", "127.0.0.1"),
            ("http://127.1/", "127.0.0.1"),
            ("http://%31%32%37.0.0.1/", "127.0.0.1"),
            ("http://[::FFFF:7F00:1]/", "::ffff:7f00:1"),
            ("http://LOCALHOST./", "localhost."),
        ] {
            let url = parse_http_url(text).unwrap_or_else(|| panic!("{text}"));
            assert_eq!(host_of(&url), host, "{text}");
            assert!(is_internal_host(&host_of(&url)), "{text}");
        }
    }

    #[test]
    fn sites_follow_the_public_suffix_list() {
        assert!(same_site("a.example.com", "b.example.com"));
        assert!(same_site("example.com", "www.example.com"));
        assert!(!same_site("example.com", "example.org"));
        // Two labels are not enough under a two-label suffix.
        assert!(!same_site("a.co.uk", "b.co.uk"));
        assert!(same_site("x.a.co.uk", "a.co.uk"));
        // Hosting suffixes: each customer is its own site.
        assert!(!same_site("a.github.io", "b.github.io"));
        // A public suffix in its xn-- form (公司.cn) is still one.
        assert!(!same_site("a.xn--55qx5d.cn", "b.xn--55qx5d.cn"));
        assert!(same_site("x.a.xn--55qx5d.cn", "a.xn--55qx5d.cn"));
        // A name the list knows nothing of is only itself.
        assert!(!same_site("a.internal", "b.internal"));
        assert!(same_site("EXAMPLE.com.", "www.example.com"));
        assert!(same_site("127.0.0.1", "127.0.0.1"));
        assert!(!same_site("127.0.0.1", "127.0.0.2"));
        assert!(!same_site("", ""));
    }

    #[test]
    fn internal_hosts() {
        for h in [
            "localhost",
            "a.localhost",
            "127.0.0.1",
            "10.1.2.3",
            "192.168.1.1",
            "172.16.0.1",
            "169.254.169.254",
            "100.64.0.1",
            "0.0.0.0",
            "::1",
            "[::1]",
            "fd00::1",
            "fe80::1",
            "::ffff:127.0.0.1",
            "0.1.2.3",
            "198.18.0.1",
            "224.0.0.1",
            "240.0.0.1",
            "255.255.255.255",
            "::",
            "::127.0.0.1",
            "64:ff9b::7f00:1",
            "64:ff9b::a9fe:a9fe",
            "2002:7f00:1::",
            "2002:c0a8:101::1",
            "ff02::1",
            "router",
            "nas.lan",
            "printer.local",
            "metadata.google.internal",
            "localhost.",
        ] {
            assert!(is_internal_host(h), "{h}");
        }
        for h in [
            "example.com",
            "8.8.8.8",
            "2001:4860:4860::8888",
            "64:ff9b::808:808",
            "local.example.com",
            "xn--mple-9nd.com",
        ] {
            assert!(!is_internal_host(h), "{h}");
        }
    }
}
