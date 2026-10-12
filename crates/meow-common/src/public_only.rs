//! Connections the core makes on behalf of data it does not trust.
//!
//! PaoPao 签到助手 re-sends requests described by rules the user imported
//! from somebody else. Such a request must not reach this machine (the
//! controller, other local services) or a private network (the router, a
//! cloud metadata endpoint), whatever its host name resolves to. The check
//! therefore sits where the address is finally known: `DIRECT` refuses to
//! dial a non-public address for a connection whose inbound name is
//! [`PUBLIC_ONLY_INBOUND`].

use std::net::{IpAddr, Ipv4Addr};

/// Inbound name of a connection that may only go to public addresses.
pub const PUBLIC_ONLY_INBOUND: &str = "checkin";

/// Inbound name of the same kind of connection once the user has allowed
/// private addresses (`checkin.json`, `settings.allow_private`).
pub const PRIVATE_ALLOWED_INBOUND: &str = "checkin-private";

/// An address on this machine or a network that is not the internet:
/// loopback, private, link-local (cloud metadata lives there), carrier
/// NAT, the benchmark range (the core's fake-IP pool), multicast,
/// reserved, and the IPv6 forms that carry one of those IPv4 addresses.
pub fn is_non_public_ip(ip: IpAddr) -> bool {
    match ip.to_canonical() {
        IpAddr::V4(ip) => {
            let o = ip.octets();
            o[0] == 0
                || ip.is_loopback()
                || ip.is_private()
                || ip.is_link_local()
                || ip.is_broadcast()
                || ip.is_multicast()
                // 100.64.0.0/10, carrier-grade NAT.
                || (o[0] == 100 && (o[1] & 0xc0) == 64)
                // 192.0.0.0/24, protocol assignments.
                || (o[0] == 192 && o[1] == 0 && o[2] == 0)
                // 198.18.0.0/15, benchmarking.
                || (o[0] == 198 && (o[1] & 0xfe) == 18)
                // 240.0.0.0/4, reserved.
                || o[0] >= 240
        }
        IpAddr::V6(ip) => {
            let s = ip.segments();
            let embedded = |hi: u16, lo: u16| {
                let (hi, lo) = (hi.to_be_bytes(), lo.to_be_bytes());
                is_non_public_ip(IpAddr::V4(Ipv4Addr::new(hi[0], hi[1], lo[0], lo[1])))
            };
            ip.is_loopback()
                || ip.is_unspecified()
                || ip.is_multicast()
                // fc00::/7 unique local, fe80::/10 link local, fec0::/10 site local.
                || (s[0] & 0xfe00) == 0xfc00
                || (s[0] & 0xffc0) == 0xfe80
                || (s[0] & 0xffc0) == 0xfec0
                // ::a.b.c.d (IPv4-compatible) and 64:ff9b::/96 (NAT64).
                || (s[..6] == [0, 0, 0, 0, 0, 0] && embedded(s[6], s[7]))
                || (s[..6] == [0x64, 0xff9b, 0, 0, 0, 0] && embedded(s[6], s[7]))
                // 2002::/16 (6to4) carries the IPv4 address next.
                || (s[0] == 0x2002 && embedded(s[1], s[2]))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn non_public_addresses() {
        for ip in [
            "127.0.0.1",
            "10.1.2.3",
            "172.16.0.1",
            "192.168.1.1",
            "169.254.169.254",
            "100.64.0.1",
            "0.0.0.0",
            "0.1.2.3",
            "198.18.0.1",
            "224.0.0.1",
            "240.0.0.1",
            "255.255.255.255",
            "::1",
            "::",
            "fd00::1",
            "fe80::1",
            "ff02::1",
            "::ffff:127.0.0.1",
            "::127.0.0.1",
            "64:ff9b::7f00:1",
            "64:ff9b::a9fe:a9fe",
            "2002:c0a8:101::1",
        ] {
            assert!(is_non_public_ip(ip.parse().unwrap()), "{ip}");
        }
        for ip in [
            "8.8.8.8",
            "1.1.1.1",
            "100.128.0.1",
            "198.20.0.1",
            "2001:4860:4860::8888",
            "64:ff9b::808:808",
            "2002:808:808::1",
        ] {
            assert!(!is_non_public_ip(ip.parse().unwrap()), "{ip}");
        }
    }
}
