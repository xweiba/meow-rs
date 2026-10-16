//! This machine's own addresses (PaoPao's network conditions: "in
//! `192.168.1.0/24`"), as Dart's `NetworkInterface.list(includeLoopback:
//! false)` lists them with the link-local ones left out.

use std::net::IpAddr;

/// Every address of every interface that is up and not a loopback, bar
/// link-local ones (`169.254.0.0/16`, `fe80::/10`); unsorted, may repeat.
pub fn host_addresses() -> Vec<IpAddr> {
    imp::list()
        .into_iter()
        .filter(|ip| !ip.is_loopback() && !is_link_local(ip))
        .collect()
}

fn is_link_local(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(a) => a.is_link_local(),
        IpAddr::V6(a) => (a.segments()[0] & 0xffc0) == 0xfe80,
    }
}

#[cfg(unix)]
mod imp {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    pub(super) fn list() -> Vec<IpAddr> {
        let mut out = Vec::new();
        let mut ifap: *mut libc::ifaddrs = std::ptr::null_mut();
        // SAFETY: getifaddrs fills a list freed below with freeifaddrs.
        if unsafe { libc::getifaddrs(&raw mut ifap) } != 0 {
            return out;
        }
        let mut cur = ifap;
        while !cur.is_null() {
            // SAFETY: a node of the list getifaddrs returned.
            let ifa = unsafe { &*cur };
            cur = ifa.ifa_next;
            let up = ifa.ifa_flags & (libc::IFF_UP as libc::c_uint) != 0;
            let lo = ifa.ifa_flags & (libc::IFF_LOOPBACK as libc::c_uint) != 0;
            if ifa.ifa_addr.is_null() || !up || lo {
                continue;
            }
            // SAFETY: ifa_addr is non-null; its family says its type.
            let fam = i32::from(unsafe { (*ifa.ifa_addr).sa_family });
            if fam == libc::AF_INET {
                // SAFETY: AF_INET → sockaddr_in.
                let sin = unsafe { &*ifa.ifa_addr.cast::<libc::sockaddr_in>() };
                out.push(IpAddr::V4(Ipv4Addr::from(u32::from_be(
                    sin.sin_addr.s_addr,
                ))));
            } else if fam == libc::AF_INET6 {
                // SAFETY: AF_INET6 → sockaddr_in6.
                let sin6 = unsafe { &*ifa.ifa_addr.cast::<libc::sockaddr_in6>() };
                out.push(IpAddr::V6(Ipv6Addr::from(sin6.sin6_addr.s6_addr)));
            }
        }
        // SAFETY: the list from getifaddrs above.
        unsafe { libc::freeifaddrs(ifap) };
        out
    }
}

#[cfg(windows)]
mod imp {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    use windows_sys::Win32::NetworkManagement::IpHelper::{
        GetAdaptersAddresses, GAA_FLAG_SKIP_ANYCAST, GAA_FLAG_SKIP_DNS_SERVER,
        GAA_FLAG_SKIP_MULTICAST, IP_ADAPTER_ADDRESSES_LH,
    };
    use windows_sys::Win32::NetworkManagement::Ndis::IfOperStatusUp;
    use windows_sys::Win32::Networking::WinSock::{
        AF_INET, AF_INET6, AF_UNSPEC, SOCKADDR_IN, SOCKADDR_IN6,
    };

    pub(super) fn list() -> Vec<IpAddr> {
        let mut out = Vec::new();
        let mut size: u32 = 16 * 1024;
        let mut buf: Vec<u64> = Vec::new();
        let flags = GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER;
        for _ in 0..3 {
            buf.resize((size as usize).div_ceil(8), 0);
            // SAFETY: `buf` holds `size` writable bytes, 8-aligned.
            let r = unsafe {
                GetAdaptersAddresses(
                    u32::from(AF_UNSPEC),
                    flags,
                    std::ptr::null(),
                    buf.as_mut_ptr().cast::<IP_ADAPTER_ADDRESSES_LH>(),
                    &raw mut size,
                )
            };
            if r == 0 {
                break;
            }
            // ERROR_BUFFER_OVERFLOW: `size` says how much is needed.
            if r != 111 {
                return out;
            }
        }
        let mut cur = buf.as_ptr().cast::<IP_ADAPTER_ADDRESSES_LH>();
        while !cur.is_null() {
            // SAFETY: a node of the list GetAdaptersAddresses wrote.
            let a = unsafe { &*cur };
            cur = a.Next;
            if a.OperStatus != IfOperStatusUp {
                continue;
            }
            let mut u = a.FirstUnicastAddress;
            while !u.is_null() {
                // SAFETY: a node of the adapter's unicast list.
                let ua = unsafe { &*u };
                u = ua.Next;
                let sa = ua.Address.lpSockaddr;
                if sa.is_null() {
                    continue;
                }
                // SAFETY: lpSockaddr is non-null; its family says its type.
                let fam = unsafe { (*sa).sa_family };
                if fam == AF_INET {
                    // SAFETY: AF_INET → SOCKADDR_IN.
                    let sin = unsafe { &*sa.cast::<SOCKADDR_IN>() };
                    // SAFETY: the union's address as four bytes.
                    let b = unsafe { sin.sin_addr.S_un.S_un_b };
                    out.push(IpAddr::V4(Ipv4Addr::new(b.s_b1, b.s_b2, b.s_b3, b.s_b4)));
                } else if fam == AF_INET6 {
                    // SAFETY: AF_INET6 → SOCKADDR_IN6.
                    let sin6 = unsafe { &*sa.cast::<SOCKADDR_IN6>() };
                    // SAFETY: the union's address as sixteen bytes.
                    let b = unsafe { sin6.sin6_addr.u.Byte };
                    out.push(IpAddr::V6(Ipv6Addr::from(b)));
                }
            }
        }
        out
    }
}

#[cfg(not(any(unix, windows)))]
mod imp {
    pub(super) fn list() -> Vec<std::net::IpAddr> {
        Vec::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_loopback_or_link_local_addresses() {
        for ip in host_addresses() {
            assert!(!ip.is_loopback() && !is_link_local(&ip), "{ip}");
        }
        assert!(is_link_local(&"fe80::1".parse().unwrap()));
        assert!(is_link_local(&"169.254.1.1".parse().unwrap()));
        assert!(!is_link_local(&"fd00::1".parse().unwrap()));
    }
}
