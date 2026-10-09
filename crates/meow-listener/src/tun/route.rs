//! RAII route installation for the TUN inbound's `auto-route`.
//!
//! v1 deliberately routes only the fake-IP range into the device (see the
//! module docs in `mod.rs` for the loop-freedom argument). Routes are added
//! with the blocking `route_manager` API at listener startup and removed on
//! drop; a failed add is a warning, not a fatal error, because the device
//! subnet's own on-link route frequently already covers the range (in which
//! case some platforms report "route exists").

use ipnet::IpNet;
use route_manager::{Route, RouteManager};
use tracing::{debug, warn};

pub(super) struct RouteGuard {
    manager: RouteManager,
    installed: Vec<Route>,
}

impl RouteGuard {
    /// Install one on-link route per net through interface `if_index`.
    /// Individual failures are logged and skipped so a pre-existing
    /// equivalent route does not abort listener startup.
    pub(super) fn setup(if_index: u32, nets: &[IpNet]) -> std::io::Result<Self> {
        let mut manager = RouteManager::new()?;
        let mut installed = Vec::with_capacity(nets.len());
        for net in nets {
            let route = Route::new(net.network(), net.prefix_len()).with_if_index(if_index);
            match manager.add(&route) {
                Ok(()) => {
                    debug!("tun auto-route: added {net} via if_index {if_index}");
                    installed.push(route);
                }
                Err(e) => warn!(
                    "tun auto-route: failed to add {net} via if_index {if_index}: {e} \
                     (continuing — the device subnet may already cover it)"
                ),
            }
        }
        Ok(Self { manager, installed })
    }
}

impl Drop for RouteGuard {
    fn drop(&mut self) {
        for route in &self.installed {
            if let Err(e) = self.manager.delete(route) {
                warn!("tun auto-route: failed to remove {route}: {e}");
            }
        }
    }
}

/// What an interface is, as far as picking the outbound one goes: a
/// physical uplink (Wi-Fi, Ethernet) is preferred, an unknown one next, a
/// known virtual one (another VPN's tunnel, a VM / container bridge,
/// Tailscale, WireGuard …) last — any of them may hold the default route.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum IfaceKind {
    Physical,
    Unknown,
    Virtual,
}

/// Name prefixes of virtual interfaces on every platform (lower case).
const VIRTUAL_PREFIXES: &[&str] = &[
    "utun", "ipsec", "ppp", "tun", "tap", "wg", "tailscale", "zt", "docker", "br-", "veth",
    "virbr", "vnet", "vmnet", "vboxnet", "lxc", "lxd", "cni", "flannel", "kube", "cali",
    "bridge", "feth", "gif", "stf", "awdl", "llw", "anpi", "ap", "meow", "clash", "mihomo",
];

/// Words in Windows interface aliases that mark virtual adapters.
const VIRTUAL_WORDS: &[&str] = &[
    "vethernet", "hyper-v", "vmware", "virtualbox", "tailscale", "wireguard", "zerotier",
    "openvpn", "tap-", "wintun", "clash", "mihomo", "meta", "loopback", "vpn",
];

/// [`IfaceKind`] from the name alone (pure; see [`interface_kind`] for the
/// runtime check that also asks the OS).
pub fn kind_by_name(name: &str) -> IfaceKind {
    let lower = name.to_ascii_lowercase();
    if VIRTUAL_WORDS.iter().any(|w| lower.contains(w))
        || VIRTUAL_PREFIXES.iter().any(|p| {
            lower.starts_with(p)
                // `ap1` (Apple's AP), not `apple…`: a prefix ending in a
                // letter must be followed by a digit or a separator.
                && lower[p.len()..]
                    .chars()
                    .next()
                    .is_none_or(|c| !c.is_ascii_alphabetic() || p.ends_with('-'))
        })
    {
        return IfaceKind::Virtual;
    }
    // macOS / BSD Ethernet and Wi-Fi are `en*`; Linux's predictable names.
    if lower.starts_with("en") || lower.starts_with("eth") || lower.starts_with("wl") {
        return IfaceKind::Physical;
    }
    if lower.starts_with("wi-fi") || lower.starts_with("wlan") || lower.starts_with("ethernet") {
        return IfaceKind::Physical;
    }
    IfaceKind::Unknown
}

/// [`IfaceKind`] of a live interface: the name first, then (Linux) whether
/// it has a device behind it (`/sys/class/net/<if>/device`).
pub fn interface_kind(name: &str) -> IfaceKind {
    let by_name = kind_by_name(name);
    #[cfg(target_os = "linux")]
    {
        if by_name != IfaceKind::Virtual
            && std::path::Path::new("/sys/class/net").join(name).join("device").exists()
        {
            return IfaceKind::Physical;
        }
    }
    by_name
}

/// Detect the interface to bind outbound sockets to for global route scope
/// (#375): among the interfaces carrying an IPv4 default route, a physical
/// one before an unknown one before a virtual one, then the best metric
/// (see [`pick_default_interface`]).
///
/// - Linux reads every UP `0.0.0.0/0` entry of `/proc/net/route` (with its
///   metric).
/// - macOS and Windows list the routing table (`route_manager`). On
///   Windows the name is the interface alias (`Ethernet`, `Wi-Fi`, …).
///
/// The TUN's own split defaults are never the answer, even when they are
/// installed: a config reload detects the new configuration's interface
/// while the old global-scope listener's routes still exist (issue #695),
/// and the kernel lists `0.0.0.0/1` *before* the real default — so the
/// mask must be `/0`, not just the destination.
pub fn default_interface() -> std::io::Result<String> {
    pick_default_interface(default_candidates()?, interface_kind).ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "no IPv4 default route found in the routing table",
        )
    })
}

/// The interfaces holding an IPv4 default route, with their kind and
/// metric, best first (what [`default_interface`] chooses among).
pub fn default_interfaces() -> std::io::Result<Vec<(String, IfaceKind, u32)>> {
    let mut all: Vec<(String, IfaceKind, u32)> = default_candidates()?
        .into_iter()
        .filter(is_default)
        .filter_map(|r| r.if_name.map(|n| (interface_kind(&n), r.metric, n)))
        .map(|(k, m, n)| (n, k, m))
        .collect();
    all.sort_by_key(|(_, k, m)| (*k, *m));
    all.dedup_by(|a, b| a.0 == b.0);
    Ok(all)
}

fn default_candidates() -> std::io::Result<Vec<DefaultCandidate>> {
    #[cfg(target_os = "linux")]
    {
        let table = std::fs::read_to_string("/proc/net/route")?;
        Ok(parse_default_candidates(&table))
    }
    #[cfg(any(target_os = "macos", target_os = "windows"))]
    {
        let routes = RouteManager::new()?.list()?;
        Ok(routes.iter().map(default_candidate).collect())
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    {
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "default-interface auto-detection is not implemented on this platform \
             (Linux, macOS and Windows only; #375)",
        ))
    }
}

/// The fields of a routing-table entry that decide default-interface
/// detection, lifted out of `route_manager::Route` (whose
/// platform-specific accessors only exist on their own target) and
/// `/proc/net/route` so the selection is unit-testable on every host.
#[derive(Debug, Clone)]
struct DefaultCandidate {
    destination: std::net::IpAddr,
    prefix: u8,
    if_name: Option<String>,
    /// macOS `RTF_IFSCOPE`: a default that only applies to sockets already
    /// scoped to its interface — every non-primary interface has one.
    scoped: bool,
    /// Effective metric, lower wins. Windows: route metric + interface
    /// metric; Linux: the route's metric. macOS has no metric; the table
    /// order decides.
    metric: u32,
}

#[cfg(target_os = "macos")]
fn default_candidate(route: &Route) -> DefaultCandidate {
    DefaultCandidate {
        destination: route.destination(),
        prefix: route.prefix(),
        if_name: route.if_name().cloned(),
        scoped: route.if_scope(),
        metric: 0,
    }
}

#[cfg(target_os = "windows")]
fn default_candidate(route: &Route) -> DefaultCandidate {
    let interface_metric = route
        .if_index()
        .and_then(meow_common::outbound_iface::interface_metric_v4)
        .unwrap_or(0);
    DefaultCandidate {
        destination: route.destination(),
        prefix: route.prefix(),
        if_name: route.if_name().cloned(),
        scoped: false,
        metric: route.metric().unwrap_or(0).saturating_add(interface_metric),
    }
}

/// An unscoped IPv4 `0.0.0.0/0` route. Requiring prefix `/0` skips the
/// TUN's own `0.0.0.0/1` split route, which shares the destination.
fn is_default(r: &DefaultCandidate) -> bool {
    r.prefix == 0 && r.destination == std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED) && !r.scoped
}

/// Pure selection behind [`default_interface`]: among the unscoped IPv4
/// `0.0.0.0/0` routes, the interface ranked best by `kind` (physical,
/// unknown, virtual), then lowest metric, the first listed winning a tie.
fn pick_default_interface(
    routes: impl IntoIterator<Item = DefaultCandidate>,
    kind: impl Fn(&str) -> IfaceKind,
) -> Option<String> {
    routes
        .into_iter()
        .filter(is_default)
        .filter_map(|r| r.if_name.map(|name| ((kind(&name), r.metric), name)))
        .min_by_key(|(rank, _)| *rank)
        .map(|(_, name)| name)
}

/// `/proc/net/route` columns: Iface, Destination (hex LE), Gateway, Flags
/// (hex; bit 0 = RTF_UP), RefCnt, Use, Metric, Mask, … A default route has
/// destination `00000000`, mask `00000000` (a split `0.0.0.0/1` shares the
/// destination but has mask `00000080`) and the UP flag set. Only those
/// are returned.
#[cfg(any(target_os = "linux", test))]
fn parse_default_candidates(table: &str) -> Vec<DefaultCandidate> {
    let mut out = Vec::new();
    for line in table.lines().skip(1) {
        let cols: Vec<&str> = line.split_whitespace().collect();
        let [iface, dest, _gateway, flags, _refcnt, _use, metric, mask, ..] = cols[..] else {
            continue;
        };
        let up = u32::from_str_radix(flags, 16).is_ok_and(|f| f & 0x1 != 0);
        if dest == "00000000" && mask == "00000000" && up {
            out.push(DefaultCandidate {
                destination: std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),
                prefix: 0,
                if_name: Some(iface.to_string()),
                scoped: false,
                metric: metric.parse().unwrap_or(0),
            });
        }
    }
    out
}

/// [`default_interface`] over a `/proc/net/route` table with names alone
/// deciding the kind (unit tests).
#[cfg(test)]
fn parse_default_interface(table: &str) -> Option<String> {
    pick_default_interface(parse_default_candidates(table), kind_by_name)
}

#[cfg(test)]
mod tests {
    use super::{
        kind_by_name, parse_default_interface, pick_default_interface, DefaultCandidate,
        IfaceKind,
    };

    fn pick(
        routes: impl IntoIterator<Item = DefaultCandidate>,
    ) -> Option<String> {
        pick_default_interface(routes, kind_by_name)
    }

    fn candidate(net: &str, if_name: &str, scoped: bool, metric: u32) -> DefaultCandidate {
        let net: ipnet::IpNet = net.parse().unwrap();
        DefaultCandidate {
            destination: net.addr(),
            prefix: net.prefix_len(),
            if_name: Some(if_name.to_string()),
            scoped,
            metric,
        }
    }

    /// A macOS table with two uplinks: the primary's default is unscoped,
    /// the secondary's carries `RTF_IFSCOPE` (`netstat -rn` flags `UGScg`
    /// vs `UGScIg`).
    #[test]
    fn macos_picks_the_unscoped_default() {
        let table = [
            candidate("0.0.0.0/0", "en0", true, 0),
            candidate("0.0.0.0/0", "en1", false, 0),
            candidate("127.0.0.0/8", "lo0", false, 0),
            candidate("192.168.0.0/24", "en1", false, 0),
            candidate("::/0", "utun0", false, 0),
        ];
        assert_eq!(pick(table).as_deref(), Some("en1"));
    }

    /// Windows ranks defaults by route metric + interface metric; with
    /// automatic metrics the route metric ties at 0 and the interface
    /// decides.
    #[test]
    fn windows_picks_the_lowest_effective_metric() {
        let table = [
            candidate("0.0.0.0/0", "Wi-Fi", false, 35),
            candidate("0.0.0.0/0", "Ethernet", false, 25),
            candidate("::/0", "Ethernet 2", false, 5),
        ];
        assert_eq!(pick(table).as_deref(), Some("Ethernet"));
        // A tie keeps table order.
        let tie = [
            candidate("0.0.0.0/0", "Ethernet", false, 25),
            candidate("0.0.0.0/0", "Wi-Fi", false, 25),
        ];
        assert_eq!(pick(tie).as_deref(), Some("Ethernet"));
    }

    /// Issue #695, on the route-table platforms: a reload detects the
    /// interface while the running global listener's split defaults are
    /// installed. They share the default's destination (and on Windows may
    /// undercut its metric) but are `/1`, never `/0`.
    #[test]
    fn route_table_detection_skips_the_tun_split_default_routes() {
        let table = [
            candidate("0.0.0.0/1", "utun7", false, 0),
            candidate("128.0.0.0/1", "utun7", false, 0),
            candidate("::/1", "utun7", false, 0),
            candidate("8000::/1", "utun7", false, 0),
            candidate("0.0.0.0/0", "en0", false, 10),
        ];
        assert_eq!(
            pick(table.clone()).as_deref(),
            Some("en0")
        );
        // Only the split routes left (no real default): nothing to bind to.
        let only_split = table.into_iter().filter(|r| r.prefix == 1);
        assert_eq!(pick(only_split), None);
        // A default whose interface has no resolvable name is unusable.
        let nameless = DefaultCandidate {
            if_name: None,
            ..candidate("0.0.0.0/0", "x", false, 0)
        };
        assert_eq!(pick([nameless]), None);
    }

    /// Another VPN / a VM bridge holding a better default than the
    /// physical uplink: the physical one is still chosen (users' "直连走错
    /// 网卡"), on every platform.
    #[test]
    fn a_physical_uplink_wins_over_virtual_defaults() {
        // macOS: another VPN's utun took the unscoped default.
        let mac = [
            candidate("0.0.0.0/0", "utun3", false, 0),
            candidate("0.0.0.0/0", "en0", false, 0),
        ];
        assert_eq!(pick(mac).as_deref(), Some("en0"));
        // Windows: the WSL / Hyper-V switch has a lower metric.
        let win = [
            candidate("0.0.0.0/0", "vEthernet (WSL)", false, 5),
            candidate("0.0.0.0/0", "Wi-Fi", false, 35),
        ];
        assert_eq!(pick(win).as_deref(), Some("Wi-Fi"));
        // Linux: WireGuard's default ahead of (and cheaper than) the NIC.
        let linux = "\
Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT
wg0\t00000000\t00000000\t0001\t0\t0\t0\t00000000\t0\t0\t0
enp3s0\t00000000\t0101A8C0\t0003\t0\t0\t100\t00000000\t0\t0\t0
wlan0\t00000000\t0101A8C0\t0003\t0\t0\t600\t00000000\t0\t0\t0
";
        assert_eq!(parse_default_interface(linux).as_deref(), Some("enp3s0"));
        // Only virtual ones: the best of them (better than nothing).
        let only_vpn = [
            candidate("0.0.0.0/0", "utun3", false, 0),
            candidate("0.0.0.0/0", "tailscale0", false, 0),
        ];
        assert_eq!(pick(only_vpn).as_deref(), Some("utun3"));
    }

    #[test]
    fn interface_kinds_by_name() {
        for n in ["en0", "en7", "eth0", "enp3s0", "wlan0", "wlp2s0", "Wi-Fi", "Ethernet"] {
            assert_eq!(kind_by_name(n), IfaceKind::Physical, "{n}");
        }
        for n in [
            "utun3", "ipsec0", "ppp0", "tun0", "tap1", "wg0", "tailscale0", "zt5u4y", "docker0",
            "br-1a2b", "veth9", "virbr0", "vmnet8", "vboxnet0", "bridge100", "awdl0", "llw0",
            "anpi0", "ap1", "meow-tun", "vEthernet (WSL)", "VMware Network Adapter VMnet8",
            "Tailscale", "OpenVPN TAP-Windows6",
        ] {
            assert_eq!(kind_by_name(n), IfaceKind::Virtual, "{n}");
        }
        assert_eq!(kind_by_name("lo0"), IfaceKind::Unknown);
        assert_eq!(kind_by_name("apple0"), IfaceKind::Unknown);
    }

    /// The real routing table, unprivileged: listing routes needs no root.
    /// A host without an IPv4 default route (offline CI) legitimately has
    /// nothing to detect; anything detected must be a real interface.
    #[cfg(target_os = "macos")]
    #[test]
    fn macos_detects_a_real_interface_from_the_live_table() {
        match super::default_interface() {
            Ok(name) => {
                let c_name = std::ffi::CString::new(name.clone()).unwrap();
                // SAFETY: `c_name` is a valid NUL-terminated string.
                let index = unsafe { libc::if_nametoindex(c_name.as_ptr()) };
                assert_ne!(index, 0, "detected interface '{name}' must exist");
                println!("detected default interface: {name} (index {index})");
            }
            Err(e) => assert_eq!(e.kind(), std::io::ErrorKind::NotFound, "{e}"),
        }
    }

    const SAMPLE: &str = "\
Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT
docker0\t000011AC\t00000000\t0001\t0\t0\t0\t0000FFFF\t0\t0\t0
eth0\t00000000\t0101A8C0\t0003\t0\t0\t100\t00000000\t0\t0\t0
eth0\t0001A8C0\t00000000\t0001\t0\t0\t100\t00FFFFFF\t0\t0\t0
";

    #[test]
    fn picks_the_up_default_route_interface() {
        assert_eq!(parse_default_interface(SAMPLE).as_deref(), Some("eth0"));
    }

    #[test]
    fn ignores_down_defaults_and_empty_tables() {
        // Same default entry but with the UP bit clear → not a candidate.
        let down = SAMPLE.replace("00000000\t0101A8C0\t0003", "00000000\t0101A8C0\t0002");
        assert_eq!(parse_default_interface(&down), None);
        assert_eq!(parse_default_interface("Iface\tDestination\n"), None);
        assert_eq!(parse_default_interface(""), None);
    }

    /// Issue #695: a reload detects the interface while the running global
    /// listener's split defaults are installed, and the kernel lists
    /// `0.0.0.0/1` ahead of the real default (captured from a live table
    /// with `0.0.0.0/1` + `128.0.0.0/1` on the TUN).
    #[test]
    fn skips_the_tun_split_default_routes() {
        let table = "\
Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT
meow-tun\t00000000\t00000000\t0001\t0\t0\t0\t00000080\t0\t0\t0
eth0\t00000000\t010011AC\t0003\t0\t0\t0\t00000000\t0\t0\t0
meow-tun\t00000080\t00000000\t0001\t0\t0\t0\t00000080\t0\t0\t0
eth0\t000011AC\t00000000\t0001\t0\t0\t0\t0000FFFF\t0\t0\t0
";
        assert_eq!(parse_default_interface(table).as_deref(), Some("eth0"));
        // Only the split routes left (no real default): nothing to bind to.
        let only_split: String = table
            .lines()
            .filter(|l| !l.starts_with("eth0"))
            .map(|l| format!("{l}\n"))
            .collect();
        assert_eq!(parse_default_interface(&only_split), None);
    }
}
