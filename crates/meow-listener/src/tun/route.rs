//! RAII route installation for the TUN inbound's `auto-route`.
//!
//! v1 deliberately routes only the fake-IP range into the device (see the
//! module docs in `mod.rs` for the loop-freedom argument). Routes are added
//! with the blocking `route_manager` API at listener startup and removed on
//! drop. In fake-IP scope a failed add is a warning, not a fatal error,
//! because the device subnet's own on-link route frequently already covers
//! the range (in which case some platforms report "route exists"). In
//! global scope (PaoPao) it is fatal, except that a route another VPN
//! already holds is installed as its two halves ([`RouteFailure`]).

use ipnet::IpNet;
use meow_common::outbound_balance::{Link, LinkKind, LinkSource};
use meow_common::route_table::{DefaultVia, RawRoute, RouteIfaceKind, RouteTable};
use route_manager::{Route, RouteManager};
use tracing::{debug, warn};

pub(super) struct RouteGuard {
    manager: RouteManager,
    installed: Vec<Route>,
    /// PaoPao: a route collided with someone else's identical one (another
    /// VPN's `/1`) and went in one level more specific instead.
    conflict: bool,
}

/// How [`RouteGuard::setup`] treats a route that cannot be added.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum RouteFailure {
    /// Fake-IP scope: log and go on — the device subnet's own on-link
    /// route frequently covers the range already.
    Skip,
    /// PaoPao, global scope: a route someone else already holds (another
    /// VPN's `/1`) is installed as its two halves instead, which are more
    /// specific and so still win; anything else fails the setup. A partly
    /// routed device must not report success.
    SplitOrFail,
}

/// "That exact route already exists" (`EEXIST`; Windows
/// `ERROR_OBJECT_ALREADY_EXISTS`).
fn is_route_exists(e: &std::io::Error) -> bool {
    e.kind() == std::io::ErrorKind::AlreadyExists
        || (cfg!(windows) && matches!(e.raw_os_error(), Some(5010 | 183)))
}

/// Whether `routes` (destination, prefix, interface index) already hold
/// exactly `net` on interface `if_index`.
fn already_on_device(
    routes: impl IntoIterator<Item = (std::net::IpAddr, u8, Option<u32>)>,
    net: &IpNet,
    if_index: u32,
) -> bool {
    routes.into_iter().any(|(dest, prefix, index)| {
        index == Some(if_index) && prefix == net.prefix_len() && dest == net.network()
    })
}

/// Pure driver behind [`RouteGuard::setup`]: adds every net through `add`
/// and returns whether any had to be split. On error the nets added so far
/// have been reported to `add` — the caller removes them.
fn install_nets(
    nets: &[IpNet],
    on_failure: RouteFailure,
    mut add: impl FnMut(&IpNet) -> std::io::Result<()>,
) -> std::io::Result<bool> {
    let mut conflict = false;
    for net in nets {
        let Err(e) = add(net) else { continue };
        match on_failure {
            RouteFailure::Skip => warn!(
                "tun auto-route: failed to add {net}: {e} \
                 (continuing — the device subnet may already cover it)"
            ),
            RouteFailure::SplitOrFail if is_route_exists(&e) => {
                let halves = net
                    .subnets(net.prefix_len() + 1)
                    .map_err(|_| std::io::Error::other(format!("route {net} already exists")))?;
                warn!(
                    "tun auto-route: {net} is already routed by someone else (another \
                     VPN in full-tunnel mode?); installing its two halves instead"
                );
                conflict = true;
                for half in halves {
                    add(&half).map_err(|e| {
                        std::io::Error::new(
                            e.kind(),
                            format!(
                                "route {half} (half of {net}, which another VPN already \
                                 holds) could not be added: {e}"
                            ),
                        )
                    })?;
                }
            }
            RouteFailure::SplitOrFail => {
                return Err(std::io::Error::new(
                    e.kind(),
                    format!("route {net} could not be added: {e}"),
                ));
            }
        }
    }
    Ok(conflict)
}

impl RouteGuard {
    /// Install one on-link route per net through interface `if_index`.
    /// What a failed add does is `on_failure`'s call; when the setup fails
    /// the routes already added are removed again.
    pub(super) fn setup(
        if_index: u32,
        nets: &[IpNet],
        on_failure: RouteFailure,
    ) -> std::io::Result<Self> {
        let mut guard = Self {
            manager: RouteManager::new()?,
            installed: Vec::with_capacity(nets.len()),
            conflict: false,
        };
        let Self {
            manager, installed, ..
        } = &mut guard;
        // On error `guard` drops here and removes what went in.
        let conflict = install_nets(nets, on_failure, |net| {
            let route = Route::new(net.network(), net.prefix_len()).with_if_index(if_index);
            match manager.add(&route) {
                Ok(()) => debug!("tun auto-route: added {net} via if_index {if_index}"),
                // The identical route is already on this very device (a
                // device that outlived an unclean exit of ours, or its own
                // subnet): it is the route we wanted — adopt it, so it is
                // removed with the rest, instead of taking it for another
                // VPN's.
                Err(e)
                    if is_route_exists(&e)
                        && manager.list().is_ok_and(|all| {
                            already_on_device(
                                all.iter()
                                    .map(|r| (r.destination(), r.prefix(), r.if_index())),
                                net,
                                if_index,
                            )
                        }) =>
                {
                    debug!("tun auto-route: {net} is already on if_index {if_index}; adopted");
                }
                Err(e) => return Err(e),
            }
            installed.push(route);
            Ok(())
        })?;
        guard.conflict = conflict;
        Ok(guard)
    }

    /// Whether a route had to be installed as its halves.
    pub(super) fn conflict(&self) -> bool {
        self.conflict
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
    "utun",
    "ipsec",
    "ppp",
    "tun",
    "tap",
    "wg",
    "tailscale",
    "zt",
    "docker",
    "br-",
    "veth",
    "virbr",
    "vnet",
    "vmnet",
    "vboxnet",
    "lxc",
    "lxd",
    "cni",
    "flannel",
    "kube",
    "cali",
    "bridge",
    "feth",
    "gif",
    "stf",
    "awdl",
    "llw",
    "anpi",
    "ap",
    "meow",
    "clash",
    "mihomo",
];

/// Words in Windows interface aliases that mark virtual adapters.
const VIRTUAL_WORDS: &[&str] = &[
    "vethernet",
    "hyper-v",
    "vmware",
    "virtualbox",
    "tailscale",
    "wireguard",
    "zerotier",
    "openvpn",
    "tap-",
    "wintun",
    "clash",
    "mihomo",
    "meta",
    "loopback",
    "vpn",
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
            && std::path::Path::new("/sys/class/net")
                .join(name)
                .join("device")
                .exists()
        {
            return IfaceKind::Physical;
        }
    }
    by_name
}

/// The ranking the outbound binding starts from (PaoPao: what is actually
/// bound is [`choose_default`]'s call over [`default_interfaces`], which
/// ranks the same way; this single-answer form is kept for the tests).
///
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
#[cfg(test)]
#[allow(dead_code)] // only the macOS / Windows live test reads it
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
    r.prefix == 0
        && r.destination == std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED)
        && !r.scoped
}

/// Pure selection behind [`default_interface`]: among the unscoped IPv4
/// `0.0.0.0/0` routes, the interface ranked best by `kind` (physical,
/// unknown, virtual), then lowest metric, the first listed winning a tie.
#[cfg(test)]
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

/// PaoPao: [`IfaceKind`] as the route snapshot names it.
pub fn route_kind(name: &str) -> RouteIfaceKind {
    route_kind_of(interface_kind(name))
}

fn route_kind_of(kind: IfaceKind) -> RouteIfaceKind {
    match kind {
        IfaceKind::Physical => RouteIfaceKind::Physical,
        IfaceKind::Virtual => RouteIfaceKind::OtherVpn,
        IfaceKind::Unknown => RouteIfaceKind::Other,
    }
}

/// One `route_manager` row in the platform-neutral shape the snapshot is
/// built from. Rows without a named interface (Linux multipath, a vanished
/// interface) are of no use to a per-socket binding.
fn raw_route(route: &Route) -> Option<RawRoute> {
    let iface = route.if_name()?.clone();
    let net = IpNet::new(route.destination(), route.prefix()).ok()?;
    #[cfg(any(target_os = "linux", target_os = "windows"))]
    let metric = route.metric().unwrap_or(0);
    #[cfg(not(any(target_os = "linux", target_os = "windows")))]
    let metric = 0;
    #[cfg(target_os = "linux")]
    let table = Some(route.table());
    #[cfg(not(target_os = "linux"))]
    let table = None;
    #[cfg(target_os = "macos")]
    let scoped = route.if_scope();
    #[cfg(not(target_os = "macos"))]
    let scoped = false;
    Some(RawRoute {
        net,
        iface,
        index: route.if_index().unwrap_or(0),
        gateway: route.gateway(),
        metric,
        table,
        scoped,
    })
}

/// PaoPao: the whole system routing table (every Linux table — policy
/// tables included, which `/proc/net/route` does not show). Listing needs
/// no privilege.
pub fn system_routes() -> std::io::Result<Vec<RawRoute>> {
    Ok(RouteManager::new()?
        .list()?
        .iter()
        .filter_map(raw_route)
        .collect())
}

/// PaoPao: read the routing table and build the snapshot the dial path
/// follows (see `meow_common::route_table`).
pub fn route_snapshot() -> std::io::Result<RouteTable> {
    Ok(RouteTable::build(
        system_routes()?,
        meow_common::route_table::is_own_tun,
        route_kind,
    ))
}

/// PaoPao (`tun.outbound-interfaces`): every interface holding a default
/// route in `raw`, for spreading outbound connections over several of them
/// — pure. Either family counts, and so does a macOS interface-scoped
/// default (every non-primary interface has one, and a socket bound to
/// that interface uses it). Linux policy tables do not count: a socket
/// bound to a device is still routed by the main table. Our own TUN and
/// loopback are left out. Physical interfaces first, then by name.
pub fn uplink_links(
    raw: &[RawRoute],
    kind: impl Fn(&str) -> IfaceKind,
    own_tun: impl Fn(&str) -> bool,
) -> Vec<Link> {
    const LINUX_MAIN_TABLE: u8 = 254;
    let mut links: Vec<Link> = Vec::new();
    for r in raw {
        let lower = r.iface.to_ascii_lowercase();
        if r.net.prefix_len() != 0
            || r.iface.is_empty()
            || r.table.is_some_and(|t| t != LINUX_MAIN_TABLE)
            || lower == "lo"
            || lower == "lo0"
            || lower.starts_with("loopback")
            || own_tun(&r.iface)
        {
            continue;
        }
        let v4 = r.net.addr().is_ipv4();
        let at = match links.iter().position(|l| l.name == r.iface) {
            Some(at) => at,
            None => {
                links.push(Link {
                    name: r.iface.clone(),
                    index: r.index,
                    kind: link_kind(kind(&r.iface)),
                    v4: false,
                    v6: false,
                    strict_rp_filter: false,
                });
                links.len() - 1
            }
        };
        let link = &mut links[at];
        link.v4 |= v4;
        link.v6 |= !v4;
        if link.index == 0 {
            link.index = r.index;
        }
    }
    links.sort_by(|a, b| (a.kind, &a.name).cmp(&(b.kind, &b.name)));
    links
}

fn link_kind(kind: IfaceKind) -> LinkKind {
    match kind {
        IfaceKind::Physical => LinkKind::Physical,
        IfaceKind::Unknown => LinkKind::Unknown,
        IfaceKind::Virtual => LinkKind::Virtual,
    }
}

/// Linux: whether reverse-path filtering is strict (`1`) for `iface` — the
/// larger of the interface's and the `all` setting applies. Replies to a
/// socket bound to such an interface are dropped unless it also is the
/// best route back to the peer.
#[cfg(target_os = "linux")]
fn strict_rp_filter(iface: &str) -> bool {
    let read = |name: &str| -> u8 {
        std::fs::read_to_string(format!("/proc/sys/net/ipv4/conf/{name}/rp_filter"))
            .ok()
            .and_then(|v| v.trim().parse().ok())
            .unwrap_or(0)
    };
    // A name with a path separator is not an interface.
    !iface.contains('/') && read("all").max(read(iface)) == 1
}

#[cfg(not(target_os = "linux"))]
fn strict_rp_filter(_iface: &str) -> bool {
    false
}

/// PaoPao: the system's interfaces as outbound balancing sees them — the
/// ones holding a default route, read from the routing table.
#[derive(Debug, Clone, Default)]
pub struct SystemLinks(Vec<Link>);

impl SystemLinks {
    /// From routes already read (the monitor's own pass).
    pub fn from_routes(raw: &[RawRoute]) -> Self {
        let mut links = uplink_links(raw, interface_kind, meow_common::route_table::is_own_tun);
        for link in &mut links {
            link.strict_rp_filter = link.kind != LinkKind::Virtual && strict_rp_filter(&link.name);
        }
        Self(links)
    }

    /// Reading the routing table now.
    pub fn read() -> std::io::Result<Self> {
        Ok(Self::from_routes(&system_routes()?))
    }

    pub fn into_links(self) -> Vec<Link> {
        self.0
    }
}

impl LinkSource for SystemLinks {
    fn links(&self) -> Vec<Link> {
        self.0.clone()
    }

    fn kind_of(&self, name: &str) -> Option<LinkKind> {
        meow_common::outbound_iface::interface_exists(name)?;
        if meow_common::route_table::is_own_tun(name) {
            return Some(LinkKind::Virtual);
        }
        Some(link_kind(interface_kind(name)))
    }
}

/// PaoPao: block on the OS's route-change notifications, calling
/// `on_change` for each. Returns when the listener cannot be opened or
/// ends.
pub(super) fn watch_route_changes(on_change: impl Fn()) -> std::io::Result<()> {
    let mut listener = RouteManager::listener()?;
    loop {
        listener.listen()?;
        on_change();
    }
}

/// PaoPao: a virtual interface that is plumbing rather than somebody's VPN
/// tunnel — a container bridge, a VM switch, a veth pair. Their routes are
/// followed like any other, but the UI does not list them as VPNs.
pub fn is_container_like(name: &str) -> bool {
    const PREFIXES: &[&str] = &[
        "docker",
        "br-",
        "veth",
        "virbr",
        "vnet",
        "vmnet",
        "vboxnet",
        "lxc",
        "lxd",
        "cni",
        "flannel",
        "kube",
        "cali",
        "bridge",
        "feth",
        "awdl",
        "llw",
        "anpi",
        "ap",
        "gif",
        "stf",
        "podman",
        "vethernet",
    ];
    const WORDS: &[&str] = &["hyper-v", "wsl", "virtualbox", "vmware", "loopback"];
    let lower = name.to_ascii_lowercase();
    PREFIXES.iter().any(|p| lower.starts_with(p)) || WORDS.iter().any(|w| lower.contains(w))
}

/// PaoPao: every interface's addresses (`address/prefix`), for display.
/// Empty where the platform has no `getifaddrs` (Windows).
#[cfg(unix)]
pub fn interface_addresses() -> Vec<(String, ipnet::IpNet)> {
    use std::net::{Ipv4Addr, Ipv6Addr};

    /// The address in a `sockaddr`, when it is an IP one.
    ///
    /// # Safety
    /// `sa` is null or points at a `sockaddr` at least as large as its
    /// family says (what `getifaddrs` hands out).
    unsafe fn ip_of(sa: *const libc::sockaddr) -> Option<std::net::IpAddr> {
        if sa.is_null() {
            return None;
        }
        match i32::from((*sa).sa_family) {
            libc::AF_INET => {
                let a = &*(sa as *const libc::sockaddr_in);
                Some(Ipv4Addr::from(u32::from_be(a.sin_addr.s_addr)).into())
            }
            libc::AF_INET6 => {
                let a = &*(sa as *const libc::sockaddr_in6);
                Some(Ipv6Addr::from(a.sin6_addr.s6_addr).into())
            }
            _ => None,
        }
    }

    let mut out = Vec::new();
    let mut list: *mut libc::ifaddrs = std::ptr::null_mut();
    // SAFETY: `getifaddrs` fills `list` with a linked list it owns until
    // `freeifaddrs`; every node is read before that call and nothing is
    // kept past it.
    unsafe {
        if libc::getifaddrs(&mut list) != 0 {
            return out;
        }
        let mut cur = list;
        while !cur.is_null() {
            let ifa = &*cur;
            cur = ifa.ifa_next;
            let Some(addr) = ip_of(ifa.ifa_addr) else {
                continue;
            };
            let prefix = match ip_of(ifa.ifa_netmask) {
                Some(std::net::IpAddr::V4(m)) => u32::from(m).leading_ones() as u8,
                Some(std::net::IpAddr::V6(m)) => u128::from(m).leading_ones() as u8,
                None => {
                    if addr.is_ipv4() {
                        32
                    } else {
                        128
                    }
                }
            };
            let name = std::ffi::CStr::from_ptr(ifa.ifa_name)
                .to_string_lossy()
                .into_owned();
            if let Ok(net) = ipnet::IpNet::new(addr, prefix) {
                out.push((name, net));
            }
        }
        libc::freeifaddrs(list);
    }
    out
}

#[cfg(not(unix))]
pub fn interface_addresses() -> Vec<(String, ipnet::IpNet)> {
    Vec::new()
}

/// What [`choose_default`] decided.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct DefaultChoice {
    /// The interface outbound sockets should bind to by default; `None` =
    /// nothing usable was found (keep whatever is bound).
    pub iface: Option<String>,
    /// No physical interface holds a default route.
    pub physical_route_missing: bool,
    /// Another VPN holds the default route (or a split equivalent).
    pub full_tunnel: Option<String>,
    /// The physical uplink, wherever the default binding goes (a VPN
    /// client's own traffic leaves by it).
    pub physical: Option<String>,
}

/// PaoPao (`tun.default-via`): pure choice of the default outbound
/// interface.
///
/// - `physical` (the default): the best non-virtual interface holding a
///   default route. When there is none — another VPN replaced the default —
///   the binding is **not** moved to the VPN: the current one is kept (or,
///   with nothing bound yet, any physical interface that still has a route)
///   and `physical_route_missing` is reported. Only when no physical
///   interface is known at all does it fall back to the best virtual
///   default, because global route scope cannot run unbound.
/// - `other-vpn`: the VPN holding the default route (or a split
///   equivalent) while there is one, the physical choice otherwise.
///
/// `candidates` are the interfaces holding an unscoped IPv4 `0.0.0.0/0`,
/// best first, our own TUN excluded; `current` is what is bound now.
pub(super) fn choose_default(
    candidates: &[(String, IfaceKind, u32)],
    table: &RouteTable,
    via: DefaultVia,
    current: Option<(&str, IfaceKind)>,
) -> DefaultChoice {
    let physical_default = candidates
        .iter()
        .find(|(_, kind, _)| *kind != IfaceKind::Virtual)
        .map(|(name, ..)| name.clone());
    // A virtual interface holding a plain default is a full tunnel even
    // when the snapshot (built a moment earlier or later) did not list it.
    let full_tunnel = table
        .full_tunnel()
        .map(|e| e.iface.to_string())
        .or_else(|| {
            candidates
                .iter()
                .find(|(_, kind, _)| *kind == IfaceKind::Virtual)
                .map(|(name, ..)| name.clone())
        });
    let physical_route_missing = physical_default.is_none();
    let physical = physical_default
        .or_else(|| {
            current
                .filter(|(_, kind)| *kind != IfaceKind::Virtual)
                .map(|(name, _)| name.to_owned())
        })
        .or_else(|| table.any_physical().map(|e| e.iface.to_string()));
    let iface = match (via, &full_tunnel) {
        (DefaultVia::OtherVpn, Some(vpn)) => Some(vpn.clone()),
        _ => physical
            .clone()
            .or_else(|| current.map(|(name, _)| name.to_owned()))
            .or_else(|| candidates.first().map(|(name, ..)| name.clone())),
    };
    DefaultChoice {
        iface,
        physical_route_missing,
        full_tunnel,
        physical,
    }
}

/// PaoPao: [`choose_default`] over the live routing table. `table` is the
/// snapshot read in the same pass.
pub(super) fn detect_default(
    table: &RouteTable,
    via: DefaultVia,
    current: Option<&str>,
) -> std::io::Result<DefaultChoice> {
    let candidates: Vec<_> = default_interfaces()?
        .into_iter()
        .filter(|(name, ..)| !meow_common::route_table::is_own_tun(name))
        .collect();
    let current = current.map(|name| (name, interface_kind(name)));
    Ok(choose_default(&candidates, table, via, current))
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
    use super::{choose_default, install_nets, DefaultChoice, RouteFailure};
    use super::{
        kind_by_name, parse_default_interface, pick_default_interface, DefaultCandidate, IfaceKind,
    };
    use meow_common::route_table::{DefaultVia, RawRoute, RouteIfaceKind, RouteTable};

    fn nets(list: &[&str]) -> Vec<ipnet::IpNet> {
        list.iter().map(|n| n.parse().unwrap()).collect()
    }

    /// Records what was added; fails the nets in `taken` with `EEXIST` and
    /// the ones in `broken` with `EPERM`.
    fn install(
        list: &[&str],
        on_failure: RouteFailure,
        taken: &[&str],
        broken: &[&str],
    ) -> (std::io::Result<bool>, Vec<String>) {
        let mut added = Vec::new();
        let result = install_nets(&nets(list), on_failure, |net| {
            let name = net.to_string();
            if taken.contains(&name.as_str()) {
                return Err(std::io::Error::from(std::io::ErrorKind::AlreadyExists));
            }
            if broken.contains(&name.as_str()) {
                return Err(std::io::Error::from(std::io::ErrorKind::PermissionDenied));
            }
            added.push(name);
            Ok(())
        });
        (result, added)
    }

    /// PaoPao (`tun.outbound-interfaces`): what can be a member is every
    /// interface holding a default route — a macOS interface-scoped one
    /// counts, a Linux policy-table one and a split `/1` do not; our own
    /// TUN and loopback are never listed; the family is kept per interface.
    #[test]
    fn uplink_links_are_the_interfaces_holding_a_default_route() {
        use meow_common::outbound_balance::LinkKind;
        let route = |net: &str, iface: &str, index: u32| RawRoute {
            net: net.parse().unwrap(),
            iface: iface.into(),
            index,
            gateway: None,
            metric: 0,
            table: None,
            scoped: false,
        };
        let raw = vec![
            route("0.0.0.0/0", "en0", 4),
            route("::/0", "en0", 4),
            // macOS: the second NIC's default only applies to sockets
            // bound to it — exactly what a member's socket is.
            RawRoute {
                scoped: true,
                ..route("0.0.0.0/0", "en7", 9)
            },
            route("192.168.1.0/24", "en0", 4),
            route("10.8.0.0/16", "utun6", 12),
            route("0.0.0.0/0", "utun6", 12),
            route("0.0.0.0/1", "meow-tun", 30),
            route("0.0.0.0/0", "meow-tun", 30),
            route("0.0.0.0/0", "lo0", 1),
            route("0.0.0.0/0", "", 0),
            // Linux: a default in a policy table does not route a socket
            // bound to the device; the main table's does.
            RawRoute {
                table: Some(52),
                ..route("0.0.0.0/0", "wlan0", 3)
            },
            RawRoute {
                table: Some(254),
                ..route("::/0", "eth1", 2)
            },
            route("0.0.0.0/0", "以太网", 15),
        ];
        let links = super::uplink_links(&raw, kind_by_name, |name| name == "meow-tun");
        let got: Vec<(&str, u32, LinkKind, bool, bool)> = links
            .iter()
            .map(|l| (l.name.as_str(), l.index, l.kind, l.v4, l.v6))
            .collect();
        assert_eq!(
            got,
            [
                ("en0", 4, LinkKind::Physical, true, true),
                ("en7", 9, LinkKind::Physical, true, false),
                ("eth1", 2, LinkKind::Physical, false, true),
                ("以太网", 15, LinkKind::Unknown, true, false),
                ("utun6", 12, LinkKind::Virtual, true, false),
            ]
        );
        assert!(links.iter().all(|l| !l.strict_rp_filter));
        assert!(super::uplink_links(&[], kind_by_name, |_| false).is_empty());
    }

    /// PaoPao: another VPN already holds `0.0.0.0/1` + `128.0.0.0/1`
    /// (OpenVPN `def1`): ours go in as four `/2`s, which still win, and
    /// the conflict is reported.
    #[test]
    fn a_split_default_someone_else_holds_goes_in_as_its_halves() {
        let split = ["0.0.0.0/1", "128.0.0.0/1"];
        let (result, added) = install(&split, RouteFailure::SplitOrFail, &split, &[]);
        assert!(result.unwrap(), "conflict must be reported");
        assert_eq!(
            added,
            ["0.0.0.0/2", "64.0.0.0/2", "128.0.0.0/2", "192.0.0.0/2"]
        );

        // macOS shape: only the shared `128.0.0.0/1` collides; its halves
        // do not use the all-zero key either.
        let mac = ["64.0.0.0/2", "128.0.0.0/1"];
        let (result, added) = install(&mac, RouteFailure::SplitOrFail, &["128.0.0.0/1"], &[]);
        assert!(result.unwrap());
        assert_eq!(added, ["64.0.0.0/2", "128.0.0.0/2", "192.0.0.0/2"]);

        // Nothing collides: no conflict.
        let (result, added) = install(&split, RouteFailure::SplitOrFail, &[], &[]);
        assert!(!result.unwrap());
        assert_eq!(added, split);
    }

    /// PaoPao: in global scope any other failure — or a half that cannot
    /// go in either — fails the setup instead of leaving the device partly
    /// routed; fake-IP scope keeps skipping.
    #[test]
    fn a_route_that_cannot_be_added_fails_global_scope_only() {
        let split = ["0.0.0.0/1", "128.0.0.0/1"];
        let (result, added) = install(&split, RouteFailure::SplitOrFail, &[], &["128.0.0.0/1"]);
        let err = result.unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::PermissionDenied);
        assert!(err.to_string().contains("128.0.0.0/1"), "{err}");
        assert_eq!(added, ["0.0.0.0/1"]);

        let (result, _) = install(
            &split,
            RouteFailure::SplitOrFail,
            &["0.0.0.0/1", "0.0.0.0/2"],
            &[],
        );
        let err = result.unwrap_err();
        assert!(err.to_string().contains("half of 0.0.0.0/1"), "{err}");

        let (result, added) = install(&split, RouteFailure::Skip, &["0.0.0.0/1"], &["128.0.0.0/1"]);
        assert!(!result.unwrap());
        assert!(added.is_empty());
    }

    /// A route that is already on our own device is not somebody else's:
    /// only the same destination, prefix and interface counts.
    #[test]
    fn an_identical_route_on_our_own_device_is_recognised() {
        let net: ipnet::IpNet = "0.0.0.0/1".parse().unwrap();
        let row = |dest: &str, prefix: u8, index: Option<u32>| {
            (dest.parse::<std::net::IpAddr>().unwrap(), prefix, index)
        };
        assert!(super::already_on_device(
            [row("10.0.0.0", 8, Some(7)), row("0.0.0.0", 1, Some(7))],
            &net,
            7
        ));
        // Another VPN's device, another prefix, no interface, nothing.
        assert!(!super::already_on_device(
            [row("0.0.0.0", 1, Some(9))],
            &net,
            7
        ));
        assert!(!super::already_on_device(
            [row("0.0.0.0", 0, Some(7))],
            &net,
            7
        ));
        assert!(!super::already_on_device(
            [row("0.0.0.0", 1, None)],
            &net,
            7
        ));
        assert!(!super::already_on_device([], &net, 7));
    }

    fn table(routes: &[(&str, &str)]) -> RouteTable {
        RouteTable::build(
            routes.iter().map(|(net, iface)| RawRoute {
                net: net.parse().unwrap(),
                iface: (*iface).into(),
                index: 1,
                gateway: None,
                metric: 0,
                table: None,
                scoped: false,
            }),
            |name| name == "meow-tun",
            |name| super::route_kind_of(kind_by_name(name)),
        )
    }

    fn cands(list: &[&str]) -> Vec<(String, IfaceKind, u32)> {
        let mut all: Vec<_> = list
            .iter()
            .map(|n| ((*n).to_string(), kind_by_name(n), 0))
            .collect();
        all.sort_by_key(|(_, k, m)| (*k, *m));
        all
    }

    fn choice(iface: Option<&str>, missing: bool, vpn: Option<&str>) -> DefaultChoice {
        DefaultChoice {
            iface: iface.map(str::to_owned),
            physical_route_missing: missing,
            full_tunnel: vpn.map(str::to_owned),
            physical: None,
        }
    }

    /// [`choose_default`] without the physical uplink (checked on its own).
    fn decide(
        candidates: &[(String, IfaceKind, u32)],
        table: &RouteTable,
        via: DefaultVia,
        current: Option<(&str, IfaceKind)>,
    ) -> DefaultChoice {
        DefaultChoice {
            physical: None,
            ..choose_default(candidates, table, via, current)
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn loopback_has_its_address() {
        let addrs = super::interface_addresses();
        assert!(
            addrs
                .iter()
                .any(|(name, net)| name == "lo" && net.to_string() == "127.0.0.1/8"),
            "{addrs:?}"
        );
    }

    #[test]
    fn container_bridges_are_not_somebodys_vpn() {
        for name in [
            "docker0",
            "br-1a2b3c",
            "virbr0",
            "veth12ab",
            "vEthernet (WSL)",
            "bridge100",
        ] {
            assert!(super::is_container_like(name), "{name}");
        }
        for name in [
            "tun0",
            "utun6",
            "wg0",
            "ppp0",
            "Cisco AnyConnect",
            "tailscale0",
        ] {
            assert!(!super::is_container_like(name), "{name}");
        }
    }

    /// The physical uplink is reported wherever the default binding goes:
    /// a VPN client's own traffic leaves by it.
    #[test]
    fn the_physical_uplink_is_known_even_when_the_default_goes_to_the_vpn() {
        let both = table(&[("0.0.0.0/0", "en0"), ("0.0.0.0/0", "utun6")]);
        let c = cands(&["utun6", "en0"]);
        let got = choose_default(&c, &both, DefaultVia::OtherVpn, None);
        assert_eq!(got.iface.as_deref(), Some("utun6"));
        assert_eq!(got.physical.as_deref(), Some("en0"));
        // Only the VPN holds a default: the NIC we were on stays the uplink.
        let vpn_only = table(&[("0.0.0.0/0", "tun0")]);
        let got = choose_default(
            &cands(&["tun0"]),
            &vpn_only,
            DefaultVia::OtherVpn,
            Some(("en0", IfaceKind::Physical)),
        );
        assert_eq!(got.physical.as_deref(), Some("en0"));
    }

    /// PaoPao (`tun.default-via`): next to a full-tunnel VPN the binding
    /// goes where the user said, never where the default route moved.
    #[test]
    fn default_via_decides_next_to_a_full_tunnel_vpn() {
        let physical = Some(("en0", IfaceKind::Physical));
        assert_eq!(
            super::route_kind_of(IfaceKind::Virtual),
            RouteIfaceKind::OtherVpn
        );

        // Both hold a default (the VPN added a cheaper one).
        let both = table(&[("0.0.0.0/0", "en0"), ("0.0.0.0/0", "utun6")]);
        let c = cands(&["utun6", "en0"]);
        assert_eq!(
            decide(&c, &both, DefaultVia::Physical, physical),
            choice(Some("en0"), false, Some("utun6"))
        );
        assert_eq!(
            decide(&c, &both, DefaultVia::OtherVpn, physical),
            choice(Some("utun6"), false, Some("utun6"))
        );

        // `def1`: the VPN holds the two /1s, the NIC keeps the default.
        let def1 = table(&[
            ("0.0.0.0/0", "en0"),
            ("0.0.0.0/1", "tun0"),
            ("128.0.0.0/1", "tun0"),
        ]);
        let c = cands(&["en0"]);
        assert_eq!(
            decide(&c, &def1, DefaultVia::Physical, physical),
            choice(Some("en0"), false, Some("tun0"))
        );
        assert_eq!(
            decide(&c, &def1, DefaultVia::OtherVpn, physical),
            choice(Some("tun0"), false, Some("tun0"))
        );

        // The VPN replaced the default: `physical` keeps the NIC bound and
        // says so; it does not follow the default to the VPN.
        let replaced = table(&[("0.0.0.0/0", "tun0"), ("192.168.1.0/24", "en0")]);
        let c = cands(&["tun0"]);
        assert_eq!(
            decide(&c, &replaced, DefaultVia::Physical, physical),
            choice(Some("en0"), true, Some("tun0"))
        );
        // Nothing bound yet (startup): a physical NIC that still has a
        // route, not the VPN.
        assert_eq!(
            decide(&c, &replaced, DefaultVia::Physical, None),
            choice(Some("en0"), true, Some("tun0"))
        );
        assert_eq!(
            decide(&c, &replaced, DefaultVia::OtherVpn, physical),
            choice(Some("tun0"), true, Some("tun0"))
        );
        // No physical interface known at all: the VPN, rather than nothing.
        let only_vpn = table(&[("0.0.0.0/0", "tun0")]);
        assert_eq!(
            decide(&c, &only_vpn, DefaultVia::Physical, None),
            choice(Some("tun0"), true, Some("tun0"))
        );

        // The VPN went away under `other-vpn`: back to the NIC.
        let plain = table(&[("0.0.0.0/0", "en0"), ("192.168.1.0/24", "en0")]);
        let c = cands(&["en0"]);
        assert_eq!(
            decide(
                &c,
                &plain,
                DefaultVia::OtherVpn,
                Some(("tun0", IfaceKind::Virtual))
            ),
            choice(Some("en0"), false, None)
        );
        // Offline: keep what is bound.
        assert_eq!(
            decide(&[], &RouteTable::default(), DefaultVia::Physical, physical),
            choice(Some("en0"), true, None)
        );
        assert_eq!(
            decide(&[], &RouteTable::default(), DefaultVia::Physical, None),
            choice(None, true, None)
        );
    }

    /// The live table, unprivileged: listing needs no root, and the
    /// snapshot never follows loopback.
    #[test]
    fn the_live_routing_table_builds_a_snapshot() {
        let table = super::route_snapshot().expect("listing routes needs no privilege");
        assert!(table.lookup("127.0.0.1".parse().unwrap()).is_none());
        for e in table.entries() {
            assert!(!e.iface.is_empty());
        }
    }

    fn pick(routes: impl IntoIterator<Item = DefaultCandidate>) -> Option<String> {
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
        assert_eq!(pick(table.clone()).as_deref(), Some("en0"));
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
        for n in [
            "en0", "en7", "eth0", "enp3s0", "wlan0", "wlp2s0", "Wi-Fi", "Ethernet",
        ] {
            assert_eq!(kind_by_name(n), IfaceKind::Physical, "{n}");
        }
        for n in [
            "utun3",
            "ipsec0",
            "ppp0",
            "tun0",
            "tap1",
            "wg0",
            "tailscale0",
            "zt5u4y",
            "docker0",
            "br-1a2b",
            "veth9",
            "virbr0",
            "vmnet8",
            "vboxnet0",
            "bridge100",
            "awdl0",
            "llw0",
            "anpi0",
            "ap1",
            "meow-tun",
            "vEthernet (WSL)",
            "VMware Network Adapter VMnet8",
            "Tailscale",
            "OpenVPN TAP-Windows6",
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
