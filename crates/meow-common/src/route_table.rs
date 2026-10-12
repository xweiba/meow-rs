//! PaoPao: a snapshot of the system routing table, for living next to
//! another VPN (anylink / AnyConnect / OpenConnect / WireGuard …).
//!
//! With `tun.auto-route: global` every outbound socket is bound to one
//! interface (see [`crate::outbound_iface`]), which ignores whatever routes
//! another VPN pushed: its intranet prefixes would leave by the physical
//! NIC. The snapshot gives the dial path the answer the kernel would have
//! given without our TUN: [`RouteTable::lookup`] is a longest-prefix match
//! over the *specific* routes of every interface but our own.
//!
//! What is kept and what is dropped ([`RouteTable::build`]):
//!
//! - dropped outright: loopback, link-local and multicast destinations, the
//!   Linux `local` table (addresses and broadcasts), macOS interface-scoped
//!   routes (`RTF_IFSCOPE` — they only apply to sockets already bound);
//! - our own TUN's routes are kept for display only;
//! - default routes and their split equivalents (`0.0.0.0/1` + `128.0.0.0/1`,
//!   the macOS eight-route form, a `/2` split) are kept apart: they say who
//!   holds the default, not where a prefix lives;
//! - everything else — a VPN's pushed prefixes, a physical NIC's connected
//!   subnet, a container bridge — is a specific route.
//!
//! The data lives here (the bottom crate) so the dial chokepoints, the DNS
//! resolver, the tunnel and the API can all read it; the producer is the
//! TUN listener's monitor thread (`meow-listener`), the only place that
//! links `route_manager`.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::SystemTime;

use ipnet::{IpNet, Ipv4Net, Ipv6Net};
use parking_lot::RwLock;
use serde::Serialize;

/// What the interface behind a route is, as far as coexistence goes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum RouteIfaceKind {
    /// Wi-Fi / Ethernet.
    Physical,
    /// Another VPN's tunnel, or any other virtual interface (container
    /// bridge, VM switch): its specific routes are followed.
    OtherVpn,
    /// Our own TUN device.
    OwnTun,
    /// Not recognisable by name.
    Other,
}

/// One routing-table row as the platform reported it, before filtering.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawRoute {
    pub net: IpNet,
    pub iface: String,
    pub index: u32,
    /// Next hop, when the route has an IP one.
    pub gateway: Option<IpAddr>,
    /// Lower wins among equal prefixes (0 where the platform has none).
    pub metric: u32,
    /// Linux routing table id (254 = `main`, 255 = `local`); `None`
    /// elsewhere.
    pub table: Option<u8>,
    /// macOS `RTF_IFSCOPE`.
    pub scoped: bool,
}

/// One kept route.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteEntry {
    pub net: IpNet,
    pub iface: Arc<str>,
    pub index: u32,
    pub kind: RouteIfaceKind,
    pub gateway: Option<IpAddr>,
    pub metric: u32,
    /// A default route or a split equivalent of one.
    pub is_default: bool,
}

/// A longest-prefix answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteHit {
    pub iface: Arc<str>,
    pub index: u32,
    pub kind: RouteIfaceKind,
    pub prefix: IpNet,
}

/// The filtered routing table. Cheap to share (`Arc`), immutable.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct RouteTable {
    /// Specific routes, longest prefix first (then best metric).
    v4: Vec<RouteEntry>,
    v6: Vec<RouteEntry>,
    /// Default routes and their split equivalents, not ours.
    defaults: Vec<RouteEntry>,
    /// Our own TUN's routes (display only).
    own: Vec<RouteEntry>,
}

const LINUX_LOCAL_TABLE: u8 = 255;
const LINUX_MAIN_TABLE: u8 = 254;

fn v4net(s: &str) -> Ipv4Net {
    s.parse().expect("static CIDR parses")
}

fn v6net(s: &str) -> Ipv6Net {
    s.parse().expect("static CIDR parses")
}

/// Destinations that never say where a prefix lives.
fn is_noise(net: &IpNet) -> bool {
    match net {
        IpNet::V4(n) => {
            let a = n.network();
            a.is_loopback()
                || v4net("169.254.0.0/16").contains(n)
                || v4net("224.0.0.0/4").contains(n)
                || (n.prefix_len() == 32 && a == Ipv4Addr::BROADCAST)
                || (n.prefix_len() == 32 && a.is_unspecified())
        }
        IpNet::V6(n) => {
            let a = n.network();
            (n.prefix_len() == 128 && (a == Ipv6Addr::LOCALHOST || a.is_unspecified()))
                || v6net("fe80::/10").contains(n)
                || v6net("ff00::/8").contains(n)
        }
    }
}

fn is_loopback_iface(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    lower == "lo" || lower == "lo0" || lower.starts_with("loopback")
}

/// The lower-half routes of the macOS zero-key-avoiding split (see
/// `meow-listener`'s `global_route_nets_for`): next to a `128.0.0.0/1` /
/// `8000::/1` on the same interface they are a default, not a prefix.
fn in_no_zero_key_split(net: &IpNet) -> bool {
    const V4: &[&str] = &[
        "1.0.0.0/8",
        "2.0.0.0/7",
        "4.0.0.0/6",
        "8.0.0.0/5",
        "16.0.0.0/4",
        "32.0.0.0/3",
        "64.0.0.0/2",
    ];
    const V6: &[&str] = &[
        "100::/8", "200::/7", "400::/6", "800::/5", "1000::/4", "2000::/3", "4000::/2",
    ];
    match net {
        IpNet::V4(n) => V4.iter().any(|s| v4net(s) == *n),
        IpNet::V6(n) => V6.iter().any(|s| v6net(s) == *n),
    }
}

/// A default route or a split equivalent of one. `holds_half` = the same
/// interface has a `/0` or `/1` of that family.
fn is_default_like(net: &IpNet, holds_half: bool) -> bool {
    let wide = match net {
        // `/2`: what a `/1` split falls back to when the `/1` is taken.
        IpNet::V4(n) => n.prefix_len() <= 2,
        // `2000::/3` is all of global unicast.
        IpNet::V6(n) => n.prefix_len() <= 3,
    };
    wide || (holds_half && in_no_zero_key_split(net))
}

impl RouteTable {
    /// Filter and index `raw`. `own_tun` says whether an interface is our
    /// own TUN; `kind` classifies every other one.
    pub fn build(
        raw: impl IntoIterator<Item = RawRoute>,
        own_tun: impl Fn(&str) -> bool,
        kind: impl Fn(&str) -> RouteIfaceKind,
    ) -> Self {
        let kept: Vec<RawRoute> = raw
            .into_iter()
            .filter(|r| {
                r.table != Some(LINUX_LOCAL_TABLE)
                    && !r.scoped
                    && !r.iface.is_empty()
                    && !is_loopback_iface(&r.iface)
                    && !is_noise(&r.net)
            })
            .collect();
        // (interface, is v4) pairs holding a /0 or /1.
        let halves: Vec<(&str, bool)> = kept
            .iter()
            .filter(|r| r.net.prefix_len() <= 1)
            .map(|r| (r.iface.as_str(), r.net.addr().is_ipv4()))
            .collect();

        let mut table = Self::default();
        // Main table first, so it wins a tie against a policy table.
        let mut order: Vec<&RawRoute> = kept.iter().collect();
        order.sort_by_key(|r| r.table.is_some_and(|t| t != LINUX_MAIN_TABLE));
        for r in order {
            let own = own_tun(&r.iface);
            let holds_half = halves.contains(&(r.iface.as_str(), r.net.addr().is_ipv4()));
            let entry = RouteEntry {
                net: r.net.trunc(),
                iface: Arc::from(r.iface.as_str()),
                index: r.index,
                kind: if own {
                    RouteIfaceKind::OwnTun
                } else {
                    kind(&r.iface)
                },
                gateway: r.gateway.filter(|g| !g.is_unspecified()),
                metric: r.metric,
                is_default: is_default_like(&r.net, holds_half),
            };
            let list = if own {
                &mut table.own
            } else if entry.is_default {
                &mut table.defaults
            } else if entry.net.addr().is_ipv4() {
                &mut table.v4
            } else {
                &mut table.v6
            };
            // One row per (prefix, interface): the lowest metric, the
            // first listed on a tie.
            match list
                .iter_mut()
                .find(|e| e.net == entry.net && e.iface == entry.iface)
            {
                Some(seen) if entry.metric < seen.metric => *seen = entry,
                Some(_) => {}
                None => list.push(entry),
            }
        }
        // Stable: equal (prefix, metric) keeps main-table-first order.
        let by_specificity = |e: &RouteEntry| (std::cmp::Reverse(e.net.prefix_len()), e.metric);
        table.v4.sort_by_key(by_specificity);
        table.v6.sort_by_key(by_specificity);
        table
            .defaults
            .sort_by_key(|e| (e.net.prefix_len(), e.metric));
        table
    }

    /// The most specific route to `ip` that is not ours and not a default.
    pub fn lookup(&self, ip: IpAddr) -> Option<RouteHit> {
        let ip = ip.to_canonical();
        let list = if ip.is_ipv4() { &self.v4 } else { &self.v6 };
        list.iter().find(|e| e.net.contains(&ip)).map(|e| RouteHit {
            iface: Arc::clone(&e.iface),
            index: e.index,
            kind: e.kind,
            prefix: e.net,
        })
    }

    /// Specific routes of both families, longest prefix first per family.
    pub fn specific(&self) -> impl Iterator<Item = &RouteEntry> {
        self.v4.iter().chain(self.v6.iter())
    }

    /// Default routes and split equivalents held by other interfaces.
    pub fn defaults(&self) -> &[RouteEntry] {
        &self.defaults
    }

    /// Our own TUN's routes.
    pub fn own(&self) -> &[RouteEntry] {
        &self.own
    }

    /// Everything kept, for display: defaults, then specific routes, then
    /// our own.
    pub fn entries(&self) -> impl Iterator<Item = &RouteEntry> {
        self.defaults.iter().chain(self.specific()).chain(&self.own)
    }

    pub fn is_empty(&self) -> bool {
        self.v4.is_empty() && self.v6.is_empty() && self.defaults.is_empty() && self.own.is_empty()
    }

    /// The other VPN that took over the IPv4 default route, if any: a
    /// virtual interface holding a default or a split equivalent, or an
    /// unrecognised one holding a split (no real NIC has a `/1`). IPv6 is
    /// not looked at: default-interface detection is IPv4-only, and macOS
    /// keeps IPv6 defaults on its own system tunnels.
    pub fn full_tunnel(&self) -> Option<&RouteEntry> {
        self.defaults
            .iter()
            .filter(|e| e.net.addr().is_ipv4())
            .find(|e| match e.kind {
                RouteIfaceKind::OtherVpn => true,
                RouteIfaceKind::Other => e.net.prefix_len() > 0,
                RouteIfaceKind::Physical | RouteIfaceKind::OwnTun => false,
            })
    }

    /// Whether `iface` holds a default route or a split equivalent.
    pub fn holds_default(&self, iface: &str) -> bool {
        self.defaults.iter().any(|e| &*e.iface == iface)
    }

    /// The first physical interface with any route at all — the fallback
    /// when no physical default route is left.
    pub fn any_physical(&self) -> Option<&RouteEntry> {
        self.defaults
            .iter()
            .chain(self.v4.iter())
            .find(|e| e.kind == RouteIfaceKind::Physical)
    }
}

/// `net` minus every net in `exclude`, as the fewest CIDRs. Order follows
/// address order. A net that `exclude` covers entirely disappears.
pub fn subtract_nets(net: IpNet, exclude: &[IpNet]) -> Vec<IpNet> {
    let mut out = vec![net];
    for ex in exclude {
        let ex = ex.trunc();
        let mut next = Vec::with_capacity(out.len() + 8);
        for n in out {
            subtract_one(n, ex, &mut next);
        }
        out = next;
    }
    out
}

fn subtract_one(net: IpNet, ex: IpNet, out: &mut Vec<IpNet>) {
    if net.addr().is_ipv4() != ex.addr().is_ipv4() {
        out.push(net);
        return;
    }
    if ex.contains(&net) {
        return;
    }
    if !net.contains(&ex) {
        out.push(net);
        return;
    }
    // `ex` is strictly inside `net`: halve and recurse into the half that
    // holds it (at most one level per prefix bit).
    let Ok(halves) = net.subnets(net.prefix_len() + 1) else {
        out.push(net);
        return;
    };
    for half in halves {
        subtract_one(half, ex, out);
    }
}

// ---------------------------------------------------------------------------
// Process-global state: the published snapshot, our own TUN names, and what
// the monitor found out about the default route.
// ---------------------------------------------------------------------------

static TABLE: RwLock<Option<Arc<RouteTable>>> = RwLock::new(None);

/// Publish a fresh snapshot (the monitor thread).
pub fn publish_route_table(table: RouteTable) {
    let mut slot = TABLE.write();
    if slot.as_deref() != Some(&table) {
        *slot = Some(Arc::new(table));
    }
}

/// Forget the snapshot (the last TUN listener went away).
pub fn clear_route_table() {
    *TABLE.write() = None;
}

/// The current snapshot; empty when none was published.
pub fn route_table() -> Arc<RouteTable> {
    TABLE.read().clone().unwrap_or_default()
}

static OWN_TUNS: RwLock<Vec<(u64, Arc<str>)>> = RwLock::new(Vec::new());
static NEXT_OWN_TUN_ID: AtomicU64 = AtomicU64::new(1);

/// Registration of one of our own TUN devices; dropping it forgets the name.
#[must_use = "dropping the guard forgets the device at once"]
#[derive(Debug)]
pub struct OwnTunGuard(u64);

impl Drop for OwnTunGuard {
    fn drop(&mut self) {
        OWN_TUNS.write().retain(|(id, _)| *id != self.0);
    }
}

/// Mark `name` as our own TUN device, so its routes are never followed and
/// it is never taken for another VPN. Call before installing its routes.
pub fn register_own_tun(name: &str) -> OwnTunGuard {
    let id = NEXT_OWN_TUN_ID.fetch_add(1, Ordering::Relaxed);
    OWN_TUNS.write().push((id, Arc::from(name)));
    OwnTunGuard(id)
}

/// Whether `name` is one of our own TUN devices.
pub fn is_own_tun(name: &str) -> bool {
    OWN_TUNS.read().iter().any(|(_, n)| &**n == name)
}

/// `tun.default-via`: which interface takes what only a default route
/// covers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum DefaultVia {
    /// The physical uplink, whoever holds the default route.
    #[default]
    Physical,
    /// Another VPN that took over the default route, while it is up.
    OtherVpn,
}

impl DefaultVia {
    pub fn parse(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "physical" => Some(Self::Physical),
            "other-vpn" | "other_vpn" | "vpn" => Some(Self::OtherVpn),
            _ => None,
        }
    }
}

/// What the monitor knows about the default route, for the API.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct OutboundStatus {
    /// Another VPN holds the default route (or a split equivalent): its
    /// interface and when that was first seen.
    pub full_tunnel: Option<(Arc<str>, SystemTime)>,
    /// No physical interface holds a default route.
    pub physical_route_missing: bool,
    /// Our own split default collided with someone else's identical route
    /// and was installed one level more specific.
    pub route_conflict: bool,
    /// `tun.default-via` in effect.
    pub default_via: DefaultVia,
    /// `tun.follow-system-routes` in effect.
    pub follow_routes: bool,
    /// The physical uplink, whoever the default binding went to — where a
    /// VPN client's own traffic leaves.
    pub physical_iface: Option<Arc<str>>,
}

static STATUS: RwLock<Option<OutboundStatus>> = RwLock::new(None);

/// The monitor's latest findings (default when nothing runs).
pub fn outbound_status() -> OutboundStatus {
    STATUS.read().clone().unwrap_or_default()
}

/// Update the findings in place.
pub fn update_outbound_status(f: impl FnOnce(&mut OutboundStatus)) {
    let mut slot = STATUS.write();
    f(slot.get_or_insert_with(OutboundStatus::default));
}

/// The physical uplink: what the monitor found, else the default binding.
/// `None` when nothing is bound.
pub fn physical_interface() -> Option<Arc<str>> {
    // The status lock is released before the binding's is taken.
    let found = STATUS
        .read()
        .as_ref()
        .and_then(|s| s.physical_iface.clone());
    found.or_else(crate::outbound_iface::outbound_interface)
}

/// Forget the findings (the last TUN listener went away).
pub fn clear_outbound_status() {
    *STATUS.write() = None;
}

/// DNS configuration one interface was given (by its VPN client / DHCP).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct IfaceDns {
    pub iface: String,
    pub kind: RouteIfaceKind,
    pub servers: Vec<IpAddr>,
    /// Search / routing domains, lower case, no leading dot or `~`, never
    /// the catch-all.
    pub domains: Vec<String>,
}

static IFACE_DNS: RwLock<Option<Arc<Vec<IfaceDns>>>> = RwLock::new(None);

/// Publish what the per-interface DNS reader found. Returns whether it
/// differs from what was published before.
pub fn publish_iface_dns(list: Vec<IfaceDns>) -> bool {
    let mut slot = IFACE_DNS.write();
    if slot.as_deref().is_some_and(|old| *old == list) {
        return false;
    }
    *slot = Some(Arc::new(list));
    true
}

/// Per-interface DNS as last published; empty when none was.
pub fn iface_dns() -> Arc<Vec<IfaceDns>> {
    IFACE_DNS.read().clone().unwrap_or_default()
}

pub fn clear_iface_dns() {
    *IFACE_DNS.write() = None;
}

/// A hand-entered "this name belongs to the other VPN" entry
/// (`tun.vpn-domains`) — the fallback for a VPN whose DNS push carries no
/// domain.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ManualVpnDomain {
    /// Lower case, no leading dot or wildcard.
    pub suffix: String,
    /// Empty: the VPN interface's own servers.
    pub servers: Vec<IpAddr>,
    /// `None`: whichever interface the route snapshot gives the server.
    pub iface: Option<String>,
}

/// What the configuration says by hand about the other VPN
/// (`tun.vpn-domains`, `tun.vpn-client-apps`).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct VpnManual {
    pub domains: Vec<ManualVpnDomain>,
    /// App matchers: `name:<file>` / `path:<file or directory>`; a bare
    /// string is a name.
    pub client_apps: Vec<String>,
    /// The other VPN's server names (`tun.vpn-gateway-domains`), lower
    /// case: answered with real addresses, dialled by the physical
    /// interface.
    pub gateway_domains: Vec<String>,
}

static MANUAL: RwLock<Option<(u64, Arc<VpnManual>)>> = RwLock::new(None);
static NEXT_MANUAL_ID: AtomicU64 = AtomicU64::new(1);

/// Keeps the hand-entered entries installed; dropping it removes them
/// unless a newer set replaced them meanwhile (config reload).
#[derive(Debug)]
pub struct VpnManualGuard(u64);

impl Drop for VpnManualGuard {
    fn drop(&mut self) {
        let mut slot = MANUAL.write();
        if slot.as_ref().is_some_and(|(id, _)| *id == self.0) {
            *slot = None;
        }
    }
}

/// Install the hand-entered entries (replacing the previous set).
pub fn install_vpn_manual(manual: VpnManual) -> VpnManualGuard {
    let id = NEXT_MANUAL_ID.fetch_add(1, Ordering::Relaxed);
    *MANUAL.write() = Some((id, Arc::new(manual)));
    VpnManualGuard(id)
}

/// The hand-entered entries in effect (empty when none).
pub fn vpn_manual() -> Arc<VpnManual> {
    MANUAL
        .read()
        .as_ref()
        .map(|(_, m)| Arc::clone(m))
        .unwrap_or_default()
}

/// Where a name another VPN owns is asked: forwarded as is, answered as is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VpnDns {
    /// The interface the query leaves by; `None` lets the route snapshot
    /// pick per server.
    pub iface: Option<String>,
    pub servers: Vec<IpAddr>,
    /// The suffix that matched.
    pub suffix: String,
}

fn normalise_domain(domain: &str) -> String {
    domain.trim().trim_end_matches('.').to_ascii_lowercase()
}

fn suffix_matches(domain: &str, suffix: &str) -> bool {
    !suffix.is_empty()
        && (domain == suffix
            || (domain.len() > suffix.len()
                && domain.ends_with(suffix)
                && domain.as_bytes()[domain.len() - suffix.len() - 1] == b'.'))
}

/// The pure part of [`vpn_dns_for`]: the longest matching suffix wins, a
/// hand-entered one over a detected one of the same length.
///
/// Detected entries come from VPN-kind interfaces that have both servers
/// and domains. A hand-entered entry without servers borrows the servers of
/// its interface — or, with no interface named, of the first VPN interface
/// that has any — and matches nothing while no such interface is up.
pub fn match_vpn_dns(
    detected: &[IfaceDns],
    manual: &[ManualVpnDomain],
    domain: &str,
) -> Option<VpnDns> {
    if detected.is_empty() && manual.is_empty() {
        return None;
    }
    let domain = normalise_domain(domain);
    let vpn = |d: &&IfaceDns| d.kind == RouteIfaceKind::OtherVpn && !d.servers.is_empty();
    let mut best: Option<VpnDns> = None;
    let better = |best: &Option<VpnDns>, suffix: &str| {
        best.as_ref().is_none_or(|b| suffix.len() > b.suffix.len())
    };
    for m in manual {
        if !suffix_matches(&domain, &m.suffix) || !better(&best, &m.suffix) {
            continue;
        }
        let (iface, servers) = if m.servers.is_empty() {
            let from = detected
                .iter()
                .filter(vpn)
                .find(|d| m.iface.as_deref().is_none_or(|i| i == d.iface));
            match from {
                Some(d) => (Some(d.iface.clone()), d.servers.clone()),
                None => continue,
            }
        } else {
            (m.iface.clone(), m.servers.clone())
        };
        best = Some(VpnDns {
            iface,
            servers,
            suffix: m.suffix.clone(),
        });
    }
    for d in detected.iter().filter(vpn) {
        for suffix in &d.domains {
            if suffix_matches(&domain, suffix) && better(&best, suffix) {
                best = Some(VpnDns {
                    iface: Some(d.iface.clone()),
                    servers: d.servers.clone(),
                    suffix: suffix.clone(),
                });
            }
        }
    }
    best
}

/// PaoPao: the other VPN's DNS for `domain`, when the name is one of its
/// search / routing domains (or was entered by hand) and
/// `tun.follow-system-routes` is on. Such a query is passed through
/// untouched — no fake IP, no hosts entry, no rule, whatever the mode.
pub fn vpn_dns_for(domain: &str) -> Option<VpnDns> {
    let detected = IFACE_DNS.read().clone();
    let manual = MANUAL.read().as_ref().map(|(_, m)| Arc::clone(m));
    let no_manual = manual.as_deref().is_none_or(|m| m.domains.is_empty());
    if detected.as_deref().is_none_or(Vec::is_empty) && no_manual {
        return None;
    }
    if !crate::outbound_iface::follows_system_routes() {
        return None;
    }
    match_vpn_dns(
        detected.as_deref().map_or(&[], |d| d.as_slice()),
        manual.as_deref().map_or(&[], |m| m.domains.as_slice()),
        domain,
    )
}

/// A process found holding another VPN's tunnel device.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct VpnClientProc {
    pub pid: u32,
    pub name: String,
    pub path: String,
    pub iface: String,
}

static VPN_CLIENTS: RwLock<Option<Arc<Vec<VpnClientProc>>>> = RwLock::new(None);

/// Publish the detected VPN client processes. Returns whether the list
/// changed.
pub fn publish_vpn_clients(list: Vec<VpnClientProc>) -> bool {
    let mut slot = VPN_CLIENTS.write();
    if slot.as_deref().map_or(list.is_empty(), |old| *old == list) {
        return false;
    }
    *slot = if list.is_empty() {
        None
    } else {
        Some(Arc::new(list))
    };
    true
}

pub fn vpn_clients() -> Arc<Vec<VpnClientProc>> {
    VPN_CLIENTS.read().clone().unwrap_or_default()
}

/// Whether `pid` is a detected VPN client process.
pub fn is_vpn_client_pid(pid: u32) -> bool {
    VPN_CLIENTS
        .read()
        .as_deref()
        .is_some_and(|l| l.iter().any(|c| c.pid == pid))
}

/// Whether `pid`, running the program at `path`, is a detected VPN client.
/// The scan is periodic, so a pid may have been reused since: when both
/// sides know the program's path it has to be the same one.
fn is_detected_client(pid: u32, path: &str) -> bool {
    VPN_CLIENTS.read().as_deref().is_some_and(|l| {
        l.iter()
            .any(|c| c.pid == pid && (c.path.is_empty() || path.is_empty() || c.path == path))
    })
}

/// Whether `host` is (under) one of the hand-entered VPN server names.
pub fn is_vpn_gateway_domain(host: &str) -> bool {
    let slot = MANUAL.read();
    let Some((_, manual)) = slot.as_ref().filter(|(_, m)| !m.gateway_domains.is_empty()) else {
        return false;
    };
    let host = normalise_domain(host);
    manual
        .gateway_domains
        .iter()
        .any(|suffix| suffix_matches(&host, suffix))
}

/// Whether any VPN client process is known (detected or entered by hand)
/// — only then is a connection's process looked up for the passthrough.
pub fn vpn_clients_known() -> bool {
    VPN_CLIENTS.read().is_some()
        || MANUAL
            .read()
            .as_ref()
            .is_some_and(|(_, m)| !m.client_apps.is_empty())
}

/// One app matcher against a process: `name:<file>` (or a bare string)
/// equals the process name; `path:<p>` equals the executable's path or is a
/// directory above it. Case is ignored (Windows and macOS file systems do).
pub fn app_matches(matcher: &str, name: &str, path: &str) -> bool {
    let matcher = matcher.trim();
    if let Some(want) = matcher.strip_prefix("path:") {
        let want = want.trim().trim_end_matches(['/', '\\']);
        // A root (`/`, `C:\`) is above every program: not a matcher.
        let drive_root = want.len() == 2 && want.ends_with(':');
        if want.is_empty() || drive_root || path.len() < want.len() {
            return false;
        }
        let (Some(head), Some(rest)) = (path.get(..want.len()), path.get(want.len()..)) else {
            return false;
        };
        return head.eq_ignore_ascii_case(want)
            && (rest.is_empty() || rest.starts_with(['/', '\\']));
    }
    let want = matcher.strip_prefix("name:").unwrap_or(matcher).trim();
    !want.is_empty() && name.eq_ignore_ascii_case(want)
}

/// Whether a connection's process is another VPN's client: found holding
/// that VPN's tunnel device, or matched by a hand-entered app.
pub fn is_vpn_client(pid: Option<u32>, name: &str, path: &str) -> bool {
    if pid.is_some_and(|pid| is_detected_client(pid, path)) {
        return true;
    }
    MANUAL
        .read()
        .as_ref()
        .is_some_and(|(_, m)| m.client_apps.iter().any(|a| app_matches(a, name, path)))
}

pub fn clear_vpn_clients() {
    *VPN_CLIENTS.write() = None;
}

/// `/proc/<pid>/fdinfo/<fd>` of a tun/tap handle carries `iff:\t<name>`;
/// every other descriptor has no such line.
pub fn parse_fdinfo_iff(fdinfo: &str) -> Option<&str> {
    fdinfo
        .lines()
        .find_map(|l| l.strip_prefix("iff:"))
        .map(str::trim)
        .filter(|n| !n.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn raw(net: &str, iface: &str, gw: Option<&str>) -> RawRoute {
        RawRoute {
            net: net.parse().unwrap(),
            iface: iface.into(),
            index: iface.len() as u32,
            gateway: gw.map(|g| g.parse().unwrap()),
            metric: 0,
            table: None,
            scoped: false,
        }
    }

    fn linux(net: &str, iface: &str, gw: Option<&str>, table: u8, metric: u32) -> RawRoute {
        RawRoute {
            table: Some(table),
            metric,
            ..raw(net, iface, gw)
        }
    }

    /// Names decide the kind the way `meow-listener`'s `kind_by_name` does,
    /// reduced to what the samples use.
    fn kind(name: &str) -> RouteIfaceKind {
        let l = name.to_ascii_lowercase();
        if ["tun", "utun", "wg", "docker", "ppp", "tap"]
            .iter()
            .any(|p| l.starts_with(p))
            || l.contains("vpn")
            || l.contains("anyconnect")
        {
            RouteIfaceKind::OtherVpn
        } else if ["en", "eth", "wl", "wi-fi", "ethernet"]
            .iter()
            .any(|p| l.starts_with(p))
        {
            RouteIfaceKind::Physical
        } else {
            RouteIfaceKind::Other
        }
    }

    fn build(raw: Vec<RawRoute>, own: &str) -> RouteTable {
        RouteTable::build(raw, |n| n == own, kind)
    }

    fn hit(t: &RouteTable, ip: &str) -> Option<(String, String)> {
        t.lookup(ip.parse().unwrap())
            .map(|h| (h.iface.to_string(), h.prefix.to_string()))
    }

    #[allow(clippy::unnecessary_wraps)]
    fn some(iface: &str, prefix: &str) -> Option<(String, String)> {
        Some((iface.into(), prefix.into()))
    }

    /// Linux, anylink in split mode (`ip route show table all`, netlink
    /// dump order): the `local` table, our own `/1`s, the NIC's default and
    /// subnet, the VPN's pushed prefixes and its gateway host route.
    fn linux_split_sample() -> Vec<RawRoute> {
        vec![
            linux("0.0.0.0/1", "meow-tun", None, 254, 0),
            linux("0.0.0.0/0", "enp3s0", Some("192.168.1.1"), 254, 100),
            linux("10.0.0.0/8", "tun0", None, 254, 0),
            linux("10.20.0.0/16", "tun0", None, 254, 0),
            linux("128.0.0.0/1", "meow-tun", None, 254, 0),
            linux("172.17.0.0/16", "docker0", None, 254, 0),
            linux("172.19.0.0/30", "meow-tun", None, 254, 0),
            linux("192.168.1.0/24", "enp3s0", None, 254, 100),
            linux("203.0.113.9/32", "enp3s0", Some("192.168.1.1"), 254, 0),
            linux("169.254.0.0/16", "enp3s0", None, 254, 1000),
            // local table
            linux("10.20.0.5/32", "tun0", None, 255, 0),
            linux("127.0.0.0/8", "lo", None, 255, 0),
            linux("127.0.0.1/32", "lo", None, 255, 0),
            linux("192.168.1.23/32", "enp3s0", None, 255, 0),
            linux("192.168.1.255/32", "enp3s0", None, 255, 0),
            // IPv6
            linux("::1/128", "lo", None, 254, 256),
            linux("fd00:10::/32", "tun0", None, 254, 1024),
            linux("fe80::/64", "enp3s0", None, 254, 1024),
            linux("::/0", "enp3s0", Some("fe80::1"), 254, 1024),
            linux("ff00::/8", "enp3s0", None, 255, 256),
        ]
    }

    #[test]
    fn linux_split_vpn_routes_are_followed_by_longest_prefix() {
        let t = build(linux_split_sample(), "meow-tun");
        // The VPN's prefixes, most specific first.
        assert_eq!(hit(&t, "10.20.3.4"), some("tun0", "10.20.0.0/16"));
        assert_eq!(hit(&t, "10.99.0.1"), some("tun0", "10.0.0.0/8"));
        assert_eq!(hit(&t, "fd00:10::7"), some("tun0", "fd00:10::/32"));
        // The VPN gateway's host route stays on the NIC (no loop).
        assert_eq!(hit(&t, "203.0.113.9"), some("enp3s0", "203.0.113.9/32"));
        // The NIC's own subnet, a container bridge.
        assert_eq!(hit(&t, "192.168.1.77"), some("enp3s0", "192.168.1.0/24"));
        assert_eq!(hit(&t, "172.17.0.2"), some("docker0", "172.17.0.0/16"));
        // Only a default route (ours or the NIC's) covers these.
        assert_eq!(hit(&t, "8.8.8.8"), None);
        assert_eq!(hit(&t, "2001:db8::1"), None);
        // Our own device subnet, loopback, link-local, the local table.
        assert_eq!(hit(&t, "172.19.0.2"), None);
        assert_eq!(hit(&t, "127.0.0.1"), None);
        assert_eq!(hit(&t, "169.254.1.1"), None);
        assert_eq!(hit(&t, "fe80::1"), None);
        // IPv4-mapped destinations are looked up as IPv4.
        assert_eq!(hit(&t, "::ffff:10.20.3.4"), some("tun0", "10.20.0.0/16"));

        assert_eq!(t.own().len(), 3);
        assert!(t.full_tunnel().is_none());
        assert_eq!(
            t.lookup("10.20.3.4".parse().unwrap()).unwrap().kind,
            RouteIfaceKind::OtherVpn
        );
        assert_eq!(
            t.lookup("192.168.1.77".parse().unwrap()).unwrap().kind,
            RouteIfaceKind::Physical
        );
        let defaults: Vec<String> = t
            .defaults()
            .iter()
            .map(|e| format!("{} {}", e.net, e.iface))
            .collect();
        assert_eq!(defaults, ["0.0.0.0/0 enp3s0", "::/0 enp3s0"]);
        assert_eq!(
            t.defaults()[0].gateway,
            Some("192.168.1.1".parse().unwrap())
        );
    }

    /// Linux, a VPN in full-tunnel mode: `def1`-style `/1`s, a replaced
    /// default, and a wg-quick policy table.
    #[test]
    fn linux_full_tunnel_is_a_default_not_a_prefix() {
        let def1 = vec![
            linux("0.0.0.0/0", "enp3s0", Some("192.168.1.1"), 254, 100),
            linux("0.0.0.0/1", "tun0", Some("10.8.0.1"), 254, 0),
            linux("128.0.0.0/1", "tun0", Some("10.8.0.1"), 254, 0),
            linux("10.8.0.0/24", "tun0", None, 254, 0),
            linux("192.168.1.0/24", "enp3s0", None, 254, 100),
        ];
        let t = build(def1, "meow-tun");
        assert_eq!(hit(&t, "8.8.8.8"), None);
        assert_eq!(hit(&t, "10.8.0.9"), some("tun0", "10.8.0.0/24"));
        assert_eq!(&*t.full_tunnel().unwrap().iface, "tun0");
        assert!(t.holds_default("tun0") && t.holds_default("enp3s0"));
        assert_eq!(&*t.any_physical().unwrap().iface, "enp3s0");

        // The physical default is gone altogether (OpenConnect).
        let replaced = vec![
            linux("0.0.0.0/0", "tun0", None, 254, 0),
            linux("203.0.113.9/32", "enp3s0", Some("192.168.1.1"), 254, 0),
            linux("192.168.1.0/24", "enp3s0", None, 254, 100),
        ];
        let t = build(replaced, "meow-tun");
        assert_eq!(&*t.full_tunnel().unwrap().iface, "tun0");
        assert!(!t.holds_default("enp3s0"));
        assert_eq!(&*t.any_physical().unwrap().iface, "enp3s0");

        // wg-quick: the default lives in its own table (51820 → 252 in the
        // 8-bit header field).
        let policy = vec![
            linux("0.0.0.0/0", "wg0", None, 252, 0),
            linux("0.0.0.0/0", "enp3s0", Some("192.168.1.1"), 254, 100),
        ];
        let t = build(policy, "meow-tun");
        assert_eq!(&*t.full_tunnel().unwrap().iface, "wg0");
        assert!(t.holds_default("enp3s0"));
    }

    /// macOS (`netstat -rn`): the primary default is unscoped, every other
    /// interface has a scoped one; our TUN is a `utun` like the VPN's, and
    /// carries the eight-route split.
    #[test]
    fn macos_sample_keeps_other_utun_and_drops_scoped_and_own() {
        let scoped = |net: &str, iface: &str, gw: Option<&str>| RawRoute {
            scoped: true,
            ..raw(net, iface, gw)
        };
        let mut sample = vec![
            raw("0.0.0.0/0", "en0", Some("192.168.0.1")),
            scoped("0.0.0.0/0", "en5", Some("10.1.1.1")),
            scoped("192.168.0.0/24", "en0", None),
            raw("127.0.0.0/8", "lo0", Some("127.0.0.1")),
            raw("169.254.0.0/16", "en0", None),
            raw("192.168.0.0/24", "en0", None),
            raw("10.1.1.0/24", "en5", None),
            raw("10.30.0.0/16", "utun6", Some("10.30.0.1")),
            raw("172.16.0.0/12", "utun6", Some("10.30.0.1")),
            raw("198.51.100.7/32", "en0", Some("192.168.0.1")),
            raw("224.0.0.0/4", "en0", None),
            raw("255.255.255.255/32", "en0", None),
            raw("::/0", "utun0", Some("fe80::")),
            raw("fe80::/64", "utun0", None),
        ];
        for net in [
            "1.0.0.0/8",
            "2.0.0.0/7",
            "4.0.0.0/6",
            "8.0.0.0/5",
            "16.0.0.0/4",
            "32.0.0.0/3",
            "64.0.0.0/2",
            "128.0.0.0/1",
        ] {
            sample.push(raw(net, "utun9", None));
        }
        let t = build(sample.clone(), "utun9");
        assert_eq!(hit(&t, "10.30.4.4"), some("utun6", "10.30.0.0/16"));
        assert_eq!(hit(&t, "172.20.1.1"), some("utun6", "172.16.0.0/12"));
        assert_eq!(hit(&t, "198.51.100.7"), some("en0", "198.51.100.7/32"));
        assert_eq!(hit(&t, "10.1.1.9"), some("en5", "10.1.1.0/24"));
        assert_eq!(hit(&t, "1.1.1.1"), None);
        assert_eq!(hit(&t, "224.0.0.251"), None);
        assert_eq!(t.own().len(), 8);
        // `utun0` holds only an IPv6 default (the system's own tunnels do):
        // not a full tunnel.
        assert!(t.full_tunnel().is_none());
        assert!(t.holds_default("utun0"));
        assert!(!t.holds_default("en5"), "scoped default is not a default");

        // The same eight routes on someone else's utun are a full tunnel,
        // not eight prefixes.
        let t = build(sample, "utun1");
        assert_eq!(hit(&t, "1.1.1.1"), None);
        assert_eq!(hit(&t, "9.9.9.9"), None);
        assert_eq!(&*t.full_tunnel().unwrap().iface, "utun9");
    }

    /// Windows (`GetIpForwardTable2`): on-link rows per adapter, multicast
    /// and broadcast rows on each, metrics deciding among equals.
    #[test]
    fn windows_sample_follows_the_vpn_adapter() {
        let m = |net: &str, iface: &str, gw: Option<&str>, metric: u32| RawRoute {
            metric,
            ..raw(net, iface, gw)
        };
        let sample = vec![
            m("0.0.0.0/0", "Wi-Fi", Some("192.168.31.1"), 35),
            m("0.0.0.0/1", "Meow", None, 0),
            m("128.0.0.0/1", "Meow", None, 0),
            m("10.0.0.0/8", "Cisco AnyConnect VPN", Some("10.255.0.1"), 2),
            m("10.0.0.0/8", "Wi-Fi", Some("192.168.31.1"), 50),
            m("10.255.0.0/24", "Cisco AnyConnect VPN", None, 257),
            m("127.0.0.0/8", "Loopback Pseudo-Interface 1", None, 331),
            m("192.168.31.0/24", "Wi-Fi", None, 291),
            m("192.168.31.20/32", "Wi-Fi", None, 291),
            m("192.168.31.255/32", "Wi-Fi", None, 291),
            m("224.0.0.0/4", "Wi-Fi", None, 291),
            m("224.0.0.0/4", "Cisco AnyConnect VPN", None, 257),
            m("255.255.255.255/32", "Wi-Fi", None, 291),
            m("fe80::/64", "Wi-Fi", None, 291),
            m("ff00::/8", "Wi-Fi", None, 291),
        ];
        let t = build(sample, "Meow");
        // Best metric among equal prefixes.
        assert_eq!(
            hit(&t, "10.3.3.3"),
            some("Cisco AnyConnect VPN", "10.0.0.0/8")
        );
        assert_eq!(
            hit(&t, "10.255.0.9"),
            some("Cisco AnyConnect VPN", "10.255.0.0/24")
        );
        assert_eq!(hit(&t, "192.168.31.9"), some("Wi-Fi", "192.168.31.0/24"));
        assert_eq!(hit(&t, "8.8.4.4"), None);
        assert_eq!(hit(&t, "239.255.255.250"), None);
        assert!(t.full_tunnel().is_none());
        assert_eq!(t.own().len(), 2);
    }

    #[test]
    fn display_entries_cover_defaults_specific_and_own() {
        let t = build(linux_split_sample(), "meow-tun");
        let all: Vec<&RouteEntry> = t.entries().collect();
        assert!(all.iter().any(|e| e.is_default && &*e.iface == "enp3s0"));
        assert!(all
            .iter()
            .any(|e| e.kind == RouteIfaceKind::OwnTun && e.net.to_string() == "0.0.0.0/1"));
        assert!(all
            .iter()
            .any(|e| e.kind == RouteIfaceKind::OtherVpn && e.net.to_string() == "10.0.0.0/8"));
        assert!(RouteTable::default().is_empty() && !t.is_empty());
    }

    fn sub(net: &str, exclude: &[&str]) -> Vec<String> {
        let exclude: Vec<IpNet> = exclude.iter().map(|s| s.parse().unwrap()).collect();
        subtract_nets(net.parse().unwrap(), &exclude)
            .iter()
            .map(ToString::to_string)
            .collect()
    }

    #[test]
    fn subtracting_a_prefix_leaves_its_siblings() {
        assert_eq!(
            sub("0.0.0.0/1", &["10.0.0.0/8"]),
            [
                "0.0.0.0/5",
                "8.0.0.0/7",
                "11.0.0.0/8",
                "12.0.0.0/6",
                "16.0.0.0/4",
                "32.0.0.0/3",
                "64.0.0.0/2"
            ]
        );
        // Outside, other family, identical, covering.
        assert_eq!(sub("0.0.0.0/1", &["192.168.0.0/16"]), ["0.0.0.0/1"]);
        assert_eq!(sub("0.0.0.0/1", &["fd00::/8"]), ["0.0.0.0/1"]);
        assert!(sub("10.0.0.0/8", &["10.0.0.0/8"]).is_empty());
        assert!(sub("10.1.0.0/16", &["10.0.0.0/8"]).is_empty());
        // Two excluded nets, one inside what the first left; host bits in
        // the excluded net are ignored.
        assert_eq!(
            sub("192.168.0.0/22", &["192.168.1.7/24", "192.168.2.0/23"]),
            ["192.168.0.0/24"]
        );
        assert_eq!(
            sub("8000::/1", &["fc00::/7"]),
            ["8000::/2", "c000::/3", "e000::/4", "f000::/5", "f800::/6", "fe00::/7"]
        );
        // A host address: 32 - 1 siblings.
        assert_eq!(sub("0.0.0.0/1", &["1.2.3.4/32"]).len(), 31);
    }

    #[test]
    fn own_tun_names_are_registered_while_the_guard_lives() {
        assert!(!is_own_tun("zz-test-tun"));
        let a = register_own_tun("zz-test-tun");
        let b = register_own_tun("zz-test-tun");
        assert!(is_own_tun("zz-test-tun"));
        drop(a);
        assert!(is_own_tun("zz-test-tun"));
        drop(b);
        assert!(!is_own_tun("zz-test-tun"));
    }

    #[test]
    fn default_via_parses() {
        assert_eq!(DefaultVia::parse("physical"), Some(DefaultVia::Physical));
        assert_eq!(DefaultVia::parse(" Other-VPN "), Some(DefaultVia::OtherVpn));
        assert_eq!(DefaultVia::parse("auto"), None);
    }

    fn dns(iface: &str, kind: RouteIfaceKind, servers: &[&str], domains: &[&str]) -> IfaceDns {
        IfaceDns {
            iface: iface.into(),
            kind,
            servers: servers.iter().map(|s| s.parse().unwrap()).collect(),
            domains: domains.iter().map(ToString::to_string).collect(),
        }
    }

    #[test]
    fn vpn_dns_matches_the_longest_suffix_and_only_vpn_interfaces() {
        let detected = [
            dns(
                "enp3s0",
                RouteIfaceKind::Physical,
                &["192.168.1.1"],
                &["lan"],
            ),
            dns(
                "tun0",
                RouteIfaceKind::OtherVpn,
                &["10.8.0.1"],
                &["corp.example"],
            ),
            dns(
                "wg0",
                RouteIfaceKind::OtherVpn,
                &["10.9.0.1"],
                &["dev.corp.example"],
            ),
            dns("tun9", RouteIfaceKind::OtherVpn, &[], &["nodns.example"]),
        ];
        let hit = |d: &str| match_vpn_dns(&detected, &[], d);
        assert_eq!(
            hit("git.corp.example").unwrap().iface.as_deref(),
            Some("tun0")
        );
        assert_eq!(
            hit("CORP.example.").unwrap().servers,
            vec!["10.8.0.1".parse::<IpAddr>().unwrap()]
        );
        assert_eq!(
            hit("a.dev.corp.example").unwrap().iface.as_deref(),
            Some("wg0")
        );
        // A physical NIC's search domain is not another VPN's.
        assert!(hit("printer.lan").is_none());
        // Label boundary, and an interface without servers.
        assert!(hit("notcorp.example").is_none());
        assert!(hit("x.nodns.example").is_none());
        assert!(hit("example.com").is_none());
    }

    #[test]
    fn hand_entered_vpn_domains_fill_in_what_was_not_detected() {
        let detected = [dns("tun0", RouteIfaceKind::OtherVpn, &["10.8.0.1"], &[])];
        let manual = [
            ManualVpnDomain {
                suffix: "intra.example".into(),
                ..Default::default()
            },
            ManualVpnDomain {
                suffix: "lab.example".into(),
                servers: vec!["172.16.0.53".parse().unwrap()],
                iface: None,
            },
            ManualVpnDomain {
                suffix: "other.example".into(),
                servers: vec![],
                iface: Some("tun7".into()),
            },
        ];
        // No servers given: the VPN interface's own.
        let hit = match_vpn_dns(&detected, &manual, "wiki.intra.example").unwrap();
        assert_eq!(hit.iface.as_deref(), Some("tun0"));
        assert_eq!(hit.servers, vec!["10.8.0.1".parse::<IpAddr>().unwrap()]);
        // Servers given, no interface: the route snapshot picks.
        let hit = match_vpn_dns(&detected, &manual, "lab.example").unwrap();
        assert_eq!(hit.iface, None);
        // The named interface is not up: nothing to pass through to.
        assert!(match_vpn_dns(&detected, &manual, "x.other.example").is_none());
        // With no VPN up at all the suffix-only entry is inert.
        assert!(match_vpn_dns(&[], &manual, "wiki.intra.example").is_none());
    }

    #[test]
    fn fdinfo_of_a_tun_handle_names_its_interface() {
        let tun = "pos:\t0\nflags:\t02104002\nmnt_id:\t27\nino:\t650\niff:\ttun0\n";
        assert_eq!(parse_fdinfo_iff(tun), Some("tun0"));
        let file = "pos:\t0\nflags:\t0100002\nmnt_id:\t27\nino:\t1234\n";
        assert_eq!(parse_fdinfo_iff(file), None);
        assert_eq!(parse_fdinfo_iff("iff:\t\n"), None);
    }

    #[test]
    fn app_matchers_go_by_name_or_by_path_prefix() {
        assert!(app_matches(
            "name:openconnect",
            "OpenConnect",
            "/usr/bin/openconnect"
        ));
        assert!(app_matches("vpnagentd", "vpnagentd", ""));
        assert!(!app_matches("name:openconnect", "openconnect-gui", ""));
        assert!(app_matches(
            "path:/opt/cisco/",
            "vpnagentd",
            "/opt/cisco/anyconnect/bin/vpnagentd"
        ));
        assert!(app_matches(
            "path:/usr/bin/openconnect",
            "x",
            "/usr/bin/openconnect"
        ));
        assert!(!app_matches("path:/opt/cis", "x", "/opt/cisco/bin/vpn"));
        assert!(app_matches(
            "path:C:\\Program Files\\Cisco",
            "vpnagent.exe",
            "c:\\program files\\cisco\\vpnagent.exe"
        ));
        assert!(!app_matches("path:", "x", "/usr/bin/x"));
        assert!(!app_matches("name:", "", ""));
        // A root would name every program.
        assert!(!app_matches("path:/", "x", "/usr/bin/x"));
        assert!(!app_matches("path:C:\\", "x.exe", "C:\\Windows\\x.exe"));
        assert!(!app_matches("path:c:", "x.exe", "C:\\Windows\\x.exe"));
        assert!(!app_matches("", "", ""));
    }

    /// A detected client is its pid *and* its program: a pid reused by
    /// another program since the last scan is not the client.
    #[test]
    fn a_reused_pid_is_not_the_vpn_client() {
        publish_vpn_clients(vec![VpnClientProc {
            pid: 4_100_001,
            name: "openconnect".into(),
            path: "/usr/sbin/openconnect".into(),
            iface: "zz-tun0".into(),
        }]);
        assert!(is_vpn_client(
            Some(4_100_001),
            "openconnect",
            "/usr/sbin/openconnect"
        ));
        // The lookup could not read the path: the pid decides.
        assert!(is_vpn_client(Some(4_100_001), "openconnect", ""));
        assert!(!is_vpn_client(Some(4_100_001), "curl", "/usr/bin/curl"));
        assert!(!is_vpn_client(
            Some(4_100_002),
            "openconnect",
            "/usr/sbin/openconnect"
        ));
        assert!(!is_vpn_client(None, "openconnect", "/usr/sbin/openconnect"));
        clear_vpn_clients();
    }

    /// A tiny deterministic generator (no new dependency).
    struct Lcg(u64);
    impl Lcg {
        fn next(&mut self) -> u64 {
            self.0 = self
                .0
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            self.0 >> 16
        }
        fn below(&mut self, n: u64) -> u64 {
            self.next() % n
        }
    }

    /// Property: `lookup` is the longest-prefix match over the specific
    /// routes of interfaces that are not ours — the lowest metric among
    /// equal prefixes — and never answers with our own TUN, a default or a
    /// split default, whatever the table holds. Both families.
    #[test]
    fn lookup_agrees_with_a_brute_force_longest_prefix_match() {
        let ifaces = ["eth0", "tun0", "wg0", "docker0", "meow-tun"];
        let mut rng = Lcg(0x5eed);
        for round in 0..300 {
            let v6 = round % 3 == 0;
            let n = rng.below(12) as usize;
            let mut raws = Vec::new();
            for _ in 0..n {
                // Prefixes cluster so that routes nest and collide.
                let net: IpNet = if v6 {
                    let len = [0u8, 1, 3, 8, 32, 48, 64, 128][rng.below(8) as usize];
                    let addr =
                        Ipv6Addr::from((0x2001_0db8u128 << 96) | u128::from(rng.below(4)) << 64);
                    Ipv6Net::new(addr, len).unwrap().trunc().into()
                } else {
                    let len = [0u8, 1, 2, 8, 16, 24, 32][rng.below(7) as usize];
                    let addr = Ipv4Addr::new(
                        10,
                        rng.below(2) as u8,
                        rng.below(2) as u8,
                        rng.below(3) as u8,
                    );
                    Ipv4Net::new(addr, len).unwrap().trunc().into()
                };
                raws.push(RawRoute {
                    net,
                    iface: ifaces[rng.below(ifaces.len() as u64) as usize].into(),
                    index: 1,
                    gateway: None,
                    metric: rng.below(3) as u32,
                    table: None,
                    scoped: false,
                });
            }
            let t = build(raws.clone(), "meow-tun");
            for _ in 0..20 {
                let ip: IpAddr = if v6 {
                    Ipv6Addr::from(
                        (0x2001_0db8u128 << 96)
                            | u128::from(rng.below(4)) << 64
                            | u128::from(rng.below(3)),
                    )
                    .into()
                } else {
                    Ipv4Addr::new(
                        10,
                        rng.below(2) as u8,
                        rng.below(2) as u8,
                        rng.below(3) as u8,
                    )
                    .into()
                };
                let wide = if v6 { 3 } else { 2 };
                let best = raws
                    .iter()
                    .filter(|r| {
                        r.iface != "meow-tun" && r.net.prefix_len() > wide && r.net.contains(&ip)
                    })
                    .map(|r| (std::cmp::Reverse(r.net.prefix_len()), r.metric))
                    .min();
                let got = t.lookup(ip);
                match best {
                    None => assert!(got.is_none(), "{ip}: {got:?} from {raws:?}"),
                    Some((std::cmp::Reverse(len), metric)) => {
                        let got = got.unwrap_or_else(|| panic!("{ip}: no hit in {raws:?}"));
                        assert_eq!(got.prefix.prefix_len(), len, "{ip} in {raws:?}");
                        assert_ne!(&*got.iface, "meow-tun");
                        assert_ne!(got.kind, RouteIfaceKind::OwnTun);
                        // Among equal prefixes the hit carries the best metric.
                        assert!(
                            raws.iter().any(|r| r.net == got.prefix
                                && *r.iface == *got.iface
                                && r.metric == metric),
                            "{ip}: {got:?} is not a best-metric route of {raws:?}"
                        );
                    }
                }
            }
        }
        // Nothing published / an empty table: no answer, no panic.
        assert!(RouteTable::default()
            .lookup("10.0.0.1".parse().unwrap())
            .is_none());
        assert!(RouteTable::default()
            .lookup("2001:db8::1".parse().unwrap())
            .is_none());
        assert!(RouteTable::default().full_tunnel().is_none());
        assert!(RouteTable::default().any_physical().is_none());
    }

    /// Property: what `subtract_nets` returns covers exactly the
    /// complement — no address of an excluded net, every other address of
    /// the original once — and stays within one route per prefix bit per
    /// excluded net.
    #[test]
    fn subtraction_is_exactly_the_complement() {
        let mut rng = Lcg(0xc0ffee);
        for round in 0..200 {
            let v6 = round % 4 == 0;
            let count = 1 + rng.below(6) as usize;
            let (net, exclude): (IpNet, Vec<IpNet>) = if v6 {
                let ex = (0..count)
                    .map(|_| {
                        let len = 1 + rng.below(128) as u8;
                        let addr =
                            Ipv6Addr::from(u128::from(rng.next()) << 80 | u128::from(rng.next()));
                        IpNet::from(Ipv6Net::new(addr, len).unwrap())
                    })
                    .collect();
                ("::/0".parse().unwrap(), ex)
            } else {
                let ex = (0..count)
                    .map(|_| {
                        let len = 1 + rng.below(32) as u8;
                        let addr = Ipv4Addr::from(rng.next() as u32);
                        IpNet::from(Ipv4Net::new(addr, len).unwrap())
                    })
                    .collect();
                ("0.0.0.0/0".parse().unwrap(), ex)
            };
            let rest = subtract_nets(net, &exclude);
            let bits = if v6 { 128 } else { 32 };
            assert!(
                rest.len() <= count * bits,
                "{} routes for {exclude:?}",
                rest.len()
            );
            for (i, a) in rest.iter().enumerate() {
                for ex in &exclude {
                    let ex = ex.trunc();
                    assert!(
                        !a.contains(&ex) && !ex.contains(a),
                        "{a} overlaps excluded {ex}"
                    );
                }
                for b in &rest[i + 1..] {
                    assert!(!a.contains(b) && !b.contains(a), "{a} overlaps {b}");
                }
            }
            // The edges of every excluded net and of every remaining one,
            // and their neighbours, are on the right side.
            let mut probes: Vec<IpAddr> = Vec::new();
            for n in exclude.iter().map(IpNet::trunc).chain(rest.iter().copied()) {
                for edge in [n.network(), n.broadcast()] {
                    probes.push(edge);
                    match edge {
                        IpAddr::V4(a) => {
                            let a = u32::from(a);
                            probes.push(Ipv4Addr::from(a.wrapping_add(1)).into());
                            probes.push(Ipv4Addr::from(a.wrapping_sub(1)).into());
                        }
                        IpAddr::V6(a) => {
                            let a = u128::from(a);
                            probes.push(Ipv6Addr::from(a.wrapping_add(1)).into());
                            probes.push(Ipv6Addr::from(a.wrapping_sub(1)).into());
                        }
                    }
                }
            }
            for ip in probes {
                let excluded = exclude.iter().any(|ex| ex.trunc().contains(&ip));
                let covering = rest.iter().filter(|n| n.contains(&ip)).count();
                assert_eq!(covering, usize::from(!excluded), "{ip} with {exclude:?}");
            }
        }
    }

    #[test]
    fn hand_entered_set_is_dropped_with_its_guard_unless_replaced() {
        let old = install_vpn_manual(VpnManual {
            client_apps: vec!["name:first".into()],
            ..Default::default()
        });
        let new = install_vpn_manual(VpnManual {
            client_apps: vec!["name:second".into()],
            gateway_domains: vec!["vpn.corp.example".into()],
            ..Default::default()
        });
        assert!(is_vpn_gateway_domain("VPN.corp.example."));
        assert!(is_vpn_gateway_domain("a.vpn.corp.example"));
        assert!(!is_vpn_gateway_domain("corp.example"));
        // The reload's old listener goes away after the new one came up.
        drop(old);
        assert_eq!(vpn_manual().client_apps, ["name:second"]);
        assert!(is_vpn_client(None, "second", ""));
        assert!(!is_vpn_client(None, "first", ""));
        drop(new);
        assert!(vpn_manual().client_apps.is_empty());
        assert!(!is_vpn_gateway_domain("vpn.corp.example"));
    }
}
