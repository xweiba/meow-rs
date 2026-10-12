//! Outbound-socket interface binding for TUN global-route mode (#375).
//!
//! With `tun.auto-route: global` the split default routes send *all*
//! traffic into the TUN device — including, without countermeasures, meow's
//! own dials to proxy upstreams and DIRECT destinations, which would re-enter
//! the device and loop. The countermeasure is per-socket: every outbound
//! socket meow creates is bound to the physical interface **before**
//! `connect()`/`bind()`, so its packets take the physical route regardless of
//! the routing table. The binding is per platform:
//!
//! | Platform | Socket option | Keyed by |
//! |----------|---------------|----------|
//! | Linux | `SO_BINDTODEVICE` | interface name |
//! | macOS | `IP_BOUND_IF` / `IPV6_BOUND_IF` | interface index |
//! | Windows | `IP_UNICAST_IF` / `IPV6_UNICAST_IF` | interface index |
//!
//! The index-keyed platforms resolve the index once, at install time. An
//! interface that is destroyed and re-created under the same name gets a
//! new index, which the binding does not follow until it is re-installed
//! (a TUN listener restart).
//!
//! On macOS a socket scoped to a physical interface cannot reach an IPv4
//! loopback peer (`connect()` fails with `EADDRNOTAVAIL`), and loopback
//! traffic never follows the TUN's routes anyway — so on the index-keyed
//! platforms TCP dials to a loopback address, and UDP sockets pinned to a
//! loopback local address, are left unbound (`binds_peer`). Linux keeps
//! binding every socket, as it did before those platforms were added.
//!
//! This module is the process-global registry for that interface, mirroring
//! the `SocketProtector` pattern in [`crate::socket_protect`]: the owners of
//! global route scope install the interface with
//! [`install_outbound_interface`], and the dial chokepoints
//! ([`crate::connect_tcp`], [`crate::bind_udp`], plus the marked-socket path
//! in `meow-proxy`) apply it to each socket.
//!
//! # Owners
//!
//! The binding is owned, not set: [`install_outbound_interface`] returns an
//! [`OutboundIfaceGuard`], and dropping the guard gives the binding up.
//! Owners can overlap — a config reload installs the *new* configuration's
//! binding before its first dial, while the old TUN listener (and its own
//! binding) is still running (issue #695) — so the registry keeps every
//! live owner in installation order and the **most recently installed live
//! owner** decides the interface:
//!
//! - installing supersedes the current owner without invalidating it;
//! - dropping the current owner hands the binding back to the newest owner
//!   still alive (or clears it when none is left), so a rejected reload
//!   restores the running listener's binding;
//! - dropping a superseded owner changes nothing, so an old listener torn
//!   down after its successor installed cannot clear or clobber the
//!   successor's binding.
//!
//! The registry itself compiles on every platform so call sites stay free of
//! `cfg` spaghetti; [`install_outbound_interface`] fails with `Unsupported`
//! on platforms where the binding syscall is not implemented, which lets
//! the TUN listener fail closed instead of starting a looping configuration.

use std::io;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use parking_lot::RwLock;

use crate::outbound_balance::Balancer;

/// One live owner of the binding.
struct Owner {
    id: u64,
    iface: Arc<str>,
    /// OS interface index, resolved when the owner installed. What the
    /// index-keyed platforms bind to; Linux binds by name.
    index: u32,
    /// PaoPao (`tun.follow-system-routes`): sockets follow the system
    /// route snapshot per destination instead of always binding `iface`.
    follow: bool,
    /// PaoPao (`tun.outbound-interfaces`): what would take `iface` is
    /// spread over these members instead (see [`crate::outbound_balance`]).
    balance: Option<Arc<Balancer>>,
}

/// The socket option the binding uses on this platform, for log lines.
const MECHANISM: &str = if cfg!(target_os = "macos") {
    "IP_BOUND_IF"
} else if cfg!(target_os = "windows") {
    "IP_UNICAST_IF"
} else {
    "SO_BINDTODEVICE"
};

/// Live owners in installation order; the last one is in effect. Holds at
/// most a handful of entries — one per overlapping owner (running listener,
/// in-flight reload).
static OWNERS: RwLock<Vec<Owner>> = RwLock::new(Vec::new());

/// Owner identity source. Interface names cannot identify owners: two
/// overlapping owners routinely bind the same interface.
static NEXT_OWNER_ID: AtomicU64 = AtomicU64::new(1);

/// Ownership of one installation of the outbound-interface binding,
/// returned by [`install_outbound_interface`]. Dropping it gives the
/// binding up: the newest owner still alive takes over, or the binding is
/// cleared when none is left (see the [module docs](self)).
#[must_use = "dropping the guard gives the binding up immediately"]
#[derive(Debug)]
pub struct OutboundIfaceGuard {
    id: u64,
    iface: Arc<str>,
}

impl OutboundIfaceGuard {
    /// The interface this owner installed. Not necessarily the one in
    /// effect — a newer owner may have superseded it
    /// (see [`outbound_interface`]).
    pub fn interface(&self) -> &str {
        &self.iface
    }

    /// PaoPao (`tun.follow-system-routes`): whether sockets dialled under
    /// this owner follow the system route snapshot per destination (see
    /// [`interface_for`]). Off until set.
    pub fn set_follow_routes(&mut self, follow: bool) {
        if let Some(o) = OWNERS.write().iter_mut().find(|o| o.id == self.id) {
            o.follow = follow;
        }
    }

    /// PaoPao (`tun.outbound-interfaces`): sockets dialled under this
    /// owner that would take its interface are spread over `balancer`'s
    /// members; `None` turns that off.
    pub fn set_balance(&mut self, balancer: Option<Arc<Balancer>>) {
        if let Some(o) = OWNERS.write().iter_mut().find(|o| o.id == self.id) {
            o.balance = balancer;
        }
    }

    /// PaoPao: this owner now binds to `name` instead (the network changed:
    /// another uplink took over). Its place among the owners is kept, so an
    /// owner superseded meanwhile (a reload in flight) stays superseded and
    /// the newer owner's binding is untouched. When this owner is the one
    /// in effect and the interface changed, the hook set with
    /// [`set_rebind_hook`] runs (to close what is bound to the old one).
    /// Errors (nothing changed) when `name` does not exist.
    pub fn rebind(&mut self, name: &str) -> io::Result<()> {
        if name == &*self.iface {
            return Ok(());
        }
        let index = interface_index(name)?.ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                format!("outbound interface '{name}' does not exist"),
            )
        })?;
        let iface: Arc<str> = Arc::from(name);
        let mut owners = OWNERS.write();
        let Some(pos) = owners.iter().position(|o| o.id == self.id) else {
            return Ok(());
        };
        owners[pos].iface = Arc::clone(&iface);
        owners[pos].index = index;
        let in_effect = pos + 1 == owners.len();
        drop(owners);
        let prev = std::mem::replace(&mut self.iface, iface);
        if in_effect {
            tracing::info!(
                "outbound sockets now bound to interface '{name}' ({MECHANISM}; was '{prev}')"
            );
            let hook = REBIND_HOOK.read().clone();
            if let Some(hook) = hook {
                hook();
            }
        }
        Ok(())
    }
}

/// What runs after the interface in effect changed under a running
/// configuration ([`OutboundIfaceGuard::rebind`]): the API layer closes the
/// connections and pooled sessions bound to the old one.
type RebindHook = Arc<dyn Fn() + Send + Sync>;
static REBIND_HOOK: RwLock<Option<RebindHook>> = RwLock::new(None);

/// PaoPao: sets the hook run when the interface in effect changes (one;
/// a later call replaces it).
pub fn set_rebind_hook(hook: impl Fn() + Send + Sync + 'static) {
    *REBIND_HOOK.write() = Some(Arc::new(hook));
}

impl Drop for OutboundIfaceGuard {
    fn drop(&mut self) {
        let mut owners = OWNERS.write();
        let Some(pos) = owners.iter().position(|o| o.id == self.id) else {
            return;
        };
        owners.remove(pos);
        if pos != owners.len() {
            // A superseded owner left; the binding in effect is unchanged.
            return;
        }
        let restored = owners.last().map(|o| Arc::clone(&o.iface));
        drop(owners);
        match restored {
            Some(name) if *name == *self.iface => {}
            Some(name) => {
                tracing::info!("outbound interface binding restored to '{name}' ({MECHANISM})");
            }
            None => tracing::info!("outbound interface binding cleared"),
        }
    }
}

/// Install `name` as the physical interface every subsequent outbound
/// socket binds to, superseding (not discarding) any current owner; the
/// binding lasts as long as the returned guard. Validates that the
/// interface exists by resolving its index (`if_nametoindex` on Linux and
/// macOS; on Windows `name` is the interface *alias*, e.g. `Ethernet` or
/// `Wi-Fi`). Errors with `Unsupported` on platforms where per-socket
/// binding is not implemented — callers must treat that as fatal for
/// global-route mode, not a warning. On error the registry is left
/// untouched.
pub fn install_outbound_interface(name: &str) -> io::Result<OutboundIfaceGuard> {
    if name.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "outbound interface name is empty",
        ));
    }
    if name.contains('\0') {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("outbound interface name '{name}' contains a NUL byte"),
        ));
    }
    let index = interface_index(name)?.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::NotFound,
            format!("outbound interface '{name}' does not exist"),
        )
    })?;
    Ok(push_owner(Arc::from(name), index))
}

/// Resolve a NUL-free interface name to its index; `None` = no such
/// interface.
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn interface_index(name: &str) -> io::Result<Option<u32>> {
    let c_name =
        std::ffi::CString::new(name).map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
    // SAFETY: `c_name` is a valid NUL-terminated string for the call.
    let index = unsafe { libc::if_nametoindex(c_name.as_ptr()) };
    Ok((index != 0).then_some(index))
}

/// Resolve an interface alias (`Ethernet`, `Wi-Fi`, …) to its index;
/// `None` = no such interface.
#[cfg(target_os = "windows")]
#[allow(
    clippy::unnecessary_wraps,
    reason = "signature shared with the other platforms' interface_index"
)]
fn interface_index(name: &str) -> io::Result<Option<u32>> {
    use windows_sys::Win32::NetworkManagement::IpHelper::{
        ConvertInterfaceAliasToLuid, ConvertInterfaceLuidToIndex,
    };
    use windows_sys::Win32::NetworkManagement::Ndis::NET_LUID_LH;

    let alias: Vec<u16> = name.encode_utf16().chain(std::iter::once(0)).collect();
    // SAFETY: `NET_LUID_LH` is a plain 64-bit union; all-zero is valid.
    let mut luid: NET_LUID_LH = unsafe { std::mem::zeroed() };
    // SAFETY: `alias` is NUL-terminated UTF-16 and `luid` a valid out-pointer.
    if unsafe { ConvertInterfaceAliasToLuid(alias.as_ptr(), &raw mut luid) } != 0 {
        return Ok(None);
    }
    let mut index = 0u32;
    // SAFETY: both pointers reference live locals for the call.
    if unsafe { ConvertInterfaceLuidToIndex(&raw const luid, &raw mut index) } != 0 {
        return Ok(None);
    }
    Ok((index != 0).then_some(index))
}

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
fn interface_index(name: &str) -> io::Result<Option<u32>> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        format!(
            "outbound interface binding ('{name}') is not implemented on this \
             platform (Linux, macOS and Windows only; #375)"
        ),
    ))
}

/// The IPv4 metric of interface `index`. Windows ranks competing default
/// routes by route metric **plus** this, so default-interface detection
/// needs both.
#[cfg(target_os = "windows")]
pub fn interface_metric_v4(index: u32) -> Option<u32> {
    use windows_sys::Win32::NetworkManagement::IpHelper::{
        GetIpInterfaceEntry, InitializeIpInterfaceEntry, MIB_IPINTERFACE_ROW,
    };
    use windows_sys::Win32::Networking::WinSock::AF_INET;

    // SAFETY: the row is plain data; `InitializeIpInterfaceEntry` then sets
    // every field to its documented default.
    let mut row: MIB_IPINTERFACE_ROW = unsafe { std::mem::zeroed() };
    // SAFETY: `row` is a valid, exclusively borrowed row for both calls.
    unsafe {
        InitializeIpInterfaceEntry(&raw mut row);
        row.Family = AF_INET;
        row.InterfaceIndex = index;
        (GetIpInterfaceEntry(&raw mut row) == 0).then_some(row.Metric)
    }
}

/// Register a validated interface as the newest owner.
fn push_owner(iface: Arc<str>, index: u32) -> OutboundIfaceGuard {
    let id = NEXT_OWNER_ID.fetch_add(1, Ordering::Relaxed);
    let mut owners = OWNERS.write();
    let superseded = owners.last().map(|o| Arc::clone(&o.iface));
    owners.push(Owner {
        id,
        iface: Arc::clone(&iface),
        index,
        follow: false,
        balance: None,
    });
    drop(owners);
    match superseded {
        Some(prev) if *prev == *iface => {
            tracing::debug!("outbound interface binding '{iface}' taken over by a new owner");
        }
        Some(prev) => tracing::info!(
            "outbound sockets bound to interface '{iface}' ({MECHANISM}; supersedes '{prev}')"
        ),
        None => tracing::info!("outbound sockets bound to interface '{iface}' ({MECHANISM})"),
    }
    OutboundIfaceGuard { id, iface }
}

/// The interface currently in effect (the newest live owner's), if any.
pub fn outbound_interface() -> Option<Arc<str>> {
    OWNERS.read().last().map(|o| Arc::clone(&o.iface))
}

/// Whether a socket talking to `peer` — a TCP dial's destination, or the
/// local address a UDP socket is pinned to — takes the binding.
///
/// Loopback is exempt on the index-keyed platforms (see the
/// [module docs](self)): the traffic never follows the TUN's routes, and
/// macOS refuses an IPv4 loopback connect from an interface-scoped socket.
#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
pub(crate) fn binds_peer(peer: IpAddr) -> bool {
    cfg!(target_os = "linux") || !is_loopback(peer)
}

/// Loopback including the IPv4-mapped form a dual-stack socket dials.
#[cfg(any(test, target_os = "linux", target_os = "macos", target_os = "windows"))]
fn is_loopback(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_loopback(),
        IpAddr::V6(v6) => {
            v6.is_loopback() || v6.to_ipv4_mapped().is_some_and(|v4| v4.is_loopback())
        }
    }
}

/// PaoPao: the balancer of the binding in effect
/// (`tun.outbound-interfaces`), if it has one.
pub fn balancer() -> Option<Arc<Balancer>> {
    OWNERS.read().last().and_then(|o| o.balance.clone())
}

/// PaoPao: the OS index of interface `name`; `None` when there is no such
/// interface (or the platform has no per-socket binding).
pub fn interface_exists(name: &str) -> Option<u32> {
    if name.is_empty() || name.contains('\0') {
        return None;
    }
    interface_index(name).ok().flatten()
}

/// PaoPao: whether the binding in effect follows the system route snapshot
/// (`tun.follow-system-routes`). `false` when nothing is bound.
pub fn follows_system_routes() -> bool {
    OWNERS.read().last().is_some_and(|o| o.follow)
}

/// PaoPao: the interface a socket talking to `dest` binds to — name and OS
/// index — or `None` when nothing is bound.
///
/// With `tun.follow-system-routes` the system route snapshot
/// ([`crate::route_table`]) is asked first: a destination inside a specific
/// route of some interface (another VPN's pushed prefix, a second NIC's
/// subnet, a container bridge) leaves by that interface, with the index the
/// snapshot read (so a re-created interface is followed). Everything else —
/// and every destination when the key is off — takes the default interface
/// (the newest live owner's).
pub fn interface_for(dest: Option<IpAddr>) -> Option<(Arc<str>, u32)> {
    let (name, index, follow) = OWNERS
        .read()
        .last()
        .map(|o| (Arc::clone(&o.iface), o.index, o.follow))?;
    if follow {
        // Never our own TUN, even when the snapshot was read before the
        // device was known to be ours: that would be the loop the binding
        // exists to prevent.
        if let Some(hit) = dest
            .and_then(|ip| crate::route_table::route_table().lookup(ip))
            .filter(|hit| !crate::route_table::is_own_tun(&hit.iface))
        {
            return Some((hit.iface, hit.index));
        }
    }
    Some((name, index))
}

/// PaoPao: the route that makes `dest` another VPN's — a specific route on
/// a virtual interface — when `tun.follow-system-routes` is on. What the
/// tunnel's `OtherRoute` decision asks.
pub fn other_vpn_route(dest: IpAddr) -> Option<crate::route_table::RouteHit> {
    if !follows_system_routes() {
        return None;
    }
    crate::route_table::route_table()
        .lookup(dest)
        .filter(|hit| hit.kind == crate::route_table::RouteIfaceKind::OtherVpn)
        .filter(|hit| !crate::route_table::is_own_tun(&hit.iface))
}

/// Bind `socket` — created in `domain` — to the installed interface, if one
/// is installed. No-op when none is. Callers must invoke this **before**
/// `connect()`/`bind()` so the very first packet already takes the physical
/// route.
#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
pub fn apply_outbound_interface(
    socket: &socket2::Socket,
    domain: socket2::Domain,
) -> io::Result<()> {
    apply_outbound_interface_for(socket, domain, None)
}

/// PaoPao: [`apply_outbound_interface`] for a socket that will talk to
/// `dest`: the interface is chosen by `bind_outbound`.
#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
pub fn apply_outbound_interface_for(
    socket: &socket2::Socket,
    domain: socket2::Domain,
    dest: Option<IpAddr>,
) -> io::Result<()> {
    bind_outbound(socket, domain, dest, &mut 0, true).map(drop)
}

/// PaoPao: whether a socket to `dest` that no specific route claimed is
/// spread over the balancer's members: a public destination, while the
/// default interface is not another VPN's (`tun.default-via: other-vpn`
/// with that VPN holding the default route sends everything to it).
pub fn balance_applies(dest: IpAddr, status: &crate::route_table::OutboundStatus) -> bool {
    crate::outbound_balance::is_balanced_dest(dest)
        && !(status.default_via == crate::route_table::DefaultVia::OtherVpn
            && status.full_tunnel.is_some())
}

/// PaoPao: the balancer member a socket was bound to, so the dial can
/// report how it went.
#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
pub(crate) type BoundMember = Option<(Arc<Balancer>, usize)>;

/// PaoPao: bind `socket` for a peer at `dest`, in this order:
///
/// 1. a destination the system has a specific route for (another VPN's
///    prefix, a NIC's subnet) is never spread: it takes the interface of
///    that route when `tun.follow-system-routes` is on, else the default
///    one, as before;
/// 2. a member of `tun.outbound-interfaces`, when configured and
///    [`balance_applies`], unless the current
///    [`DialScope`](crate::outbound_balance::DialScope) is
///    [`unbalanced`](crate::outbound_balance::DialScope::unbalanced):
///    chosen by the balancer with the scope's key, skipping the members in
///    `tried` (the one chosen is added to it); a member that cannot be
///    bound counts as failed and the next one is taken;
/// 3. the default interface.
///
/// No-op when nothing is installed. The owner in effect is read once (one
/// shared lock); with neither key set nothing else is looked at. The
/// interface is recorded in the current dial scope — a member only when
/// `record_member` (a caller that may still move the dial to another
/// member records it itself, with [`record_member`], once the dial is
/// settled). Returns the member bound, if it was one.
#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
pub(crate) fn bind_outbound(
    socket: &socket2::Socket,
    domain: socket2::Domain,
    dest: Option<IpAddr>,
    tried: &mut u32,
    record_member: bool,
) -> io::Result<BoundMember> {
    use crate::outbound_balance::{sticky_key, DialOutcome, DialScope};

    let Some((default_name, default_index, follow, balancer)) = OWNERS
        .read()
        .last()
        .map(|o| (Arc::clone(&o.iface), o.index, o.follow, o.balance.clone()))
    else {
        return Ok(None);
    };
    if !follow && balancer.is_none() {
        // Neither key: the default interface, nothing else to decide.
        bind_socket(socket, domain, &default_name, default_index)?;
        return Ok(None);
    }
    let scope = DialScope::current();
    let note = |name: &Arc<str>, member: Option<(&Arc<Balancer>, usize)>| {
        if let Some(scope) = &scope {
            scope.record(name, member);
        }
    };
    // Never our own TUN, even when the snapshot was read before the device
    // was known to be ours (see `interface_for`).
    let routed = dest
        .and_then(|ip| crate::route_table::route_table().lookup(ip))
        .filter(|hit| !crate::route_table::is_own_tun(&hit.iface));
    if let Some(hit) = routed {
        if follow && hit.iface != default_name {
            match bind_socket(socket, domain, &hit.iface, hit.index) {
                Ok(()) => {
                    note(&hit.iface, None);
                    return Ok(None);
                }
                Err(e) => tracing::debug!(
                    "outbound interface: could not bind to routed interface '{}' ({e}); \
                     using '{default_name}'",
                    hit.iface
                ),
            }
        }
    } else if let (Some(balancer), Some(ip)) = (&balancer, dest.map(|ip| ip.to_canonical())) {
        let pinned = scope.as_ref().is_some_and(|s| s.default_only());
        if !pinned && balance_applies(ip, &crate::route_table::outbound_status()) {
            let key = scope
                .as_ref()
                .and_then(|s| s.key())
                .or_else(|| sticky_key("", Some(ip)));
            let prefer = scope.as_ref().and_then(|s| s.member_of(balancer));
            let now = std::time::Instant::now();
            // The family of the address the packets carry: a mapped IPv4
            // destination on a dual-stack socket needs an IPv4 route.
            while let Some(pick) = balancer.pick(ip.is_ipv4(), key, prefer, *tried, now) {
                *tried |= 1 << pick.member;
                match bind_socket(socket, domain, &pick.name, pick.index) {
                    Ok(()) => {
                        if record_member {
                            note(&pick.name, Some((balancer, pick.member)));
                        }
                        return Ok(Some((Arc::clone(balancer), pick.member)));
                    }
                    Err(e) => {
                        tracing::debug!(
                            "outbound balance: could not bind to '{}' ({e}); trying another",
                            pick.name
                        );
                        balancer.report(pick.member, DialOutcome::Failed, now);
                    }
                }
            }
        }
    }
    bind_socket(socket, domain, &default_name, default_index)?;
    note(&default_name, None);
    Ok(None)
}

/// PaoPao: record `member` as the interface of the connection dialling on
/// this task (see [`bind_outbound`]'s `record_member`).
#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
pub(crate) fn record_member(balancer: &Arc<Balancer>, member: usize) {
    if let Some(scope) = crate::outbound_balance::DialScope::current() {
        scope.record(&balancer.names()[member], Some((balancer, member)));
    }
}

/// PaoPao: binds one socket to interface `name` (a per-outbound
/// `interface-name:`, e.g. another VPN's `utun6`), whatever the global
/// binding. Errors when the interface does not exist.
#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
pub fn bind_socket_to_interface(
    socket: &socket2::Socket,
    domain: socket2::Domain,
    name: &str,
) -> io::Result<()> {
    let index = interface_index(name)?.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::NotFound,
            format!("interface '{name}' does not exist"),
        )
    })?;
    bind_socket(socket, domain, name, index)?;
    // PaoPao: a connection pinned to an interface (a per-rule one, another
    // VPN's client on the physical uplink) shows it too.
    if let Some(scope) = crate::outbound_balance::DialScope::current() {
        scope.record(&Arc::from(name), None);
    }
    Ok(())
}

/// TCP dial with the socket bound to interface `name` before `connect()`.
#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
pub async fn connect_tcp_on(
    addr: std::net::SocketAddr,
    name: &str,
) -> io::Result<tokio::net::TcpStream> {
    let domain = if addr.is_ipv4() {
        socket2::Domain::IPV4
    } else {
        socket2::Domain::IPV6
    };
    let socket = socket2::Socket::new(domain, socket2::Type::STREAM, Some(socket2::Protocol::TCP))?;
    bind_socket_to_interface(&socket, domain, name)?;
    socket.set_nonblocking(true)?;
    tokio::net::TcpSocket::from_std_stream(socket.into())
        .connect(addr)
        .await
}

/// UDP socket bound to `local` and to interface `name`.
#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
pub fn bind_udp_on(local: std::net::SocketAddr, name: &str) -> io::Result<tokio::net::UdpSocket> {
    let domain = if local.is_ipv4() {
        socket2::Domain::IPV4
    } else {
        socket2::Domain::IPV6
    };
    let socket = socket2::Socket::new(domain, socket2::Type::DGRAM, Some(socket2::Protocol::UDP))?;
    bind_socket_to_interface(&socket, domain, name)?;
    socket.set_nonblocking(true)?;
    socket.bind(&local.into())?;
    tokio::net::UdpSocket::from_std(socket.into())
}

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
pub async fn connect_tcp_on(
    _addr: std::net::SocketAddr,
    name: &str,
) -> io::Result<tokio::net::TcpStream> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        format!("interface binding ('{name}') is not available on this platform"),
    ))
}

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
pub fn bind_udp_on(_local: std::net::SocketAddr, name: &str) -> io::Result<tokio::net::UdpSocket> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        format!("interface binding ('{name}') is not available on this platform"),
    ))
}

/// Linux: `SO_BINDTODEVICE`, by name — one option covers both families.
#[cfg(target_os = "linux")]
fn bind_socket(
    socket: &socket2::Socket,
    _domain: socket2::Domain,
    name: &str,
    _index: u32,
) -> io::Result<()> {
    socket.bind_device(Some(name.as_bytes()))
}

/// macOS: `IP_BOUND_IF` on an IPv4 socket, `IPV6_BOUND_IF` on an IPv6 one.
/// The IPv6 option scopes the whole socket, so a dual-stack socket's
/// IPv4-mapped traffic is covered too.
#[cfg(target_os = "macos")]
fn bind_socket(
    socket: &socket2::Socket,
    domain: socket2::Domain,
    _name: &str,
    index: u32,
) -> io::Result<()> {
    let index = std::num::NonZeroU32::new(index);
    if domain == socket2::Domain::IPV6 {
        socket.bind_device_by_index_v6(index)
    } else {
        socket.bind_device_by_index_v4(index)
    }
}

/// Windows: `IP_UNICAST_IF` on an IPv4 socket, `IPV6_UNICAST_IF` on an IPv6
/// one. A dual-stack IPv6 socket sends its IPv4-mapped traffic by the IPv4
/// option, so an IPv6 socket gets that one as well — best effort, because
/// a v6-only socket refuses it.
#[cfg(target_os = "windows")]
fn bind_socket(
    socket: &socket2::Socket,
    domain: socket2::Domain,
    _name: &str,
    index: u32,
) -> io::Result<()> {
    use std::os::windows::io::AsRawSocket;
    use windows_sys::Win32::Networking::WinSock::{
        setsockopt, IPPROTO_IP, IPPROTO_IPV6, IPV6_UNICAST_IF, IP_UNICAST_IF, SOCKET, SOCKET_ERROR,
    };

    let raw = socket.as_raw_socket() as SOCKET;
    let set = |level: i32, option: i32, value: u32| -> io::Result<()> {
        // SAFETY: `raw` is a live socket for the duration of the borrow and
        // `value` a 4-byte option value, as both options expect.
        let ret = unsafe { setsockopt(raw, level, option, (&raw const value).cast(), 4) };
        if ret == SOCKET_ERROR {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    };
    if domain == socket2::Domain::IPV6 {
        set(IPPROTO_IPV6, IPV6_UNICAST_IF, index)?;
        let _ = set(IPPROTO_IP, IP_UNICAST_IF, unicast_if_v4(index));
        Ok(())
    } else {
        set(IPPROTO_IP, IP_UNICAST_IF, unicast_if_v4(index))
    }
}

/// The `IP_UNICAST_IF` option value for interface `index`: the IPv4 option
/// takes the index in **network** byte order, while `IPV6_UNICAST_IF` takes
/// it in host byte order.
#[cfg(any(test, target_os = "windows"))]
const fn unicast_if_v4(index: u32) -> u32 {
    index.to_be()
}

#[cfg(test)]
mod pure_tests {
    use super::*;

    #[test]
    fn ip_unicast_if_value_is_the_index_in_network_byte_order() {
        assert_eq!(unicast_if_v4(5).to_ne_bytes(), [0, 0, 0, 5]);
        assert_eq!(unicast_if_v4(0x0102_0304).to_ne_bytes(), [1, 2, 3, 4]);
    }

    #[test]
    fn loopback_peers_include_the_mapped_form() {
        for ip in ["127.0.0.1", "127.8.9.10", "::1", "::ffff:127.0.0.1"] {
            assert!(is_loopback(ip.parse().unwrap()), "{ip}");
        }
        for ip in [
            "192.0.2.1",
            "0.0.0.0",
            "::",
            "2001:db8::1",
            "::ffff:192.0.2.1",
        ] {
            assert!(!is_loopback(ip.parse().unwrap()), "{ip}");
        }
    }
}

#[cfg(all(test, any(target_os = "linux", target_os = "macos")))]
mod tests {
    use super::balancer as balancer_in_effect;
    use super::*;

    /// The loopback interface: the only one every host is guaranteed to
    /// have, and binding to it keeps the concurrent loopback socket tests
    /// in this binary working (a made-up name would break them).
    const LO: &str = if cfg!(target_os = "macos") {
        "lo0"
    } else {
        "lo"
    };

    /// Id of the owner in effect — distinguishes owners that bind the same
    /// interface.
    fn current_owner() -> Option<u64> {
        OWNERS.read().last().map(|o| o.id)
    }

    fn live_owners() -> usize {
        OWNERS.read().len()
    }

    fn lo() -> OutboundIfaceGuard {
        install_outbound_interface(LO).expect("loopback must exist")
    }

    /// One test drives every case because the registry is process-global;
    /// separate `#[test]` fns would race each other.
    #[test]
    fn owners_install_apply_supersede_and_restore() {
        assert!(outbound_interface().is_none());

        // A bogus interface must be rejected and leave nothing installed.
        assert!(install_outbound_interface("no-such-iface-zz9").is_err());
        assert!(install_outbound_interface("").is_err());
        assert!(install_outbound_interface("lo0\0x").is_err());
        assert!(outbound_interface().is_none());

        // Install → apply → drop clears.
        let a = lo();
        assert_eq!(a.interface(), LO);
        assert_eq!(outbound_interface().as_deref(), Some(LO));
        assert_eq!(current_owner(), Some(a.id));
        // Binding a fresh socket to loopback succeeds, in both families
        // and for both socket types.
        for domain in [socket2::Domain::IPV4, socket2::Domain::IPV6] {
            for (ty, proto) in [
                (socket2::Type::STREAM, socket2::Protocol::TCP),
                (socket2::Type::DGRAM, socket2::Protocol::UDP),
            ] {
                let socket = socket2::Socket::new(domain, ty, Some(proto)).unwrap();
                apply_outbound_interface(&socket, domain).expect("bind to loopback");
                assert_bound_to_loopback(&socket, domain);
            }
        }
        dial_chokepoints_bind_their_sockets();
        drop(a);
        assert!(outbound_interface().is_none());
        assert_eq!(live_owners(), 0);

        // With nothing installed, apply is a no-op.
        let socket2 = socket2::Socket::new(
            socket2::Domain::IPV4,
            socket2::Type::STREAM,
            Some(socket2::Protocol::TCP),
        )
        .unwrap();
        apply_outbound_interface(&socket2, socket2::Domain::IPV4).expect("no-op apply");
        #[cfg(target_os = "macos")]
        assert_eq!(socket2.device_index_v4().unwrap(), None);

        // Supersede, then the superseding owner leaves (a rejected reload):
        // the still-live superseded owner is back in effect, not cleared.
        let a = lo();
        let b = lo();
        assert_eq!(current_owner(), Some(b.id));
        drop(b);
        assert_eq!(current_owner(), Some(a.id));
        assert_eq!(outbound_interface().as_deref(), Some(LO));
        drop(a);
        assert!(outbound_interface().is_none());

        // Out of order (a reload restart: the new binding is installed,
        // then the old listener is torn down): dropping the superseded
        // owner is a no-op — the successor's binding survives.
        let a = lo();
        let b = lo();
        drop(a);
        assert_eq!(current_owner(), Some(b.id));
        assert_eq!(outbound_interface().as_deref(), Some(LO));
        // The superseding owner outlived its predecessor: nothing to
        // restore, so its drop clears.
        drop(b);
        assert!(outbound_interface().is_none());
        assert_eq!(live_owners(), 0);

        // Three deep, middle owner dropped first: the top stays in effect,
        // and the top leaving skips the dead middle and restores the bottom.
        let a = lo();
        let b = lo();
        let c = lo();
        drop(b);
        assert_eq!(current_owner(), Some(c.id));
        drop(c);
        assert_eq!(current_owner(), Some(a.id));
        assert_eq!(outbound_interface().as_deref(), Some(LO));
        drop(a);
        assert!(outbound_interface().is_none());

        // Three deep, unwound strictly in order.
        let a = lo();
        let b = lo();
        let c = lo();
        drop(c);
        assert_eq!(current_owner(), Some(b.id));
        drop(b);
        assert_eq!(current_owner(), Some(a.id));
        drop(a);
        assert!(outbound_interface().is_none());

        // Three deep, bottom first then top: the middle takes over.
        let a = lo();
        let b = lo();
        let c = lo();
        drop(a);
        assert_eq!(current_owner(), Some(c.id));
        drop(c);
        assert_eq!(current_owner(), Some(b.id));
        drop(b);
        assert!(outbound_interface().is_none());
        assert_eq!(live_owners(), 0);

        // A failed install while an owner is live leaves it in effect.
        let a = lo();
        assert!(install_outbound_interface("no-such-iface-zz9").is_err());
        assert_eq!(current_owner(), Some(a.id));
        assert_eq!(live_owners(), 1);
        drop(a);
        assert!(outbound_interface().is_none());

        follow_system_routes_per_destination();
        balanced_sockets_take_members_and_passthrough_does_not();

        // PaoPao: rebinding in place. A missing interface changes nothing;
        // the same one is a no-op (no hook: nothing to close); the owner
        // keeps its place among the others.
        let hooked = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let h = Arc::clone(&hooked);
        set_rebind_hook(move || {
            h.fetch_add(1, Ordering::Relaxed);
        });
        let mut a = lo();
        let b = lo();
        assert!(a.rebind("no-such-iface-zz9").is_err());
        assert_eq!(a.interface(), LO);
        a.rebind(LO).expect("same interface");
        assert_eq!(current_owner(), Some(b.id), "a stays superseded");
        assert_eq!(hooked.load(Ordering::Relaxed), 0);
        drop(b);
        assert_eq!(current_owner(), Some(a.id));
        drop(a);
        assert!(outbound_interface().is_none());
        *REBIND_HOOK.write() = None;
    }

    /// PaoPao: with `tun.follow-system-routes` a destination inside a
    /// specific route of another interface binds to that interface; the
    /// default one takes everything else, and everything when the key is
    /// off. Called from the one registry test.
    fn follow_system_routes_per_destination() {
        use crate::route_table::{
            clear_route_table, publish_route_table, RawRoute, RouteIfaceKind, RouteTable,
        };
        let route = |net: &str, iface: &str| RawRoute {
            net: net.parse().unwrap(),
            iface: iface.into(),
            index: 99,
            gateway: None,
            metric: 0,
            table: None,
            scoped: false,
        };
        publish_route_table(RouteTable::build(
            [
                route("198.51.100.0/24", "zz-vpn0"),
                route("203.0.113.0/24", "zz-eth9"),
            ],
            |_| false,
            |name| {
                if name == "zz-vpn0" {
                    RouteIfaceKind::OtherVpn
                } else {
                    RouteIfaceKind::Physical
                }
            },
        ));
        let vpn_dest: IpAddr = "198.51.100.7".parse().unwrap();
        let nic_dest: IpAddr = "203.0.113.7".parse().unwrap();
        let elsewhere: IpAddr = "192.0.2.1".parse().unwrap();
        let name = |dest| interface_for(dest).map(|(n, i)| (n.to_string(), i));

        // Nothing bound: nothing to follow.
        assert_eq!(name(Some(vpn_dest)), None);
        assert!(other_vpn_route(vpn_dest).is_none());

        // Bound, key off: always the default interface.
        let mut a = lo();
        let lo_index = interface_index(LO).unwrap().unwrap();
        assert!(!follows_system_routes());
        assert_eq!(name(Some(vpn_dest)), Some((LO.to_string(), lo_index)));
        assert!(other_vpn_route(vpn_dest).is_none());

        // Key on: the routed interface with the snapshot's index.
        a.set_follow_routes(true);
        assert!(follows_system_routes());
        assert_eq!(name(Some(vpn_dest)), Some(("zz-vpn0".to_string(), 99)));
        assert_eq!(name(Some(nic_dest)), Some(("zz-eth9".to_string(), 99)));
        assert_eq!(name(Some(elsewhere)), Some((LO.to_string(), lo_index)));
        assert_eq!(name(None), Some((LO.to_string(), lo_index)));
        // Only a virtual interface's route makes a destination "the other
        // VPN's".
        assert_eq!(&*other_vpn_route(vpn_dest).unwrap().iface, "zz-vpn0");
        assert!(other_vpn_route(nic_dest).is_none());
        assert!(other_vpn_route(elsewhere).is_none());
        // The device turned out to be ours after the snapshot was read:
        // never followed, never "another VPN's".
        let ours = crate::route_table::register_own_tun("zz-vpn0");
        assert_eq!(name(Some(vpn_dest)), Some((LO.to_string(), lo_index)));
        assert!(other_vpn_route(vpn_dest).is_none());
        drop(ours);
        assert_eq!(name(Some(vpn_dest)), Some(("zz-vpn0".to_string(), 99)));

        // The routed interface does not exist (it vanished since the
        // snapshot): the socket falls back to the default one.
        let socket = socket2::Socket::new(
            socket2::Domain::IPV4,
            socket2::Type::DGRAM,
            Some(socket2::Protocol::UDP),
        )
        .unwrap();
        apply_outbound_interface_for(&socket, socket2::Domain::IPV4, Some(vpn_dest))
            .expect("falls back to the default interface");
        assert_bound_to_loopback(&socket, socket2::Domain::IPV4);

        // A newer owner without the key supersedes it.
        let b = lo();
        assert!(!follows_system_routes());
        assert_eq!(name(Some(vpn_dest)), Some((LO.to_string(), lo_index)));
        drop(b);
        assert!(follows_system_routes());
        drop(a);
        clear_route_table();
    }

    /// PaoPao (`tun.outbound-interfaces`): a socket to a public address
    /// takes a balancer member; one to a private address, one a specific
    /// route claims (another VPN's prefix) and one pinned to an interface
    /// do not. A member that cannot be bound is skipped within the same
    /// dial. Called from the one registry test.
    fn balanced_sockets_take_members_and_passthrough_does_not() {
        use crate::outbound_balance::{
            scoped, BalanceOptions, Balancer, DialScope, Link, LinkKind, LinkSource, MemberState,
        };
        use crate::route_table::{
            clear_route_table, publish_route_table, RawRoute, RouteIfaceKind, RouteTable,
        };

        /// Both members hold a default route as far as the balancer knows;
        /// only loopback really exists.
        struct Links;
        impl LinkSource for Links {
            fn links(&self) -> Vec<Link> {
                [LO, "zz-gone9"]
                    .into_iter()
                    .map(|name| Link {
                        name: name.into(),
                        index: interface_index(name).unwrap().unwrap_or(999),
                        kind: LinkKind::Physical,
                        v4: true,
                        v6: true,
                        strict_rp_filter: false,
                    })
                    .collect()
            }
            fn kind_of(&self, _name: &str) -> Option<LinkKind> {
                None
            }
        }
        let udp = || {
            socket2::Socket::new(
                socket2::Domain::IPV4,
                socket2::Type::DGRAM,
                Some(socket2::Protocol::UDP),
            )
            .unwrap()
        };
        let public: IpAddr = "93.184.216.34".parse().unwrap();
        let private: IpAddr = "192.168.77.9".parse().unwrap();
        let vpn_dest: IpAddr = "198.51.100.7".parse().unwrap();

        let balancer = Balancer::new(&BalanceOptions {
            interfaces: vec![LO.into(), "zz-gone9".into()],
            sticky: false,
        });
        balancer.refresh(&Links);
        let assigned = |b: &Balancer| -> Vec<u64> {
            b.snapshot(std::time::Instant::now())
                .interfaces
                .iter()
                .map(|m| m.assigned)
                .collect()
        };

        // Nothing bound: no balancer in effect, no scope made.
        assert!(balancer_in_effect().is_none());
        assert!(DialScope::for_target("example.com", None).is_none());

        let mut a = lo();
        a.set_follow_routes(true);
        a.set_balance(Some(Arc::clone(&balancer)));
        assert!(Arc::ptr_eq(&balancer_in_effect().unwrap(), &balancer));
        assert!(DialScope::for_target("example.com", None).is_some());

        // A public destination: a member. The first choice is loopback.
        let socket = udp();
        let mut tried = 0;
        let member = bind_outbound(
            &socket,
            socket2::Domain::IPV4,
            Some(public),
            &mut tried,
            true,
        )
        .unwrap();
        assert_eq!(member.map(|(_, m)| m), Some(0));
        assert_eq!(tried, 0b01);
        assert_bound_to_loopback(&socket, socket2::Domain::IPV4);
        assert_eq!(assigned(&balancer), [1, 0]);

        // The next one's turn is the member that does not exist: binding
        // fails, it is counted as failed, and the socket takes the other
        // member — the caller sees no error.
        let socket = udp();
        let mut tried = 0;
        let member = bind_outbound(
            &socket,
            socket2::Domain::IPV4,
            Some(public),
            &mut tried,
            true,
        )
        .unwrap();
        assert_eq!(member.map(|(_, m)| m), Some(0));
        assert_eq!(tried, 0b11);
        assert_bound_to_loopback(&socket, socket2::Domain::IPV4);
        let snap = balancer.snapshot(std::time::Instant::now());
        assert_eq!(snap.interfaces[1].failures, 1);
        assert_eq!(snap.interfaces[1].state, MemberState::Up);

        // Every member tried: the default interface.
        let socket = udp();
        let mut tried = 0b11;
        let member = bind_outbound(
            &socket,
            socket2::Domain::IPV4,
            Some(public),
            &mut tried,
            true,
        )
        .unwrap();
        assert!(member.is_none());
        assert_bound_to_loopback(&socket, socket2::Domain::IPV4);

        // Not spread: a private destination, and a socket with no peer.
        let before = assigned(&balancer);
        for dest in [Some(private), None] {
            let socket = udp();
            let member = bind_outbound(&socket, socket2::Domain::IPV4, dest, &mut 0, true).unwrap();
            assert!(member.is_none(), "{dest:?}");
            assert_bound_to_loopback(&socket, socket2::Domain::IPV4);
        }
        assert_eq!(assigned(&balancer), before);

        // Not spread: a destination another VPN has a route for goes to
        // that VPN's interface (here it does not exist, so the default one
        // takes it) — the balancer is not asked either way.
        publish_route_table(RouteTable::build(
            [RawRoute {
                net: "198.51.100.0/24".parse().unwrap(),
                iface: "zz-vpn0".into(),
                index: 99,
                gateway: None,
                metric: 0,
                table: None,
                scoped: false,
            }],
            |_| false,
            |_| RouteIfaceKind::OtherVpn,
        ));
        assert_eq!(
            interface_for(Some(vpn_dest)).map(|(n, _)| n.to_string()),
            Some("zz-vpn0".to_string())
        );
        let socket = udp();
        let member =
            bind_outbound(&socket, socket2::Domain::IPV4, Some(vpn_dest), &mut 0, true).unwrap();
        assert!(member.is_none());
        assert_bound_to_loopback(&socket, socket2::Domain::IPV4);
        assert_eq!(assigned(&balancer), before);
        clear_route_table();

        // Not spread: everything while another VPN is the default
        // interface (`default-via: other-vpn`, full tunnel up).
        let mut status = crate::route_table::OutboundStatus::default();
        assert!(balance_applies(public, &status));
        assert!(!balance_applies(private, &status));
        status.full_tunnel = Some((Arc::from("zz-vpn0"), std::time::SystemTime::now()));
        assert!(balance_applies(public, &status), "default-via: physical");
        status.default_via = crate::route_table::DefaultVia::OtherVpn;
        assert!(!balance_applies(public, &status));

        // Inside a connection's dial scope the interface is recorded and
        // the connection counted in flight on its member; a socket pinned
        // to an interface (a per-rule one, another VPN's client on the
        // physical uplink) is recorded but never a member's.
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let scope = DialScope::for_target("www.example.com", None).unwrap();
            scoped(Some(Arc::clone(&scope)), async {
                let socket = udp();
                bind_outbound(&socket, socket2::Domain::IPV4, Some(public), &mut 0, true).unwrap();
                // The connection's next socket stays on its member.
                let socket = udp();
                let member =
                    bind_outbound(&socket, socket2::Domain::IPV4, Some(public), &mut 0, true)
                        .unwrap();
                assert_eq!(member.map(|(_, m)| m), Some(0));
            })
            .await;
            assert_eq!(scope.interface().as_deref(), Some(LO));
            assert_eq!(scope.member_of(&balancer), Some(0));
            let snap = balancer.snapshot(std::time::Instant::now());
            assert_eq!(snap.interfaces[0].connections, 1);
            drop(scope);
            let snap = balancer.snapshot(std::time::Instant::now());
            assert_eq!(snap.interfaces[0].connections, 0);

            let before = assigned(&balancer);
            let pinned = DialScope::for_target("vpn.corp.example", None).unwrap();
            scoped(Some(Arc::clone(&pinned)), async {
                let socket = udp();
                bind_socket_to_interface(&socket, socket2::Domain::IPV4, LO).unwrap();
            })
            .await;
            assert_eq!(pinned.interface().as_deref(), Some(LO));
            assert_eq!(pinned.member_of(&balancer), None);
            assert_eq!(assigned(&balancer), before);
        });

        // Not spread: a destination the system has a specific route for,
        // also while the routes are not followed (`follow-system-routes`
        // off) — another VPN's prefix, a second NIC's static route: the
        // default interface, as without balancing. (A route on the default
        // interface itself is the same branch; loopback routes are not
        // kept in the snapshot, so it cannot be shown here.)
        let route_on = |net: &str, iface: &str, kind: RouteIfaceKind| {
            publish_route_table(RouteTable::build(
                [RawRoute {
                    net: net.parse().unwrap(),
                    iface: iface.into(),
                    index: 99,
                    gateway: None,
                    metric: 0,
                    table: None,
                    scoped: false,
                }],
                |_| false,
                move |_| kind,
            ));
        };
        let before = assigned(&balancer);
        a.set_follow_routes(false);
        for (net, iface, kind, dest) in [
            (
                "198.51.100.0/24",
                "zz-vpn0",
                RouteIfaceKind::OtherVpn,
                vpn_dest,
            ),
            (
                "203.0.113.0/24",
                "zz-eth9",
                RouteIfaceKind::Physical,
                "203.0.113.7".parse().unwrap(),
            ),
        ] {
            route_on(net, iface, kind);
            let socket = udp();
            let member =
                bind_outbound(&socket, socket2::Domain::IPV4, Some(dest), &mut 0, true).unwrap();
            assert!(member.is_none(), "{net}");
            assert_bound_to_loopback(&socket, socket2::Domain::IPV4);
        }
        a.set_follow_routes(true);
        clear_route_table();
        assert_eq!(assigned(&balancer), before);

        rt.block_on(async {
            // Not spread: what runs in an unbalanced scope (DNS upstream
            // queries), and it leaves the asking connection's scope alone.
            let before = assigned(&balancer);
            let conn = DialScope::for_target("www.example.org", None).unwrap();
            scoped(Some(Arc::clone(&conn)), async {
                let dns = DialScope::unbalanced().expect("balancing is configured");
                assert!(dns.default_only());
                scoped(Some(dns), async {
                    let socket = udp();
                    let member =
                        bind_outbound(&socket, socket2::Domain::IPV4, Some(public), &mut 0, true)
                            .unwrap();
                    assert!(member.is_none());
                    assert_bound_to_loopback(&socket, socket2::Domain::IPV4);
                })
                .await;
            })
            .await;
            assert_eq!(conn.interface(), None);
            assert_eq!(assigned(&balancer), before);

            // A dial that leaves a member for the next one (its line is
            // down: a loopback-bound IPv6 socket has no route to the
            // documentation prefix — nothing leaves the host) does not keep
            // the connection on the member it gave up: no in-flight count
            // is left behind. (IPv6, because Linux takes an IPv4
            // destination without a route on the bound device for on-link
            // and waits. On a host without IPv6 the dial fails before any
            // member is asked, which satisfies the same assertions.)
            let outside: std::net::SocketAddr = "[2001:db8::1]:9".parse().unwrap();
            let conn = DialScope::for_target("retry.example", None).unwrap();
            let failures_before =
                balancer.snapshot(std::time::Instant::now()).interfaces[0].failures;
            let dial = scoped(
                Some(Arc::clone(&conn)),
                tokio::time::timeout(
                    std::time::Duration::from_secs(5),
                    crate::socket_protect::connect_tcp_iface_bound(outside),
                ),
            )
            .await
            .expect("no route: fails at once");
            assert!(dial.is_err());
            assert_eq!(conn.member_of(&balancer), None);
            let snap = balancer.snapshot(std::time::Instant::now());
            assert_eq!(snap.interfaces[0].connections, 0);
            assert_eq!(snap.interfaces[1].connections, 0);
            if snap.interfaces[0].failures > failures_before {
                // The member was tried and given up: the connection ended
                // on the default interface.
                assert_eq!(conn.interface().as_deref(), Some(LO));
            }
        });

        // A mapped IPv4 destination on an IPv6 socket needs a member with
        // an IPv4 default route, not one with only an IPv6 one.
        struct SplitFamilies;
        impl LinkSource for SplitFamilies {
            fn links(&self) -> Vec<Link> {
                [(LO, true), ("zz-gone9", false)]
                    .into_iter()
                    .map(|(name, v4)| Link {
                        name: name.into(),
                        index: interface_index(name).unwrap().unwrap_or(999),
                        kind: LinkKind::Physical,
                        v4,
                        v6: !v4,
                        strict_rp_filter: false,
                    })
                    .collect()
            }
            fn kind_of(&self, _name: &str) -> Option<LinkKind> {
                None
            }
        }
        let split = Balancer::new(&BalanceOptions {
            interfaces: vec![LO.into(), "zz-gone9".into()],
            sticky: false,
        });
        split.refresh(&SplitFamilies);
        a.set_balance(Some(Arc::clone(&split)));
        let mapped: IpAddr = "::ffff:93.184.216.34".parse().unwrap();
        for _ in 0..3 {
            let socket = socket2::Socket::new(
                socket2::Domain::IPV6,
                socket2::Type::DGRAM,
                Some(socket2::Protocol::UDP),
            )
            .unwrap();
            let member =
                bind_outbound(&socket, socket2::Domain::IPV6, Some(mapped), &mut 0, true).unwrap();
            assert_eq!(member.map(|(_, m)| m), Some(0));
        }
        assert_eq!(assigned(&split), [3, 0]);
        // No member has a route for the family: the default interface.
        struct NoLinks;
        impl LinkSource for NoLinks {
            fn links(&self) -> Vec<Link> {
                Vec::new()
            }
            fn kind_of(&self, _name: &str) -> Option<LinkKind> {
                None
            }
        }
        split.refresh(&NoLinks);
        let socket = udp();
        let member =
            bind_outbound(&socket, socket2::Domain::IPV4, Some(public), &mut 0, true).unwrap();
        assert!(member.is_none());
        assert_bound_to_loopback(&socket, socket2::Domain::IPV4);
        a.set_balance(Some(Arc::clone(&balancer)));

        // A newer owner without members turns it off; leaving restores it.
        let b = lo();
        assert!(balancer_in_effect().is_none());
        let socket = udp();
        let member =
            bind_outbound(&socket, socket2::Domain::IPV4, Some(public), &mut 0, true).unwrap();
        assert!(member.is_none());
        drop(b);
        assert!(balancer_in_effect().is_some());
        a.set_balance(None);
        assert!(balancer_in_effect().is_none());
        drop(a);
    }

    /// The dial chokepoints behind `connect_tcp` / `bind_udp`, driven with
    /// the loopback interface installed. Called from the one registry test
    /// (the chokepoints read the process-global registry), and through the
    /// `*_iface_bound` halves directly: the public entry points prefer a
    /// `SocketProtector`, which concurrent tests in this binary install.
    fn dial_chokepoints_bind_their_sockets() {
        use crate::socket_protect::{bind_udp_iface_bound, connect_tcp_iface_bound};
        use socket2::{Domain, SockRef};
        use std::net::SocketAddr;

        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            // TCP: the dial is bound and still reaches a loopback listener.
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            let stream = connect_tcp_iface_bound(addr).await.expect("loopback dial");
            listener.accept().await.unwrap();
            assert_bound_to_loopback(&SockRef::from(&stream), Domain::IPV4);

            // UDP: a wildcard socket is bound and carries a datagram.
            let receiver = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let wildcard: SocketAddr = "0.0.0.0:0".parse().unwrap();
            let socket = bind_udp_iface_bound(wildcard, None).expect("wildcard bind");
            assert_bound_to_loopback(&SockRef::from(&socket), Domain::IPV4);
            socket
                .send_to(b"ping", receiver.local_addr().unwrap())
                .await
                .unwrap();
            let mut buf = [0u8; 8];
            let (n, _) = receiver.recv_from(&mut buf).await.unwrap();
            assert_eq!(&buf[..n], b"ping");

            let wildcard6: SocketAddr = "[::]:0".parse().unwrap();
            let socket6 = bind_udp_iface_bound(wildcard6, None).expect("v6 wildcard bind");
            assert_bound_to_loopback(&SockRef::from(&socket6), Domain::IPV6);

            // The scope is enforced by the kernel, not just recorded: a
            // socket bound to loopback has no route to a non-loopback
            // destination (TEST-NET-1 — nothing leaves the host either way).
            #[cfg(target_os = "macos")]
            {
                let outside: SocketAddr = "192.0.2.1:9".parse().unwrap();
                let err = connect_tcp_iface_bound(outside)
                    .await
                    .expect_err("loopback-scoped socket must not reach TEST-NET-1");
                assert_eq!(err.raw_os_error(), Some(libc::ENETUNREACH), "{err}");
                let err = socket.send_to(b"x", outside).await.expect_err("scoped UDP");
                assert_eq!(err.raw_os_error(), Some(libc::ENETUNREACH), "{err}");

                // A UDP socket pinned to a loopback address is exempt.
                let pinned: SocketAddr = "127.0.0.1:0".parse().unwrap();
                let socket = bind_udp_iface_bound(pinned, None).expect("loopback bind");
                assert_eq!(SockRef::from(&socket).device_index_v4().unwrap(), None);
                assert!(!binds_peer(pinned.ip()) && binds_peer(outside.ip()));
            }
        });
    }

    /// The kernel reports the binding the socket option installed.
    fn assert_bound_to_loopback(socket: &socket2::Socket, domain: socket2::Domain) {
        #[cfg(target_os = "macos")]
        {
            let want = interface_index(LO).unwrap();
            let got = if domain == socket2::Domain::IPV6 {
                socket.device_index_v6().unwrap()
            } else {
                socket.device_index_v4().unwrap()
            };
            assert_eq!(got.map(std::num::NonZeroU32::get), want);
        }
        #[cfg(target_os = "linux")]
        {
            let _ = domain;
            assert_eq!(socket.device().unwrap().as_deref(), Some(LO.as_bytes()));
        }
    }
}
