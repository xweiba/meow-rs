use crate::tunnel::{ResolvedTarget, TunnelInner};
use dashmap::DashMap;
use meow_common::atomic::AtomicU;
use meow_common::{with_dial_timeout, Metadata, ProxyPacketConn};
use std::net::SocketAddr;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::task::JoinHandle;
use tracing::{debug, info, warn};

/// A routed UDP socket owns its statistics entry. Closing, cancellation and
/// dropping the socket all unregister it, including in headless mode.
struct TrackedPacketConn {
    conn: Box<dyn ProxyPacketConn>,
    registration: UdpRegistration,
}

/// Own registration before the dial too, so cancelling setup never leaks it.
struct UdpRegistration {
    stats: Arc<crate::Statistics>,
    counters: Arc<crate::statistics::ConnCounters>,
    id: Option<uuid::Uuid>,
    closed: std::sync::atomic::AtomicBool,
}

impl UdpRegistration {
    fn finish(&self) -> bool {
        if !self.closed.swap(true, Ordering::AcqRel) {
            match self.id {
                Some(id) => self.stats.close_connection(id),
                None => self.stats.close_headless_connection(&self.counters),
            }
            return true;
        }
        false
    }
}

impl Drop for UdpRegistration {
    fn drop(&mut self) {
        let _ = self.finish();
    }
}

impl TrackedPacketConn {
    fn finish(&self) {
        if self.registration.finish() {
            let _ = self.conn.close();
        }
    }
}

impl Drop for TrackedPacketConn {
    fn drop(&mut self) {
        self.finish();
    }
}

#[async_trait::async_trait]
impl ProxyPacketConn for TrackedPacketConn {
    async fn read_packet(&self, buf: &mut [u8]) -> meow_common::Result<(usize, SocketAddr)> {
        tokio::select! {
            biased;
            () = self.registration.counters.closed() => {
                self.finish();
                Err(meow_common::MeowError::Other("UDP connection closed".into()))
            }
            result = self.conn.read_packet(buf) => {
                if let Ok((n, _)) = &result {
                    self.registration.stats.record_download(&self.registration.counters, *n as _);
                } else {
                    self.finish();
                }
                result
            }
        }
    }

    async fn write_packet(&self, buf: &[u8], addr: &SocketAddr) -> meow_common::Result<usize> {
        tokio::select! {
            biased;
            () = self.registration.counters.closed() => {
                self.finish();
                Err(meow_common::MeowError::Other("UDP connection closed".into()))
            }
            result = self.conn.write_packet(buf, addr) => {
                if let Ok(n) = &result {
                    self.registration.stats.record_upload(&self.registration.counters, *n as _);
                } else {
                    self.finish();
                }
                result
            }
        }
    }

    fn local_addr(&self) -> meow_common::Result<SocketAddr> {
        self.conn.local_addr()
    }

    fn close(&self) -> meow_common::Result<()> {
        self.finish();
        Ok(())
    }
}

/// Select a concrete UDP node once, then register and dial it. The recorded
/// chain uses that same selection, so round-robin groups cannot report the
/// next node instead. Relay adapters remain complete paths.
pub async fn dial_tracked_udp(
    tunnel: &TunnelInner,
    metadata: &Metadata,
    target: ResolvedTarget,
) -> meow_common::Result<Box<dyn ProxyPacketConn>> {
    Ok(Box::new(
        dial_tracked_udp_conn(tunnel, metadata, target).await?,
    ))
}

async fn dial_tracked_udp_conn(
    tunnel: &TunnelInner,
    metadata: &Metadata,
    mut target: ResolvedTarget,
) -> meow_common::Result<TrackedPacketConn> {
    if target.chains.is_empty() {
        target
            .pin_dns_leaf(metadata, true)
            .map_err(meow_common::MeowError::Io)?;
    }
    let ResolvedTarget {
        adapter,
        rule_name,
        rule_payload,
        route,
        chains,
    } = target;
    if !adapter.support_udp() {
        return Err(meow_common::MeowError::NotSupported(format!(
            "UDP unavailable via {} (udp:false); select a node with udp:true or configure an explicit REJECT fallback",
            adapter.name()
        )));
    }
    let (id, counters) = if let Some(counters) = tunnel.stats.begin_headless_connection() {
        (None, counters)
    } else {
        let (id, counters) = tunnel.stats.track_connection_with_counters(
            metadata.clone(),
            rule_name,
            rule_payload,
            chains,
        );
        (Some(id), counters)
    };
    // This guard also owns registration while the dial is pending or fails.
    let registration = UdpRegistration {
        stats: Arc::clone(&tunnel.stats),
        counters,
        id,
        closed: std::sync::atomic::AtomicBool::new(false),
    };
    let dial = meow_common::outbound_balance::scoped(
        registration.counters.dial_scope(metadata),
        with_dial_timeout(adapter.name(), adapter.dial_udp(metadata)),
    );
    let conn = tokio::select! {
        biased;
        () = registration.counters.closed() => {
            return Err(meow_common::MeowError::Other("UDP connection closed during dial".into()));
        }
        result = dial => result?,
    };
    drop(route);
    Ok(TrackedPacketConn { conn, registration })
}

/// Own the reply task together with its socket. A cancelled listener future
/// must abort the detached reader before releasing the tracked connection.
pub struct UdpRelayGuard {
    conn: Arc<dyn ProxyPacketConn>,
    reader: tokio::task::AbortHandle,
}

impl UdpRelayGuard {
    pub fn new(conn: Arc<dyn ProxyPacketConn>, reader: tokio::task::AbortHandle) -> Self {
        Self { conn, reader }
    }
}

impl Drop for UdpRelayGuard {
    fn drop(&mut self) {
        self.reader.abort();
        let _ = self.conn.close();
    }
}

/// Idle timeout before a UDP NAT session is swept. Matches upstream mihomo-go.
pub const DEFAULT_UDP_IDLE: Duration = Duration::from_secs(60);

/// How often the sweeper scans for expired sessions.
pub const DEFAULT_SWEEP_INTERVAL: Duration = Duration::from_secs(15);

/// NAT table entry for UDP sessions.
// M2 layout change (ADR-0011 T3):
//   proxy_name: String (24 B) → Arc<str> (16 B fat-ptr, −8 B per struct
//   instance). Note this is *not* interning: the slow path in `handle_udp`
//   builds a fresh `Arc::from(proxy.name())` per dial, so two sessions using
//   the same proxy each hold their own heap allocation, not a shared one.
pub struct UdpSession {
    pub conn: Box<dyn ProxyPacketConn>,
    pub proxy_name: Arc<str>,
    /// Monotonic millis since process start. Bumped on every fast-path forward
    /// so idle sessions can be evicted by [`spawn_nat_sweeper`].
    last_activity_ms: AtomicU,
}

impl UdpSession {
    pub fn new(conn: Box<dyn ProxyPacketConn>, proxy_name: Arc<str>) -> Self {
        Self {
            conn,
            proxy_name,
            last_activity_ms: AtomicU::new(monotonic_ms() as meow_common::atomic::Uint),
        }
    }

    /// Mark the session active as of now. Called on every outbound fast-path
    /// forward so [`spawn_nat_sweeper`] keeps the entry alive. `pub` so an
    /// out-of-crate reply reader (e.g. the meow-ios FFI, which owns the
    /// inbound read loop) can refresh the same clock on server→app traffic —
    /// otherwise a receive-active / send-quiet session is wrongly swept.
    pub fn touch(&self) {
        self.last_activity_ms.store(
            monotonic_ms() as meow_common::atomic::Uint,
            Ordering::Relaxed,
        );
    }

    /// Time since the last [`touch`](Self::touch). `pub` so an out-of-crate
    /// reply reader can gate its own idle backstop on the same bidirectional
    /// clock the sweeper uses, instead of a one-directional wall-clock timer.
    pub fn idle_for(&self) -> Duration {
        let now = monotonic_ms() as meow_common::atomic::Uint;
        let last = self.last_activity_ms.load(Ordering::Relaxed);
        #[allow(
            clippy::useless_conversion,
            reason = "identity on 64-bit; u32→u64 widening on mips32"
        )]
        Duration::from_millis(u64::from(now.wrapping_sub(last)))
    }
}

impl Drop for UdpSession {
    fn drop(&mut self) {
        let _ = self.conn.close();
    }
}

fn monotonic_ms() -> u64 {
    static START: std::sync::OnceLock<Instant> = std::sync::OnceLock::new();
    let start = START.get_or_init(Instant::now);
    start.elapsed().as_millis() as u64
}

// Direction A (ADR-0008 §6): key is a (src, dst) SocketAddr tuple — zero heap
// allocation on the per-packet fast path, replacing the previous String built
// by `format!("{}:{}", src, metadata.remote_address())`.
pub type NatTable = Arc<DashMap<(SocketAddr, SocketAddr), Arc<UdpSession>>>;

pub fn new_nat_table() -> NatTable {
    Arc::new(DashMap::new())
}

/// One UDP flow's handle on the tunnel's flush signal (issue #695).
///
/// The listeners own their UDP flow tables (TUN, SOCKS5, TProxy and the
/// Shadowsocks inbound each run one task per flow), so the tunnel cannot
/// close those flows directly. Each flow takes a watch from
/// [`TunnelInner::udp_flush_watch`] *before* dialling its outbound and adds
/// [`flushed`](Self::flushed) to its relay `select!`: once
/// [`Tunnel::close_all_udp_sessions`](crate::Tunnel::close_all_udp_sessions)
/// runs, the flow ends and closes its outbound conn, and the client's next
/// datagram opens a fresh flow with a fresh dial. A live watch is what the
/// flush counts as a listener-owned flow.
pub struct UdpFlushWatch(tokio::sync::watch::Receiver<u64>);

impl UdpFlushWatch {
    pub(crate) fn new(receiver: tokio::sync::watch::Receiver<u64>) -> Self {
        Self(receiver)
    }

    /// Resolve once a flush has been issued since this watch was taken —
    /// immediately if one landed while the flow was still dialling.
    /// Cancel-safe. Never resolves once the tunnel is gone.
    pub async fn flushed(&mut self) {
        if self.0.changed().await.is_err() {
            std::future::pending::<()>().await;
        }
    }

    /// Whether a flush has been issued since this watch was taken.
    pub fn is_flushed(&self) -> bool {
        self.0.has_changed().unwrap_or(false)
    }
}

/// Evict sessions idle for more than `idle` from `table`, returning the
/// eviction count. Split out of the sweeper loop so tests can exercise the
/// decision synchronously instead of racing a real-time ticker.
fn sweep_idle_sessions(table: &NatTable, idle: Duration) -> usize {
    let before = table.len();
    if before == 0 {
        return 0;
    }
    table.retain(|_key, session| {
        if session.idle_for() < idle {
            return true;
        }
        // A reply reader can still hold an Arc after table eviction.
        let _ = session.conn.close();
        false
    });
    // A concurrent `handle_udp` insert can land between the `before`
    // snapshot and the post-retain `len()`, so saturating-sub is load
    // bearing — plain subtraction would panic in dev builds and kill the
    // detached sweeper task.
    let evicted = before.saturating_sub(table.len());
    if evicted > 0 {
        debug!(
            "UDP NAT sweeper: evicted {evicted} idle sessions (remaining {})",
            table.len()
        );
    }
    evicted
}

/// Spawn the background sweeper that evicts UDP NAT sessions idle for more
/// than `idle`. Scans every `interval`. The task exits when the caller drops
/// the returned `JoinHandle`'s aborter (or the last Arc to the table is
/// dropped and the weak upgrade fails).
pub fn spawn_nat_sweeper(
    nat_table: &NatTable,
    idle: Duration,
    interval: Duration,
) -> JoinHandle<()> {
    let weak = Arc::downgrade(nat_table);
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(interval);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        // First tick fires immediately; skip it.
        ticker.tick().await;
        loop {
            ticker.tick().await;
            let Some(table) = weak.upgrade() else {
                debug!("UDP NAT sweeper: table dropped, exiting");
                return;
            };
            sweep_idle_sessions(&table, idle);
        }
    })
}

/// Handle a UDP packet: look up or create a NAT session.
pub async fn handle_udp(
    tunnel: &TunnelInner,
    data: &[u8],
    src: SocketAddr,
    mut metadata: Metadata,
) {
    // Fake-IP → host rewrite (no-op outside fake-IP mode aside from a
    // snooping-cache hostname fill-in). An unmapped fake-IP destination
    // is dropped — dialing it loops back into a fake-IP-routed inbound
    // (issue #618).
    if matches!(
        tunnel.pre_handle_metadata(&mut metadata),
        crate::tunnel::PreHandleVerdict::Drop
    ) {
        return;
    }

    let flush = tunnel.udp_flush_watch();
    let selected = tunnel.resolve_udp_route(&mut metadata).await;

    // Build destination SocketAddr for the NAT key.
    // pre_resolve() populates dst_ip for any hostname; if it is still None
    // after that (resolution failure or unresolvable host), we cannot track
    // the session and must discard the packet.
    let Some(dst_ip) = metadata.dst_ip else {
        warn!(
            "UDP {}: dst_ip not resolved after pre_resolve — dropping",
            metadata.remote_address()
        );
        return;
    };
    let dst_addr = SocketAddr::new(dst_ip, metadata.dst_port);
    let key = (src, dst_addr);

    // Fast path: existing session — forward and return.
    //
    // Clone the `Arc<UdpSession>` out and DROP the DashMap guard before the
    // `.await` below. `nat_table.get()` returns a `Ref` that holds a *read*
    // lock on the key's shard for as long as it is alive. Two ways the old
    // `if let Some(session) = nat_table.get(&key)` form deadlocked:
    //   1. The guard was held across `write_packet().await`, so while this task
    //      parked on the upstream round-trip the shard read-lock stayed held,
    //      blocking every same-shard `insert`/`remove`/sweep.
    //   2. On a write error it called `nat_table.remove(&key)` — a *write* lock
    //      on the very shard whose read-lock the `session` guard still held.
    //      A read+write on the same shard from one thread self-deadlocks the
    //      shard's RwLock, parking the worker forever; on the 2-worker iOS
    //      runtime both workers then wedge → total packet stall + dead control
    //      API. Fires whenever an established session's upstream has died and
    //      the app sends another datagram (common for QUIC / long-lived UDP).
    // Holding only the cloned `Arc` keeps the session alive with no lock held.
    let existing = tunnel.nat_table.get(&key).map(|s| Arc::clone(s.value()));
    if let Some(session) = existing {
        if let Err(e) = session.conn.write_packet(data, &dst_addr).await {
            debug!("UDP write error for {} -> {}: {}", src, dst_addr, e);
            // Compare-and-remove: evict only the session that actually failed.
            // While this write was parked a concurrent slow path may have
            // replaced the entry with a fresh healthy session; an
            // unconditional `remove()` would tear that replacement down and
            // force the next packet to redial (issue #432).
            tunnel
                .nat_table
                .remove_if(&key, |_, s| Arc::ptr_eq(s, &session));
        } else {
            session.touch();
        }
        return;
    }

    // `find-process-mode: always`: the app shows (and filters by) it.
    tunnel.enrich_process(&mut metadata).await;

    // Slow path: all client UDP, including port 53, follows routing policy.
    // The tracked dial retains this route's registry until setup finishes.
    let Some(target) = (match selected {
        Some(target) => Some(target),
        None => tunnel.resolve_proxy(&metadata).await,
    }) else {
        warn!("no matching rule for UDP {}", metadata.remote_address());
        return;
    };

    info!(
        "UDP {} --> {} match {}({}) using {}",
        src,
        dst_addr,
        target.rule_name,
        target.rule_payload,
        target.adapter.name()
    );

    // The pre-routing watch rejects a socket established across a flush.
    // Bounded like mihomo's `C.DefaultUDPTimeout`. An unbounded dial here is
    // worse than on TCP: the key is still unclaimed (see below), so every
    // datagram of the flow starts its own stalled dial.
    let proxy_name = Arc::from(target.adapter.name());
    match dial_tracked_udp_conn(tunnel, &metadata, target).await {
        Ok(conn) if flush.is_flushed() => {
            debug!(
                "UDP {} -> {}: sessions flushed during the dial; dropping datagram",
                src, dst_addr
            );
            let _ = conn.close();
        }
        Ok(conn) => {
            let counters = Arc::clone(&conn.registration.counters);
            let session = Arc::new(UdpSession::new(Box::new(conn), proxy_name));
            // Claim the key atomically before the first write. The dial above
            // is a long await with the key unclaimed, so two concurrent
            // handle_udp calls for the same brand-new (src, dst) can both
            // reach this point; a blind `insert` here made the second call
            // silently drop — and thereby close — the first session with the
            // reply to its datagram still in flight (issue #432).
            // `entry().or_insert_with()` takes the shard write lock but has no
            // `.await` inside, and the guard is dropped before the write
            // below, so this cannot reintroduce the guard-across-await
            // deadlock fixed in 1454ef2.
            let winner = Arc::clone(
                tunnel
                    .nat_table
                    .entry(key)
                    .or_insert_with(|| Arc::clone(&session))
                    .value(),
            );
            if Arc::ptr_eq(&winner, &session) {
                // A shared NAT session may have no reply reader. DELETE must
                // still close its socket and evict it immediately. Weak refs
                // let normal idle/drop cleanup wake and retire this watcher.
                let table = Arc::downgrade(&tunnel.nat_table);
                let weak_session = Arc::downgrade(&session);
                tokio::spawn(async move {
                    counters.closed().await;
                    if let Some(session) = weak_session.upgrade() {
                        let _ = session.conn.close();
                        if let Some(table) = table.upgrade() {
                            table.remove_if(&key, |_, s| Arc::ptr_eq(s, &session));
                        }
                    }
                });
            }
            if !Arc::ptr_eq(&winner, &session) {
                // Lost the claim: a concurrent call installed its session
                // first. Close the redundant conn and carry this datagram on
                // the winner, so exactly one upstream flow ever sees traffic.
                debug!(
                    "UDP concurrent session create for {} -> {}: folding into winner",
                    src, dst_addr
                );
                if let Err(e) = session.conn.close() {
                    debug!(
                        "UDP close of redundant conn for {} -> {}: {}",
                        src, dst_addr, e
                    );
                }
            }
            if let Err(e) = winner.conn.write_packet(data, &dst_addr).await {
                warn!("UDP initial write error for {} -> {}: {}", src, dst_addr, e);
                tunnel
                    .nat_table
                    .remove_if(&key, |_, s| Arc::ptr_eq(s, &winner));
            }
        }
        Err(e) => {
            warn!("UDP dial error for {} -> {}: {}", src, dst_addr, e);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tunnel::Tunnel;
    use async_trait::async_trait;
    use meow_common::adapter::ProxyAdapter;
    use meow_common::error::Result as MeowResult;
    use meow_common::{
        AdapterType, DelayHistory, DnsMode, MeowError, Network, Proxy, ProxyConn, ProxyHealth,
        TunnelMode,
    };
    use smol_str::SmolStr;
    use std::collections::HashMap;
    use std::sync::atomic::{AtomicBool, AtomicUsize};
    use std::sync::Mutex;

    fn mk_tunnel() -> Tunnel {
        let resolver = Arc::new(meow_dns::Resolver::new(
            vec![],
            vec![],
            DnsMode::Normal,
            meow_trie::DomainTrie::new(),
            false,
            true,
        ));
        Tunnel::new(resolver)
    }

    fn mk_metadata(src: SocketAddr, dst: SocketAddr) -> Metadata {
        Metadata {
            network: Network::Udp,
            src_ip: Some(src.ip()),
            src_port: src.port(),
            dst_ip: Some(dst.ip()),
            dst_port: dst.port(),
            ..Default::default()
        }
    }

    async fn configured_tunnel(yaml: &str) -> Tunnel {
        let config = meow_config::build_config(meow_config::parse_raw_yaml(yaml).unwrap(), None)
            .await
            .unwrap();
        let tunnel = Tunnel::new_with_slot(Arc::clone(&config.dns.resolver_slot));
        tunnel.update_routing(config.proxies, config.rules, config.dialer_registry);
        tunnel
    }

    #[tokio::test]
    async fn real_udp_counters_metadata_delete_and_idle_cleanup() {
        let tunnel = mk_tunnel();
        let server = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let dst = server.local_addr().unwrap();
        let src = "127.0.0.1:43210".parse().unwrap();
        handle_udp(tunnel.inner(), b"hello", src, mk_metadata(src, dst)).await;
        let session = Arc::clone(tunnel.inner().nat_table.get(&(src, dst)).unwrap().value());
        let mut buf = [0; 32];
        let (n, peer) = tokio::time::timeout(Duration::from_secs(2), server.recv_from(&mut buf))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&buf[..n], b"hello");
        server.send_to(b"world!", peer).await.unwrap();
        let (n, _) =
            tokio::time::timeout(Duration::from_secs(2), session.conn.read_packet(&mut buf))
                .await
                .unwrap()
                .unwrap();
        assert_eq!(&buf[..n], b"world!");
        let entries = tunnel.inner().stats.active_connections();
        assert_eq!(entries.len(), 1);
        let info = &entries[0];
        assert_eq!(info.metadata.network, Network::Udp);
        assert_eq!(info.metadata.src_port, src.port());
        assert_eq!(info.metadata.dst_port, dst.port());
        assert_eq!(&*info.chains[0], "DIRECT");
        assert_eq!(info.counters.upload_bytes(), 5);
        assert_eq!(info.counters.download_bytes(), 6);
        let json = serde_json::to_value(info).unwrap();
        assert_eq!(json["metadata"]["network"], "udp");
        assert_eq!(json["upload"], 5);
        assert_eq!(json["download"], 6);
        assert_eq!(json["chains"], serde_json::json!(["DIRECT"]));
        assert!(json["rule"].is_string() && json["rulePayload"].is_string());
        assert_eq!(tunnel.inner().stats.snapshot(), (5, 6));
        tunnel.inner().stats.close_connection(info.id);
        tokio::time::timeout(Duration::from_secs(2), async {
            while !tunnel.inner().nat_table.is_empty() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert!(session.conn.write_packet(b"closed", &dst).await.is_err());
        assert_eq!(tunnel.inner().stats.active_connection_count(), 0);

        handle_udp(tunnel.inner(), b"new", src, mk_metadata(src, dst)).await;
        assert_eq!(tunnel.inner().stats.active_connection_count(), 1);
        // Even a reader holding an Arc must not keep an evicted entry alive.
        let held = Arc::clone(tunnel.inner().nat_table.get(&(src, dst)).unwrap().value());
        assert_eq!(
            sweep_idle_sessions(&tunnel.inner().nat_table, Duration::ZERO),
            1
        );
        assert_eq!(tunnel.inner().stats.active_connection_count(), 0);
        assert!(held.conn.write_packet(b"closed", &dst).await.is_err());
    }

    #[tokio::test]
    async fn udp_rule_fallthrough_remains_compatible_and_reject_fallback_wins() {
        for fallback in [false, true] {
            let rule = if fallback {
                "  - AND,((NETWORK,UDP),(DST-PORT,3478)),REJECT\n"
            } else {
                ""
            };
            let tunnel = configured_tunnel(&format!(
                r#"
proxies:
  - {{name: tcp-only, type: http, server: 127.0.0.1, port: 1}}
proxy-groups:
  - {{name: policy:ai, type: select, proxies: [tcp-only]}}
rules:
  - AND,((NETWORK,UDP),(DST-PORT,3478)),policy:ai
{rule}  - MATCH,DIRECT
"#
            ))
            .await;
            let mut metadata = mk_metadata(
                "127.0.0.1:43211".parse().unwrap(),
                "127.0.0.1:3478".parse().unwrap(),
            );
            let selected = tunnel
                .inner()
                .resolve_udp_route(&mut metadata)
                .await
                .unwrap();
            assert_eq!(
                selected.adapter.name(),
                if fallback { "REJECT" } else { "DIRECT" }
            );
        }
    }

    #[tokio::test]
    async fn global_tcp_only_udp_diagnostic_is_actionable_and_does_not_leak() {
        let tunnel = configured_tunnel(
            r#"
proxies:
  - {name: tcp-only, type: http, server: 127.0.0.1, port: 1}
proxy-groups:
  - {name: GLOBAL, type: select, proxies: [tcp-only]}
"#,
        )
        .await;
        tunnel.set_mode(TunnelMode::Global);
        let mut metadata = mk_metadata(
            "127.0.0.1:43212".parse().unwrap(),
            "127.0.0.1:3478".parse().unwrap(),
        );
        let target = tunnel
            .inner()
            .resolve_udp_route(&mut metadata)
            .await
            .unwrap();
        let error = match dial_tracked_udp(tunnel.inner(), &metadata, target).await {
            Ok(_) => panic!("TCP-only node must not carry UDP"),
            Err(error) => error.to_string(),
        };
        assert!(
            error.contains("tcp-only") && error.contains("udp:false") && error.contains("udp:true")
        );
        assert_eq!(tunnel.inner().stats.active_connection_count(), 0);
    }

    #[tokio::test]
    async fn headless_udp_can_be_closed_without_api_entries() {
        let tunnel = mk_tunnel();
        tunnel.inner().stats.set_headless();
        let src = "127.0.0.1:43215".parse().unwrap();
        let dst = "127.0.0.1:3478".parse().unwrap();
        handle_udp(tunnel.inner(), b"hello", src, mk_metadata(src, dst)).await;
        assert_eq!(tunnel.inner().stats.active_connection_count(), 0);
        assert_eq!(tunnel.inner().nat_table.len(), 1);
        assert_eq!(tunnel.inner().stats.close_all_connections_counted(), 1);
        tokio::time::timeout(Duration::from_secs(2), async {
            while !tunnel.inner().nat_table.is_empty() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert_eq!(tunnel.inner().stats.close_all_connections_counted(), 0);
    }

    #[tokio::test]
    async fn udp_history_capacity_and_zero_never_close_active_connections() {
        let tunnel = mk_tunnel();
        let server = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let dst = server.local_addr().unwrap();
        let mut metadata = mk_metadata("127.0.0.1:43217".parse().unwrap(), dst);
        let target = tunnel
            .inner()
            .resolve_udp_route(&mut metadata)
            .await
            .unwrap();
        let active = dial_tracked_udp(tunnel.inner(), &metadata, target)
            .await
            .unwrap();
        let history = tunnel.inner().stats.history();
        history.set_limit(2);
        for _ in 0..5 {
            let target = tunnel
                .inner()
                .resolve_udp_route(&mut metadata)
                .await
                .unwrap();
            let conn = dial_tracked_udp(tunnel.inner(), &metadata, target)
                .await
                .unwrap();
            conn.write_packet(b"x", &dst).await.unwrap();
            drop(conn);
            assert!(history.len() <= 2);
            assert_eq!(tunnel.inner().stats.active_connection_count(), 1);
        }
        let kept = history.delta(0);
        assert_eq!(kept.kept, vec![5, 6]);
        assert!(kept
            .changed
            .iter()
            .all(|row| row.metadata.network == Network::Udp && row.upload == 1));
        history.set_limit(1);
        assert_eq!(history.len(), 1);
        assert_eq!(
            active.write_packet(b"still active", &dst).await.unwrap(),
            12
        );
        history.set_limit(0);
        assert!(history.is_empty());
        assert_eq!(tunnel.inner().stats.active_connection_count(), 1);
        assert_eq!(
            active.write_packet(b"still active", &dst).await.unwrap(),
            12
        );
        drop(active);
        assert_eq!(tunnel.inner().stats.active_connection_count(), 0);
        assert!(
            history.is_empty(),
            "zero disables ended records, not active tracking"
        );
    }

    #[tokio::test]
    async fn udp_delete_or_abort_during_dial_releases_registration() {
        for abort in [false, true] {
            let tunnel = mk_tunnel();
            tunnel.set_mode(TunnelMode::Global);
            let mut proxies: HashMap<SmolStr, Arc<dyn Proxy>> = HashMap::new();
            proxies.insert(
                "GLOBAL".into(),
                Arc::new(StalledDialProxy {
                    health: ProxyHealth::new(),
                }),
            );
            tunnel.update_proxies(proxies, Default::default());
            let task = tokio::spawn({
                let tunnel = tunnel.clone();
                async move {
                    let src = "127.0.0.1:43216".parse().unwrap();
                    let dst = "127.0.0.1:3478".parse().unwrap();
                    handle_udp(tunnel.inner(), b"hello", src, mk_metadata(src, dst)).await;
                }
            });
            tokio::time::timeout(Duration::from_secs(2), async {
                while tunnel.inner().stats.active_connection_count() == 0 {
                    tokio::task::yield_now().await;
                }
            })
            .await
            .unwrap();
            if abort {
                task.abort();
            } else {
                let info = tunnel.inner().stats.active_connections().pop().unwrap();
                tunnel.inner().stats.close_connection(info.id);
            }
            let _ = tokio::time::timeout(Duration::from_secs(2), task)
                .await
                .unwrap();
            assert_eq!(tunnel.inner().stats.active_connection_count(), 0);
            assert!(tunnel.inner().nat_table.is_empty());
        }
    }

    #[tokio::test]
    async fn round_robin_chain_names_the_actual_udp_socket() {
        let tunnel = configured_tunnel(
            r#"
proxies:
  - {name: first, type: direct}
  - {name: second, type: direct}
proxy-groups:
  - {name: balance, type: load-balance, strategy: round-robin, proxies: [first, second]}
  - {name: policy, type: select, proxies: [balance]}
rules: ["MATCH,policy"]
"#,
        )
        .await;
        let mut metadata = mk_metadata(
            "127.0.0.1:43213".parse().unwrap(),
            "127.0.0.1:3478".parse().unwrap(),
        );
        let mut names = Vec::new();
        for _ in 0..2 {
            let target = tunnel
                .inner()
                .resolve_udp_route(&mut metadata)
                .await
                .unwrap();
            let conn = dial_tracked_udp(tunnel.inner(), &metadata, target)
                .await
                .unwrap();
            let info = tunnel.inner().stats.active_connections().pop().unwrap();
            assert_eq!(&*info.chains[1], "balance");
            assert_eq!(&*info.chains[2], "policy");
            names.push(Arc::clone(&info.chains[0]));
            drop(conn);
            assert_eq!(tunnel.inner().stats.active_connection_count(), 0);
        }
        assert_ne!(names[0], names[1]);
    }

    #[tokio::test]
    async fn udp_port_53_obeys_reject_rule() {
        let tunnel = mk_tunnel();
        let res = meow_config::rebuild_from_raw(&Default::default()).unwrap();
        tunnel.update_proxies(res.proxies, res.dialer_registry);
        tunnel.update_rules(vec![Box::new(meow_rules::final_rule::FinalRule::new(
            "REJECT",
        ))]);
        let src = "127.0.0.1:12345".parse().unwrap();
        for port in [53, 5353] {
            let dst = SocketAddr::from(([127, 0, 0, 1], port));
            handle_udp(
                tunnel.inner(),
                b"not a DNS query",
                src,
                mk_metadata(src, dst),
            )
            .await;
            let session = tunnel.inner().nat_table.get(&(src, dst)).unwrap();
            assert_eq!(&*session.proxy_name, "REJECT");
            assert!(
                session.conn.local_addr().is_err(),
                "must not open a DIRECT socket"
            );
        }
    }

    #[tokio::test(start_paused = true)]
    async fn udp_port_53_obeys_proxy_rule_and_global_mode() {
        for mode in [TunnelMode::Rule, TunnelMode::Global] {
            let tunnel = mk_tunnel();
            tunnel.set_mode(mode);
            let proxy = Arc::new(SlowDialProxy::new());
            let mut proxies: HashMap<SmolStr, Arc<dyn Proxy>> = HashMap::new();
            proxies.insert("GLOBAL".into(), Arc::clone(&proxy) as Arc<dyn Proxy>);
            tunnel.update_proxies(proxies, Default::default());
            tunnel.update_rules(vec![Box::new(meow_rules::final_rule::FinalRule::new(
                "GLOBAL",
            ))]);
            let src = "127.0.0.1:12345".parse().unwrap();
            let dst = "127.0.0.1:53".parse().unwrap();
            handle_udp(tunnel.inner(), b"query", src, mk_metadata(src, dst)).await;
            assert_eq!(proxy.dials.load(Ordering::SeqCst), 1);
            assert_eq!(proxy.conns.lock().unwrap()[0].0.load(Ordering::SeqCst), 1);
        }
    }

    struct NoopPacketConn;

    #[async_trait]
    impl ProxyPacketConn for NoopPacketConn {
        async fn read_packet(&self, _buf: &mut [u8]) -> MeowResult<(usize, SocketAddr)> {
            Ok((0, "0.0.0.0:0".parse().unwrap()))
        }
        async fn write_packet(&self, buf: &[u8], _addr: &SocketAddr) -> MeowResult<usize> {
            Ok(buf.len())
        }
        fn local_addr(&self) -> MeowResult<SocketAddr> {
            Ok("0.0.0.0:0".parse().unwrap())
        }
        fn close(&self) -> MeowResult<()> {
            Ok(())
        }
    }

    fn mk_session() -> Arc<UdpSession> {
        Arc::new(UdpSession::new(Box::new(NoopPacketConn), Arc::from("test")))
    }

    /// A packet conn whose `write_packet` always fails — models an established
    /// UDP session whose upstream relay has died. Used to drive the fast-path
    /// write-error branch in `handle_udp`.
    struct FailingPacketConn;

    #[async_trait]
    impl ProxyPacketConn for FailingPacketConn {
        async fn read_packet(&self, _buf: &mut [u8]) -> MeowResult<(usize, SocketAddr)> {
            Ok((0, "0.0.0.0:0".parse().unwrap()))
        }
        async fn write_packet(&self, _buf: &[u8], _addr: &SocketAddr) -> MeowResult<usize> {
            Err(meow_common::MeowError::Other("upstream dead".into()))
        }
        fn local_addr(&self) -> MeowResult<SocketAddr> {
            Ok("0.0.0.0:0".parse().unwrap())
        }
        fn close(&self) -> MeowResult<()> {
            Ok(())
        }
    }

    fn mk_key(port: u16) -> (SocketAddr, SocketAddr) {
        (
            SocketAddr::from(([127, 0, 0, 1], port)),
            SocketAddr::from(([8, 8, 8, 8], 53)),
        )
    }

    #[tokio::test(start_paused = false)]
    async fn sweeper_evicts_idle_sessions() {
        let table = new_nat_table();
        table.insert(mk_key(1), mk_session());
        table.insert(mk_key(2), mk_session());
        assert_eq!(table.len(), 2);

        let _handle =
            spawn_nat_sweeper(&table, Duration::from_millis(50), Duration::from_millis(20));

        // Poll instead of racing a fixed sleep: the sweep needs one tick
        // past the idle threshold (~70ms), but a loaded CI runner may
        // stall the ticker far longer than that.
        for _ in 0..100 {
            if table.is_empty() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        panic!("idle sessions should have been swept");
    }

    /// The sweep decision itself is deterministic once activity stamps are
    /// injected — exercise `sweep_idle_sessions` directly rather than racing
    /// `touch()` calls against a real-time ticker (a >55ms scheduler stall
    /// between touches used to evict the session mid-test).
    #[test]
    fn sweep_keeps_fresh_evicts_stale() {
        let table = new_nat_table();
        let fresh = mk_session();
        let stale = mk_session();
        // `idle_for` subtracts with wrapping arithmetic, so a wrapped-back
        // stamp reads as "60s ago" even when the process monotonic clock
        // is younger than that.
        stale.last_activity_ms.store(
            monotonic_ms().wrapping_sub(60_000) as meow_common::atomic::Uint,
            Ordering::Relaxed,
        );
        table.insert(mk_key(1), Arc::clone(&fresh));
        table.insert(mk_key(2), Arc::clone(&stale));
        table.insert(mk_key(3), mk_session());

        // A 5s horizon leaves the stale stamp (60s) safely evictable while
        // making the "fresh" side immune to any realistic test-thread
        // stall between stamping and retain.
        let evicted = sweep_idle_sessions(&table, Duration::from_secs(5));
        assert_eq!(evicted, 1);
        assert_eq!(table.len(), 2);
        assert!(table.contains_key(&mk_key(1)), "fresh session kept");
        assert!(table.contains_key(&mk_key(3)), "fresh session kept");

        // Even a previously-fresh entry goes once its activity ages past
        // `idle`, while the still-fresh key-3 session survives.
        fresh.last_activity_ms.store(
            monotonic_ms().wrapping_sub(60_000) as meow_common::atomic::Uint,
            Ordering::Relaxed,
        );
        assert_eq!(sweep_idle_sessions(&table, Duration::from_secs(5)), 1);
        assert_eq!(table.len(), 1);
        assert!(table.contains_key(&mk_key(3)));
    }

    /// `touch()` must refresh the same monotonic stamp the sweeper reads —
    /// pinned directly since the real-time `touch`-vs-ticker race it used
    /// to be covered by was flaky.
    #[test]
    fn touch_refreshes_the_sweep_clock() {
        let session = mk_session();
        session.last_activity_ms.store(
            monotonic_ms().wrapping_sub(60_000) as meow_common::atomic::Uint,
            Ordering::Relaxed,
        );
        session.touch();
        assert!(session.idle_for() < Duration::from_secs(1));
    }

    #[tokio::test(start_paused = false)]
    async fn sweeper_exits_when_table_dropped() {
        let table = new_nat_table();
        table.insert(mk_key(1), mk_session());
        let handle = spawn_nat_sweeper(&table, Duration::from_secs(60), Duration::from_millis(20));
        drop(table);
        // Allow the next tick to observe the dropped table.
        for _ in 0..100 {
            if handle.is_finished() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        panic!("sweeper should exit once the table is dropped");
    }

    /// Regression: a fast-path write failure on an existing session must evict
    /// the entry and return promptly. The previous code held the
    /// `nat_table.get()` shard read-guard across `write_packet().await` and then
    /// called `nat_table.remove()` (same-shard write lock) while the read-guard
    /// was still alive — a self-deadlock that hangs forever. The `timeout` here
    /// fails the test instead of hanging CI if that pattern is reintroduced.
    #[tokio::test(start_paused = false)]
    async fn fast_path_write_failure_evicts_without_deadlock() {
        let tunnel = mk_tunnel();

        // Literal-IP destination so pre_resolve is a no-op and the NAT key is
        // deterministic. Insert a session whose upstream write always fails.
        let src = SocketAddr::from(([127, 0, 0, 1], 5555));
        let dst = SocketAddr::from(([198, 51, 100, 7], 443));
        let key = (src, dst);
        tunnel.inner().nat_table.insert(
            key,
            Arc::new(UdpSession::new(
                Box::new(FailingPacketConn),
                Arc::from("test"),
            )),
        );

        tokio::time::timeout(
            Duration::from_secs(2),
            handle_udp(tunnel.inner(), b"ping", src, mk_metadata(src, dst)),
        )
        .await
        .expect("handle_udp must not deadlock on a fast-path write failure");

        assert!(
            tunnel.inner().nat_table.get(&key).is_none(),
            "a session with a dead upstream must be evicted"
        );
    }

    /// Packet conn that records every write and whether it has been closed,
    /// via handles shared with the test body.
    struct RecordingPacketConn {
        writes: Arc<AtomicUsize>,
        closed: Arc<AtomicBool>,
    }

    #[async_trait]
    impl ProxyPacketConn for RecordingPacketConn {
        async fn read_packet(&self, _buf: &mut [u8]) -> MeowResult<(usize, SocketAddr)> {
            Ok((0, "0.0.0.0:0".parse().unwrap()))
        }
        async fn write_packet(&self, buf: &[u8], _addr: &SocketAddr) -> MeowResult<usize> {
            self.writes.fetch_add(1, Ordering::SeqCst);
            Ok(buf.len())
        }
        fn local_addr(&self) -> MeowResult<SocketAddr> {
            Ok("0.0.0.0:0".parse().unwrap())
        }
        fn close(&self) -> MeowResult<()> {
            self.closed.store(true, Ordering::SeqCst);
            Ok(())
        }
    }

    /// Mock proxy whose `dial_udp` sleeps before returning, widening the
    /// dial-then-insert window so two concurrent `handle_udp` calls for the
    /// same (src, dst) both reach the NAT insert. Hands out
    /// [`RecordingPacketConn`]s and keeps their (writes, closed) handles.
    struct SlowDialProxy {
        dials: AtomicUsize,
        conns: Mutex<Vec<(Arc<AtomicUsize>, Arc<AtomicBool>)>>,
        health: ProxyHealth,
    }

    impl SlowDialProxy {
        fn new() -> Self {
            Self {
                dials: AtomicUsize::new(0),
                conns: Mutex::new(Vec::new()),
                health: ProxyHealth::new(),
            }
        }
    }

    #[async_trait]
    impl ProxyAdapter for SlowDialProxy {
        fn name(&self) -> &str {
            "slow-mock"
        }
        fn adapter_type(&self) -> AdapterType {
            AdapterType::Direct
        }
        fn addr(&self) -> &str {
            ""
        }
        fn support_udp(&self) -> bool {
            true
        }
        async fn dial_tcp(&self, _metadata: &Metadata) -> MeowResult<Box<dyn ProxyConn>> {
            Err(MeowError::NotSupported("slow-mock: tcp".into()))
        }
        async fn dial_udp(&self, _metadata: &Metadata) -> MeowResult<Box<dyn ProxyPacketConn>> {
            self.dials.fetch_add(1, Ordering::SeqCst);
            tokio::time::sleep(Duration::from_millis(50)).await;
            let writes = Arc::new(AtomicUsize::new(0));
            let closed = Arc::new(AtomicBool::new(false));
            self.conns
                .lock()
                .unwrap()
                .push((Arc::clone(&writes), Arc::clone(&closed)));
            Ok(Box::new(RecordingPacketConn { writes, closed }))
        }
        fn health(&self) -> &ProxyHealth {
            &self.health
        }
    }

    impl Proxy for SlowDialProxy {
        fn alive(&self) -> bool {
            true
        }
        fn alive_for_url(&self, _url: &str) -> bool {
            true
        }
        fn last_delay(&self) -> u16 {
            0
        }
        fn last_delay_for_url(&self, _url: &str) -> u16 {
            0
        }
        fn delay_history(&self) -> Vec<DelayHistory> {
            Vec::new()
        }
    }

    /// Regression for issue #432 (slow path): two concurrent `handle_udp`
    /// calls for the same brand-new (src, dst) both miss the NAT table and
    /// both dial (the check-then-act window), but the atomic claim must fold
    /// them into exactly one surviving session — the loser's conn is closed
    /// without ever carrying traffic, and the loser's datagram is re-sent on
    /// the winner. Before the fix the second blind `insert` silently dropped
    /// the first session with its datagram's reply in flight.
    #[tokio::test(start_paused = true)]
    async fn concurrent_first_packets_fold_into_single_session() {
        let tunnel = mk_tunnel();
        tunnel.set_mode(TunnelMode::Global);
        let proxy = Arc::new(SlowDialProxy::new());
        let mut proxies: HashMap<SmolStr, Arc<dyn Proxy>> = HashMap::new();
        proxies.insert(
            SmolStr::new_static("GLOBAL"),
            Arc::clone(&proxy) as Arc<dyn Proxy>,
        );
        tunnel.update_proxies(proxies, Default::default());

        let src = SocketAddr::from(([127, 0, 0, 1], 6666));
        let dst = SocketAddr::from(([198, 51, 100, 8], 443));
        let key = (src, dst);

        tokio::join!(
            handle_udp(tunnel.inner(), b"ping-a", src, mk_metadata(src, dst)),
            handle_udp(tunnel.inner(), b"ping-b", src, mk_metadata(src, dst)),
        );

        // Both calls raced past the NAT-miss check before either inserted, so
        // both dialled — the claim must still leave exactly one session.
        assert_eq!(
            proxy.dials.load(Ordering::SeqCst),
            2,
            "test premise: both calls must overlap in the dial window"
        );
        assert_eq!(tunnel.inner().nat_table.len(), 1);
        assert!(tunnel.inner().nat_table.get(&key).is_some());

        let conns = proxy.conns.lock().unwrap();
        let (open, lost): (Vec<_>, Vec<_>) = conns
            .iter()
            .partition(|(_, closed)| !closed.load(Ordering::SeqCst));
        assert_eq!(open.len(), 1, "exactly one conn must survive");
        assert_eq!(lost.len(), 1, "the losing conn must be closed");
        assert_eq!(
            open[0].0.load(Ordering::SeqCst),
            2,
            "both datagrams must be carried on the winning conn"
        );
        assert_eq!(
            lost[0].0.load(Ordering::SeqCst),
            0,
            "the losing conn must never carry traffic"
        );
    }

    /// Conn that, when written to, first installs `replacement` at `key` —
    /// playing the part of a concurrent slow path that dialled a fresh
    /// session while this write was in flight — and then fails the write.
    struct SwapOnFailConn {
        table: NatTable,
        key: (SocketAddr, SocketAddr),
        replacement: Arc<UdpSession>,
    }

    #[async_trait]
    impl ProxyPacketConn for SwapOnFailConn {
        async fn read_packet(&self, _buf: &mut [u8]) -> MeowResult<(usize, SocketAddr)> {
            Ok((0, "0.0.0.0:0".parse().unwrap()))
        }
        async fn write_packet(&self, _buf: &[u8], _addr: &SocketAddr) -> MeowResult<usize> {
            self.table.insert(self.key, Arc::clone(&self.replacement));
            Err(MeowError::Other("upstream dead".into()))
        }
        fn local_addr(&self) -> MeowResult<SocketAddr> {
            Ok("0.0.0.0:0".parse().unwrap())
        }
        fn close(&self) -> MeowResult<()> {
            Ok(())
        }
    }

    /// Regression for issue #432 (fast path): a write failure on an existing
    /// session must evict only the session that failed. If a concurrent slow
    /// path has already replaced the entry with a fresh healthy session, the
    /// old unconditional `remove(&key)` tore the replacement down and forced
    /// the next packet to redial.
    #[tokio::test]
    async fn fast_path_failure_keeps_concurrent_replacement_session() {
        let tunnel = mk_tunnel();

        let src = SocketAddr::from(([127, 0, 0, 1], 7777));
        let dst = SocketAddr::from(([198, 51, 100, 9], 443));
        let key = (src, dst);

        let replacement = mk_session();
        tunnel.inner().nat_table.insert(
            key,
            Arc::new(UdpSession::new(
                Box::new(SwapOnFailConn {
                    table: Arc::clone(&tunnel.inner().nat_table),
                    key,
                    replacement: Arc::clone(&replacement),
                }),
                Arc::from("test"),
            )),
        );

        handle_udp(tunnel.inner(), b"ping", src, mk_metadata(src, dst)).await;

        let current = tunnel
            .inner()
            .nat_table
            .get(&key)
            .map(|s| Arc::clone(s.value()));
        assert!(
            current.is_some_and(|s| Arc::ptr_eq(&s, &replacement)),
            "the fresh replacement session must survive the failed session's eviction"
        );
    }

    /// A proxy whose dial never resolves — a server that completes the TCP/QUIC
    /// handshake and then goes silent mid-protocol.
    struct StalledDialProxy {
        health: ProxyHealth,
    }

    #[async_trait]
    impl ProxyAdapter for StalledDialProxy {
        fn name(&self) -> &str {
            "stalled-mock"
        }
        fn adapter_type(&self) -> AdapterType {
            AdapterType::Direct
        }
        fn addr(&self) -> &str {
            ""
        }
        fn support_udp(&self) -> bool {
            true
        }
        async fn dial_tcp(&self, _metadata: &Metadata) -> MeowResult<Box<dyn ProxyConn>> {
            std::future::pending().await
        }
        async fn dial_udp(&self, _metadata: &Metadata) -> MeowResult<Box<dyn ProxyPacketConn>> {
            std::future::pending().await
        }
        fn health(&self) -> &ProxyHealth {
            &self.health
        }
    }

    impl Proxy for StalledDialProxy {
        fn alive(&self) -> bool {
            true
        }
        fn alive_for_url(&self, _url: &str) -> bool {
            true
        }
        fn last_delay(&self) -> u16 {
            0
        }
        fn last_delay_for_url(&self, _url: &str) -> u16 {
            0
        }
        fn delay_history(&self) -> Vec<DelayHistory> {
            Vec::new()
        }
    }

    /// A dial that never completes must not park the caller forever. Without
    /// the `DIAL_TIMEOUT` bound this test hangs: every datagram of the flow
    /// spawns another immortal task, since the NAT key is only claimed after
    /// the dial returns.
    #[tokio::test(start_paused = true)]
    async fn a_stalled_dial_gives_up_instead_of_parking_the_flow() {
        let tunnel = mk_tunnel();
        tunnel.set_mode(TunnelMode::Global);
        let mut proxies: HashMap<SmolStr, Arc<dyn Proxy>> = HashMap::new();
        proxies.insert(
            SmolStr::new_static("GLOBAL"),
            Arc::new(StalledDialProxy {
                health: ProxyHealth::new(),
            }) as Arc<dyn Proxy>,
        );
        tunnel.update_proxies(proxies, Default::default());

        let src = SocketAddr::from(([127, 0, 0, 1], 8888));
        let dst = SocketAddr::from(([198, 51, 100, 10], 443));

        let start = tokio::time::Instant::now();
        handle_udp(tunnel.inner(), b"ping", src, mk_metadata(src, dst)).await;

        assert_eq!(start.elapsed(), meow_common::DIAL_TIMEOUT);
        assert!(
            tunnel.inner().nat_table.is_empty(),
            "a dial that never completed must not leave a session behind"
        );
    }

    fn recording_session() -> (Arc<UdpSession>, Arc<AtomicBool>) {
        let closed = Arc::new(AtomicBool::new(false));
        let conn = RecordingPacketConn {
            writes: Arc::new(AtomicUsize::new(0)),
            closed: Arc::clone(&closed),
        };
        (
            Arc::new(UdpSession::new(Box::new(conn), Arc::from("test"))),
            closed,
        )
    }

    /// Issue #695: `close_all_udp_sessions` closes and evicts every NAT
    /// session and signals every listener flow (or dial) holding a flush
    /// watch, counting both; watches taken after it see no flush.
    #[tokio::test]
    async fn close_all_udp_sessions_drains_nat_and_signals_listener_flows() {
        let tunnel = mk_tunnel();
        let (first, first_closed) = recording_session();
        let (second, second_closed) = recording_session();
        tunnel.inner().nat_table.insert(mk_key(1000), first);
        tunnel.inner().nat_table.insert(mk_key(1001), second);

        let mut established = tunnel.inner().udp_flush_watch();
        let flow = tokio::spawn(async move { established.flushed().await });
        let dialling = tunnel.inner().udp_flush_watch();
        assert!(!dialling.is_flushed());

        assert_eq!(tunnel.close_all_udp_sessions(), 4);
        assert!(tunnel.inner().nat_table.is_empty());
        assert!(first_closed.load(Ordering::SeqCst));
        assert!(second_closed.load(Ordering::SeqCst));
        tokio::time::timeout(Duration::from_secs(2), flow)
            .await
            .expect("a listener flow must observe the flush")
            .unwrap();
        assert!(dialling.is_flushed());
        assert!(!tunnel.inner().udp_flush_watch().is_flushed());

        drop(dialling);
        let _late = tunnel.inner().udp_flush_watch();
        assert_eq!(tunnel.close_all_udp_sessions(), 1);
    }

    /// Issue #695: a session whose dial straddles a flush may ride a socket
    /// created before the new outbound binding, so it is closed instead of
    /// cached; the next datagram dials afresh.
    #[tokio::test(start_paused = true)]
    async fn a_session_dialled_across_a_flush_is_not_cached() {
        let tunnel = mk_tunnel();
        tunnel.set_mode(TunnelMode::Global);
        let proxy = Arc::new(SlowDialProxy::new());
        let mut proxies: HashMap<SmolStr, Arc<dyn Proxy>> = HashMap::new();
        proxies.insert(
            SmolStr::new_static("GLOBAL"),
            Arc::clone(&proxy) as Arc<dyn Proxy>,
        );
        tunnel.update_proxies(proxies, Default::default());

        let src = SocketAddr::from(([127, 0, 0, 1], 6667));
        let dst = SocketAddr::from(([198, 51, 100, 10], 443));
        let flush = async {
            tokio::time::sleep(Duration::from_millis(10)).await;
            tunnel.close_all_udp_sessions()
        };
        let ((), flushed) = tokio::join!(
            handle_udp(tunnel.inner(), b"ping", src, mk_metadata(src, dst)),
            flush,
        );
        assert_eq!(flushed, 1, "the in-flight dial holds a flush watch");
        assert!(tunnel.inner().nat_table.is_empty());
        {
            let conns = proxy.conns.lock().unwrap();
            assert_eq!(conns.len(), 1);
            assert!(conns[0].1.load(Ordering::SeqCst), "stale conn is closed");
            assert_eq!(conns[0].0.load(Ordering::SeqCst), 0, "and never written");
        }

        handle_udp(tunnel.inner(), b"ping", src, mk_metadata(src, dst)).await;
        assert_eq!(proxy.dials.load(Ordering::SeqCst), 2);
        assert_eq!(tunnel.inner().nat_table.len(), 1);
        let conns = proxy.conns.lock().unwrap();
        assert!(!conns[1].1.load(Ordering::SeqCst));
        assert_eq!(conns[1].0.load(Ordering::SeqCst), 1);
    }
}
