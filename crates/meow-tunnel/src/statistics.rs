// M2 layout change (ADR-0011 T2):
//   id: String (24 B heap) → Uuid (16 B inline, −8 B)
//   metadata: Metadata (272 B inline) → Arc<Metadata> (8 B thin-ptr, −264 B)
//     Closing a connection drops a refcount, not a 272 B drop chain.
//   rule: String → SmolStr (inline ≤23 B, heap-backed above that, −8 B)
//   rule_payload: String → SmolStr (same)
//     ADR-0008 HP-3: previously these were `Arc<str>`, which always allocates
//     on construction. SmolStr inlines the common cases (`Direct`, `DOMAIN`,
//     `example.com`, `192.168.0.0/16`, …) — zero heap touches per connection
//     for the rule-match record.
//   chains: Vec<String> (24 B struct, heap elems) → Vec<Arc<str>> (24 B struct,
//     ref-counted elems — no per-element allocation for proxy names)
// Public JSON shape: Uuid serialises as hyphenated string via the `serde`
// feature; SmolStr / Arc<str> / Vec<Arc<str>> all serialise as string/array.
// Arc<Metadata> serialises transparently as the inner `Metadata` under the
// mihomo-compatible `metadata` key (issue #241).
// Breaking change permitted by ADR-0009.

use dashmap::DashMap;
use meow_common::atomic::{AtomicI, Int};
use meow_common::Metadata;
use parking_lot::Mutex;
use serde::Serialize;
use smallvec::SmallVec;
use smol_str::SmolStr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, OnceLock};
use uuid::Uuid;

/// Hot-path rule-match counters. Keys are `&'static str` to avoid per-call
/// allocation since `increment` is called on every proxied connection.
pub struct RuleMatchCounters {
    inner: DashMap<(&'static str, &'static str), u64>,
}

impl RuleMatchCounters {
    pub fn new() -> Self {
        Self {
            inner: DashMap::new(),
        }
    }

    /// `rule_type` and `action` MUST be `'static` literals (e.g. "DOMAIN", "PROXY").
    pub fn increment(&self, rule_type: &'static str, action: &'static str) {
        *self.inner.entry((rule_type, action)).or_insert(0) += 1;
    }

    pub fn snapshot(&self) -> Vec<((&'static str, &'static str), u64)> {
        self.inner.iter().map(|e| (*e.key(), *e.value())).collect()
    }
}

impl Default for RuleMatchCounters {
    fn default() -> Self {
        Self::new()
    }
}

/// Live per-connection byte counters, shared between the relay closures and
/// the `/connections` serializer. `Arc`-owned by the relay's `ConnectionGuard`
/// so the hot loop bumps the atomics directly — no per-chunk DashMap lookup
/// (measured −8..10% on bulk throughput when the lookup was per-chunk).
/// The single `Arc::new` happens once per connection inside
/// [`Statistics::track_connection`], which is setup-path, not steady-state
/// (ADR-0008 §3 scopes the zero-alloc rule to per-iteration counts).
#[derive(Debug, Default)]
pub struct ConnCounters {
    pub upload: AtomicI,
    pub download: AtomicI,
    // Stored in the existing Arc so cancellation adds no setup allocation.
    closed: AtomicBool,
    close_notify: tokio::sync::Notify,
    /// PaoPao (`tun.outbound-interfaces`): the connection's dial context —
    /// which interface it left by, and where its bytes are attributed.
    /// Unset unless balancing is configured.
    dial: OnceLock<Arc<meow_common::outbound_balance::DialScope>>,
}

impl ConnCounters {
    fn close(&self) {
        self.closed.store(true, Ordering::Release);
        self.close_notify.notify_waiters();
    }

    pub(crate) async fn closed(&self) {
        // Register before checking the flag: closing before the first poll or
        // between the check and await must not lose the wakeup.
        let notified = self.close_notify.notified();
        tokio::pin!(notified);
        notified.as_mut().enable();
        if !self.closed.load(Ordering::Acquire) {
            notified.await;
        }
    }

    /// PaoPao: the scope this connection's dial runs in
    /// (`meow_common::outbound_balance::scoped`), made on first use from
    /// the connection's destination. `None` while outbound balancing is
    /// not configured.
    pub fn dial_scope(
        &self,
        metadata: &Metadata,
    ) -> Option<Arc<meow_common::outbound_balance::DialScope>> {
        if let Some(scope) = self.dial.get() {
            return Some(Arc::clone(scope));
        }
        let scope =
            meow_common::outbound_balance::DialScope::for_target(&metadata.host, metadata.dst_ip)?;
        Some(Arc::clone(self.dial.get_or_init(|| scope)))
    }

    /// PaoPao: the interface the connection's first socket was bound to,
    /// when known (see [`Self::dial_scope`]).
    pub fn interface(&self) -> Option<Arc<str>> {
        self.dial.get()?.interface()
    }

    pub fn upload_bytes(&self) -> Int {
        self.upload.load(Ordering::Relaxed)
    }

    pub fn download_bytes(&self) -> Int {
        self.download.load(Ordering::Relaxed)
    }
}

// Serialises as `"upload": N, "download": N` so the flattened field keeps the
// exact mihomo connection JSON shape the plain i64 fields produced.
impl Serialize for ConnCounters {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeStruct;
        let interface = self.interface();
        let mut s =
            serializer.serialize_struct("ConnCounters", 2 + usize::from(interface.is_some()))?;
        s.serialize_field("upload", &self.upload_bytes())?;
        s.serialize_field("download", &self.download_bytes())?;
        // PaoPao: only under outbound balancing, so the mihomo shape is
        // untouched otherwise.
        if let Some(interface) = &interface {
            s.serialize_field("interface", &**interface)?;
        }
        s.end()
    }
}

#[derive(Serialize, Clone)]
pub struct ConnectionInfo {
    /// 16 B inline UUID; serialises as `"xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"`.
    pub id: Uuid,
    /// 8 B thin-ptr; refcount drop on close instead of 272 B drop chain.
    /// Serialised as the mihomo-compatible `metadata` object (host, IPs, ports,
    /// network, type, …) so panels can show `host:port` as the connection title
    /// (issue #241). The `Arc` wrapper is transparent to serde — it serialises
    /// the inner `Metadata`. Struct size is unchanged (still an 8 B thin-ptr);
    /// only the `/connections` JSON payload grows.
    pub metadata: Arc<Metadata>,
    /// 8 B thin-ptr (was two inline `i64`s, −8 B). Flattened so the JSON keeps
    /// the top-level `upload`/`download` fields.
    #[serde(flatten)]
    pub counters: Arc<ConnCounters>,
    pub start: SmolStr,
    /// Proxy chain; ref-counted so proxy-name strings are shared across entries.
    pub chains: SmallVec<[Arc<str>; 1]>,
    /// Rule type that matched this connection (e.g. `"DOMAIN-SUFFIX"`).
    /// `SmolStr` so common short names inline (no heap on the connection
    /// hot path).
    pub rule: SmolStr,
    /// Rule payload (e.g. the domain pattern). Config-derived, low-cardinality.
    /// Renamed so the derived JSON matches the REST API's camelCase field.
    #[serde(rename = "rulePayload")]
    pub rule_payload: SmolStr,
    /// PaoPao: order of arrival (1, 2, 3 …), going on from the history's
    /// highest across restarts: the number a list shows it by, the same
    /// while it lives and once it is in [`Statistics::history`].
    pub seq: u64,
}

/// Values exposed by the mihomo `/traffic` stream, captured together under
/// one lock so a reader never mixes rates and totals from different sampling
/// ticks (issue #338). Totals are the cumulative counters as observed at the
/// last tick; rates are the delta between consecutive observations (issue
/// #357) — derived from one counter, so `rate <= total` holds by construction
/// and no interleaving can publish an impossible pair (issue #340).
#[derive(Default, Clone, Copy)]
struct TrafficSnapshot {
    upload_rate: Int,
    download_rate: Int,
    upload_total: Int,
    download_total: Int,
}

pub struct Statistics {
    /// Cumulative relay byte totals. The only global counters the relay hot
    /// path touches (one relaxed `fetch_add` per direction per chunk). The
    /// sampler derives per-interval rates as deltas of consecutive
    /// observations and never writes these counters, so no relay increment
    /// can land on the wrong side of a `swap(0)`-style reset (issue #357).
    upload_total: AtomicI,
    download_total: AtomicI,
    traffic: Mutex<TrafficSnapshot>,
    /// Keyed by `Uuid` (16 B Copy) — formerly `String`, which heap-allocated a
    /// 36-byte hyphenated representation per insert.  REST handlers parse the
    /// query path back into a `Uuid` at lookup time.
    pub connections: DashMap<Uuid, ConnectionInfo>,
    /// Headless flows still need cancellation on a cold config reload, but
    /// never need the metadata and serialization fields used by the API.
    headless_connections: OnceLock<DashMap<usize, Arc<ConnCounters>>>,
    pub rule_match: Arc<RuleMatchCounters>,
    /// PaoPao: the API-tracked connections that ended.
    history: crate::history::ConnectionHistory,
    seq: std::sync::atomic::AtomicU64,
}

impl Statistics {
    pub fn new() -> Self {
        Self {
            upload_total: AtomicI::new(0),
            download_total: AtomicI::new(0),
            traffic: Mutex::new(TrafficSnapshot::default()),
            connections: DashMap::new(),
            headless_connections: OnceLock::new(),
            rule_match: Arc::new(RuleMatchCounters::new()),
            history: crate::history::ConnectionHistory::new(),
            seq: std::sync::atomic::AtomicU64::new(0),
        }
    }

    /// PaoPao: the connections that ended (`GET /connections/history`).
    pub fn history(&self) -> &crate::history::ConnectionHistory {
        &self.history
    }

    /// PaoPao: where the history is saved; what was saved there is read,
    /// and numbering goes on from it.
    pub fn open_history(&self, path: &std::path::Path) {
        self.history.open(path);
        self.seq
            .fetch_max(self.history.last_seq(), Ordering::Relaxed);
    }

    // `Int` is `i32` on 32-bit targets.
    #[allow(clippy::useless_conversion)]
    fn remember(&self, info: ConnectionInfo) {
        let end_ms = crate::history::now_ms();
        self.history.push(crate::history::EndedConnection {
            id: info.id,
            upload: i64::from(info.counters.upload_bytes()),
            download: i64::from(info.counters.download_bytes()),
            interface: info.counters.interface(),
            metadata: info.metadata,
            start: info.start,
            chains: info.chains,
            rule: info.rule,
            rule_payload: info.rule_payload,
            end: chrono_now(),
            end_ms,
            seq: info.seq,
            rev: 0,
            count: 1,
            first: None,
        });
    }

    pub fn add_upload(&self, n: Int) {
        self.upload_total.fetch_add(n, Ordering::Relaxed);
    }

    pub fn add_download(&self, n: Int) {
        self.download_total.fetch_add(n, Ordering::Relaxed);
    }

    /// Per-chunk relay accounting: two relaxed atomic adds, no map lookup.
    /// Callers obtain the `ConnCounters` once at connection setup via
    /// [`Self::connection_counters`] (or `ConnectionGuard::counters`).
    pub fn record_upload(&self, counters: &ConnCounters, n: Int) {
        counters.upload.fetch_add(n, Ordering::Relaxed);
        self.add_upload(n);
        // PaoPao: the connection's share of its outbound interface.
        if let Some(scope) = counters.dial.get() {
            scope.add_upload(u64::try_from(n).unwrap_or(0));
        }
    }

    /// See [`Self::record_upload`].
    pub fn record_download(&self, counters: &ConnCounters, n: Int) {
        counters.download.fetch_add(n, Ordering::Relaxed);
        self.add_download(n);
        if let Some(scope) = counters.dial.get() {
            scope.add_download(u64::try_from(n).unwrap_or(0));
        }
    }

    /// One-time (per connection) handle to the live byte counters of a
    /// tracked connection. Setup-path only — never call per chunk.
    pub fn connection_counters(&self, id: Uuid) -> Option<Arc<ConnCounters>> {
        self.connections
            .get(&id)
            .map(|entry| Arc::clone(&entry.counters))
    }

    /// Roll the cumulative counters into the values exposed by the mihomo
    /// `/traffic` stream. All four values are published under one lock so
    /// `traffic_snapshot` readers see a mutually consistent set; rates are the
    /// delta between consecutive observations of the same counter, so they can
    /// never disagree with the totals (issue #340). The hot path stays
    /// lock-free — the once-per-second ticker plus API readers are the only
    /// contenders. Delta sampling means the ticker only loads the counters
    /// (issue #357): there is no reset for a concurrent relay `fetch_add` to
    /// race against, so an increment lands in exactly one interval — this one
    /// if the load observed it, the next one otherwise.
    pub fn sample_traffic(&self) {
        let mut snap = self.traffic.lock();
        let upload = self.upload_total.load(Ordering::Relaxed);
        let download = self.download_total.load(Ordering::Relaxed);
        snap.upload_rate = upload - snap.upload_total;
        snap.download_rate = download - snap.download_total;
        snap.upload_total = upload;
        snap.download_total = download;
    }

    /// `(upload_rate, download_rate, upload_total, download_total)` as of the
    /// last `sample_traffic` tick. Totals lag the live counters by up to one
    /// tick, in exchange for being consistent with the rates.
    pub fn traffic_snapshot(&self) -> (Int, Int, Int, Int) {
        let snap = *self.traffic.lock();
        (
            snap.upload_rate,
            snap.download_rate,
            snap.upload_total,
            snap.download_total,
        )
    }

    pub fn track_connection(
        &self,
        metadata: Metadata,
        rule: SmolStr,
        rule_payload: SmolStr,
        chains: SmallVec<[Arc<str>; 1]>,
    ) -> Uuid {
        self.track_connection_with_counters(metadata, rule, rule_payload, chains)
            .0
    }

    pub(crate) fn track_connection_with_counters(
        &self,
        metadata: Metadata,
        rule: SmolStr,
        rule_payload: SmolStr,
        chains: SmallVec<[Arc<str>; 1]>,
    ) -> (Uuid, Arc<ConnCounters>) {
        let uuid = Uuid::new_v4();
        let counters = Arc::new(ConnCounters::default());
        let info = ConnectionInfo {
            id: uuid,
            metadata: Arc::new(metadata),
            counters: Arc::clone(&counters),
            start: chrono_now(),
            chains,
            rule,
            rule_payload,
            seq: self.seq.fetch_add(1, Ordering::Relaxed) + 1,
        };
        self.connections.insert(uuid, info);
        (uuid, counters)
    }

    /// Select the lighter connection registry before listeners start. The
    /// default remains full tracking for embedders and API consumers.
    pub fn set_headless(&self) {
        assert!(self.connections.is_empty());
        assert!(self.headless_connections.set(DashMap::new()).is_ok());
    }

    pub(crate) fn begin_headless_connection(&self) -> Option<Arc<ConnCounters>> {
        let connections = self.headless_connections.get()?;
        let counters = Arc::new(ConnCounters::default());
        // The guard pins this allocation until after its Drop unregisters it.
        // Even after a reload drains the map, a stale guard keeps its address
        // from being reused by a new connection. The address is only a private
        // map key, never dereferenced, and has no cumulative ID limit on 32-bit.
        connections.insert(Arc::as_ptr(&counters).addr(), Arc::clone(&counters));
        Some(counters)
    }

    pub(crate) fn close_headless_connection(&self, counters: &Arc<ConnCounters>) {
        // Borrow the owning Arc so the key cannot outlive its allocation.
        let key = Arc::as_ptr(counters).addr();
        if let Some((_, counters)) = self
            .headless_connections
            .get()
            .and_then(|connections| connections.remove(&key))
        {
            counters.close();
        }
    }

    /// Signal the owner to drop its dial/relay future and remove the entry.
    pub fn close_connection(&self, id: Uuid) {
        if let Some((_, info)) = self.connections.remove(&id) {
            info.counters.close();
            self.remember(info);
        }
    }

    /// Live cumulative `(upload, download)` totals, read straight from the
    /// hot-path counters. Each counter is a single monotonic atomic — no
    /// lock, no split between sampled and unsampled parts — so the values are
    /// exact and monotonic per direction.
    pub fn snapshot(&self) -> (Int, Int) {
        (
            self.upload_total.load(Ordering::Relaxed),
            self.download_total.load(Ordering::Relaxed),
        )
    }

    /// Number of API-tracked connections. Headless cancellation handles are
    /// excluded, so this can return zero while headless TCP flows are live.
    pub fn active_connection_count(&self) -> usize {
        self.connections.len()
    }

    pub fn active_connections(&self) -> Vec<ConnectionInfo> {
        self.connections.iter().map(|e| e.value().clone()).collect()
    }

    /// Borrow-serializing view over the active-connections table.
    ///
    /// Serialises each entry in place while iterating the DashMap — no
    /// per-call `Vec` clone, no intermediate `serde_json::Value` tree.
    /// Shard read locks are held per entry during serialization, the same
    /// window the clone in [`Self::active_connections`] holds them.
    pub fn active_connections_view(&self) -> ActiveConnectionsView<'_> {
        ActiveConnectionsView(self)
    }

    pub fn close_all_connections(&self) {
        self.close_all_connections_counted();
    }

    /// Request closure of all tracked TCP connections and remove their entries.
    /// Returns the number of closure requests, not completed socket teardowns.
    pub fn close_all_connections_counted(&self) -> usize {
        let mut closed = 0;
        let mut ended = Vec::new();
        // Signal and remove under the same shard lock. A separate iteration
        // followed by clear could erase newly inserted, unsignalled entries.
        self.connections.retain(|_, info| {
            info.counters.close();
            closed += 1;
            ended.push(info.clone());
            false
        });
        // Oldest first, as they would have ended one by one.
        ended.sort_by_key(|info| info.seq);
        for info in ended {
            self.remember(info);
        }
        if let Some(connections) = self.headless_connections.get() {
            connections.retain(|_, counters| {
                counters.close();
                closed += 1;
                false
            });
        }
        closed
    }

    /// PaoPao: request closure of the tracked TCP connections `close` picks
    /// (by their entry) and remove their entries; the rest, and the
    /// headless flows, run on. Returns the number of closure requests.
    pub fn close_connections_where(&self, close: impl Fn(&ConnectionInfo) -> bool) -> usize {
        let mut ended = Vec::new();
        self.connections.retain(|_, info| {
            if !close(info) {
                return true;
            }
            info.counters.close();
            ended.push(info.clone());
            false
        });
        let closed = ended.len();
        ended.sort_by_key(|info| info.seq);
        for info in ended {
            self.remember(info);
        }
        closed
    }
}

impl Default for Statistics {
    fn default() -> Self {
        Self::new()
    }
}

/// See [`Statistics::active_connections_view`].
pub struct ActiveConnectionsView<'a>(&'a Statistics);

impl Serialize for ActiveConnectionsView<'_> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_seq(self.0.connections.iter().map(EntryRef))
    }
}

/// Wraps a DashMap entry guard so `collect_seq` can serialize the borrowed
/// `ConnectionInfo` without cloning it out of the map.
struct EntryRef<'a>(dashmap::mapref::multiple::RefMulti<'a, Uuid, ConnectionInfo>);

impl Serialize for EntryRef<'_> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.0.value().serialize(serializer)
    }
}

fn chrono_now() -> SmolStr {
    use time::format_description::well_known::Rfc3339;

    // Seconds precision is sufficient for mihomo's connection API and keeps
    // the 20-byte RFC 3339 value inline in `SmolStr`. Formatting into a stack
    // buffer also avoids allocating an intermediate `String` on this hot path.
    let now = time::OffsetDateTime::now_utc()
        .replace_nanosecond(0)
        .unwrap_or(time::OffsetDateTime::UNIX_EPOCH);
    let mut buffer = TimestampBuffer::default();
    if now.format_into(&mut buffer, &Rfc3339).is_ok() {
        if let Ok(value) = std::str::from_utf8(&buffer.bytes[..buffer.len]) {
            return SmolStr::new(value);
        }
    }

    SmolStr::new_static("1970-01-01T00:00:00Z")
}

#[derive(Default)]
struct TimestampBuffer {
    bytes: [u8; 32],
    len: usize,
}

impl std::io::Write for TimestampBuffer {
    fn write(&mut self, input: &[u8]) -> std::io::Result<usize> {
        let end = self.len.saturating_add(input.len());
        if end > self.bytes.len() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::WriteZero,
                "timestamp exceeds fixed buffer",
            ));
        }
        self.bytes[self.len..end].copy_from_slice(input);
        self.len = end;
        Ok(input.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod outbound_interface_tests {
    use super::*;
    use meow_common::outbound_balance::{BalanceOptions, Balancer, DialScope};

    /// PaoPao (`tun.outbound-interfaces`): a connection shows the interface
    /// it left by as a top-level `interface`, its bytes count towards that
    /// member, and without balancing the mihomo shape is untouched.
    #[test]
    fn a_connection_shows_its_interface_and_feeds_its_member() {
        let stats = Statistics::new();
        let (id, counters) = stats.track_connection_with_counters(
            Metadata::default(),
            "MATCH".into(),
            "".into(),
            smallvec::smallvec![Arc::from("DIRECT")],
        );
        let json = |stats: &Statistics| serde_json::to_value(stats.active_connections()).unwrap();

        // Balancing is not configured: no scope, no field.
        assert!(counters.dial_scope(&Metadata::default()).is_none());
        assert_eq!(counters.interface(), None);
        let before = json(&stats);
        assert!(before[0].get("interface").is_none());
        assert_eq!(before[0]["upload"], 0);

        // The dial's first socket was given member 1.
        let balancer = Balancer::new(&BalanceOptions {
            interfaces: vec!["en0".into(), "en7".into()],
            sticky: true,
        });
        let scope = DialScope::new(None);
        counters.dial.set(Arc::clone(&scope)).unwrap();
        // Dialled, not bound yet: still unknown.
        assert!(json(&stats)[0].get("interface").is_none());
        scope.record(&balancer.names()[1], Some((&balancer, 1)));
        drop(scope);
        stats.record_upload(&counters, 10);
        stats.record_download(&counters, 30);

        let after = json(&stats);
        assert_eq!(after[0]["interface"], "en7");
        assert_eq!(after[0]["upload"], 10);
        assert_eq!(after[0]["download"], 30);
        assert_eq!(after[0]["chains"], serde_json::json!(["DIRECT"]));
        // The streaming view serialises the same.
        assert_eq!(
            serde_json::to_value(stats.active_connections_view()).unwrap(),
            after
        );
        let snap = balancer.snapshot(std::time::Instant::now());
        assert_eq!(snap.interfaces[1].connections, 1);
        assert_eq!(
            (snap.interfaces[1].upload, snap.interfaces[1].download),
            (10, 30)
        );
        assert_eq!(snap.interfaces[0].download, 0);

        // Closing the connection releases the member.
        drop(counters);
        stats.close_connection(id);
        let snap = balancer.snapshot(std::time::Instant::now());
        assert_eq!(snap.interfaces[1].connections, 0);
        assert_eq!(snap.interfaces[1].download, 30);
    }
}

#[cfg(test)]
mod history_tests {
    use super::*;

    /// PaoPao: a connection that ends goes into the history with what it
    /// moved and its number; the numbering is the one `/connections` shows.
    #[test]
    fn an_ended_connection_is_kept_with_its_bytes_and_number() {
        let stats = Statistics::new();
        let track = |host: &str| {
            stats.track_connection_with_counters(
                Metadata {
                    host: host.into(),
                    dst_port: 443,
                    ..Metadata::default()
                },
                "DOMAIN".into(),
                host.into(),
                smallvec::smallvec![Arc::from("DIRECT")],
            )
        };
        let (a, counters) = track("a.example");
        let (b, _) = track("b.example");
        let live = serde_json::to_value(stats.active_connections_view()).unwrap();
        let mut seqs: Vec<u64> = live
            .as_array()
            .unwrap()
            .iter()
            .map(|c| c["seq"].as_u64().unwrap())
            .collect();
        seqs.sort_unstable();
        assert_eq!(seqs, vec![1, 2]);

        stats.record_upload(&counters, 10);
        stats.record_download(&counters, 30);
        stats.close_connection(a);
        // Closing twice (the API, then the owner) keeps it once.
        stats.close_connection(a);
        let d = stats.history().delta(0);
        assert_eq!(d.kept, vec![1]);
        let v = serde_json::to_value(&d.changed[0]).unwrap();
        assert_eq!(v["id"], a.to_string());
        assert_eq!(
            (v["upload"].as_i64(), v["download"].as_i64()),
            (Some(10), Some(30))
        );
        assert_eq!(v["metadata"]["host"], "a.example");
        assert_eq!(v["rulePayload"], "a.example");
        assert!(v["end"].as_str().unwrap().ends_with('Z'));

        // Everything closed at once: each kept, in the order they came.
        let (_c, _) = track("c.example");
        stats.close_all_connections();
        assert_eq!(stats.history().delta(0).kept, vec![1, 2, 3]);
        let _ = b;
    }
}
