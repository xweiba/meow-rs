//! PaoPao: spreading outbound connections over several physical interfaces
//! (`tun.outbound-interfaces`).
//!
//! With two or more members configured, every outbound socket that would
//! take the default interface — a DIRECT connection, a dial to a proxy
//! server — is bound to one of the members instead, chosen per connection.
//! What stays as it was: a destination another interface has a specific
//! route for (another VPN's prefixes, a NIC's own subnet), a per-rule
//! `interface-name`, another VPN's client and gateway traffic, and every
//! destination that is not a public address (see [`is_balanced_dest`]).
//!
//! This module is the policy: pure, no sockets, no clock of its own (every
//! decision takes `now`), no interface list of its own (a [`LinkSource`]
//! tells it what the system has). The binding itself is in
//! [`crate::outbound_iface`].
//!
//! # Choosing
//!
//! Among the usable members the one with the fewest connections in flight
//! per unit of weight wins; a tie goes to the one that got the fewest
//! assignments per unit of weight since the usable set last changed, then
//! to configuration order. Weight (25–100) follows the smoothed TCP connect
//! time measured through each member — the fastest gets 100, the others
//! `100 × fastest / own`, never under 25. Without measurements and without
//! long-lived connections that is plain round robin.
//!
//! # Sticking
//!
//! With `sticky` (the default) a destination — the site of the host name,
//! else the address — keeps the member it got first, so a site does not see
//! the exit address change between requests. A member that stops being
//! usable hands its destinations to another one, and does not get them
//! back when it returns.
//!
//! # Failing over
//!
//! A member is usable while the system has a default route on it
//! ([`Balancer::refresh`], driven by the route monitor) and dials through
//! it work: [`SUSPEND_AFTER`] failures in a row with no success between
//! them suspend it for [`SUSPEND_BASE`], doubling up to [`SUSPEND_MAX`].
//! When every member is suspended the suspension is ignored — a wrong
//! guess must not cut everything off.

use std::collections::HashMap;
use std::future::Future;
use std::hash::{Hash, Hasher};
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, OnceLock, Weak};
use std::time::{Duration, Instant};

use parking_lot::Mutex;
use serde::Serialize;

/// Most members a balancer takes; further names are dropped.
pub const MAX_MEMBERS: usize = 8;
/// Longest interface name kept (Windows aliases are long, not this long).
pub const MAX_NAME_LEN: usize = 255;
/// Failures in a row that suspend a member.
pub const SUSPEND_AFTER: u32 = 3;
/// First suspension.
pub const SUSPEND_BASE: Duration = Duration::from_secs(10);
/// Longest suspension.
pub const SUSPEND_MAX: Duration = Duration::from_secs(60);
/// A sticky entry not used for this long is forgotten.
pub const STICKY_TTL: Duration = Duration::from_secs(600);
/// Most sticky entries kept.
pub const STICKY_MAX: usize = 4096;
/// A connect abandoned after at least this long counts as a failure of the
/// member (sooner, the caller just changed its mind).
pub const ABANDON_AFTER: Duration = Duration::from_secs(3);

const WEIGHT_MAX: u64 = 100;
const WEIGHT_MIN: u64 = 25;

/// `tun.outbound-interfaces` / `tun.outbound-sticky` as configured.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BalanceOptions {
    /// Member names, cleaned ([`clean_interfaces`]), at least two.
    pub interfaces: Vec<String>,
    /// The same destination keeps its member.
    pub sticky: bool,
}

/// Interface names as a balancer takes them: trimmed; empty ones, ones
/// with a control character and over-long ones dropped; each once; at most
/// [`MAX_MEMBERS`].
pub fn clean_interfaces<'a>(names: impl IntoIterator<Item = &'a str>) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for name in names {
        let name = name.trim();
        if name.is_empty()
            || name.chars().count() > MAX_NAME_LEN
            || name.chars().any(char::is_control)
            || out.iter().any(|n| n == name)
        {
            continue;
        }
        if out.len() == MAX_MEMBERS {
            break;
        }
        out.push(name.to_owned());
    }
    out
}

/// What kind of interface a name is, for membership: a virtual one (another
/// VPN's tunnel, a bridge, our own TUN, loopback) is never a member.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum LinkKind {
    Physical,
    Unknown,
    Virtual,
}

/// One interface holding a default route right now.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Link {
    pub name: String,
    /// OS interface index (what macOS and Windows bind by).
    pub index: u32,
    pub kind: LinkKind,
    /// Holds an IPv4 default route.
    pub v4: bool,
    /// Holds an IPv6 default route.
    pub v6: bool,
    /// Linux: reverse-path filtering is strict on it, so replies to a
    /// socket bound to it are dropped unless it is the best route back.
    pub strict_rp_filter: bool,
}

/// Where a balancer learns what interfaces the system has. The route
/// monitor implements it over the routing table; tests over a list.
pub trait LinkSource {
    /// Every interface holding a default route (either family).
    fn links(&self) -> Vec<Link>;
    /// The kind of an interface that exists; `None` when there is no such
    /// interface.
    fn kind_of(&self, name: &str) -> Option<LinkKind>;
}

/// A member as the system has it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum MemberState {
    /// Usable.
    Up,
    /// Exists, holds no default route (unplugged, no lease, no gateway).
    NoRoute,
    /// No such interface.
    Missing,
    /// A virtual interface: never used.
    Virtual,
    /// Up by its routes, but dials through it keep failing.
    Suspended,
}

/// How one dial through a member ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DialOutcome {
    /// Connected after this long.
    Connected(Duration),
    /// The far end answered (refused): the line works.
    Alive,
    /// Could not bind, no route, timed out.
    Failed,
}

/// Byte and connection counters of one member; lock-free, shared with the
/// connections attributed to it.
#[derive(Debug, Default)]
struct MemberStats {
    active: AtomicUsize,
    assigned: AtomicU64,
    upload: AtomicU64,
    download: AtomicU64,
}

#[derive(Debug)]
struct Member {
    state: MemberState,
    index: u32,
    v4: bool,
    v6: bool,
    strict_rp_filter: bool,
    /// Assignments since the usable set last changed.
    epoch: u64,
    /// Smoothed connect time, milliseconds.
    latency: Option<f64>,
    failures: u32,
    suspended_until: Option<Instant>,
    /// Suspensions in a row (the next one lasts `SUSPEND_BASE << backoff`).
    backoff: u32,
    sampled: (u64, u64),
    rate: (u64, u64),
}

impl Member {
    fn new() -> Self {
        Self {
            state: MemberState::Missing,
            index: 0,
            v4: false,
            v6: false,
            strict_rp_filter: false,
            epoch: 0,
            latency: None,
            failures: 0,
            suspended_until: None,
            backoff: 0,
            sampled: (0, 0),
            rate: (0, 0),
        }
    }

    fn suspended(&self, now: Instant) -> bool {
        self.suspended_until.is_some_and(|until| until > now)
    }

    fn routes(&self, v4: bool) -> bool {
        self.state == MemberState::Up && if v4 { self.v4 } else { self.v6 }
    }
}

struct Inner {
    members: Vec<Member>,
    /// Destination key → (member, last used).
    sticky: HashMap<u64, (usize, Instant)>,
    /// The members last seen available, per family (v4, v6), as bit sets.
    available: (u32, u32),
    sampled_at: Option<Instant>,
}

/// The members of `tun.outbound-interfaces` and everything known about
/// them. See the [module docs](self).
pub struct Balancer {
    names: Vec<Arc<str>>,
    stats: Vec<Arc<MemberStats>>,
    sticky: bool,
    inner: Mutex<Inner>,
}

impl std::fmt::Debug for Balancer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Balancer")
            .field("names", &self.names)
            .field("sticky", &self.sticky)
            .finish_non_exhaustive()
    }
}

/// A member chosen for one socket.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pick {
    /// Position among the members.
    pub member: usize,
    pub name: Arc<str>,
    /// OS interface index as of the last refresh.
    pub index: u32,
}

/// One member in [`BalanceSnapshot`] (`GET /network/outbound`,
/// `balance.interfaces[]`).
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MemberSnapshot {
    pub name: String,
    pub state: MemberState,
    pub ipv4: bool,
    pub ipv6: bool,
    /// Connections in flight attributed to it.
    pub connections: usize,
    /// Sockets given to it since the start.
    pub assigned: u64,
    pub upload: u64,
    pub download: u64,
    /// Bytes per second over the last sample window.
    pub upload_rate: u64,
    pub download_rate: u64,
    /// Its part of all members' traffic, 0–1 (by assignments while no
    /// byte was counted).
    pub share: f64,
    /// Smoothed connect time in milliseconds.
    pub latency: Option<u64>,
    pub weight: u64,
    /// Failures in a row.
    pub failures: u32,
    /// Seconds until a suspended member is tried again.
    pub retry_in: Option<u64>,
    pub strict_rp_filter: bool,
}

/// `GET /network/outbound` → `balance`.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BalanceSnapshot {
    /// At least two members are usable right now.
    pub active: bool,
    pub sticky: bool,
    pub interfaces: Vec<MemberSnapshot>,
}

/// The balancer of the newest configuration, shared by overlapping owners
/// of the binding (a reload installs before the old listener leaves) so
/// counters and sticky choices survive a reload that changed nothing here.
static SHARED: Mutex<Weak<Balancer>> = Mutex::new(Weak::new());

impl Balancer {
    /// A balancer over `options.interfaces`; every member starts
    /// [`MemberState::Missing`] until the first [`refresh`](Self::refresh).
    pub fn new(options: &BalanceOptions) -> Arc<Self> {
        let names: Vec<Arc<str>> = clean_interfaces(options.interfaces.iter().map(String::as_str))
            .into_iter()
            .map(Arc::from)
            .collect();
        Arc::new(Self {
            stats: names.iter().map(|_| Arc::default()).collect(),
            inner: Mutex::new(Inner {
                members: names.iter().map(|_| Member::new()).collect(),
                sticky: HashMap::new(),
                available: (0, 0),
                sampled_at: None,
            }),
            names,
            sticky: options.sticky,
        })
    }

    /// The live balancer when it was made from the same options, else a new
    /// one (which later calls then share).
    pub fn obtain(options: &BalanceOptions) -> Arc<Self> {
        let mut shared = SHARED.lock();
        if let Some(live) = shared.upgrade().filter(|b| b.matches(options)) {
            return live;
        }
        let made = Self::new(options);
        *shared = Arc::downgrade(&made);
        made
    }

    fn matches(&self, options: &BalanceOptions) -> bool {
        self.sticky == options.sticky
            && self.names.len() == options.interfaces.len()
            && self
                .names
                .iter()
                .zip(&options.interfaces)
                .all(|(a, b)| **a == **b)
    }

    /// Whether the same destination keeps its member.
    pub fn sticky(&self) -> bool {
        self.sticky
    }

    /// Member names in configuration order.
    pub fn names(&self) -> &[Arc<str>] {
        &self.names
    }

    /// Take the system's view of the members: which exist, which hold a
    /// default route (and in which family), under what index.
    pub fn refresh(&self, source: &dyn LinkSource) {
        let links = source.links();
        let mut inner = self.inner.lock();
        for (name, m) in self.names.iter().zip(inner.members.iter_mut()) {
            let link = links.iter().find(|l| *l.name == **name);
            let was_up = m.state == MemberState::Up;
            let (state, index, v4, v6, strict) = match link {
                Some(l) if l.kind == LinkKind::Virtual => {
                    (MemberState::Virtual, l.index, false, false, false)
                }
                Some(l) if l.v4 || l.v6 => {
                    (MemberState::Up, l.index, l.v4, l.v6, l.strict_rp_filter)
                }
                _ => match source.kind_of(name) {
                    Some(LinkKind::Virtual) => (MemberState::Virtual, 0, false, false, false),
                    Some(_) => (MemberState::NoRoute, 0, false, false, false),
                    None => (MemberState::Missing, 0, false, false, false),
                },
            };
            if state != m.state {
                tracing::info!("outbound balance: interface '{name}' is now {state:?}");
            }
            m.state = state;
            m.index = index;
            m.v4 = v4;
            m.v6 = v6;
            m.strict_rp_filter = strict;
            if state == MemberState::Up && !was_up {
                // A line that came back gets a fresh chance.
                m.failures = 0;
                m.suspended_until = None;
                m.backoff = 0;
            }
        }
    }

    /// Weight of every member, 25–100, from the smoothed connect times.
    fn weights(members: &[Member]) -> Vec<u64> {
        let best = members
            .iter()
            .filter_map(|m| m.latency)
            .fold(f64::INFINITY, f64::min);
        members
            .iter()
            .map(|m| match m.latency {
                Some(own) if own > 0.0 && best.is_finite() => {
                    // Bounded to 25..=100 before the cast.
                    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
                    let w = (WEIGHT_MAX as f64 * best / own).round() as u64;
                    w.clamp(WEIGHT_MIN, WEIGHT_MAX)
                }
                _ => WEIGHT_MAX,
            })
            .collect()
    }

    /// Choose a member for a socket to a `v4` (else IPv6) destination.
    ///
    /// `key` identifies the destination for sticking (ignored when sticking
    /// is off); `prefer` is the member the same connection already used;
    /// members in the `tried` bit set are left out. `None` when no member
    /// can take it — the caller uses the default interface.
    pub fn pick(
        &self,
        v4: bool,
        key: Option<u64>,
        prefer: Option<usize>,
        tried: u32,
        now: Instant,
    ) -> Option<Pick> {
        let mut inner = self.inner.lock();
        let inner = &mut *inner;
        let bit = |i: usize| 1u32 << i;
        let mut routed = 0u32;
        let mut ready = 0u32;
        for (i, m) in inner.members.iter_mut().enumerate() {
            if !m.routes(v4) {
                continue;
            }
            routed |= bit(i);
            if !m.suspended(now) {
                m.suspended_until = None;
                ready |= bit(i);
            }
        }
        // Every member suspended: the suspension is ignored.
        let available = if ready == 0 { routed } else { ready };
        let seen = if v4 {
            &mut inner.available.0
        } else {
            &mut inner.available.1
        };
        if *seen != available {
            *seen = available;
            for m in &mut inner.members {
                m.epoch = 0;
            }
        }
        let candidates = available & !tried;
        if candidates == 0 {
            return None;
        }
        let key = key.filter(|_| self.sticky);
        // An entry not used for `STICKY_TTL` is forgotten, whether or not
        // the table was trimmed since.
        let stuck = key
            .and_then(|k| inner.sticky.get(&k))
            .filter(|(_, used)| now.saturating_duration_since(*used) < STICKY_TTL)
            .map(|(i, _)| *i)
            .filter(|i| candidates & bit(*i) != 0);
        let chosen = prefer
            .filter(|i| *i < self.names.len() && candidates & bit(*i) != 0)
            .or(stuck);
        let chosen = match chosen {
            Some(i) => i,
            None => {
                let weights = Self::weights(&inner.members);
                let mut best: Option<usize> = None;
                for i in (0..inner.members.len()).filter(|i| candidates & bit(*i) != 0) {
                    let Some(b) = best else {
                        best = Some(i);
                        continue;
                    };
                    // a/wa < b/wb  ⇔  a·wb < b·wa (weights are positive).
                    let load = |x: usize| self.stats[x].active.load(Ordering::Relaxed) as u128;
                    let (wi, wb) = (u128::from(weights[i]), u128::from(weights[b]));
                    let by_load = (load(i) * wb).cmp(&(load(b) * wi));
                    let by_turn = (u128::from(inner.members[i].epoch) * wb)
                        .cmp(&(u128::from(inner.members[b].epoch) * wi));
                    if by_load.then(by_turn).is_lt() {
                        best = Some(i);
                    }
                }
                best?
            }
        };
        inner.members[chosen].epoch += 1;
        self.stats[chosen].assigned.fetch_add(1, Ordering::Relaxed);
        if let Some(k) = key {
            if inner.sticky.len() >= STICKY_MAX && !inner.sticky.contains_key(&k) {
                trim_sticky(&mut inner.sticky, now);
            }
            inner.sticky.insert(k, (chosen, now));
        }
        Some(Pick {
            member: chosen,
            name: Arc::clone(&self.names[chosen]),
            index: inner.members[chosen].index,
        })
    }

    /// Whether a member outside `tried` could still take a `v4` (else
    /// IPv6) destination.
    pub fn has_untried(&self, v4: bool, tried: u32) -> bool {
        self.inner
            .lock()
            .members
            .iter()
            .enumerate()
            .any(|(i, m)| m.routes(v4) && tried & (1u32 << i) == 0)
    }

    /// Record how a dial through `member` ended.
    pub fn report(&self, member: usize, outcome: DialOutcome, now: Instant) {
        let mut inner = self.inner.lock();
        let Some(m) = inner.members.get_mut(member) else {
            return;
        };
        match outcome {
            DialOutcome::Connected(took) => {
                let ms = took.as_secs_f64() * 1000.0;
                m.latency = Some(m.latency.map_or(ms, |old| old + (ms - old) / 8.0));
                m.failures = 0;
                m.backoff = 0;
                m.suspended_until = None;
            }
            DialOutcome::Alive => {
                m.failures = 0;
                m.backoff = 0;
                m.suspended_until = None;
            }
            DialOutcome::Failed => {
                m.failures = m.failures.saturating_add(1);
                if m.failures >= SUSPEND_AFTER && !m.suspended(now) {
                    let wait = SUSPEND_BASE
                        .saturating_mul(1u32 << m.backoff.min(8))
                        .min(SUSPEND_MAX);
                    m.backoff = m.backoff.saturating_add(1);
                    m.suspended_until = Some(now + wait);
                    tracing::warn!(
                        "outbound balance: interface '{}' suspended for {}s after {} failed dials",
                        self.names[member],
                        wait.as_secs(),
                        m.failures
                    );
                }
            }
        }
    }

    /// Work out the byte rates since the last call (the route monitor calls
    /// this every couple of seconds).
    pub fn sample(&self, now: Instant) {
        let mut inner = self.inner.lock();
        let elapsed = inner
            .sampled_at
            .map(|at| now.saturating_duration_since(at).as_secs_f64());
        inner.sampled_at = Some(now);
        for (m, stats) in inner.members.iter_mut().zip(&self.stats) {
            let total = (
                stats.upload.load(Ordering::Relaxed),
                stats.download.load(Ordering::Relaxed),
            );
            if let Some(secs) = elapsed.filter(|s| *s > 0.0) {
                // Byte rates fit u64 by a wide margin.
                #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
                let per_sec = |new: u64, old: u64| (new.saturating_sub(old) as f64 / secs) as u64;
                m.rate = (per_sec(total.0, m.sampled.0), per_sec(total.1, m.sampled.1));
            }
            m.sampled = total;
        }
    }

    /// Everything about the members, for the API.
    pub fn snapshot(&self, now: Instant) -> BalanceSnapshot {
        let inner = self.inner.lock();
        let weights = Self::weights(&inner.members);
        let totals: Vec<(u64, u64, u64)> = self
            .stats
            .iter()
            .map(|s| {
                (
                    s.upload.load(Ordering::Relaxed),
                    s.download.load(Ordering::Relaxed),
                    s.assigned.load(Ordering::Relaxed),
                )
            })
            .collect();
        let bytes: u64 = totals.iter().map(|t| t.0.saturating_add(t.1)).sum();
        let assigned: u64 = totals.iter().map(|t| t.2).sum();
        let mut usable = 0;
        let interfaces = self
            .names
            .iter()
            .enumerate()
            .map(|(i, name)| {
                let m = &inner.members[i];
                let (upload, download, given) = totals[i];
                let suspended = m.state == MemberState::Up && m.suspended(now);
                if m.state == MemberState::Up && !suspended {
                    usable += 1;
                }
                let share = if bytes > 0 {
                    upload.saturating_add(download) as f64 / bytes as f64
                } else if assigned > 0 {
                    given as f64 / assigned as f64
                } else {
                    0.0
                };
                MemberSnapshot {
                    name: name.to_string(),
                    state: if suspended {
                        MemberState::Suspended
                    } else {
                        m.state
                    },
                    ipv4: m.v4,
                    ipv6: m.v6,
                    connections: self.stats[i].active.load(Ordering::Relaxed),
                    assigned: given,
                    upload,
                    download,
                    upload_rate: m.rate.0,
                    download_rate: m.rate.1,
                    share,
                    // Milliseconds, far below u64::MAX.
                    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
                    latency: m.latency.map(|ms| ms.round() as u64),
                    weight: weights[i],
                    failures: m.failures,
                    retry_in: m
                        .suspended_until
                        .filter(|_| suspended)
                        .map(|until| until.saturating_duration_since(now).as_secs().max(1)),
                    strict_rp_filter: m.strict_rp_filter,
                }
            })
            .collect();
        BalanceSnapshot {
            active: usable >= 2,
            sticky: self.sticky,
            interfaces,
        }
    }
}

/// Make room in a full sticky table: the expired entries, and when that is
/// not enough the oldest quarter.
fn trim_sticky(table: &mut HashMap<u64, (usize, Instant)>, now: Instant) {
    table.retain(|_, (_, used)| now.saturating_duration_since(*used) < STICKY_TTL);
    if table.len() < STICKY_MAX {
        return;
    }
    let mut ages: Vec<Instant> = table.values().map(|(_, used)| *used).collect();
    ages.sort_unstable();
    let cut = ages[ages.len() / 4];
    table.retain(|_, (_, used)| *used > cut);
}

/// Whether a socket to `ip` is spread over the members: only a public
/// address is. Private, shared (100.64/10), link-local, loopback,
/// multicast, broadcast and unspecified addresses are reachable by one
/// particular interface and keep the default one.
pub fn is_balanced_dest(ip: IpAddr) -> bool {
    match ip.to_canonical() {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            !(v4.is_private()
                || v4.is_loopback()
                || v4.is_link_local()
                || v4.is_multicast()
                || v4.is_broadcast()
                || v4.is_unspecified()
                || o[0] == 0
                || (o[0] == 100 && (o[1] & 0xc0) == 64))
        }
        IpAddr::V6(v6) => {
            let first = v6.segments()[0];
            !(v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_multicast()
                || (first & 0xfe00) == 0xfc00
                || (first & 0xffc0) == 0xfe80)
        }
    }
}

/// Second-level labels that are registries under a two-letter top level
/// (`example.com.cn`, `example.co.uk`).
const REGISTRY_LABELS: &[&str] = &["com", "net", "org", "gov", "edu", "ac", "co"];

/// The site a host name belongs to, for sticking: its last two labels, or
/// the last three when the second-level one is a registry under a
/// two-letter top level. Not the public-suffix list — close enough to keep
/// one site's hosts together.
pub fn site_of(host: &str) -> &str {
    let host = host.trim_end_matches('.');
    let mut dots = host.rmatch_indices('.').map(|(i, _)| i);
    let Some(last) = dots.next() else {
        return host;
    };
    let Some(second) = dots.next() else {
        return host;
    };
    let tld = &host[last + 1..];
    let sld = &host[second + 1..last];
    let registry = tld.len() == 2 && REGISTRY_LABELS.iter().any(|r| r.eq_ignore_ascii_case(sld));
    if !registry {
        return &host[second + 1..];
    }
    match dots.next() {
        Some(third) => &host[third + 1..],
        None => host,
    }
}

/// The sticky key of a destination: the site of `host` (case-insensitive),
/// else `ip`; `None` when there is neither.
pub fn sticky_key(host: &str, ip: Option<IpAddr>) -> Option<u64> {
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    // A host that is an address literal is keyed like the address.
    let literal = crate::metadata_ip_literal(host);
    if let Some(ip) = literal.or(ip.filter(|_| host.is_empty())) {
        ip.to_canonical().hash(&mut hasher);
    } else if host.is_empty() {
        return None;
    } else {
        for b in site_of(host).bytes() {
            hasher.write_u8(b.to_ascii_lowercase());
        }
        hasher.write_u8(0xff);
    }
    Some(hasher.finish())
}

/// A connection's hold on the member it was given: counted in flight until
/// dropped, and where its bytes are attributed.
struct Lease {
    balancer: Arc<Balancer>,
    member: usize,
}

impl Lease {
    fn new(balancer: &Arc<Balancer>, member: usize) -> Self {
        balancer.stats[member]
            .active
            .fetch_add(1, Ordering::Relaxed);
        Self {
            balancer: Arc::clone(balancer),
            member,
        }
    }
}

impl Drop for Lease {
    fn drop(&mut self) {
        self.balancer.stats[self.member]
            .active
            .fetch_sub(1, Ordering::Relaxed);
    }
}

struct Chosen {
    name: Arc<str>,
    lease: Option<Lease>,
}

/// One connection's dial context: what destination it is for (the sticky
/// key) and — once its first socket was bound — which interface it left
/// by. The inbound paths create one per connection ([`DialScope::for_target`]),
/// run the dial inside it ([`scoped`]) and keep it for the connection's
/// life.
pub struct DialScope {
    key: Option<u64>,
    /// Sockets made in this scope never take a balancer member (see
    /// [`DialScope::unbalanced`]).
    default_only: bool,
    chosen: OnceLock<Chosen>,
}

impl std::fmt::Debug for DialScope {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DialScope")
            .field("key", &self.key)
            .field("interface", &self.interface())
            .finish()
    }
}

tokio::task_local! {
    static DIAL_SCOPE: Arc<DialScope>;
}

impl DialScope {
    /// A scope for a connection to `host` (may be empty) / `ip`, when
    /// balancing is configured; `None` otherwise — nothing to record, and
    /// the common case costs one lock read.
    pub fn for_target(host: &str, ip: Option<IpAddr>) -> Option<Arc<Self>> {
        crate::outbound_iface::balancer()?;
        Some(Self::new(sticky_key(host, ip)))
    }

    /// A scope with this sticky key, whatever is configured.
    pub fn new(key: Option<u64>) -> Arc<Self> {
        Arc::new(Self {
            key,
            default_only: false,
            chosen: OnceLock::new(),
        })
    }

    /// A scope whose sockets keep the default interface (or the one the
    /// system routes their peer through) and are never spread over the
    /// members, when balancing is configured; `None` otherwise. For what
    /// must not depend on which line a connection got: DNS upstream
    /// queries — an ISP's resolver answers its own line only, and a UDP
    /// query cannot tell the balancer that a member is dead. Running such
    /// work in its own scope also keeps its sockets out of the scope of
    /// the connection that asked (a lookup made inside a dial would
    /// otherwise be taken for the connection's first socket).
    pub fn unbalanced() -> Option<Arc<Self>> {
        crate::outbound_iface::balancer()?;
        Some(Arc::new(Self {
            key: None,
            default_only: true,
            chosen: OnceLock::new(),
        }))
    }

    /// Whether sockets made in this scope stay off the balancer's members.
    pub fn default_only(&self) -> bool {
        self.default_only
    }

    /// The scope the current task dials in, if any.
    pub fn current() -> Option<Arc<Self>> {
        DIAL_SCOPE.try_with(Arc::clone).ok()
    }

    /// The destination's sticky key.
    pub fn key(&self) -> Option<u64> {
        self.key
    }

    /// The interface this connection's first socket was bound to.
    pub fn interface(&self) -> Option<Arc<str>> {
        self.chosen.get().map(|c| Arc::clone(&c.name))
    }

    /// The member of `balancer` this connection already uses.
    pub fn member_of(&self, balancer: &Arc<Balancer>) -> Option<usize> {
        let lease = self.chosen.get()?.lease.as_ref()?;
        Arc::ptr_eq(&lease.balancer, balancer).then_some(lease.member)
    }

    /// Record the first socket's interface: a member (counted in flight
    /// from now until the scope is dropped) or any other interface. Later
    /// calls change nothing.
    pub fn record(&self, name: &Arc<str>, member: Option<(&Arc<Balancer>, usize)>) {
        if self.chosen.get().is_some() {
            return;
        }
        // A lost race drops the lease it made, which undoes its count.
        let _ = self.chosen.set(Chosen {
            name: Arc::clone(name),
            lease: member.map(|(b, m)| Lease::new(b, m)),
        });
    }

    fn stats(&self) -> Option<&MemberStats> {
        let lease = self.chosen.get()?.lease.as_ref()?;
        Some(&lease.balancer.stats[lease.member])
    }

    /// Attribute uploaded bytes to the connection's member.
    pub fn add_upload(&self, n: u64) {
        if let Some(s) = self.stats() {
            s.upload.fetch_add(n, Ordering::Relaxed);
        }
    }

    /// Attribute downloaded bytes to the connection's member.
    pub fn add_download(&self, n: u64) {
        if let Some(s) = self.stats() {
            s.download.fetch_add(n, Ordering::Relaxed);
        }
    }
}

/// Run a dial inside `scope` (when there is one): the sockets it creates
/// on this task take the scope's sticky key and record their interface in
/// it. Tasks the dial spawns do not inherit it.
pub async fn scoped<F: Future>(scope: Option<Arc<DialScope>>, dial: F) -> F::Output {
    match scope {
        Some(scope) => DIAL_SCOPE.scope(scope, dial).await,
        None => dial.await,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Links(Vec<Link>, Vec<(&'static str, LinkKind)>);

    impl LinkSource for Links {
        fn links(&self) -> Vec<Link> {
            self.0.clone()
        }
        fn kind_of(&self, name: &str) -> Option<LinkKind> {
            self.0
                .iter()
                .find(|l| l.name == name)
                .map(|l| l.kind)
                .or_else(|| self.1.iter().find(|(n, _)| *n == name).map(|(_, k)| *k))
        }
    }

    fn link(name: &str, v4: bool, v6: bool) -> Link {
        Link {
            name: name.into(),
            index: 7,
            kind: LinkKind::Physical,
            v4,
            v6,
            strict_rp_filter: false,
        }
    }

    fn both() -> Links {
        Links(
            vec![link("en0", true, true), link("en7", true, false)],
            vec![],
        )
    }

    fn balancer(sticky: bool) -> Arc<Balancer> {
        let b = Balancer::new(&BalanceOptions {
            interfaces: vec!["en0".into(), "en7".into()],
            sticky,
        });
        b.refresh(&both());
        b
    }

    fn names(b: &Balancer, n: usize, now: Instant) -> Vec<String> {
        (0..n)
            .map(|_| b.pick(true, None, None, 0, now).unwrap().name.to_string())
            .collect()
    }

    #[test]
    fn names_are_cleaned() {
        let long = "x".repeat(MAX_NAME_LEN + 1);
        assert_eq!(
            clean_interfaces([
                " en0 ",
                "",
                "en0",
                "bad\u{0}name",
                "tab\tname",
                &long,
                "以太网 2"
            ]),
            ["en0", "以太网 2"]
        );
        let many: Vec<String> = (0..20).map(|i| format!("eth{i}")).collect();
        assert_eq!(
            clean_interfaces(many.iter().map(String::as_str)).len(),
            MAX_MEMBERS
        );
    }

    #[test]
    fn without_measurements_it_is_round_robin() {
        let b = balancer(false);
        let now = Instant::now();
        assert_eq!(
            names(&b, 6, now),
            ["en0", "en7", "en0", "en7", "en0", "en7"]
        );
        let snap = b.snapshot(now);
        assert!(snap.active && !snap.sticky);
        assert_eq!(snap.interfaces[0].assigned, 3);
        assert_eq!(snap.interfaces[1].assigned, 3);
        assert!((snap.interfaces[0].share - 0.5).abs() < 1e-9);
        assert_eq!(snap.interfaces[0].weight, 100);
        assert_eq!(snap.interfaces[0].latency, None);
    }

    #[test]
    fn a_faster_line_gets_more_but_the_slow_one_is_not_starved() {
        let b = balancer(false);
        let now = Instant::now();
        b.report(0, DialOutcome::Connected(Duration::from_millis(20)), now);
        b.report(1, DialOutcome::Connected(Duration::from_millis(40)), now);
        let snap = b.snapshot(now);
        assert_eq!(
            (snap.interfaces[0].weight, snap.interfaces[1].weight),
            (100, 50)
        );
        assert_eq!(snap.interfaces[1].latency, Some(40));
        let got = names(&b, 30, now);
        let fast = got.iter().filter(|n| *n == "en0").count();
        assert_eq!(fast, 20, "2:1 by weight: {got:?}");
    }

    #[test]
    fn a_very_slow_line_still_gets_a_quarter_of_the_turns() {
        let b = balancer(false);
        let now = Instant::now();
        b.report(0, DialOutcome::Connected(Duration::from_millis(20)), now);
        b.report(1, DialOutcome::Connected(Duration::from_secs(60)), now);
        assert_eq!(b.snapshot(now).interfaces[1].weight, 25);
        let got = names(&b, 50, now);
        assert_eq!(got.iter().filter(|n| *n == "en7").count(), 10, "{got:?}");
    }

    #[test]
    fn connections_in_flight_send_new_ones_to_the_idle_line() {
        let b = balancer(false);
        let now = Instant::now();
        // Three downloads hold en0.
        let held: Vec<_> = (0..3)
            .map(|_| {
                let scope = DialScope::new(None);
                scope.record(&b.names()[0], Some((&b, 0)));
                scope
            })
            .collect();
        assert_eq!(b.snapshot(now).interfaces[0].connections, 3);
        assert_eq!(names(&b, 3, now), ["en7", "en7", "en7"]);
        drop(held);
        assert_eq!(b.snapshot(now).interfaces[0].connections, 0);
    }

    #[test]
    fn the_same_destination_keeps_its_interface() {
        let b = balancer(true);
        let now = Instant::now();
        let site = sticky_key("www.example.com", None);
        let first = b.pick(true, site, None, 0, now).unwrap();
        // Other destinations in between move the round-robin on.
        for i in 0..5 {
            b.pick(true, sticky_key(&format!("h{i}.test"), None), None, 0, now);
        }
        for host in ["www.example.com", "API.Example.com", "example.com."] {
            let again = b.pick(true, sticky_key(host, None), None, 0, now).unwrap();
            assert_eq!(again.member, first.member, "{host}");
        }
        // Different sites are still spread.
        let spread: std::collections::HashSet<usize> = (0..8)
            .map(|i| {
                b.pick(
                    true,
                    sticky_key(&format!("site{i}.test"), None),
                    None,
                    0,
                    now,
                )
                .unwrap()
                .member
            })
            .collect();
        assert_eq!(spread.len(), 2);
    }

    #[test]
    fn sticking_off_ignores_the_key_but_a_connection_keeps_its_member() {
        let b = balancer(false);
        let now = Instant::now();
        let key = sticky_key("example.com", None);
        let got: Vec<usize> = (0..4)
            .map(|_| b.pick(true, key, None, 0, now).unwrap().member)
            .collect();
        assert_eq!(got, [0, 1, 0, 1]);
        // The second socket of one connection (a retry, the next hop).
        for _ in 0..3 {
            assert_eq!(b.pick(true, None, Some(1), 0, now).unwrap().member, 1);
        }
    }

    #[test]
    fn an_interface_that_goes_down_is_skipped_and_comes_back() {
        let b = balancer(true);
        let now = Instant::now();
        let key = sticky_key("example.com", None);
        // Stuck to en0 (the first choice).
        assert_eq!(b.pick(true, key, None, 0, now).unwrap().member, 0);

        // en0 loses its default route: unplugged.
        b.refresh(&Links(
            vec![link("en7", true, false)],
            vec![("en0", LinkKind::Physical)],
        ));
        let snap = b.snapshot(now);
        assert_eq!(snap.interfaces[0].state, MemberState::NoRoute);
        assert!(!snap.active);
        assert_eq!(names(&b, 3, now), ["en7", "en7", "en7"]);
        // The stuck destination moves to en7 …
        assert_eq!(b.pick(true, key, None, 0, now).unwrap().member, 1);

        // … the interface vanishes altogether …
        b.refresh(&Links(vec![link("en7", true, false)], vec![]));
        assert_eq!(b.snapshot(now).interfaces[0].state, MemberState::Missing);

        // … and returns: used again, but the destination stays where it is.
        b.refresh(&both());
        let snap = b.snapshot(now);
        assert_eq!(snap.interfaces[0].state, MemberState::Up);
        assert!(snap.active);
        assert_eq!(b.pick(true, key, None, 0, now).unwrap().member, 1);
        let got = names(&b, 4, now);
        assert!(
            got.iter().any(|n| n == "en0") && got.iter().any(|n| n == "en7"),
            "{got:?}"
        );

        // Nothing left: the caller falls back to the default interface.
        b.refresh(&Links(vec![], vec![]));
        assert!(b.pick(true, None, None, 0, now).is_none());
    }

    #[test]
    fn virtual_interfaces_are_never_members() {
        let b = Balancer::new(&BalanceOptions {
            interfaces: vec!["en0".into(), "utun6".into(), "docker0".into()],
            sticky: true,
        });
        let mut vpn = link("utun6", true, true);
        vpn.kind = LinkKind::Virtual;
        b.refresh(&Links(
            vec![link("en0", true, false), vpn],
            vec![("docker0", LinkKind::Virtual)],
        ));
        let now = Instant::now();
        let snap = b.snapshot(now);
        assert_eq!(snap.interfaces[1].state, MemberState::Virtual);
        assert_eq!(snap.interfaces[2].state, MemberState::Virtual);
        assert!(!snap.active);
        assert_eq!(names(&b, 4, now), ["en0"; 4]);
    }

    #[test]
    fn a_member_only_takes_the_family_it_has_a_default_route_for() {
        let b = balancer(false);
        let now = Instant::now();
        // en7 has no IPv6 default route.
        for _ in 0..4 {
            assert_eq!(&*b.pick(false, None, None, 0, now).unwrap().name, "en0");
        }
        assert!(b.has_untried(true, 0b01));
        assert!(!b.has_untried(false, 0b01));
        assert!(b.pick(false, None, None, 0b01, now).is_none());
    }

    #[test]
    fn failed_dials_suspend_a_member_and_time_brings_it_back() {
        let b = balancer(false);
        let t0 = Instant::now();
        b.report(1, DialOutcome::Failed, t0);
        b.report(1, DialOutcome::Failed, t0);
        assert_eq!(b.snapshot(t0).interfaces[1].state, MemberState::Up);
        // A refusal proves the line works: the count starts over.
        b.report(1, DialOutcome::Alive, t0);
        assert_eq!(b.snapshot(t0).interfaces[1].failures, 0);
        for _ in 0..SUSPEND_AFTER {
            b.report(1, DialOutcome::Failed, t0);
        }
        let snap = b.snapshot(t0);
        assert_eq!(snap.interfaces[1].state, MemberState::Suspended);
        assert_eq!(snap.interfaces[1].retry_in, Some(10));
        assert!(!snap.active);
        assert_eq!(names(&b, 3, t0), ["en0"; 3]);

        // After the wait it is tried again; one more failure suspends it
        // for twice as long.
        let t1 = t0 + SUSPEND_BASE;
        assert_eq!(b.snapshot(t1).interfaces[1].state, MemberState::Up);
        assert!(names(&b, 2, t1).contains(&"en7".to_string()));
        b.report(1, DialOutcome::Failed, t1);
        let snap = b.snapshot(t1);
        assert_eq!(snap.interfaces[1].state, MemberState::Suspended);
        assert_eq!(snap.interfaces[1].retry_in, Some(20));

        // A success clears everything.
        let t2 = t1 + Duration::from_secs(20);
        b.report(1, DialOutcome::Connected(Duration::from_millis(5)), t2);
        let snap = b.snapshot(t2);
        assert_eq!(snap.interfaces[1].state, MemberState::Up);
        assert_eq!(snap.interfaces[1].failures, 0);
        for _ in 0..SUSPEND_AFTER {
            b.report(1, DialOutcome::Failed, t2);
        }
        assert_eq!(b.snapshot(t2).interfaces[1].retry_in, Some(10));

        // The suspension never exceeds the ceiling.
        let mut t = t2;
        for _ in 0..10 {
            t += SUSPEND_MAX;
            b.report(1, DialOutcome::Failed, t);
        }
        assert_eq!(b.snapshot(t).interfaces[1].retry_in, Some(60));
    }

    #[test]
    fn all_members_suspended_means_none_is() {
        let b = balancer(false);
        let now = Instant::now();
        for m in 0..2 {
            for _ in 0..SUSPEND_AFTER {
                b.report(m, DialOutcome::Failed, now);
            }
        }
        assert!(!b.snapshot(now).active);
        assert_eq!(names(&b, 4, now), ["en0", "en7", "en0", "en7"]);
    }

    #[test]
    fn a_failed_member_is_left_out_of_the_same_dial() {
        let b = balancer(true);
        let now = Instant::now();
        let key = sticky_key("example.com", None);
        let first = b.pick(true, key, None, 0, now).unwrap();
        let second = b.pick(true, key, None, 1 << first.member, now).unwrap();
        assert_ne!(first.member, second.member);
        let tried = (1 << first.member) | (1 << second.member);
        assert!(b.pick(true, key, None, tried, now).is_none());
        assert!(!b.has_untried(true, tried));
    }

    #[test]
    fn bytes_are_attributed_and_rated() {
        let b = balancer(false);
        let t0 = Instant::now();
        let a = DialScope::new(None);
        a.record(&b.names()[0], Some((&b, 0)));
        let c = DialScope::new(None);
        c.record(&b.names()[1], Some((&b, 1)));
        // An interface outside the balancer is recorded, not counted.
        let other = DialScope::new(None);
        other.record(&Arc::from("tun0"), None);
        other.add_download(1_000_000);
        assert_eq!(other.interface().as_deref(), Some("tun0"));
        assert_eq!(other.member_of(&b), None);
        // The first record wins.
        a.record(&b.names()[1], Some((&b, 1)));
        assert_eq!(a.interface().as_deref(), Some("en0"));
        assert_eq!(a.member_of(&b), Some(0));

        b.sample(t0);
        a.add_upload(1000);
        a.add_download(5000);
        c.add_download(2000);
        b.sample(t0 + Duration::from_secs(2));
        let snap = b.snapshot(t0);
        let (en0, en7) = (&snap.interfaces[0], &snap.interfaces[1]);
        assert_eq!((en0.upload, en0.download), (1000, 5000));
        assert_eq!((en0.upload_rate, en0.download_rate), (500, 2500));
        assert_eq!((en7.download, en7.download_rate), (2000, 1000));
        assert!((en0.share - 0.75).abs() < 1e-9);
        assert!((en0.share + en7.share - 1.0).abs() < 1e-9);
        assert_eq!((en0.connections, en7.connections), (1, 1));
        drop((a, c));
        let snap = b.snapshot(t0);
        assert_eq!(snap.interfaces[0].connections, 0);
        assert_eq!(snap.interfaces[0].download, 5000);
    }

    #[test]
    fn the_sticky_table_is_bounded() {
        let b = balancer(true);
        let t0 = Instant::now();
        for i in 0..STICKY_MAX as u64 {
            b.pick(true, Some(i), None, 0, t0);
        }
        // All expired: one insert clears them.
        let later = t0 + STICKY_TTL;
        b.pick(true, Some(u64::MAX), None, 0, later);
        assert_eq!(b.inner.lock().sticky.len(), 1);
        // None expired: the oldest quarter goes.
        for i in 0..STICKY_MAX as u64 {
            b.pick(true, Some(i), None, 0, later + Duration::from_millis(i));
        }
        let len = b.inner.lock().sticky.len();
        assert!(len <= STICKY_MAX && len > STICKY_MAX / 2, "{len}");
    }

    #[test]
    fn a_sticky_entry_expires_when_it_is_not_used() {
        let b = balancer(true);
        let t0 = Instant::now();
        let key = sticky_key("example.com", None);
        assert_eq!(b.pick(true, key, None, 0, t0).unwrap().member, 0);
        // Another destination takes en7, so the next free turn is en0's.
        assert_eq!(b.pick(true, Some(1), None, 0, t0).unwrap().member, 1);
        assert_eq!(b.pick(true, Some(2), None, 0, t0).unwrap().member, 0);
        // Used within the window: kept, and the window starts over.
        let t1 = t0 + STICKY_TTL - Duration::from_secs(1);
        assert_eq!(b.pick(true, key, None, 0, t1).unwrap().member, 0);
        let t2 = t1 + STICKY_TTL - Duration::from_secs(1);
        assert_eq!(b.pick(true, key, None, 0, t2).unwrap().member, 0);
        // Idle for the whole window: chosen afresh (en7 is behind by two).
        let t3 = t2 + STICKY_TTL;
        assert_eq!(b.pick(true, key, None, 0, t3).unwrap().member, 1);
        assert_eq!(b.pick(true, key, None, 0, t3).unwrap().member, 1);
    }

    #[test]
    fn only_public_destinations_are_spread() {
        for ip in [
            "8.8.8.8",
            "1.1.1.1",
            "100.128.0.1",
            "2001:4860:4860::8888",
            "::ffff:8.8.8.8",
        ] {
            assert!(is_balanced_dest(ip.parse().unwrap()), "{ip}");
        }
        for ip in [
            "10.8.0.5",
            "172.16.3.4",
            "192.168.1.1",
            "100.64.0.1",
            "100.127.255.255",
            "169.254.1.1",
            "127.0.0.1",
            "224.0.0.251",
            "255.255.255.255",
            "0.0.0.0",
            "::1",
            "::",
            "fe80::1",
            "fd00::1",
            "ff02::1",
            "::ffff:192.168.1.1",
        ] {
            assert!(!is_balanced_dest(ip.parse().unwrap()), "{ip}");
        }
    }

    #[test]
    fn sites_and_sticky_keys() {
        for (host, site) in [
            ("example.com", "example.com"),
            ("a.b.example.com", "example.com"),
            ("a.b.example.com.cn", "example.com.cn"),
            ("www.example.co.uk", "example.co.uk"),
            ("com.cn", "com.cn"),
            ("localhost", "localhost"),
            ("www.example.com.", "example.com"),
            ("a.example.io", "example.io"),
        ] {
            assert_eq!(site_of(host), site, "{host}");
        }
        let ip: IpAddr = "93.184.216.34".parse().unwrap();
        assert_eq!(sticky_key("", None), None);
        assert_eq!(
            sticky_key("a.Example.com", None),
            sticky_key("b.example.COM", Some(ip))
        );
        assert_ne!(
            sticky_key("example.com", None),
            sticky_key("example.org", None)
        );
        // No name: the address; a literal host is the address too.
        assert_eq!(sticky_key("", Some(ip)), sticky_key("93.184.216.34", None));
        assert_ne!(
            sticky_key("", Some(ip)),
            sticky_key("", Some("93.184.216.35".parse().unwrap()))
        );
    }

    #[test]
    fn the_live_balancer_is_shared_while_the_options_match() {
        let options = BalanceOptions {
            interfaces: vec!["zz-a".into(), "zz-b".into()],
            sticky: true,
        };
        let a = Balancer::obtain(&options);
        let b = Balancer::obtain(&options);
        assert!(Arc::ptr_eq(&a, &b));
        let other = Balancer::obtain(&BalanceOptions {
            sticky: false,
            ..options
        });
        assert!(!Arc::ptr_eq(&a, &other));
    }

    #[tokio::test]
    async fn a_dial_sees_its_scope_and_a_spawned_task_does_not() {
        assert!(DialScope::current().is_none());
        let scope = DialScope::new(Some(42));
        let seen = scoped(Some(Arc::clone(&scope)), async {
            let inside = DialScope::current().map(|s| s.key());
            let spawned = tokio::spawn(async { DialScope::current().is_none() })
                .await
                .unwrap();
            (inside, spawned)
        })
        .await;
        assert_eq!(seen, (Some(Some(42)), true));
        assert!(scoped(None, async { DialScope::current().is_none() }).await);
    }
}
