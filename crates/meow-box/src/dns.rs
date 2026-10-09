//! The box's DNS service on its own address (UDP and TCP 53).
//!
//! Who asks decides the answer: a device that routes through the box gets
//! the core's answers (fake-ip, so rules see the names); every other device
//! (DNS pointed at the box, gateway not — or not yet) gets real addresses,
//! because a fake address would leave it with nowhere to go.
//!
//! Real addresses must be clean: domestic resolvers return poisoned
//! addresses for blocked foreign names (`www.google.com` → a Facebook IP).
//! So a name on the domestic list (the core's `GEOSITE,cn`, from the core's
//! `geosite.dat`) asks the domestic upstreams, and any other name is asked
//! of [`FOREIGN_UPSTREAMS`] over TCP through one of the lines (the core's
//! SOCKS port on 127.0.0.1, the core's rules pick the line). With no lines
//! yet, or when that fails, the domestic upstreams answer (not cached).
//!
//! Real answers carry a short TTL ([`REAL_TTL`]): a device that has just
//! made the box its gateway asks again soon, and is then known and gets
//! the core's answers.

use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use std::sync::{Mutex, RwLock};

use meow_rules::geosite::GeositeDB;
use serde_json::{json, Value};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};

/// Default upstreams for real answers to domestic names (the app's
/// domestic resolvers); editable on the page.
pub const DEFAULT_UPSTREAMS: [&str; 2] = ["223.5.5.5", "119.29.29.29"];
/// Resolvers asked through a line for every name off the domestic list
/// (DNS over TCP; raced, the first answer wins).
pub const FOREIGN_UPSTREAMS: [SocketAddrV4; 2] = [
    SocketAddrV4::new(Ipv4Addr::new(8, 8, 8, 8), 53),
    SocketAddrV4::new(Ipv4Addr::new(1, 1, 1, 1), 53),
];
/// The geosite category of domestic names (the core's `GEOSITE,cn`).
pub const DOMESTIC_CATEGORY: &str = "cn";
/// Largest TTL (seconds) of a real answer to a device: one that has just
/// set its gateway to the box asks again soon and then gets fake-ip.
pub const REAL_TTL: u32 = 10;
/// Largest UDP answer sent to a device (no IP fragmentation).
pub const MAX_UDP_ANSWER: usize = 1472;

const CACHE_MAX: usize = 4096;
const CACHE_MAX_TTL: u32 = 600;
const NEGATIVE_TTL: u32 = 60;
const UPSTREAM_TIMEOUT: Duration = Duration::from_secs(2);
const CORE_TIMEOUT: Duration = Duration::from_secs(5);
/// A query through a line: the SOCKS handshake, the line's dial and the
/// answer (devices give up after about 5 s; the domestic fallback needs
/// the rest).
const LINE_TIMEOUT: Duration = Duration::from_secs(3);

/// A query's question.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Question {
    /// Lowercase, no trailing dot.
    pub name: String,
    pub qtype: u16,
    pub qclass: u16,
    /// Where the question ends in the message.
    pub end: usize,
}

/// The first question of a DNS message; None when malformed (or a
/// compressed name, which a query never has).
pub fn question(m: &[u8]) -> Option<Question> {
    if m.len() < 12 || u16::from_be_bytes([m[4], m[5]]) == 0 {
        return None;
    }
    let mut at = 12;
    let mut labels: Vec<String> = Vec::new();
    loop {
        let len = usize::from(*m.get(at)?);
        at += 1;
        if len == 0 {
            break;
        }
        if len & 0xc0 != 0 {
            return None;
        }
        let label = m.get(at..at + len)?;
        labels.push(String::from_utf8_lossy(label).to_ascii_lowercase());
        at += len;
    }
    let t = m.get(at..at + 4)?;
    Some(Question {
        name: labels.join("."),
        qtype: u16::from_be_bytes([t[0], t[1]]),
        qclass: u16::from_be_bytes([t[2], t[3]]),
        end: at + 4,
    })
}

/// Skips a (possibly compressed) name at `at`; the offset after it.
fn skip_name(m: &[u8], mut at: usize) -> Option<usize> {
    loop {
        let len = *m.get(at)?;
        if len & 0xc0 == 0xc0 {
            return Some(at + 2);
        }
        at += 1;
        if len == 0 {
            return Some(at);
        }
        at += usize::from(len);
    }
}

/// How long an answer may be cached: its smallest TTL (answer and
/// authority records), [`NEGATIVE_TTL`] for a no-data / NXDOMAIN answer;
/// None for answers not worth keeping (errors, truncated).
pub fn cache_ttl(m: &[u8]) -> Option<u32> {
    if m.len() < 12 || m[2] & 0x02 != 0 {
        return None;
    }
    let rcode = m[3] & 0x0f;
    if rcode != 0 && rcode != 3 {
        return None;
    }
    let count = |i: usize| usize::from(u16::from_be_bytes([m[i], m[i + 1]]));
    let (qd, an, ns) = (count(4), count(6), count(8));
    let mut at = 12;
    for _ in 0..qd {
        at = skip_name(m, at)? + 4;
    }
    let mut ttl: Option<u32> = None;
    for _ in 0..an + ns {
        at = skip_name(m, at)?;
        let h = m.get(at..at + 10)?;
        let t = u32::from_be_bytes([h[4], h[5], h[6], h[7]]);
        ttl = Some(ttl.map_or(t, |x| x.min(t)));
        at += 10 + usize::from(u16::from_be_bytes([h[8], h[9]]));
    }
    if an == 0 {
        return Some(ttl.unwrap_or(NEGATIVE_TTL).min(NEGATIVE_TTL));
    }
    ttl.map(|t| t.min(CACHE_MAX_TTL))
}

/// `answer` with the id of `query`.
pub fn with_id(mut answer: Vec<u8>, query: &[u8]) -> Vec<u8> {
    if answer.len() >= 2 && query.len() >= 2 {
        answer[0] = query[0];
        answer[1] = query[1];
    }
    answer
}

/// An answer cut to `max` bytes for UDP: header + question, TC set (the
/// device asks again over TCP).
pub fn truncate(answer: Vec<u8>, max: usize) -> Vec<u8> {
    if answer.len() <= max {
        return answer;
    }
    let Some(q) = question(&answer) else {
        return answer[..12.min(answer.len())].to_vec();
    };
    let mut m = answer[..q.end].to_vec();
    m[2] |= 0x02;
    m[6..12].fill(0);
    m[4..6].copy_from_slice(&1u16.to_be_bytes());
    m
}

/// `answer` with every record's TTL at most `max` (the EDNS OPT record,
/// whose TTL field holds flags, untouched); as it was when malformed.
pub fn cap_ttl(mut answer: Vec<u8>, max: u32) -> Vec<u8> {
    let mut at_ttls: Vec<usize> = Vec::new();
    let ok = (|| {
        if answer.len() < 12 {
            return None;
        }
        let count = |i: usize| usize::from(u16::from_be_bytes([answer[i], answer[i + 1]]));
        let (qd, records) = (count(4), count(6) + count(8) + count(10));
        let mut at = 12;
        for _ in 0..qd {
            at = skip_name(&answer, at)? + 4;
        }
        for _ in 0..records {
            at = skip_name(&answer, at)?;
            let h = answer.get(at..at + 10)?;
            if u16::from_be_bytes([h[0], h[1]]) != 41 {
                at_ttls.push(at + 4);
            }
            at += 10 + usize::from(u16::from_be_bytes([h[8], h[9]]));
        }
        (at <= answer.len()).then_some(())
    })();
    if ok.is_some() {
        for i in at_ttls {
            let t = u32::from_be_bytes([answer[i], answer[i + 1], answer[i + 2], answer[i + 3]]);
            answer[i..i + 4].copy_from_slice(&t.min(max).to_be_bytes());
        }
    }
    answer
}

/// An A answer for `query` with `ip` (hosts entries), TTL [`REAL_TTL`].
pub fn answer_a(query: &[u8], q: &Question, ip: Ipv4Addr) -> Vec<u8> {
    let mut m = query[..q.end].to_vec();
    m[2] = 0x80 | (query[2] & 0x01); // QR, keep RD
    m[3] = 0x80; // RA, NOERROR
    m[4..6].copy_from_slice(&1u16.to_be_bytes());
    let answers: u16 = if q.qtype == 1 { 1 } else { 0 };
    m[6..8].copy_from_slice(&answers.to_be_bytes());
    m[8..12].fill(0);
    if answers == 1 {
        m.extend_from_slice(&[0xc0, 12, 0, 1, 0, 1]);
        m.extend_from_slice(&REAL_TTL.to_be_bytes());
        m.extend_from_slice(&4u16.to_be_bytes());
        m.extend_from_slice(&ip.octets());
    }
    m
}

/// A SERVFAIL for `query` (nothing answered in time).
pub fn servfail(query: &[u8], q: &Question) -> Vec<u8> {
    let mut m = query[..q.end].to_vec();
    m[2] = 0x80 | (query[2] & 0x01);
    m[3] = 0x82;
    m[4..6].copy_from_slice(&1u16.to_be_bytes());
    m[6..12].fill(0);
    m
}

/// One hosts entry (the app's `paopao-hosts`) with an IPv4 address; the
/// real-answer side honours `exact`, `suffix`, `keyword` and `wildcard`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostRule {
    kind: String,
    value: String,
    ip: Ipv4Addr,
}

impl HostRule {
    /// The rules of a config's `paopao-hosts` list (entries without an
    /// IPv4 address, or of other kinds, left out).
    pub fn from_config(v: Option<&Value>) -> Vec<Self> {
        v.and_then(Value::as_array)
            .map(|a| {
                a.iter()
                    .filter_map(|e| {
                        let kind = e.get("type")?.as_str()?;
                        if !matches!(kind, "exact" | "suffix" | "keyword" | "wildcard") {
                            return None;
                        }
                        Some(Self {
                            kind: kind.to_owned(),
                            value: e.get("value")?.as_str()?.trim().to_ascii_lowercase(),
                            ip: e.get("address")?.as_str()?.trim().parse().ok()?,
                        })
                    })
                    .collect()
            })
            .unwrap_or_default()
    }

    fn matches(&self, name: &str) -> bool {
        let v = self.value.as_str();
        match self.kind.as_str() {
            "exact" => name == v,
            "suffix" => name == v || name.ends_with(&format!(".{v}")),
            "keyword" => name.contains(v),
            "wildcard" => glob(v.as_bytes(), name.as_bytes()),
            _ => false,
        }
    }
}

/// `*` (any run) and `?` (one character) matching.
fn glob(p: &[u8], s: &[u8]) -> bool {
    match (p.first(), s.first()) {
        (None, None) => true,
        (Some(b'*'), _) => glob(&p[1..], s) || (!s.is_empty() && glob(p, &s[1..])),
        (Some(b'?'), Some(_)) => glob(&p[1..], &s[1..]),
        (Some(a), Some(b)) if a == b => glob(&p[1..], &s[1..]),
        _ => false,
    }
}

/// Counters for the status page.
#[derive(Debug, Default)]
pub struct Stats {
    pub queries: AtomicU64,
    pub cache_hits: AtomicU64,
    /// Answered by the core (devices routing through the box).
    pub via_core: AtomicU64,
    /// Answered by a domestic upstream (real addresses).
    pub via_upstream: AtomicU64,
    /// Answered through a line (real addresses of names off the domestic
    /// list).
    pub via_line: AtomicU64,
    pub hosts: AtomicU64,
    pub failed: AtomicU64,
}

type CacheKey = (String, u16, u16);

/// The DNS front.
#[derive(Debug)]
pub struct Front {
    upstreams: RwLock<Vec<SocketAddr>>,
    /// The core's DNS listener (127.0.0.1); None while the core is down.
    core: RwLock<Option<SocketAddr>>,
    hosts: RwLock<Vec<HostRule>>,
    /// The core's SOCKS listener (127.0.0.1) while it has lines; None:
    /// domestic upstreams only.
    line: RwLock<Option<SocketAddr>>,
    /// The domestic list (`geosite.dat`'s `cn` only); None until the file
    /// is here.
    domestic: RwLock<Option<Arc<GeositeDB>>>,
    cache: Mutex<HashMap<CacheKey, (Vec<u8>, Instant)>>,
    pub stats: Stats,
}

/// `223.5.5.5` / `223.5.5.5:53` → a socket address; None when invalid.
pub fn upstream_addr(s: &str) -> Option<SocketAddr> {
    let s = s.trim();
    s.parse::<SocketAddr>().ok().or_else(|| {
        s.parse::<Ipv4Addr>()
            .ok()
            .map(|ip| SocketAddr::from((ip, 53)))
    })
}

impl Front {
    /// A front asking `upstreams` for real answers.
    pub fn new(upstreams: &[String]) -> Self {
        let f = Self {
            upstreams: RwLock::new(Vec::new()),
            core: RwLock::new(None),
            hosts: RwLock::new(Vec::new()),
            line: RwLock::new(None),
            domestic: RwLock::new(None),
            cache: Mutex::new(HashMap::new()),
            stats: Stats::default(),
        };
        f.set_upstreams(upstreams);
        f
    }

    /// Replaces the upstreams (invalid entries dropped; none valid → the
    /// defaults). Clears the cache.
    pub fn set_upstreams(&self, list: &[String]) {
        let mut v: Vec<SocketAddr> = list.iter().filter_map(|s| upstream_addr(s)).collect();
        if v.is_empty() {
            v = DEFAULT_UPSTREAMS
                .iter()
                .filter_map(|s| upstream_addr(s))
                .collect();
        }
        *self
            .upstreams
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = v;
        self.cache
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clear();
    }

    /// The upstreams in use.
    pub fn upstreams(&self) -> Vec<SocketAddr> {
        self.upstreams
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    /// Where the core's DNS listens (None: core down).
    pub fn set_core(&self, addr: Option<SocketAddr>) {
        *self
            .core
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = addr;
    }

    /// The hosts entries for real answers.
    pub fn set_hosts(&self, hosts: Vec<HostRule>) {
        *self
            .hosts
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = hosts;
        self.cache
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clear();
    }

    /// Where names off the domestic list are asked through a line (the
    /// core's SOCKS listener), None while there is no line. Clears the
    /// cache when it changes.
    pub fn set_line(&self, socks: Option<SocketAddr>) {
        let mut l = self
            .line
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if *l != socks {
            *l = socks;
            self.clear_cache();
        }
    }

    /// The domestic list (a geosite DB holding [`DOMESTIC_CATEGORY`]).
    /// Clears the cache.
    pub fn set_domestic(&self, db: Option<Arc<GeositeDB>>) {
        *self
            .domestic
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = db;
        self.clear_cache();
    }

    /// Whether the domestic list is loaded.
    pub fn has_domestic(&self) -> bool {
        self.domestic
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .is_some()
    }

    /// `name` is on the domestic list.
    fn is_domestic(&self, name: &str) -> bool {
        self.domestic
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .as_ref()
            .is_some_and(|db| db.lookup(DOMESTIC_CATEGORY, name))
    }

    fn clear_cache(&self) {
        self.cache
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clear();
    }

    /// The status page's view.
    pub fn status(&self) -> Value {
        let n = |a: &AtomicU64| a.load(Ordering::Relaxed);
        let s = &self.stats;
        json!({
            "queries": n(&s.queries),
            "cacheHits": n(&s.cache_hits),
            "viaCore": n(&s.via_core),
            "viaUpstream": n(&s.via_upstream),
            "viaLine": n(&s.via_line),
            "hosts": n(&s.hosts),
            "failed": n(&s.failed),
            "upstreams": self.upstreams().iter().map(ToString::to_string).collect::<Vec<_>>(),
            "throughLine": self.line.read().unwrap_or_else(std::sync::PoisonError::into_inner).is_some(),
            "domesticList": self.has_domestic(),
        })
    }

    /// The answer to `query`; `fake_ip`: the asker routes through the box.
    /// Always some answer for a well-formed query (SERVFAIL at worst);
    /// None for garbage.
    pub async fn answer(&self, query: &[u8], fake_ip: bool) -> Option<Vec<u8>> {
        let q = question(query)?;
        if query[2] & 0x80 != 0 {
            return None; // a response, not a query
        }
        self.stats.queries.fetch_add(1, Ordering::Relaxed);
        if fake_ip {
            let core = *self
                .core
                .read()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if let Some(core) = core {
                if let Ok(a) = udp_query(core, query, CORE_TIMEOUT).await {
                    self.stats.via_core.fetch_add(1, Ordering::Relaxed);
                    return Some(a);
                }
            }
        }
        Some(cap_ttl(self.real(query, &q).await, REAL_TTL))
    }

    /// A real answer: hosts, cache, then a line (names off the domestic
    /// list) or the domestic upstreams. SERVFAIL when nothing answered.
    async fn real(&self, query: &[u8], q: &Question) -> Vec<u8> {
        if let Some(ip) = self.host(&q.name) {
            self.stats.hosts.fetch_add(1, Ordering::Relaxed);
            return answer_a(query, q, ip);
        }
        let key = (q.name.clone(), q.qtype, q.qclass);
        if let Some(hit) = self.cached(&key) {
            self.stats.cache_hits.fetch_add(1, Ordering::Relaxed);
            return with_id(hit, query);
        }
        let line = *self
            .line
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let line = line.filter(|_| !self.is_domestic(&q.name));
        if let Some(socks) = line {
            if let Some(a) = line_query(socks, query).await {
                self.stats.via_line.fetch_add(1, Ordering::Relaxed);
                if let Some(ttl) = cache_ttl(&a) {
                    self.store(key, a.clone(), ttl);
                }
                return a;
            }
        }
        for up in self.upstreams() {
            let Ok(mut a) = udp_query(up, query, UPSTREAM_TIMEOUT).await else {
                continue;
            };
            if a.len() > 2 && a[2] & 0x02 != 0 {
                if let Ok(full) = tcp_query(up, query, UPSTREAM_TIMEOUT).await {
                    a = full;
                }
            }
            self.stats.via_upstream.fetch_add(1, Ordering::Relaxed);
            // A foreign name the line could not answer: possibly poisoned,
            // so not kept (the next query tries the line again).
            if line.is_none() {
                if let Some(ttl) = cache_ttl(&a) {
                    self.store(key, a.clone(), ttl);
                }
            }
            return a;
        }
        self.stats.failed.fetch_add(1, Ordering::Relaxed);
        servfail(query, q)
    }

    fn host(&self, name: &str) -> Option<Ipv4Addr> {
        self.hosts
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .iter()
            .find(|h| h.matches(name))
            .map(|h| h.ip)
    }

    fn cached(&self, key: &CacheKey) -> Option<Vec<u8>> {
        let c = self
            .cache
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        c.get(key)
            .filter(|(_, until)| *until > Instant::now())
            .map(|(a, _)| a.clone())
    }

    fn store(&self, key: CacheKey, answer: Vec<u8>, ttl: u32) {
        if ttl == 0 {
            return;
        }
        let mut c = self
            .cache
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if c.len() >= CACHE_MAX {
            let now = Instant::now();
            c.retain(|_, (_, until)| *until > now);
            if c.len() >= CACHE_MAX {
                c.clear();
            }
        }
        c.insert(
            key,
            (answer, Instant::now() + Duration::from_secs(ttl.into())),
        );
    }
}

/// One query over UDP; the answer whose id matches.
async fn udp_query(to: SocketAddr, query: &[u8], wait: Duration) -> std::io::Result<Vec<u8>> {
    let bind: SocketAddr = if to.is_ipv4() {
        (Ipv4Addr::UNSPECIFIED, 0).into()
    } else {
        (std::net::Ipv6Addr::UNSPECIFIED, 0).into()
    };
    let sock = UdpSocket::bind(bind).await?;
    sock.connect(to).await?;
    sock.send(query).await?;
    let mut buf = vec![0u8; 65535];
    tokio::time::timeout(wait, async {
        loop {
            let n = sock.recv(&mut buf).await?;
            if n >= 12 && buf[..2] == query[..2] {
                return Ok(buf[..n].to_vec());
            }
        }
    })
    .await
    .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "dns timeout"))?
}

/// One query over TCP (length-prefixed).
async fn tcp_query(to: SocketAddr, query: &[u8], wait: Duration) -> std::io::Result<Vec<u8>> {
    tokio::time::timeout(wait, async {
        let mut s = TcpStream::connect(to).await?;
        tcp_exchange(&mut s, query).await
    })
    .await
    .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "dns timeout"))?
}

/// One length-prefixed query and its answer on `s`.
async fn tcp_exchange(s: &mut TcpStream, query: &[u8]) -> std::io::Result<Vec<u8>> {
    let len = u16::try_from(query.len()).unwrap_or(u16::MAX);
    let mut out = len.to_be_bytes().to_vec();
    out.extend_from_slice(query);
    s.write_all(&out).await?;
    let mut l = [0u8; 2];
    s.read_exact(&mut l).await?;
    let mut a = vec![0u8; usize::from(u16::from_be_bytes(l))];
    s.read_exact(&mut a).await?;
    if a.len() < 12 || a[..2] != query[..2] {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "not the answer to the query",
        ));
    }
    Ok(a)
}

/// `query` asked of [`FOREIGN_UPSTREAMS`] through the SOCKS listener
/// `socks` (all at once, the first answer wins); None when none answered
/// within [`LINE_TIMEOUT`].
async fn line_query(socks: SocketAddr, query: &[u8]) -> Option<Vec<u8>> {
    let mut asks = tokio::task::JoinSet::new();
    for up in FOREIGN_UPSTREAMS {
        let query = query.to_vec();
        asks.spawn(async move { socks_query(socks, up, &query).await });
    }
    tokio::time::timeout(LINE_TIMEOUT, async {
        while let Some(r) = asks.join_next().await {
            if let Ok(Ok(a)) = r {
                return Some(a);
            }
        }
        None
    })
    .await
    .ok()
    .flatten()
    // Dropping the set aborts the slower asks.
}

/// One query over TCP to `to` through the SOCKS5 server `socks` (no
/// authentication: the core's listener on 127.0.0.1).
async fn socks_query(
    socks: SocketAddr,
    to: SocketAddrV4,
    query: &[u8],
) -> std::io::Result<Vec<u8>> {
    let bad = |what: &str| std::io::Error::other(format!("socks: {what}"));
    let mut s = TcpStream::connect(socks).await?;
    s.write_all(&[5, 1, 0]).await?;
    let mut hello = [0u8; 2];
    s.read_exact(&mut hello).await?;
    if hello != [5, 0] {
        return Err(bad("refused the no-auth method"));
    }
    let mut connect = vec![5, 1, 0, 1];
    connect.extend_from_slice(&to.ip().octets());
    connect.extend_from_slice(&to.port().to_be_bytes());
    s.write_all(&connect).await?;
    let mut head = [0u8; 4];
    s.read_exact(&mut head).await?;
    if head[1] != 0 {
        return Err(bad("connect failed"));
    }
    // The bound address that follows: IPv4, IPv6 or a name, then a port.
    let rest = match head[3] {
        1 => 4 + 2,
        4 => 16 + 2,
        3 => {
            let mut n = [0u8; 1];
            s.read_exact(&mut n).await?;
            usize::from(n[0]) + 2
        }
        _ => return Err(bad("unknown address type")),
    };
    let mut skip = vec![0u8; rest];
    s.read_exact(&mut skip).await?;
    tcp_exchange(&mut s, query).await
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// A query for `name` / `qtype` with id 0x1234.
    pub(crate) fn query(name: &str, qtype: u16) -> Vec<u8> {
        let mut m = vec![0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
        for l in name.split('.') {
            m.push(l.len() as u8);
            m.extend_from_slice(l.as_bytes());
        }
        m.push(0);
        m.extend_from_slice(&qtype.to_be_bytes());
        m.extend_from_slice(&1u16.to_be_bytes());
        m
    }

    /// An answer to `q` with A records of the given TTLs.
    fn answer(q: &[u8], ttls: &[u32]) -> Vec<u8> {
        let mut m = q.to_vec();
        m[2] = 0x81;
        m[3] = 0x80;
        m[6..8].copy_from_slice(&(ttls.len() as u16).to_be_bytes());
        for t in ttls {
            m.extend_from_slice(&[0xc0, 12, 0, 1, 0, 1]);
            m.extend_from_slice(&t.to_be_bytes());
            m.extend_from_slice(&[0, 4, 1, 2, 3, 4]);
        }
        m
    }

    #[test]
    fn question_is_parsed_lowercase() {
        let q = question(&query("WWW.Example.com", 28)).unwrap();
        assert_eq!(
            (q.name.as_str(), q.qtype, q.qclass),
            ("www.example.com", 28, 1)
        );
        assert_eq!(q.end, query("www.example.com", 28).len());
        assert!(question(&[0; 5]).is_none());
        let mut bad = query("a.b", 1);
        bad[12] = 0xc0;
        assert!(question(&bad).is_none());
        let mut cut = query("abc.def", 1);
        cut.truncate(16);
        assert!(question(&cut).is_none());
    }

    #[test]
    fn cache_ttl_takes_the_smallest_and_caps() {
        let q = query("a.cn", 1);
        assert_eq!(cache_ttl(&answer(&q, &[300, 120])), Some(120));
        assert_eq!(cache_ttl(&answer(&q, &[86400])), Some(CACHE_MAX_TTL));
        assert_eq!(cache_ttl(&answer(&q, &[])), Some(NEGATIVE_TTL), "no data");
        let mut nx = answer(&q, &[]);
        nx[3] = 0x83;
        assert_eq!(cache_ttl(&nx), Some(NEGATIVE_TTL));
        let mut fail = answer(&q, &[300]);
        fail[3] = 0x82;
        assert_eq!(cache_ttl(&fail), None, "SERVFAIL is not kept");
        let mut tc = answer(&q, &[300]);
        tc[2] |= 0x02;
        assert_eq!(cache_ttl(&tc), None, "truncated is not kept");
    }

    #[test]
    fn truncate_keeps_the_question_and_sets_tc() {
        let q = query("a.cn", 1);
        let big = answer(&q, &[60; 200]);
        assert_eq!(truncate(big.clone(), 4096), big);
        let t = truncate(big, 512);
        assert_eq!(t.len(), q.len());
        assert_ne!(t[2] & 0x02, 0);
        assert_eq!(question(&t).unwrap().name, "a.cn");
        assert_eq!(&t[6..12], &[0; 6]);
    }

    #[test]
    fn hosts_answers() {
        let cfg = serde_json::json!([
            {"type": "exact", "value": "nas.home", "address": "192.168.1.10"},
            {"type": "suffix", "value": "weiba.pp.ua", "address": "192.168.1.20"},
            {"type": "keyword", "value": "direct-me"},
            {"type": "regex", "value": ".*", "address": "1.1.1.1"},
            {"type": "wildcard", "value": "*.lan", "address": "192.168.1.30"},
        ]);
        let rules = HostRule::from_config(Some(&cfg));
        assert_eq!(rules.len(), 3);
        let f = Front::new(&[]);
        f.set_hosts(rules);
        assert_eq!(f.host("nas.home"), Some(Ipv4Addr::new(192, 168, 1, 10)));
        assert_eq!(
            f.host("a.weiba.pp.ua"),
            Some(Ipv4Addr::new(192, 168, 1, 20))
        );
        assert_eq!(f.host("weiba.pp.ua"), Some(Ipv4Addr::new(192, 168, 1, 20)));
        assert_eq!(f.host("xweiba.pp.ua"), None);
        assert_eq!(f.host("printer.lan"), Some(Ipv4Addr::new(192, 168, 1, 30)));
        assert_eq!(f.host("example.com"), None);

        let q = query("nas.home", 1);
        let a = answer_a(&q, &question(&q).unwrap(), Ipv4Addr::new(192, 168, 1, 10));
        assert_eq!(&a[..2], &[0x12, 0x34]);
        assert_eq!(a[2] & 0x80, 0x80);
        assert_eq!(u16::from_be_bytes([a[6], a[7]]), 1);
        assert_eq!(&a[a.len() - 4..], &[192, 168, 1, 10]);
        assert_eq!(cache_ttl(&a), Some(REAL_TTL));
        // AAAA for a hosts name: no data rather than a real lookup.
        let q6 = query("nas.home", 28);
        let a6 = answer_a(&q6, &question(&q6).unwrap(), Ipv4Addr::new(192, 168, 1, 10));
        assert_eq!(u16::from_be_bytes([a6[6], a6[7]]), 0);
    }

    #[test]
    fn upstreams_parse_and_fall_back_to_defaults() {
        assert_eq!(
            upstream_addr("223.5.5.5"),
            Some("223.5.5.5:53".parse().unwrap())
        );
        assert_eq!(
            upstream_addr("1.1.1.1:5353"),
            Some("1.1.1.1:5353".parse().unwrap())
        );
        assert_eq!(upstream_addr("dns.google"), None);
        let f = Front::new(&["junk".into()]);
        assert_eq!(f.upstreams().len(), 2);
        f.set_upstreams(&["8.8.8.8".into()]);
        assert_eq!(f.upstreams(), vec!["8.8.8.8:53".parse().unwrap()]);
    }

    #[test]
    fn real_answers_come_from_upstream_then_cache() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            // A local stand-in for the upstream and for the core.
            let up = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let core = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let up_addr = up.local_addr().unwrap();
            let core_addr = core.local_addr().unwrap();
            tokio::spawn(async move {
                let mut b = [0u8; 512];
                loop {
                    let (n, from) = up.recv_from(&mut b).await.unwrap();
                    let _ = up.send_to(&answer(&b[..n], &[300]), from).await;
                }
            });
            tokio::spawn(async move {
                let mut b = [0u8; 512];
                loop {
                    let (n, from) = core.recv_from(&mut b).await.unwrap();
                    let mut a = answer(&b[..n], &[1]);
                    let at = a.len() - 4;
                    a[at..].copy_from_slice(&[198, 18, 0, 5]);
                    let _ = core.send_to(&a, from).await;
                }
            });
            let f = Front::new(&[up_addr.to_string()]);
            f.set_core(Some(core_addr));
            let q = query("example.com", 1);
            let real = f.answer(&q, false).await.unwrap();
            assert_eq!(&real[real.len() - 4..], &[1, 2, 3, 4]);
            let mut q2 = q.clone();
            q2[0] = 0x55;
            let again = f.answer(&q2, false).await.unwrap();
            assert_eq!(again[0], 0x55, "cached answer carries the new id");
            assert_eq!(f.stats.cache_hits.load(Ordering::Relaxed), 1);
            let fake = f.answer(&q, true).await.unwrap();
            assert_eq!(&fake[fake.len() - 4..], &[198, 18, 0, 5]);
            assert_eq!(f.stats.via_core.load(Ordering::Relaxed), 1);
            // Core down: a gateway device still gets a (real) answer.
            f.set_core(None);
            let fallback = f.answer(&q, true).await.unwrap();
            assert_eq!(&fallback[fallback.len() - 4..], &[1, 2, 3, 4]);
            // Garbage and responses get nothing.
            assert!(f.answer(&[1, 2, 3], false).await.is_none());
            assert!(f.answer(&real, false).await.is_none());
            assert_eq!(f.status()["queries"], 4);
        });
    }

    /// The TTL fields of every record of `m` (OPT included).
    fn ttls(m: &[u8]) -> Vec<u32> {
        let count = |i: usize| usize::from(u16::from_be_bytes([m[i], m[i + 1]]));
        let mut at = skip_name(m, 12).unwrap() + 4;
        let mut out = Vec::new();
        for _ in 0..count(6) + count(8) + count(10) {
            at = skip_name(m, at).unwrap();
            out.push(u32::from_be_bytes([
                m[at + 4],
                m[at + 5],
                m[at + 6],
                m[at + 7],
            ]));
            at += 10 + usize::from(u16::from_be_bytes([m[at + 8], m[at + 9]]));
        }
        out
    }

    #[test]
    fn real_answers_get_a_short_ttl_and_opt_is_kept() {
        let q = query("a.cn", 1);
        let mut a = answer(&q, &[300, 5]);
        // An EDNS OPT record (root name, type 41, "TTL" = flags).
        a[11] = 1;
        a.extend_from_slice(&[0, 0, 41, 0x10, 0, 0x00, 0x00, 0x80, 0x00, 0, 0]);
        let capped = cap_ttl(a.clone(), REAL_TTL);
        assert_eq!(ttls(&capped), vec![REAL_TTL, 5, 0x8000]);
        assert_eq!(capped.len(), a.len());
        // Malformed: left as it is.
        let mut cut = a;
        cut.truncate(cut.len() - 3);
        assert_eq!(cap_ttl(cut.clone(), 1), cut);
    }

    /// A SOCKS5 stand-in for the core: answers DNS over TCP itself with
    /// 9.9.9.9 (TTL 300) whatever the target, and counts the targets.
    async fn fake_line() -> (SocketAddr, Arc<Mutex<Vec<SocketAddrV4>>>) {
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        let seen = Arc::new(Mutex::new(Vec::new()));
        let log = Arc::clone(&seen);
        tokio::spawn(async move {
            loop {
                let (mut s, _) = l.accept().await.unwrap();
                let log = Arc::clone(&log);
                tokio::spawn(async move {
                    let mut b = [0u8; 3];
                    s.read_exact(&mut b).await.unwrap();
                    s.write_all(&[5, 0]).await.unwrap();
                    let mut c = [0u8; 10];
                    s.read_exact(&mut c).await.unwrap();
                    let to = SocketAddrV4::new(
                        Ipv4Addr::new(c[4], c[5], c[6], c[7]),
                        u16::from_be_bytes([c[8], c[9]]),
                    );
                    log.lock().unwrap().push(to);
                    s.write_all(&[5, 0, 0, 1, 127, 0, 0, 1, 0, 1])
                        .await
                        .unwrap();
                    let mut l = [0u8; 2];
                    s.read_exact(&mut l).await.unwrap();
                    let mut q = vec![0u8; usize::from(u16::from_be_bytes(l))];
                    s.read_exact(&mut q).await.unwrap();
                    let mut a = answer(&q, &[300]);
                    let at = a.len() - 4;
                    a[at..].copy_from_slice(&[9, 9, 9, 9]);
                    let mut out = u16::try_from(a.len()).unwrap().to_be_bytes().to_vec();
                    out.extend_from_slice(&a);
                    s.write_all(&out).await.unwrap();
                });
            }
        });
        (addr, seen)
    }

    /// A domestic upstream stand-in answering 1.2.3.4.
    async fn fake_upstream() -> SocketAddr {
        let up = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = up.local_addr().unwrap();
        tokio::spawn(async move {
            let mut b = [0u8; 512];
            loop {
                let (n, from) = up.recv_from(&mut b).await.unwrap();
                let _ = up.send_to(&answer(&b[..n], &[300]), from).await;
            }
        });
        addr
    }

    fn tail(a: &[u8]) -> [u8; 4] {
        a[a.len() - 4..].try_into().unwrap()
    }

    #[test]
    fn foreign_names_go_through_a_line_domestic_ones_do_not() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let up = fake_upstream().await;
            let (line, seen) = fake_line().await;
            let f = Front::new(&[up.to_string()]);
            let mut db = GeositeDB::empty();
            db.insert(DOMESTIC_CATEGORY, "+.baidu.com");
            f.set_domestic(Some(Arc::new(db)));
            // No line yet: everything from the domestic upstreams.
            let g = f.answer(&query("www.google.com", 1), false).await.unwrap();
            assert_eq!(tail(&g), [1, 2, 3, 4]);
            assert_eq!(ttls(&g), vec![REAL_TTL], "short TTL to the device");
            f.set_line(Some(line));
            let g = f.answer(&query("www.google.com", 1), false).await.unwrap();
            assert_eq!(
                tail(&g),
                [9, 9, 9, 9],
                "through the line, not cached domestic"
            );
            assert_eq!(ttls(&g), vec![REAL_TTL]);
            let b = f.answer(&query("www.baidu.com", 1), false).await.unwrap();
            assert_eq!(tail(&b), [1, 2, 3, 4], "domestic name");
            let mut targets = seen.lock().unwrap().clone();
            targets.sort();
            let mut want = FOREIGN_UPSTREAMS.to_vec();
            want.sort();
            assert!(targets.iter().all(|t| want.contains(t)) && !targets.is_empty());
            assert_eq!(f.stats.via_line.load(Ordering::Relaxed), 1);
            // Cached with the line's TTL, still short to the device.
            let again = f.answer(&query("www.google.com", 1), false).await.unwrap();
            assert_eq!((tail(&again), ttls(&again)), ([9, 9, 9, 9], vec![REAL_TTL]));
            assert_eq!(f.stats.cache_hits.load(Ordering::Relaxed), 1);
            assert_eq!(f.status()["viaLine"], 1);
            assert_eq!(f.status()["domesticList"], true);
        });
    }

    #[test]
    fn a_dead_line_falls_back_without_caching() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let up = fake_upstream().await;
            // A port nobody listens on: the connection is refused.
            let dead = {
                let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
                l.local_addr().unwrap()
            };
            let f = Front::new(&[up.to_string()]);
            f.set_line(Some(dead));
            let a = f.answer(&query("www.google.com", 1), false).await.unwrap();
            assert_eq!(tail(&a), [1, 2, 3, 4]);
            let b = f.answer(&query("www.google.com", 1), false).await.unwrap();
            assert_eq!(tail(&b), [1, 2, 3, 4]);
            assert_eq!(f.stats.cache_hits.load(Ordering::Relaxed), 0, "not kept");
            assert_eq!(f.stats.via_upstream.load(Ordering::Relaxed), 2);
            // Without the line, the same answer is kept.
            f.set_line(None);
            f.answer(&query("www.google.com", 1), false).await.unwrap();
            f.answer(&query("www.google.com", 1), false).await.unwrap();
            assert_eq!(f.stats.cache_hits.load(Ordering::Relaxed), 1);
        });
    }

    #[test]
    fn nothing_reachable_is_servfail() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            // A bound socket that never answers.
            let silent = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let f = Front::new(&[silent.local_addr().unwrap().to_string()]);
            tokio::time::pause();
            let q = query("x.cn", 1);
            let a = f.answer(&q, false).await.unwrap();
            assert_eq!(a[3] & 0x0f, 2);
            assert_eq!(f.stats.failed.load(Ordering::Relaxed), 1);
        });
    }
}
