//! `smart` group: per website, the line that actually works best.
//!
//! - New sites race the three most promising lines (different exits where
//!   known); the winner serves, the others still report how fast they were.
//! - Known sites use their best line alone; now and then a challenger gets
//!   a chance (exploration).
//! - Sites of one company keep one exit for a while (risk control); a
//!   failing exit hands over to a line on the same address, then the same
//!   country, before anything else.
//! - `strategy: consistent-hashing` (多点负载): sites spread over the
//!   healthy lines, one site always on the same line.
//! - Lines that fail three times in a row sit out five minutes ("ban box")
//!   and come back only after a probe passes. When every line is out, the
//!   connection is refused — never sent around the proxy.
//!
//! Ideas from PaoPao's Go core (and mihomo's Smart group); our own code.

mod family;
mod metered;
pub mod stats;

use std::path::PathBuf;
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::{Arc, Weak};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use meow_common::{
    AdapterType, ConnType, DelayHistory, MeowError, Metadata, Network, Proxy, ProxyAdapter,
    ProxyConn, ProxyHealth, ProxyPacketConn, Result,
};
use parking_lot::RwLock;
use smol_str::SmolStr;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tracing::{debug, warn};

use self::metered::MeteredConn;
use self::stats::{site_key, Exit, Outcome, Store};
use super::UsageTracker;

const SINGLE_TIMEOUT: Duration = Duration::from_secs(5);
const RACE_TIMEOUT: Duration = Duration::from_secs(8);
const BATCH_SIZE: usize = 3;
const MAX_BATCHES: usize = 3;
const PROBE_TIMEOUT: Duration = Duration::from_secs(8);
const PROBE_CONCURRENCY: usize = 8;

/// Answers with the caller's address and country (`ip=…`, `loc=…`);
/// reachable through practically every line.
const TRACE_HOST: &str = "www.cloudflare.com";

pub struct SmartGroup {
    shared: Arc<Shared>,
}

struct Shared {
    name: SmolStr,
    members: Vec<Arc<dyn Proxy>>,
    store: Store,
    test_url: String,
    /// The line used last (what the API shows as `now`).
    now: RwLock<Option<SmolStr>>,
    health: ProxyHealth,
    usage: UsageTracker,
    /// Unix nanos of the last all-banned re-probe.
    reprobe: AtomicI64,
}

impl Drop for Shared {
    fn drop(&mut self) {
        if let Err(e) = self.store.save() {
            warn!("{}: saving smart records: {e}", self.name);
        }
    }
}

/// Where a group's records live: `<home>/smart-<name>.json`.
fn store_path(name: &str) -> PathBuf {
    let safe: String = name
        .chars()
        .map(|c| {
            if c.is_alphanumeric() || c == '-' {
                c
            } else {
                '_'
            }
        })
        .collect();
    meow_common::home_dir::resolved_home_dir().join(format!("smart-{safe}.json"))
}

impl SmartGroup {
    /// `balance`: spread new sites over the healthy lines (多点负载).
    /// `persist`: keep what was learnt across restarts.
    pub fn new(
        name: &str,
        members: Vec<Arc<dyn Proxy>>,
        test_url: String,
        balance: bool,
        persist: bool,
    ) -> Self {
        let store = Store::new(persist.then(|| store_path(name)));
        Self::with_store(name, members, test_url, balance, store)
    }

    fn with_store(
        name: &str,
        members: Vec<Arc<dyn Proxy>>,
        test_url: String,
        balance: bool,
        store: Store,
    ) -> Self {
        store.set_balance(balance);
        let shared = Arc::new(Shared {
            name: SmolStr::from(name),
            members,
            store,
            test_url,
            now: RwLock::new(None),
            health: ProxyHealth::new(),
            usage: UsageTracker::new(),
            reprobe: AtomicI64::new(0),
        });
        // Background upkeep; it ends once the group is dropped (reload).
        if let Ok(rt) = tokio::runtime::Handle::try_current() {
            rt.spawn(upkeep(Arc::downgrade(&shared)));
        }
        Self { shared }
    }

    /// What is known about `site` (the app's "this site uses …").
    pub fn snapshot(&self, host: &str) -> std::collections::HashMap<String, stats::Record> {
        self.shared.store.snapshot(&site_key(host))
    }

    /// Lines sitting out now, with when they may come back (unix seconds).
    pub fn bans(&self) -> std::collections::HashMap<String, i64> {
        self.shared.store.bans()
    }
}

impl Shared {
    fn member(&self, name: &str) -> Option<&Arc<dyn Proxy>> {
        self.members.iter().find(|p| p.name() == name)
    }

    fn names(&self) -> Vec<String> {
        self.members.iter().map(|p| p.name().to_string()).collect()
    }

    /// Members that carry `network`, not sitting out a ban.
    fn candidates(&self, udp: bool) -> Vec<String> {
        let capable: Vec<String> = self
            .members
            .iter()
            .filter(|p| !udp || p.support_udp())
            .map(|p| p.name().to_string())
            .collect();
        self.store.free(&capable)
    }

    /// Every line is banned: refuse (never around the proxy, so the real
    /// address can't leak) and probe them at once — at most every 30 s —
    /// in case the network only blinked.
    fn no_line(self: &Arc<Self>) -> MeowError {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos() as i64);
        let last = self.reprobe.load(Ordering::Relaxed);
        if now - last > 30_000_000_000
            && self
                .reprobe
                .compare_exchange(last, now, Ordering::Relaxed, Ordering::Relaxed)
                .is_ok()
        {
            if let Ok(rt) = tokio::runtime::Handle::try_current() {
                let me = Arc::clone(self);
                rt.spawn(async move { me.probe(me.names()).await });
            }
        }
        MeowError::Proxy(format!(
            "{}: no line available (all lines failing)",
            self.name
        ))
    }

    /// Gives `lines` an overall record (and their exit) so the first visit
    /// to a new site already prefers lines that answer at all.
    async fn probe(self: &Arc<Self>, lines: Vec<String>) {
        let sem = Arc::new(tokio::sync::Semaphore::new(PROBE_CONCURRENCY));
        let mut tasks = Vec::new();
        for line in lines {
            let Some(p) = self.member(&line).cloned() else {
                continue;
            };
            let me = Arc::clone(self);
            let sem = Arc::clone(&sem);
            tasks.push(tokio::spawn(async move {
                let Ok(_permit) = sem.acquire().await else {
                    return;
                };
                let start = Instant::now();
                // Where the line exits (and how fast it answers), in one go.
                match tokio::time::timeout(PROBE_TIMEOUT, probe_exit(p.as_ref())).await {
                    Ok(Ok(exit)) => {
                        me.store.set_exit(&line, exit);
                        me.store.report(
                            "",
                            &line,
                            &Outcome {
                                first_ms: start.elapsed().as_secs_f64() * 1000.0,
                                ..Outcome::default()
                            },
                        );
                    }
                    _ => {
                        let r =
                            crate::health::url_test(p.as_ref(), &me.test_url, None, PROBE_TIMEOUT)
                                .await;
                        me.store.report(
                            "",
                            &line,
                            &Outcome {
                                failed: r.is_err(),
                                first_ms: r.map_or(0.0, f64::from),
                                ..Outcome::default()
                            },
                        );
                    }
                }
            }));
        }
        for t in tasks {
            let _ = t.await;
        }
    }

    /// Dials `lines` at once; the first to connect wins, the others still
    /// teach the store how fast they were (until the timeout).
    async fn race(
        self: &Arc<Self>,
        site: &str,
        metadata: &Metadata,
        lines: &[String],
        timeout: Duration,
    ) -> std::result::Result<(String, Box<dyn ProxyConn>, Duration), MeowError> {
        let (tx, mut rx) = tokio::sync::mpsc::channel(lines.len().max(1));
        for line in lines {
            let Some(p) = self.member(line).cloned() else {
                continue;
            };
            let tx = tx.clone();
            let meta = metadata.clone();
            let line = line.clone();
            tokio::spawn(async move {
                let start = Instant::now();
                let r = tokio::time::timeout(timeout, p.dial_tcp(&meta)).await;
                let _ = tx.send((line, r, start.elapsed())).await;
            });
        }
        drop(tx);
        let mut errs = Vec::new();
        while let Some((line, r, took)) = rx.recv().await {
            match r {
                Ok(Ok(conn)) => {
                    // The losers keep going in the background and report.
                    let me = Arc::clone(self);
                    let site = site.to_string();
                    tokio::spawn(async move {
                        while let Some((line, r, took)) = rx.recv().await {
                            match r {
                                Ok(Ok(c)) => {
                                    drop(c);
                                    me.store.report(
                                        &site,
                                        &line,
                                        &Outcome {
                                            connect_ms: took.as_secs_f64() * 1000.0,
                                            ..Outcome::default()
                                        },
                                    );
                                }
                                Ok(Err(_)) => me.store.report(
                                    &site,
                                    &line,
                                    &Outcome {
                                        failed: true,
                                        ..Outcome::default()
                                    },
                                ),
                                // Slower than the timeout: says nothing new.
                                Err(_) => {}
                            }
                        }
                    });
                    return Ok((line, conn, took));
                }
                Ok(Err(e)) => {
                    self.store.report(
                        site,
                        &line,
                        &Outcome {
                            failed: true,
                            connect_ms: took.as_secs_f64() * 1000.0,
                            ..Outcome::default()
                        },
                    );
                    debug!("{}: {line} failed for {site}: {e}", self.name);
                    errs.push(format!("{line}: {e}"));
                }
                Err(_) => {
                    self.store.report(
                        site,
                        &line,
                        &Outcome {
                            failed: true,
                            ..Outcome::default()
                        },
                    );
                    errs.push(format!("{line}: timeout"));
                }
            }
        }
        Err(MeowError::Proxy(errs.join("; ")))
    }
}

/// Starts by probing every line, then: every minute lines whose ban is up
/// are probed (passing ones come back), every ten minutes the lines that
/// matter are re-probed, every two minutes the records are saved.
async fn upkeep(weak: Weak<Shared>) {
    if let Some(me) = weak.upgrade() {
        me.probe(me.names()).await;
    }
    let mut tick = tokio::time::interval(Duration::from_secs(60));
    tick.tick().await;
    let mut n: u64 = 0;
    loop {
        tick.tick().await;
        n += 1;
        let Some(me) = weak.upgrade() else {
            return;
        };
        let due = me.store.due(&me.names());
        if !due.is_empty() {
            me.probe(due).await;
        }
        if n.is_multiple_of(10) {
            let lines = me.store.refresh_candidates(&me.names(), 12);
            me.probe(lines).await;
        }
        if n.is_multiple_of(2) {
            if let Err(e) = me.store.save() {
                warn!("{}: saving smart records: {e}", me.name);
            }
        }
    }
}

/// Asks through `proxy` where its traffic leaves to the internet.
async fn probe_exit(proxy: &dyn Proxy) -> std::io::Result<Exit> {
    let meta = Metadata {
        network: Network::Tcp,
        conn_type: ConnType::Tunnel,
        host: TRACE_HOST.into(),
        dst_port: 80,
        ..Default::default()
    };
    let mut conn = proxy
        .dial_tcp(&meta)
        .await
        .map_err(|e| std::io::Error::other(e.to_string()))?;
    conn.write_all(
        format!(
            "GET /cdn-cgi/trace HTTP/1.1\r\nHost: {TRACE_HOST}\r\nUser-Agent: paopao\r\nConnection: close\r\n\r\n"
        )
        .as_bytes(),
    )
    .await?;
    let mut body = Vec::with_capacity(1024);
    let mut buf = [0u8; 1024];
    while body.len() < 8192 {
        let n = conn.read(&mut buf).await?;
        if n == 0 {
            break;
        }
        body.extend_from_slice(&buf[..n]);
    }
    parse_trace(&String::from_utf8_lossy(&body))
        .ok_or_else(|| std::io::Error::other("no ip in trace"))
}

/// `ip=…` / `loc=…` lines of Cloudflare's trace.
pub fn parse_trace(body: &str) -> Option<Exit> {
    let mut e = Exit::default();
    for line in body.lines() {
        match line.trim().split_once('=') {
            Some(("ip", v)) => e.ip = v.to_string(),
            Some(("loc", v)) => e.country = v.to_string(),
            _ => {}
        }
    }
    (!e.ip.is_empty()).then_some(e)
}

fn site_of(metadata: &Metadata) -> String {
    let host = if metadata.host.is_empty() {
        metadata.dst_ip.map(|ip| ip.to_string()).unwrap_or_default()
    } else {
        metadata.host.to_string()
    };
    site_key(&host)
}

#[async_trait]
impl ProxyAdapter for SmartGroup {
    fn name(&self) -> &str {
        &self.shared.name
    }

    fn adapter_type(&self) -> AdapterType {
        AdapterType::Smart
    }

    fn addr(&self) -> &str {
        ""
    }

    fn support_udp(&self) -> bool {
        self.shared.members.iter().any(|p| p.support_udp())
    }

    async fn dial_tcp(&self, metadata: &Metadata) -> Result<Box<dyn ProxyConn>> {
        let me = &self.shared;
        me.usage.touch_user_traffic(metadata);
        let site = site_of(metadata);
        let plan = me.store.plan(&site, &me.candidates(false));
        if plan.lines.is_empty() {
            return Err(me.no_line());
        }
        let mut errs = Vec::new();
        let mut lines: &[String] = &plan.lines;
        let mut size = plan.race.max(1);
        // A site with an exit sees one address at a time, same exit first.
        let batches = if plan.pinned {
            lines.len()
        } else {
            MAX_BATCHES
        };
        for _ in 0..batches {
            if lines.is_empty() {
                break;
            }
            let n = size.min(lines.len());
            let timeout = if n == 1 { SINGLE_TIMEOUT } else { RACE_TIMEOUT };
            match me.race(&site, metadata, &lines[..n], timeout).await {
                Ok((line, conn, connect)) => {
                    *me.now.write() = Some(SmolStr::from(line.as_str()));
                    me.store.use_line(&site, &line);
                    let store_owner = Arc::clone(me);
                    return Ok(Box::new(MeteredConn::new(conn, connect, move |r| {
                        store_owner.store.report(&site, &line, &r);
                    })));
                }
                Err(e) => errs.push(e.to_string()),
            }
            lines = &lines[n..];
            if !plan.pinned {
                size = BATCH_SIZE;
            }
        }
        Err(MeowError::Proxy(format!(
            "{}: all lines failed for {site}: {}",
            me.name,
            errs.join("; ")
        )))
    }

    async fn dial_udp(&self, metadata: &Metadata) -> Result<Box<dyn ProxyPacketConn>> {
        let me = &self.shared;
        me.usage.touch_user_traffic(metadata);
        let site = site_of(metadata);
        let plan = me.store.plan(&site, &me.candidates(true));
        if plan.lines.is_empty() {
            return Err(me.no_line());
        }
        let mut errs = Vec::new();
        for line in plan.lines.iter().take(BATCH_SIZE * MAX_BATCHES) {
            let Some(p) = me.member(line) else {
                continue;
            };
            let start = Instant::now();
            match p.dial_udp(metadata).await {
                Ok(pc) => {
                    *me.now.write() = Some(SmolStr::from(line.as_str()));
                    me.store.report(
                        &site,
                        line,
                        &Outcome {
                            connect_ms: start.elapsed().as_secs_f64() * 1000.0,
                            ..Outcome::default()
                        },
                    );
                    return Ok(pc);
                }
                Err(e) => {
                    me.store.report(
                        &site,
                        line,
                        &Outcome {
                            failed: true,
                            ..Outcome::default()
                        },
                    );
                    errs.push(format!("{line}: {e}"));
                }
            }
        }
        Err(MeowError::Proxy(errs.join("; ")))
    }

    fn unwrap_proxy(&self, metadata: &Metadata, touch: bool) -> Option<Arc<dyn Proxy>> {
        if touch {
            self.shared.usage.touch_user_traffic(metadata);
        }
        let me = &self.shared;
        let line = me.store.peek(&site_of(metadata), &me.candidates(false))?;
        me.member(&line).cloned()
    }

    fn health(&self) -> &ProxyHealth {
        &self.shared.health
    }
}

impl SmartGroup {
    fn current_proxy(&self) -> Option<Arc<dyn Proxy>> {
        let now = self.shared.now.read().clone();
        now.and_then(|n| self.shared.member(&n).cloned())
            .or_else(|| self.shared.members.first().cloned())
    }
}

impl Proxy for SmartGroup {
    fn alive(&self) -> bool {
        self.shared.health.alive() && !self.shared.candidates(false).is_empty()
    }

    fn alive_for_url(&self, _url: &str) -> bool {
        self.alive()
    }

    fn last_delay(&self) -> u16 {
        self.current_proxy().map_or(0, |p| p.last_delay())
    }

    fn last_delay_for_url(&self, url: &str) -> u16 {
        self.current_proxy()
            .map_or(0, |p| p.last_delay_for_url(url))
    }

    fn delay_history(&self) -> Vec<DelayHistory> {
        self.current_proxy()
            .map(|p| p.delay_history())
            .unwrap_or_default()
    }

    fn members(&self) -> Option<Vec<String>> {
        Some(self.shared.names())
    }

    fn member_proxies(&self) -> Option<Vec<Arc<dyn Proxy>>> {
        Some(self.shared.members.clone())
    }

    fn current(&self) -> Option<String> {
        self.current_proxy().map(|p| p.name().to_string())
    }

    fn test_url(&self) -> Option<&str> {
        Some(&self.shared.test_url)
    }

    fn usage_generation(&self) -> u64 {
        self.shared.usage.generation()
    }

    fn as_any(&self) -> Option<&dyn std::any::Any> {
        Some(self)
    }
}

#[cfg(test)]
mod tests;
