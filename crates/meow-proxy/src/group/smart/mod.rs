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
//! - A single dial that hasn't connected after [`HEDGE_AFTER`] gets a second
//!   line (another exit) alongside; the first to connect serves, all
//!   within the caller's dial deadline.
//! - A download crawling below 200 KiB/s (or stalling) marks its line slow
//!   for that site ten minutes: the site's next connections go to another
//!   line, and a few others get a short speed test.
//!
//! Ideas from PaoPao's Go core (and mihomo's Smart group); our own code.

mod family;
mod load;
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
use tokio::sync::{watch, Semaphore};
use tracing::{debug, info, warn};

use self::load::Loads;
use self::metered::{is_video_site, Cut, Live, MeteredConn, VIDEO_SLOW_BPS};
use self::stats::{site_key, Exit, Outcome, Store};
use super::UsageTracker;

const SINGLE_TIMEOUT: Duration = Duration::from_secs(5);
const RACE_TIMEOUT: Duration = Duration::from_secs(8);
const BATCH_SIZE: usize = 3;
const MAX_BATCHES: usize = 3;
const PROBE_TIMEOUT: Duration = Duration::from_secs(8);
const PROBE_CONCURRENCY: usize = 8;
/// A single dial not connected by now gets a second line alongside.
const HEDGE_AFTER: Duration = Duration::from_millis(1500);
/// Ends our dial this much before the caller's deadline, so the caller
/// hears our answer rather than its own timeout.
const DEADLINE_MARGIN: Duration = Duration::from_millis(200);
/// Lines speed-tested when a site's line turned out slow.
const SPEED_PROBE_LINES: usize = 3;
/// Speed tests running at once, per group.
const SPEED_PROBE_CONCURRENCY: usize = 2;
/// One speed test reads at most this much …
const SPEED_PROBE_BYTES: u64 = 2 << 20;
/// … for at most this long.
const SPEED_PROBE_TIME: Duration = Duration::from_secs(8);
/// Large files served close to every line's exit, tried in order: the next
/// one when a server answers with an error status (moved, refused), not
/// when the line fails. Google's download CDN first (one hop from where
/// video comes from; long-lived paths, no redirects; several, should one
/// move); a GitHub raw file next (under 1 MB: a rougher figure);
/// Cloudflare's speed endpoint last: it answered 403 through many lines
/// and crawled through others.
const SPEED_URLS: &[&str] = &[
    "https://dl.google.com/chrome/mac/universal/stable/googlechrome.dmg",
    "https://dl.google.com/linux/direct/google-chrome-stable_current_amd64.deb",
    "https://dl.google.com/chrome/install/googlechromestandaloneenterprise64.msi",
    "https://dl.google.com/android/repository/platform-tools-latest-darwin.zip",
    "https://dl.google.com/android/repository/platform-tools-latest-linux.zip",
    "https://dl.google.com/go/go1.22.0.src.tar.gz",
    "https://raw.githubusercontent.com/torvalds/linux/master/MAINTAINERS",
    "https://speed.cloudflare.com/__down?bytes=2097152",
];
/// A faster line must be this many times the slow one before a video
/// stream is cut over to it.
const CUT_GAIN: f64 = 2.0;
/// A site's streams are cut at most once this often (no flapping).
const CUT_COOLDOWN: Duration = Duration::from_secs(180);

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
    /// How busy each line is now (received bytes per second).
    loads: Loads,
    /// Upkeep (probes, the load sampler) runs: from the first dial on.
    started: std::sync::atomic::AtomicBool,
    /// Where speed tests download from ([`SPEED_URLS`]).
    speed_urls: Vec<String>,
    /// Bounds the speed tests running at once.
    speed_tests: Arc<Semaphore>,
    /// `strategy: sticky` (PaoPao): every site shares one line, so a
    /// service and its helpers (sign-in, captcha, telemetry) see one exit.
    sticky: std::sync::atomic::AtomicBool,
    /// Running video streams (site, line) that may be cut over.
    streams: parking_lot::Mutex<Vec<(String, String, Weak<Cut>)>>,
    /// When each site's streams were cut last.
    cut_at: parking_lot::Mutex<std::collections::HashMap<String, Instant>>,
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
            loads: Loads::default(),
            started: std::sync::atomic::AtomicBool::new(false),
            speed_urls: SPEED_URLS.iter().map(|u| u.to_string()).collect(),
            speed_tests: Arc::new(Semaphore::new(SPEED_PROBE_CONCURRENCY)),
            sticky: std::sync::atomic::AtomicBool::new(false),
            streams: parking_lot::Mutex::new(Vec::new()),
            cut_at: parking_lot::Mutex::new(std::collections::HashMap::new()),
        });
        Self { shared }
    }

    /// 固定出口: one line for every site of the group (AI services: the
    /// page, its sign-in, its captcha and its telemetry from one address);
    /// it moves only when that line fails or turns slow.
    pub fn sticky(self) -> Self {
        self.shared.sticky.store(true, Ordering::Relaxed);
        self
    }

    /// 速度最快: always the line seen fastest on real downloads.
    pub fn fastest(self) -> Self {
        self.shared.store.set_fastest(true);
        self
    }

    /// What is known about `site` (the app's "this site uses …").
    pub fn snapshot(&self, host: &str) -> std::collections::HashMap<String, stats::Record> {
        self.shared.store.snapshot(&site_key(host))
    }

    /// Lines sitting out now, with when they may come back (unix seconds).
    pub fn bans(&self) -> std::collections::HashMap<String, i64> {
        self.shared.store.bans()
    }

    /// Lines slow for `host`'s site now, with until when (unix seconds).
    pub fn slow(&self, host: &str) -> std::collections::HashMap<String, i64> {
        self.shared.store.slow(&site_key(host))
    }
}

impl Shared {
    /// Starts the background upkeep (probes every line, samples the loads)
    /// the first time the group is used: a config has many automatic
    /// groups, most never chosen, and probing all of them at start costs
    /// memory and connections for nothing. It ends once the group is
    /// dropped (reload).
    fn start(self: &Arc<Self>) {
        if self.started.swap(true, Ordering::Relaxed) {
            return;
        }
        if let Ok(rt) = tokio::runtime::Handle::try_current() {
            rt.spawn(upkeep(Arc::downgrade(self)));
            rt.spawn(sample_loads(Arc::downgrade(self)));
        }
    }

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

    /// Dials `lines` at once — and `hedge` too once they haven't connected
    /// after [`HEDGE_AFTER`] (at once if they all failed); the first to
    /// connect wins, the others still teach the store how fast they were
    /// (until `deadline`). A loser that was merely slower is no failure.
    async fn race(
        self: &Arc<Self>,
        site: &str,
        metadata: &Metadata,
        lines: &[String],
        hedge: Option<&str>,
        deadline: tokio::time::Instant,
    ) -> std::result::Result<(String, Box<dyn ProxyConn>, Duration), MeowError> {
        let (tx, mut rx) = tokio::sync::mpsc::channel(lines.len() + 1);
        let dial = |p: Arc<dyn Proxy>, line: String| {
            let tx = tx.clone();
            let meta = metadata.clone();
            async move {
                let start = Instant::now();
                let r = tokio::time::timeout_at(deadline, p.dial_tcp(&meta)).await;
                let _ = tx.send((line, r, start.elapsed())).await;
            }
        };
        let mut started = 0;
        for line in lines {
            if let Some(p) = self.member(line).cloned() {
                tokio::spawn(dial(p, line.clone()));
                started += 1;
            }
        }
        // The hedge waits: Some(true) = go now, Some(false) = not needed.
        let (go, mut wait) = watch::channel(None::<bool>);
        if let Some(p) = hedge.and_then(|h| self.member(h)).cloned() {
            let fut = dial(p, hedge.unwrap_or_default().to_string());
            let (name, site) = (self.name.clone(), site.to_string());
            let at = tokio::time::Instant::now() + HEDGE_AFTER;
            tokio::spawn(async move {
                tokio::select! {
                    _ = tokio::time::sleep_until(at) => {}
                    r = wait.wait_for(Option::is_some) => {
                        if !matches!(r.as_deref(), Ok(Some(true))) {
                            return;
                        }
                    }
                }
                debug!("{name}: hedging {site}");
                fut.await;
            });
        }
        drop(tx);
        let mut errs = Vec::new();
        let mut failed = 0;
        while let Some((line, r, took)) = rx.recv().await {
            match r {
                Ok(Ok(conn)) => {
                    let _ = go.send(Some(false));
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
                                // Slower than the deadline: says nothing new.
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
            failed += 1;
            if failed == started {
                // Everything planned failed: the hedge goes now.
                let _ = go.send(Some(true));
            }
        }
        Err(MeowError::Proxy(errs.join("; ")))
    }

    /// Reacts to how a running connection of `line` to `site` goes.
    fn live(self: &Arc<Self>, site: &str, line: &str, ev: Live) {
        match ev {
            Live::Sample { bytes, active_ms } => self.store.sample(site, line, bytes, active_ms),
            Live::Slow { rate } => self.slow_line(site, line, rate),
            Live::Stalled => self.slow_line(site, line, 0.0),
        }
    }

    /// `line` crawls on `site`: mark it, so the site's next connections go
    /// elsewhere, and speed-test a few others (once per cooldown).
    fn slow_line(self: &Arc<Self>, site: &str, line: &str, rate: f64) {
        if site.is_empty() {
            return;
        }
        if self.store.mark_slow(site, line) {
            info!(
                "{}: moving {site} off {line} ({:.0} KiB/s)",
                self.name,
                rate / 1024.0
            );
        } else {
            debug!(
                "{}: {line} still slow for {site} ({:.0} KiB/s)",
                self.name,
                rate / 1024.0
            );
        }
        if !self.store.speed_probe_due(site) {
            return;
        }
        if let Ok(rt) = tokio::runtime::Handle::try_current() {
            let me = Arc::clone(self);
            let (site, line) = (site.to_string(), line.to_string());
            rt.spawn(async move { me.speed_probe(&site, &line, rate).await });
        }
    }

    /// `line`'s download speed from the first of [`SPEED_URLS`] that serves
    /// (a server's error status tries the next; the line's own failure
    /// ends it).
    async fn download_rate(&self, line: &dyn ProxyAdapter) -> std::result::Result<f64, String> {
        let mut last = "no speed test url".to_string();
        for url in &self.speed_urls {
            match crate::health::download_rate(line, url, SPEED_PROBE_BYTES, SPEED_PROBE_TIME).await
            {
                Err(e) if e.starts_with("unexpected status") => last = format!("{url}: {e}"),
                r => return r,
            }
        }
        Err(last)
    }

    /// A video stream of `site` on `line`, to cut over later if needed.
    fn stream(&self, site: &str, line: &str) -> Arc<Cut> {
        let cut = Arc::new(Cut::default());
        let mut all = self.streams.lock();
        all.retain(|(_, _, c)| c.strong_count() > 0);
        all.push((site.to_string(), line.to_string(), Arc::downgrade(&cut)));
        cut
    }

    /// Ends `site`'s running streams on `line` (a line `gain` times faster
    /// is known): the players reconnect, and their new connections plan
    /// afresh, away from the slow line. At most once per [`CUT_COOLDOWN`].
    fn cut_over(&self, site: &str, line: &str, to: &str, gain: f64) {
        {
            let mut at = self.cut_at.lock();
            let now = Instant::now();
            at.retain(|_, t| now.duration_since(*t) < CUT_COOLDOWN);
            if at.contains_key(site) {
                return;
            }
            at.insert(site.to_string(), now);
        }
        let mut n = 0;
        for (s, l, c) in self.streams.lock().iter() {
            if s == site && l == line {
                if let Some(c) = c.upgrade() {
                    c.cut();
                    n += 1;
                }
            }
        }
        if n > 0 {
            info!(
                "{}: cutting {n} {site} stream(s) off {line}: {to} is {gain:.1}x faster",
                self.name
            );
        }
    }

    /// Downloads a test file through the best few lines for `site` other
    /// than `slow`; their speeds go into the records, and the fastest
    /// becomes the site's line if it hasn't settled on another meanwhile.
    async fn speed_probe(self: &Arc<Self>, site: &str, slow: &str, slow_rate: f64) {
        let mut others = self.candidates(false);
        others.retain(|l| l != slow);
        let mut lines = self.store.plan(site, &others).lines;
        lines.truncate(SPEED_PROBE_LINES);
        let mut tasks = Vec::new();
        for line in lines {
            let Some(p) = self.member(&line).cloned() else {
                continue;
            };
            let me = Arc::clone(self);
            tasks.push(tokio::spawn(async move {
                let Ok(_permit) = me.speed_tests.acquire().await else {
                    return None;
                };
                let start = Instant::now();
                let r = me.download_rate(p.as_ref()).await;
                match r {
                    Ok(rate) => Some((line, rate, start.elapsed())),
                    Err(e) => {
                        // The test server may be what's unreachable: no
                        // failure for the line.
                        debug!("{}: speed test via {line}: {e}", me.name);
                        None
                    }
                }
            }));
        }
        let mut best: Option<(String, f64)> = None;
        for t in tasks {
            let Ok(Some((line, rate, took))) = t.await else {
                continue;
            };
            debug!(
                "{}: {line} downloads {:.0} KiB/s for {site}",
                self.name,
                rate / 1024.0
            );
            self.store.sample(
                site,
                &line,
                (rate * took.as_secs_f64()) as u64,
                took.as_secs_f64() * 1000.0,
            );
            if best.as_ref().is_none_or(|b| rate > b.1) {
                best = Some((line, rate));
            }
        }
        if let Some((line, rate)) = best.filter(|b| b.1 >= metered::SLOW_BULK_BPS) {
            info!(
                "{}: {site} goes to {line} ({:.0} KiB/s in a speed test)",
                self.name,
                rate / 1024.0
            );
            self.store.adopt(site, &line);
            // A video stream stays on its line for as long as it lasts:
            // cut it, so the player comes back on the faster one (the
            // records now rank it first).
            let gain = rate / slow_rate.max(1.0);
            if is_video_site(site) && rate >= VIDEO_SLOW_BPS && gain >= CUT_GAIN {
                self.cut_over(site, slow, &line, gain);
            }
        }
    }

    /// Of `rest`, the line to hedge `first` with: another exit if known.
    fn hedge_for<'a>(&self, first: &str, rest: &'a [String]) -> Option<&'a String> {
        let ip = self.store.exit_of(first).map(|e| e.ip);
        rest.iter()
            .find(|l| ip.is_none() || self.store.exit_of(l).map(|e| e.ip) != ip)
            .or_else(|| rest.first())
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

/// Turns the lines' byte counters into rates, once a second, until the
/// group is dropped.
async fn sample_loads(weak: Weak<Shared>) {
    let mut tick = tokio::time::interval(Duration::from_secs(1));
    loop {
        tick.tick().await;
        let Some(me) = weak.upgrade() else {
            return;
        };
        me.loads.sample(Instant::now());
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

/// The key the store learns and pins under: the site, or one key for the
/// whole group when it is sticky.
fn key_of(me: &Shared, metadata: &Metadata) -> String {
    if me.sticky.load(Ordering::Relaxed) {
        return STICKY_SITE.to_string();
    }
    site_of(metadata)
}

/// The one "site" of a sticky group.
const STICKY_SITE: &str = "*";

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
        me.start();
        me.usage.touch_user_traffic(metadata);
        let site = key_of(me, metadata);
        let plan = me
            .store
            .plan_with(&site, &me.candidates(false), &me.loads.snapshot());
        if plan.lines.is_empty() {
            return Err(me.no_line());
        }
        // Answer before the caller's own dial deadline runs out.
        let outer = meow_common::dial::dial_deadline().map(|d| d - DEADLINE_MARGIN);
        let mut errs = Vec::new();
        let mut lines: Vec<String> = plan.lines.clone();
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
            let mut deadline = tokio::time::Instant::now() + timeout;
            if let Some(o) = outer {
                if o <= tokio::time::Instant::now() {
                    break;
                }
                deadline = deadline.min(o);
            }
            // One line alone: a second (another exit) joins if it is slow.
            let hedge = (n == 1)
                .then(|| me.hedge_for(&lines[0], &lines[1..]).cloned())
                .flatten();
            let tried: Vec<String> = lines[..n].iter().chain(hedge.iter()).cloned().collect();
            match me
                .race(&site, metadata, &lines[..n], hedge.as_deref(), deadline)
                .await
            {
                Ok((line, conn, connect)) => {
                    *me.now.write() = Some(SmolStr::from(line.as_str()));
                    if !plan.no_pin {
                        // A connection lent to a roomier line keeps the
                        // family on its exit; a failover moves it.
                        let keep = plan
                            .keep_pin
                            .as_deref()
                            .filter(|_| plan.lines.first() == Some(&line));
                        me.store.use_line(&site, keep.unwrap_or(&line));
                    }
                    let store_owner = Arc::clone(me);
                    let live_owner = Arc::clone(me);
                    let load = me.loads.of(&line);
                    let (live_site, live_line) = (site.clone(), line.clone());
                    let stream = is_video_site(&site).then(|| me.stream(&site, &line));
                    let mut conn = MeteredConn::new(conn, connect, move |r| {
                        store_owner.store.report(&site, &line, &r);
                    })
                    .counting(load)
                    .watching(move |ev| live_owner.live(&live_site, &live_line, ev));
                    // Video: slow below what HD needs, and cut over to a
                    // faster line once one is known.
                    if let Some(cut) = stream {
                        conn = conn.slow_below(VIDEO_SLOW_BPS).cuttable(cut);
                    }
                    return Ok(Box::new(conn));
                }
                Err(e) => errs.push(e.to_string()),
            }
            lines.retain(|l| !tried.contains(l));
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
        me.start();
        me.usage.touch_user_traffic(metadata);
        let site = key_of(me, metadata);
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
        let line = me
            .store
            .peek(&key_of(me, metadata), &me.candidates(false))?;
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
