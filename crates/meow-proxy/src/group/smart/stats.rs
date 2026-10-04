//! What the smart group knows: per website, how each line did.
//!
//! Every finished connection reports how long the line took to connect,
//! how long until the first byte came back, how much data moved and
//! whether it failed. Those numbers are kept per (site, line) as decaying
//! averages; a site is its registrable domain ("video.example.com" ->
//! "example.com"). Sites never seen before borrow the line's record across
//! all sites.
//!
//! Lines that keep failing sit out a while ("ban box") and come back only
//! after a probe passes. Sites of one company keep one exit (risk control).

use std::collections::HashMap;
use std::net::IpAddr;
use std::path::PathBuf;

use parking_lot::Mutex;
use rand::{rngs::StdRng, Rng, SeedableRng};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::family::family_key;

/// Weight of a new sample against the history.
const EWMA_ALPHA: f64 = 0.3;
/// A record this old (seconds) counts half: lines change over days.
const HALF_LIFE: f64 = 72.0 * 3600.0;
/// Bounds memory and the saved file; least recently used go first.
const MAX_SITES: usize = 4000;
/// Share of known-site dials that also try a challenger.
const EXPLORE_RATE: f64 = 0.05;
/// Above this a connection counts as a download for throughput.
const BULK_BYTES: u64 = 1 << 20;
/// Favours a line proven on this site over a guess (ms).
const GUESS_PREMIUM: f64 = 300.0;
/// A known line this fast (ms) is used alone.
const GOOD_COST: f64 = 1500.0;
/// A site family keeps its exit while used at least this often (s).
const STICKY_TTL: i64 = 2 * 3600;
/// Bounds the one-by-one failover of a pinned site.
const PINNED_TRIES: usize = 4;
/// A line that can't connect sits out this long (s), then is probed again.
pub const BAN_SECS: i64 = 5 * 60;
/// This many failures in a row (any site) ban a line.
const BAN_STREAK: u32 = 3;
/// A line receiving this fast (bytes/s) is busy: new connections may go to
/// a line with more room left.
const SPILL_RATE: f64 = (1u64 << 20) as f64;
/// What a line not yet seen busy is assumed to carry (bytes/s).
const ASSUMED_CAPACITY: f64 = 2.0 * SPILL_RATE;
/// 速度最快: share of dials that try a line not measured yet.
const MEASURE_RATE: f64 = 0.1;

/// Lines' load now: line → (bytes/s now, fastest seen).
pub type LoadView = HashMap<String, (f64, f64)>;

/// What is known about one line for one site (or overall).
#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize, PartialEq)]
pub struct Record {
    #[serde(rename = "s")]
    pub success: f64,
    #[serde(rename = "f")]
    pub failure: f64,
    #[serde(rename = "c")]
    pub connect_ms: f64,
    /// Time to first byte after the request.
    #[serde(rename = "t")]
    pub first_ms: f64,
    /// Bytes per second on large transfers.
    #[serde(rename = "b", default, skip_serializing_if = "is_zero")]
    pub throughput: f64,
    /// Unix seconds.
    #[serde(rename = "u")]
    pub last_used: i64,
}

fn is_zero(v: &f64) -> bool {
    *v == 0.0
}

/// One finished connection.
#[derive(Clone, Copy, Debug, Default)]
pub struct Outcome {
    pub failed: bool,
    pub connect_ms: f64,
    /// 0 when unknown (no request / response seen).
    pub first_ms: f64,
    /// Received.
    pub bytes: u64,
    pub duration_ms: f64,
}

fn ewma(old: f64, sample: f64) -> f64 {
    if old <= 0.0 {
        sample
    } else {
        old * (1.0 - EWMA_ALPHA) + sample * EWMA_ALPHA
    }
}

impl Record {
    /// Brings the counters to `now` so old failures fade.
    fn decay(&mut self, now: i64) {
        if self.last_used == 0 || now <= self.last_used {
            return;
        }
        let f = 0.5f64.powf((now - self.last_used) as f64 / HALF_LIFE);
        self.success *= f;
        self.failure *= f;
    }

    fn add(&mut self, r: &Outcome, now: i64) {
        self.decay(now);
        self.last_used = now;
        if r.failed {
            self.failure += 1.0;
            return;
        }
        self.success += 1.0;
        if r.connect_ms > 0.0 {
            self.connect_ms = ewma(self.connect_ms, r.connect_ms);
        }
        if r.first_ms > 0.0 {
            self.first_ms = ewma(self.first_ms, r.first_ms);
        }
        if r.bytes >= BULK_BYTES && r.duration_ms > 0.0 {
            self.throughput = ewma(self.throughput, r.bytes as f64 / (r.duration_ms / 1000.0));
        }
    }

    /// The decayed number of observations.
    pub fn samples(&self) -> f64 {
        self.success + self.failure
    }

    /// The expected wait in ms; lower is better. Failures count as a long
    /// wait, a fast large-transfer line gets a discount.
    pub fn cost(&self) -> f64 {
        let n = self.samples();
        if n <= 0.0 {
            return f64::INFINITY;
        }
        // Laplace smoothing: one lucky success doesn't look perfect.
        let fail_rate = (self.failure + 0.5) / (n + 1.0);
        let mut wait = self.first_ms;
        if wait <= 0.0 {
            wait = self.connect_ms;
        }
        if wait <= 0.0 {
            wait = 1500.0;
        }
        let mut cost = wait * (1.0 - fail_rate) + 8000.0 * fail_rate;
        if self.throughput > 0.0 {
            // 1 MB/s -> no change, 10 MB/s -> about half.
            cost /= 1.0 + (self.throughput / (1u64 << 20) as f64).log10().max(0.0);
        }
        cost
    }
}

/// Groups hosts of one website: the registrable domain, or the address for
/// IPs (IPv4 /24, IPv6 /48: servers of one site sit together).
pub fn site_key(host: &str) -> String {
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    if host.is_empty() {
        return String::new();
    }
    if let Ok(ip) = host
        .trim_matches(|c| c == '[' || c == ']')
        .parse::<IpAddr>()
    {
        return match ip {
            IpAddr::V4(v4) => {
                let o = v4.octets();
                format!("{}.{}.{}.0/24", o[0], o[1], o[2])
            }
            IpAddr::V6(v6) => {
                let s = v6.segments();
                format!("{:x}:{:x}:{:x}::/48", s[0], s[1], s[2])
            }
        };
    }
    psl::domain_str(&host).map_or(host.clone(), str::to_string)
}

/// A site family keeps one exit for a while.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq)]
pub struct Pin {
    #[serde(rename = "l")]
    pub line: String,
    #[serde(rename = "u")]
    pub last_used: i64,
}

/// Where a line's traffic leaves to the internet; many entry lines of one
/// provider land on the same exit.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct Exit {
    pub ip: String,
    #[serde(rename = "cc", default, skip_serializing_if = "String::is_empty")]
    pub country: String,
}

/// How to dial: try `lines` in order; the first `race` of them at the same
/// time, the rest one batch after another.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Plan {
    pub lines: Vec<String>,
    pub race: usize,
    /// The order comes from this site's own history.
    pub known: bool,
    /// The site has an exit: one line at a time (never two addresses at
    /// once), same exit first.
    pub pinned: bool,
    /// The first line takes this connection only (its exit's line is busy):
    /// the family stays on this pin.
    pub keep_pin: Option<String>,
    /// 速度最快: no pins at all.
    pub no_pin: bool,
}

#[derive(Default, Serialize, Deserialize)]
struct Saved {
    #[serde(rename = "v")]
    version: u32,
    sites: HashMap<String, HashMap<String, Record>>,
    overall: HashMap<String, Record>,
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pins: HashMap<String, Pin>,
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    exits: HashMap<String, Exit>,
}

struct Inner {
    sites: HashMap<String, HashMap<String, Record>>,
    overall: HashMap<String, Record>,
    pins: HashMap<String, Pin>,
    exits: HashMap<String, Exit>,
    /// Failures in a row per line.
    streak: HashMap<String, u32>,
    /// Banned until (unix seconds) per line; kept past the time until a
    /// probe passes.
    bans: HashMap<String, i64>,
    dirty: bool,
    balance: bool,
    /// 速度最快: the line seen fastest, no per-site learning.
    fastest: bool,
    rng: StdRng,
}

/// The records of one group.
pub struct Store {
    inner: Mutex<Inner>,
    path: Option<PathBuf>,
    now: Box<dyn Fn() -> i64 + Send + Sync>,
}

#[derive(Clone, Copy)]
struct Ranked<'a> {
    line: &'a str,
    site: f64,
    all: f64,
    known: bool,
}

impl Ranked<'_> {
    /// One number per line: this site's own cost when known, otherwise the
    /// line's cost across sites plus a premium for being a guess.
    fn eff(&self) -> f64 {
        if self.known {
            self.site
        } else {
            self.all + GUESS_PREMIUM
        }
    }
}

fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs() as i64)
}

impl Store {
    /// Records kept at `path` (JSON); `None` keeps them in memory only.
    pub fn new(path: Option<PathBuf>) -> Self {
        let mut inner = Inner {
            sites: HashMap::new(),
            overall: HashMap::new(),
            pins: HashMap::new(),
            exits: HashMap::new(),
            streak: HashMap::new(),
            bans: HashMap::new(),
            dirty: false,
            balance: false,
            fastest: false,
            rng: StdRng::from_os_rng(),
        };
        if let Some(saved) = path
            .as_ref()
            .and_then(|p| std::fs::read(p).ok())
            .and_then(|b| serde_json::from_slice::<Saved>(&b).ok())
            .filter(|s| s.version == 1)
        {
            inner.sites = saved.sites;
            inner.overall = saved.overall;
            inner.pins = saved.pins;
            inner.exits = saved.exits;
        }
        Self {
            inner: Mutex::new(inner),
            path,
            now: Box::new(unix_now),
        }
    }

    /// Tests: a fixed clock and seed.
    #[cfg(test)]
    pub fn with_clock(now: impl Fn() -> i64 + Send + Sync + 'static, seed: u64) -> Self {
        let s = Self::new(None);
        s.inner.lock().rng = StdRng::seed_from_u64(seed);
        Self {
            now: Box::new(now),
            ..s
        }
    }

    /// Spread new sites over the healthy lines (true) instead of racing for
    /// the fastest.
    pub fn set_balance(&self, on: bool) {
        self.inner.lock().balance = on;
    }

    /// 速度最快: always the line seen fastest on real downloads (latency
    /// until measured), now and then one not measured yet.
    pub fn set_fastest(&self, on: bool) {
        self.inner.lock().fastest = on;
    }

    /// Writes the records if they changed (atomic replace).
    pub fn save(&self) -> std::io::Result<()> {
        let Some(path) = &self.path else {
            return Ok(());
        };
        let data = {
            let mut g = self.inner.lock();
            if !g.dirty {
                return Ok(());
            }
            g.dirty = false;
            serde_json::to_vec(&Saved {
                version: 1,
                sites: g.sites.clone(),
                overall: g.overall.clone(),
                pins: g.pins.clone(),
                exits: g.exits.clone(),
            })
            .map_err(std::io::Error::other)?
        };
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir)?;
        }
        let tmp = path.with_extension("json.tmp");
        std::fs::write(&tmp, data)?;
        std::fs::rename(tmp, path)
    }

    /// Records one finished connection of `line` to `site` ("" = a probe).
    pub fn report(&self, site: &str, line: &str, r: &Outcome) {
        let now = (self.now)();
        let mut g = self.inner.lock();
        g.dirty = true;
        g.overall.entry(line.to_string()).or_default().add(r, now);
        judge(&mut g, line, site.is_empty(), r.failed, now);
        if site.is_empty() {
            return;
        }
        if !g.sites.contains_key(site) && g.sites.len() >= MAX_SITES {
            evict(&mut g);
        }
        g.sites
            .entry(site.to_string())
            .or_default()
            .entry(line.to_string())
            .or_default()
            .add(r, now);
    }

    /// Filters `lines` to those not on the ban list (order kept). A line
    /// whose time is up stays off until a probe lets it out ([`Self::due`]).
    pub fn free(&self, lines: &[String]) -> Vec<String> {
        let g = self.inner.lock();
        lines
            .iter()
            .filter(|l| !g.bans.contains_key(l.as_str()))
            .cloned()
            .collect()
    }

    /// Banned lines whose time is up: probe them before use.
    pub fn due(&self, lines: &[String]) -> Vec<String> {
        let now = (self.now)();
        let g = self.inner.lock();
        lines
            .iter()
            .filter(|l| g.bans.get(l.as_str()).is_some_and(|until| *until <= now))
            .cloned()
            .collect()
    }

    /// Lines sitting out now, with when they may come back (unix seconds).
    pub fn bans(&self) -> HashMap<String, i64> {
        let now = (self.now)();
        self.inner
            .lock()
            .bans
            .iter()
            .filter(|(_, until)| **until > now)
            .map(|(l, until)| (l.clone(), *until))
            .collect()
    }

    pub fn banned(&self, line: &str) -> bool {
        let now = (self.now)();
        self.inner.lock().bans.get(line).is_some_and(|u| *u > now)
    }

    /// Records where `line` leaves to the internet.
    pub fn set_exit(&self, line: &str, e: Exit) {
        let mut g = self.inner.lock();
        if g.exits.get(line) != Some(&e) {
            g.exits.insert(line.to_string(), e);
            g.dirty = true;
        }
    }

    pub fn exit_of(&self, line: &str) -> Option<Exit> {
        self.inner.lock().exits.get(line).cloned()
    }

    /// `line` served `site` now: it becomes (or stays) the family's exit.
    pub fn use_line(&self, site: &str, line: &str) {
        if site.is_empty() {
            return;
        }
        let now = (self.now)();
        let mut g = self.inner.lock();
        g.pins.insert(
            family_key(site),
            Pin {
                line: line.to_string(),
                last_used: now,
            },
        );
        g.dirty = true;
    }

    /// The line a site would use now without dialing (its pin, else the
    /// best known): what the connection list shows as the chain.
    pub fn peek(&self, site: &str, lines: &[String]) -> Option<String> {
        let now = (self.now)();
        {
            let g = self.inner.lock();
            if let Some(pin) = g.pins.get(&family_key(site)) {
                if now - pin.last_used < STICKY_TTL && lines.contains(&pin.line) {
                    return Some(pin.line.clone());
                }
            }
        }
        self.plan(site, lines).lines.first().cloned()
    }

    /// Orders `lines` (the group members that are up) for `site`.
    pub fn plan(&self, site: &str, lines: &[String]) -> Plan {
        self.plan_with(site, lines, &LoadView::new())
    }

    /// [`Self::plan`], with how busy each line is now: a busy line hands
    /// new connections to a comparable one with more room left.
    pub fn plan_with(&self, site: &str, lines: &[String], load: &LoadView) -> Plan {
        if lines.is_empty() {
            return Plan::default();
        }
        let now = (self.now)();
        let mut g = self.inner.lock();
        let site_recs = g.sites.get(site);
        let mut rs: Vec<Ranked<'_>> = lines
            .iter()
            .map(|l| {
                let mut r = Ranked {
                    line: l,
                    site: f64::INFINITY,
                    all: f64::INFINITY,
                    known: false,
                };
                if let Some(rec) = site_recs.and_then(|m| m.get(l.as_str())) {
                    let mut c = *rec;
                    c.decay(now);
                    if c.samples() >= 1.0 {
                        r.site = c.cost();
                        r.known = true;
                    }
                }
                if let Some(rec) = g.overall.get(l.as_str()) {
                    let mut c = *rec;
                    c.decay(now);
                    r.all = c.cost();
                }
                r
            })
            .collect();
        rs.sort_by(|a, b| a.eff().total_cmp(&b.eff()));
        let ordered: Vec<String> = rs.iter().map(|r| r.line.to_string()).collect();
        // How much a line carries at most, and how much is free now.
        let capacity = |g: &Inner, l: &str| -> f64 {
            let (_, peak) = load.get(l).copied().unwrap_or_default();
            let tp = g.overall.get(l).map_or(0.0, |r| r.throughput);
            peak.max(tp)
        };
        let busy = |l: &str| load.get(l).is_some_and(|(rate, _)| *rate >= SPILL_RATE);

        if g.fastest {
            return fastest_plan(&mut g, &rs, &|g: &Inner, l: &str| capacity(g, l));
        }

        // Sites whose accounts watch the address (Google, OpenAI …) never
        // spread over lines.
        let watched = family_key(site).starts_with("family:");
        if let Some(pin) = g.pins.get(&family_key(site)).cloned() {
            if now - pin.last_used < STICKY_TTL && lines.contains(&pin.line) {
                let cost: HashMap<&str, f64> = rs.iter().map(|r| (r.line, r.eff())).collect();
                let mut plan = pinned_plan(&g, &pin, &ordered, &cost);
                if !watched && busy(&plan.lines[0]) {
                    // The exit's line is busy (a download): this new
                    // connection may take a line of the same country with
                    // more room. The family stays where it is.
                    let first = plan.lines[0].clone();
                    let country = g
                        .exits
                        .get(&first)
                        .map(|e| e.country.clone())
                        .unwrap_or_default();
                    let limit = cost.get(first.as_str()).copied().unwrap_or(f64::INFINITY);
                    let peers: Vec<&str> = rs
                        .iter()
                        .filter(|r| {
                            r.line == first
                                || (!country.is_empty()
                                    && g.exits.get(r.line).is_some_and(|e| e.country == country)
                                    && r.eff().is_finite()
                                    && r.eff() <= (limit * 2.0).max(limit + 400.0))
                        })
                        .map(|r| r.line)
                        .collect();
                    let pick = roomiest(&mut g, &peers, load, &|g: &Inner, l: &str| capacity(g, l));
                    if pick != first {
                        plan.lines.retain(|l| l != &pick);
                        plan.lines.insert(0, pick);
                        plan.keep_pin = Some(pin.line.clone());
                    }
                }
                return plan;
            }
        }
        let best = rs[0];
        if g.balance && !best.known {
            return balanced_plan(site, &rs);
        }
        let mut plan = Plan {
            lines: ordered,
            ..Plan::default()
        };
        let good = best.known && best.site < GOOD_COST;
        let roll: f64 = g.rng.random();
        if good && roll >= EXPLORE_RATE {
            // A good line for this site: use it alone — or, when it is busy,
            // the comparable one with the most room left.
            if !watched && busy(best.line) {
                let limit = best.site;
                let peers: Vec<&str> = rs
                    .iter()
                    .filter(|r| r.known && r.site <= limit * 1.3 + 100.0)
                    .map(|r| r.line)
                    .collect();
                let pick = roomiest(&mut g, &peers, load, &|g: &Inner, l: &str| capacity(g, l));
                plan.lines.retain(|l| l != &pick);
                plan.lines.insert(0, pick);
            }
            plan.race = 1;
            plan.known = true;
        } else if good && rs.len() > 1 {
            // Now and then give a challenger from further down a chance.
            let i = 1 + g.rng.random_range(0..(rs.len() - 1).min(5));
            plan.lines.swap(1, i);
            plan.race = 2;
            plan.known = true;
        } else {
            // Unknown or poor: race the three most promising, from
            // different exits where known (three lines on one machine prove
            // nothing).
            // Nothing known about any line yet (just started, probes still
            // running): race wider so a few dead lines up front can't make
            // the first pages wait on timeouts.
            let width = if best.all.is_finite() { 3 } else { 6 };
            plan.lines = diverse_first(&g, plan.lines, width);
            plan.race = rs.len().min(width);
            plan.known = best.known;
        }
        drop(g);
        plan
    }

    /// What is known about `site`, per line (the app's "this site uses …").
    pub fn snapshot(&self, site: &str) -> HashMap<String, Record> {
        self.inner
            .lock()
            .sites
            .get(site)
            .cloned()
            .unwrap_or_default()
    }

    /// Lines worth re-probing now: those that served sites most recently,
    /// then the best overall, at most `n`.
    pub fn refresh_candidates(&self, lines: &[String], n: usize) -> Vec<String> {
        let g = self.inner.lock();
        let mut cs: Vec<(&String, i64, f64)> = lines
            .iter()
            .map(|l| {
                g.overall
                    .get(l)
                    .map_or((l, 0, f64::INFINITY), |r| (l, r.last_used, r.cost()))
            })
            .collect();
        cs.sort_by_key(|c| std::cmp::Reverse(c.1));
        let mut out: Vec<String> = cs.iter().take(n / 2).map(|c| c.0.clone()).collect();
        cs.sort_by(|a, b| a.2.total_cmp(&b.2));
        for c in cs {
            if out.len() >= n {
                break;
            }
            if !out.contains(c.0) {
                out.push(c.0.clone());
            }
        }
        out
    }
}

/// Keeps the ban list: [`BAN_STREAK`] failures in a row ban a line for
/// [`BAN_SECS`]; a banned line whose re-check probe fails stays in another
/// round; any success lets it out. A first probe failing alone doesn't ban:
/// the probe target may be what's unreachable, not the line.
fn judge(g: &mut Inner, line: &str, probe: bool, failed: bool, now: i64) {
    if !failed {
        g.streak.remove(line);
        g.bans.remove(line);
        return;
    }
    let streak = g.streak.entry(line.to_string()).or_default();
    *streak += 1;
    let streak = *streak;
    let banned = g.bans.contains_key(line);
    if (probe && banned) || streak >= BAN_STREAK {
        g.bans.insert(line.to_string(), now + BAN_SECS);
    }
}

fn evict(g: &mut Inner) {
    let mut all: Vec<(String, i64)> = g
        .sites
        .iter()
        .map(|(s, lines)| {
            (
                s.clone(),
                lines.values().map(|r| r.last_used).max().unwrap_or(0),
            )
        })
        .collect();
    all.sort_by_key(|a| a.1);
    let n = all.len() / 10 + 1;
    for (site, _) in all.into_iter().take(n) {
        g.sites.remove(&site);
    }
}

/// Of `lines`, the one with the most room left (capacity − rate now),
/// comparing two picked at random ("power of two choices": spreads load
/// without everyone rushing to the same line).
fn roomiest(
    g: &mut Inner,
    lines: &[&str],
    load: &LoadView,
    capacity: &dyn Fn(&Inner, &str) -> f64,
) -> String {
    match lines.len() {
        0 => return String::new(),
        1 => return lines[0].to_string(),
        _ => {}
    }
    let room = |g: &Inner, l: &str| {
        let rate = load.get(l).map_or(0.0, |(r, _)| *r);
        let cap = capacity(g, l);
        (if cap > 0.0 { cap } else { ASSUMED_CAPACITY }) - rate
    };
    let a = g.rng.random_range(0..lines.len());
    let mut b = g.rng.random_range(0..lines.len() - 1);
    if b >= a {
        b += 1;
    }
    let (la, lb) = (lines[a], lines[b]);
    if room(g, la) >= room(g, lb) {
        la.to_string()
    } else {
        lb.to_string()
    }
}

/// 速度最快: the line seen fastest on real downloads first (lines not
/// measured yet after, by latency); now and then an unmeasured one first,
/// so it gets measured.
fn fastest_plan(g: &mut Inner, rs: &[Ranked<'_>], capacity: &dyn Fn(&Inner, &str) -> f64) -> Plan {
    let mut measured: Vec<(&str, f64)> = rs
        .iter()
        .filter(|r| r.all.is_finite())
        .map(|r| (r.line, capacity(g, r.line)))
        .filter(|(_, c)| *c > 0.0)
        .collect();
    measured.sort_by(|a, b| b.1.total_cmp(&a.1));
    let mut lines: Vec<String> = measured.iter().map(|(l, _)| l.to_string()).collect();
    let rest: Vec<String> = rs
        .iter()
        .map(|r| r.line.to_string())
        .filter(|l| !lines.contains(l))
        .collect();
    let unmeasured: Vec<&String> = rest
        .iter()
        .filter(|l| rs.iter().any(|r| r.line == l.as_str() && r.all.is_finite()))
        .collect();
    if !unmeasured.is_empty() && (lines.is_empty() || g.rng.random::<f64>() < MEASURE_RATE) {
        let pick = unmeasured[g.rng.random_range(0..unmeasured.len())].clone();
        lines.insert(0, pick);
    }
    for l in rest {
        if !lines.contains(&l) {
            lines.push(l);
        }
    }
    Plan {
        lines,
        race: 1,
        known: true,
        no_pin: true,
        ..Plan::default()
    }
}

/// Keeps a pinned family on its exit: the pinned line, then lines with the
/// same exit address, then the same country, then the rest by cost.
fn pinned_plan(g: &Inner, pin: &Pin, ordered: &[String], cost: &HashMap<&str, f64>) -> Plan {
    let exit = g.exits.get(&pin.line);
    let c = |l: &str| cost.get(l).copied().unwrap_or(f64::INFINITY);
    // Same address, so the site can't tell: a pinned line that became much
    // slower hands over to a faster line on the same exit.
    let mut lead = pin.line.as_str();
    if let Some(e) = exit {
        for l in ordered {
            if l != &pin.line
                && g.exits.get(l).is_some_and(|x| x.ip == e.ip)
                && c(&pin.line) > 3.0 * c(l)
                && c(&pin.line) - c(l) > 500.0
            {
                lead = l;
                break;
            }
        }
    }
    let rank = |l: &str| -> u8 {
        let x = g.exits.get(l);
        if l == lead {
            0
        } else if l == pin.line || exit.is_some_and(|e| x.is_some_and(|x| x.ip == e.ip)) {
            1
        } else if exit
            .is_some_and(|e| !e.country.is_empty() && x.is_some_and(|x| x.country == e.country))
        {
            2
        } else {
            3
        }
    };
    let mut lines = ordered.to_vec();
    lines.sort_by_key(|l| rank(l));
    lines.truncate(PINNED_TRIES);
    Plan {
        lines,
        race: 1,
        known: true,
        pinned: true,
        ..Plan::default()
    }
}

/// For a site the group hasn't learnt yet, one of the healthy lines by
/// rendezvous hashing of the site family: sites spread over lines, one
/// site always lands on the same line, and adding or losing a line only
/// moves the sites that were on it.
fn balanced_plan(site: &str, rs: &[Ranked<'_>]) -> Plan {
    let best = rs[0].eff();
    let mut healthy: Vec<&str> = rs
        .iter()
        .filter(|r| r.eff().is_finite() && r.eff() <= (best * 2.0).max(best + 400.0))
        .map(|r| r.line)
        .collect();
    if healthy.is_empty() {
        healthy.push(rs[0].line);
    }
    let fam = family_key(site);
    healthy.sort_by_key(|l| std::cmp::Reverse(rendezvous(&fam, l)));
    let mut lines: Vec<String> = healthy.iter().map(ToString::to_string).collect();
    for r in rs {
        if !lines.iter().any(|l| l == r.line) {
            lines.push(r.line.to_string());
        }
    }
    lines.truncate(PINNED_TRIES);
    Plan {
        lines,
        race: 1,
        known: false,
        pinned: true,
        ..Plan::default()
    }
}

/// A strong hash: similar site names must still land far apart.
fn rendezvous(key: &str, line: &str) -> u64 {
    let mut h = Sha256::new();
    h.update(key.as_bytes());
    h.update([0u8]);
    h.update(line.as_bytes());
    let sum = h.finalize();
    u64::from_be_bytes(sum[..8].try_into().expect("8 bytes"))
}

/// Reorders `lines` so the first `n` have different exit addresses where
/// that is known; the order is otherwise kept.
fn diverse_first(g: &Inner, lines: Vec<String>, n: usize) -> Vec<String> {
    let mut out = Vec::with_capacity(lines.len());
    let mut later = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for l in lines {
        let ip = g.exits.get(&l).map(|e| e.ip.clone()).unwrap_or_default();
        if out.len() < n && (ip.is_empty() || !seen.contains(&ip)) {
            if !ip.is_empty() {
                seen.insert(ip);
            }
            out.push(l);
        } else {
            later.push(l);
        }
    }
    out.extend(later);
    out
}

#[cfg(test)]
#[path = "stats_tests.rs"]
mod tests;
