//! Where each line exits to the internet, looked up the way the app looks
//! it up (Dart `ProxyController._locateExits`, `probeExit` in `exits.dart`)
//! so it goes on with the app closed:
//!
//! - every line of the running config's speed-test group, by its server's
//!   IP and port ("1.2.3.4:443"; a domain resolved over DNS-over-HTTPS
//!   first, a fake-ip answer being none), once: kept until cleared, a
//!   rate-limited one asked again at the next round;
//! - a round 15 s after an input was handed over (or the core started with
//!   one) and every 30 minutes, lines one after another, seven IP-info
//!   services asked at once through the line itself (the line's adapter in
//!   this core, so the app's speed tests on the speed-test port are not
//!   disturbed), settled by majority; a rate limit ends the round;
//! - what was learned is written to `exits.json` and handed to the build
//!   (`exits`: key → country, `resolved`: domain → IP, the keys the app
//!   puts in its input) by a rebuild that runs the config when its groups
//!   changed.
//!
//! The round runs in the core: it holds one line's seven small answers at
//! a time (bodies capped at [`MAX_ANSWER`]) and keeps nothing between
//! rounds but the file. Off until told (`PUT /paopao/schedule` with
//! `exits`): while an older app looks exits up itself, the two must not
//! both run.

use std::collections::HashSet;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use futures::future::BoxFuture;
use indexmap::IndexMap;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::sync::Mutex;

use super::service::{now_ms, JobError, Service};
use super::store::{write_atomic, Store};

/// The first round after a hand-over waits this long (first pages load
/// first; Dart `locateAfter`).
pub const LOCATE_AFTER: Duration = Duration::from_secs(15);
/// Rounds after that (Dart `exitCheckEvery`).
pub const CHECK_EVERY: Duration = Duration::from_secs(30 * 60);
/// What is read of a service's answer.
pub const MAX_ANSWER: usize = 64 * 1024;
/// The speed-test group of a PaoPao config: every line of the pool.
const SPEED_TEST_GROUP: &str = "speedtest";

/// Where a line was measured to exit (Dart `ExitInfo.toJson`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExitInfo {
    /// ISO country code.
    pub cc: String,
    /// When, Unix ms.
    #[serde(default)]
    pub at: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ip: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub city: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub region: Option<String>,
    /// The network operator ("AS13335 Cloudflare").
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub org: Option<String>,
    /// The services that agreed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub src: Option<String>,
}

/// `exits.json`.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct ExitsFile {
    /// By the server's IP and port.
    #[serde(default)]
    pub exits: IndexMap<String, ExitInfo>,
    /// Rate limited last time: asked again.
    #[serde(default)]
    pub pending: Vec<String>,
    /// Server domains resolved to an address.
    #[serde(default)]
    pub resolved: IndexMap<String, String>,
    /// When the last round ran, Unix ms.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_run: Option<i64>,
    /// Why the last rebuild with what was learned failed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_error: Option<String>,
}

impl ExitsFile {
    pub fn read(store: &Store) -> Option<Self> {
        std::fs::read(store.exits())
            .ok()
            .and_then(|b| serde_json::from_slice(&b).ok())
    }

    pub fn write(&self, store: &Store) -> std::io::Result<()> {
        let bytes = serde_json::to_vec(self).map_err(std::io::Error::other)?;
        write_atomic(&store.exits(), &bytes, false)
    }

    /// What the build reads: each server's country.
    pub fn countries(&self) -> serde_json::Map<String, Value> {
        self.exits
            .iter()
            .map(|(k, v)| (k.clone(), v.cc.clone().into()))
            .collect()
    }
}

/// What one lookup came to (Dart `ExitProbe`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Probe {
    Found(ExitInfo),
    /// The services said "too many requests".
    Limited,
    /// No answer through the line.
    Failed,
}

impl Probe {
    pub fn name(&self) -> &'static str {
        match self {
            Self::Found(_) => "found",
            Self::Limited => "limited",
            Self::Failed => "failed",
        }
    }
}

/// Asks `url` through line `tag`: the status and the body, None without
/// an answer.
pub type Ask =
    Arc<dyn Fn(String, String) -> BoxFuture<'static, Option<(u16, String)>> + Send + Sync>;
/// A server domain's real address, None when unknown.
pub type Resolve = Arc<dyn Fn(String) -> BoxFuture<'static, Option<String>> + Send + Sync>;

/// A fake-ip stand-in (198.18.0.0/15; fc00::/7): never a server's address.
pub fn is_fake_ip(ip: &str) -> bool {
    match ip.parse::<std::net::IpAddr>() {
        Ok(std::net::IpAddr::V4(a)) => a.octets()[0] == 198 && matches!(a.octets()[1], 18 | 19),
        Ok(std::net::IpAddr::V6(a)) => (a.octets()[0] & 0xFE) == 0xFC,
        Err(_) => false,
    }
}

/// `host` as the key's address part: an IP as it is, a domain resolved.
fn key_of(ip: &str, port: u64) -> String {
    if ip.contains(':') {
        format!("[{ip}]:{port}")
    } else {
        format!("{ip}:{port}")
    }
}

/// Several services' answers settled by majority (Dart `voteExit`): the
/// country most of them name (ties to the earlier), with the details of
/// the fullest answer that agrees.
pub fn vote(answers: &[ExitInfo]) -> Option<ExitInfo> {
    let count = |cc: &str| answers.iter().filter(|a| a.cc == cc).count();
    let top = answers.iter().map(|a| count(&a.cc)).max()?;
    let country = answers.iter().find(|a| count(&a.cc) == top)?.cc.clone();
    let agreeing: Vec<&ExitInfo> = answers.iter().filter(|a| a.cc == country).collect();
    let detail = |a: &ExitInfo| {
        u8::from(a.city.is_some()) * 2 + u8::from(a.region.is_some()) + u8::from(a.org.is_some())
    };
    let mut best = agreeing[0];
    for a in &agreeing[1..] {
        if detail(a) > detail(best) {
            best = a;
        }
    }
    let sources: Vec<&str> = agreeing.iter().filter_map(|a| a.src.as_deref()).collect();
    Some(ExitInfo {
        cc: country,
        at: best.at,
        ip: best
            .ip
            .clone()
            .or_else(|| agreeing.iter().find_map(|a| a.ip.clone())),
        city: best.city.clone(),
        region: best.region.clone(),
        org: best.org.clone(),
        src: Some(format!(
            "{} ({}/{})",
            sources.join("+"),
            agreeing.len(),
            answers.len()
        )),
    })
}

/// The services asked, in Dart's order.
pub const SERVICES: [&str; 7] = [
    "https://ipinfo.io/json",
    "https://api.ip.sb/geoip",
    "https://www.cloudflare.com/cdn-cgi/trace",
    "http://ip-api.com/json/",
    "https://ipwho.is/",
    "https://ipapi.co/json/",
    "https://api.country.is/",
];

fn text(v: Option<&Value>) -> Option<String> {
    v.and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
}

/// `'AS$asn'` the way Dart prints the decoded number or string.
fn dart_text(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        Value::Number(n) if n.is_f64() => {
            let f = n.as_f64().unwrap_or(0.0);
            if f.fract() == 0.0 && f.abs() < 1e21 {
                format!("{f:.1}")
            } else {
                f.to_string()
            }
        }
        v => v.to_string(),
    }
}

/// Service `i`'s answer `body` read (Dart `probeExit`'s parsers).
fn read_answer(i: usize, body: &str, at: i64) -> Option<ExitInfo> {
    let info = |cc: Option<&Value>, src: &str, ip, city, region, org: Option<String>| {
        let cc = cc?.as_str()?;
        if cc.chars().count() != 2 || cc.eq_ignore_ascii_case("XX") {
            return None;
        }
        Some(ExitInfo {
            cc: cc.to_uppercase(),
            at,
            ip,
            city,
            region,
            org: org.filter(|o| !o.is_empty()),
            src: Some(src.to_owned()),
        })
    };
    let json = || {
        serde_json::from_str::<Value>(body)
            .ok()
            .filter(Value::is_object)
    };
    match i {
        0 => {
            let v = json()?;
            info(
                v.get("country"),
                "ipinfo.io",
                text(v.get("ip")),
                text(v.get("city")),
                text(v.get("region")),
                text(v.get("org")),
            )
        }
        1 => {
            let v = json()?;
            let mut org = Vec::new();
            if let Some(asn) = v.get("asn").filter(|a| !a.is_null()) {
                org.push(format!("AS{}", dart_text(asn)));
            }
            if let Some(o) = v.get("organization").and_then(Value::as_str) {
                org.push(o.to_owned());
            }
            info(
                v.get("country_code"),
                "ip.sb",
                text(v.get("ip")),
                text(v.get("city")),
                text(v.get("region")),
                Some(org.join(" ")),
            )
        }
        2 => {
            let line = |k: &str| {
                body.lines()
                    .find_map(|l| l.strip_prefix(k))
                    .map(str::to_owned)
            };
            let loc =
                line("loc=").filter(|l| l.len() == 2 && l.bytes().all(|b| b.is_ascii_uppercase()));
            let ip = line("ip=").filter(|ip| !ip.is_empty() && !ip.contains(char::is_whitespace));
            info(
                loc.map(Value::String).as_ref(),
                "cloudflare",
                ip,
                None,
                None,
                None,
            )
        }
        3 => {
            let v = json()?;
            if v.get("status").and_then(Value::as_str) != Some("success") {
                return None;
            }
            info(
                v.get("countryCode"),
                "ip-api.com",
                text(v.get("query")),
                text(v.get("city")),
                text(v.get("regionName")),
                text(v.get("as")),
            )
        }
        4 => {
            let v = json()?;
            if v.get("success") == Some(&Value::Bool(false)) {
                return None;
            }
            let org = v.get("connection").and_then(Value::as_object).map(|c| {
                let mut org = Vec::new();
                if let Some(asn) = c.get("asn").filter(|a| !a.is_null()) {
                    org.push(format!("AS{}", dart_text(asn)));
                }
                if let Some(o) = c.get("org").and_then(Value::as_str) {
                    org.push(o.to_owned());
                }
                org.join(" ")
            });
            info(
                v.get("country_code"),
                "ipwho.is",
                text(v.get("ip")),
                text(v.get("city")),
                text(v.get("region")),
                org,
            )
        }
        5 => {
            let v = json()?;
            if v.get("error") == Some(&Value::Bool(true)) {
                return None;
            }
            let org: Vec<&str> = [v.get("asn"), v.get("org")]
                .into_iter()
                .filter_map(|x| x.and_then(Value::as_str))
                .collect();
            info(
                v.get("country_code"),
                "ipapi.co",
                text(v.get("ip")),
                text(v.get("city")),
                text(v.get("region")),
                Some(org.join(" ")),
            )
        }
        6 => {
            let v = json()?;
            info(
                v.get("country"),
                "country.is",
                text(v.get("ip")),
                None,
                None,
                None,
            )
        }
        _ => None,
    }
}

/// Every service asked at once through line `tag` (Dart `probeExit`):
/// found by majority; limited when any said "too many requests" (429,
/// 403); failed otherwise.
pub async fn probe(ask: &Ask, tag: &str, at: i64) -> Probe {
    let asks = SERVICES
        .iter()
        .map(|url| ask(tag.to_owned(), (*url).to_owned()));
    let answers = futures::future::join_all(asks).await;
    let mut found = Vec::new();
    let mut limited = false;
    for (i, a) in answers.into_iter().enumerate() {
        match a {
            Some((429 | 403, _)) => limited = true,
            Some((200, body)) => found.extend(read_answer(i, &body, at)),
            _ => {}
        }
    }
    match vote(&found) {
        Some(f) => Probe::Found(f),
        None if limited => Probe::Limited,
        None => Probe::Failed,
    }
}

/// A line of the running config: its tag and server.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Line {
    pub tag: String,
    pub server: String,
    pub port: u64,
}

/// The pool's lines (the speed-test group's members) with their servers.
pub fn lines_of(raw: &meow_config::raw::RawConfig) -> Vec<Line> {
    let Some(members) = raw
        .proxy_groups
        .iter()
        .flatten()
        .find(|g| g.name == SPEED_TEST_GROUP)
        .and_then(|g| g.proxies.as_ref())
    else {
        return Vec::new();
    };
    let proxies = raw.proxies.as_deref().unwrap_or_default();
    members
        .iter()
        .filter_map(|tag| {
            let p = proxies
                .iter()
                .find(|p| p.get("name").and_then(serde_yaml::Value::as_str) == Some(tag))?;
            let server = p.get("server")?.as_str()?.to_ascii_lowercase();
            let port = p.get("port")?.as_u64()?;
            (!server.is_empty()).then(|| Line {
                tag: tag.clone(),
                server,
                port,
            })
        })
        .collect()
}

/// The exit lookups over the service's store.
pub struct Exits {
    pub(super) ask: Ask,
    pub(super) resolve: Resolve,
    /// Held through a round or a single lookup.
    turn: Mutex<()>,
    /// Domains resolved by this run of the core: others again.
    resolved_here: parking_lot::Mutex<HashSet<String>>,
    /// The first round since an input was handed over is still due.
    pub(super) fresh: AtomicBool,
}

impl Exits {
    pub fn new(ask: Ask, resolve: Resolve) -> Self {
        Self {
            ask,
            resolve,
            turn: Mutex::new(()),
            resolved_here: parking_lot::Mutex::new(HashSet::new()),
            fresh: AtomicBool::new(true),
        }
    }

    pub fn running(&self) -> bool {
        self.turn.try_lock().is_err()
    }
}

/// What a round or a lookup did.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct RoundReport {
    /// Lines looked up.
    pub asked: usize,
    /// Exits learned.
    pub found: usize,
    /// The round ended at a rate limit.
    pub limited: bool,
    /// The core runs a new config (groups changed).
    pub reloaded: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

impl Service {
    fn exits_file(&self) -> ExitsFile {
        ExitsFile::read(self.store()).unwrap_or_default()
    }

    /// The file; started from the input's countries when there is none
    /// (an app that never handed its exits over).
    async fn exits_or_input(&self) -> ExitsFile {
        if let Some(f) = ExitsFile::read(self.store()) {
            return f;
        }
        let mut f = ExitsFile::default();
        if let Ok(head) = self.input_head().await {
            for (k, cc) in head.exits {
                f.exits.insert(
                    k,
                    ExitInfo {
                        cc,
                        at: 0,
                        ip: None,
                        city: None,
                        region: None,
                        org: None,
                        src: None,
                    },
                );
            }
        }
        f
    }

    /// The servers' keys, domains resolved (new ones and, once a run, all).
    async fn keys_of(&self, f: &mut ExitsFile, lines: &[Line]) -> Vec<Option<String>> {
        let exits = self.exits_job();
        let hosts: Vec<String> = {
            let here = exits.resolved_here.lock();
            let mut hosts: Vec<String> = lines
                .iter()
                .filter(|l| {
                    l.server.parse::<std::net::IpAddr>().is_err() && !here.contains(&l.server)
                })
                .map(|l| l.server.clone())
                .collect();
            hosts.sort();
            hosts.dedup();
            hosts
        };
        let found =
            futures::future::join_all(hosts.iter().map(|h| (exits.resolve)(h.clone()))).await;
        for (h, ip) in hosts.into_iter().zip(found) {
            if let Some(ip) = ip {
                f.resolved.insert(h.clone(), ip);
                exits.resolved_here.lock().insert(h);
            }
        }
        lines
            .iter()
            .map(|l| {
                let ip = if l.server.parse::<std::net::IpAddr>().is_ok() {
                    Some(l.server.clone())
                } else {
                    f.resolved.get(&l.server).cloned()
                };
                ip.map(|ip: String| key_of(ip.as_str(), l.port))
            })
            .collect()
    }

    /// Takes a lookup's result in; true when something was learned.
    fn record(f: &mut ExitsFile, key: &str, r: &Probe) -> bool {
        match r {
            Probe::Found(info) => {
                f.pending.retain(|k| k != key);
                f.exits.insert(key.to_owned(), info.clone());
                true
            }
            Probe::Limited => {
                if !f.pending.iter().any(|k| k == key) {
                    f.pending.push(key.to_owned());
                }
                false
            }
            Probe::Failed => false,
        }
    }

    /// One round: every line that needs its exit, until a rate limit.
    pub async fn locate(&self) -> Result<RoundReport, JobError> {
        if !self.can_run() {
            return Err(JobError::Unavailable);
        }
        let exits = self.exits_job();
        let _turn = exits.turn.lock().await;
        exits.fresh.store(false, Ordering::Relaxed);
        let lines = lines_of(&self.raw_config.read());
        let mut f = self.exits_or_input().await;
        let before = f.clone();
        let keys = self.keys_of(&mut f, &lines).await;
        let mut report = RoundReport::default();
        let mut seen = HashSet::new();
        for (l, key) in lines.iter().zip(keys) {
            let Some(key) = key else { continue };
            let needs = !f.exits.contains_key(&key) || f.pending.contains(&key);
            if !needs || !seen.insert(key.clone()) {
                continue;
            }
            let r = probe(&exits.ask, &l.tag, now_ms()).await;
            report.asked += 1;
            if Self::record(&mut f, &key, &r) {
                report.found += 1;
            }
            if r == Probe::Limited {
                report.limited = true;
                break;
            }
        }
        f.last_run = Some(now_ms());
        self.settle(f, &before, &mut report, false).await;
        super::give_back();
        Ok(report)
    }

    /// Looks line `tag` up again now (Dart `relocate`).
    pub async fn relocate(&self, tag: &str) -> Result<(Probe, RoundReport), JobError> {
        if !self.can_run() {
            return Err(JobError::Unavailable);
        }
        let exits = self.exits_job();
        let _turn = exits.turn.lock().await;
        let lines = lines_of(&self.raw_config.read());
        let line = lines
            .into_iter()
            .find(|l| l.tag == tag)
            .ok_or(JobError::UnknownId)?;
        let mut f = self.exits_or_input().await;
        let before = f.clone();
        let key = self
            .keys_of(&mut f, std::slice::from_ref(&line))
            .await
            .pop()
            .flatten();
        let mut report = RoundReport::default();
        let Some(key) = key else {
            return Ok((Probe::Failed, report));
        };
        let r = probe(&exits.ask, tag, now_ms()).await;
        report.asked = 1;
        if Self::record(&mut f, &key, &r) {
            report.found = 1;
        }
        report.limited = r == Probe::Limited;
        self.settle(f, &before, &mut report, false).await;
        super::give_back();
        Ok((r, report))
    }

    /// Forgets line `tag`'s exit (None: every line's); looked up again at
    /// the next round, which starts at once.
    pub async fn clear_exits(&self, tag: Option<&str>) -> Result<RoundReport, JobError> {
        let exits = self.exits_job();
        let mut report = RoundReport::default();
        {
            let _turn = exits.turn.lock().await;
            let mut f = self.exits_or_input().await;
            let before = f.clone();
            match tag {
                None => {
                    f.exits.clear();
                    f.pending.clear();
                }
                Some(tag) => {
                    let lines: Vec<Line> = lines_of(&self.raw_config.read())
                        .into_iter()
                        .filter(|l| l.tag == tag)
                        .collect();
                    if lines.is_empty() {
                        return Err(JobError::UnknownId);
                    }
                    for key in self.keys_of(&mut f, &lines).await.into_iter().flatten() {
                        f.exits.shift_remove(&key);
                        f.pending.retain(|k| *k != key);
                    }
                }
            }
            self.settle(f, &before, &mut report, false).await;
        }
        Ok(report)
    }

    /// Exits the app measured (its own file, a speed test's lookup): an
    /// exit newer than the one kept replaces it; `pending` joins unless
    /// found since.
    pub async fn take_exits(&self, given: ExitsFile) -> Result<RoundReport, JobError> {
        let exits = self.exits_job();
        let _turn = exits.turn.lock().await;
        let mut f = self.exits_or_input().await;
        let before = f.clone();
        for (k, info) in given.exits {
            let newer = f.exits.get(&k).is_none_or(|old| info.at > old.at);
            if newer {
                f.pending.retain(|p| *p != k);
                f.exits.insert(k, info);
            }
        }
        for k in given.pending {
            let later = f
                .exits
                .get(&k)
                .is_none_or(|e| e.at < now_ms() - CHECK_EVERY.as_millis() as i64);
            if later && !f.pending.contains(&k) {
                f.pending.push(k);
            }
        }
        for (h, ip) in given.resolved {
            f.resolved.entry(h).or_insert(ip);
        }
        // The app's start ran its own exits: the config is built with
        // these whatever the file had.
        let mut report = RoundReport::default();
        self.settle(f, &before, &mut report, true).await;
        Ok(report)
    }

    /// Writes `f` when it changed and hands what the build reads of it
    /// over when that changed (`force`: in any case, the build itself
    /// telling whether the input differs); a failed rebuild is kept in the
    /// file.
    async fn settle(
        &self,
        mut f: ExitsFile,
        before: &ExitsFile,
        report: &mut RoundReport,
        force: bool,
    ) {
        let built_from = |f: &ExitsFile| (f.countries(), f.resolved.clone());
        if (force || built_from(&f) != built_from(before)) && self.can_run() {
            let mut resolved: serde_json::Map<String, Value> = self
                .input_head()
                .await
                .map(|h| h.resolved.into_iter().map(|(k, v)| (k, v.into())).collect())
                .unwrap_or_default();
            for (k, v) in &f.resolved {
                resolved.insert(k.clone(), v.clone().into());
            }
            let mut set = serde_json::Map::new();
            set.insert("exits".into(), Value::Object(f.countries()));
            set.insert("resolved".into(), Value::Object(resolved));
            match self.apply_set(set).await {
                Ok(r) => {
                    report.reloaded = r.reloaded;
                    f.last_error = r.error.clone();
                    report.error = r.error;
                }
                // Nothing handed over yet: the input has nothing to build.
                Err(JobError::NoInput) => {}
                Err(e) => {
                    f.last_error = Some(e.to_string());
                    report.error = Some(e.to_string());
                }
            }
        }
        if &f != before {
            let store = self.store().clone();
            let _ = tokio::task::spawn_blocking(move || f.write(&store)).await;
        }
    }

    /// `GET /paopao/exits`.
    pub async fn exits_answer(&self) -> Value {
        let f = self.exits_file();
        serde_json::json!({
            "exits": f.exits,
            "pending": f.pending,
            "resolved": f.resolved,
            "last_run": f.last_run,
            "last_error": f.last_error,
            "running": self.exits_job().running(),
        })
    }
}

/// Looks exits up on the schedule while it is on: [`LOCATE_AFTER`] after
/// a hand-over (or the core's start with an input), then every
/// [`CHECK_EVERY`]. Runs for good: spawn it.
pub async fn run_exits(svc: Arc<Service>) {
    let mut since = tokio::time::Instant::now();
    loop {
        let s = svc.schedule().await;
        let wait = if !s.exits || !svc.store().input().exists() {
            None
        } else if svc.exits_job().fresh.load(Ordering::Relaxed) {
            Some(svc.locate_after().saturating_sub(since.elapsed()))
        } else {
            let last = svc.exits_file().last_run.unwrap_or(0);
            let due = last.saturating_add(svc.check_every().as_millis() as i64);
            Some(Duration::from_millis(
                u64::try_from(due.saturating_sub(now_ms())).unwrap_or(0),
            ))
        };
        if wait != Some(Duration::ZERO) {
            let nap = wait.unwrap_or(CHECK_EVERY).min(CHECK_EVERY);
            tokio::select! {
                () = tokio::time::sleep(nap) => {}
                handed = svc.exits_woken() => {
                    if handed {
                        since = tokio::time::Instant::now();
                    }
                }
            }
            continue;
        }
        if let Err(e) = svc.locate().await {
            tracing::warn!("paopao exits: {e}");
            tokio::time::sleep(svc.check_every()).await;
        }
    }
}

/// The real lookups: through line `tag` of the running config (its adapter
/// held with its route generation across the request), and domains over
/// DNS-over-HTTPS, then the system's resolver.
pub fn real_ask(tunnel: meow_tunnel::Tunnel) -> Ask {
    Arc::new(move |tag: String, url: String| {
        let tunnel = tunnel.clone();
        Box::pin(async move {
            let route = tunnel.route_snapshot();
            let proxy = route.proxies.get(tag.as_str()).cloned()?;
            let headers = [("User-Agent".to_owned(), "curl/8".to_owned())];
            let got = tokio::time::timeout(
                Duration::from_secs(16),
                meow_config::internal_http::fetch_response(
                    &url,
                    Some(&proxy),
                    &headers,
                    MAX_ANSWER,
                ),
            )
            .await;
            drop(route);
            match got {
                Ok(Ok(res)) => Some((res.status, String::from_utf8_lossy(&res.body).into_owned())),
                _ => None,
            }
        })
    })
}

/// Node metadata uses the same file-configured proxy-host resolver as
/// actual outbound dials. No independent DNS providers or OS fallback.
pub fn real_resolve() -> Resolve {
    Arc::new(|host: String| {
        Box::pin(async move {
            let resolver = meow_common::host_resolver()?;
            match tokio::time::timeout(Duration::from_secs(8), resolver.resolve(&host)).await {
                Ok(Ok(ip)) if !is_fake_ip(&ip.to_string()) => Some(ip.to_string()),
                _ => None,
            }
        })
    })
}

/// The first A record of a DNS JSON answer that is no fake-ip.
pub fn doh_answer(body: &[u8]) -> Option<String> {
    let v: Value = serde_json::from_slice(body).ok()?;
    v.get("Answer")?.as_array()?.iter().find_map(|a| {
        let ip = a.get("data")?.as_str()?;
        (a.get("type")?.as_u64()? == 1 && ip.parse::<std::net::IpAddr>().is_ok() && !is_fake_ip(ip))
            .then(|| ip.to_owned())
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn info(cc: &str, src: &str) -> ExitInfo {
        ExitInfo {
            cc: cc.into(),
            at: 1,
            ip: None,
            city: None,
            region: None,
            org: None,
            src: Some(src.into()),
        }
    }

    #[test]
    fn the_majority_decides_with_the_fullest_details() {
        let mut hk = info("HK", "b");
        hk.city = Some("Hong Kong".into());
        hk.ip = Some("1.1.1.1".into());
        let v = vote(&[
            info("US", "a"),
            hk,
            info("HK", "c"),
            info("US", "d"),
            info("HK", "e"),
        ])
        .unwrap();
        assert_eq!(v.cc, "HK");
        assert_eq!(v.city.as_deref(), Some("Hong Kong"));
        assert_eq!(v.src.as_deref(), Some("b+c+e (3/5)"));
        // A tie goes to the country named first.
        assert_eq!(vote(&[info("JP", "a"), info("US", "b")]).unwrap().cc, "JP");
        assert_eq!(vote(&[]), None);
    }

    #[test]
    fn each_services_answer_reads_as_the_app_reads_it() {
        let r = read_answer(
            0,
            r#"{"ip":"1.2.3.4","city":"Tokyo","region":"","country":"jp","org":"AS1 X"}"#,
            5,
        )
        .unwrap();
        assert_eq!(
            (r.cc.as_str(), r.city.as_deref(), r.region, r.org.as_deref()),
            ("JP", Some("Tokyo"), None, Some("AS1 X"))
        );
        let r = read_answer(
            1,
            r#"{"country_code":"US","asn":13335,"organization":"Cloudflare"}"#,
            5,
        )
        .unwrap();
        assert_eq!(r.org.as_deref(), Some("AS13335 Cloudflare"));
        let r = read_answer(2, "fl=1\nip=5.6.7.8\nloc=SG\n", 5).unwrap();
        assert_eq!((r.cc.as_str(), r.ip.as_deref()), ("SG", Some("5.6.7.8")));
        assert_eq!(read_answer(2, "loc=XX\nip=1", 5), None);
        assert_eq!(
            read_answer(3, r#"{"status":"fail","countryCode":"US"}"#, 5),
            None
        );
        assert_eq!(
            read_answer(4, r#"{"success":false,"country_code":"US"}"#, 5),
            None
        );
        let r = read_answer(
            4,
            r#"{"country_code":"DE","connection":{"asn":3320,"org":"DT"}}"#,
            5,
        )
        .unwrap();
        assert_eq!(r.org.as_deref(), Some("AS3320 DT"));
        assert_eq!(
            read_answer(5, r#"{"error":true,"country_code":"US"}"#, 5),
            None
        );
        let r = read_answer(5, r#"{"country_code":"GB","asn":"AS2","org":"B"}"#, 5).unwrap();
        assert_eq!(r.org.as_deref(), Some("AS2 B"));
        assert_eq!(
            read_answer(6, r#"{"country":"FR","ip":"9.9.9.9"}"#, 5)
                .unwrap()
                .cc,
            "FR"
        );
        assert_eq!(read_answer(6, "not json", 5), None);
    }

    #[test]
    fn fake_ips_and_doh_answers() {
        assert!(is_fake_ip("198.18.0.5") && is_fake_ip("198.19.255.1") && is_fake_ip("fd00::1"));
        assert!(!is_fake_ip("198.20.0.1") && !is_fake_ip("1.1.1.1") && !is_fake_ip("x"));
        let body = json!({"Answer": [
            {"type": 5, "data": "cname.example."},
            {"type": 1, "data": "198.18.0.1"},
            {"type": 1, "data": "2.2.2.2"}
        ]});
        assert_eq!(
            doh_answer(body.to_string().as_bytes()).as_deref(),
            Some("2.2.2.2")
        );
        assert_eq!(doh_answer(b"{}"), None);
        assert_eq!(key_of("::1", 443), "[::1]:443");
    }

    #[tokio::test]
    async fn a_probe_is_found_limited_or_failed() {
        let answering = |answers: Vec<Option<(u16, &'static str)>>| -> Ask {
            let answers = Arc::new(answers);
            Arc::new(move |_tag, url: String| {
                let i = SERVICES.iter().position(|s| *s == url).unwrap();
                let a = answers[i].map(|(s, b)| (s, b.to_owned()));
                Box::pin(async move { a })
            })
        };
        let none = vec![None; 7];
        assert_eq!(probe(&answering(none.clone()), "t", 1).await, Probe::Failed);
        let mut limited = none.clone();
        limited[3] = Some((429, ""));
        assert_eq!(probe(&answering(limited), "t", 1).await, Probe::Limited);
        let mut odd = none.clone();
        odd[0] = Some((200, "<html>"));
        odd[1] = Some((500, ""));
        assert_eq!(probe(&answering(odd), "t", 1).await, Probe::Failed);
        let mut found = none;
        found[6] = Some((200, r#"{"country":"HK"}"#));
        found[2] = Some((200, "ip=1.1.1.1\nloc=HK"));
        match probe(&answering(found), "t", 1).await {
            Probe::Found(f) => assert_eq!(f.src.as_deref(), Some("cloudflare+country.is (2/2)")),
            other => panic!("{other:?}"),
        }
    }
}
