//! The box's state and what the config page can do with it: subscriptions,
//! mode, password, DNS upstreams; every change rebuilds the core's config
//! and hot-reloads the core.

use std::net::{Ipv4Addr, SocketAddr};
use std::os::fd::{AsRawFd as _, IntoRawFd as _, OwnedFd};
use std::path::PathBuf;
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{bail, Context as _};
use rand::Rng as _;
use serde_json::{json, Map, Value};
use tracing::{info, warn};

use crate::config::{core_config, GeodataUrls, Runtime};
use crate::ctl::Api;
use crate::dns::{upstream_addr, Front, HostRule};
use crate::store::{BoxFile, Store, ADMIN_USER};
use crate::switch::{Addr, Switch};
use crate::sys::Iface;
use crate::CoreHost;

/// How the box got its address.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddrSource {
    Dhcp,
    Static,
}

/// The address in force.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Net {
    pub addr: Addr,
    pub gateway: Option<Ipv4Addr>,
    pub source: AddrSource,
}

/// The modes the page offers (the app's `ProxyMode` names).
pub const MODES: [&str; 3] = ["smart", "global", "direct"];

/// Shortest password the page accepts.
const MIN_PASSWORD: usize = 6;

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_millis()).unwrap_or(i64::MAX))
}

/// The host part of a URL (a subscription's default name).
pub fn url_host(url: &str) -> String {
    let rest = url.split_once("://").map_or(url, |(_, r)| r);
    let host = rest.split(['/', '?', '#']).next().unwrap_or("");
    let host = host.rsplit_once('@').map_or(host, |(_, h)| h);
    host.split(':').next().unwrap_or("").to_owned()
}

/// A subscription after a download: the persisted shape with `parse_json`'s
/// nodes / skipped / split / usage, or the old entry with `error` set.
pub fn refreshed(old: &Value, body: anyhow::Result<Vec<u8>>, now: i64) -> Value {
    let mut sub = old.as_object().cloned().unwrap_or_default();
    let fail = |mut s: Map<String, Value>, why: String| {
        s.insert("error".into(), why.into());
        Value::Object(s)
    };
    let body = match body {
        Ok(b) => b,
        Err(e) => return fail(sub, format!("下载失败：{e:#}")),
    };
    let text = String::from_utf8_lossy(&body);
    let parsed = meow_paopao::parse_json(&text);
    if let Some(e) = parsed.get("error").and_then(Value::as_str) {
        return fail(sub, format!("无法识别订阅内容：{e}"));
    }
    if parsed["nodes"].as_array().is_none_or(Vec::is_empty) {
        return fail(sub, "订阅里没有可用的节点".into());
    }
    for k in ["nodes", "skipped", "split", "usage"] {
        sub.insert(k.into(), parsed[k].clone());
    }
    sub.insert("updated".into(), now.into());
    sub.remove("error");
    Value::Object(sub)
}

/// Shared state.
pub struct App {
    pub store: Store,
    pub iface: Iface,
    host: Arc<dyn CoreHost>,
    pub box_file: RwLock<BoxFile>,
    settings: RwLock<Value>,
    subs: RwLock<Vec<Value>>,
    pub dns: Arc<Front>,
    pub switch: Arc<Mutex<Switch>>,
    pub net: RwLock<Option<Net>>,
    pub api: Api,
    core_dns: SocketAddr,
    /// The core's SOCKS listener (127.0.0.1): the DNS front's way through
    /// a line.
    core_socks: SocketAddr,
    /// Where the rule data comes from (the last applied config's links).
    geodata_urls: RwLock<GeodataUrls>,
    secret: String,
    /// The core's end of the socket pair; each start gets a duplicate.
    core_end: OwnedFd,
    /// The descriptor number the running core holds (None: not running).
    /// Also serialises config applies.
    core: tokio::sync::Mutex<Option<i32>>,
    /// Serialises subscription downloads.
    refreshing: tokio::sync::Mutex<()>,
    lines: RwLock<usize>,
    traffic: Mutex<Option<(Instant, u64, u64)>>,
    started: Instant,
}

/// Lock helpers: a poisoned lock still holds usable data here.
macro_rules! r {
    ($l:expr) => {
        $l.read().unwrap_or_else(std::sync::PoisonError::into_inner)
    };
}
macro_rules! w {
    ($l:expr) => {
        $l.write()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    };
}
pub(crate) use w;

/// A free TCP port on 127.0.0.1 (for the core's API and DNS listeners).
pub fn free_port() -> anyhow::Result<u16> {
    let l = std::net::TcpListener::bind("127.0.0.1:0")?;
    // The DNS listener takes UDP too: make sure that port is free as well.
    let port = l.local_addr()?.port();
    std::net::UdpSocket::bind(("127.0.0.1", port))?;
    Ok(port)
}

impl App {
    /// The state for `store`, `iface`, running the core through `host`.
    pub fn new(
        store: Store,
        iface: Iface,
        host: Arc<dyn CoreHost>,
        switch: Arc<Mutex<Switch>>,
        core_end: OwnedFd,
    ) -> anyhow::Result<Self> {
        let box_file = store.box_file()?;
        let dns = Arc::new(Front::new(&box_file.dns_upstreams));
        let secret: String = {
            let mut rng = rand::rng();
            (0..32)
                .map(|_| char::from(b"0123456789abcdef"[rng.random_range(0..16)]))
                .collect()
        };
        let api = Api::new(
            SocketAddr::from((Ipv4Addr::LOCALHOST, free_port()?)),
            secret.clone(),
        );
        let core_dns = SocketAddr::from((Ipv4Addr::LOCALHOST, free_port()?));
        let core_socks = loop {
            // Ports picked one after the other can repeat once released.
            let a = SocketAddr::from((Ipv4Addr::LOCALHOST, free_port()?));
            if a != core_dns && a != api.addr {
                break a;
            }
        };
        Ok(Self {
            settings: RwLock::new(store.settings()),
            subs: RwLock::new(store.subscriptions()),
            store,
            iface,
            host,
            box_file: RwLock::new(box_file),
            dns,
            switch,
            net: RwLock::new(None),
            api,
            core_dns,
            core_socks,
            geodata_urls: RwLock::new(GeodataUrls::default()),
            secret,
            core_end,
            core: tokio::sync::Mutex::new(None),
            refreshing: tokio::sync::Mutex::new(()),
            lines: RwLock::new(0),
            traffic: Mutex::new(None),
            started: Instant::now(),
        })
    }

    /// The page's password.
    pub fn password(&self) -> String {
        r!(self.box_file).password.clone()
    }

    /// Whether `user` / `password` may use the page.
    pub fn check_login(&self, user: &str, password: &str) -> bool {
        let want = self.password();
        // Length-independent comparison of the whole string.
        let same = want.len() == password.len()
            && want
                .bytes()
                .zip(password.bytes())
                .fold(0u8, |acc, (a, b)| acc | (a ^ b))
                == 0;
        user == ADMIN_USER && same
    }

    fn runtime(&self, fd: i32) -> Runtime {
        Runtime {
            controller: self.api.addr,
            secret: self.secret.clone(),
            dns: self.core_dns,
            socks: self.core_socks,
            tun_fd: fd,
            addr: r!(self.net).map(|n| n.addr.ip),
        }
    }

    /// Builds the config and gets the core running it: a hot reload when
    /// it runs, else a start (with a fresh duplicate of the TUN end).
    pub async fn apply(self: &Arc<Self>) -> anyhow::Result<()> {
        let mut core = self.core.lock().await;
        let settings = r!(self.settings).clone();
        let subs = r!(self.subs).clone();
        let offset = crate::sys::utc_offset_minutes();
        if let Some(fd) = *core {
            let cfg = core_config(&settings, &subs, &self.runtime(fd), now_ms(), offset)?;
            match self.api.reload(&cfg.yaml).await {
                Ok(()) => {
                    self.applied(&cfg);
                    return Ok(());
                }
                Err(e) => {
                    warn!("core reload failed, restarting it: {e:#}");
                    let me = Arc::clone(self);
                    tokio::task::spawn_blocking(move || me.host.stop()).await?;
                    *core = None;
                    self.dns.set_core(None);
                    self.dns.set_line(None);
                }
            }
        }
        // The core owns (and closes) what it gets: a duplicate.
        let dup = self
            .core_end
            .try_clone()
            .context("cannot duplicate the TUN descriptor")?;
        let fd = dup.as_raw_fd();
        let cfg = core_config(&settings, &subs, &self.runtime(fd), now_ms(), offset)?;
        let home: PathBuf = self.store.core_home()?;
        let me = Arc::clone(self);
        let yaml = cfg.yaml.clone();
        let raw = dup.into_raw_fd();
        tokio::task::spawn_blocking(move || me.host.start(&home, &yaml, raw))
            .await?
            .context("the core did not start")?;
        *core = Some(fd);
        self.dns.set_core(Some(self.core_dns));
        self.applied(&cfg);
        info!(lines = cfg.lines, "core started");
        Ok(())
    }

    fn applied(&self, cfg: &crate::config::CoreConfig) {
        self.dns
            .set_hosts(HostRule::from_config(cfg.hosts.as_ref()));
        *w!(self.lines) = cfg.lines;
        *w!(self.geodata_urls) = cfg.geodata_urls.clone();
        // Foreign names through a line once there is one (in 直连 mode
        // nothing goes through a line).
        let line = cfg.lines > 0 && self.mode() != "direct";
        self.dns.set_line(line.then_some(self.core_socks));
    }

    /// Whether the rule data files (GeoIP, GeoSite) are in the core's home.
    pub fn rule_data(&self) -> (bool, bool) {
        self.store.core_home().map_or((false, false), |h| {
            (
                h.join(crate::geodata::MMDB).is_file(),
                h.join(crate::geodata::GEOSITE).is_file(),
            )
        })
    }

    /// Gets the rule data into the core's home and the domestic list into
    /// the DNS front: downloads what is missing (mirrors, retried with
    /// backoff until it arrives), reloads the core after a download.
    /// Returns once both files are here and the list is loaded.
    pub async fn ensure_rule_data(self: Arc<Self>) {
        use crate::geodata::{backoff, domestic_list, load_domestic, mirrors, mmdb_ok, save};
        use crate::geodata::{GEOSITE, MMDB, RETRY_FIRST};
        let mut wait = RETRY_FIRST;
        loop {
            let home = match self.store.core_home() {
                Ok(h) => h,
                Err(e) => {
                    warn!("rule data: no core home: {e:#}");
                    tokio::time::sleep(wait).await;
                    wait = backoff(wait);
                    continue;
                }
            };
            // The core may have fetched GeoSite itself (its startup fetch).
            if !self.dns.has_domestic() {
                if let Some(db) = load_domestic(&home.join(GEOSITE)).await {
                    self.dns.set_domestic(Some(db));
                    info!("DNS domestic list loaded");
                }
            }
            let urls = r!(self.geodata_urls).clone();
            let mut missing: Vec<(&str, String)> = Vec::new();
            if !home.join(MMDB).is_file() {
                missing.push((MMDB, urls.mmdb));
            }
            // Absent, or here but unusable: fetched (again).
            if !self.dns.has_domestic() {
                missing.push((GEOSITE, urls.geosite));
            }
            if missing.is_empty() {
                info!("rule data ready");
                return;
            }
            let mut got = false;
            for (file, url) in missing {
                for link in mirrors(&url) {
                    let bytes = match self.host.fetch(&link).await {
                        Ok(b) => b,
                        Err(e) => {
                            warn!("rule data: {link}: {e:#}");
                            continue;
                        }
                    };
                    let usable = if file == MMDB {
                        mmdb_ok(&bytes)
                    } else {
                        domestic_list(&bytes).is_some()
                    };
                    if !usable {
                        warn!("rule data: {link}: not a usable {file}");
                        continue;
                    }
                    match save(&home, file, &bytes) {
                        Ok(()) => {
                            info!("rule data: {file} downloaded ({} bytes)", bytes.len());
                            got = true;
                            break;
                        }
                        Err(e) => warn!("rule data: saving {file}: {e}"),
                    }
                }
            }
            if got {
                // The rules read the files when the config is applied.
                if let Err(e) = self.apply().await {
                    warn!("rule data: core reload: {e:#}");
                }
                wait = RETRY_FIRST;
                continue;
            }
            tokio::time::sleep(wait).await;
            wait = backoff(wait);
        }
    }

    /// Stops the core (on exit).
    pub async fn stop_core(self: &Arc<Self>) {
        let mut core = self.core.lock().await;
        if core.take().is_some() {
            self.dns.set_core(None);
            self.dns.set_line(None);
            let me = Arc::clone(self);
            let _ = tokio::task::spawn_blocking(move || me.host.stop()).await;
        }
    }

    /// The settings' mode (`smart` unless set).
    pub fn mode(&self) -> String {
        r!(self.settings)
            .get("mode")
            .and_then(Value::as_str)
            .filter(|m| MODES.contains(m))
            .unwrap_or("smart")
            .to_owned()
    }

    /// Changes the mode and applies it.
    pub async fn set_mode(self: &Arc<Self>, mode: &str) -> anyhow::Result<()> {
        if !MODES.contains(&mode) {
            bail!("未知的模式");
        }
        let s = {
            let mut s = w!(self.settings);
            if !s.is_object() {
                *s = json!({});
            }
            s["mode"] = mode.into();
            s.clone()
        };
        self.store.save_settings(&s)?;
        self.apply().await
    }

    /// Changes the page's password.
    pub fn set_password(&self, password: &str) -> anyhow::Result<()> {
        if password.chars().count() < MIN_PASSWORD {
            bail!("密码至少 {MIN_PASSWORD} 位");
        }
        if password.chars().any(char::is_control) {
            bail!("密码里不能有控制字符");
        }
        let b = {
            let mut b = w!(self.box_file);
            b.password = password.to_owned();
            b.clone()
        };
        self.store.save_box_file(&b)
    }

    /// Changes the upstreams of real DNS answers (empty: the defaults).
    pub fn set_dns_upstreams(&self, list: &[String]) -> anyhow::Result<()> {
        let list: Vec<String> = list
            .iter()
            .map(|s| s.trim().to_owned())
            .filter(|s| !s.is_empty())
            .collect();
        if let Some(bad) = list.iter().find(|s| upstream_addr(s).is_none()) {
            bail!("DNS 上游要写 IP 地址（如 223.5.5.5），不认识：{bad}");
        }
        let b = {
            let mut b = w!(self.box_file);
            b.dns_upstreams = if list.is_empty() {
                crate::dns::DEFAULT_UPSTREAMS
                    .iter()
                    .map(|s| (*s).to_owned())
                    .collect()
            } else {
                list
            };
            b.clone()
        };
        self.store.save_box_file(&b)?;
        self.dns.set_upstreams(&b.dns_upstreams);
        Ok(())
    }

    /// Adds a subscription link, downloads it, applies.
    pub async fn add_subscription(self: &Arc<Self>, url: &str) -> anyhow::Result<()> {
        let url = url.trim();
        if !(url.starts_with("http://") || url.starts_with("https://")) {
            bail!("订阅链接要以 http:// 或 https:// 开头");
        }
        if r!(self.subs)
            .iter()
            .any(|s| s.get("url").and_then(Value::as_str) == Some(url))
        {
            bail!("这个订阅已经添加过了");
        }
        let busy = self.refreshing.lock().await;
        let id: String = {
            let mut rng = rand::rng();
            (0..8)
                .map(|_| char::from(b"0123456789abcdef"[rng.random_range(0..16)]))
                .collect()
        };
        let fresh = json!({ "id": id, "url": url, "name": url_host(url) });
        let sub = refreshed(&fresh, self.host.fetch(url).await, now_ms());
        if let Some(e) = sub.get("error").and_then(Value::as_str) {
            bail!("{e}");
        }
        let subs = {
            let mut subs = w!(self.subs);
            subs.push(sub);
            subs.clone()
        };
        self.store.save_subscriptions(&subs)?;
        drop(busy);
        self.apply().await
    }

    /// Removes a subscription, applies.
    pub async fn remove_subscription(self: &Arc<Self>, id: &str) -> anyhow::Result<()> {
        let subs = {
            let mut subs = w!(self.subs);
            let before = subs.len();
            subs.retain(|s| s.get("id").and_then(Value::as_str) != Some(id));
            if subs.len() == before {
                bail!("没有这个订阅");
            }
            subs.clone()
        };
        self.store.save_subscriptions(&subs)?;
        self.apply().await
    }

    /// Downloads every subscription again (a failed one keeps its lines),
    /// applies when anything changed.
    pub async fn refresh_subscriptions(self: &Arc<Self>) -> anyhow::Result<()> {
        let busy = self.refreshing.lock().await;
        let list = r!(self.subs).clone();
        if list.is_empty() {
            return Ok(());
        }
        let mut out = Vec::with_capacity(list.len());
        for s in &list {
            let url = s.get("url").and_then(Value::as_str).unwrap_or_default();
            let r = refreshed(s, self.host.fetch(url).await, now_ms());
            if let Some(e) = r.get("error").and_then(Value::as_str) {
                warn!(name = %url_host(url), "subscription refresh failed: {e}");
            }
            out.push(r);
        }
        {
            // Keep entries added or removed meanwhile as they are.
            let mut subs = w!(self.subs);
            for s in subs.iter_mut() {
                if let Some(n) = out.iter().find(|n| n.get("id") == s.get("id")) {
                    *s = n.clone();
                }
            }
            self.store.save_subscriptions(&subs)?;
        }
        drop(busy);
        self.apply().await
    }

    /// The status page's document.
    pub async fn status(&self) -> Value {
        let net = *r!(self.net);
        let now = crate::run::now_ms();
        let clients = self.switch.lock().map_or(0, |s| s.gateway_users(now));
        let running = self.core.lock().await.is_some();
        let (mut up, mut down) = (0.0, 0.0);
        let mut line = None;
        if running {
            if let Ok((u, d)) = self.api.totals().await {
                let t = Instant::now();
                let mut last = self
                    .traffic
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                if let Some((t0, u0, d0)) = *last {
                    let dt = t.duration_since(t0).as_secs_f64().max(0.001);
                    up = u.saturating_sub(u0) as f64 / dt;
                    down = d.saturating_sub(d0) as f64 / dt;
                }
                *last = Some((t, u, d));
            }
            line = self.api.current_line().await.ok().flatten();
        }
        let (geoip, geosite) = self.rule_data();
        let subs: Vec<Value> = r!(self.subs)
            .iter()
            .map(|s| {
                json!({
                    "id": s.get("id"),
                    "name": s.get("name"),
                    "host": url_host(s.get("url").and_then(Value::as_str).unwrap_or("")),
                    "nodes": s.get("nodes").and_then(Value::as_array).map_or(0, Vec::len),
                    "updated": s.get("updated"),
                    "usage": s.get("usage"),
                    "error": s.get("error"),
                })
            })
            .collect();
        json!({
            "ip": net.map(|n| n.addr.ip.to_string()),
            "prefix": net.map(|n| n.addr.prefix),
            "gateway": net.and_then(|n| n.gateway).map(|g| g.to_string()),
            "addrSource": net.map(|n| match n.source { AddrSource::Dhcp => "dhcp", AddrSource::Static => "static" }),
            "iface": self.iface.name,
            "wifi": self.iface.wireless,
            "mac": self.switch.lock().map(|s| s.mac.to_string()).unwrap_or_default(),
            "mode": self.mode(),
            "core": running,
            "line": line,
            "lines": *r!(self.lines),
            "up": up.round(),
            "down": down.round(),
            "clients": clients,
            "dns": self.dns.status(),
            "ruleData": { "geoip": geoip, "geosite": geosite, "ready": geoip && geosite && self.dns.has_domestic() },
            "subscriptions": subs,
            "uptime": self.started.elapsed().as_secs(),
            "refreshEvery": Duration::from_secs(crate::run::REFRESH_SECS).as_secs(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hosts_of_urls() {
        assert_eq!(url_host("https://a.example/sub?token=x"), "a.example");
        assert_eq!(url_host("http://u:p@b.example:8443/x"), "b.example");
        assert_eq!(url_host("c.example"), "c.example");
    }

    #[test]
    fn refresh_keeps_old_lines_on_failure() {
        let old = json!({"id": "a", "url": "https://x/s", "name": "x", "nodes": [1], "updated": 5});
        let r = refreshed(&old, Err(anyhow::anyhow!("timed out")), 9);
        assert_eq!(r["nodes"], json!([1]));
        assert_eq!(r["updated"], 5);
        assert!(r["error"].as_str().unwrap().contains("timed out"));
        let r = refreshed(&old, Ok(b"nothing useful".to_vec()), 9);
        assert!(r["error"].is_string());
        assert_eq!(r["nodes"], json!([1]));
    }

    #[test]
    fn refresh_takes_parsed_lines() {
        let body = b"ss://YWVzLTEyOC1nY206cA@1.2.3.4:1000#HK%2001\n".to_vec();
        let old = json!({"id": "a", "url": "https://x/s", "name": "x", "error": "old"});
        let r = refreshed(&old, Ok(body), 9);
        assert!(r.get("error").is_none(), "{r}");
        assert_eq!(r["nodes"].as_array().unwrap().len(), 1);
        assert_eq!(r["nodes"][0]["name"], "HK 01");
        assert_eq!(r["updated"], 9);
        // It is the persisted shape the builder reads.
        let s = meow_paopao::Subscription::from_json(&r).unwrap();
        assert_eq!(s.nodes.len(), 1);
    }
}
