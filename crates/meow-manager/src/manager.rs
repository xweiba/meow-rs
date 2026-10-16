//! The manager: the user's one owner of the core. It runs as the logged-in
//! user (never as root): it starts, stops and restarts the core, switches
//! its 虚拟网卡 (the config rebuilt from the stored input, the core started
//! again where it may have the adapter: the privileged helper on macOS, the
//! core with its capabilities on Linux), points the user's OS proxy at it
//! while it runs ([`crate::proxy`]), keeps the switches (its state file)
//! and registers 开机自启 ([`LoginItem`]): the tray program starts at login,
//! starts the manager, and the manager brings the core up.
//!
//! Transport-agnostic and process-agnostic: running the core ([`Core`]),
//! changing the stored build input and rebuilding the config ([`Builder`]),
//! the OS proxy ([`ProxySwitch`]) and the login item are given to it. The
//! desktop daemon (`meow manager`, meow-app's `manager_daemon.rs`) gives
//! child processes; an app or a router build that runs the core in-process
//! gives in-process calls. The HTTP API over it is [`crate::http`].

use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use std::path::{Path, PathBuf};

/// The API's version in `status` (`manager`): what clients check for.
pub const VERSION: u32 = 1;

/// What the core runs: its config and its home directory (`-f`, `-d`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Run {
    pub config: PathBuf,
    pub dir: PathBuf,
}

impl Run {
    /// The core's PaoPao store (its stored build input): `<dir>/paopao`.
    pub fn store(&self) -> PathBuf {
        self.dir.join("paopao")
    }
}

/// Why the core did not start: a sentence, and its last log lines.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Failure {
    pub error: String,
    pub log: Option<String>,
}

impl Failure {
    pub fn new(error: impl Into<String>) -> Failure {
        Failure {
            error: error.into(),
            log: None,
        }
    }
}

/// Runs the core.
pub trait Core: Send {
    /// The core started on `run`, a running one ended first.
    fn start(&mut self, run: &Run) -> Result<(), Failure>;
    fn stop(&mut self);
    fn running(&mut self) -> bool;

    /// Where the core runs with 虚拟网卡 `tun` or without: its config and
    /// home (macOS: the privileged helper's core has its own, so root's
    /// files never land in the user core's). None: wherever a client says.
    fn place(&self, tun: bool) -> Option<Run> {
        let _ = tun;
        None
    }
}

/// 开机自启: the login item (the tray program, which starts the manager).
pub trait LoginItem: Send {
    /// It is there now (the user may have removed it).
    fn registered(&self) -> bool;
    fn set(&self, on: bool) -> Result<(), String>;
}

/// The stored build input changed and the config rebuilt (desktops: the
/// core's `meow paopao apply` child).
pub trait Builder: Send + Sync {
    /// The input in `store` with `settings`' keys replaced; with `build`
    /// the config rebuilt from it (`keep`: top-level keys kept as the
    /// running config has them). The new config's path when it differs
    /// from `config`.
    fn apply(
        &self,
        store: &Path,
        config: &Path,
        settings: &Map<String, Value>,
        build: bool,
        keep: &Map<String, Value>,
    ) -> Result<Option<PathBuf>, String>;
}

/// The OS proxy ([`crate::proxy::SystemProxy`]).
pub trait ProxySwitch: Send + Sync {
    fn enable(&self, port: u16) -> Result<(), String>;
    fn disable(&self);
    /// A leftover put back; true when there was one.
    fn recover(&self) -> bool;
}

impl ProxySwitch for crate::proxy::SystemProxy {
    fn enable(&self, port: u16) -> Result<(), String> {
        crate::proxy::SystemProxy::enable(self, port).map_err(|e| e.to_string())
    }

    fn disable(&self) {
        crate::proxy::SystemProxy::disable(self);
    }

    fn recover(&self) -> bool {
        crate::proxy::SystemProxy::recover(self)
    }
}

/// Why a request was not done.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Refusal {
    /// The request itself.
    Bad(String),
    /// Nothing to start: no client ever gave a config.
    NoRun,
    /// 虚拟网卡 needs rights this manager has not got (Linux: the core
    /// without its capabilities): the app asks the OS once.
    NeedsAuthorization,
    Failed(Failure),
}

impl Refusal {
    pub fn code(&self) -> &'static str {
        match self {
            Refusal::Bad(_) => "bad_request",
            Refusal::NoRun => "no_run",
            Refusal::NeedsAuthorization => "needs_authorization",
            Refusal::Failed(_) => "failed",
        }
    }

    pub fn to_json(&self) -> Value {
        match self {
            Refusal::Bad(why) => json!({"error": why, "code": self.code()}),
            Refusal::NoRun => {
                json!({"error": "no core was ever started here", "code": self.code()})
            }
            Refusal::NeedsAuthorization => {
                json!({"error": "the virtual adapter needs authorization", "code": self.code()})
            }
            Refusal::Failed(f) => json!({"error": f.error, "log": f.log, "code": self.code()}),
        }
    }
}

/// What is kept across the manager's runs.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Saved {
    /// What the core last ran.
    #[serde(default)]
    pub run: Option<Run>,
    /// 内核: on as last switched (the core comes up with the manager when
    /// [`Self::launch_at_login`] too).
    #[serde(default)]
    pub core: bool,
    /// 系统代理: the OS proxy points at the core while it runs.
    #[serde(default)]
    pub system_proxy: bool,
    /// 开机自启: the core comes up as the manager starts (boot, login).
    #[serde(default)]
    pub launch_at_login: bool,
}

/// A change of switches (`PATCH /manager/settings`); None: as it is.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
pub struct Patch {
    #[serde(default)]
    pub system_proxy: Option<bool>,
    #[serde(default)]
    pub tun: Option<bool>,
    #[serde(default)]
    pub launch_at_login: Option<bool>,
}

pub struct Manager {
    saved: Saved,
    state: Option<PathBuf>,
    core: Box<dyn Core>,
    builder: Box<dyn Builder>,
    proxy: Box<dyn ProxySwitch>,
    login: Box<dyn LoginItem>,
    can_tun: Box<dyn Fn() -> bool + Send>,
    /// The OS proxy points at the running core.
    proxy_on: bool,
    /// The running config's few keys ([`Manager::config`]), as last read,
    /// with the file's size and time then: read again only when it changed
    /// (status is asked every second; a config with its lines is MBs).
    keys: std::cell::RefCell<Option<KeysRead>>,
    /// 虚拟网卡 could be had, as last asked for the status (a socket call
    /// on macOS): asked again after [`CAN_TUN_FOR`].
    can_tun_seen: Option<(std::time::Instant, bool)>,
}

/// The config file's keys and what the file was when they were read.
struct KeysRead {
    path: PathBuf,
    len: u64,
    modified: Option<std::time::SystemTime>,
    keys: Map<String, Value>,
}

/// How long the status's `can_tun` is taken as last asked.
const CAN_TUN_FOR: std::time::Duration = std::time::Duration::from_secs(5);

/// The keys of the running config the manager uses (the rest, the lines
/// and rules, skipped as read: never held).
#[derive(Deserialize)]
struct ConfigKeys {
    #[serde(default)]
    tun: Option<Value>,
    #[serde(default, rename = "external-controller")]
    controller: Option<Value>,
    #[serde(default)]
    secret: Option<Value>,
    #[serde(default, rename = "mixed-port")]
    mixed_port: Option<Value>,
}

/// What a [`Manager`] is given.
pub struct Parts {
    pub core: Box<dyn Core>,
    pub builder: Box<dyn Builder>,
    pub proxy: Box<dyn ProxySwitch>,
    pub login: Box<dyn LoginItem>,
    /// 虚拟网卡 can be had now (the helper installed, the capabilities set).
    pub can_tun: Box<dyn Fn() -> bool + Send>,
}

impl Manager {
    /// [`Saved`] read from `state` (None: kept in memory only).
    pub fn new(state: Option<PathBuf>, parts: Parts) -> Manager {
        let Parts {
            core,
            builder,
            proxy,
            login,
            can_tun,
        } = parts;
        let saved = state
            .as_deref()
            .and_then(|p| std::fs::read(p).ok())
            .and_then(|b| serde_json::from_slice(&b).ok())
            .unwrap_or_default();
        Manager {
            saved,
            state,
            core,
            builder,
            proxy,
            login,
            can_tun,
            proxy_on: false,
            keys: std::cell::RefCell::new(None),
            can_tun_seen: None,
        }
    }

    pub fn saved(&self) -> &Saved {
        &self.saved
    }

    fn save(&self) {
        let Some(path) = &self.state else { return };
        if let Some(dir) = path.parent() {
            let _ = std::fs::create_dir_all(dir);
        }
        let tmp = path.with_extension("json.tmp");
        let written = serde_json::to_vec(&self.saved)
            .map_err(std::io::Error::other)
            .and_then(|b| std::fs::write(&tmp, b))
            .and_then(|()| std::fs::rename(&tmp, path));
        if let Err(e) = written {
            tracing::warn!("manager: the state is not kept: {e}");
        }
    }

    /// As the manager starts: a proxy left pointing at a core of before put
    /// back; the core brought up when 开机自启 and 内核 are on.
    pub fn boot(&mut self) {
        if self.proxy.recover() {
            tracing::info!("manager: the system proxy of an earlier run put back");
        }
        if self.saved.launch_at_login && self.saved.core && self.saved.run.is_some() {
            if let Err(e) = self.start(None, None) {
                tracing::warn!("manager: the core did not come up: {e:?}");
            }
        }
    }

    /// The keys of the config the core runs that the manager uses (`tun`,
    /// `external-controller`, `secret`, `mixed-port`; JSON — YAML only when
    /// a client gave one: none then). Read again only when the file changed.
    fn config(&self) -> Map<String, Value> {
        let Some(run) = self.saved.run.as_ref() else {
            return Map::new();
        };
        let meta = std::fs::metadata(&run.config).ok();
        let len = meta.as_ref().map_or(0, std::fs::Metadata::len);
        let modified = meta.as_ref().and_then(|m| m.modified().ok());
        let mut cache = self.keys.borrow_mut();
        if let Some(c) = cache.as_ref() {
            if c.path == run.config && c.len == len && c.modified == modified {
                return c.keys.clone();
            }
        }
        let keys = Self::read_keys(&run.config);
        *cache = Some(KeysRead {
            path: run.config.clone(),
            len,
            modified,
            keys: keys.clone(),
        });
        keys
    }

    /// [`ConfigKeys`] of the config at `path`, streamed (a small buffer,
    /// not the file whole).
    pub(crate) fn read_keys(path: &Path) -> Map<String, Value> {
        let Ok(f) = std::fs::File::open(path) else {
            return Map::new();
        };
        let Ok(k) = serde_json::from_reader::<_, ConfigKeys>(std::io::BufReader::new(f)) else {
            return Map::new();
        };
        let mut m = Map::new();
        for (key, v) in [
            ("tun", k.tun),
            ("external-controller", k.controller),
            ("secret", k.secret),
            ("mixed-port", k.mixed_port),
        ] {
            if let Some(v) = v {
                m.insert(key.into(), v);
            }
        }
        m
    }

    /// 虚拟网卡 can be had, for the status: as last asked within
    /// [`CAN_TUN_FOR`].
    fn can_tun_now(&mut self) -> bool {
        let now = std::time::Instant::now();
        if let Some((at, v)) = self.can_tun_seen {
            if now.duration_since(at) < CAN_TUN_FOR {
                return v;
            }
        }
        let v = (self.can_tun)();
        self.can_tun_seen = Some((now, v));
        v
    }

    fn tun_in(config: &Map<String, Value>) -> bool {
        config
            .get("tun")
            .and_then(|t| t.get("enable"))
            .and_then(Value::as_bool)
            .unwrap_or(false)
    }

    fn port_in(config: &Map<String, Value>) -> Option<u16> {
        config
            .get("mixed-port")
            .and_then(Value::as_u64)
            .and_then(|p| u16::try_from(p).ok())
            .filter(|&p| p != 0)
    }

    /// `{manager, running, core, system_proxy, launch_at_login, tun,
    /// can_tun, config, dir, controller, secret, mixed_port}`.
    pub fn status(&mut self) -> Value {
        let running = self.core.running();
        let can_tun = self.can_tun_now();
        let config = self.config();
        let run = self.saved.run.as_ref();
        json!({
            "manager": VERSION,
            "running": running,
            "core": self.saved.core,
            "system_proxy": self.saved.system_proxy,
            "launch_at_login": self.login.registered(),
            "tun": Self::tun_in(&config),
            "can_tun": can_tun,
            "config": run.map(|r| r.config.display().to_string()),
            "dir": run.map(|r| r.dir.display().to_string()),
            "controller": config.get("external-controller"),
            "secret": config.get("secret"),
            "mixed_port": Self::port_in(&config),
        })
    }

    /// The OS proxy as [`Saved::system_proxy`] says, for the running core.
    fn follow_proxy(&mut self) {
        let port = Self::port_in(&self.config());
        match (self.saved.system_proxy, port) {
            (true, Some(port)) => match self.proxy.enable(port) {
                Ok(()) => self.proxy_on = true,
                Err(e) => tracing::warn!("manager: the system proxy is not set: {e}"),
            },
            _ => {
                self.proxy.disable();
                self.proxy_on = false;
            }
        }
    }

    /// The core started on `run` (else what it last ran); `system_proxy`
    /// (else as saved) applied once it runs.
    pub fn start(
        &mut self,
        run: Option<Run>,
        system_proxy: Option<bool>,
    ) -> Result<Value, Refusal> {
        let run = match run.or_else(|| self.saved.run.clone()) {
            Some(r) => r,
            None => return Err(Refusal::NoRun),
        };
        if !run.config.is_absolute() || !run.dir.is_absolute() {
            return Err(Refusal::Bad("config and dir must be absolute paths".into()));
        }
        if let Some(on) = system_proxy {
            self.saved.system_proxy = on;
        }
        self.saved.run = Some(run.clone());
        let started = self.core.start(&run);
        self.saved.core = started.is_ok();
        if let Err(f) = started {
            self.proxy.disable();
            self.proxy_on = false;
            self.save();
            return Err(Refusal::Failed(f));
        }
        self.follow_proxy();
        self.save();
        Ok(self.status())
    }

    /// The core started on `config` (the app's build), written where the
    /// core runs with or without 虚拟网卡 ([`Core::place`]).
    pub fn start_config(
        &mut self,
        config: &Value,
        system_proxy: Option<bool>,
    ) -> Result<Value, Refusal> {
        let Value::Object(map) = config else {
            return Err(Refusal::Bad("config must be a JSON object".into()));
        };
        let Some(run) = self.core.place(Self::tun_in(map)) else {
            return Err(Refusal::Bad("give config and dir".into()));
        };
        let fail = |e: std::io::Error| Refusal::Failed(Failure::new(e.to_string()));
        std::fs::create_dir_all(&run.dir).map_err(fail)?;
        // Holds the API secret: the user's alone. A new file renamed over
        // the old one (root's core may have left that one root's).
        let tmp = run.config.with_extension("tmp");
        let _ = std::fs::remove_file(&tmp);
        write_private(&tmp, config.to_string().as_bytes()).map_err(fail)?;
        std::fs::rename(&tmp, &run.config).map_err(fail)?;
        self.start(Some(run), system_proxy)
    }

    /// The OS proxy put back first, then the core stopped (内核 off).
    pub fn stop(&mut self) -> Value {
        self.proxy.disable();
        self.proxy_on = false;
        self.core.stop();
        self.saved.core = false;
        self.save();
        self.status()
    }

    pub fn restart(&mut self) -> Result<Value, Refusal> {
        if self.saved.run.is_none() {
            return Err(Refusal::NoRun);
        }
        self.start(None, None)
    }

    /// The switches changed (`patch`); the new status.
    pub fn set(&mut self, patch: Patch) -> Result<Value, Refusal> {
        // Asked afresh after a switch (the authorization may be new).
        self.can_tun_seen = None;
        let mut mirror = Map::new();
        if let Some(on) = patch.tun {
            self.set_tun(on)?;
        }
        if let Some(on) = patch.launch_at_login {
            self.login
                .set(on)
                .map_err(|e| Refusal::Failed(Failure::new(e)))?;
            self.saved.launch_at_login = on;
            mirror.insert("launch_at_login".into(), on.into());
        }
        if let Some(on) = patch.system_proxy {
            self.saved.system_proxy = on;
            mirror.insert("system_proxy".into(), on.into());
            if self.core.running() {
                self.follow_proxy();
            }
        }
        self.save();
        // The stored input says so too: the panel takes its settings from it.
        if let (false, Some(run)) = (mirror.is_empty(), &self.saved.run) {
            if let Err(e) =
                self.builder
                    .apply(&run.store(), &run.config, &mirror, false, &Map::new())
            {
                tracing::debug!("manager: the input keeps the switches as they were: {e}");
            }
        }
        Ok(self.status())
    }

    /// 虚拟网卡: the config rebuilt with it (or without) and run where the
    /// core may have it ([`Core::place`]; the input goes along). Not taken:
    /// the old config back and running.
    fn set_tun(&mut self, on: bool) -> Result<(), Refusal> {
        let config = self.config();
        if Self::tun_in(&config) == on {
            return Ok(());
        }
        if on && !(self.can_tun)() {
            return Err(Refusal::NeedsAuthorization);
        }
        let Some(run) = self.saved.run.clone() else {
            return Err(Refusal::NoRun);
        };
        let mut keep = Map::new();
        for k in ["external-controller", "secret", "mixed-port"] {
            if let Some(v) = config.get(k) {
                keep.insert(k.into(), v.clone());
            }
        }
        let mut settings = Map::new();
        settings.insert("tun".into(), on.into());
        let next = self
            .builder
            .apply(&run.store(), &run.config, &settings, true, &keep)
            .map_err(|e| Refusal::Failed(Failure::new(e)))?;
        let Some(next) = next else { return Ok(()) };
        let place = self.core.place(on).unwrap_or_else(|| run.clone());
        let fail = |e: std::io::Error| Refusal::Failed(Failure::new(e.to_string()));
        let old = std::fs::read(&place.config).ok();
        if place.dir != run.dir {
            std::fs::create_dir_all(place.store()).map_err(fail)?;
            let input = run.store().join("input.json");
            if input.exists() {
                std::fs::copy(&input, place.store().join("input.json")).map_err(fail)?;
            }
        }
        replace(&next, &place.config).map_err(fail)?;
        self.saved.run = Some(place.clone());
        if !self.core.running() {
            return Ok(());
        }
        match self.core.start(&place) {
            Ok(()) => {
                self.follow_proxy();
                Ok(())
            }
            Err(f) => {
                // As it was: the old config, its input, its place.
                if place.dir == run.dir {
                    if let Some(old) = old {
                        let _ = std::fs::write(&run.config, old);
                    }
                }
                settings.insert("tun".into(), (!on).into());
                let _ = self
                    .builder
                    .apply(&run.store(), &run.config, &settings, false, &keep);
                self.saved.run = Some(run.clone());
                if self.core.start(&run).is_ok() {
                    self.follow_proxy();
                } else {
                    self.proxy.disable();
                    self.proxy_on = false;
                    self.saved.core = false;
                }
                Err(Refusal::Failed(f))
            }
        }
    }

    /// Now and then: a core that ended by itself leaves no proxy pointing
    /// at nothing.
    pub fn watch(&mut self) {
        if self.proxy_on && !self.core.running() {
            tracing::warn!("manager: the core ended; the system proxy put back");
            self.proxy.disable();
            self.proxy_on = false;
        }
    }

    /// The manager ends (the OS stops it): the proxy put back, the core
    /// stopped; the switches stay as they are for its next start.
    pub fn shutdown(&mut self) {
        self.proxy.disable();
        self.proxy_on = false;
        self.core.stop();
    }
}

fn write_private(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::io::Write as _;
        use std::os::unix::fs::OpenOptionsExt as _;
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)?;
        f.write_all(bytes)
    }
    #[cfg(not(unix))]
    std::fs::write(path, bytes)
}

/// `next` over `path` (renamed; copied across file systems), keeping
/// `path`'s owner and mode (the app's user reads it).
fn replace(next: &Path, path: &Path) -> std::io::Result<()> {
    #[cfg(unix)]
    if let Ok(was) = std::fs::metadata(path) {
        use std::os::unix::fs::MetadataExt as _;
        let _ = std::os::unix::fs::chown(next, Some(was.uid()), Some(was.gid()));
        let _ = std::fs::set_permissions(next, was.permissions());
    }
    if std::fs::rename(next, path).is_ok() {
        return Ok(());
    }
    std::fs::copy(next, path)?;
    let _ = std::fs::remove_file(next);
    Ok(())
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    #[derive(Default)]
    pub struct Log(pub Mutex<Vec<String>>);

    impl Log {
        pub fn take(&self) -> Vec<String> {
            std::mem::take(&mut *self.0.lock().unwrap())
        }
        fn push(&self, s: String) {
            self.0.lock().unwrap().push(s);
        }
    }

    pub struct FakeCore {
        pub log: Arc<Log>,
        pub up: Arc<Mutex<bool>>,
        /// Starts refused while the config contains this.
        pub refuse: Arc<Mutex<Option<String>>>,
        pub root: PathBuf,
    }

    impl Core for FakeCore {
        fn start(&mut self, run: &Run) -> Result<(), Failure> {
            let text = std::fs::read_to_string(&run.config).unwrap_or_default();
            self.log.push(format!("start {text}"));
            if let Some(bad) = &*self.refuse.lock().unwrap() {
                if text.contains(bad.as_str()) {
                    *self.up.lock().unwrap() = false;
                    return Err(Failure::new("core exited"));
                }
            }
            *self.up.lock().unwrap() = true;
            Ok(())
        }
        fn stop(&mut self) {
            self.log.push("stop".into());
            *self.up.lock().unwrap() = false;
        }
        fn running(&mut self) -> bool {
            *self.up.lock().unwrap()
        }
        fn place(&self, tun: bool) -> Option<Run> {
            let dir = self.root.join(if tun { "core-service" } else { "meow" });
            Some(Run {
                config: dir.join("config.json"),
                dir,
            })
        }
    }

    pub struct FakeLogin {
        pub on: Arc<Mutex<bool>>,
    }

    impl LoginItem for FakeLogin {
        fn registered(&self) -> bool {
            *self.on.lock().unwrap()
        }
        fn set(&self, on: bool) -> Result<(), String> {
            *self.on.lock().unwrap() = on;
            Ok(())
        }
    }

    /// Writes `{"tun":{"enable":<tun>},…keep}` as the next config.
    pub struct FakeBuilder {
        pub log: Arc<Log>,
    }

    impl Builder for FakeBuilder {
        fn apply(
            &self,
            store: &Path,
            config: &Path,
            settings: &Map<String, Value>,
            build: bool,
            keep: &Map<String, Value>,
        ) -> Result<Option<PathBuf>, String> {
            self.log.push(format!(
                "apply {} build={build}",
                Value::Object(settings.clone())
            ));
            if !build {
                return Ok(None);
            }
            let mut next = keep.clone();
            next.insert("tun".into(), json!({"enable": settings.get("tun")}));
            let path = store.join("config.next.yaml");
            std::fs::create_dir_all(store).unwrap();
            std::fs::write(&path, Value::Object(next).to_string()).unwrap();
            let _ = config;
            Ok(Some(path))
        }
    }

    pub struct FakeProxy {
        pub log: Arc<Log>,
    }

    impl ProxySwitch for FakeProxy {
        fn enable(&self, port: u16) -> Result<(), String> {
            self.log.push(format!("proxy on {port}"));
            Ok(())
        }
        fn disable(&self) {
            self.log.push("proxy off".into());
        }
        fn recover(&self) -> bool {
            self.log.push("recover".into());
            false
        }
    }

    pub struct Rig {
        pub dir: tempfile::TempDir,
        pub core: Arc<Log>,
        pub build: Arc<Log>,
        pub proxy: Arc<Log>,
        pub up: Arc<Mutex<bool>>,
        pub refuse: Arc<Mutex<Option<String>>>,
        pub can_tun: Arc<Mutex<bool>>,
        pub login: Arc<Mutex<bool>>,
    }

    impl Rig {
        pub fn new() -> Rig {
            Rig {
                dir: tempfile::tempdir().unwrap(),
                core: Arc::default(),
                build: Arc::default(),
                proxy: Arc::default(),
                up: Arc::default(),
                refuse: Arc::default(),
                can_tun: Arc::new(Mutex::new(true)),
                login: Arc::default(),
            }
        }

        pub fn manager(&self) -> Manager {
            let can = Arc::clone(&self.can_tun);
            Manager::new(
                Some(self.dir.path().join("manager.json")),
                Parts {
                    core: Box::new(FakeCore {
                        log: Arc::clone(&self.core),
                        up: Arc::clone(&self.up),
                        refuse: Arc::clone(&self.refuse),
                        root: self.dir.path().to_owned(),
                    }),
                    builder: Box::new(FakeBuilder {
                        log: Arc::clone(&self.build),
                    }),
                    proxy: Box::new(FakeProxy {
                        log: Arc::clone(&self.proxy),
                    }),
                    login: Box::new(FakeLogin {
                        on: Arc::clone(&self.login),
                    }),
                    can_tun: Box::new(move || *can.lock().unwrap()),
                },
            )
        }

        /// A config as the app writes it, and the run naming it.
        pub fn run(&self) -> Run {
            let dir = self.dir.path().join("meow");
            std::fs::create_dir_all(&dir).unwrap();
            let config = dir.join("config.json");
            std::fs::write(
                &config,
                r#"{"external-controller":"127.0.0.1:9090","secret":"s3","mixed-port":7890}"#,
            )
            .unwrap();
            Run { config, dir }
        }
    }

    #[test]
    fn start_stop_and_the_system_proxy() {
        let rig = Rig::new();
        let mut m = rig.manager();
        assert_eq!(m.restart(), Err(Refusal::NoRun));
        let s = m.start(Some(rig.run()), Some(true)).unwrap();
        assert_eq!(s["running"], true);
        assert_eq!(s["controller"], "127.0.0.1:9090");
        assert_eq!(s["secret"], "s3");
        assert_eq!(s["mixed_port"], 7890);
        assert_eq!(s["tun"], false);
        assert_eq!(s["manager"], VERSION);
        assert_eq!(rig.proxy.take(), ["proxy on 7890"]);
        // Off: the proxy put back before the core goes.
        let s = m.stop();
        assert_eq!(s["running"], false);
        assert_eq!(s["core"], false);
        assert_eq!(rig.proxy.take(), ["proxy off"]);
        assert_eq!(rig.core.take().last().unwrap(), "stop");
        // Kept: the next manager knows the run and the switches.
        let mut again = rig.manager();
        assert_eq!(again.saved().run, Some(rig.run()));
        assert!(again.saved().system_proxy);
        again.restart().unwrap();
        assert_eq!(rig.proxy.take(), ["proxy on 7890"]);
        assert!(m
            .start(
                Some(Run {
                    config: "rel".into(),
                    dir: "/x".into()
                }),
                None
            )
            .is_err());
    }

    #[test]
    fn switches_are_kept_and_mirrored_into_the_input() {
        let rig = Rig::new();
        let mut m = rig.manager();
        m.start(Some(rig.run()), Some(false)).unwrap();
        rig.proxy.take();
        rig.build.take();
        let s = m
            .set(Patch {
                system_proxy: Some(true),
                launch_at_login: Some(true),
                ..Patch::default()
            })
            .unwrap();
        assert_eq!(s["system_proxy"], true);
        assert_eq!(s["launch_at_login"], true);
        assert!(*rig.login.lock().unwrap());
        assert_eq!(rig.proxy.take(), ["proxy on 7890"]);
        assert_eq!(
            rig.build.take(),
            [r#"apply {"launch_at_login":true,"system_proxy":true} build=false"#]
        );
        // Off while the core does not run: kept, nothing set.
        m.stop();
        rig.proxy.take();
        m.set(Patch {
            system_proxy: Some(false),
            ..Patch::default()
        })
        .unwrap();
        assert!(rig.proxy.take().is_empty());
        assert!(!rig.manager().saved().system_proxy);
        // The user removed the login item: status says so.
        *rig.login.lock().unwrap() = false;
        assert_eq!(m.status()["launch_at_login"], false);
    }

    #[test]
    fn the_status_reads_the_config_keys_again_only_when_it_changed() {
        let rig = Rig::new();
        let mut m = rig.manager();
        let run = rig.run();
        // A config with its lines: only the four keys are taken.
        let lines: Vec<String> = (0..2000)
            .map(|i| format!(r#"{{"name":"n{i}","type":"ss","server":"s{i}","port":443}}"#))
            .collect();
        std::fs::write(
            &run.config,
            format!(
                r#"{{"proxies":[{}],"external-controller":"127.0.0.1:9090","secret":"s3","mixed-port":7890,"tun":{{"enable":false}},"rules":["MATCH,DIRECT"]}}"#,
                lines.join(",")
            ),
        )
        .unwrap();
        m.start(Some(run.clone()), Some(false)).unwrap();
        let s = m.status();
        assert_eq!(
            (&s["mixed_port"], &s["secret"], &s["tun"]),
            (&json!(7890), &json!("s3"), &json!(false))
        );
        assert_eq!(m.config().len(), 4);
        // Rewritten (another port, 虚拟网卡 on): read again.
        std::fs::write(
            &run.config,
            r#"{"external-controller":"127.0.0.1:9091","secret":"s4","mixed-port":7891,"tun":{"enable":true}}"#,
        )
        .unwrap();
        let s = m.status();
        assert_eq!(
            (&s["mixed_port"], &s["controller"], &s["tun"]),
            (&json!(7891), &json!("127.0.0.1:9091"), &json!(true))
        );
        // Not JSON (a client's YAML): none of them.
        std::fs::write(&run.config, "mixed-port: 7892\n").unwrap();
        assert_eq!(m.status()["mixed_port"], Value::Null);
        // can_tun as last asked for a moment, afresh after a switch.
        *rig.can_tun.lock().unwrap() = false;
        assert_eq!(m.status()["can_tun"], true);
        m.set(Patch::default()).unwrap();
        assert_eq!(m.status()["can_tun"], false);
    }

    #[test]
    fn boot_brings_the_core_up_with_launch_at_login() {
        let rig = Rig::new();
        let mut m = rig.manager();
        m.start(Some(rig.run()), Some(true)).unwrap();
        // Not at login: the manager comes up, the core does not.
        rig.manager().boot();
        m.set(Patch {
            launch_at_login: Some(true),
            ..Patch::default()
        })
        .unwrap();
        *rig.up.lock().unwrap() = false;
        rig.core.take();
        rig.proxy.take();
        let mut next = rig.manager();
        next.boot();
        assert_eq!(rig.proxy.take(), ["recover", "proxy on 7890"]);
        assert!(rig.core.take()[0].starts_with("start"));
        // 内核 switched off: not brought up.
        next.stop();
        rig.core.take();
        rig.manager().boot();
        assert!(rig.core.take().is_empty());
    }

    #[test]
    fn the_virtual_adapter_rebuilds_and_restarts() {
        let rig = Rig::new();
        let mut m = rig.manager();
        let run = rig.run();
        m.start(Some(run.clone()), Some(false)).unwrap();
        rig.core.take();
        *rig.can_tun.lock().unwrap() = false;
        assert_eq!(
            m.set(Patch {
                tun: Some(true),
                ..Patch::default()
            }),
            Err(Refusal::NeedsAuthorization)
        );
        *rig.can_tun.lock().unwrap() = true;
        let s = m
            .set(Patch {
                tun: Some(true),
                ..Patch::default()
            })
            .unwrap();
        assert_eq!(s["tun"], true);
        // Its API and port kept.
        assert_eq!(s["controller"], "127.0.0.1:9090");
        assert_eq!(rig.build.take(), [r#"apply {"tun":true} build=true"#]);
        assert!(rig.core.take()[0].contains(r#""tun":{"enable":true}"#));
        // Run where the adapter may be had, the input along.
        let tun_run = m.saved().run.clone().unwrap();
        assert!(tun_run.dir.ends_with("core-service"));
        assert_eq!(s["dir"], tun_run.dir.display().to_string());
        // The same again: nothing.
        m.set(Patch {
            tun: Some(true),
            ..Patch::default()
        })
        .unwrap();
        assert!(rig.build.take().is_empty());
        // The core refuses the config without it: the old one back, running.
        *rig.refuse.lock().unwrap() = Some(r#""enable":false"#.into());
        let r = m.set(Patch {
            tun: Some(false),
            ..Patch::default()
        });
        assert!(matches!(r, Err(Refusal::Failed(_))));
        assert!(std::fs::read_to_string(&tun_run.config)
            .unwrap()
            .contains(r#""enable":true"#));
        assert_eq!(m.saved().run.as_ref(), Some(&tun_run));
        assert_eq!(m.status()["running"], true);
        let _ = run;
        assert_eq!(
            rig.build.take(),
            [
                r#"apply {"tun":false} build=true"#,
                r#"apply {"tun":true} build=false"#
            ]
        );
    }

    #[test]
    fn a_config_is_placed_by_its_virtual_adapter() {
        let rig = Rig::new();
        let mut m = rig.manager();
        let s = m
            .start_config(&json!({"mixed-port": 7891, "secret": "x"}), Some(true))
            .unwrap();
        assert!(s["dir"].as_str().unwrap().ends_with("meow"));
        assert_eq!(rig.proxy.take(), ["proxy on 7891"]);
        let s = m
            .start_config(&json!({"mixed-port": 7891, "tun": {"enable": true}}), None)
            .unwrap();
        assert!(s["dir"].as_str().unwrap().ends_with("core-service"));
        assert_eq!(s["tun"], true);
        assert!(m.start_config(&json!([1]), None).is_err());
    }

    #[test]
    fn a_core_that_ends_leaves_no_proxy_behind() {
        let rig = Rig::new();
        let mut m = rig.manager();
        m.start(Some(rig.run()), Some(true)).unwrap();
        rig.proxy.take();
        m.watch();
        assert!(rig.proxy.take().is_empty());
        *rig.up.lock().unwrap() = false;
        m.watch();
        assert_eq!(rig.proxy.take(), ["proxy off"]);
        m.watch();
        assert!(rig.proxy.take().is_empty());
        // Shut down: switches kept for the next start.
        m.shutdown();
        assert!(rig.manager().saved().core);
    }
}
