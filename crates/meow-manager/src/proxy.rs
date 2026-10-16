//! The OS proxy settings pointed at the core's port while it runs, and put
//! back exactly as they were — also after a crash: what was there before is
//! kept in the state file until it is restored. The port of the app's
//! `packages/paopao_proxy/lib/src/system_proxy.dart` (the same state file
//! format, so either side can put back what the other saved).
//!
//! - macOS: `networksetup` for every network service (web, secure web,
//!   SOCKS, the bypass list); works as root (the manager's launchd daemon)
//!   and as the user.
//! - Linux: GNOME's `gsettings` and KDE's `kwriteconfig5/6` (kioslaverc,
//!   then a D-Bus signal so running programs read it again), whichever is
//!   there; run as the user (the manager is the user's systemd service).
//! - Windows: the user's Internet Settings in the registry (`reg`).
//!
//! Commands go through [`Commands`]: tests give their own, nothing here
//! spawns a process by itself.

use serde_json::{json, Map, Value};
use std::path::{Path, PathBuf};
use std::sync::Arc;

/// Runs OS commands for [`SystemProxy`].
pub trait Commands: Send + Sync {
    /// The command's output (trimmed) when it ran and exited with 0.
    fn out(&self, exe: &str, args: &[&str]) -> Option<String>;

    /// Whether it ran and exited with 0.
    fn ok(&self, exe: &str, args: &[&str]) -> bool {
        self.out(exe, args).is_some()
    }
}

/// Which system's settings.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Os {
    Linux,
    MacOs,
    Windows,
    /// Nothing to set (phones, routers).
    Other,
}

impl Os {
    pub fn current() -> Os {
        if cfg!(target_os = "macos") {
            Os::MacOs
        } else if cfg!(target_os = "linux") && !cfg!(target_os = "android") {
            Os::Linux
        } else if cfg!(windows) {
            Os::Windows
        } else {
            Os::Other
        }
    }
}

/// Hosts that never go through the proxy (as the app's `bypassHosts`).
pub const BYPASS: [&str; 7] = [
    "localhost",
    "127.0.0.0/8",
    "::1",
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "*.local",
];

const NETWORKSETUP: &str = "/usr/sbin/networksetup";
const INET: &str = r"HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings";

const GNOME_KEYS: [(&str, &str); 8] = [
    ("org.gnome.system.proxy", "mode"),
    ("org.gnome.system.proxy", "ignore-hosts"),
    ("org.gnome.system.proxy.http", "host"),
    ("org.gnome.system.proxy.http", "port"),
    ("org.gnome.system.proxy.https", "host"),
    ("org.gnome.system.proxy.https", "port"),
    ("org.gnome.system.proxy.socks", "host"),
    ("org.gnome.system.proxy.socks", "port"),
];
const KDE_KEYS: [&str; 5] = [
    "ProxyType",
    "httpProxy",
    "httpsProxy",
    "socksProxy",
    "NoProxyFor",
];

/// (kind, get, set, set state) of `networksetup`.
const MAC_KINDS: [(&str, &str, &str, &str); 3] = [
    ("web", "-getwebproxy", "-setwebproxy", "-setwebproxystate"),
    (
        "secureweb",
        "-getsecurewebproxy",
        "-setsecurewebproxy",
        "-setsecurewebproxystate",
    ),
    (
        "socks",
        "-getsocksfirewallproxy",
        "-setsocksfirewallproxy",
        "-setsocksfirewallproxystate",
    ),
];

pub struct SystemProxy {
    state: PathBuf,
    os: Os,
    run: Arc<dyn Commands>,
    /// KDE 5's tools (`kwriteconfig5`) rather than 6's.
    kde5: bool,
}

impl SystemProxy {
    pub fn new(state: PathBuf, os: Os, run: Arc<dyn Commands>, kde5: bool) -> SystemProxy {
        SystemProxy {
            state,
            os,
            run,
            kde5,
        }
    }

    pub fn supported(&self) -> bool {
        self.os != Os::Other
    }

    pub fn state_file(&self) -> &Path {
        &self.state
    }

    /// The proxy set to 127.0.0.1:`port` (HTTP, HTTPS and SOCKS). What was
    /// there is saved first; enabling twice keeps the first save (never our
    /// own values as "before").
    pub fn enable(&self, port: u16) -> std::io::Result<()> {
        if !self.supported() {
            return Ok(());
        }
        let saved = match self.read_state() {
            Some(s) => s,
            None => self.capture(),
        };
        self.write_state(&saved)?;
        match self.os {
            Os::Linux => self.linux_set(port),
            Os::MacOs => self.mac_set(port, &saved),
            Os::Windows => self.windows_set(port),
            Os::Other => {}
        }
        Ok(())
    }

    /// What was there before [`Self::enable`] put back; nothing saved,
    /// nothing done. Safe at any time.
    pub fn disable(&self) {
        let Some(saved) = self.read_state() else {
            return;
        };
        match self.os {
            Os::Linux => self.linux_restore(&saved),
            Os::MacOs => self.mac_restore(&saved),
            Os::Windows => self.windows_restore(&saved),
            Os::Other => {}
        }
        let _ = std::fs::remove_file(&self.state);
    }

    /// A state left behind (the manager or the core died while the proxy
    /// pointed at it): put back. True when there was one.
    pub fn recover(&self) -> bool {
        if self.read_state().is_none() {
            return false;
        }
        self.disable();
        true
    }

    fn read_state(&self) -> Option<Map<String, Value>> {
        let bytes = std::fs::read(&self.state).ok()?;
        match serde_json::from_slice(&bytes).ok()? {
            Value::Object(m) => Some(m),
            _ => None,
        }
    }

    fn write_state(&self, state: &Map<String, Value>) -> std::io::Result<()> {
        if let Some(dir) = self.state.parent() {
            std::fs::create_dir_all(dir)?;
        }
        let tmp = self.state.with_extension("json.tmp");
        std::fs::write(&tmp, serde_json::to_vec(state)?)?;
        std::fs::rename(&tmp, &self.state)
    }

    fn capture(&self) -> Map<String, Value> {
        match self.os {
            Os::Linux => self.linux_capture(),
            Os::MacOs => self.mac_capture(),
            Os::Windows => self.windows_capture(),
            Os::Other => Map::new(),
        }
    }

    // ------------------------------------------------------------- Linux

    fn kde_write_tool(&self) -> &'static str {
        if self.kde5 {
            "kwriteconfig5"
        } else {
            "kwriteconfig6"
        }
    }

    fn kde_read_tool(&self) -> &'static str {
        if self.kde5 {
            "kreadconfig5"
        } else {
            "kreadconfig6"
        }
    }

    fn linux_capture(&self) -> Map<String, Value> {
        let mut gnome = Map::new();
        for (schema, key) in GNOME_KEYS {
            if let Some(v) = self.run.out("gsettings", &["get", schema, key]) {
                gnome.insert(format!("{schema} {key}"), v.into());
            }
        }
        let mut kde = Map::new();
        for key in KDE_KEYS {
            let args = [
                "--file",
                "kioslaverc",
                "--group",
                "Proxy Settings",
                "--key",
                key,
            ];
            if let Some(v) = self.run.out(self.kde_read_tool(), &args) {
                kde.insert(key.into(), v.into());
            }
        }
        let mut m = Map::new();
        m.insert("gnome".into(), Value::Object(gnome));
        m.insert("kde".into(), Value::Object(kde));
        m
    }

    fn linux_set(&self, port: u16) {
        let hosts = format!(
            "[{}]",
            BYPASS
                .iter()
                .map(|h| format!("'{h}'"))
                .collect::<Vec<_>>()
                .join(", ")
        );
        let port_s = port.to_string();
        let values = [
            ("org.gnome.system.proxy", "mode", "'manual'"),
            ("org.gnome.system.proxy", "ignore-hosts", hosts.as_str()),
            ("org.gnome.system.proxy.http", "host", "'127.0.0.1'"),
            ("org.gnome.system.proxy.http", "port", port_s.as_str()),
            ("org.gnome.system.proxy.https", "host", "'127.0.0.1'"),
            ("org.gnome.system.proxy.https", "port", port_s.as_str()),
            ("org.gnome.system.proxy.socks", "host", "'127.0.0.1'"),
            ("org.gnome.system.proxy.socks", "port", port_s.as_str()),
        ];
        for (schema, key, value) in values {
            self.run.ok("gsettings", &["set", schema, key, value]);
        }
        let http = format!("http://127.0.0.1 {port}");
        let socks = format!("socks://127.0.0.1 {port}");
        let no_proxy = BYPASS.join(",");
        let ok = self.kde_write(&[
            ("ProxyType", "1"),
            ("httpProxy", &http),
            ("httpsProxy", &http),
            ("socksProxy", &socks),
            ("NoProxyFor", &no_proxy),
        ]);
        if ok {
            self.kde_notify();
        }
    }

    fn kde_write(&self, values: &[(&str, &str)]) -> bool {
        let mut ok = true;
        for (key, value) in values {
            let args = [
                "--file",
                "kioslaverc",
                "--group",
                "Proxy Settings",
                "--key",
                key,
                value,
            ];
            ok &= self.run.ok(self.kde_write_tool(), &args);
        }
        ok
    }

    fn kde_notify(&self) {
        self.run.ok(
            "dbus-send",
            &[
                "--type=signal",
                "/KIO/Scheduler",
                "org.kde.KIO.Scheduler.reparseSlaveConfiguration",
                "string:",
            ],
        );
    }

    fn linux_restore(&self, saved: &Map<String, Value>) {
        if let Some(Value::Object(gnome)) = saved.get("gnome") {
            for (k, v) in gnome {
                let Some((schema, key)) = k.split_once(' ') else {
                    continue;
                };
                self.run.ok("gsettings", &["set", schema, key, &text(v)]);
            }
        }
        if let Some(Value::Object(kde)) = saved.get("kde") {
            if !kde.is_empty() {
                let values: Vec<(String, String)> = KDE_KEYS
                    .iter()
                    .map(|k| {
                        let v = kde.get(*k).map_or_else(
                            || {
                                if *k == "ProxyType" {
                                    "0".into()
                                } else {
                                    String::new()
                                }
                            },
                            text,
                        );
                        ((*k).to_owned(), v)
                    })
                    .collect();
                let pairs: Vec<(&str, &str)> = values
                    .iter()
                    .map(|(k, v)| (k.as_str(), v.as_str()))
                    .collect();
                self.kde_write(&pairs);
                self.kde_notify();
            }
        }
    }

    // ------------------------------------------------------------- macOS

    fn mac_services(&self) -> Vec<String> {
        let Some(out) = self.run.out(NETWORKSETUP, &["-listallnetworkservices"]) else {
            return Vec::new();
        };
        out.lines()
            .skip(1)
            .map(str::trim)
            .filter(|l| !l.is_empty() && !l.starts_with('*'))
            .map(str::to_owned)
            .collect()
    }

    fn mac_capture(&self) -> Map<String, Value> {
        let mut services = Map::new();
        for s in self.mac_services() {
            let mut kinds = Map::new();
            for (kind, get, _, _) in MAC_KINDS {
                let out = self.run.out(NETWORKSETUP, &[get, &s]).unwrap_or_default();
                let field = |name: &str| {
                    out.lines()
                        .find_map(|l| l.strip_prefix(&format!("{name}: ")))
                        .unwrap_or_default()
                        .to_owned()
                };
                kinds.insert(
                    kind.into(),
                    json!({
                        "enabled": field("Enabled") == "Yes",
                        "server": field("Server"),
                        "port": field("Port"),
                    }),
                );
            }
            let bypass = self.run.out(NETWORKSETUP, &["-getproxybypassdomains", &s]);
            kinds.insert("bypass".into(), bypass.map_or(Value::Null, Value::String));
            services.insert(s, Value::Object(kinds));
        }
        let mut m = Map::new();
        m.insert("services".into(), Value::Object(services));
        m
    }

    fn mac_set(&self, port: u16, saved: &Map<String, Value>) {
        let port = port.to_string();
        let Some(Value::Object(services)) = saved.get("services") else {
            return;
        };
        for s in services.keys() {
            for (_, _, set, _) in MAC_KINDS {
                self.run.ok(NETWORKSETUP, &[set, s, "127.0.0.1", &port]);
            }
            let mut args = vec!["-setproxybypassdomains", s.as_str()];
            args.extend(BYPASS);
            self.run.ok(NETWORKSETUP, &args);
        }
    }

    fn mac_restore(&self, saved: &Map<String, Value>) {
        let Some(Value::Object(services)) = saved.get("services") else {
            return;
        };
        for (s, kinds) in services {
            for (kind, _, set, state) in MAC_KINDS {
                let was = kinds.get(kind);
                let enabled = was
                    .and_then(|w| w.get("enabled"))
                    .and_then(Value::as_bool)
                    .unwrap_or(false);
                let server = was
                    .and_then(|w| w.get("server"))
                    .map(text)
                    .unwrap_or_default();
                let port = was
                    .and_then(|w| w.get("port"))
                    .map(text)
                    .unwrap_or_default();
                if enabled && !server.is_empty() {
                    self.run.ok(NETWORKSETUP, &[set, s, &server, &port]);
                } else {
                    self.run.ok(NETWORKSETUP, &[state, s, "off"]);
                }
            }
            let bypass = kinds.get("bypass").and_then(Value::as_str);
            let domains: Vec<&str> = match bypass {
                None => vec!["Empty"],
                Some(b) if b.contains("There aren't any") => vec!["Empty"],
                Some(b) => b.lines().collect(),
            };
            let mut args = vec!["-setproxybypassdomains", s.as_str()];
            args.extend(domains);
            self.run.ok(NETWORKSETUP, &args);
        }
    }

    // ----------------------------------------------------------- Windows

    fn windows_capture(&self) -> Map<String, Value> {
        let value = |name: &str| -> Value {
            let Some(out) = self.run.out("reg", &["query", INET, "/v", name]) else {
                return Value::Null;
            };
            out.lines()
                .find_map(|l| {
                    let mut parts = l.split_whitespace();
                    (parts.next() == Some(name)).then(|| {
                        let _type = parts.next();
                        parts.collect::<Vec<_>>().join(" ")
                    })
                })
                .map_or(Value::Null, Value::String)
        };
        let mut m = Map::new();
        for name in ["ProxyEnable", "ProxyServer", "ProxyOverride"] {
            m.insert(name.into(), value(name));
        }
        m
    }

    fn windows_set(&self, port: u16) {
        let server = format!("127.0.0.1:{port}");
        let bypass: Vec<&str> = BYPASS
            .iter()
            .copied()
            .filter(|h| !h.contains('/'))
            .collect();
        let over = format!("{};<local>", bypass.join(";"));
        let add = |name: &str, kind: &str, data: &str| {
            self.run.ok(
                "reg",
                &["add", INET, "/v", name, "/t", kind, "/d", data, "/f"],
            );
        };
        add("ProxyEnable", "REG_DWORD", "1");
        add("ProxyServer", "REG_SZ", &server);
        add("ProxyOverride", "REG_SZ", &over);
    }

    fn windows_restore(&self, saved: &Map<String, Value>) {
        let enable = saved.get("ProxyEnable").map(text).unwrap_or_default();
        let on = if enable == "0x1" || enable == "1" {
            "1"
        } else {
            "0"
        };
        self.run.ok(
            "reg",
            &[
                "add",
                INET,
                "/v",
                "ProxyEnable",
                "/t",
                "REG_DWORD",
                "/d",
                on,
                "/f",
            ],
        );
        for name in ["ProxyServer", "ProxyOverride"] {
            match saved.get(name) {
                None | Some(Value::Null) => {
                    self.run.ok("reg", &["delete", INET, "/v", name, "/f"]);
                }
                Some(v) => {
                    self.run.ok(
                        "reg",
                        &[
                            "add",
                            INET,
                            "/v",
                            name,
                            "/t",
                            "REG_SZ",
                            "/d",
                            &text(v),
                            "/f",
                        ],
                    );
                }
            }
        }
    }
}

/// A saved value as text (strings as they are).
fn text(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        Value::Null => String::new(),
        other => other.to_string(),
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::sync::Mutex;

    /// Answers by `exe args…` prefix, records every call.
    #[derive(Default)]
    pub struct FakeCommands {
        pub answers: Mutex<HashMap<String, String>>,
        pub calls: Mutex<Vec<String>>,
    }

    impl FakeCommands {
        pub fn answer(&self, cmd: &str, out: &str) {
            self.answers
                .lock()
                .unwrap()
                .insert(cmd.to_owned(), out.to_owned());
        }

        pub fn take(&self) -> Vec<String> {
            std::mem::take(&mut *self.calls.lock().unwrap())
        }
    }

    impl Commands for FakeCommands {
        fn out(&self, exe: &str, args: &[&str]) -> Option<String> {
            let line = std::iter::once(exe)
                .chain(args.iter().copied())
                .collect::<Vec<_>>()
                .join(" ");
            self.calls.lock().unwrap().push(line.clone());
            let answers = self.answers.lock().unwrap();
            match answers.get(&line) {
                Some(a) => Some(a.clone()),
                // Setters succeed; getters without an answer find nothing.
                None if line.contains(" get")
                    || line.contains("query")
                    || line.contains("kread") =>
                {
                    None
                }
                None => Some(String::new()),
            }
        }
    }

    fn proxy(os: Os) -> (tempfile::TempDir, Arc<FakeCommands>, SystemProxy) {
        let d = tempfile::tempdir().unwrap();
        let run = Arc::new(FakeCommands::default());
        let p = SystemProxy::new(
            d.path().join("system-proxy.json"),
            os,
            Arc::clone(&run) as _,
            false,
        );
        (d, run, p)
    }

    #[test]
    fn macos_saves_sets_and_puts_back() {
        let (_d, run, p) = proxy(Os::MacOs);
        run.answer(
            "/usr/sbin/networksetup -listallnetworkservices",
            "An asterisk (*) denotes that a network service is disabled.\nWi-Fi\n*Bluetooth PAN",
        );
        run.answer(
            "/usr/sbin/networksetup -getwebproxy Wi-Fi",
            "Enabled: Yes\nServer: corp\nPort: 8080",
        );
        run.answer(
            "/usr/sbin/networksetup -getproxybypassdomains Wi-Fi",
            "There aren't any bypass domains set on Wi-Fi.",
        );
        p.enable(7890).unwrap();
        let calls = run.take();
        assert!(
            calls.contains(&"/usr/sbin/networksetup -setwebproxy Wi-Fi 127.0.0.1 7890".to_string())
        );
        assert!(calls.contains(
            &"/usr/sbin/networksetup -setsocksfirewallproxy Wi-Fi 127.0.0.1 7890".to_string()
        ));
        assert!(!calls.iter().any(|c| c.contains("Bluetooth")));
        // Enabled again: the first save is kept (not our own values).
        run.answer(
            "/usr/sbin/networksetup -getwebproxy Wi-Fi",
            "Enabled: Yes\nServer: 127.0.0.1\nPort: 7890",
        );
        p.enable(7890).unwrap();
        run.take();
        p.disable();
        let calls = run.take();
        assert!(calls.contains(&"/usr/sbin/networksetup -setwebproxy Wi-Fi corp 8080".to_string()));
        assert!(
            calls.contains(&"/usr/sbin/networksetup -setsecurewebproxystate Wi-Fi off".to_string())
        );
        assert!(calls
            .contains(&"/usr/sbin/networksetup -setproxybypassdomains Wi-Fi Empty".to_string()));
        assert!(!p.state_file().exists());
        // Nothing saved: nothing done.
        p.disable();
        assert!(run.take().is_empty());
        assert!(!p.recover());
    }

    #[test]
    fn linux_gnome_and_kde() {
        let (_d, run, p) = proxy(Os::Linux);
        run.answer("gsettings get org.gnome.system.proxy mode", "'none'");
        run.answer(
            "kreadconfig6 --file kioslaverc --group Proxy Settings --key ProxyType",
            "0",
        );
        p.enable(7890).unwrap();
        let calls = run.take();
        assert!(calls.contains(&"gsettings set org.gnome.system.proxy mode 'manual'".to_string()));
        assert!(calls.contains(&"gsettings set org.gnome.system.proxy.http port 7890".to_string()));
        assert!(calls.contains(
            &"kwriteconfig6 --file kioslaverc --group Proxy Settings --key httpProxy http://127.0.0.1 7890"
                .to_string()
        ));
        assert!(calls.iter().any(|c| c.starts_with("dbus-send")));
        // A crash: the next start puts it back.
        assert!(p.recover());
        let calls = run.take();
        assert!(calls.contains(&"gsettings set org.gnome.system.proxy mode 'none'".to_string()));
        assert!(calls.contains(
            &"kwriteconfig6 --file kioslaverc --group Proxy Settings --key ProxyType 0".to_string()
        ));
        assert!(calls.contains(
            &"kwriteconfig6 --file kioslaverc --group Proxy Settings --key httpProxy ".to_string()
        ));
    }

    #[test]
    fn windows_registry() {
        let (_d, run, p) = proxy(Os::Windows);
        run.answer(
            &format!("reg query {INET} /v ProxyEnable"),
            &format!("\r\n{INET}\r\n    ProxyEnable    REG_DWORD    0x0\r\n"),
        );
        p.enable(7890).unwrap();
        let calls = run.take();
        assert!(calls.contains(&format!(
            "reg add {INET} /v ProxyServer /t REG_SZ /d 127.0.0.1:7890 /f"
        )));
        assert!(calls.contains(&format!(
            "reg add {INET} /v ProxyOverride /t REG_SZ /d localhost;::1;*.local;<local> /f"
        )));
        p.disable();
        let calls = run.take();
        assert!(calls.contains(&format!(
            "reg add {INET} /v ProxyEnable /t REG_DWORD /d 0 /f"
        )));
        assert!(calls.contains(&format!("reg delete {INET} /v ProxyServer /f")));
    }

    #[test]
    fn the_app_s_state_file_is_read() {
        // As system_proxy.dart writes it (values are strings).
        let (_d, run, p) = proxy(Os::Windows);
        std::fs::write(
            p.state_file(),
            r#"{"ProxyEnable":"0x1","ProxyServer":"corp:3128","ProxyOverride":null}"#,
        )
        .unwrap();
        p.disable();
        let calls = run.take();
        assert!(calls.contains(&format!(
            "reg add {INET} /v ProxyEnable /t REG_DWORD /d 1 /f"
        )));
        assert!(calls.contains(&format!(
            "reg add {INET} /v ProxyServer /t REG_SZ /d corp:3128 /f"
        )));
        assert!(calls.contains(&format!("reg delete {INET} /v ProxyOverride /f")));
    }
}
