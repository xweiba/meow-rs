//! The network the core is on, watched the way the app watches it (Dart
//! `NetworkWatcher` and `ProxyController.setNetwork`) so the per-network
//! settings follow with the app closed:
//!
//! - every [`WATCH_EVERY`] the kind and Wi-Fi name are asked of the system
//!   (Linux `nmcli`, macOS `ipconfig getsummary` with `wdutil` / the
//!   authorized service for a redacted name, Windows `netsh`; elsewhere
//!   unknown) and this machine's addresses listed;
//! - when that differs from the network the config was built for (the
//!   input's, then each one applied here; `network.json`), the input's
//!   `network` and `ipv6` are replaced and the config rebuilt, run when it
//!   differs (rules, hosts and the mode per network; IPv6). A Wi-Fi name
//!   the system hides from the core does not count as a change;
//! - IPv6 is tried once per network with a global address (a connection
//!   to two public IPv6 resolvers within two seconds); failing, the config
//!   is built without it.
//!
//! The look holds a few strings; the commands are short-lived children.
//! Off until told (`PUT /paopao/schedule` with `network`).

use std::sync::Arc;
use std::time::Duration;

use futures::future::BoxFuture;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::service::{now_ms, Service};
use super::store::{write_atomic, Store};

/// How often the system is asked (Dart `NetworkWatcher.interval`).
pub const WATCH_EVERY: Duration = Duration::from_secs(10);
/// The macOS authorized service (Dart `MacService.socket`).
const MAC_SERVICE_SOCKET: &str = "/var/run/paopao-core.sock";

/// A network as the build input names it (Dart `NetworkInfo`: `{kind,
/// ssid?, addresses}`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Net {
    /// wifi | ethernet | cellular | none | unknown
    pub kind: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ssid: Option<String>,
    #[serde(default)]
    pub addresses: Vec<String>,
}

impl Net {
    pub fn unknown() -> Self {
        Self {
            kind: "unknown".into(),
            ssid: None,
            addresses: Vec::new(),
        }
    }

    /// A public IPv6 address (2000::/3) here.
    pub fn has_global_ipv6(&self) -> bool {
        self.addresses.iter().any(|a| {
            let a = a.split('/').next().unwrap_or(a);
            let a = a.split('%').next().unwrap_or(a);
            matches!(a.parse::<std::net::IpAddr>(),
                Ok(std::net::IpAddr::V6(v6)) if (v6.octets()[0] & 0xE0) == 0x20)
        })
    }

    /// `seen` names the same network as this one: the same, or the same
    /// but for a Wi-Fi name the system hid from the core.
    pub fn same_as(&self, seen: &Self) -> bool {
        self == seen
            || (seen.ssid.is_none() && self.kind == seen.kind && self.addresses == seen.addresses)
    }
}

/// `network.json`.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct NetworkFile {
    /// The network the running config is built for.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub network: Option<Net>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ipv6: Option<bool>,
    /// The network IPv6 was tried on, and whether it worked.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ipv6_tried: Option<(Net, bool)>,
    /// When the core last applied a network change, Unix ms.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub changed: Option<i64>,
    /// Why that rebuild failed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_error: Option<String>,
}

impl NetworkFile {
    pub fn read(store: &Store) -> Self {
        std::fs::read(store.network())
            .ok()
            .and_then(|b| serde_json::from_slice(&b).ok())
            .unwrap_or_default()
    }

    pub fn write(&self, store: &Store) -> std::io::Result<()> {
        let bytes = serde_json::to_vec(self).map_err(std::io::Error::other)?;
        write_atomic(&store.network(), &bytes, false)
    }
}

/// The network now.
pub type Look = Arc<dyn Fn() -> BoxFuture<'static, Net> + Send + Sync>;
/// Whether IPv6 goes out.
pub type TryIpv6 = Arc<dyn Fn() -> BoxFuture<'static, bool> + Send + Sync>;

/// What the config is built with on `n` (Dart `ProxyController.ipv6`):
/// IPv6 unless the network has addresses and no working global one.
fn ipv6_for(n: &Net, tried: Option<&(Net, bool)>) -> bool {
    n.addresses.is_empty() || (n.has_global_ipv6() && !matches!(tried, Some((t, false)) if t == n))
}

impl Service {
    /// The input's network as handed over: what the config is built for.
    pub(super) fn network_handed(&self, network: Option<Value>, ipv6: Option<bool>) {
        let mut f = NetworkFile::read(self.store());
        f.network = network.and_then(|v| serde_json::from_value(v).ok());
        f.ipv6 = ipv6;
        f.last_error = None;
        let _ = f.write(self.store());
    }

    /// One look: the network now, applied when it changed. True when the
    /// config was rebuilt for it.
    pub async fn watch_network_once(&self) -> bool {
        let watch = self.network_watch();
        let seen = (watch.0)().await;
        let mut f = NetworkFile::read(self.store());
        let Some(was) = f.network.clone() else {
            // Nothing handed over: nothing to compare with.
            return false;
        };
        if was.same_as(&seen) {
            // IPv6 not tried here yet.
            let tried = f.ipv6_tried.as_ref().is_some_and(|(t, _)| *t == was);
            if !was.has_global_ipv6() || tried {
                return false;
            }
        }
        let now = if was.same_as(&seen) {
            was.clone()
        } else {
            seen
        };
        if now.has_global_ipv6() && f.ipv6_tried.as_ref().is_none_or(|(t, _)| *t != now) {
            let works = (watch.1)().await;
            f.ipv6_tried = Some((now.clone(), works));
        }
        let ipv6 = ipv6_for(&now, f.ipv6_tried.as_ref());
        if now == was && Some(ipv6) == f.ipv6 {
            let _ = f.write(self.store());
            return false;
        }
        let mut set = serde_json::Map::new();
        set.insert(
            "network".into(),
            serde_json::to_value(&now).unwrap_or(Value::Null),
        );
        set.insert("ipv6".into(), ipv6.into());
        match self.apply_set(set).await {
            Ok(r) => {
                f.last_error = r.error;
            }
            Err(e) => f.last_error = Some(e.to_string()),
        }
        f.network = Some(now);
        f.ipv6 = Some(ipv6);
        f.changed = Some(now_ms());
        let _ = f.write(self.store());
        true
    }

    /// `GET /paopao/network`.
    pub fn network_answer(&self) -> Value {
        let f = NetworkFile::read(self.store());
        serde_json::json!({
            "network": f.network,
            "ipv6": f.ipv6,
            "changed": f.changed,
            "last_error": f.last_error,
        })
    }
}

/// Watches the network while the schedule says so. Runs for good: spawn
/// it.
pub async fn run_network(svc: Arc<Service>) {
    loop {
        let on = svc.schedule().await.network && svc.can_run();
        if on {
            svc.watch_network_once().await;
        }
        tokio::select! {
            () = tokio::time::sleep(svc.watch_every()) => {}
            () = svc.network_woken() => {}
        }
    }
}

/// The system's answer: the kind and name by the OS's tools, and the
/// addresses.
pub fn real_look() -> Look {
    Arc::new(|| {
        Box::pin(async {
            let (kind, ssid) = kind_and_name().await;
            let mut addresses: Vec<String> = meow_common::host_addrs::host_addresses()
                .iter()
                .map(ToString::to_string)
                .collect();
            addresses.sort();
            Net {
                kind: kind.into(),
                ssid,
                addresses,
            }
        })
    })
}

/// Dart `reachesIpv6`: a TCP connection to Alibaba's or Tencent's public
/// IPv6 resolver within two seconds.
pub fn real_try_ipv6() -> TryIpv6 {
    Arc::new(|| {
        Box::pin(async {
            let dial = |ip: &'static str| async move {
                let addr: std::net::SocketAddr = (ip.parse::<std::net::IpAddr>().ok()?, 53).into();
                tokio::time::timeout(Duration::from_secs(2), tokio::net::TcpStream::connect(addr))
                    .await
                    .ok()?
                    .ok()
            };
            let (a, b) = tokio::join!(dial("2400:3200::1"), dial("2402:4e00::"));
            a.is_some() || b.is_some()
        })
    })
}

/// A command's output when it exits 0.
async fn out(exe: &str, args: &[&str]) -> Option<String> {
    let mut c = tokio::process::Command::new(exe);
    c.args(args)
        .stdin(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .kill_on_drop(true);
    #[cfg(windows)]
    c.creation_flags(0x0800_0000); // CREATE_NO_WINDOW
    let o = tokio::time::timeout(Duration::from_secs(5), c.output())
        .await
        .ok()?
        .ok()?;
    o.status
        .success()
        .then(|| String::from_utf8_lossy(&o.stdout).into_owned())
}

/// The first `^\s*<key> : (.+)$` (`netsh`, `ipconfig getsummary`).
fn field(text: &str, key: &str) -> Option<String> {
    text.lines().find_map(|l| {
        let rest = l.trim_start().strip_prefix(key)?;
        let rest = rest.trim_start().strip_prefix(':')?;
        let v = rest.trim();
        (!v.is_empty()).then(|| v.to_owned())
    })
}

/// Linux: `nmcli`'s active Wi-Fi line (`yes:<name>`, `\:` for a colon).
pub fn nmcli_wifi(text: &str) -> Option<String> {
    text.lines()
        .find_map(|l| l.strip_prefix("yes:"))
        .map(|n| n.replace("\\:", ":"))
        .filter(|n| !n.is_empty())
}

/// macOS: the Wi-Fi port's device in `networksetup -listallhardwareports`.
pub fn wifi_device_of(ports: &str) -> Option<String> {
    let mut lines = ports.lines();
    while let Some(l) = lines.next() {
        if matches!(
            l.trim_end(),
            "Hardware Port: Wi-Fi" | "Hardware Port: AirPort"
        ) {
            let dev = lines
                .next()?
                .strip_prefix("Device: ")?
                .split_whitespace()
                .next()?;
            return Some(dev.to_owned());
        }
    }
    None
}

async fn kind_and_name() -> (&'static str, Option<String>) {
    if cfg!(target_os = "linux") {
        let wifi = out("nmcli", &["-t", "-f", "ACTIVE,SSID", "dev", "wifi"]).await;
        if let Some(name) = wifi.as_deref().and_then(nmcli_wifi) {
            return ("wifi", Some(name));
        }
        let Some(devs) = out("nmcli", &["-t", "-f", "TYPE,STATE", "dev"]).await else {
            return ("unknown", None);
        };
        if devs.contains("ethernet:connected") {
            return ("ethernet", None);
        }
        if devs.contains("gsm:connected") {
            return ("cellular", None);
        }
        return ("none", None);
    }
    if cfg!(target_os = "macos") {
        let route = out("route", &["-n", "get", "default"]).await;
        let dev = route
            .as_deref()
            .and_then(|r| field(r, "interface"))
            .filter(|d| d.starts_with("en"));
        let dev = match dev {
            Some(d) => d,
            None => out("networksetup", &["-listallhardwareports"])
                .await
                .as_deref()
                .and_then(wifi_device_of)
                .unwrap_or_else(|| "en0".into()),
        };
        let summary = out("ipconfig", &["getsummary", &dev]).await;
        let ssid = summary.as_deref().and_then(|s| field(s, "SSID"));
        if let Some(name) = ssid.filter(|n| n != "<redacted>") {
            return ("wifi", Some(name));
        }
        let Some(summary) = summary else {
            return ("unknown", None);
        };
        if summary.contains("InterfaceType : WiFi") {
            return ("wifi", mac_wifi_name().await);
        }
        if summary.contains("InterfaceType : Ethernet") {
            return ("ethernet", None);
        }
        return ("unknown", None);
    }
    if cfg!(windows) {
        let Some(o) = out("netsh", &["wlan", "show", "interfaces"]).await else {
            return ("unknown", None);
        };
        let state = field(&o, "State");
        let ssid = field(&o, "SSID");
        if state.as_deref().and_then(|s| s.split_whitespace().next()) == Some("connected") {
            if let Some(name) = ssid {
                return ("wifi", Some(name));
            }
        }
        return ("unknown", None);
    }
    ("unknown", None)
}

/// macOS hides the name from programs without Location permission:
/// `wdutil` reads it as root (the core run by the authorized service),
/// else the service is asked (`service-call --op wifi`).
async fn mac_wifi_name() -> Option<String> {
    let name = |text: &str| {
        let v: Value = serde_json::from_str(text.trim()).ok()?;
        (v.get("ok") == Some(&Value::Bool(true)))
            .then(|| v.get("ssid")?.as_str().map(str::trim).map(str::to_owned))
            .flatten()
            .filter(|s| !s.is_empty())
    };
    if !std::path::Path::new(MAC_SERVICE_SOCKET).exists() {
        return None;
    }
    let exe = std::env::current_exe().ok()?;
    let exe = exe.to_str()?;
    let o = out(
        exe,
        &[
            "service-call",
            "--socket",
            MAC_SERVICE_SOCKET,
            "--op",
            "wifi",
        ],
    )
    .await?;
    name(&o)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn net(kind: &str, ssid: Option<&str>, addrs: &[&str]) -> Net {
        Net {
            kind: kind.into(),
            ssid: ssid.map(Into::into),
            addresses: addrs.iter().map(|a| (*a).to_owned()).collect(),
        }
    }

    #[test]
    fn a_hidden_name_is_the_same_network() {
        let home = net("wifi", Some("home"), &["192.168.1.2"]);
        assert!(home.same_as(&net("wifi", None, &["192.168.1.2"])));
        assert!(!home.same_as(&net("wifi", Some("cafe"), &["192.168.1.2"])));
        assert!(!home.same_as(&net("wifi", None, &["10.0.0.2"])));
        assert!(!home.same_as(&net("ethernet", None, &["192.168.1.2"])));
    }

    #[test]
    fn ipv6_follows_the_app() {
        let v4 = net("wifi", None, &["192.168.1.2"]);
        let v6 = net("wifi", None, &["192.168.1.2", "2409:8a00::5"]);
        let ula = net("wifi", None, &["fd00::5"]);
        assert!(ipv6_for(&Net::unknown(), None));
        assert!(!ipv6_for(&v4, None));
        assert!(!ipv6_for(&ula, None));
        assert!(ipv6_for(&v6, None));
        assert!(ipv6_for(&v6, Some(&(v6.clone(), true))));
        assert!(!ipv6_for(&v6, Some(&(v6.clone(), false))));
        assert!(ipv6_for(&v6, Some(&(v4, false))));
    }

    #[test]
    fn the_tools_answers_read_as_the_app_reads_them() {
        assert_eq!(
            nmcli_wifi("no:Other\nyes:My\\:Net\n").as_deref(),
            Some("My:Net")
        );
        assert_eq!(nmcli_wifi("no:x\nyes:\n"), None);
        let ports = "Hardware Port: Ethernet\nDevice: en0\n\nHardware Port: Wi-Fi\nDevice: en1\nEthernet Address: x\n";
        assert_eq!(wifi_device_of(ports).as_deref(), Some("en1"));
        let summary = "<dictionary> {\n  InterfaceType : WiFi\n  SSID : Cafe Net \n}";
        assert_eq!(field(summary, "SSID").as_deref(), Some("Cafe Net"));
        let netsh = "    Name                   : Wi-Fi\n    State                  : connected\n    SSID                   : Home\n    BSSID                  : aa\n";
        assert_eq!(field(netsh, "State").as_deref(), Some("connected"));
        assert_eq!(field(netsh, "SSID").as_deref(), Some("Home"));
    }
}
