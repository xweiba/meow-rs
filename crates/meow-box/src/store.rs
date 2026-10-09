//! The box's data directory:
//! - `box.json` (0600): the page's password, the box's MAC, DNS upstreams;
//! - `settings.json`: the app's `ProxySettings` JSON (`{}` = the app's
//!   defaults);
//! - `subscriptions.json`: subscriptions as the app persists them, nodes
//!   from `meow_paopao::parse_json`;
//! - `core/`: the core's home (caches, geodata).

use std::fs;
use std::io::Write as _;
use std::os::unix::fs::{DirBuilderExt as _, OpenOptionsExt as _};
use std::path::{Path, PathBuf};

use anyhow::Context as _;
use rand::Rng as _;
use serde_json::{json, Value};

use crate::dns::DEFAULT_UPSTREAMS;
use crate::frame::Mac;

/// The page's user name.
pub const ADMIN_USER: &str = "admin";
/// Password length on first start.
const PASSWORD_LEN: usize = 12;
/// No look-alikes (0/O, 1/l/I).
const PASSWORD_CHARS: &[u8] = b"abcdefghijkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789";

/// `box.json`.
#[derive(Clone, PartialEq, Eq)]
pub struct BoxFile {
    /// The config page's password (shown in the start banner).
    pub password: String,
    /// The box's own MAC (wired; on Wi-Fi its DHCP client id).
    pub mac: Mac,
    /// Upstreams for real DNS answers.
    pub dns_upstreams: Vec<String>,
}

impl std::fmt::Debug for BoxFile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BoxFile")
            .field("password", &"<redacted>")
            .field("mac", &self.mac)
            .field("dns_upstreams", &self.dns_upstreams)
            .finish()
    }
}

/// A fresh random password.
pub fn new_password() -> String {
    let mut rng = rand::rng();
    (0..PASSWORD_LEN)
        .map(|_| char::from(PASSWORD_CHARS[rng.random_range(0..PASSWORD_CHARS.len())]))
        .collect()
}

/// A fresh random locally administered MAC.
pub fn new_mac() -> Mac {
    Mac::random_local(rand::rng().random())
}

impl BoxFile {
    fn from_json(v: &Value) -> Self {
        let password = v
            .get("password")
            .and_then(Value::as_str)
            .filter(|p| !p.is_empty())
            .map_or_else(new_password, str::to_owned);
        let mac = v
            .get("mac")
            .and_then(Value::as_str)
            .and_then(Mac::parse)
            .filter(|m| !m.is_group() && m.0 != [0; 6])
            .unwrap_or_else(new_mac);
        let dns_upstreams = v
            .get("dnsUpstreams")
            .and_then(Value::as_array)
            .map(|a| {
                a.iter()
                    .filter_map(Value::as_str)
                    .map(str::to_owned)
                    .collect::<Vec<_>>()
            })
            .filter(|a| !a.is_empty())
            .unwrap_or_else(|| DEFAULT_UPSTREAMS.iter().map(|s| (*s).to_owned()).collect());
        Self {
            password,
            mac,
            dns_upstreams,
        }
    }

    fn to_json(&self) -> Value {
        json!({
            "password": self.password,
            "mac": self.mac.to_string(),
            "dnsUpstreams": self.dns_upstreams,
        })
    }
}

/// The data directory.
#[derive(Debug, Clone)]
pub struct Store {
    dir: PathBuf,
}

impl Store {
    /// Opens (creates, 0700) `dir`.
    pub fn open(dir: &Path) -> anyhow::Result<Self> {
        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(dir)
            .with_context(|| format!("cannot create the data directory {}", dir.display()))?;
        Ok(Self {
            dir: dir.to_path_buf(),
        })
    }

    /// The core's home directory (created).
    pub fn core_home(&self) -> anyhow::Result<PathBuf> {
        let p = self.dir.join("core");
        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(&p)?;
        Ok(p)
    }

    fn read(&self, name: &str) -> Option<Value> {
        let text = fs::read_to_string(self.dir.join(name)).ok()?;
        serde_json::from_str(&text).ok()
    }

    /// Writes `name` atomically with mode 0600.
    fn write(&self, name: &str, v: &Value) -> anyhow::Result<()> {
        let path = self.dir.join(name);
        let tmp = self.dir.join(format!(".{name}.tmp"));
        let mut f = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&tmp)
            .with_context(|| format!("cannot write {}", tmp.display()))?;
        f.write_all(serde_json::to_string_pretty(v)?.as_bytes())?;
        f.sync_all()?;
        fs::rename(&tmp, &path).with_context(|| format!("cannot write {}", path.display()))?;
        Ok(())
    }

    /// `box.json`, created with a new password and MAC on first start
    /// (and completed when fields are missing).
    pub fn box_file(&self) -> anyhow::Result<BoxFile> {
        let raw = self.read("box.json");
        let b = BoxFile::from_json(raw.as_ref().unwrap_or(&Value::Null));
        if raw.as_ref() != Some(&b.to_json()) {
            self.save_box_file(&b)?;
        }
        Ok(b)
    }

    /// Saves `box.json`.
    pub fn save_box_file(&self, b: &BoxFile) -> anyhow::Result<()> {
        self.write("box.json", &b.to_json())
    }

    /// `settings.json`; `{}` (the app's defaults) when missing.
    pub fn settings(&self) -> Value {
        self.read("settings.json")
            .filter(Value::is_object)
            .unwrap_or_else(|| json!({}))
    }

    /// Saves `settings.json`.
    pub fn save_settings(&self, v: &Value) -> anyhow::Result<()> {
        self.write("settings.json", v)
    }

    /// `subscriptions.json`; empty when missing.
    pub fn subscriptions(&self) -> Vec<Value> {
        self.read("subscriptions.json")
            .and_then(|v| v.as_array().cloned())
            .unwrap_or_default()
    }

    /// Saves `subscriptions.json`.
    pub fn save_subscriptions(&self, subs: &[Value]) -> anyhow::Result<()> {
        self.write("subscriptions.json", &Value::Array(subs.to_vec()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt as _;

    #[test]
    fn first_start_makes_a_private_box_file_and_keeps_it() {
        let dir = tempfile::tempdir().unwrap();
        let s = Store::open(&dir.path().join("data")).unwrap();
        let b = s.box_file().unwrap();
        assert_eq!(b.password.len(), PASSWORD_LEN);
        assert!(b.password.bytes().all(|c| PASSWORD_CHARS.contains(&c)));
        assert_eq!(b.mac.0[0] & 0x03, 0x02, "local unicast");
        assert_eq!(b.dns_upstreams, ["223.5.5.5", "119.29.29.29"]);
        let meta = fs::metadata(dir.path().join("data/box.json")).unwrap();
        assert_eq!(meta.permissions().mode() & 0o777, 0o600);
        let dmeta = fs::metadata(dir.path().join("data")).unwrap();
        assert_eq!(dmeta.permissions().mode() & 0o777, 0o700);
        // Same password and MAC next start.
        assert_eq!(s.box_file().unwrap(), b);
        // Changing the password persists.
        let mut c = b.clone();
        c.password = "new-secret".into();
        s.save_box_file(&c).unwrap();
        assert_eq!(s.box_file().unwrap().password, "new-secret");
        assert_eq!(s.box_file().unwrap().mac, b.mac);
    }

    #[test]
    fn broken_fields_are_replaced() {
        let dir = tempfile::tempdir().unwrap();
        let s = Store::open(dir.path()).unwrap();
        fs::write(
            dir.path().join("box.json"),
            r#"{"password": "", "mac": "ff:ff:ff:ff:ff:ff", "dnsUpstreams": []}"#,
        )
        .unwrap();
        let b = s.box_file().unwrap();
        assert_eq!(b.password.len(), PASSWORD_LEN);
        assert!(!b.mac.is_group());
        assert_eq!(b.dns_upstreams.len(), 2);
        assert!(format!("{b:?}").contains("<redacted>"));
        assert!(!format!("{b:?}").contains(&b.password));
    }

    #[test]
    fn settings_and_subscriptions_default_and_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let s = Store::open(dir.path()).unwrap();
        assert_eq!(s.settings(), json!({}));
        assert!(s.subscriptions().is_empty());
        s.save_settings(&json!({"mode": "global"})).unwrap();
        assert_eq!(s.settings()["mode"], "global");
        s.save_subscriptions(&[json!({"id": "a", "url": "https://x"})])
            .unwrap();
        assert_eq!(s.subscriptions()[0]["id"], "a");
        fs::write(dir.path().join("settings.json"), "[1]").unwrap();
        assert_eq!(s.settings(), json!({}), "not an object: defaults");
    }

    #[test]
    fn passwords_differ() {
        assert_ne!(new_password(), new_password());
    }
}
