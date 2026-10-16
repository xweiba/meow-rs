//! PaoPao's state on disk, under the core's home (`<home>/paopao/`):
//!
//! - `input.json`: the build input last handed over (`PUT
//!   /paopao/input`), with the refreshes merged in since. Holds secrets
//!   (the API secret, SSH passwords): owner-only on Unix.
//! - `subscriptions/<id>.json`: each subscription's last refresh
//!   (`meow_paopao::refresh::Refreshed`): how it went, and the lines of the
//!   last one that worked.
//! - `modules/<id>.json`: each rewrite module's last refresh: how it went,
//!   and the spec and text of the last one that worked (its scripts are
//!   kept beside the core, `<home>/modules/<id>/<i>.js`).
//! - `schedule.json`: [`Schedule`].
//! - `exits.json`: where each line exits ([`super::exits`]).
//! - `network.json`: the network the core last saw ([`super::network`]).
//! - `route.json`: where the route API listens and its key
//!   ([`super::route`]); `policies.json`: what it offers, from the last
//!   config built (here or by the app).
//! - `track.json`: the trip 虚拟定位 moves along ([`super::track`]).
//! - `config.next.yaml`: a config built and not yet run; moved over the
//!   core's config file once the core runs it, removed when it refuses it.
//!
//! The core reads these when a job or a request needs them and keeps
//! nothing of them between: the long lists live in the files and in the
//! short-lived children that work on them. Every write replaces the file
//! whole ([`write_atomic`]): a reader sees the old file or the new one.

use std::fmt::{self, Write as _};
use std::io::{self, Write as _};
use std::path::{Path, PathBuf};

use serde::de::{self, Deserializer, IgnoredAny, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Serialize};

/// Minutes between scheduled refreshes unless set: the app's
/// (`ProxyController.refreshEvery`, 12 hours).
pub const DEFAULT_MINUTES: u32 = 12 * 60;

/// The files' places.
#[derive(Debug, Clone)]
pub struct Store {
    dir: PathBuf,
}

impl Store {
    pub fn new(dir: impl Into<PathBuf>) -> Self {
        Self { dir: dir.into() }
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    pub fn input(&self) -> PathBuf {
        self.dir.join("input.json")
    }

    pub fn subscriptions(&self) -> PathBuf {
        self.dir.join("subscriptions")
    }

    /// Subscription `id`'s record.
    pub fn subscription(&self, id: &str) -> PathBuf {
        self.subscriptions()
            .join(format!("{}.json", file_name_for(id)))
    }

    pub fn schedule(&self) -> PathBuf {
        self.dir.join("schedule.json")
    }

    pub fn modules(&self) -> PathBuf {
        self.dir.join("modules")
    }

    /// Module `id`'s record.
    pub fn module(&self, id: &str) -> PathBuf {
        self.modules().join(format!("{}.json", file_name_for(id)))
    }

    pub fn exits(&self) -> PathBuf {
        self.dir.join("exits.json")
    }

    pub fn network(&self) -> PathBuf {
        self.dir.join("network.json")
    }

    pub fn route(&self) -> PathBuf {
        self.dir.join("route.json")
    }

    /// The route policies of the last config built here.
    pub fn policies(&self) -> PathBuf {
        self.dir.join("policies.json")
    }

    pub fn track(&self) -> PathBuf {
        self.dir.join("track.json")
    }

    /// The core's home, where module scripts and the scripts' store live.
    pub fn home(&self) -> &Path {
        self.dir.parent().unwrap_or(&self.dir)
    }

    pub fn next_config(&self) -> PathBuf {
        self.dir.join("config.next.yaml")
    }
}

/// A subscription id as a file name: as it is when it is plain (the app's
/// are eight letters and digits), else `~` and its bytes in hex, so no id
/// can name a path elsewhere or two ids one file.
pub fn file_name_for(id: &str) -> String {
    let plain = !id.is_empty()
        && id.len() <= 64
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_');
    if plain {
        return id.to_owned();
    }
    let mut out = String::with_capacity(1 + id.len() * 2);
    out.push('~');
    for b in id.bytes() {
        let _ = write!(out, "{b:02x}");
    }
    out
}

/// Replaces `path` with `bytes`: written beside it, flushed, then renamed
/// over it. `private`: readable by the owner alone (Unix).
pub fn write_atomic(path: &Path, bytes: &[u8], private: bool) -> io::Result<()> {
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let mut tmp = path.as_os_str().to_owned();
    tmp.push(format!(".{}.tmp", std::process::id()));
    let tmp = PathBuf::from(tmp);
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    if private {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    #[cfg(not(unix))]
    let _ = private;
    let written = (|| {
        let mut f = options.open(&tmp)?;
        f.write_all(bytes)?;
        f.sync_all()
    })();
    let done = written.and_then(|()| std::fs::rename(&tmp, path));
    if done.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    done
}

/// When subscriptions and modules are refreshed on their own, and whether
/// exits are looked up and the network watched. All off until told (`PUT
/// /paopao/schedule`): while the app does them itself, the two must not
/// both run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Schedule {
    #[serde(default)]
    pub enabled: bool,
    /// Minutes between refreshes; 0 = none.
    #[serde(default = "default_minutes")]
    pub minutes: u32,
    /// When the last scheduled (or refresh-all) job ran, Unix ms.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_run: Option<i64>,
    /// What went wrong in it, if anything.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_error: Option<String>,
    /// Exits are looked up here ([`super::exits`]).
    #[serde(default)]
    pub exits: bool,
    /// The network is watched here ([`super::network`]).
    #[serde(default)]
    pub network: bool,
}

fn default_minutes() -> u32 {
    DEFAULT_MINUTES
}

impl Default for Schedule {
    fn default() -> Self {
        Self {
            enabled: false,
            minutes: DEFAULT_MINUTES,
            last_run: None,
            last_error: None,
            exits: false,
            network: false,
        }
    }
}

impl Schedule {
    /// The next run, Unix ms; None while off. Never run: now.
    pub fn next_run(&self, now: i64, minute_ms: i64) -> Option<i64> {
        if !self.enabled || self.minutes == 0 {
            return None;
        }
        Some(match self.last_run {
            None => now,
            Some(last) => last.saturating_add(i64::from(self.minutes) * minute_ms),
        })
    }

    /// The file's schedule; the default when there is none (or it is
    /// unreadable).
    pub fn read(store: &Store) -> Self {
        std::fs::read(store.schedule())
            .ok()
            .and_then(|b| serde_json::from_slice(&b).ok())
            .unwrap_or_default()
    }

    pub fn write(&self, store: &Store) -> io::Result<()> {
        let bytes = serde_json::to_vec(self).map_err(io::Error::other)?;
        write_atomic(&store.schedule(), &bytes, false)
    }
}

/// A subscription record's status: what `meow_paopao::refresh::Refreshed`
/// says besides the lines (read past without keeping them).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SubStatus {
    pub id: String,
    pub url: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user_agent: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub via: Option<String>,
    #[serde(default)]
    pub checked: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub updated: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub usage: Option<serde_json::Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_error: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub body_sha: Option<String>,
    #[serde(default)]
    pub node_count: usize,
    #[serde(default)]
    pub skipped: i64,
}

/// A rewrite module's last refresh (`modules/<id>.json`): how it went and,
/// from the last one that worked, its spec (`ModuleSpec.toJson`) and text,
/// parsed with `values`. The text comes last so a reader after the status
/// alone stops short of it.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct ModuleRecord {
    pub id: String,
    pub url: String,
    /// When it was last tried, Unix ms.
    pub checked: i64,
    /// When it last worked, Unix ms.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub updated: Option<i64>,
    /// The last try's problem in the app's words; None when it worked.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_error: Option<String>,
    /// The settings the spec was made with.
    #[serde(default)]
    pub values: serde_json::Map<String, serde_json::Value>,
    #[serde(default, skip_serializing_if = "serde_json::Value::is_null")]
    pub spec: serde_json::Value,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
}

impl ModuleRecord {
    /// The record at `path`, when there is one of module `id`.
    pub fn read(path: &Path, id: &str) -> Option<Self> {
        std::fs::read(path)
            .ok()
            .and_then(|b| serde_json::from_slice::<Self>(&b).ok())
            .filter(|r| r.id == id)
    }

    /// Its last try worked.
    pub fn worked(&self) -> bool {
        self.updated == Some(self.checked) && self.last_error.is_none()
    }
}

/// What the core reads of a build input: its subscriptions' ids and
/// addresses and its modules' (with their settings), everything else (the
/// lines and the modules' texts above all) parsed past without being kept. Lenient as the builder (`BuildInput::from_json`): a
/// subscription without a string `id` and `url` is left out, a
/// `subscriptions` that is no list reads as none. Only a document that is
/// no JSON object fails.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct InputHead {
    pub subscriptions: Vec<SubHead>,
    pub modules: Vec<ModuleHead>,
    /// Measured exits: server key → country.
    pub exits: Vec<(String, String)>,
    /// Server domains resolved: domain → IP.
    pub resolved: Vec<(String, String)>,
    /// The network it was built for (`{kind, ssid?, addresses}`).
    pub network: Option<serde_json::Value>,
    pub ipv6: Option<bool>,
}

/// A rewrite module of the input (`ScriptModule.toJson` without its spec
/// and text).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModuleHead {
    pub id: String,
    pub url: String,
    pub enabled: bool,
    /// The user's settings for its arguments.
    pub values: Vec<(String, String)>,
}

impl ModuleHead {
    /// Downloaded from the web (not one built in, `builtin:…`).
    pub fn is_remote(&self) -> bool {
        let lower = self.url.to_ascii_lowercase();
        lower.starts_with("http://") || lower.starts_with("https://")
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubHead {
    pub id: String,
    pub url: String,
    pub name: Option<String>,
    /// A user agent of its own (none from the app today).
    pub user_agent: Option<String>,
}

impl InputHead {
    pub fn parse(bytes: &[u8]) -> Result<Self, String> {
        serde_json::from_slice(bytes).map_err(|e| format!("not a build input: {e}"))
    }
}

impl<'de> Deserialize<'de> for InputHead {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct V;
        impl<'de> Visitor<'de> for V {
            type Value = InputHead;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a JSON object")
            }
            fn visit_map<A: MapAccess<'de>>(self, mut m: A) -> Result<InputHead, A::Error> {
                let mut head = InputHead::default();
                while let Some(k) = m.next_key::<String>()? {
                    if k == "subscriptions" {
                        head.subscriptions = m.next_value::<Subs>()?.0;
                    } else if k == "modules" {
                        head.modules = m.next_value::<Modules>()?.0;
                    } else if k == "exits" || k == "resolved" {
                        let pairs = match m.next_value::<serde_json::Value>()? {
                            serde_json::Value::Object(o) => o
                                .into_iter()
                                .filter_map(|(k, v)| Some((k, v.as_str()?.to_owned())))
                                .collect(),
                            _ => Vec::new(),
                        };
                        if k == "exits" {
                            head.exits = pairs;
                        } else {
                            head.resolved = pairs;
                        }
                    } else if k == "network" {
                        head.network = Some(m.next_value::<serde_json::Value>()?)
                            .filter(serde_json::Value::is_object);
                    } else if k == "ipv6" {
                        head.ipv6 = m.next_value::<serde_json::Value>()?.as_bool();
                    } else {
                        m.next_value::<IgnoredAny>()?;
                    }
                }
                Ok(head)
            }
        }
        d.deserialize_map(V)
    }
}

/// Any JSON value, drained; `T::default()` unless the visitor below takes
/// it. Saves writing every `visit_*` for the lenient readers.
macro_rules! lenient_visitor {
    ($name:ident, $out:ty, $expect:literal, { $($body:tt)* }) => {
        struct $name;
        impl<'de> Visitor<'de> for $name {
            type Value = $out;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str($expect)
            }
            fn visit_bool<E: de::Error>(self, _: bool) -> Result<$out, E> {
                Ok(<$out>::default())
            }
            fn visit_i64<E: de::Error>(self, _: i64) -> Result<$out, E> {
                Ok(<$out>::default())
            }
            fn visit_u64<E: de::Error>(self, _: u64) -> Result<$out, E> {
                Ok(<$out>::default())
            }
            fn visit_f64<E: de::Error>(self, _: f64) -> Result<$out, E> {
                Ok(<$out>::default())
            }
            fn visit_unit<E: de::Error>(self) -> Result<$out, E> {
                Ok(<$out>::default())
            }
            $($body)*
        }
    };
}

/// `subscriptions`: a list, else none.
struct Subs(Vec<SubHead>);

impl<'de> Deserialize<'de> for Subs {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        lenient_visitor!(V, Vec<SubHead>, "a list", {
            fn visit_str<E: de::Error>(self, _: &str) -> Result<Vec<SubHead>, E> {
                Ok(Vec::new())
            }
            fn visit_map<A: MapAccess<'de>>(self, mut m: A) -> Result<Vec<SubHead>, A::Error> {
                while m.next_entry::<IgnoredAny, IgnoredAny>()?.is_some() {}
                Ok(Vec::new())
            }
            fn visit_seq<A: SeqAccess<'de>>(self, mut s: A) -> Result<Vec<SubHead>, A::Error> {
                let mut out = Vec::new();
                while let Some(sub) = s.next_element::<Sub>()? {
                    out.extend(sub.0);
                }
                Ok(out)
            }
        });
        d.deserialize_any(V).map(Subs)
    }
}

/// One subscription: its head when it has a string `id` and `url`.
struct Sub(Option<SubHead>);

impl<'de> Deserialize<'de> for Sub {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        lenient_visitor!(V, Option<SubHead>, "a subscription", {
            fn visit_str<E: de::Error>(self, _: &str) -> Result<Option<SubHead>, E> {
                Ok(None)
            }
            fn visit_seq<A: SeqAccess<'de>>(self, mut s: A) -> Result<Option<SubHead>, A::Error> {
                while s.next_element::<IgnoredAny>()?.is_some() {}
                Ok(None)
            }
            fn visit_map<A: MapAccess<'de>>(self, mut m: A) -> Result<Option<SubHead>, A::Error> {
                let (mut id, mut url, mut name, mut user_agent) = (None, None, None, None);
                while let Some(k) = m.next_key::<String>()? {
                    let slot = match k.as_str() {
                        "id" => &mut id,
                        "url" => &mut url,
                        "name" => &mut name,
                        "user_agent" => &mut user_agent,
                        _ => {
                            m.next_value::<IgnoredAny>()?;
                            continue;
                        }
                    };
                    *slot = m.next_value::<Text>()?.0;
                }
                Ok(id.zip(url).map(|(id, url)| SubHead {
                    id,
                    url,
                    name,
                    user_agent,
                }))
            }
        });
        d.deserialize_any(V).map(Sub)
    }
}

/// `modules`: a list, else none.
struct Modules(Vec<ModuleHead>);

impl<'de> Deserialize<'de> for Modules {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        lenient_visitor!(V, Vec<ModuleHead>, "a list", {
            fn visit_str<E: de::Error>(self, _: &str) -> Result<Vec<ModuleHead>, E> {
                Ok(Vec::new())
            }
            fn visit_map<A: MapAccess<'de>>(self, mut m: A) -> Result<Vec<ModuleHead>, A::Error> {
                while m.next_entry::<IgnoredAny, IgnoredAny>()?.is_some() {}
                Ok(Vec::new())
            }
            fn visit_seq<A: SeqAccess<'de>>(self, mut s: A) -> Result<Vec<ModuleHead>, A::Error> {
                let mut out = Vec::new();
                while let Some(m) = s.next_element::<Module>()? {
                    out.extend(m.0);
                }
                Ok(out)
            }
        });
        d.deserialize_any(V).map(Modules)
    }
}

/// One module: its head when it has a string `id` (Dart reads a module
/// without a `url` as one with an empty one, `enabled` unless `false`).
struct Module(Option<ModuleHead>);

impl<'de> Deserialize<'de> for Module {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        lenient_visitor!(V, Option<ModuleHead>, "a module", {
            fn visit_str<E: de::Error>(self, _: &str) -> Result<Option<ModuleHead>, E> {
                Ok(None)
            }
            fn visit_seq<A: SeqAccess<'de>>(
                self,
                mut s: A,
            ) -> Result<Option<ModuleHead>, A::Error> {
                while s.next_element::<IgnoredAny>()?.is_some() {}
                Ok(None)
            }
            fn visit_map<A: MapAccess<'de>>(
                self,
                mut m: A,
            ) -> Result<Option<ModuleHead>, A::Error> {
                let (mut id, mut url, mut enabled, mut values) = (None, None, true, Vec::new());
                while let Some(k) = m.next_key::<String>()? {
                    match k.as_str() {
                        "id" => id = m.next_value::<Text>()?.0,
                        "url" => url = m.next_value::<Text>()?.0,
                        "enabled" => enabled = m.next_value::<serde_json::Value>()? != false,
                        "values" => {
                            if let serde_json::Value::Object(o) = m.next_value()? {
                                values = o
                                    .into_iter()
                                    .map(|(k, v)| {
                                        let v = match v {
                                            serde_json::Value::String(s) => s,
                                            v => v.to_string(),
                                        };
                                        (k, v)
                                    })
                                    .collect();
                            }
                        }
                        _ => {
                            m.next_value::<IgnoredAny>()?;
                        }
                    }
                }
                Ok(id.map(|id| ModuleHead {
                    id,
                    url: url.unwrap_or_default(),
                    enabled,
                    values,
                }))
            }
        });
        d.deserialize_any(V).map(Module)
    }
}

/// A string, else None.
struct Text(Option<String>);

impl<'de> Deserialize<'de> for Text {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        lenient_visitor!(V, Option<String>, "a string", {
            fn visit_str<E: de::Error>(self, s: &str) -> Result<Option<String>, E> {
                Ok(Some(s.to_owned()))
            }
            fn visit_seq<A: SeqAccess<'de>>(self, mut s: A) -> Result<Option<String>, A::Error> {
                while s.next_element::<IgnoredAny>()?.is_some() {}
                Ok(None)
            }
            fn visit_map<A: MapAccess<'de>>(self, mut m: A) -> Result<Option<String>, A::Error> {
                while m.next_entry::<IgnoredAny, IgnoredAny>()?.is_some() {}
                Ok(None)
            }
        });
        d.deserialize_any(V).map(Text)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_head_is_read_leniently_past_everything_else() {
        let input = br#"{
            "settings": {"mixed_port": 7890},
            "subscriptions": [
                {"id": "a1", "url": "https://a/", "name": "A", "nodes": [{"name": "x", "outbound": {"type": "trojan"}}]},
                {"id": 7, "url": "https://b/"},
                {"url": "https://c/"},
                "junk", 3, null, [1],
                {"id": "d", "url": "https://d/", "name": 5, "user_agent": "ua", "split": {"rules": []}}
            ],
            "runtime": {"secret": "s"},
            "modules": [
                {"id": "m1", "url": "https://m/a.sgmodule", "enabled": false, "spec": {"scripts": []},
                 "source": "x", "values": {"k": "v", "n": 1}},
                {"id": "m2", "url": "builtin:location-spoofer"},
                {"url": "https://no-id/"}, 4
            ]
        }"#;
        let head = InputHead::parse(input).unwrap();
        assert_eq!(
            head.modules,
            [
                ModuleHead {
                    id: "m1".into(),
                    url: "https://m/a.sgmodule".into(),
                    enabled: false,
                    values: vec![("k".into(), "v".into()), ("n".into(), "1".into())],
                },
                ModuleHead {
                    id: "m2".into(),
                    url: "builtin:location-spoofer".into(),
                    enabled: true,
                    values: vec![],
                },
            ]
        );
        assert!(head.modules[0].is_remote() && !head.modules[1].is_remote());
        let ids: Vec<&str> = head.subscriptions.iter().map(|s| s.id.as_str()).collect();
        assert_eq!(ids, ["a1", "d"]);
        assert_eq!(head.subscriptions[0].name.as_deref(), Some("A"));
        assert_eq!(head.subscriptions[1].name, None);
        assert_eq!(head.subscriptions[1].user_agent.as_deref(), Some("ua"));

        for odd in [
            &br#"{"subscriptions": {"a": 1}}"#[..],
            br#"{"subscriptions": "x"}"#,
            b"{}",
        ] {
            assert_eq!(InputHead::parse(odd).unwrap(), InputHead::default());
        }
        for bad in [&b"[1]"[..], b"nope", b"{\"subscriptions\": [", b""] {
            assert!(InputHead::parse(bad).is_err());
        }
    }

    #[test]
    fn ids_become_safe_distinct_file_names() {
        assert_eq!(file_name_for("ab12cd34"), "ab12cd34");
        assert_eq!(file_name_for("../x"), "~2e2e2f78");
        assert_eq!(file_name_for(""), "~");
        assert_ne!(file_name_for("~2e"), file_name_for("."));
        let store = Store::new("/h/paopao");
        assert_eq!(
            store.subscription("a/b"),
            Path::new("/h/paopao/subscriptions/~612f62.json")
        );
    }

    #[test]
    fn writes_replace_the_file_whole() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("deep/er/input.json");
        write_atomic(&path, b"one", true).unwrap();
        write_atomic(&path, b"two", true).unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"two");
        let left: Vec<_> = std::fs::read_dir(path.parent().unwrap())
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert_eq!(left, ["input.json"]);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600);
        }
        // A directory where the file should be: an error, nothing left
        // behind.
        let blocked = dir.path().join("blocked");
        std::fs::create_dir_all(blocked.join("x")).unwrap();
        assert!(write_atomic(&blocked, b"x", false).is_err());
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 2);
    }

    #[test]
    fn the_schedule_defaults_to_off_at_the_apps_interval() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::new(dir.path());
        let s = Schedule::read(&store);
        assert_eq!(s, Schedule::default());
        assert_eq!(s.minutes, 720);
        assert_eq!(s.next_run(1_000, 60_000), None);
        let on = Schedule { enabled: true, ..s };
        assert_eq!(on.next_run(1_000, 60_000), Some(1_000));
        let ran = Schedule {
            last_run: Some(5_000),
            ..on.clone()
        };
        assert_eq!(ran.next_run(6_000, 60_000), Some(5_000 + 720 * 60_000));
        ran.write(&store).unwrap();
        assert_eq!(Schedule::read(&store), ran);
        let none = Schedule { minutes: 0, ..on };
        assert_eq!(none.next_run(1, 60_000), None);
    }
}
