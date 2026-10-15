//! PaoPao's state on disk, under the core's home (`<home>/paopao/`):
//!
//! - `input.json`: the build input last handed over (`PUT
//!   /paopao/input`), with the refreshes merged in since. Holds secrets
//!   (the API secret, SSH passwords): owner-only on Unix.
//! - `subscriptions/<id>.json`: each subscription's last refresh
//!   (`meow_paopao::refresh::Refreshed`): how it went, and the lines of the
//!   last one that worked.
//! - `schedule.json`: [`Schedule`].
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

/// When subscriptions are refreshed on their own. Off until told
/// (`PUT /paopao/schedule`): while the app refreshes them itself, the two
/// must not both run.
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

/// What the core reads of a build input: its subscriptions' ids and
/// addresses, everything else (the lines above all) parsed past without
/// being kept. Lenient as the builder (`BuildInput::from_json`): a
/// subscription without a string `id` and `url` is left out, a
/// `subscriptions` that is no list reads as none. Only a document that is
/// no JSON object fails.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct InputHead {
    pub subscriptions: Vec<SubHead>,
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
            "runtime": {"secret": "s"}
        }"#;
        let head = InputHead::parse(input).unwrap();
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
