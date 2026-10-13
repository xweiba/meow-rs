//! PaoPao: the connections that ended, kept by the core.
//!
//! The app used to keep this list itself, which left a core running without
//! it (a server, a router) with no record of what had passed. Here it is
//! bounded, merged and saved by the core; `GET /connections/history` serves
//! it and the app only draws it.
//!
//! Memory: a record shares the connection's `Arc<Metadata>` (no copy), and
//! holds a few short strings beside it — about 0.5 KB each on a 64-bit
//! target. The list never grows past [`ConnectionHistory::hard_limit`]
//! (six times the limit set): 500 → at most 3000 records, ~1.5 MB, and
//! ~0.25 MB in the steady state.

use std::collections::VecDeque;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use meow_common::Metadata;
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use smallvec::SmallVec;
use smol_str::SmolStr;
use uuid::Uuid;

/// Kept when nothing says otherwise (`connection-history-limit`).
pub const DEFAULT_LIMIT: usize = 500;
/// The most that can be asked for: a router has little memory to give.
pub const MAX_LIMIT: usize = 20_000;
/// Ended ones this recent stay beyond the limit (up to the hard limit): a
/// busy machine ends more than the limit in the minutes an overview looks
/// back over.
const KEEP_MS: i64 = 5 * 60 * 1000;

/// One connection that ended — or several tries of the same thing that
/// moved nothing, kept as their latest ([`Self::count`], [`Self::first`]).
///
/// Serialises as an entry of `GET /connections` does, with `end`, `seq`,
/// `rev` and, when it stands for several, `count` and `first` beside.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EndedConnection {
    pub id: Uuid,
    pub metadata: Arc<Metadata>,
    pub upload: i64,
    pub download: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub interface: Option<Arc<str>>,
    pub start: SmolStr,
    pub chains: SmallVec<[Arc<str>; 1]>,
    pub rule: SmolStr,
    #[serde(rename = "rulePayload", default)]
    pub rule_payload: SmolStr,
    /// RFC 3339, to the second, as `start` is.
    pub end: SmolStr,
    /// Unix milliseconds of [`Self::end`]: what trimming goes by.
    #[serde(rename = "endMs", default)]
    pub end_ms: i64,
    /// Order of arrival among all connections (1, 2, 3 …; kept across
    /// restarts).
    #[serde(default)]
    pub seq: u64,
    /// Bumped whenever the record is added or changed: a reader that has
    /// everything up to some `rev` asks for what came after.
    #[serde(default)]
    pub rev: u64,
    /// How many connections it stands for.
    #[serde(default = "one", skip_serializing_if = "is_one")]
    pub count: u32,
    /// When the earliest of them began; absent while [`Self::count`] is 1.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub first: Option<SmolStr>,
}

fn one() -> u32 {
    1
}

fn is_one(n: &u32) -> bool {
    *n == 1
}

impl EndedConnection {
    /// Ended without moving a byte: joins the others like it.
    fn mergeable(&self) -> bool {
        self.upload == 0 && self.download == 0
    }

    /// What two mergeable records share to be kept as one: the program, the
    /// target (name, port, protocol), the rule and the whole way out.
    fn same_try(&self, other: &Self) -> bool {
        let (a, b) = (&*self.metadata, &*other.metadata);
        a.dst_port == b.dst_port
            && a.network == b.network
            && a.host == b.host
            && (!a.host.is_empty() || a.dst_ip == b.dst_ip)
            && a.process == b.process
            && a.process_path == b.process_path
            && self.rule == other.rule
            && self.rule_payload == other.rule_payload
            && self.interface == other.interface
            && self.chains == other.chains
    }
}

/// What a reader gets: the records changed since it last asked, and the
/// `seq` of every record still kept (what it holds beyond those is gone).
#[derive(Debug, Serialize)]
pub struct HistoryDelta {
    pub rev: u64,
    pub limit: usize,
    pub changed: Vec<EndedConnection>,
    pub kept: Vec<u64>,
}

#[derive(Default)]
struct Inner {
    /// Oldest ended first.
    records: VecDeque<EndedConnection>,
    limit: usize,
    rev: u64,
    saved_rev: u64,
    store: Option<PathBuf>,
}

pub struct ConnectionHistory {
    inner: Mutex<Inner>,
}

impl Default for ConnectionHistory {
    fn default() -> Self {
        Self::new()
    }
}

impl ConnectionHistory {
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(Inner {
                limit: DEFAULT_LIMIT,
                ..Inner::default()
            }),
        }
    }

    /// Never more than this many kept, whatever their age.
    pub fn hard_limit(limit: usize) -> usize {
        limit.saturating_mul(6)
    }

    pub fn limit(&self) -> usize {
        self.inner.lock().limit
    }

    /// How many to keep (`0` keeps none); what is over goes now.
    pub fn set_limit(&self, limit: usize) {
        let mut inner = self.inner.lock();
        inner.limit = limit.min(MAX_LIMIT);
        let before = inner.records.len();
        inner.trim(now_ms());
        if inner.records.len() != before {
            inner.rev += 1;
        }
    }

    /// Changes with every change to the list.
    pub fn rev(&self) -> u64 {
        self.inner.lock().rev
    }

    pub fn len(&self) -> usize {
        self.inner.lock().records.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// The highest `seq` kept: numbering goes on from it after a restart.
    pub fn last_seq(&self) -> u64 {
        let inner = self.inner.lock();
        inner.records.iter().map(|r| r.seq).max().unwrap_or(0)
    }

    /// A connection ended.
    pub fn push(&self, mut record: EndedConnection) {
        let mut inner = self.inner.lock();
        if inner.limit == 0 {
            return;
        }
        if record.mergeable() {
            // The same thing tried again: one record, the latest try.
            if let Some(i) = inner
                .records
                .iter()
                .rposition(|r| r.mergeable() && r.same_try(&record))
            {
                let old = inner.records.remove(i).expect("index from rposition");
                record.count = record.count.saturating_add(old.count);
                record.first = Some(old.first.unwrap_or(old.start));
            }
        }
        inner.rev += 1;
        record.rev = inner.rev;
        let at = record.end_ms;
        inner.records.push_back(record);
        inner.trim(at);
    }

    /// Forgets everything.
    pub fn clear(&self) {
        let mut inner = self.inner.lock();
        inner.records.clear();
        inner.rev += 1;
    }

    /// The records changed after `after` (`0`, or a `rev` this run has not
    /// reached: all of them), newest last.
    pub fn delta(&self, after: u64) -> HistoryDelta {
        let inner = self.inner.lock();
        // Ahead of this run: a reader from before a restart gets it all.
        let after = if after > inner.rev { 0 } else { after };
        HistoryDelta {
            rev: inner.rev,
            limit: inner.limit,
            changed: inner
                .records
                .iter()
                .filter(|r| r.rev > after)
                .cloned()
                .collect(),
            kept: inner.records.iter().map(|r| r.seq).collect(),
        }
    }

    /// Where the list is saved; what was saved there before is read now.
    pub fn open(&self, path: &Path) {
        let loaded: Vec<EndedConnection> = std::fs::read(path)
            .ok()
            .and_then(|bytes| serde_json::from_slice(&bytes).ok())
            .unwrap_or_default();
        let mut inner = self.inner.lock();
        inner.store = Some(path.to_path_buf());
        if inner.limit == 0 {
            return;
        }
        // Ended while this run was starting: after the saved ones.
        let fresh: Vec<_> = inner.records.drain(..).collect();
        for mut r in loaded.into_iter().chain(fresh) {
            inner.rev += 1;
            r.rev = inner.rev;
            inner.records.push_back(r);
        }
        inner.saved_rev = inner.rev;
        inner.trim(now_ms());
    }

    /// Writes the newest [`Self::limit`] to the file given to [`Self::open`],
    /// when anything changed since the last time. Blocking file I/O: call it
    /// off the async workers.
    pub fn save(&self) {
        let (path, bytes, rev) = {
            let inner = self.inner.lock();
            let Some(path) = inner.store.clone() else {
                return;
            };
            if inner.rev == inner.saved_rev {
                return;
            }
            let skip = inner.records.len().saturating_sub(inner.limit);
            let newest: Vec<&EndedConnection> = inner.records.iter().skip(skip).collect();
            let Ok(bytes) = serde_json::to_vec(&newest) else {
                return;
            };
            (path, bytes, inner.rev)
        };
        // Whole or not at all: a reader never finds half a file.
        let tmp = path.with_extension("json.tmp");
        if std::fs::write(&tmp, bytes).is_ok() && std::fs::rename(&tmp, &path).is_ok() {
            self.inner.lock().saved_rev = rev;
        } else {
            let _ = std::fs::remove_file(&tmp);
        }
    }
}

impl Inner {
    /// Over the limit: the ones that ended more than [`KEEP_MS`] ago go,
    /// the oldest first; past the hard limit the recent ones too.
    fn trim(&mut self, now_ms: i64) {
        let hard = ConnectionHistory::hard_limit(self.limit);
        while self.records.len() > self.limit {
            let old = self
                .records
                .front()
                .is_some_and(|r| now_ms - r.end_ms > KEEP_MS);
            if !old && self.records.len() <= hard {
                break;
            }
            self.records.pop_front();
        }
    }
}

pub(crate) fn now_ms() -> i64 {
    (time::OffsetDateTime::now_utc().unix_timestamp_nanos() / 1_000_000) as i64
}

#[cfg(test)]
mod tests {
    use super::*;
    use meow_common::{ConnType, DnsMode, Network};

    fn ended(seq: u64, host: &str, bytes: i64, end_ms: i64) -> EndedConnection {
        EndedConnection {
            id: Uuid::new_v4(),
            metadata: Arc::new(Metadata {
                network: Network::Tcp,
                conn_type: ConnType::Http,
                host: host.into(),
                dst_port: 443,
                dns_mode: DnsMode::Normal,
                process: "curl".into(),
                ..Metadata::default()
            }),
            upload: bytes,
            download: 0,
            interface: None,
            start: format!("2026-10-13T00:00:{:02}Z", seq % 60).into(),
            chains: SmallVec::from_vec(vec![Arc::from("DIRECT")]),
            rule: "MATCH".into(),
            rule_payload: "".into(),
            end: "2026-10-13T00:01:00Z".into(),
            end_ms,
            seq,
            rev: 0,
            count: 1,
            first: None,
        }
    }

    #[test]
    fn over_the_limit_the_old_ones_go_and_the_recent_stay() {
        let h = ConnectionHistory::new();
        h.set_limit(3);
        let now = 10 * KEEP_MS;
        // Three that ended long ago, then three just now.
        for i in 0..3 {
            h.push(ended(
                i + 1,
                &format!("old{i}.example"),
                1,
                now - 2 * KEEP_MS,
            ));
        }
        for i in 0..3 {
            h.push(ended(i + 4, &format!("new{i}.example"), 1, now));
        }
        let d = h.delta(0);
        assert_eq!(d.kept, vec![4, 5, 6]);
        // Recent ones stay past the limit, until the hard one.
        for i in 0..40 {
            h.push(ended(i + 7, &format!("burst{i}.example"), 1, now));
        }
        assert_eq!(h.len(), ConnectionHistory::hard_limit(3));
        assert_eq!(h.delta(0).kept.last(), Some(&46));
    }

    #[test]
    fn tries_that_moved_nothing_are_one_record() {
        let h = ConnectionHistory::new();
        h.push(ended(1, "down.example", 0, 1000));
        h.push(ended(2, "fine.example", 9, 2000));
        h.push(ended(3, "down.example", 0, 3000));
        h.push(ended(4, "down.example", 0, 4000));
        // One that moved something is its own, whatever it shares.
        h.push(ended(5, "fine.example", 9, 5000));
        let d = h.delta(0);
        assert_eq!(d.kept, vec![2, 4, 5]);
        let merged = d.changed.iter().find(|r| r.seq == 4).unwrap();
        assert_eq!(merged.count, 3);
        assert_eq!(merged.first.as_deref(), Some("2026-10-13T00:00:01Z"));
        let v = serde_json::to_value(merged).unwrap();
        assert_eq!(v["count"], 3);
        assert_eq!(v["metadata"]["host"], "down.example");
        assert_eq!(v["chains"], serde_json::json!(["DIRECT"]));
        // A single one says neither.
        let v = serde_json::to_value(d.changed.iter().find(|r| r.seq == 2).unwrap()).unwrap();
        assert!(v.get("count").is_none() && v.get("first").is_none());
    }

    #[test]
    fn a_reader_gets_only_what_changed_since() {
        let h = ConnectionHistory::new();
        h.push(ended(1, "a.example", 1, 1000));
        h.push(ended(2, "b.example", 1, 2000));
        let first = h.delta(0);
        assert_eq!(first.changed.len(), 2);
        assert!(h.delta(first.rev).changed.is_empty());
        h.push(ended(3, "c.example", 1, 3000));
        let next = h.delta(first.rev);
        assert_eq!(next.changed.len(), 1);
        assert_eq!(next.kept, vec![1, 2, 3]);
        h.clear();
        let cleared = h.delta(next.rev);
        assert!(cleared.kept.is_empty() && cleared.rev > next.rev);
    }

    #[test]
    fn saved_and_read_back_and_none_kept_at_zero() {
        let dir = std::env::temp_dir().join(format!("meow-history-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("connections.json");
        let h = ConnectionHistory::new();
        h.open(&path);
        h.push(ended(1, "a.example", 1, now_ms()));
        h.push(ended(2, "down.example", 0, now_ms()));
        h.push(ended(3, "down.example", 0, now_ms()));
        h.save();

        let again = ConnectionHistory::new();
        again.open(&path);
        let d = again.delta(0);
        assert_eq!(d.kept, vec![1, 3]);
        assert_eq!(d.changed[1].count, 2);
        assert_eq!(again.last_seq(), 3);

        again.set_limit(0);
        assert!(again.is_empty());
        again.push(ended(4, "b.example", 1, now_ms()));
        assert!(again.is_empty());
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
