//! The engine's files, under one directory of the core's data dir:
//!
//! | file | holds |
//! |---|---|
//! | `checkin.json` | tasks: steps, schedule, variable names and sources. No value |
//! | `checkin-secrets.json` | variable values (cookies, tokens, what the user typed) and the webview's User-Agent, by task |
//! | `checkin-runs.json` | the latest run of each task and the day each task last ran for the schedule |
//!
//! Every file is written whole to a scratch sibling and renamed over the
//! old one, readable by the owner only: on unix the scratch file is
//! created 0600 and the directory 0700, and both are tightened at load
//! when somebody widened them. Elsewhere (Windows) there are no modes;
//! the files inherit the access list of the core's data directory, which
//! is the user's own profile.
//!
//! Loading never fails: a missing file is empty, a file that is not JSON
//! or was written by a newer version is moved aside and replaced by an
//! empty one, an entry that does not read is left out. When the task file
//! is moved aside the other two go with it (same suffix): values and runs
//! belong to tasks, and would otherwise be wiped by the next write.
//!
//! Writing is two steps so the engine never holds its state lock over the
//! disk: [`Store::stage_tasks`] and friends turn the state into bytes and
//! number them (under the lock), [`Store::commit`] writes them (outside
//! it). A commit that arrives after a later one for the same file is
//! dropped, so the file always ends as the latest state.

use crate::model::{Run, Step, Task};
use crate::rule::{STEPS_MAX, VARIABLES_MAX};
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{BTreeMap, HashMap};
use std::fmt;
use std::io::{self, Write as _};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use tracing::warn;

pub const SCHEMA_VERSION: u64 = 1;

const TASKS_FILE: &str = "checkin.json";
const SECRETS_FILE: &str = "checkin-secrets.json";
const RUNS_FILE: &str = "checkin-runs.json";
const FILES: [&str; 3] = [TASKS_FILE, SECRETS_FILE, RUNS_FILE];

/// Tasks kept; the API refuses to create more, a file holding more is cut.
pub const TASKS_MAX: usize = 100;
/// Local days remembered per task as "has run", newest last.
pub const DONE_DAYS_MAX: usize = 4;

/// Task id → the local days (`yyyy-MM-dd`) a run that counts for the
/// schedule finished on, newest last. More than one day is kept so a clock
/// that steps back a day and forward again does not run that day twice.
pub type Done = HashMap<String, Vec<String>>;

/// Remembers that `task_id` ran on `day`.
pub fn mark_done(done: &mut Done, task_id: &str, day: &str) {
    let days = done.entry(task_id.to_string()).or_default();
    days.retain(|d| d != day);
    days.push(day.to_string());
    if days.len() > DONE_DAYS_MAX {
        let extra = days.len() - DONE_DAYS_MAX;
        days.drain(..extra);
    }
}

pub fn is_done(done: &Done, task_id: &str, day: &str) -> bool {
    done.get(task_id)
        .is_some_and(|days| days.iter().any(|d| d == day))
}

/// A variable's value. Never printed.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredValue {
    pub value: String,
    pub updated_at: String,
}

impl fmt::Debug for StoredValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StoredValue")
            .field("value", &"<redacted>")
            .field("updated_at", &self.updated_at)
            .finish()
    }
}

/// What one task knows that must stay on this machine.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TaskSecrets {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user_agent: Option<String>,
    #[serde(default)]
    pub values: BTreeMap<String, StoredValue>,
}

pub type Secrets = HashMap<String, TaskSecrets>;

/// Extra 登录失效 markers, editable by hand in `checkin.json`.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Settings {
    /// Path fragments that mean "this is a login page" (added to the
    /// built-in ones).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub login_paths: Vec<String>,
    /// Response texts that mean "not logged in" (added to the built-in
    /// ones).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub logged_out_texts: Vec<String>,
    /// Let request steps reach this machine and private networks
    /// (a self-hosted panel on the LAN). Off unless set by hand.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub allow_private: bool,
}

#[derive(Debug, Default)]
pub struct Loaded {
    pub tasks: Vec<Task>,
    pub settings: Settings,
    pub secrets: Secrets,
    pub runs: HashMap<String, Run>,
    pub done: Done,
}

/// One file's content, ready to write. See the module text.
#[must_use = "a staged write does nothing until committed"]
pub struct Staged {
    file: usize,
    seq: u64,
    bytes: Vec<u8>,
}

#[derive(Debug)]
pub struct Store {
    dir: PathBuf,
    seq: AtomicU64,
    /// Per file: the number of the latest content written.
    written: [Mutex<u64>; 3],
}

static SCRATCH_SEQ: AtomicU64 = AtomicU64::new(0);

enum Read {
    Missing,
    /// Moved aside under this suffix.
    Unusable(String),
    Usable(Value),
}

impl Store {
    pub fn new(dir: impl Into<PathBuf>) -> Self {
        Self {
            dir: dir.into(),
            seq: AtomicU64::new(0),
            written: [Mutex::new(0), Mutex::new(0), Mutex::new(0)],
        }
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    fn path(&self, name: &str) -> PathBuf {
        self.dir.join(name)
    }

    fn set_aside(&self, name: &str, suffix: &str) {
        let (path, aside) = (self.path(name), self.path(&format!("{name}.{suffix}")));
        if let Err(e) = std::fs::rename(&path, &aside) {
            if e.kind() != io::ErrorKind::NotFound {
                warn!("checkin: cannot set {name} aside: {e}");
            }
        }
    }

    /// The parsed file. A file that cannot be used is moved aside, never
    /// overwritten in place.
    fn read(&self, name: &str) -> Read {
        let path = self.path(name);
        let bytes = match std::fs::read(&path) {
            Ok(bytes) => bytes,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Read::Missing,
            Err(e) => {
                warn!("checkin: cannot read {name}: {e}");
                return Read::Missing;
            }
        };
        let value: Value = match serde_json::from_slice(&bytes) {
            Ok(v @ Value::Object(_)) => v,
            _ => {
                warn!("checkin: {name} is not readable; kept as {name}.corrupt, starting empty");
                self.set_aside(name, "corrupt");
                return Read::Unusable("corrupt".to_string());
            }
        };
        let version = value.get("version").and_then(Value::as_u64).unwrap_or(0);
        if version > SCHEMA_VERSION {
            warn!(
                "checkin: {name} was written by a newer version ({version}); kept as \
                 {name}.v{version}.bak, starting empty"
            );
            let suffix = format!("v{version}.bak");
            self.set_aside(name, &suffix);
            return Read::Unusable(suffix);
        }
        Read::Usable(value)
    }

    /// Owner-only modes on what is already there, and no scratch file left
    /// by a core that died mid-write (it holds what the real file holds).
    fn tidy(&self) {
        let Ok(entries) = std::fs::read_dir(&self.dir) else {
            return;
        };
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let tighten = |path: &Path, mode: u32| {
                if let Ok(meta) = std::fs::metadata(path) {
                    if meta.permissions().mode() & 0o777 & !mode != 0 {
                        let _ =
                            std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode));
                    }
                }
            };
            tighten(&self.dir, 0o700);
            for name in FILES {
                tighten(&self.path(name), 0o600);
            }
        }
        for entry in entries.flatten() {
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if name.ends_with(".tmp") && FILES.iter().any(|f| name.starts_with(&format!("{f}."))) {
                let _ = std::fs::remove_file(entry.path());
            }
        }
    }

    pub fn load(&self) -> Loaded {
        let mut out = Loaded::default();
        self.tidy();

        let tasks = self.read(TASKS_FILE);
        if let Read::Unusable(suffix) = &tasks {
            // Values and runs of tasks this core cannot read: kept beside
            // them rather than wiped by the next write.
            self.set_aside(SECRETS_FILE, suffix);
            self.set_aside(RUNS_FILE, suffix);
        }
        if let Read::Usable(mut file) = tasks {
            if let Some(settings) = file.get_mut("settings").map(Value::take) {
                out.settings = serde_json::from_value(settings).unwrap_or_default();
            }
            if let Some(Value::Array(tasks)) = file.get_mut("tasks").map(Value::take) {
                let mut skipped = 0usize;
                for mut task in tasks {
                    // Steps one by one: a step of a kind this version does
                    // not know must not take the task with it.
                    let steps = match task.get_mut("steps").map(Value::take) {
                        Some(Value::Array(steps)) => steps,
                        _ => Vec::new(),
                    };
                    if let Some(obj) = task.as_object_mut() {
                        obj.remove("steps");
                    }
                    match serde_json::from_value::<Task>(task) {
                        Ok(mut task) if !task.id.is_empty() => {
                            task.steps = steps
                                .into_iter()
                                .filter_map(|s| serde_json::from_value::<Step>(s).ok())
                                .take(STEPS_MAX)
                                .collect();
                            task.variables.truncate(VARIABLES_MAX);
                            if out.tasks.len() < TASKS_MAX
                                && !out.tasks.iter().any(|t| t.id == task.id)
                            {
                                out.tasks.push(task);
                            }
                        }
                        _ => skipped += 1,
                    }
                }
                if skipped > 0 {
                    // The next write drops them from the file: keep a copy.
                    let _ = std::fs::copy(
                        self.path(TASKS_FILE),
                        self.path(&format!("{TASKS_FILE}.partial.bak")),
                    );
                    warn!(
                        "checkin: left out {skipped} unreadable task(s) of {TASKS_FILE}; \
                         the file as it was is kept as {TASKS_FILE}.partial.bak"
                    );
                }
            }
        }

        if let Read::Usable(mut file) = self.read(SECRETS_FILE) {
            if let Some(Value::Object(tasks)) = file.get_mut("tasks").map(Value::take) {
                for (id, secrets) in tasks {
                    if let Ok(secrets) = serde_json::from_value::<TaskSecrets>(secrets) {
                        out.secrets.insert(id, secrets);
                    }
                }
            }
        }

        if let Read::Usable(mut file) = self.read(RUNS_FILE) {
            if let Some(Value::Array(runs)) = file.get_mut("runs").map(Value::take) {
                for run in runs {
                    if let Ok(run) = serde_json::from_value::<Run>(run) {
                        out.runs.insert(run.task_id.clone(), run);
                    }
                }
            }
            if let Some(Value::Object(done)) = file.get_mut("done").map(Value::take) {
                for (id, days) in done {
                    // One day as a string, or the days as a list.
                    let days: Vec<String> = match days {
                        Value::String(day) => vec![day],
                        Value::Array(days) => days
                            .into_iter()
                            .filter_map(|d| d.as_str().map(str::to_string))
                            .collect(),
                        _ => continue,
                    };
                    for day in days.iter().filter(|d| d.len() == 10) {
                        mark_done(&mut out.done, &id, day);
                    }
                }
            }
        }

        // Nothing of a task that is gone.
        let known = |id: &String| out.tasks.iter().any(|t| &t.id == id);
        out.secrets.retain(|id, _| known(id));
        out.runs.retain(|id, _| known(id));
        out.done.retain(|id, _| known(id));
        out
    }

    fn stage<T: Serialize>(&self, file: usize, content: &T) -> io::Result<Staged> {
        let bytes = serde_json::to_vec_pretty(content).map_err(io::Error::other)?;
        Ok(Staged {
            file,
            seq: self.seq.fetch_add(1, Ordering::SeqCst) + 1,
            bytes,
        })
    }

    pub fn stage_tasks(&self, tasks: &[Task], settings: &Settings) -> io::Result<Staged> {
        #[derive(Serialize)]
        struct File<'a> {
            version: u64,
            tasks: &'a [Task],
            settings: &'a Settings,
        }
        self.stage(
            0,
            &File {
                version: SCHEMA_VERSION,
                tasks,
                settings,
            },
        )
    }

    pub fn stage_secrets(&self, secrets: &Secrets) -> io::Result<Staged> {
        #[derive(Serialize)]
        struct File<'a> {
            version: u64,
            // Sorted: the file does not reshuffle between writes.
            tasks: BTreeMap<&'a str, &'a TaskSecrets>,
        }
        self.stage(
            1,
            &File {
                version: SCHEMA_VERSION,
                tasks: secrets.iter().map(|(k, v)| (k.as_str(), v)).collect(),
            },
        )
    }

    pub fn stage_runs(&self, runs: &HashMap<String, Run>, done: &Done) -> io::Result<Staged> {
        #[derive(Serialize)]
        struct File<'a> {
            version: u64,
            runs: Vec<&'a Run>,
            done: BTreeMap<&'a str, &'a [String]>,
        }
        let mut list: Vec<&Run> = runs.values().collect();
        list.sort_by(|a, b| a.task_id.cmp(&b.task_id));
        self.stage(
            2,
            &File {
                version: SCHEMA_VERSION,
                runs: list,
                done: done
                    .iter()
                    .map(|(k, v)| (k.as_str(), v.as_slice()))
                    .collect(),
            },
        )
    }

    /// Writes staged content, unless later content of the same file is
    /// already written.
    pub fn commit(&self, staged: Staged) -> io::Result<()> {
        let Staged { file, seq, bytes } = staged;
        let mut written = self.written[file].lock();
        if seq < *written {
            return Ok(());
        }
        self.write(FILES[file], &bytes)?;
        *written = seq;
        Ok(())
    }

    pub fn save_tasks(&self, tasks: &[Task], settings: &Settings) -> io::Result<()> {
        self.commit(self.stage_tasks(tasks, settings)?)
    }

    pub fn save_secrets(&self, secrets: &Secrets) -> io::Result<()> {
        self.commit(self.stage_secrets(secrets)?)
    }

    pub fn save_runs(&self, runs: &HashMap<String, Run>, done: &Done) -> io::Result<()> {
        self.commit(self.stage_runs(runs, done)?)
    }

    fn write(&self, name: &str, bytes: &[u8]) -> io::Result<()> {
        self.ensure_dir()?;
        let target = self.path(name);
        let scratch = self.path(&format!(
            "{name}.{}.{}.tmp",
            std::process::id(),
            SCRATCH_SEQ.fetch_add(1, Ordering::Relaxed)
        ));
        let result = (|| {
            let mut options = std::fs::OpenOptions::new();
            // `create_new`: never through a link somebody left there.
            options.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt as _;
                options.mode(0o600);
            }
            let mut file = options.open(&scratch)?;
            file.write_all(bytes)?;
            file.sync_all()?;
            drop(file);
            std::fs::rename(&scratch, &target)
        })();
        if result.is_err() {
            let _ = std::fs::remove_file(&scratch);
        }
        result
    }

    fn ensure_dir(&self) -> io::Result<()> {
        if self.dir.is_dir() {
            return Ok(());
        }
        let mut builder = std::fs::DirBuilder::new();
        builder.recursive(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt as _;
            builder.mode(0o700);
        }
        builder.create(&self.dir)
    }
}
