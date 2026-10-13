//! The engine: tasks and their edits, the one queue, the runner, the
//! schedule.
//!
//! Everything that changes state goes through [`Engine`]; every change
//! bumps a counter the API's event stream follows ([`Engine::changes`]).
//!
//! Running is strictly serial: one queue for manual runs, trial runs, the
//! schedule and 现在全部执行; one task at a time ([`Engine::run_pending`]
//! holds a lock for the whole drain); a task's steps in order.
//!
//! Locks: `state` (a plain mutex) is only ever held for memory work, never
//! across an `.await` and never over the disk: a change is turned into
//! bytes under it ([`Writes`]) and written after it is released. The click
//! hub has a lock of its own and is never entered with `state` held.

use crate::clicks::{ClickHub, ClickOutcome};
use crate::clock::{local_now, rfc3339, Clock, LocalNow};
use crate::error::{CheckinError, Result};
use crate::expiry::{self, Markers};
use crate::http::{Connector, Limits};
use crate::model::{
    ApiStep, ClickReport, ClickRequest, ClickStep, RuleCheck, RuleExport, Run, Snapshot, Source,
    Step, StepResult, StepStatus, Task, TaskView, Trigger, VariableView, MASK,
};
use crate::replay::{self, Jar, Outbound, Variables};
use crate::rule::{self, Reader, DEFAULT_MINUTE, USER_AGENT_MAX, VALUE_MAX, VARIABLES_MAX};
use crate::site;
use crate::store::{
    is_done, mark_done, Done, Loaded, Secrets, Settings, Staged, Store, StoredValue, TaskSecrets,
};
use crate::vars;
use parking_lot::Mutex;
use serde_json::{Map, Value};
use std::collections::{HashMap, VecDeque};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use time::OffsetDateTime;
use tokio::sync::{watch, Notify};
use tracing::{debug, warn};

pub use crate::store::TASKS_MAX;

#[derive(Clone, Debug)]
pub struct EngineConfig {
    /// How long a click step waits for an app when none is attached, and
    /// how long the apps may all be gone mid-step, before `needs_app`.
    pub attach_wait: Duration,
    /// What the app is given to perform one click step.
    pub click_timeout_ms: u64,
    /// On top of `click_timeout_ms` before a silent app fails the step.
    pub click_report_grace: Duration,
    pub limits: Limits,
    /// How often the schedule looks at the clock.
    pub tick: Duration,
    /// Before the schedule's first look after start: time for the app to
    /// attach, so a catch-up run finds it.
    pub start_delay: Duration,
    /// Let request steps reach this machine and private networks. Off:
    /// such a step fails with a sentence and nothing is sent. Also
    /// switched on by `"settings": {"allow_private": true}` in
    /// `checkin.json`.
    pub allow_private: bool,
    /// Trust anchors (DER) for HTTPS on top of the built-in ones.
    pub extra_roots: Vec<Vec<u8>>,
}

impl Default for EngineConfig {
    fn default() -> Self {
        Self {
            attach_wait: Duration::from_secs(3),
            click_timeout_ms: 20_000,
            click_report_grace: Duration::from_secs(30),
            limits: Limits::default(),
            tick: Duration::from_secs(20),
            start_delay: Duration::from_secs(20),
            allow_private: false,
            extra_roots: Vec::new(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Job {
    task_id: String,
    trigger: Trigger,
    /// Only the click steps the latest run left as `needs_app`.
    resume: bool,
}

struct State {
    tasks: Vec<Task>,
    settings: Settings,
    secrets: Secrets,
    runs: HashMap<String, Run>,
    done: Done,
    queue: VecDeque<Job>,
    running: Option<String>,
}

pub struct Engine {
    store: Store,
    connector: Arc<dyn Connector>,
    clock: Arc<dyn Clock>,
    config: EngineConfig,
    markers: Markers,
    allow_private: bool,
    state: Mutex<State>,
    changes: watch::Sender<u64>,
    wake: Notify,
    draining: tokio::sync::Mutex<()>,
    clicks: ClickHub,
    started_at: OffsetDateTime,
    click_seq: AtomicU64,
}

/// The engine's background tasks. Dropping it stops them.
#[must_use = "dropping it stops the runner and the schedule"]
pub struct EngineTasks(Vec<tokio::task::JoinHandle<()>>);

impl Drop for EngineTasks {
    fn drop(&mut self) {
        for task in &self.0 {
            task.abort();
        }
    }
}

/// Changes turned into bytes under the state lock, to be written once it
/// is released ([`Engine::commit`]).
#[derive(Default)]
struct Writes {
    /// Tasks and values: the call fails when one cannot be written.
    must: Vec<(&'static str, std::io::Result<Staged>)>,
    /// Runs: a failure is logged and the engine goes on.
    may: Vec<std::io::Result<Staged>>,
}

const TASK_MISSING: &str = "这个任务已经不在了。";
const BODY_INVALID: &str = "请求内容格式不对。";

fn object(body: &Value) -> Result<&Map<String, Value>> {
    body.as_object()
        .ok_or_else(|| CheckinError::invalid(BODY_INVALID))
}

fn new_id(prefix: char, taken: impl Fn(&str) -> bool) -> String {
    loop {
        let id = format!(
            "{prefix}{}",
            &uuid::Uuid::new_v4().simple().to_string()[..8]
        );
        if !taken(&id) {
            return id;
        }
    }
}

fn has_value(secrets: &Secrets, task_id: &str, name: &str) -> bool {
    secrets
        .get(task_id)
        .and_then(|s| s.values.get(name))
        .is_some_and(|v| !v.value.is_empty())
}

/// Manual variables nobody has filled in.
fn unfilled<'a>(task: &'a Task, secrets: &Secrets) -> Vec<&'a str> {
    task.variables
        .iter()
        .filter(|v| v.source == Source::Manual && !has_value(secrets, &task.id, &v.name))
        .map(|v| v.name.as_str())
        .collect()
}

fn view(task: &Task, secrets: &Secrets, reveal_manual: bool) -> TaskView {
    let stored = secrets.get(&task.id);
    TaskView {
        id: task.id.clone(),
        name: task.name.clone(),
        home: task.home.clone(),
        access: task.access,
        policy: task.proxy_policy.clone(),
        minute_of_day: task.minute_of_day,
        enabled: task.enabled,
        subscription_id: task.subscription_id.clone(),
        steps: task.steps.clone(),
        variables: task
            .variables
            .iter()
            .map(|def| {
                let value = stored
                    .and_then(|s| s.values.get(&def.name))
                    .filter(|v| !v.value.is_empty());
                let manual = def.source == Source::Manual;
                VariableView {
                    name: def.name.clone(),
                    source: def.source,
                    from: def.from,
                    key: (!manual).then(|| def.key.clone()),
                    url: (!manual).then(|| def.url.clone()),
                    // An auto value never leaves; a manual one is what the
                    // user typed and is shown back only on request.
                    value: manual.then(|| match value {
                        Some(v) if reveal_manual => v.value.clone(),
                        Some(_) => MASK.to_string(),
                        None => String::new(),
                    }),
                    masked: manual.then(|| value.is_some() && !reveal_manual),
                    has_value: value.is_some(),
                    updated_at: value.map(|v| v.updated_at.clone()),
                }
            })
            .collect(),
    }
}

impl State {
    fn task(&self, id: &str) -> Result<&Task> {
        self.tasks
            .iter()
            .find(|t| t.id == id)
            .ok_or_else(|| CheckinError::not_found(TASK_MISSING))
    }

    fn task_mut(&mut self, id: &str) -> Result<&mut Task> {
        self.tasks
            .iter_mut()
            .find(|t| t.id == id)
            .ok_or_else(|| CheckinError::not_found(TASK_MISSING))
    }

    fn view(&self, id: &str, reveal_manual: bool) -> Result<TaskView> {
        Ok(view(self.task(id)?, &self.secrets, reveal_manual))
    }
}

impl Engine {
    /// Opens the engine on the files under `dir` (created on first write).
    pub fn open(
        dir: impl Into<PathBuf>,
        connector: Arc<dyn Connector>,
        clock: Arc<dyn Clock>,
        config: EngineConfig,
    ) -> Arc<Self> {
        let store = Store::new(dir);
        let Loaded {
            tasks,
            settings,
            secrets,
            runs,
            done,
        } = store.load();
        let markers = Markers::with_extra(&settings.login_paths, &settings.logged_out_texts);
        let allow_private = config.allow_private || settings.allow_private;
        let started_at = clock.now_utc();
        Arc::new(Self {
            store,
            connector,
            clock,
            config,
            markers,
            allow_private,
            state: Mutex::new(State {
                tasks,
                settings,
                secrets,
                runs,
                done,
                queue: VecDeque::new(),
                running: None,
            }),
            changes: watch::channel(0).0,
            wake: Notify::new(),
            draining: tokio::sync::Mutex::new(()),
            clicks: ClickHub::default(),
            started_at,
            click_seq: AtomicU64::new(0),
        })
    }

    /// Starts the runner, the schedule and the watch for an app attaching.
    /// Must be called inside a tokio runtime.
    pub fn start(self: &Arc<Self>) -> EngineTasks {
        let runner = {
            let engine = Arc::clone(self);
            tokio::spawn(async move {
                loop {
                    engine.run_pending().await;
                    engine.wake.notified().await;
                }
            })
        };
        let schedule = {
            let engine = Arc::clone(self);
            tokio::spawn(async move {
                tokio::time::sleep(engine.config.start_delay).await;
                loop {
                    engine.tick();
                    tokio::time::sleep(engine.config.tick).await;
                }
            })
        };
        let attach = {
            let engine = Arc::clone(self);
            tokio::spawn(async move {
                let mut attached = engine.clicks.watch_attached();
                loop {
                    if attached.wait_for(|n| *n > 0).await.is_err() {
                        return;
                    }
                    engine.resume_needs_app();
                    if attached.wait_for(|n| *n == 0).await.is_err() {
                        return;
                    }
                }
            })
        };
        EngineTasks(vec![runner, schedule, attach])
    }

    // ---- reading ----

    /// A counter bumped after every change of what [`Self::snapshot`]
    /// returns.
    pub fn changes(&self) -> watch::Receiver<u64> {
        self.changes.subscribe()
    }

    fn changed(&self) {
        self.changes.send_modify(|n| *n = n.wrapping_add(1));
    }

    /// Everything the page shows. Auto values are never in it; manual
    /// values are masked unless `reveal_manual`.
    pub fn snapshot(&self, reveal_manual: bool) -> Snapshot {
        let st = self.state.lock();
        Snapshot {
            tasks: st
                .tasks
                .iter()
                .map(|t| view(t, &st.secrets, reveal_manual))
                .collect(),
            runs: st
                .tasks
                .iter()
                .filter_map(|t| st.runs.get(&t.id).cloned())
                .collect(),
            running_task_id: st.running.clone(),
            queued_task_ids: st.queue.iter().map(|j| j.task_id.clone()).collect(),
        }
    }

    pub fn clicks(&self) -> &ClickHub {
        &self.clicks
    }

    /// Whether request steps may reach this machine and private networks.
    pub fn allow_private(&self) -> bool {
        self.allow_private
    }

    // ---- writing ----

    fn stage_tasks(&self, st: &State, w: &mut Writes) {
        w.must
            .push(("tasks", self.store.stage_tasks(&st.tasks, &st.settings)));
    }

    fn stage_secrets(&self, st: &State, w: &mut Writes) {
        w.must
            .push(("values", self.store.stage_secrets(&st.secrets)));
    }

    fn stage_runs(&self, st: &State, w: &mut Writes) {
        w.may.push(self.store.stage_runs(&st.runs, &st.done));
    }

    /// Writes what was staged and tells the followers. Call it with the
    /// state lock released.
    fn commit(&self, w: Writes) -> Result<()> {
        let mut out = Ok(());
        for (what, staged) in w.must {
            if let Err(e) = staged.and_then(|s| self.store.commit(s)) {
                warn!("checkin: cannot save {what}: {e}");
                out = Err(CheckinError::storage());
            }
        }
        for staged in w.may {
            if let Err(e) = staged.and_then(|s| self.store.commit(s)) {
                warn!("checkin: cannot save runs: {e}");
            }
        }
        self.changed();
        out
    }

    pub fn create_task(&self, body: &Value, reveal_manual: bool) -> Result<TaskView> {
        let obj = object(body)?;
        let home = Reader::home(obj)?;
        let host = site::parse_http_url(&home)
            .map(|u| site::host_of(&u))
            .unwrap_or_default();
        let mut st = self.state.lock();
        if st.tasks.len() >= TASKS_MAX {
            return Err(CheckinError::too_large(format!(
                "任务数量已到上限（{TASKS_MAX} 个）。"
            )));
        }
        let task = Task {
            id: new_id('t', |id| st.tasks.iter().any(|t| t.id == id)),
            name: Reader::name(obj)?.filter(|n| !n.is_empty()).unwrap_or(host),
            home,
            access: Reader::access(obj)?.unwrap_or_default(),
            proxy_policy: Reader::policy(obj)?.flatten(),
            minute_of_day: Reader::minute_of_day(obj)?.unwrap_or(DEFAULT_MINUTE),
            enabled: Reader::enabled(obj)?.unwrap_or(false),
            subscription_id: Reader::subscription_id(obj)?.flatten(),
            steps: Vec::new(),
            variables: Vec::new(),
        };
        let id = task.id.clone();
        st.tasks.push(task);
        let mut w = Writes::default();
        self.stage_tasks(&st, &mut w);
        let out = st.view(&id, reveal_manual);
        drop(st);
        self.commit(w)?;
        out
    }

    pub fn update_task(&self, id: &str, body: &Value, reveal_manual: bool) -> Result<TaskView> {
        let obj = object(body)?;
        let name = Reader::name(obj)?;
        let home = match obj.get("home") {
            None | Some(Value::Null) => None,
            Some(_) => Some(Reader::home(obj)?),
        };
        let access = Reader::access(obj)?;
        let policy = Reader::policy(obj)?;
        let minute = Reader::minute_of_day(obj)?;
        let enabled = Reader::enabled(obj)?;
        let subscription = Reader::subscription_id(obj)?;
        let mut st = self.state.lock();
        let task = st.task_mut(id)?;
        if let Some(name) = name.filter(|n| !n.is_empty()) {
            task.name = name;
        }
        let mut orphaned: Vec<String> = Vec::new();
        if let Some(home) = home {
            let site_of = |home: &str| {
                site::parse_http_url(home).map(|u| site::registrable(&site::host_of(&u)))
            };
            if site_of(&home) != site_of(&task.home) {
                // A login read for the old site (no `url` of its own) is
                // not the new site's.
                orphaned = task
                    .variables
                    .iter()
                    .filter(|v| {
                        v.source == Source::Auto
                            && v.url.is_none()
                            && v.from.is_some_and(crate::model::AutoFrom::is_site_bound)
                    })
                    .map(|v| v.name.clone())
                    .collect();
            }
            task.home = home;
        }
        if let Some(access) = access {
            task.access = access;
        }
        if let Some(policy) = policy {
            task.proxy_policy = policy;
        }
        if let Some(minute) = minute {
            task.minute_of_day = minute;
        }
        if let Some(enabled) = enabled {
            task.enabled = enabled;
        }
        if let Some(subscription) = subscription {
            task.subscription_id = subscription;
        }
        let mut w = Writes::default();
        let mut dropped = false;
        if let Some(stored) = st.secrets.get_mut(id) {
            for name in &orphaned {
                dropped |= stored.values.remove(name).is_some();
            }
        }
        self.stage_tasks(&st, &mut w);
        if dropped {
            self.stage_secrets(&st, &mut w);
        }
        let out = st.view(id, reveal_manual);
        drop(st);
        self.commit(w)?;
        out
    }

    pub fn delete_task(&self, id: &str) -> Result<()> {
        let mut st = self.state.lock();
        st.task(id)?;
        st.tasks.retain(|t| t.id != id);
        st.queue.retain(|j| j.task_id != id);
        st.runs.remove(id);
        st.done.remove(id);
        let had_secrets = st.secrets.remove(id).is_some();
        let mut w = Writes::default();
        self.stage_tasks(&st, &mut w);
        if had_secrets {
            self.stage_secrets(&st, &mut w);
        }
        self.stage_runs(&st, &mut w);
        drop(st);
        self.commit(w)
    }

    /// `{"task_ids": [...]}`: those first, in that order; the rest keep
    /// theirs behind.
    pub fn reorder_tasks(&self, body: &Value) -> Result<()> {
        let ids: Vec<&str> = object(body)?
            .get("task_ids")
            .and_then(Value::as_array)
            .ok_or_else(|| CheckinError::invalid(BODY_INVALID))?
            .iter()
            .filter_map(Value::as_str)
            .collect();
        let mut st = self.state.lock();
        let mut rest = std::mem::take(&mut st.tasks);
        let mut next = Vec::with_capacity(rest.len());
        for id in ids {
            if let Some(at) = rest.iter().position(|t| t.id == id) {
                next.push(rest.remove(at));
            }
        }
        next.append(&mut rest);
        st.tasks = next;
        let mut w = Writes::default();
        self.stage_tasks(&st, &mut w);
        drop(st);
        self.commit(w)
    }

    /// `{"steps": [...]}`: the complete list. A step with an empty id is
    /// new; steps left out are gone.
    pub fn save_steps(&self, id: &str, body: &Value, reveal_manual: bool) -> Result<TaskView> {
        let mut steps = Reader::default().steps(object(body)?)?;
        let mut st = self.state.lock();
        st.task(id)?;
        let mut seen: Vec<String> = Vec::with_capacity(steps.len());
        for step in &mut steps {
            if step.id().is_empty() || seen.iter().any(|s| s == step.id()) {
                step.set_id(new_id('s', |c| seen.iter().any(|s| s == c)));
            }
            seen.push(step.id().to_string());
        }
        st.task_mut(id)?.steps = steps;
        let mut w = Writes::default();
        self.stage_tasks(&st, &mut w);
        let out = st.view(id, reveal_manual);
        drop(st);
        self.commit(w)?;
        out
    }

    /// Adds a variable, or changes the one called `path_name`.
    pub fn save_variable(
        &self,
        id: &str,
        path_name: &str,
        body: &Value,
        reveal_manual: bool,
    ) -> Result<TaskView> {
        let (def, value) = Reader::default().variable(object(body)?)?;
        let now = rfc3339(self.clock.now_utc());
        let mut st = self.state.lock();
        let task = st.task(id)?;
        let at = task.variables.iter().position(|v| v.name == path_name);
        if task
            .variables
            .iter()
            .enumerate()
            .any(|(i, v)| v.name == def.name && Some(i) != at)
        {
            return Err(CheckinError::conflict(format!(
                "已经有一个叫 {} 的变量了。",
                def.name
            )));
        }
        if at.is_none() && task.variables.len() >= VARIABLES_MAX {
            return Err(CheckinError::too_large(format!(
                "变量数量已到上限（{VARIABLES_MAX} 个）。"
            )));
        }
        let old = at.map(|i| task.variables[i].clone());
        let renamed = old.as_ref().is_some_and(|o| o.name != def.name);
        // A value read from somewhere else is not this variable's value.
        let same_origin = old.as_ref().is_some_and(|o| {
            o.source == def.source && o.from == def.from && o.key == def.key && o.url == def.url
        });

        let mut secrets_changed = false;
        if let Some(old) = &old {
            let stored = st.secrets.get_mut(id);
            if let Some(stored) = stored {
                let kept = stored.values.remove(&old.name);
                secrets_changed = kept.is_some();
                if let Some(kept) = kept.filter(|_| same_origin) {
                    stored.values.insert(def.name.clone(), kept);
                    secrets_changed = renamed;
                }
            }
        }
        if def.source == Source::Manual {
            match value.as_deref() {
                // Absent, or the mask handed back: unchanged.
                None => {}
                Some(v) if v == MASK && has_value(&st.secrets, id, &def.name) => {}
                Some("") => {
                    if let Some(stored) = st.secrets.get_mut(id) {
                        secrets_changed |= stored.values.remove(&def.name).is_some();
                    }
                }
                Some(v) => {
                    st.secrets.entry(id.to_string()).or_default().values.insert(
                        def.name.clone(),
                        StoredValue {
                            value: v.to_string(),
                            updated_at: now,
                        },
                    );
                    secrets_changed = true;
                }
            }
        }

        let task = st.task_mut(id)?;
        if renamed {
            if let Some(old) = &old {
                for step in &mut task.steps {
                    let Step::Api(s) = step else { continue };
                    s.url = vars::rename_refs(&s.url, &old.name, &def.name);
                    for value in s.headers.values_mut() {
                        *value = vars::rename_refs(value, &old.name, &def.name);
                    }
                    if !s.body_base64 {
                        if let Some(body) = &mut s.body {
                            *body = vars::rename_refs(body, &old.name, &def.name);
                        }
                    }
                }
            }
        }
        match at {
            Some(i) => task.variables[i] = def,
            None => task.variables.push(def),
        }
        let mut w = Writes::default();
        self.stage_tasks(&st, &mut w);
        if secrets_changed {
            self.stage_secrets(&st, &mut w);
        }
        let out = st.view(id, reveal_manual);
        drop(st);
        self.commit(w)?;
        out
    }

    pub fn delete_variable(&self, id: &str, name: &str, reveal_manual: bool) -> Result<TaskView> {
        let mut st = self.state.lock();
        let task = st.task_mut(id)?;
        let before = task.variables.len();
        task.variables.retain(|v| v.name != name);
        let removed = task.variables.len() != before;
        let had_value = st
            .secrets
            .get_mut(id)
            .is_some_and(|s| s.values.remove(name).is_some());
        let mut w = Writes::default();
        if removed {
            self.stage_tasks(&st, &mut w);
        }
        if had_value {
            self.stage_secrets(&st, &mut w);
        }
        let out = st.view(id, reveal_manual);
        drop(st);
        if removed || had_value {
            self.commit(w)?;
        }
        out
    }

    /// `{"values": {name: value}, "user_agent": "…"}` from the app's
    /// webview. Only names that are `auto` variables of the task are
    /// taken; the rest is ignored.
    pub fn push_variables(&self, id: &str, body: &Value) -> Result<()> {
        let obj = object(body)?;
        let now = rfc3339(self.clock.now_utc());
        let mut st = self.state.lock();
        let task = st.task(id)?;
        let mut accepted: Vec<(String, String)> = Vec::new();
        if let Some(Value::Object(values)) = obj.get("values") {
            for (name, value) in values {
                let Value::String(value) = value else {
                    continue;
                };
                if value.is_empty() || value.len() > VALUE_MAX {
                    continue;
                }
                if task
                    .variable(name)
                    .is_some_and(|v| v.source == Source::Auto)
                {
                    accepted.push((name.clone(), value.clone()));
                }
            }
        }
        let user_agent = obj
            .get("user_agent")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|ua| !ua.is_empty() && ua.len() <= USER_AGENT_MAX && vars::header_safe(ua));
        let stored = st.secrets.entry(id.to_string()).or_default();
        let mut changed = !accepted.is_empty();
        for (name, value) in accepted {
            stored.values.insert(
                name,
                StoredValue {
                    value,
                    updated_at: now.clone(),
                },
            );
        }
        if let Some(ua) = user_agent {
            if stored.user_agent.as_deref() != Some(ua) {
                stored.user_agent = Some(ua.to_string());
                changed = true;
            }
        }
        if !changed {
            return Ok(());
        }
        let mut w = Writes::default();
        self.stage_secrets(&st, &mut w);
        drop(st);
        self.commit(w)
    }

    // ---- rules ----

    pub fn export_rule(&self, id: &str) -> Result<RuleExport> {
        rule::export_rule(self.state.lock().task(id)?)
    }

    /// Reads a rule without creating anything.
    pub fn check_rule(&self, text: &str) -> RuleCheck {
        rule::check_rule(text)
    }

    /// Creates a task from a rule: switched off, without any value.
    /// Nothing is sent.
    pub fn import_rule(&self, text: &str, reveal_manual: bool) -> Result<TaskView> {
        let parsed = rule::read_rule(text)?;
        let mut st = self.state.lock();
        if st.tasks.len() >= TASKS_MAX {
            return Err(CheckinError::too_large(format!(
                "任务数量已到上限（{TASKS_MAX} 个）。"
            )));
        }
        let mut steps = parsed.steps;
        let mut seen: Vec<String> = Vec::with_capacity(steps.len());
        for step in &mut steps {
            step.set_id(new_id('s', |c| seen.iter().any(|s| s == c)));
            seen.push(step.id().to_string());
        }
        let task = Task {
            id: new_id('t', |id| st.tasks.iter().any(|t| t.id == id)),
            name: parsed.name,
            home: parsed.home,
            access: parsed.access,
            // Names of this core's own lines: a rule carries none.
            proxy_policy: None,
            minute_of_day: parsed.minute_of_day,
            // The user looks at it, logs in, and switches it on.
            enabled: false,
            subscription_id: None,
            steps,
            variables: parsed.variables,
        };
        let id = task.id.clone();
        st.tasks.push(task);
        let mut w = Writes::default();
        self.stage_tasks(&st, &mut w);
        let out = st.view(&id, reveal_manual);
        drop(st);
        self.commit(w)?;
        out
    }

    // ---- queueing ----

    fn enqueue(&self, st: &mut State, job: Job) -> bool {
        if st.queue.contains(&job) {
            return false;
        }
        st.queue.push_back(job);
        self.wake.notify_one();
        true
    }

    /// Queues one run. Refused while a manual variable is unfilled.
    pub fn run_task(&self, id: &str, trial: bool) -> Result<()> {
        let mut st = self.state.lock();
        let task = st.task(id)?;
        let missing = unfilled(task, &st.secrets);
        if !missing.is_empty() {
            return Err(CheckinError::conflict(format!(
                "还有变量没填写：{}。填好后再执行。",
                missing.join("、")
            )));
        }
        let job = Job {
            task_id: id.to_string(),
            trigger: if trial {
                Trigger::Trial
            } else {
                Trigger::Manual
            },
            resume: false,
        };
        let queued = self.enqueue(&mut st, job);
        drop(st);
        if queued {
            self.changed();
        }
        Ok(())
    }

    /// 现在全部执行: every enabled task that can run, in tab order.
    /// Returns how many were queued.
    pub fn run_all(&self) -> usize {
        let mut st = self.state.lock();
        let ids: Vec<String> = st
            .tasks
            .iter()
            .filter(|t| t.enabled && unfilled(t, &st.secrets).is_empty())
            .map(|t| t.id.clone())
            .collect();
        let mut queued = 0;
        for task_id in ids {
            let job = Job {
                task_id,
                trigger: Trigger::Manual,
                resume: false,
            };
            if self.enqueue(&mut st, job) {
                queued += 1;
            }
        }
        drop(st);
        if queued > 0 {
            self.changed();
        }
        queued
    }

    /// The schedule's look at the clock: queues every enabled task whose
    /// time today has come and that has not run today. Returns their ids.
    ///
    /// Only "now" is consulted, so a clock that jumps cannot strand a
    /// task: after a jump forward the run is simply due; after a jump back
    /// within the day nothing is due again. The last few days a task ran
    /// on are remembered, so a clock that steps back a day and forward
    /// again runs neither day twice.
    pub fn tick(&self) -> Vec<String> {
        let now = local_now(self.clock.as_ref());
        let mut st = self.state.lock();
        let due: Vec<(String, Trigger)> = st
            .tasks
            .iter()
            .filter(|t| {
                t.enabled
                    && !t.steps.is_empty()
                    && now.minute >= t.minute_of_day
                    && !is_done(&st.done, &t.id, &now.day)
                    && st.running.as_deref() != Some(t.id.as_str())
                    && !st
                        .queue
                        .iter()
                        .any(|j| j.task_id == t.id && j.trigger != Trigger::Trial)
                    && unfilled(t, &st.secrets).is_empty()
            })
            .map(|t| {
                // Was the time already past when the core started? Then
                // this is the run it missed.
                let late = i64::from(now.minute - t.minute_of_day) * 60;
                let due_at = now.utc - time::Duration::seconds(late + i64::from(now.utc.second()));
                let trigger = if due_at < self.started_at {
                    Trigger::CatchUp
                } else {
                    Trigger::Scheduled
                };
                (t.id.clone(), trigger)
            })
            .collect();
        let mut queued = Vec::new();
        for (task_id, trigger) in due {
            let job = Job {
                task_id: task_id.clone(),
                trigger,
                resume: false,
            };
            if self.enqueue(&mut st, job) {
                queued.push(task_id);
            }
        }
        drop(st);
        if !queued.is_empty() {
            self.changed();
        }
        queued
    }

    /// An app has attached: the click steps today's runs left as
    /// `needs_app` can be done now.
    pub fn resume_needs_app(&self) -> usize {
        let today = local_now(self.clock.as_ref()).day;
        let mut st = self.state.lock();
        let jobs: Vec<Job> = st
            .tasks
            .iter()
            .filter_map(|t| {
                let run = st.runs.get(&t.id)?;
                let waiting = run.finished_at.is_some()
                    && run.day == today
                    && run.trigger != Trigger::Trial
                    && run.steps.iter().any(|s| s.status == StepStatus::NeedsApp);
                waiting.then(|| Job {
                    task_id: t.id.clone(),
                    trigger: run.trigger,
                    resume: true,
                })
            })
            .collect();
        let mut queued = 0;
        for job in jobs {
            if self.enqueue(&mut st, job) {
                queued += 1;
            }
        }
        drop(st);
        if queued > 0 {
            self.changed();
        }
        queued
    }

    // ---- running ----

    /// Runs what is queued, one task after another, until the queue is
    /// empty. A second caller waits for the first: never two tasks at
    /// once.
    pub async fn run_pending(&self) {
        let _serial = self.draining.lock().await;
        loop {
            let job = self.state.lock().queue.pop_front();
            let Some(job) = job else { break };
            self.run_job(job).await;
        }
    }

    /// Records the run as it stands. `false`: the task is gone.
    fn put_run(&self, run: &Run) -> bool {
        let mut w = Writes::default();
        let mut st = self.state.lock();
        // A task deleted mid-run leaves nothing behind.
        let exists = st.tasks.iter().any(|t| t.id == run.task_id);
        if exists {
            st.runs.insert(run.task_id.clone(), run.clone());
            self.stage_runs(&st, &mut w);
        }
        drop(st);
        let _ = self.commit(w);
        exists
    }

    async fn run_job(&self, job: Job) {
        let now: LocalNow = local_now(self.clock.as_ref());
        let begun = {
            let mut st = self.state.lock();
            let Some(task) = st.tasks.iter().find(|t| t.id == job.task_id).cloned() else {
                drop(st);
                self.changed();
                return;
            };
            let run = if job.resume {
                match st.runs.get(&task.id) {
                    Some(r)
                        if r.finished_at.is_some()
                            && r.steps.iter().any(|s| s.status == StepStatus::NeedsApp) =>
                    {
                        let mut r = r.clone();
                        r.finished_at = None;
                        Some(r)
                    }
                    _ => None,
                }
            } else {
                Some(Run {
                    task_id: task.id.clone(),
                    day: now.day.clone(),
                    started_at: rfc3339(now.utc),
                    finished_at: None,
                    trigger: job.trigger,
                    steps: Vec::new(),
                    error: None,
                })
            };
            let missing = unfilled(&task, &st.secrets).join("、");
            if run.is_some() {
                st.running = Some(task.id.clone());
            }
            run.map(|run| (task, run, missing))
        };
        let Some((task, mut run, missing)) = begun else {
            self.changed();
            return;
        };
        debug!("checkin: running task {} ({:?})", task.id, job.trigger);
        let mut exists = self.put_run(&run);

        let mut counts = true;
        if !missing.is_empty() {
            // Filled when queued, emptied since.
            run.error = Some(format!("还有变量没填写：{missing}。没有执行。"));
            counts = false;
        } else if job.resume {
            self.resume_steps(&task, &mut run).await;
        } else {
            let mut jar = Jar::default();
            let mut stopped = false;
            for step in &task.steps {
                // Deleted while it ran: nothing more is sent for it.
                if !exists {
                    break;
                }
                let result = if stopped {
                    StepResult::new(step.id(), StepStatus::Skipped, "")
                } else {
                    match step {
                        Step::Api(s) => self.run_api(&task, s, &mut jar).await,
                        Step::Click(s) => self.run_click(&task, s).await,
                    }
                };
                // Nothing after a lost login can work.
                stopped |= result.status == StepStatus::LoggedOut;
                run.steps.push(result);
                exists = self.put_run(&run);
            }
        }

        run.finished_at = Some(rfc3339(self.clock.now_utc()));
        let mut w = Writes::default();
        let mut st = self.state.lock();
        st.running = None;
        if st.tasks.iter().any(|t| t.id == run.task_id) {
            if counts && run.trigger != Trigger::Trial {
                mark_done(&mut st.done, &run.task_id, &run.day);
            }
            st.runs.insert(run.task_id.clone(), run);
            self.stage_runs(&st, &mut w);
        }
        drop(st);
        let _ = self.commit(w);
    }

    async fn resume_steps(&self, task: &Task, run: &mut Run) {
        let mut stopped = run.steps.iter().any(|s| s.status == StepStatus::LoggedOut);
        for step in &task.steps {
            let Step::Click(click) = step else { continue };
            let Some(at) = run
                .steps
                .iter()
                .position(|r| r.step_id == click.id && r.status == StepStatus::NeedsApp)
            else {
                continue;
            };
            if stopped {
                run.steps[at] = StepResult::new(&click.id, StepStatus::Skipped, "");
            } else {
                let result = self.run_click(task, click).await;
                stopped |= result.status == StepStatus::LoggedOut;
                run.steps[at] = result;
            }
            if !self.put_run(run) {
                return;
            }
        }
    }

    async fn run_api(&self, task: &Task, step: &ApiStep, jar: &mut Jar) -> StepResult {
        // Read per step: the app pushes fresh values after it performs a
        // click step.
        let TaskSecrets { user_agent, values } = self
            .state
            .lock()
            .secrets
            .get(&task.id)
            .cloned()
            .unwrap_or_default();
        let variables = Variables {
            home: &task.home,
            defs: &task.variables,
            values: &values,
        };
        let out = Outbound {
            connector: self.connector.as_ref(),
            access: task.access,
            policy: task.policy(),
            limits: &self.config.limits,
            markers: &self.markers,
            allow_private: self.allow_private,
            extra_roots: &self.config.extra_roots,
        };
        replay::replay(
            step,
            variables,
            user_agent.as_deref().unwrap_or(""),
            jar,
            &out,
        )
        .await
    }

    async fn run_click(&self, task: &Task, step: &ClickStep) -> StepResult {
        let request = ClickRequest {
            id: format!("c{}", self.click_seq.fetch_add(1, Ordering::Relaxed) + 1),
            task_id: task.id.clone(),
            access: task.access,
            policy: task.policy().map(str::to_string),
            timeout_ms: self.config.click_timeout_ms,
            steps: vec![Step::Click(step.clone())],
        };
        let report_wait =
            Duration::from_millis(self.config.click_timeout_ms) + self.config.click_report_grace;
        match self
            .clicks
            .request(request, self.config.attach_wait, report_wait)
            .await
        {
            ClickOutcome::NoApp => StepResult::new(&step.id, StepStatus::NeedsApp, ""),
            ClickOutcome::TimedOut => {
                StepResult::new(&step.id, StepStatus::Failed, "应用没有回报这一步的结果。")
            }
            ClickOutcome::Reported(report) => self.judge_click(step, &report),
        }
    }

    /// The app reports facts; the verdict is made here.
    fn judge_click(&self, step: &ClickStep, report: &ClickReport) -> StepResult {
        if let Some(error) = report.error.as_deref().filter(|e| !e.trim().is_empty()) {
            let sentence: String = error
                .chars()
                .map(|c| if c.is_control() { ' ' } else { c })
                .take(200)
                .collect();
            return StepResult::new(&step.id, StepStatus::Failed, sentence.trim());
        }
        if report.found {
            return StepResult::new(&step.id, StepStatus::Ok, "");
        }
        let logged_out = report.password_field
            || expiry::click_ended_on_login(report.final_url.as_deref(), &step.page, &self.markers);
        StepResult::new(
            &step.id,
            if logged_out {
                StepStatus::LoggedOut
            } else {
                StepStatus::NotFound
            },
            "",
        )
    }

    /// The app's report for one step of a click request.
    pub fn report_click(&self, request_id: &str, body: &Value) -> Result<()> {
        let mut report: ClickReport = serde_json::from_value(body.clone())
            .map_err(|_| CheckinError::invalid(BODY_INVALID))?;
        report.request_id = request_id.to_string();
        if self.clicks.report(report) {
            Ok(())
        } else {
            Err(CheckinError::not_found(
                "这个点击请求已经结束或不存在。".to_string(),
            ))
        }
    }
}
