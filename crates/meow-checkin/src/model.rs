//! What the engine stores and what goes over the API.
//!
//! The stored types hold no variable value: values live in
//! [`crate::store::Secrets`], in a file of their own, and are joined in
//! only when a task is shown ([`TaskView`]) or run.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// How a task's requests leave: straight out, or through the core's rules
/// and lines like any other connection.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Access {
    #[default]
    Direct,
    Proxy,
}

impl Access {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Direct => "direct",
            Self::Proxy => "proxy",
        }
    }
}

/// One site's daily check-in.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Task {
    pub id: String,
    pub name: String,
    pub home: String,
    #[serde(default)]
    pub access: Access,
    /// The proxy or group every request of the task goes out through,
    /// whatever the rules say. `None`: the rules decide. Only read while
    /// `access` is [`Access::Proxy`] ([`Task::policy`]).
    #[serde(default, rename = "policy")]
    pub proxy_policy: Option<String>,
    /// Local time of the daily run, minutes after midnight.
    pub minute_of_day: u16,
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub subscription_id: Option<String>,
    #[serde(default)]
    pub steps: Vec<Step>,
    #[serde(default)]
    pub variables: Vec<VariableDef>,
}

impl Task {
    /// The proxy or group the task's requests are sent through; `None`
    /// for a direct task and for one that follows the rules.
    pub fn policy(&self) -> Option<&str> {
        match self.access {
            Access::Direct => None,
            Access::Proxy => self.proxy_policy.as_deref(),
        }
    }

    pub fn variable(&self, name: &str) -> Option<&VariableDef> {
        self.variables.iter().find(|v| v.name == name)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Step {
    Api(ApiStep),
    Click(ClickStep),
}

impl Step {
    pub fn id(&self) -> &str {
        match self {
            Self::Api(s) => &s.id,
            Self::Click(s) => &s.id,
        }
    }

    pub fn set_id(&mut self, id: String) {
        match self {
            Self::Api(s) => s.id = id,
            Self::Click(s) => s.id = id,
        }
    }
}

/// Re-send one request. `url`, header values and a text `body` may refer
/// to the task's variables as `{name}`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApiStep {
    #[serde(default)]
    pub id: String,
    #[serde(default)]
    pub name: String,
    pub method: String,
    pub url: String,
    /// Lower-case names.
    #[serde(default)]
    pub headers: BTreeMap<String, String>,
    #[serde(default)]
    pub body: Option<String>,
    #[serde(default)]
    pub body_base64: bool,
    /// The page the request was made from: `Origin` / `Referer` at replay.
    pub page: String,
    #[serde(default)]
    pub recorded_status: Option<u16>,
    #[serde(default)]
    pub recorded_content_type: Option<String>,
}

/// Click an element of a page. The core cannot: it asks the app.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClickStep {
    #[serde(default)]
    pub id: String,
    #[serde(default)]
    pub name: String,
    pub page: String,
    /// Opaque to the core: stored and handed back in order.
    #[serde(default)]
    pub locators: Vec<Locator>,
    #[serde(default)]
    pub text: String,
    #[serde(default)]
    pub tag: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Locator {
    pub kind: String,
    pub value: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Source {
    Auto,
    Manual,
}

/// What the app reads an `auto` variable from.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AutoFrom {
    CookieHeader,
    Cookie,
    LocalStorage,
    ResponseField,
    RequestHeader,
}

impl AutoFrom {
    pub fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "cookie_header" => Self::CookieHeader,
            "cookie" => Self::Cookie,
            "local_storage" => Self::LocalStorage,
            "response_field" => Self::ResponseField,
            "request_header" => Self::RequestHeader,
            _ => return None,
        })
    }

    /// Read from the cookie jar.
    pub fn is_cookie(self) -> bool {
        matches!(self, Self::CookieHeader | Self::Cookie)
    }

    /// The value belongs to one site (the variable's `url`, else the
    /// task's `home`) and is only ever sent there: cookies, and what the
    /// page put in a header of its requests to that site.
    pub fn is_site_bound(self) -> bool {
        matches!(
            self,
            Self::CookieHeader | Self::Cookie | Self::RequestHeader
        )
    }
}

/// A variable's name and where its value comes from. Never its value.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct VariableDef {
    pub name: String,
    pub source: Source,
    /// `auto` only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub from: Option<AutoFrom>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
}

/// A variable as the API shows it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct VariableView {
    pub name: String,
    pub source: Source,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub from: Option<AutoFrom>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key: Option<Option<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url: Option<Option<String>>,
    /// `manual` only; masked unless the caller asked for manual values.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value: Option<String>,
    /// `manual` only: `value` is [`MASK`], not what the user typed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub masked: Option<bool>,
    pub has_value: bool,
    pub updated_at: Option<String>,
}

/// Stands in for a manual variable's value where it is not revealed.
pub const MASK: &str = "••••••";

/// A task as the API shows it: [`Task`] with [`VariableView`]s.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct TaskView {
    pub id: String,
    pub name: String,
    pub home: String,
    pub access: Access,
    /// As stored: kept while `access` is `direct`, where it is not used.
    pub policy: Option<String>,
    pub minute_of_day: u16,
    pub enabled: bool,
    pub subscription_id: Option<String>,
    pub steps: Vec<Step>,
    pub variables: Vec<VariableView>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Trigger {
    Scheduled,
    CatchUp,
    Manual,
    Trial,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StepStatus {
    Ok,
    Failed,
    NotFound,
    LoggedOut,
    /// A click step while no app was connected. Not a failure.
    NeedsApp,
    Skipped,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StepResult {
    pub step_id: String,
    pub status: StepStatus,
    #[serde(default)]
    pub http_status: Option<u16>,
    #[serde(default)]
    pub summary: String,
}

impl StepResult {
    pub fn new(step_id: &str, status: StepStatus, summary: impl Into<String>) -> Self {
        Self {
            step_id: step_id.to_string(),
            status,
            http_status: None,
            summary: summary.into(),
        }
    }
}

/// One run of one task.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Run {
    pub task_id: String,
    /// Local date `yyyy-MM-dd` the run started on.
    pub day: String,
    pub started_at: String,
    /// `None`: running, or interrupted.
    #[serde(default)]
    pub finished_at: Option<String>,
    pub trigger: Trigger,
    #[serde(default)]
    pub steps: Vec<StepResult>,
    /// The whole task could not run.
    #[serde(default)]
    pub error: Option<String>,
}

/// Everything the page shows.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Snapshot {
    pub tasks: Vec<TaskView>,
    pub runs: Vec<Run>,
    pub running_task_id: Option<String>,
    pub queued_task_ids: Vec<String>,
}

/// Core → app: perform these click steps in a hidden webview.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ClickRequest {
    pub id: String,
    pub task_id: String,
    pub access: Access,
    /// The proxy or group the task's requests use ([`Task::policy`]).
    pub policy: Option<String>,
    pub timeout_ms: u64,
    pub steps: Vec<Step>,
}

/// App → core: what happened for one step of a [`ClickRequest`]. Facts
/// only; the verdict is the core's.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClickReport {
    #[serde(default)]
    pub request_id: String,
    pub step_id: String,
    #[serde(default)]
    pub found: bool,
    #[serde(default)]
    pub final_url: Option<String>,
    #[serde(default)]
    pub password_field: bool,
    #[serde(default)]
    pub error: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct RuleExport {
    pub text: String,
    pub link: String,
    pub file_name: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct RuleWarning {
    pub code: &'static str,
    pub message: String,
    pub detail: String,
}

/// What a pasted rule would add, and what the user must be told first.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct RuleCheck {
    pub ok: bool,
    pub error: Option<String>,
    pub name: String,
    pub home: String,
    pub steps: Vec<Step>,
    pub variables: Vec<VariableDef>,
    pub warnings: Vec<RuleWarning>,
}
