//! Reading tasks, steps and variables from JSON somebody else wrote (the
//! app, or a shared rule), and the rule format (version 1).
//!
//! Everything that comes in goes through the readers here: only the fields
//! of the format are taken, by name and type; sizes are bounded; nothing is
//! ever executed.

use crate::error::{CheckinError, Result};
use crate::model::{
    Access, ApiStep, AutoFrom, ClickStep, Locator, RuleCheck, RuleExport, RuleWarning, Source,
    Step, Task, VariableDef,
};
use crate::site;
use crate::vars;
use base64::Engine as _;
use serde::Serialize;
use serde_json::{Map, Value};
use std::collections::BTreeMap;

pub const RULE_MARKER: &str = "paopao_checkin_rule";
pub const RULE_VERSION: u64 = 1;
pub const LINK_PREFIX: &str = "paopao://checkin/rule?d=";

pub const RULE_TEXT_MAX: usize = 256 * 1024;
pub const STEPS_MAX: usize = 50;
pub const VARIABLES_MAX: usize = 50;
pub const BODY_MAX: usize = 64 * 1024;
pub const NAME_CHARS_MAX: usize = 100;
pub const TEXT_CHARS_MAX: usize = 500;
pub const HEADERS_MAX: usize = 50;
pub const HEADER_NAME_MAX: usize = 100;
pub const HEADER_VALUE_MAX: usize = 8 * 1024;
pub const LOCATORS_MAX: usize = 20;
pub const LOCATOR_VALUE_MAX: usize = 4096;
pub const KEY_MAX: usize = 256;
pub const VALUE_MAX: usize = 16 * 1024;
pub const USER_AGENT_MAX: usize = 512;
pub const MINUTE_MAX: u64 = 24 * 60 - 1;
pub const DEFAULT_MINUTE: u16 = 8 * 60 + 30;

pub const METHODS: [&str; 7] = ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"];

/// Headers that carry a login. In a rule their value must be a reference.
pub const CREDENTIAL_HEADERS: [&str; 11] = [
    "authorization",
    "cookie",
    "cookie2",
    "proxy-authorization",
    "x-csrf-token",
    "x-xsrf-token",
    "x-auth-token",
    "x-access-token",
    "x-token",
    "token",
    "access-token",
];

/// Headers the core writes itself at send time; never stored in a step.
pub fn is_core_owned_header(name: &str) -> bool {
    matches!(
        name,
        "host"
            | "content-length"
            | "connection"
            | "transfer-encoding"
            | "accept-encoding"
            | "user-agent"
            | "origin"
            | "referer"
            | "te"
            | "trailer"
            | "upgrade"
            | "keep-alive"
            | "expect"
    ) || name.starts_with("sec-")
        || name.starts_with("proxy-")
}

pub fn is_header_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= HEADER_NAME_MAX
        && name.bytes().all(|b| {
            matches!(b,
            b'!' | b'#' | b'$' | b'%' | b'&' | b'\'' | b'*' | b'+' | b'-'
            | b'.' | b'^' | b'_' | b'`' | b'|' | b'~'
            | b'0'..=b'9' | b'a'..=b'z' | b'A'..=b'Z')
        })
}

/// `Bearer {name}` or `{name}`: nothing of the login itself.
fn is_reference_only(value: &str) -> bool {
    let v = value.trim();
    let v = match v.split_once(' ') {
        Some((scheme, rest)) if scheme.bytes().all(|b| b.is_ascii_alphabetic()) => rest.trim(),
        _ => v,
    };
    v.strip_prefix('{')
        .and_then(|v| v.strip_suffix('}'))
        .is_some_and(vars::is_valid_name)
}

fn wrong(field: &str) -> CheckinError {
    CheckinError::invalid(format!("「{field}」的内容格式不对。"))
}

fn too_big(what: &str) -> CheckinError {
    CheckinError::too_large(format!("{what}超出了允许的大小。"))
}

fn truncate_chars(s: &str, max: usize) -> String {
    s.chars().filter(|c| !c.is_control()).take(max).collect()
}

/// Reads JSON objects field by field, remembering every field it was not
/// asked for.
#[derive(Default)]
pub struct Reader {
    unknown: Vec<String>,
}

/// Fields of the app's own objects that are not part of a rule: dropped
/// without a word.
const PERSONAL_FIELDS: [&str; 8] = [
    "id",
    "value",
    "has_value",
    "updated_at",
    "enabled",
    "subscription_id",
    "policy",
    "masked",
];

impl Reader {
    fn note_unknown(&mut self, obj: &Map<String, Value>, known: &[&str]) {
        for key in obj.keys() {
            let k = key.as_str();
            if !known.contains(&k) && !PERSONAL_FIELDS.contains(&k) {
                let shown = truncate_chars(k, 40);
                if !self.unknown.contains(&shown) && self.unknown.len() < 20 {
                    self.unknown.push(shown);
                }
            }
        }
    }

    /// The fields met that the format does not define.
    pub fn unknown_fields(&self) -> &[String] {
        &self.unknown
    }

    fn string(obj: &Map<String, Value>, key: &str) -> Result<Option<String>> {
        match obj.get(key) {
            None | Some(Value::Null) => Ok(None),
            Some(Value::String(s)) => Ok(Some(s.clone())),
            Some(_) => Err(wrong(key)),
        }
    }

    fn boolean(obj: &Map<String, Value>, key: &str) -> Result<Option<bool>> {
        match obj.get(key) {
            None | Some(Value::Null) => Ok(None),
            Some(Value::Bool(b)) => Ok(Some(*b)),
            Some(_) => Err(wrong(key)),
        }
    }

    fn integer(obj: &Map<String, Value>, key: &str) -> Result<Option<u64>> {
        match obj.get(key) {
            None | Some(Value::Null) => Ok(None),
            Some(v) => v.as_u64().map(Some).ok_or_else(|| wrong(key)),
        }
    }

    fn http_url(obj: &Map<String, Value>, key: &str) -> Result<String> {
        let text = Self::string(obj, key)?.unwrap_or_default();
        let text = text.trim();
        if site::parse_http_url(text).is_none() {
            return Err(CheckinError::invalid(format!(
                "「{key}」不是有效的 http / https 网址。"
            )));
        }
        Ok(text.to_string())
    }

    pub fn access(obj: &Map<String, Value>) -> Result<Option<Access>> {
        match Self::string(obj, "access")?.as_deref() {
            None => Ok(None),
            Some("direct") => Ok(Some(Access::Direct)),
            Some("proxy") => Ok(Some(Access::Proxy)),
            Some(_) => Err(wrong("access")),
        }
    }

    pub fn minute_of_day(obj: &Map<String, Value>) -> Result<Option<u16>> {
        match Self::integer(obj, "minute_of_day")? {
            None => Ok(None),
            Some(m) if m <= MINUTE_MAX => Ok(Some(m as u16)),
            Some(_) => Err(wrong("minute_of_day")),
        }
    }

    pub fn name(obj: &Map<String, Value>) -> Result<Option<String>> {
        Ok(Self::string(obj, "name")?.map(|s| truncate_chars(s.trim(), NAME_CHARS_MAX)))
    }

    pub fn home(obj: &Map<String, Value>) -> Result<String> {
        Self::http_url(obj, "home")
    }

    pub fn enabled(obj: &Map<String, Value>) -> Result<Option<bool>> {
        Self::boolean(obj, "enabled")
    }

    /// `Some(None)`: present and null.
    pub fn subscription_id(obj: &Map<String, Value>) -> Result<Option<Option<String>>> {
        match obj.get("subscription_id") {
            None => Ok(None),
            Some(Value::Null) => Ok(Some(None)),
            Some(Value::String(s)) if s.len() <= KEY_MAX && !s.chars().any(char::is_control) => {
                Ok(Some(Some(s.clone())))
            }
            Some(_) => Err(wrong("subscription_id")),
        }
    }

    /// `Some(None)`: present and null or empty, which is "the rules
    /// decide". The name is not checked against the core's proxies here:
    /// they change with every config, and a run says so when it is gone.
    pub fn policy(obj: &Map<String, Value>) -> Result<Option<Option<String>>> {
        match obj.get("policy") {
            None => Ok(None),
            Some(Value::Null) => Ok(Some(None)),
            Some(Value::String(s)) if s.is_empty() => Ok(Some(None)),
            Some(Value::String(s)) if s.len() <= KEY_MAX && !s.chars().any(char::is_control) => {
                Ok(Some(Some(s.clone())))
            }
            Some(_) => Err(wrong("policy")),
        }
    }

    /// The `steps` list of `obj`. Steps of a kind this core does not know
    /// are left out, not refused.
    pub fn steps(&mut self, obj: &Map<String, Value>) -> Result<Vec<Step>> {
        let list = match obj.get("steps") {
            None | Some(Value::Null) => return Ok(Vec::new()),
            Some(Value::Array(list)) => list,
            Some(_) => return Err(wrong("steps")),
        };
        if list.len() > STEPS_MAX {
            return Err(too_big(&format!("步骤数量（最多 {STEPS_MAX} 个）")));
        }
        let mut out = Vec::with_capacity(list.len());
        for item in list {
            if let Some(step) = self.step(item)? {
                out.push(step);
            }
        }
        Ok(out)
    }

    fn step(&mut self, value: &Value) -> Result<Option<Step>> {
        let Value::Object(obj) = value else {
            return Err(wrong("steps"));
        };
        let kind = Self::string(obj, "kind")?.ok_or_else(|| wrong("kind"))?;
        let id = match Self::string(obj, "id")? {
            Some(id) if id.len() <= 64 && id.bytes().all(|b| b.is_ascii_graphic()) => id,
            Some(_) => return Err(wrong("id")),
            None => String::new(),
        };
        let name = Self::name(obj)?.unwrap_or_default();
        match kind.as_str() {
            "api" => {
                self.note_unknown(
                    obj,
                    &[
                        "kind",
                        "name",
                        "method",
                        "url",
                        "headers",
                        "body",
                        "body_base64",
                        "page",
                        "recorded_status",
                        "recorded_content_type",
                    ],
                );
                let method = Self::string(obj, "method")?
                    .unwrap_or_else(|| "GET".to_string())
                    .to_ascii_uppercase();
                if !METHODS.contains(&method.as_str()) {
                    return Err(wrong("method"));
                }
                let url = Self::http_url(obj, "url")?;
                let page = Self::http_url(obj, "page")?;
                let headers = Self::headers(obj)?;
                let body_base64 = Self::boolean(obj, "body_base64")?.unwrap_or(false);
                let body = Self::string(obj, "body")?;
                if let Some(body) = &body {
                    if body.len() > BODY_MAX {
                        return Err(too_big(&format!("请求内容（最多 {} KB）", BODY_MAX / 1024)));
                    }
                    if body_base64
                        && base64::engine::general_purpose::STANDARD
                            .decode(body.trim())
                            .is_err()
                    {
                        return Err(wrong("body"));
                    }
                }
                let recorded_status = match Self::integer(obj, "recorded_status")? {
                    None => None,
                    Some(s) if (100..=599).contains(&s) => Some(s as u16),
                    Some(_) => return Err(wrong("recorded_status")),
                };
                let recorded_content_type = Self::string(obj, "recorded_content_type")?
                    .map(|s| truncate_chars(&s, 200))
                    .filter(|s| !s.is_empty());
                Ok(Some(Step::Api(ApiStep {
                    id,
                    name,
                    method,
                    url,
                    headers,
                    body,
                    body_base64,
                    page,
                    recorded_status,
                    recorded_content_type,
                })))
            }
            "click" => {
                self.note_unknown(obj, &["kind", "name", "page", "locators", "text", "tag"]);
                let page = Self::http_url(obj, "page")?;
                let locators = match obj.get("locators") {
                    None | Some(Value::Null) => Vec::new(),
                    Some(Value::Array(list)) => {
                        if list.len() > LOCATORS_MAX {
                            return Err(too_big("元素定位方式的数量"));
                        }
                        let mut out = Vec::with_capacity(list.len());
                        for item in list {
                            let Value::Object(l) = item else {
                                return Err(wrong("locators"));
                            };
                            self.note_unknown(l, &["kind", "value"]);
                            let kind = Self::string(l, "kind")?.ok_or_else(|| wrong("locators"))?;
                            let value =
                                Self::string(l, "value")?.ok_or_else(|| wrong("locators"))?;
                            if kind.is_empty()
                                || kind.len() > 32
                                || !kind.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
                            {
                                return Err(wrong("locators"));
                            }
                            if value.len() > LOCATOR_VALUE_MAX {
                                return Err(too_big("元素定位内容"));
                            }
                            out.push(Locator { kind, value });
                        }
                        out
                    }
                    Some(_) => return Err(wrong("locators")),
                };
                let text = Self::string(obj, "text")?
                    .map(|s| truncate_chars(&s, TEXT_CHARS_MAX))
                    .unwrap_or_default();
                let tag = Self::string(obj, "tag")?
                    .map(|s| truncate_chars(&s, 32))
                    .unwrap_or_default();
                Ok(Some(Step::Click(ClickStep {
                    id,
                    name,
                    page,
                    locators,
                    text,
                    tag,
                })))
            }
            // A newer app's step: left out so both sides keep working.
            _ => Ok(None),
        }
    }

    fn headers(obj: &Map<String, Value>) -> Result<BTreeMap<String, String>> {
        let map = match obj.get("headers") {
            None | Some(Value::Null) => return Ok(BTreeMap::new()),
            Some(Value::Object(map)) => map,
            Some(_) => return Err(wrong("headers")),
        };
        if map.len() > HEADERS_MAX {
            return Err(too_big("请求头的数量"));
        }
        let mut out = BTreeMap::new();
        for (name, value) in map {
            let Value::String(value) = value else {
                return Err(wrong("headers"));
            };
            if !is_header_name(name) {
                return Err(CheckinError::invalid(
                    "请求头的名称里有不允许的字符。".to_string(),
                ));
            }
            if value.len() > HEADER_VALUE_MAX {
                return Err(too_big("请求头的内容"));
            }
            if !vars::header_safe(value) {
                return Err(CheckinError::invalid(
                    "请求头的内容里有换行等不允许的字符。".to_string(),
                ));
            }
            let name = name.to_ascii_lowercase();
            if is_core_owned_header(&name) {
                continue;
            }
            out.insert(name, value.clone());
        }
        Ok(out)
    }

    /// The `variables` list of `obj`: definitions only.
    pub fn variables(&mut self, obj: &Map<String, Value>) -> Result<Vec<VariableDef>> {
        let list = match obj.get("variables") {
            None | Some(Value::Null) => return Ok(Vec::new()),
            Some(Value::Array(list)) => list,
            Some(_) => return Err(wrong("variables")),
        };
        if list.len() > VARIABLES_MAX {
            return Err(too_big(&format!("变量数量（最多 {VARIABLES_MAX} 个）")));
        }
        let mut out: Vec<VariableDef> = Vec::with_capacity(list.len());
        for item in list {
            let Value::Object(v) = item else {
                return Err(wrong("variables"));
            };
            let (def, _) = self.variable(v)?;
            if out.iter().any(|o| o.name == def.name) {
                return Err(CheckinError::invalid(format!(
                    "变量 {} 出现了两次。",
                    def.name
                )));
            }
            out.push(def);
        }
        Ok(out)
    }

    /// One variable: its definition and, when the object carries one, the
    /// value (`manual` only; the caller decides whether to take it).
    pub fn variable(&mut self, obj: &Map<String, Value>) -> Result<(VariableDef, Option<String>)> {
        self.note_unknown(obj, &["name", "source", "from", "key", "url"]);
        let name = Self::string(obj, "name")?.unwrap_or_default();
        if !vars::is_valid_name(&name) {
            return Err(CheckinError::invalid(
                "变量名要以字母开头，只用字母、数字和下划线，最长 40 个字符。".to_string(),
            ));
        }
        let source = match Self::string(obj, "source")?.as_deref() {
            Some("auto") => Source::Auto,
            Some("manual") => Source::Manual,
            _ => return Err(wrong("source")),
        };
        if source == Source::Manual {
            let value = Self::string(obj, "value")?;
            if value.as_ref().is_some_and(|v| v.len() > VALUE_MAX) {
                return Err(too_big("变量的值"));
            }
            return Ok((
                VariableDef {
                    name,
                    source,
                    from: None,
                    key: None,
                    url: None,
                },
                value,
            ));
        }
        let from = match Self::string(obj, "from")? {
            None => AutoFrom::CookieHeader,
            Some(s) => AutoFrom::parse(&s).ok_or_else(|| wrong("from"))?,
        };
        let key = Self::string(obj, "key")?.filter(|k| !k.is_empty());
        if key
            .as_ref()
            .is_some_and(|k| k.len() > KEY_MAX || k.chars().any(char::is_control))
        {
            return Err(wrong("key"));
        }
        let url = Self::string(obj, "url")?
            .map(|u| u.trim().to_string())
            .filter(|u| !u.is_empty());
        if let Some(u) = &url {
            let ok = if from == AutoFrom::ResponseField {
                u.len() <= site::URL_MAX && !u.chars().any(char::is_control)
            } else {
                site::parse_http_url(u).is_some()
            };
            if !ok {
                return Err(wrong("url"));
            }
        }
        Ok((
            VariableDef {
                name,
                source,
                from: Some(from),
                key,
                url,
            },
            None,
        ))
    }
}

/// Every name the step refers to.
pub fn step_refs(step: &Step) -> Vec<String> {
    let Step::Api(s) = step else {
        return Vec::new();
    };
    let mut out: Vec<String> = Vec::new();
    let texts = std::iter::once(s.url.as_str())
        .chain(s.headers.values().map(String::as_str))
        .chain(if s.body_base64 {
            None
        } else {
            s.body.as_deref()
        });
    for text in texts {
        for name in vars::refs(text) {
            if !out.iter().any(|n| n == name) {
                out.push(name.to_string());
            }
        }
    }
    out
}

/// A rule read and checked; nothing created.
#[derive(Clone, Debug)]
pub struct ParsedRule {
    pub name: String,
    pub home: String,
    pub access: Access,
    pub minute_of_day: u16,
    pub steps: Vec<Step>,
    pub variables: Vec<VariableDef>,
    pub warnings: Vec<RuleWarning>,
}

const RULE_INVALID: &str = "这不是一条签到规则，或者内容不完整。";

fn decode_carrier(text: &str) -> Result<String> {
    if text.len() > RULE_TEXT_MAX * 2 {
        return Err(too_big(&format!(
            "规则（最多 {} KB）",
            RULE_TEXT_MAX / 1024
        )));
    }
    let text = text.trim().trim_start_matches('\u{feff}');
    let raw = if let Some(data) = text.strip_prefix(LINK_PREFIX) {
        let data = data.trim().trim_end_matches('=');
        let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(data)
            .map_err(|_| CheckinError::invalid(RULE_INVALID))?;
        String::from_utf8(bytes).map_err(|_| CheckinError::invalid(RULE_INVALID))?
    } else {
        text.to_string()
    };
    if raw.len() > RULE_TEXT_MAX {
        return Err(too_big(&format!(
            "规则（最多 {} KB）",
            RULE_TEXT_MAX / 1024
        )));
    }
    Ok(raw)
}

/// Reads a rule from its text or its link. Never creates or sends
/// anything.
pub fn read_rule(text: &str) -> Result<ParsedRule> {
    let raw = decode_carrier(text)?;
    let value: Value =
        serde_json::from_str(&raw).map_err(|_| CheckinError::invalid(RULE_INVALID))?;
    let Value::Object(obj) = value else {
        return Err(CheckinError::invalid(RULE_INVALID));
    };
    match obj.get(RULE_MARKER) {
        Some(v) if v.as_u64() == Some(RULE_VERSION) => {}
        Some(v) if v.as_u64().is_some() => {
            return Err(CheckinError::invalid(
                "这条规则是更新的版本写的，这里还读不了。请先更新应用。".to_string(),
            ));
        }
        _ => return Err(CheckinError::invalid(RULE_INVALID)),
    }

    let mut reader = Reader::default();
    reader.note_unknown(
        &obj,
        &[
            RULE_MARKER,
            "name",
            "home",
            "access",
            "minute_of_day",
            "variables",
            "steps",
        ],
    );
    let home = Reader::home(&obj)?;
    let home_url = site::parse_http_url(&home).ok_or_else(|| wrong("home"))?;
    let home_host = site::host_of(&home_url);
    let name = Reader::name(&obj)?
        .filter(|n| !n.is_empty())
        .unwrap_or_else(|| home_host.clone());
    let access = Reader::access(&obj)?.unwrap_or_default();
    let minute_of_day = Reader::minute_of_day(&obj)?.unwrap_or(DEFAULT_MINUTE);
    let mut variables = reader.variables(&obj)?;
    let mut steps = reader.steps(&obj)?;
    for step in &mut steps {
        step.set_id(String::new());
    }

    // A reference nobody defined becomes a variable to fill in: sending a
    // literal `{name}` would never be what the author meant.
    for name in steps.iter().flat_map(step_refs) {
        if !variables.iter().any(|v| v.name == name) {
            if variables.len() >= VARIABLES_MAX {
                return Err(too_big(&format!("变量数量（最多 {VARIABLES_MAX} 个）")));
            }
            variables.push(VariableDef {
                name,
                source: Source::Manual,
                from: None,
                key: None,
                url: None,
            });
        }
    }

    let mut warnings = Vec::new();
    if !reader.unknown_fields().is_empty() {
        warnings.push(RuleWarning {
            code: "unknown_field",
            message: "规则里有这里不认识的内容，已忽略。".to_string(),
            detail: reader.unknown_fields().join(", "),
        });
    }
    let mut others: Vec<String> = Vec::new();
    let mut literal: Vec<String> = Vec::new();
    let mut private: Vec<String> = Vec::new();
    if site::is_internal_host(&home_host) {
        private.push(home_host.clone());
    }
    for step in &steps {
        // Where the step goes: a request's address, the page a click
        // step opens.
        let target = match step {
            Step::Api(s) => &s.url,
            Step::Click(s) => &s.page,
        };
        if let Some(url) = site::parse_http_url(target) {
            let host = site::host_of(&url);
            if site::is_internal_host(&host) && !private.contains(&host) {
                private.push(host.clone());
            }
            if !site::same_site(&host, &home_host) && !others.contains(&host) {
                others.push(host);
            }
        }
        let Step::Api(s) = step else { continue };
        for (name, value) in &s.headers {
            if CREDENTIAL_HEADERS.contains(&name.as_str())
                && !is_reference_only(value)
                && !literal.contains(name)
            {
                literal.push(name.clone());
            }
        }
    }
    for host in others {
        warnings.push(RuleWarning {
            code: "cross_site",
            message: format!(
                "有步骤会访问 {host}，与任务网址 {home_host} 不是同一个网站。请确认信任这条规则后再导入。"
            ),
            detail: host,
        });
    }
    for host in private {
        warnings.push(RuleWarning {
            code: "private_address",
            message: format!(
                "规则指向本机或内网的地址 {host}。正常的签到规则不会这样做；签到助手不会向这样的地址发送请求。"
            ),
            detail: host,
        });
    }
    let mut foreign: Vec<String> = Vec::new();
    for v in &variables {
        if v.source != Source::Auto || v.from == Some(AutoFrom::ResponseField) {
            continue;
        }
        let Some(url) = v.url.as_deref().and_then(site::parse_http_url) else {
            continue;
        };
        let host = site::host_of(&url);
        if !site::same_site(&host, &home_host) && !foreign.contains(&host) {
            foreign.push(host);
        }
    }
    for host in foreign {
        warnings.push(RuleWarning {
            code: "cross_site_variable",
            message: format!(
                "有变量会读取你在 {host} 的登录信息，与任务网址 {home_host} 不是同一个网站。请确认信任这条规则后再导入。"
            ),
            detail: host,
        });
    }
    if !literal.is_empty() {
        warnings.push(RuleWarning {
            code: "embedded_credential",
            message: "规则里直接写着别人的登录信息，而不是变量。这样的规则通常不能用，也说明分享的人泄露了自己的登录信息。"
                .to_string(),
            detail: literal.join(", "),
        });
    }
    let manual: Vec<&str> = variables
        .iter()
        .filter(|v| v.source == Source::Manual)
        .map(|v| v.name.as_str())
        .collect();
    if !manual.is_empty() {
        warnings.push(RuleWarning {
            code: "manual_variables",
            message: format!("导入后需要先填写变量：{}。", manual.join("、")),
            detail: manual.join(", "),
        });
    }

    Ok(ParsedRule {
        name,
        home,
        access,
        minute_of_day,
        steps,
        variables,
        warnings,
    })
}

/// [`read_rule`] as the answer of `checkRule`.
pub fn check_rule(text: &str) -> RuleCheck {
    match read_rule(text) {
        Ok(rule) => RuleCheck {
            ok: true,
            error: None,
            name: rule.name,
            home: rule.home,
            steps: rule.steps,
            variables: rule.variables,
            warnings: rule.warnings,
        },
        Err(e) => RuleCheck {
            ok: false,
            error: Some(e.message),
            name: String::new(),
            home: String::new(),
            steps: Vec::new(),
            variables: Vec::new(),
            warnings: Vec::new(),
        },
    }
}

#[derive(Serialize)]
struct RuleOut<'a> {
    paopao_checkin_rule: u64,
    name: &'a str,
    home: &'a str,
    access: Access,
    minute_of_day: u16,
    variables: &'a [VariableDef],
    steps: Vec<StepOut<'a>>,
}

#[derive(Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum StepOut<'a> {
    Api {
        name: &'a str,
        method: &'a str,
        url: &'a str,
        headers: &'a BTreeMap<String, String>,
        body: Option<&'a str>,
        body_base64: bool,
        page: &'a str,
        recorded_status: Option<u16>,
        recorded_content_type: Option<&'a str>,
    },
    Click {
        name: &'a str,
        page: &'a str,
        locators: &'a [Locator],
        text: &'a str,
        tag: &'a str,
    },
}

fn file_name(name: &str) -> String {
    let cleaned: String = name
        .chars()
        .map(|c| {
            if c.is_control() || matches!(c, '/' | '\\' | ':' | '*' | '?' | '"' | '<' | '>' | '|') {
                '_'
            } else {
                c
            }
        })
        .take(60)
        .collect();
    let cleaned = cleaned.trim().trim_matches('.');
    let base = if cleaned.is_empty() {
        "checkin"
    } else {
        cleaned
    };
    format!("{base}.checkin.json")
}

/// The task as a rule: no ids, no switch, no values. Refused while a
/// credential header holds a login written out instead of a reference.
pub fn export_rule(task: &Task) -> Result<RuleExport> {
    for step in &task.steps {
        let Step::Api(s) = step else { continue };
        for (name, value) in &s.headers {
            if CREDENTIAL_HEADERS.contains(&name.as_str()) && !is_reference_only(value) {
                return Err(CheckinError::conflict(format!(
                    "步骤「{}」的请求头 {name} 里直接写着登录信息，分享出去会泄露。请先把它改成变量再分享。",
                    s.name
                )));
            }
        }
    }
    let rule = RuleOut {
        paopao_checkin_rule: RULE_VERSION,
        name: &task.name,
        home: &task.home,
        access: task.access,
        minute_of_day: task.minute_of_day,
        variables: &task.variables,
        steps: task
            .steps
            .iter()
            .map(|s| match s {
                Step::Api(s) => StepOut::Api {
                    name: &s.name,
                    method: &s.method,
                    url: &s.url,
                    headers: &s.headers,
                    body: s.body.as_deref(),
                    body_base64: s.body_base64,
                    page: &s.page,
                    recorded_status: s.recorded_status,
                    recorded_content_type: s.recorded_content_type.as_deref(),
                },
                Step::Click(s) => StepOut::Click {
                    name: &s.name,
                    page: &s.page,
                    locators: &s.locators,
                    text: &s.text,
                    tag: &s.tag,
                },
            })
            .collect(),
    };
    let fail = |_| CheckinError::invalid("规则生成失败。".to_string());
    let text = serde_json::to_string_pretty(&rule).map_err(fail)?;
    let compact = serde_json::to_string(&rule).map_err(fail)?;
    Ok(RuleExport {
        text,
        link: format!(
            "{LINK_PREFIX}{}",
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(compact)
        ),
        file_name: file_name(&task.name),
    })
}
