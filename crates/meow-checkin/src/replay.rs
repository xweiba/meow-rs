//! Re-sending an `api` step and judging the answer.
//!
//! The request is rebuilt each time: the step's own headers with their
//! `{name}` references filled in, then `User-Agent` (the webview's, pushed
//! with the variables), `Referer` and `Origin` (from the step's `page`).
//! `Host`, `Content-Length`, `Connection` and `Accept-Encoding` are the
//! client's.
//!
//! Redirects (at most [`Limits::max_redirects`]):
//!
//! - same origin: followed with everything;
//! - another host of the same site: followed without any login (no
//!   `Cookie`, no credential header, no header a variable filled in), and
//!   never from a public host to this machine or a private network;
//! - another site, or `https` → `http`: not followed. The redirect is the
//!   answer.
//!
//! A cookie variable, or one read from a request header, is read by the
//! app for one site; it is only ever sent to that site.
//!
//! Nothing is sent to this machine or a private network unless the engine
//! was told to allow it: not the step's own address, not a redirect.

use crate::expiry::{self, Markers, Observation};
use crate::http::{self, Connector, Dial, Limits, Request, Response, PRIVATE_SENTENCE};
use crate::model::{Access, ApiStep, AutoFrom, Source, StepResult, StepStatus, VariableDef};
use crate::rule::{is_core_owned_header, is_header_name, CREDENTIAL_HEADERS, METHODS};
use crate::site;
use crate::store::StoredValue;
use crate::vars::{self, Escape, Lookup};
use base64::Engine as _;
use std::collections::{BTreeMap, HashMap};
use url::Url;

pub const DEFAULT_USER_AGENT: &str =
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) \
     Chrome/124.0.0.0 Safari/537.36";

/// Cookies the site set during this run, by host. Kept for the run only:
/// the next push from the app is the truth again.
#[derive(Default)]
pub struct Jar(HashMap<String, Vec<(String, String)>>);

impl Jar {
    fn absorb(&mut self, host: &str, resp: &Response) {
        for line in resp.headers_named("set-cookie") {
            let mut parts = line.split(';');
            let Some((name, value)) = parts.next().and_then(|p| p.split_once('=')) else {
                continue;
            };
            let (name, value) = (name.trim(), value.trim());
            if name.is_empty() || !vars::header_safe(name) || !vars::header_safe(value) {
                continue;
            }
            let expired = value.is_empty()
                || parts.any(|a| {
                    let a = a.trim().to_ascii_lowercase();
                    a == "max-age=0" || a.starts_with("max-age=-")
                });
            let list = self.0.entry(host.to_string()).or_default();
            list.retain(|(n, _)| n != name);
            if !expired {
                list.push((name.to_string(), value.to_string()));
            }
        }
    }

    /// `header` with this run's cookies for `host` laid over it.
    fn overlay(&self, host: &str, header: &str) -> String {
        let Some(set) = self.0.get(host).filter(|s| !s.is_empty()) else {
            return header.to_string();
        };
        let mut pairs: Vec<(String, String)> = header
            .split(';')
            .filter_map(|p| {
                let p = p.trim();
                p.split_once('=')
                    .map(|(n, v)| (n.trim().to_string(), v.trim().to_string()))
            })
            .collect();
        for (name, value) in set {
            match pairs.iter_mut().find(|(n, _)| n == name) {
                Some(pair) => pair.1.clone_from(value),
                None => pairs.push((name.clone(), value.clone())),
            }
        }
        pairs
            .iter()
            .map(|(n, v)| format!("{n}={v}"))
            .collect::<Vec<_>>()
            .join("; ")
    }
}

/// A task's variables as a step sees them.
#[derive(Clone, Copy)]
pub struct Variables<'a> {
    pub home: &'a str,
    pub defs: &'a [VariableDef],
    pub values: &'a BTreeMap<String, StoredValue>,
}

impl<'a> Variables<'a> {
    fn lookup(&self, name: &str, request_host: &str) -> Lookup<'a> {
        let Some(def) = self.defs.iter().find(|d| d.name == name) else {
            return Lookup::Undefined;
        };
        let Some(value) = self
            .values
            .get(name)
            .map(|v| v.value.as_str())
            .filter(|v| !v.is_empty())
        else {
            return Lookup::Unfilled;
        };
        if def.source == Source::Auto && def.from.is_some_and(AutoFrom::is_site_bound) {
            let read_for = def.url.as_deref().unwrap_or(self.home);
            let same = site::parse_http_url(read_for)
                .is_some_and(|u| site::same_site(&site::host_of(&u), request_host));
            if !same {
                return Lookup::Refused;
            }
        }
        Lookup::Value(value)
    }

    /// What to hide from a summary: every value of 4 characters or more,
    /// and the parts of one that are a login on their own (each cookie of
    /// a cookie header, the token after `Bearer`). Longest first, so a
    /// part never spoils the match of the whole.
    fn secrets(&self) -> Vec<&'a str> {
        let mut out: Vec<&'a str> = Vec::new();
        for value in self.values.values().map(|v| v.value.as_str()) {
            if value.len() >= 4 {
                out.push(value);
            }
            for part in value.split([';', ' ', ',']) {
                let part = part.split_once('=').map_or(part, |(_, v)| v).trim();
                if part.len() >= 8 && part != value {
                    out.push(part);
                }
            }
        }
        out.sort_by_key(|s| std::cmp::Reverse(s.len()));
        out.dedup();
        out
    }
}

/// A request ready to send, and which of its headers carry the login.
#[derive(Debug)]
pub struct Prepared {
    pub request: Request,
    /// Lower-case names.
    pub credential_headers: Vec<String>,
    /// The body holds a value of a variable.
    pub body_filled: bool,
}

/// Builds the request of `step`. `Err` is one sentence for the user.
pub fn prepare(
    step: &ApiStep,
    variables: Variables<'_>,
    user_agent: &str,
    jar: &Jar,
) -> Result<Prepared, String> {
    const BAD_URL: &str = "步骤的网址无效。";
    // Saved steps went through the readers; the file can be edited by hand.
    if !METHODS.contains(&step.method.as_str()) {
        return Err("步骤的请求方法无效。".to_string());
    }
    let template = site::parse_http_url(&step.url).ok_or(BAD_URL)?;
    let host = site::host_of(&template);
    let lookup = |name: &str| variables.lookup(name, &host);

    let url_text = vars::substitute_url(&step.url, &lookup).map_err(|e| e.sentence())?;
    let url = site::parse_http_url(&url_text).ok_or(BAD_URL)?;
    // A value is percent-encoded and only allowed after the host, so this
    // cannot differ; checked all the same.
    if url.scheme() != template.scheme()
        || url.host_str() != template.host_str()
        || url.port_or_known_default() != template.port_or_known_default()
    {
        return Err(BAD_URL.to_string());
    }

    let mut headers: Vec<(String, String)> = Vec::new();
    let mut credential_headers: Vec<String> = Vec::new();
    let mut content_type = None;
    for (name, template) in &step.headers {
        let name = name.to_ascii_lowercase();
        if is_core_owned_header(&name) {
            continue;
        }
        if !is_header_name(&name) {
            return Err("步骤里有名称无效的请求头，没有发送。".to_string());
        }
        let mut value =
            vars::substitute(template, Escape::Header, &lookup).map_err(|e| e.sentence())?;
        if !vars::header_safe(&value) {
            return Err(format!("请求头 {name} 里有换行等不允许的字符，没有发送。"));
        }
        let filled = vars::refs(template)
            .iter()
            .any(|n| !matches!(lookup(n), Lookup::Undefined));
        if filled || CREDENTIAL_HEADERS.contains(&name.as_str()) {
            credential_headers.push(name.clone());
        }
        if name == "cookie" {
            value = jar.overlay(&host, &value);
        }
        if name == "content-type" {
            content_type = Some(value.clone());
        }
        headers.push((name, value));
    }

    let body_filled = !step.body_base64
        && step.body.as_deref().is_some_and(|body| {
            vars::refs(body)
                .iter()
                .any(|n| !matches!(lookup(n), Lookup::Undefined))
        });
    let body = match &step.body {
        None => Vec::new(),
        Some(body) if step.body_base64 => base64::engine::general_purpose::STANDARD
            .decode(body.trim())
            .map_err(|_| "步骤的请求内容无效。".to_string())?,
        Some(body) => vars::substitute(body, Escape::for_body(content_type.as_deref()), &lookup)
            .map_err(|e| e.sentence())?
            .into_bytes(),
    };

    let ua = if user_agent.is_empty() || !vars::header_safe(user_agent) {
        DEFAULT_USER_AGENT
    } else {
        user_agent
    };
    headers.push(("User-Agent".to_string(), ua.to_string()));
    if !headers.iter().any(|(n, _)| n == "accept") {
        headers.push(("Accept".to_string(), "*/*".to_string()));
    }
    if let Some(mut page) = site::parse_http_url(&step.page) {
        page.set_fragment(None);
        let cross_origin = page.origin() != url.origin();
        if cross_origin || !matches!(step.method.as_str(), "GET" | "HEAD") {
            headers.push(("Origin".to_string(), site::origin_of(&page)));
        }
        // A browser sends only the origin across sites.
        let referer = if site::same_site(&site::host_of(&page), &host) {
            page.to_string()
        } else {
            format!("{}/", site::origin_of(&page))
        };
        headers.push(("Referer".to_string(), referer));
    }

    Ok(Prepared {
        request: Request {
            method: step.method.clone(),
            url,
            headers,
            body,
        },
        credential_headers,
        body_filled,
    })
}

enum Hop {
    /// Same origin.
    Full,
    /// Another host of the same site.
    WithoutLogin,
    Stop,
}

fn judge_redirect(from: &Url, to: &Url) -> Hop {
    if !matches!(to.scheme(), "http" | "https")
        || to.host_str().is_none()
        || !to.username().is_empty()
        || to.password().is_some()
    {
        return Hop::Stop;
    }
    if from.origin() == to.origin() {
        return Hop::Full;
    }
    if from.scheme() == "https" && to.scheme() != "https" {
        return Hop::Stop;
    }
    let (a, b) = (site::host_of(from), site::host_of(to));
    if !site::same_site(&a, &b) {
        return Hop::Stop;
    }
    if site::is_internal_host(&b) && !site::is_internal_host(&a) {
        return Hop::Stop;
    }
    Hop::WithoutLogin
}

fn clip(text: &str, max: usize) -> String {
    let cleaned: String = text
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect();
    let cleaned = cleaned.split_whitespace().collect::<Vec<_>>().join(" ");
    if cleaned.chars().count() <= max {
        cleaned
    } else {
        let mut s: String = cleaned.chars().take(max).collect();
        s.push('…');
        s
    }
}

fn scalar(v: &serde_json::Value) -> Option<String> {
    match v {
        serde_json::Value::String(s) if !s.is_empty() => Some(s.clone()),
        serde_json::Value::Number(n) => Some(n.to_string()),
        serde_json::Value::Bool(b) => Some(b.to_string()),
        _ => None,
    }
}

/// A few words of what the answer says. Never the whole body.
fn digest(resp: &Response) -> String {
    let content_type = resp.header("content-type");
    // Compressed although `identity` was asked for: nothing readable.
    if resp
        .header("content-encoding")
        .is_some_and(|e| !e.trim().is_empty() && !e.trim().eq_ignore_ascii_case("identity"))
    {
        return String::new();
    }
    let text = String::from_utf8_lossy(&resp.body);
    let trimmed = text.trim_start();
    if expiry::is_json(content_type) || trimmed.starts_with('{') {
        if let Ok(serde_json::Value::Object(obj)) = serde_json::from_str(trimmed) {
            let mut parts = Vec::new();
            for key in ["ret", "code", "status", "success", "errno", "result"] {
                if let Some(v) = obj.get(key).and_then(scalar) {
                    parts.push(format!("{key} {}", clip(&v, 20)));
                    break;
                }
            }
            let data = obj.get("data").and_then(|d| d.as_object());
            let message = ["msg", "message", "info", "tip", "error", "detail"]
                .iter()
                .find_map(|k| {
                    obj.get(*k)
                        .and_then(|v| v.as_str())
                        .or_else(|| data.and_then(|d| d.get(*k)).and_then(|v| v.as_str()))
                        .filter(|s| !s.trim().is_empty())
                });
            if let Some(m) = message {
                parts.push(clip(m, 80));
            }
            return parts.join(" · ");
        }
        return String::new();
    }
    if expiry::is_html(content_type) || trimmed.starts_with('<') {
        let lower = trimmed.to_lowercase();
        if let (Some(a), Some(b)) = (lower.find("<title"), lower.find("</title>")) {
            if let Some(open_end) = lower[a..].find('>') {
                let start = a + open_end + 1;
                // Offsets are from the lower-cased copy; only trust them
                // when lower-casing kept the length.
                if start <= b && lower.len() == trimmed.len() && trimmed.is_char_boundary(start) {
                    return clip(&trimmed[start..b], 60);
                }
            }
        }
        return "网页".to_string();
    }
    clip(trimmed.lines().next().unwrap_or(""), 80)
}

fn redact(summary: String, variables: Variables<'_>) -> String {
    let mut out = summary;
    for secret in variables.secrets() {
        if out.contains(secret) {
            out = out.replace(secret, "•••");
        }
    }
    out
}

/// Where and how a step's request leaves.
pub struct Outbound<'a> {
    pub connector: &'a dyn Connector,
    pub access: Access,
    pub limits: &'a Limits,
    pub markers: &'a Markers,
    /// Requests may go to this machine and private networks.
    pub allow_private: bool,
    /// Trust anchors (DER) on top of the built-in ones.
    pub extra_roots: &'a [Vec<u8>],
}

fn failed(step: &ApiStep, status: Option<u16>, summary: String) -> StepResult {
    StepResult {
        step_id: step.id.clone(),
        status: StepStatus::Failed,
        http_status: status,
        summary,
    }
}

/// Sends `step` and judges the answer.
pub async fn replay(
    step: &ApiStep,
    variables: Variables<'_>,
    user_agent: &str,
    jar: &mut Jar,
    out: &Outbound<'_>,
) -> StepResult {
    let prepared = match prepare(step, variables, user_agent, jar) {
        Ok(p) => p,
        Err(sentence) => return failed(step, None, sentence),
    };
    let Prepared {
        mut request,
        credential_headers,
        body_filled,
    } = prepared;
    let private = |url: &Url| !out.allow_private && site::is_internal_host(&site::host_of(url));
    if private(&request.url) {
        return failed(step, None, PRIVATE_SENTENCE.to_string());
    }
    let dial = Dial {
        connector: out.connector,
        access: out.access,
        allow_private: out.allow_private,
        extra_roots: out.extra_roots,
    };
    let first_url = request.url.clone();
    let mut redirected_to: Option<Url> = None;
    let mut hops = 0u8;
    let mut note = None;

    let response = loop {
        let resp = match http::send(&dial, &request, out.limits).await {
            Ok(r) => r,
            Err(e) => return failed(step, None, e.sentence()),
        };
        jar.absorb(&site::host_of(&request.url), &resp);
        if !matches!(resp.status, 301 | 302 | 303 | 307 | 308) {
            break resp;
        }
        let Some(next) = resp
            .header("location")
            .and_then(|l| request.url.join(l).ok())
        else {
            break resp;
        };
        let mut hop = judge_redirect(&request.url, &next);
        if private(&next) {
            hop = Hop::Stop;
        }
        let keeps_method = !(resp.status == 303
            || (matches!(resp.status, 301 | 302)
                && !matches!(request.method.as_str(), "GET" | "HEAD")));
        // The body would carry a value to a host it was not written for.
        if matches!(hop, Hop::WithoutLogin) && body_filled && keeps_method {
            hop = Hop::Stop;
        }
        redirected_to = Some(next.clone());
        // A login page is the answer already; fetching it adds nothing.
        if out.markers.is_login_url(&next) && !out.markers.is_login_url(&first_url) {
            break resp;
        }
        match hop {
            Hop::Stop => {
                note = Some(format!(
                    "跳转到了 {}，没有跟随",
                    next.host_str().unwrap_or("")
                ));
                break resp;
            }
            Hop::WithoutLogin => {
                request
                    .headers
                    .retain(|(n, _)| !credential_headers.contains(&n.to_ascii_lowercase()));
            }
            Hop::Full => {}
        }
        if hops >= out.limits.max_redirects {
            note = Some("跳转次数太多".to_string());
            break resp;
        }
        hops += 1;
        if !keeps_method {
            request.method = "GET".to_string();
            request.body.clear();
            request
                .headers
                .retain(|(n, _)| !n.eq_ignore_ascii_case("content-type"));
        }
        if let Some(cookie) = request.headers.iter_mut().find(|(n, _)| n == "cookie") {
            cookie.1 = jar.overlay(&site::host_of(&next), &cookie.1);
        }
        request.url = next;
    };

    let status = response.status;
    let observation = Observation {
        status,
        request_url: &first_url,
        redirected_to: redirected_to.as_ref(),
        content_type: response.header("content-type"),
        body: &response.body,
        recorded_status: step.recorded_status,
        recorded_content_type: step.recorded_content_type.as_deref(),
    };
    if expiry::looks_logged_out(&observation, out.markers) {
        return StepResult {
            step_id: step.id.clone(),
            status: StepStatus::LoggedOut,
            http_status: Some(status),
            summary: format!("{status} · 登录失效，需要重新登录"),
        };
    }
    let mut parts = vec![status.to_string()];
    if let Some(note) = note {
        parts.push(note);
    } else {
        let d = digest(&response);
        if !d.is_empty() {
            parts.push(d);
        }
    }
    let summary = redact(parts.join(" · "), variables);
    StepResult {
        step_id: step.id.clone(),
        status: if (200..300).contains(&status) {
            StepStatus::Ok
        } else {
            StepStatus::Failed
        },
        http_status: Some(status),
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Source;

    fn step(url: &str, headers: &[(&str, &str)], body: Option<&str>) -> ApiStep {
        ApiStep {
            id: "s1".into(),
            name: "签到".into(),
            method: "POST".into(),
            url: url.into(),
            headers: headers
                .iter()
                .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
                .collect(),
            body: body.map(str::to_string),
            body_base64: false,
            page: "https://main.example.com/user#top".into(),
            recorded_status: Some(200),
            recorded_content_type: Some("application/json".into()),
        }
    }

    fn auto(name: &str, from: AutoFrom, url: Option<&str>) -> VariableDef {
        VariableDef {
            name: name.into(),
            source: Source::Auto,
            from: Some(from),
            key: None,
            url: url.map(str::to_string),
        }
    }

    fn manual(name: &str) -> VariableDef {
        VariableDef {
            name: name.into(),
            source: Source::Manual,
            from: None,
            key: None,
            url: None,
        }
    }

    fn values(pairs: &[(&str, &str)]) -> BTreeMap<String, StoredValue> {
        pairs
            .iter()
            .map(|(k, v)| {
                (
                    (*k).to_string(),
                    StoredValue {
                        value: (*v).to_string(),
                        updated_at: "2026-10-12T00:00:00Z".into(),
                    },
                )
            })
            .collect()
    }

    const HOME: &str = "https://main.example.com/user";

    fn header<'a>(p: &'a Prepared, name: &str) -> Option<&'a str> {
        p.request
            .headers
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    #[test]
    fn the_request_is_rebuilt_from_the_step_and_the_values() {
        let defs = [auto("cookie", AutoFrom::CookieHeader, None), manual("uid")];
        let vals = values(&[("cookie", "sid=abc==; uid=7"), ("uid", "10 293")]);
        let s = step(
            "https://main.example.com/user/checkin?u={uid}",
            &[
                ("cookie", "{cookie}"),
                ("x-requested-with", "XMLHttpRequest"),
                ("content-type", "application/x-www-form-urlencoded"),
                // Never the step's to set.
                ("host", "evil.example"),
                ("user-agent", "stored"),
                ("content-length", "999"),
                ("sec-fetch-site", "same-origin"),
            ],
            Some("a=1&u={uid}"),
        );
        let p = prepare(
            &s,
            Variables {
                home: HOME,
                defs: &defs,
                values: &vals,
            },
            "Mozilla/5.0 Test",
            &Jar::default(),
        )
        .unwrap();
        assert_eq!(
            p.request.url.as_str(),
            "https://main.example.com/user/checkin?u=10%20293"
        );
        assert_eq!(header(&p, "cookie"), Some("sid=abc==; uid=7"));
        assert_eq!(header(&p, "user-agent"), Some("Mozilla/5.0 Test"));
        assert_eq!(header(&p, "origin"), Some("https://main.example.com"));
        assert_eq!(header(&p, "referer"), Some("https://main.example.com/user"));
        assert_eq!(header(&p, "host"), None);
        assert_eq!(header(&p, "content-length"), None);
        assert_eq!(header(&p, "sec-fetch-site"), None);
        assert_eq!(p.request.body, b"a=1&u=10%20293");
        assert_eq!(p.credential_headers, ["cookie"]);
        // One User-Agent, ours.
        assert_eq!(
            p.request
                .headers
                .iter()
                .filter(|(n, _)| n.eq_ignore_ascii_case("user-agent"))
                .count(),
            1
        );
    }

    #[test]
    fn a_get_to_its_own_origin_sends_no_origin() {
        let mut s = step("https://main.example.com/api", &[], None);
        s.method = "GET".into();
        let vals = values(&[]);
        let vars = Variables {
            home: HOME,
            defs: &[],
            values: &vals,
        };
        let p = prepare(&s, vars, "", &Jar::default()).unwrap();
        assert_eq!(header(&p, "origin"), None);
        assert_eq!(header(&p, "user-agent"), Some(DEFAULT_USER_AGENT));
        // Across sites: an Origin, and only the origin as Referer.
        s.url = "https://api.other.example/x".into();
        let p = prepare(&s, vars, "", &Jar::default()).unwrap();
        assert_eq!(header(&p, "origin"), Some("https://main.example.com"));
        assert_eq!(header(&p, "referer"), Some("https://main.example.com/"));
    }

    #[test]
    fn a_value_with_a_line_break_never_reaches_a_header() {
        let defs = [auto("cookie", AutoFrom::CookieHeader, None), manual("tok")];
        let s = step(
            "https://main.example.com/api",
            &[("cookie", "{cookie}"), ("x-token", "{tok}")],
            None,
        );
        for bad in ["a\r\nX-Injected: 1", "a\nb", "a\rb"] {
            let vals = values(&[("cookie", "sid=1"), ("tok", bad)]);
            let err = prepare(
                &s,
                Variables {
                    home: HOME,
                    defs: &defs,
                    values: &vals,
                },
                "",
                &Jar::default(),
            )
            .unwrap_err();
            assert!(err.contains("tok"), "{err}");
        }
        // Nor through the User-Agent.
        let vals = values(&[("cookie", "sid=1"), ("tok", "ok")]);
        let p = prepare(
            &s,
            Variables {
                home: HOME,
                defs: &defs,
                values: &vals,
            },
            "UA\r\nX-Injected: 1",
            &Jar::default(),
        )
        .unwrap();
        assert_eq!(header(&p, "user-agent"), Some(DEFAULT_USER_AGENT));
        let wire = String::from_utf8(http::encode(&p.request)).unwrap();
        assert!(!wire.contains("X-Injected"));
    }

    #[test]
    fn a_variable_without_a_value_fails_the_step_instead_of_being_sent() {
        let defs = [auto("cookie", AutoFrom::CookieHeader, None)];
        let vals = values(&[]);
        let s = step(
            "https://main.example.com/api",
            &[("cookie", "{cookie}")],
            None,
        );
        let err = prepare(
            &s,
            Variables {
                home: HOME,
                defs: &defs,
                values: &vals,
            },
            "",
            &Jar::default(),
        )
        .unwrap_err();
        assert!(err.contains("cookie"), "{err}");
    }

    #[test]
    fn a_cookie_is_only_sent_to_the_site_it_was_read_for() {
        let defs = [
            auto("cookie", AutoFrom::CookieHeader, None),
            auto(
                "bank",
                AutoFrom::CookieHeader,
                Some("https://bank.example/"),
            ),
            auto(
                "token",
                AutoFrom::RequestHeader,
                Some("https://bank.example/"),
            ),
        ];
        let vals = values(&[("cookie", "sid=1"), ("bank", "bank=1"), ("token", "t")]);
        let vars = Variables {
            home: HOME,
            defs: &defs,
            values: &vals,
        };
        // The task's own cookie to another site: refused.
        let s = step(
            "https://collector.example/x",
            &[("cookie", "{cookie}")],
            None,
        );
        assert!(prepare(&s, vars, "", &Jar::default()).is_err());
        // Another site's cookie to the task's site: refused.
        let s = step("https://main.example.com/x?c={bank}", &[], None);
        assert!(prepare(&s, vars, "", &Jar::default()).is_err());
        // To a sibling host of the site it was read for: fine.
        let s = step("https://api.example.com/x", &[("cookie", "{cookie}")], None);
        assert!(prepare(&s, vars, "", &Jar::default()).is_ok());
        let s = step("https://www.bank.example/x", &[("cookie", "{bank}")], None);
        assert!(prepare(&s, vars, "", &Jar::default()).is_ok());
        // A value read from a request header is bound the same way.
        let s = step(
            "https://main.example.com/x",
            &[("x-token", "{token}")],
            None,
        );
        assert!(prepare(&s, vars, "", &Jar::default()).is_err());
        let s = step("https://main.example.com/x", &[], Some("t={token}"));
        assert!(prepare(&s, vars, "", &Jar::default()).is_err());
        let s = step(
            "https://api.bank.example/x",
            &[("x-token", "{token}")],
            None,
        );
        assert!(prepare(&s, vars, "", &Jar::default()).is_ok());
    }

    #[test]
    fn a_step_edited_by_hand_cannot_break_out_of_the_request() {
        let vals = values(&[]);
        let vars = Variables {
            home: HOME,
            defs: &[],
            values: &vals,
        };
        let mut s = step("https://main.example.com/x", &[], None);
        s.method = "GET /evil HTTP/1.1\r\nX: y".into();
        assert!(prepare(&s, vars, "", &Jar::default()).is_err());
        let s = step(
            "https://main.example.com/x",
            &[("x-a\r\nx-injected", "1")],
            None,
        );
        assert!(prepare(&s, vars, "", &Jar::default()).is_err());
        let s = step(
            "https://main.example.com/x",
            &[("x-a", "1\r\nx-injected: 1")],
            None,
        );
        assert!(prepare(&s, vars, "", &Jar::default()).is_err());
        let s = step("https://main.example.com/x\r\nHost: evil", &[], None);
        assert!(prepare(&s, vars, "", &Jar::default()).is_err());
    }

    #[test]
    fn the_body_knows_whether_it_holds_a_value() {
        let defs = [manual("uid")];
        let vals = values(&[("uid", "7")]);
        let vars = Variables {
            home: HOME,
            defs: &defs,
            values: &vals,
        };
        let s = step("https://main.example.com/x", &[], Some("u={uid}"));
        assert!(prepare(&s, vars, "", &Jar::default()).unwrap().body_filled);
        let s = step("https://main.example.com/x", &[], Some("u={other}"));
        assert!(!prepare(&s, vars, "", &Jar::default()).unwrap().body_filled);
    }

    #[test]
    fn redirects_are_judged_by_where_they_go() {
        let u = |s: &str| Url::parse(s).unwrap();
        assert!(matches!(
            judge_redirect(&u("https://a.example.com/x"), &u("https://a.example.com/y")),
            Hop::Full
        ));
        assert!(matches!(
            judge_redirect(&u("https://a.example.com/x"), &u("https://b.example.com/y")),
            Hop::WithoutLogin
        ));
        // Another port is another origin.
        assert!(matches!(
            judge_redirect(
                &u("https://a.example.com/x"),
                &u("https://a.example.com:8443/y")
            ),
            Hop::WithoutLogin
        ));
        for to in [
            "https://other.example/y",
            "http://a.example.com/y",
            "ftp://a.example.com/y",
            "https://user:pw@a.example.com/y",
        ] {
            assert!(
                matches!(
                    judge_redirect(&u("https://a.example.com/x"), &u(to)),
                    Hop::Stop
                ),
                "{to}"
            );
        }
        for to in ["http://127.0.0.1:9090/configs", "http://localhost/"] {
            assert!(
                matches!(
                    judge_redirect(&u("http://a.example.com/x"), &u(to)),
                    Hop::Stop
                ),
                "{to}"
            );
        }
    }

    #[test]
    fn cookies_set_during_a_run_are_laid_over_the_header() {
        let mut jar = Jar::default();
        jar.absorb(
            "main.example.com",
            &Response {
                status: 200,
                headers: vec![
                    ("set-cookie".into(), "sid=new; Path=/; HttpOnly".into()),
                    ("set-cookie".into(), "extra=1".into()),
                    ("set-cookie".into(), "gone=x; Max-Age=0".into()),
                ],
                body: vec![],
                truncated: false,
            },
        );
        assert_eq!(
            jar.overlay("main.example.com", "sid=old; uid=7; gone=1"),
            "sid=new; uid=7; gone=1; extra=1"
        );
        assert_eq!(jar.overlay("other.example", "sid=old"), "sid=old");
    }

    #[test]
    fn summaries_are_short_and_hide_values() {
        let resp = |ct: &str, body: &str| Response {
            status: 200,
            headers: vec![("content-type".into(), ct.into())],
            body: body.as_bytes().to_vec(),
            truncated: false,
        };
        assert_eq!(
            digest(&resp(
                "application/json",
                r#"{"ret":1,"msg":"获得了 312 MB 流量"}"#
            )),
            "ret 1 · 获得了 312 MB 流量"
        );
        assert_eq!(
            digest(&resp(
                "application/json",
                r#"{"code":0,"data":{"message":"ok"}}"#
            )),
            "code 0 · ok"
        );
        assert_eq!(
            digest(&resp(
                "text/html",
                "<html><head><title> 登录 </title></head>"
            )),
            "登录"
        );
        assert_eq!(digest(&resp("text/plain", "done\nmore")), "done");
        let long = digest(&resp("text/plain", &"x".repeat(5000)));
        assert!(long.chars().count() <= 81);

        let vals = values(&[("cookie", "sid=SECRETVALUE")]);
        let vars = Variables {
            home: HOME,
            defs: &[],
            values: &vals,
        };
        assert_eq!(
            redact("200 · echo sid=SECRETVALUE".into(), vars),
            "200 · echo •••"
        );
        // A part of a value that is a login on its own.
        let vals = values(&[
            ("cookie", "sid=SECRETVALUE; uid=7"),
            ("auth", "Bearer TOKEN12345"),
        ]);
        let vars = Variables {
            home: HOME,
            defs: &[],
            values: &vals,
        };
        assert_eq!(
            redact("200 · session SECRETVALUE of TOKEN12345".into(), vars),
            "200 · session ••• of •••"
        );
        // A compressed answer is not shown as noise.
        let mut gz = resp("text/plain", "\u{1f}\u{8b}garbage");
        gz.headers.push(("content-encoding".into(), "gzip".into()));
        assert_eq!(digest(&gz), "");
    }
}
