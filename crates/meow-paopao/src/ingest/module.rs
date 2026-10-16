//! Rewrite modules (Surge `.sgmodule`, Loon `.plugin` / `.lpx`, Quantumult
//! X snippets, Stash `.stoverride`) parsed the way the app parses them
//! (Dart `parseModule` in `script_module.dart`), so the core can refresh
//! them without the app: [`parse_module`] gives `ModuleSpec.toJson`.
//!
//! The Dart parser's regular expressions are matched by hand here (their
//! `\s` is [`is_regex_space`]); lines it does not understand are left out
//! as there. Where Dart would throw on a mistyped Stash field the field
//! reads as missing, and a `task_local` line without parts is skipped.

use serde_json::{Map, Value};

use crate::dart::{
    int_try_parse, is_regex_space, json_encode, to_lower_case, trim, uri_last_path_segment, Dv,
};

/// A 1×1 transparent GIF.
const TINY_GIF: &str = "R0lGODlhAQABAIAAAP///wAAACH5BAEAAAAALAAAAAABAAEAAAICRAEAOw==";

/// The name a module without `#!name` gets: the URL's last path segment,
/// else its host (Dart: `base.pathSegments.lastOrNull ?? base.host`).
pub fn fallback_name(url: &str) -> String {
    if let Some(last) = uri_last_path_segment(url) {
        return last;
    }
    let rest = url.split_once("://").map_or(url, |(_, r)| r);
    let authority = &rest[..rest.find(['/', '?', '#']).unwrap_or(rest.len())];
    let host = authority.rsplit_once('@').map_or(authority, |(_, h)| h);
    let host = match host.strip_prefix('[') {
        Some(v6) => v6.split(']').next().unwrap_or(v6),
        None => host.split(':').next().unwrap_or(host),
    };
    to_lower_case(host)
}

#[derive(Default)]
struct Spec {
    name: String,
    description: String,
    scripts: Vec<Script>,
    rewrites: Vec<Rewrite>,
    hostnames: Vec<String>,
    excluded: Vec<String>,
    rules: Vec<String>,
    arguments: Vec<Argument>,
    arguments_help: String,
    author: String,
    homepage: String,
    icon: String,
    category: String,
    systems: Vec<String>,
    open_url: String,
}

impl Spec {
    /// `ModuleSpec.toJson`.
    fn to_json(&self) -> Value {
        let mut m = Map::new();
        m.insert("name".into(), self.name.clone().into());
        if !self.description.is_empty() {
            m.insert("desc".into(), self.description.clone().into());
        }
        m.insert(
            "scripts".into(),
            self.scripts.iter().map(Script::to_json).collect(),
        );
        m.insert(
            "rewrites".into(),
            self.rewrites.iter().map(Rewrite::to_json).collect(),
        );
        m.insert("hostnames".into(), self.hostnames.clone().into());
        if !self.excluded.is_empty() {
            m.insert("excluded".into(), self.excluded.clone().into());
        }
        m.insert("rules".into(), self.rules.clone().into());
        if !self.arguments.is_empty() {
            m.insert(
                "arguments".into(),
                self.arguments.iter().map(Argument::to_json).collect(),
            );
        }
        for (k, v) in [
            ("argumentsHelp", &self.arguments_help),
            ("author", &self.author),
            ("homepage", &self.homepage),
            ("icon", &self.icon),
            ("category", &self.category),
        ] {
            if !v.is_empty() {
                m.insert(k.into(), v.clone().into());
            }
        }
        if !self.systems.is_empty() {
            m.insert("systems".into(), self.systems.clone().into());
        }
        if !self.open_url.is_empty() {
            m.insert("openUrl".into(), self.open_url.clone().into());
        }
        Value::Object(m)
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Kind {
    Input,
    Toggle,
    Choice,
}

struct Argument {
    key: String,
    label: String,
    kind: Kind,
    default: String,
    options: Vec<String>,
    help: String,
}

impl Argument {
    fn plain(key: String, kind: Kind, default: String) -> Self {
        Self {
            key,
            label: String::new(),
            kind,
            default,
            options: Vec::new(),
            help: String::new(),
        }
    }

    fn to_json(&self) -> Value {
        let mut m = Map::new();
        m.insert("key".into(), self.key.clone().into());
        if !self.label.is_empty() {
            m.insert("label".into(), self.label.clone().into());
        }
        let kind = match self.kind {
            Kind::Input => "input",
            Kind::Toggle => "toggle",
            Kind::Choice => "choice",
        };
        m.insert("kind".into(), kind.into());
        m.insert("default".into(), self.default.clone().into());
        if !self.options.is_empty() {
            m.insert("options".into(), self.options.clone().into());
        }
        if !self.help.is_empty() {
            m.insert("help".into(), self.help.clone().into());
        }
        Value::Object(m)
    }
}

struct Script {
    name: String,
    response: bool,
    pattern: String,
    url: String,
    argument: String,
    binary_body: bool,
    requires_body: bool,
    timeout: i64,
    cron: Option<String>,
    argument_object: bool,
}

impl Script {
    fn new(name: String, response: bool, pattern: String, url: String) -> Self {
        Self {
            name,
            response,
            pattern,
            url,
            argument: String::new(),
            binary_body: false,
            requires_body: false,
            timeout: 10,
            cron: None,
            argument_object: false,
        }
    }

    fn to_json(&self) -> Value {
        let mut m = Map::new();
        m.insert("name".into(), self.name.clone().into());
        m.insert("response".into(), self.response.into());
        m.insert("pattern".into(), self.pattern.clone().into());
        m.insert("url".into(), self.url.clone().into());
        if !self.argument.is_empty() {
            m.insert("argument".into(), self.argument.clone().into());
        }
        if self.binary_body {
            m.insert("binary".into(), true.into());
        }
        if self.requires_body {
            m.insert("body".into(), true.into());
        }
        m.insert("timeout".into(), self.timeout.into());
        if let Some(c) = &self.cron {
            m.insert("cron".into(), c.clone().into());
        }
        if self.argument_object {
            m.insert("argObject".into(), true.into());
        }
        Value::Object(m)
    }
}

struct Rewrite {
    pattern: String,
    action: Map<String, Value>,
    response: bool,
    needs_body: bool,
}

impl Rewrite {
    fn new(pattern: &str, action: Map<String, Value>) -> Self {
        Self {
            pattern: pattern.to_owned(),
            action,
            response: false,
            needs_body: false,
        }
    }

    fn reject(pattern: &str, kind: &str) -> Self {
        Self::new(
            pattern,
            obj([("op", "reject".into()), ("kind", kind.into())]),
        )
    }

    fn to_json(&self) -> Value {
        let mut m = Map::new();
        m.insert("pattern".into(), self.pattern.clone().into());
        m.insert("action".into(), Value::Object(self.action.clone()));
        if self.response {
            m.insert("response".into(), true.into());
        }
        if self.needs_body {
            m.insert("body".into(), true.into());
        }
        Value::Object(m)
    }
}

fn obj<const N: usize>(entries: [(&str, Value); N]) -> Map<String, Value> {
    entries
        .into_iter()
        .map(|(k, v)| (k.to_owned(), v))
        .collect()
}

fn strings(v: &[&str]) -> Value {
    v.iter().map(|s| Value::from(*s)).collect()
}

/// `RejectKind` by its spellings.
fn reject_kind(s: &str) -> Option<&'static str> {
    Some(match to_lower_case(s).as_str() {
        "reject" => "plain",
        "reject-200" | "reject-drop" | "reject-no-drop" => "empty",
        "reject-dict" => "dict",
        "reject-array" => "array",
        "reject-img" | "reject-tinygif" | "reject-video" => "image",
        _ => return None,
    })
}

/// Dart `_splitArgs`: on commas outside double quotes; trimmed, unquoted.
fn split_args(s: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut b = String::new();
    let mut quoted = false;
    let chars: Vec<char> = s.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        let ch = chars[i];
        if quoted && ch == '\\' && chars.get(i + 1) == Some(&'"') {
            b.push('"');
            i += 1;
        } else if ch == '"' {
            quoted = !quoted;
        } else if ch == ',' && !quoted {
            out.push(trim(&b).to_owned());
            b.clear();
        } else {
            b.push(ch);
        }
        i += 1;
    }
    if !trim(&b).is_empty() {
        out.push(trim(&b).to_owned());
    }
    out
}

/// Dart `_words`: on spaces; double quotes group a word only when they wrap
/// all of it or a `key="a b"` value.
fn words(s: &str) -> Vec<String> {
    let chars: Vec<char> = s.chars().collect();
    let close = |i: usize| -> Option<usize> {
        let mut j = i + 1;
        while j < chars.len() {
            if chars[j] == '\\' && j + 1 < chars.len() {
                j += 2;
                continue;
            }
            if chars[j] == '"' {
                let end = j + 1 == chars.len() || chars[j + 1] == ' ' || chars[j + 1] == '\t';
                return end.then_some(j);
            }
            j += 1;
        }
        None
    };
    let mut out = Vec::new();
    let mut b = String::new();
    let mut started = false;
    let mut i = 0;
    while i < chars.len() {
        let ch = chars[i];
        let opens = ch == '"' && ((b.is_empty() && !started) || b.ends_with('='));
        if opens {
            if let Some(j) = close(i) {
                let mut k = i + 1;
                while k < j {
                    if chars[k] == '\\' && k + 1 < j && chars[k + 1] == '"' {
                        b.push('"');
                        k += 1;
                    } else {
                        b.push(chars[k]);
                    }
                    k += 1;
                }
                started = true;
                i = j + 1;
                continue;
            }
        }
        if ch == ' ' || ch == '\t' {
            if !b.is_empty() || started {
                out.push(std::mem::take(&mut b));
            }
            b.clear();
            started = false;
        } else {
            b.push(ch);
        }
        i += 1;
    }
    if !b.is_empty() || started {
        out.push(b);
    }
    out
}

/// Dart `_keyValues`: `key=value` parts, keys lowercased (later ones win).
fn key_values<'a>(parts: impl IntoIterator<Item = &'a String>) -> Map<String, Value> {
    let mut m = Map::new();
    for p in parts {
        if let Some(i) = p.find('=').filter(|&i| i > 0) {
            m.insert(
                to_lower_case(trim(&p[..i])),
                trim(&p[i + 1..]).to_owned().into(),
            );
        }
    }
    m
}

fn kv<'a>(m: &'a Map<String, Value>, k: &str) -> Option<&'a str> {
    m.get(k).and_then(Value::as_str)
}

fn truthy(v: Option<&str>) -> bool {
    v.is_some_and(|v| v == "1" || to_lower_case(v) == "true")
}

fn int_or(v: Option<&str>, or: i64) -> i64 {
    int_try_parse(v.unwrap_or("")).unwrap_or(or)
}

/// Every character of `s` from byte `at` on that is `\s`; where the run ends.
fn skip_spaces(s: &str, at: usize) -> usize {
    s[at..]
        .char_indices()
        .find(|&(_, c)| !is_regex_space(c))
        .map_or(s.len(), |(i, _)| at + i)
}

/// A line terminator, which `.` in a Dart regular expression does not match.
fn is_line_end(c: char) -> bool {
    matches!(c, '\n' | '\r' | '\u{2028}' | '\u{2029}')
}

/// `s` with each match `replace` finds replaced: `replace(s, at)` gives the
/// match's end and its replacement, or None for no match at `at`.
fn replace_all(s: &str, mut replace: impl FnMut(&str, usize) -> Option<(usize, String)>) -> String {
    let mut out = String::with_capacity(s.len());
    let mut at = 0;
    while at < s.len() {
        if let Some((end, with)) = replace(s, at) {
            out.push_str(&with);
            at = end;
            continue;
        }
        let c = s[at..].chars().next().unwrap_or(' ');
        out.push(c);
        at += c.len_utf8();
    }
    out
}

/// The arguments' values in effect, in the order they were declared.
type Args = Vec<(String, String)>;

fn arg<'a>(args: &'a Args, key: &str) -> Option<&'a str> {
    args.iter().find(|(k, _)| k == key).map(|(_, v)| v.as_str())
}

fn set_arg(args: &mut Args, key: String, value: String) {
    match args.iter_mut().find(|(k, _)| *k == key) {
        Some(slot) => slot.1 = value,
        None => args.push((key, value)),
    }
}

/// Dart `fill`: `{{{key}}}`, Loon's `argument=[{a},{b}]` (an object for the
/// script) and `{key}` of declared keys.
fn fill(s: &str, args: &Args) -> String {
    // \{\{\{([^}]+)\}\}\}
    let s = replace_all(s, |s, at| {
        let rest = s[at..].strip_prefix("{{{")?;
        let close = rest.find('}').filter(|&i| i > 0)?;
        rest[close..].starts_with("}}}").then(|| {
            (
                at + 3 + close + 3,
                arg(args, trim(&rest[..close])).unwrap_or("").to_owned(),
            )
        })
    });
    // argument\s*=\s*\[((?:\s*\{[^}]+\}\s*,?)+)\]
    let s = replace_all(&s, |s, at| {
        let mut i = skip_spaces(s, at + s[at..].strip_prefix("argument").map(|_| 8)?);
        i = skip_spaces(s, i + s[i..].strip_prefix('=').map(|_| 1)?);
        i += s[i..].strip_prefix('[').map(|_| 1)?;
        let mut keys = Vec::new();
        loop {
            let j = skip_spaces(s, i);
            let Some(inner) = s[j..].strip_prefix('{') else {
                break;
            };
            let Some(close) = inner.find('}').filter(|&n| n > 0) else {
                break;
            };
            keys.push(trim(&inner[..close]).to_owned());
            i = skip_spaces(s, j + 1 + close + 1);
            if s[i..].starts_with(',') {
                i += 1;
            }
        }
        if keys.is_empty() || !s[i..].starts_with(']') {
            return None;
        }
        let mut obj: Vec<(Dv, Dv)> = Vec::new();
        for k in keys {
            let v = Dv::Str(arg(args, &k).unwrap_or("").to_owned());
            match obj.iter_mut().find(|(key, _)| *key == Dv::Str(k.clone())) {
                Some(slot) => slot.1 = v,
                None => obj.push((Dv::Str(k), v)),
            }
        }
        let inner = json_encode(&Dv::Map(obj));
        Some((
            i + 1,
            format!(
                "argument={},argument-object=true",
                json_encode(&Dv::Str(inner))
            ),
        ))
    });
    // \{([^{}\s"]+)\}
    replace_all(&s, |s, at| {
        let rest = s[at..].strip_prefix('{')?;
        let end = rest
            .char_indices()
            .find(|&(_, c)| matches!(c, '{' | '}' | '"') || is_regex_space(c))
            .map_or(rest.len(), |(i, _)| i);
        if end == 0 || !rest[end..].starts_with('}') {
            return None;
        }
        let key = trim(&rest[..end]);
        arg(args, key).map(|v| (at + 1 + end + 1, v.to_owned()))
    })
}

/// Parses a module in any of the common formats (Dart `parseModule`):
/// `ModuleSpec.toJson`. [`values`]: the user's settings for its arguments
/// (the defaults fill the rest).
pub fn parse_module(text: &str, fallback: &str, values: &[(String, String)]) -> Value {
    if looks_like_stash(text) {
        return parse_stash(text, fallback).to_json();
    }
    let mut spec = Spec {
        name: fallback.to_owned(),
        ..Spec::default()
    };
    let mut meta: Vec<(String, String)> = Vec::new();
    let mut args: Args = Vec::new();

    let mut section = String::new();
    for raw in text.split('\n') {
        let line = trim(raw);
        if line.starts_with("#!") && line.contains('=') {
            let i = line.find('=').unwrap_or(0);
            let key = to_lower_case(trim(&line[2..i]));
            let value = trim(&line[i + 1..]).to_owned();
            match meta.iter_mut().find(|(k, _)| *k == key) {
                Some(slot) => slot.1 = value,
                None => meta.push((key, value)),
            }
        }
        if let Some(list) = line.strip_prefix("#!arguments=") {
            for p in split_args(list) {
                if let Some(i) = p.find(':').filter(|&i| i > 0) {
                    let key = trim(&p[..i]).to_owned();
                    let value = trim(&p[i + 1..]).replace('"', "");
                    set_arg(&mut args, key.clone(), value.clone());
                    let kind = if value == "true" || value == "false" {
                        Kind::Toggle
                    } else {
                        Kind::Input
                    };
                    spec.arguments.push(Argument::plain(key, kind, value));
                }
            }
        }
        if line.starts_with('[') && line.ends_with(']') && line.len() >= 2 {
            section = to_lower_case(trim(&line[1..line.len() - 1]));
        } else if section == "argument" && line.contains('=') {
            let i = line.find('=').unwrap_or(0);
            let key = trim(&line[..i]).to_owned();
            let parts = split_args(&line[i + 1..]);
            if key.is_empty() || parts.is_empty() {
                continue;
            }
            let options = key_values(&parts[1..]);
            let plain: Vec<String> = parts[1..]
                .iter()
                .filter(|p| !p.contains('='))
                .cloned()
                .collect();
            let kind = match to_lower_case(&parts[0]).as_str() {
                "switch" => Kind::Toggle,
                "select" => Kind::Choice,
                _ => Kind::Input,
            };
            let default = plain.first().cloned().unwrap_or_default();
            set_arg(&mut args, key.clone(), default.clone());
            spec.arguments.push(Argument {
                key,
                label: kv(&options, "tag").unwrap_or("").to_owned(),
                kind,
                default,
                options: if kind == Kind::Choice {
                    plain
                } else {
                    Vec::new()
                },
                help: kv(&options, "desc").unwrap_or("").to_owned(),
            });
        }
    }
    for (k, v) in values {
        if arg(&args, k).is_some() {
            set_arg(&mut args, k.clone(), v.clone());
        }
    }

    section.clear();
    for raw in text.split('\n') {
        let line = trim(raw);
        if let Some(name) = line.strip_prefix("#!name=") {
            spec.name = fill(trim(name), &args);
        }
        if let Some(desc) = line.strip_prefix("#!desc=") {
            spec.description = fill(trim(desc), &args);
        }
        if line.is_empty()
            || line.starts_with('#')
            || line.starts_with(';')
            || line.starts_with("//")
        {
            continue;
        }
        if line.starts_with('[') && line.ends_with(']') && line.len() >= 2 {
            section = to_lower_case(trim(&line[1..line.len() - 1]));
            continue;
        }
        let line = fill(line, &args);
        section_line(&section, &line, &mut spec);
    }
    let meta = |k: &str| {
        meta.iter()
            .find(|(key, _)| key == k)
            .map(|(_, v)| v.clone())
            .unwrap_or_default()
    };
    spec.arguments_help = meta("arguments-desc").replace("\\n", "\n");
    spec.author = meta("author");
    spec.homepage = meta("homepage");
    spec.icon = meta("icon");
    spec.category = meta("category");
    spec.systems = meta("system")
        .split(',')
        .map(trim)
        .filter(|x| !x.is_empty())
        .map(to_lower_case)
        .collect();
    spec.open_url = meta("openurl");
    spec.to_json()
}

/// One filled line of `section`.
fn section_line(section: &str, line: &str, spec: &mut Spec) {
    match section {
        // Quantumult X keeps its hostnames under [mitm] too, same syntax.
        "mitm" => {
            if let Some(i) = line.find('=').filter(|&i| i > 0) {
                if to_lower_case(trim(&line[..i])) == "hostname" {
                    add_hosts(&line[i + 1..], &mut spec.hostnames, &mut spec.excluded);
                }
            }
        }
        "script" => {
            let n = spec.scripts.len();
            if let Some(s) = surge_script(line).or_else(|| loon_script(line, n)) {
                spec.scripts.push(s);
            }
        }
        "task_local" => {
            // Quantumult X: `0 8 * * * https://…/x.js, tag=…, enabled=true`.
            let parts = split_args(line);
            let Some(first) = parts.first() else {
                return;
            };
            let head = words(first);
            if head.len() >= 6 && parts[1..].iter().all(|p| p.contains('=')) {
                let o = key_values(&parts[1..]);
                if kv(&o, "enabled") != Some("false") {
                    let name = kv(&o, "tag")
                        .map_or_else(|| format!("task{}", spec.scripts.len() + 1), str::to_owned);
                    let mut s =
                        Script::new(name, false, String::new(), head[head.len() - 1].clone());
                    s.cron = Some(head[..head.len() - 1].join(" "));
                    spec.scripts.push(s);
                }
            }
        }
        "url rewrite" | "rewrite" => spec.rewrites.extend(url_rewrite(line)),
        "header rewrite" => spec.rewrites.extend(header_rewrite(line)),
        "map local" => spec.rewrites.extend(map_local(line)),
        "body rewrite" => spec.rewrites.extend(body_rewrite(line)),
        "rewrite_local" => qx_rewrite(line, spec),
        "rule" | "filter_local" => spec.rules.extend(rule(line)),
        _ => {}
    }
}

/// Quantumult X `^pattern url <action> …`.
fn qx_rewrite(line: &str, spec: &mut Spec) {
    let parts = words(line);
    if parts.len() < 3 || parts[1] != "url" {
        return;
    }
    let (pattern, action) = (parts[0].as_str(), parts[2].as_str());
    if let Some(k) = reject_kind(action) {
        spec.rewrites.push(Rewrite::reject(pattern, k));
    } else if (action == "302" || action == "307") && parts.len() >= 4 {
        let status = if action == "302" { 302 } else { 307 };
        spec.rewrites.push(redirect(pattern, &parts[3], status));
    } else if (action == "request-header" || action == "response-header") && parts.len() >= 5 {
        // Regex over the whole header block: per header line here.
        let mut r = Rewrite::new(
            pattern,
            obj([
                ("op", "header".into()),
                (
                    "ops",
                    Value::Array(vec![strings(&["block-regex", "", &parts[3], &parts[4]])]),
                ),
            ]),
        );
        r.response = action == "response-header";
        spec.rewrites.push(r);
    } else if (action == "request-body" || action == "response-body") && parts.len() >= 6 {
        let mut r = Rewrite::new(
            pattern,
            obj([
                ("op", "body".into()),
                (
                    "pairs",
                    Value::Array(vec![strings(&[&parts[3], &parts[5]])]),
                ),
            ]),
        );
        r.response = action == "response-body";
        r.needs_body = true;
        spec.rewrites.push(r);
    } else if action == "echo-response" && parts.len() >= 5 {
        let mut headers = Map::new();
        headers.insert("Content-Type".into(), parts[3].clone().into());
        spec.rewrites.push(Rewrite::new(
            pattern,
            obj([
                ("op", "local".into()),
                ("status", 200.into()),
                ("headers", Value::Object(headers)),
                ("dataUrl", parts[parts.len() - 1].clone().into()),
            ]),
        ));
    } else if parts.len() >= 4 && action.starts_with("script-") {
        let response =
            action.starts_with("script-response") || action == "script-analyze-echo-response";
        let mut s = Script::new(
            format!("script{}", spec.scripts.len() + 1),
            response,
            pattern.to_owned(),
            parts[3].clone(),
        );
        s.requires_body = action.ends_with("-body");
        spec.scripts.push(s);
    }
}

fn add_hosts(list: &str, hosts: &mut Vec<String>, excluded: &mut Vec<String>) {
    for h in list
        .replace("%APPEND%", "")
        .replace("%INSERT%", "")
        .split(',')
    {
        let host = trim(h);
        if host.is_empty() {
            continue;
        }
        if let Some(x) = host.strip_prefix('-') {
            let x = trim(x);
            if !x.is_empty() && !excluded.iter().any(|e| e == x) {
                excluded.push(x.to_owned());
            }
        } else if !hosts.iter().any(|e| e == host) {
            hosts.push(host.to_owned());
        }
    }
}

fn redirect(pattern: &str, to: &str, status: i64) -> Rewrite {
    Rewrite::new(
        pattern,
        obj([
            ("op", "redirect".into()),
            ("from", pattern.into()),
            ("to", to.into()),
            ("status", status.into()),
        ]),
    )
}

fn header_ops(ops: Vec<Value>) -> Map<String, Value> {
    obj([("op", "header".into()), ("ops", Value::Array(ops))])
}

/// Surge `^pattern replacement 302|307|header|reject…`, Loon the same plus
/// `header-add|del|replace`, `mock-response-body`, `…-body-replace-regex`.
fn url_rewrite(line: &str) -> Option<Rewrite> {
    let w = words(line);
    if w.len() < 2 {
        return None;
    }
    let pattern = w[0].as_str();
    if let Some(k) = reject_kind(&w[w.len() - 1]).filter(|_| w.len() <= 3) {
        return Some(Rewrite::reject(pattern, k));
    }
    if w.len() >= 3 {
        match to_lower_case(&w[2]).as_str() {
            "302" => return Some(redirect(pattern, &w[1], 302)),
            "307" => return Some(redirect(pattern, &w[1], 307)),
            "header" => {
                return Some(Rewrite::new(
                    pattern,
                    obj([
                        ("op", "url".into()),
                        ("from", pattern.into()),
                        ("to", w[1].clone().into()),
                    ]),
                ))
            }
            _ => {}
        }
    }
    let rest = |from: usize| {
        if w.len() > from {
            w[from..].join(" ")
        } else {
            String::new()
        }
    };
    match to_lower_case(&w[1]).as_str() {
        s @ ("302" | "307") if w.len() >= 3 => {
            Some(redirect(pattern, &w[2], if s == "302" { 302 } else { 307 }))
        }
        "header-add" | "header-del" | "header-replace" if w.len() >= 3 => Some(Rewrite::new(
            pattern,
            header_ops(vec![strings(&[&w[1][7..], &w[2], &rest(3)])]),
        )),
        "response-header-add" | "response-header-del" | "response-header-replace"
            if w.len() >= 3 =>
        {
            let mut r = Rewrite::new(
                pattern,
                header_ops(vec![strings(&[&w[1][16..], &w[2], &rest(3)])]),
            );
            r.response = true;
            Some(r)
        }
        "mock-response-body" => Some(local(pattern, &key_values(&w[2..]))),
        "response-body-replace-regex" | "request-body-replace-regex" if w.len() >= 4 => {
            let mut r = Rewrite::new(pattern, body_pairs(&w[2..]));
            r.response = to_lower_case(&w[1]).starts_with("response");
            r.needs_body = true;
            Some(r)
        }
        _ => None,
    }
}

/// `{op: body, pairs: [[regex, replacement] …]}` from `w` two by two.
fn body_pairs(w: &[String]) -> Map<String, Value> {
    let pairs: Vec<Value> = w
        .as_chunks::<2>()
        .0
        .iter()
        .map(|[a, b]| strings(&[a, b]))
        .collect();
    obj([("op", "body".into()), ("pairs", Value::Array(pairs))])
}

/// Surge `http-request|http-response ^pattern header-add|del|replace|
/// replace-regex name [value] [with]`; the old form without the type means
/// requests.
fn header_rewrite(line: &str) -> Option<Rewrite> {
    let mut w = words(line);
    let mut response = false;
    if w.first()
        .is_some_and(|f| f == "http-request" || f == "http-response")
    {
        response = w[0] == "http-response";
        w.remove(0);
    }
    if w.len() < 3 || !w[1].starts_with("header-") {
        return None;
    }
    let op = &w[1][7..];
    if !matches!(op, "add" | "del" | "replace" | "replace-regex") {
        return None;
    }
    let value = w.get(3).cloned().unwrap_or_default();
    let with = if w.len() > 4 {
        w[4..].join(" ")
    } else {
        String::new()
    };
    let mut r = Rewrite::new(
        &w[0],
        header_ops(vec![strings(&[op, &w[2], &value, &with])]),
    );
    r.response = response;
    Some(r)
}

/// Surge `^pattern data-type=… data="…" status-code=200 header="A:b|C:d"`.
fn map_local(line: &str) -> Option<Rewrite> {
    let w = words(line);
    if w.len() < 2 {
        return None;
    }
    Some(local(&w[0], &key_values(&w[1..])))
}

fn local(pattern: &str, o: &Map<String, Value>) -> Rewrite {
    let kind = to_lower_case(kv(o, "data-type").unwrap_or("text"));
    let data = kv(o, "data").unwrap_or("");
    let mut headers = Map::new();
    for h in kv(o, "header").unwrap_or("").split('|') {
        if let Some(i) = h.find(':').filter(|&i| i > 0) {
            headers.insert(
                trim(&h[..i]).to_owned(),
                trim(&h[i + 1..]).to_owned().into(),
            );
        }
    }
    if !headers.contains_key("Content-Type") {
        let t = match kind.as_str() {
            "json" => "application/json",
            "tiny-gif" => "image/gif",
            _ => "text/plain",
        };
        headers.insert("Content-Type".into(), t.into());
    }
    let is_url = data.starts_with("http://") || data.starts_with("https://");
    let (k, v) = if kind == "tiny-gif" {
        ("base64", TINY_GIF)
    } else if is_url {
        ("dataUrl", data)
    } else if kind == "base64" {
        ("base64", data)
    } else {
        ("text", data)
    };
    Rewrite::new(
        pattern,
        obj([
            ("op", "local".into()),
            ("status", int_or(kv(o, "status-code"), 200).into()),
            ("headers", Value::Object(headers)),
            (k, v.into()),
        ]),
    )
}

/// Surge `http-request|http-response ^pattern regex replacement […]`.
fn body_rewrite(line: &str) -> Option<Rewrite> {
    let w = words(line);
    if w.len() < 4 || (w[0] != "http-request" && w[0] != "http-response") {
        return None;
    }
    let mut r = Rewrite::new(&w[1], body_pairs(&w[2..]));
    r.response = w[0] == "http-response";
    r.needs_body = true;
    Some(r)
}

/// Surge `name = type=http-response, pattern=…, script-path=…, …`.
fn surge_script(line: &str) -> Option<Script> {
    let eq = line.find('=').filter(|&i| i > 0)?;
    let o = key_values(&split_args(&line[eq + 1..]));
    let path = kv(&o, "script-path")?;
    if kv(&o, "enable") == Some("false") {
        return None;
    }
    let name = trim(&line[..eq]).to_owned();
    let kind = kv(&o, "type");
    let mut s = if kind == Some("cron") {
        let cron = kv(&o, "cronexp").or_else(|| kv(&o, "cron"))?;
        let mut s = Script::new(name, false, String::new(), path.to_owned());
        s.cron = Some(cron.to_owned());
        s.timeout = int_or(kv(&o, "timeout"), 30);
        s
    } else {
        if kind != Some("http-response") && kind != Some("http-request") {
            return None;
        }
        let pattern = kv(&o, "pattern")?;
        let mut s = Script::new(
            name,
            kind == Some("http-response"),
            pattern.to_owned(),
            path.to_owned(),
        );
        s.binary_body = truthy(kv(&o, "binary-body-mode"));
        s.requires_body = truthy(kv(&o, "requires-body"));
        s.timeout = int_or(kv(&o, "timeout"), 10);
        s
    };
    s.argument = kv(&o, "argument").unwrap_or("").to_owned();
    s.argument_object = truthy(kv(&o, "argument-object"));
    Some(s)
}

/// `^cron\s+"([^"]+)"\s+(.*)$`: the expression and the rest.
fn cron_line(line: &str) -> Option<(&str, &str)> {
    let rest = line.strip_prefix("cron")?;
    let i = skip_spaces(rest, 0);
    if i == 0 {
        return None;
    }
    let quoted = rest[i..].strip_prefix('"')?;
    let close = quoted.find('"').filter(|&n| n > 0)?;
    let after = &quoted[close + 1..];
    let j = skip_spaces(after, 0);
    if j == 0 || after.chars().any(is_line_end) {
        return None;
    }
    Some((&quoted[..close], &after[j..]))
}

/// `^(http-response|http-request)\s+(\S+)\s+(.*)$`.
fn loon_head(line: &str) -> Option<(&str, &str, &str)> {
    let (kind, rest) = ["http-response", "http-request"]
        .into_iter()
        .find_map(|k| line.strip_prefix(k).map(|r| (k, r)))?;
    let i = skip_spaces(rest, 0);
    if i == 0 {
        return None;
    }
    let p = &rest[i..];
    let end = p
        .char_indices()
        .find(|&(_, c)| is_regex_space(c))
        .map_or(p.len(), |(n, _)| n);
    if end == 0 {
        return None;
    }
    let j = skip_spaces(p, end);
    if j == end || p[j..].chars().any(is_line_end) {
        return None;
    }
    Some((kind, &p[..end], &p[j..]))
}

/// Loon `http-response ^pattern script-path=…, requires-body=true, tag=…`
/// and `cron "0 8 * * *" script-path=…`.
fn loon_script(line: &str, n: usize) -> Option<Script> {
    if let Some((cron, rest)) = cron_line(line) {
        let o = key_values(&split_args(rest));
        let path = kv(&o, "script-path")?;
        if kv(&o, "enable") == Some("false") {
            return None;
        }
        let name = kv(&o, "tag").map_or_else(|| format!("cron{}", n + 1), str::to_owned);
        let mut s = Script::new(name, false, String::new(), path.to_owned());
        s.cron = Some(cron.to_owned());
        s.argument = kv(&o, "argument").unwrap_or("").to_owned();
        s.argument_object = truthy(kv(&o, "argument-object"));
        s.timeout = int_or(kv(&o, "timeout"), 30);
        return Some(s);
    }
    let (kind, pattern, rest) = loon_head(line)?;
    let o = key_values(&split_args(rest));
    let path = kv(&o, "script-path")?;
    if kv(&o, "enable") == Some("false") {
        return None;
    }
    let name = kv(&o, "tag").map_or_else(|| format!("script{}", n + 1), str::to_owned);
    let mut s = Script::new(
        name,
        kind == "http-response",
        pattern.to_owned(),
        path.to_owned(),
    );
    s.argument_object = truthy(kv(&o, "argument-object"));
    s.argument = kv(&o, "argument").unwrap_or("").to_owned();
    s.binary_body = truthy(kv(&o, "binary-body-mode"));
    s.requires_body = truthy(kv(&o, "requires-body"));
    s.timeout = int_or(kv(&o, "timeout"), 10);
    Some(s)
}

// ---------------------------------------------------------------- Stash

/// The lines of `text` as a multi-line Dart regular expression sees them
/// (`^` after `\n`, `\r`, U+2028, U+2029).
fn regex_lines(text: &str) -> impl Iterator<Item = &str> {
    text.split(is_line_end)
}

fn looks_like_stash(text: &str) -> bool {
    let t = text.trim_start_matches(crate::dart::is_dart_space);
    let mut bracket = false;
    let mut key = false;
    for l in regex_lines(t) {
        bracket |= l.starts_with('[');
        key |= ["http", "script-providers", "name", "rules", "cron"]
            .iter()
            .any(|k| l.strip_prefix(k).is_some_and(|r| r.starts_with(':')));
    }
    !bracket && key
}

/// A list's items; anything else none (Dart would throw on the cast).
fn items(v: &Dv) -> &[Dv] {
    match v {
        Dv::List(l) => l,
        _ => &[],
    }
}

fn or_str(v: &Dv, or: &str) -> String {
    if v.is_null() {
        or.to_owned()
    } else {
        v.dart_string()
    }
}

fn num_or(v: &Dv, or: i64) -> i64 {
    v.as_int_opt().ok().flatten().unwrap_or(or)
}

/// The provider `name`'s `url` (`script-providers: {name: {url}}`).
fn provider_url(providers: &Dv, name: &str) -> String {
    match providers.get(name) {
        p @ Dv::Map(_) => or_str(p.get("url"), ""),
        _ => String::new(),
    }
}

/// Stash override: `http: {mitm, url-rewrite, header-rewrite, script}`,
/// `script-providers: {name: {url}}`, `cron: {script}`, `rules`.
fn parse_stash(text: &str, fallback: &str) -> Spec {
    let named = || Spec {
        name: fallback.to_owned(),
        ..Spec::default()
    };
    let Ok(doc) = super::yaml::load_keeping_text(text, &[]) else {
        return named();
    };
    if !matches!(doc, Dv::Map(_)) {
        return named();
    }
    let map_or_empty = |v: &Dv| match v {
        Dv::Map(_) => v.clone(),
        _ => Dv::Map(Vec::new()),
    };
    let http = map_or_empty(doc.get("http"));
    let providers = map_or_empty(doc.get("script-providers"));
    let mut spec = Spec {
        icon: or_str(doc.get("icon"), ""),
        name: or_str(doc.get("name"), fallback),
        description: or_str(doc.get("desc"), ""),
        ..Spec::default()
    };
    for h in items(http.get("mitm")) {
        add_hosts(&h.dart_string(), &mut spec.hostnames, &mut spec.excluded);
    }
    for r in items(http.get("url-rewrite")) {
        spec.rewrites.extend(url_rewrite(&r.dart_string()));
    }
    for r in items(http.get("header-rewrite")) {
        spec.rewrites.extend(header_rewrite(&r.dart_string()));
    }
    for s in items(http.get("script")) {
        if !matches!(s, Dv::Map(_)) {
            continue;
        }
        let name = or_str(s.get("name"), &format!("script{}", spec.scripts.len() + 1));
        let url = provider_url(&providers, &name);
        if url.is_empty() || s.get("match").is_null() {
            continue;
        }
        let mut script = Script::new(
            name,
            s.get("type").dart_string() == "response",
            s.get("match").dart_string(),
            url,
        );
        script.argument = or_str(s.get("argument"), "");
        script.binary_body = *s.get("binary-mode") == Dv::Bool(true);
        script.requires_body = *s.get("require-body") == Dv::Bool(true);
        script.timeout = num_or(s.get("timeout"), 10);
        spec.scripts.push(script);
    }
    let cron = map_or_empty(doc.get("cron"));
    for s in items(cron.get("script")) {
        if !matches!(s, Dv::Map(_)) || s.get("cron").is_null() {
            continue;
        }
        let name = or_str(s.get("name"), &format!("cron{}", spec.scripts.len() + 1));
        let url = provider_url(&providers, &name);
        if url.is_empty() {
            continue;
        }
        let mut script = Script::new(name, false, String::new(), url);
        script.cron = Some(s.get("cron").dart_string());
        script.argument = or_str(s.get("argument"), "");
        script.timeout = num_or(s.get("timeout"), 30);
        spec.scripts.push(script);
    }
    for r in items(doc.get("rules")) {
        spec.rules.extend(rule(&r.dart_string()));
    }
    spec
}

// ---------------------------------------------------------------- rules

const RULE_TYPES: [&str; 12] = [
    "DOMAIN",
    "DOMAIN-SUFFIX",
    "DOMAIN-KEYWORD",
    "DOMAIN-WILDCARD",
    "DOMAIN-REGEX",
    "IP-CIDR",
    "IP-CIDR6",
    "GEOIP",
    "IP-ASN",
    "DST-PORT",
    "PROCESS-NAME",
    "USER-AGENT",
];

/// A plain rule with a DIRECT / REJECT / PROXY target, Clash spelling.
fn rule(line: &str) -> Option<String> {
    let parts: Vec<&str> = line.split(',').map(trim).collect();
    if parts.len() < 3 {
        return None;
    }
    let kind = match to_lower_case(parts[0]).as_str() {
        "host" => "DOMAIN".to_owned(),
        "host-suffix" => "DOMAIN-SUFFIX".to_owned(),
        "host-keyword" => "DOMAIN-KEYWORD".to_owned(),
        "host-wildcard" => "DOMAIN-WILDCARD".to_owned(),
        "ip-cidr" => "IP-CIDR".to_owned(),
        "ip6-cidr" => "IP-CIDR6".to_owned(),
        "geoip" => "GEOIP".to_owned(),
        _ => parts[0].to_uppercase(),
    };
    if !RULE_TYPES.contains(&kind.as_str()) {
        return None;
    }
    let target = match to_lower_case(parts[2]).as_str() {
        "direct" => "DIRECT",
        "proxy" => "PROXY",
        t if reject_kind(t).is_some() => "REJECT",
        _ => return None,
    };
    let mut out = vec![kind.as_str(), parts[1], target];
    out.extend(parts[3..].iter().filter(|o| **o == "no-resolve"));
    Some(out.join(","))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn parse(text: &str) -> Value {
        parse_module(text, "fallback", &[])
    }

    #[test]
    fn a_surge_module_with_everything() {
        let text = r#"#!name=Ads {{{mode}}}
#!desc=Removes ads
#!arguments=mode:fast,debug:false
#!arguments-desc=Pick a mode\nthen go
#!author=me
#!system=ios, Mac
#!category=x

[Rule]
DOMAIN-SUFFIX,ads.example.com,REJECT
host,a.example.com,direct
GEOIP,CN,whatever
IP-CIDR,1.2.3.0/24,reject-dict,no-resolve,extra

[URL Rewrite]
^https://a\.com/ads - reject
^https://b\.com/(.*) https://c.com/$1 302
^https://d\.com header-add X-A "a b"

[Header Rewrite]
http-response ^https://e\.com header-replace Cache-Control no-cache

[Map Local]
^https://f\.com/x data-type=json data="{}" status-code=201 header="A:b|C:d"
^https://f\.com/y data-type=tiny-gif

[Body Rewrite]
http-response ^https://g\.com a b c d

[Script]
Ad = type=http-response, pattern=^https://h\.com, script-path=ad.js, requires-body=1, argument=m={{{mode}}}
Daily = type=cron, cronexp="0 8 * * *", script-path=daily.js
Off = type=http-request, pattern=x, script-path=off.js, enable=false

[MITM]
hostname = %APPEND% h.com, *.i.com, -j.i.com, h.com
"#;
        let v = parse(text);
        assert_eq!(v["name"], "Ads fast");
        assert_eq!(v["desc"], "Removes ads");
        assert_eq!(v["argumentsHelp"], "Pick a mode\nthen go");
        assert_eq!(v["systems"], json!(["ios", "mac"]));
        assert_eq!(
            v["arguments"],
            json!([
                {"key": "mode", "kind": "input", "default": "fast"},
                {"key": "debug", "kind": "toggle", "default": "false"},
            ])
        );
        assert_eq!(
            v["rules"],
            json!([
                "DOMAIN-SUFFIX,ads.example.com,REJECT",
                "DOMAIN,a.example.com,DIRECT",
                "IP-CIDR,1.2.3.0/24,REJECT,no-resolve"
            ])
        );
        assert_eq!(v["hostnames"], json!(["h.com", "*.i.com"]));
        assert_eq!(v["excluded"], json!(["j.i.com"]));
        let rw = v["rewrites"].as_array().unwrap();
        assert_eq!(
            rw[0],
            json!({"pattern": "^https://a\\.com/ads", "action": {"op": "reject", "kind": "plain"}})
        );
        assert_eq!(
            rw[1]["action"],
            json!({"op": "redirect", "from": "^https://b\\.com/(.*)", "to": "https://c.com/$1", "status": 302})
        );
        assert_eq!(
            rw[2]["action"],
            json!({"op": "header", "ops": [["add", "X-A", "a b"]]})
        );
        assert_eq!(
            rw[3],
            json!({"pattern": "^https://e\\.com", "action": {"op": "header",
                "ops": [["replace", "Cache-Control", "no-cache", ""]]}, "response": true})
        );
        assert_eq!(
            rw[4]["action"],
            json!({"op": "local", "status": 201, "headers": {"A": "b", "C": "d",
                "Content-Type": "application/json"}, "text": "{}"})
        );
        assert_eq!(rw[5]["action"]["base64"], TINY_GIF);
        assert_eq!(
            rw[6],
            json!({"pattern": "^https://g\\.com", "action": {"op": "body",
                "pairs": [["a", "b"], ["c", "d"]]}, "response": true, "body": true})
        );
        assert_eq!(
            v["scripts"],
            json!([
                {"name": "Ad", "response": true, "pattern": "^https://h\\.com", "url": "ad.js",
                 "argument": "m=fast", "body": true, "timeout": 10},
                {"name": "Daily", "response": false, "pattern": "", "url": "daily.js",
                 "timeout": 30, "cron": "0 8 * * *"},
            ])
        );
        // Keys in Dart's order.
        let keys: Vec<&String> = v.as_object().unwrap().keys().collect();
        assert_eq!(
            keys,
            [
                "name",
                "desc",
                "scripts",
                "rewrites",
                "hostnames",
                "excluded",
                "rules",
                "arguments",
                "argumentsHelp",
                "author",
                "category",
                "systems"
            ]
        );
    }

    #[test]
    fn user_values_fill_the_arguments() {
        let text = "#!arguments=mode:fast\n[Script]\nA = type=http-request, pattern=x, script-path=a.js, argument={{{mode}}}\n";
        let v = parse_module(
            text,
            "f",
            &[("mode".into(), "slow".into()), ("other".into(), "x".into())],
        );
        assert_eq!(v["scripts"][0]["argument"], "slow");
        assert_eq!(v["name"], "f");
    }

    #[test]
    fn loon_plugins_and_their_arguments() {
        let text = r#"#!name=Loon
[Argument]
token = input,"abc",tag=Token,desc=Your token
on = switch,true,tag=On
pick = select,"a","b",tag=Pick

[Script]
http-response ^https://x\.com script-path=https://s/x.js, requires-body=true, tag=X, argument=[{token},{on}]
cron "0 9 * * *" script-path=c.js, tag=Daily
http-request ^https://y\.com script-path=y.js, enable=false

[Rewrite]
^https://z\.com reject-200
^https://w\.com response-header-del Set-Cookie
^https://v\.com mock-response-body data-type=text data="hi"
^https://u\.com response-body-replace-regex a b
^https://t\.com/{token} 302 https://t2.com/{on}/{nope}
"#;
        let v = parse(text);
        assert_eq!(
            v["arguments"],
            json!([
                {"key": "token", "label": "Token", "kind": "input", "default": "abc", "help": "Your token"},
                {"key": "on", "label": "On", "kind": "toggle", "default": "true"},
                {"key": "pick", "label": "Pick", "kind": "choice", "default": "a", "options": ["a", "b"]},
            ])
        );
        let s = &v["scripts"];
        assert_eq!(s[0]["name"], "X");
        assert_eq!(s[0]["argument"], r#"{"token":"abc","on":"true"}"#);
        assert_eq!(s[0]["argObject"], true);
        assert_eq!(s[0]["body"], true);
        assert_eq!(
            s[1],
            json!({"name": "Daily", "response": false, "pattern": "", "url": "c.js",
                   "timeout": 30, "cron": "0 9 * * *"})
        );
        assert_eq!(s.as_array().unwrap().len(), 2);
        let rw = &v["rewrites"];
        assert_eq!(rw[0]["action"], json!({"op": "reject", "kind": "empty"}));
        assert_eq!(
            rw[1],
            json!({"pattern": "^https://w\\.com", "action": {"op": "header",
                "ops": [["del", "Set-Cookie", ""]]}, "response": true})
        );
        assert_eq!(
            rw[2]["action"],
            json!({"op": "local", "status": 200, "headers": {"Content-Type": "text/plain"}, "text": "hi"})
        );
        assert_eq!(rw[3]["response"], true);
        assert_eq!(rw[4]["pattern"], "^https://t\\.com/abc");
        assert_eq!(rw[4]["action"]["to"], "https://t2.com/true/{nope}");
    }

    #[test]
    fn quantumult_x_snippets() {
        let text = r#"[rewrite_local]
^https://a\.com url reject-img
^https://b\.com url 307 https://c.com
^https://d\.com url response-header (\r\n)X:1 $1X:2
^https://e\.com url response-body a response-body b
^https://f\.com url echo-response text/html https://data/x.html
^https://g\.com url script-response-body https://s/g.js
^https://h\.com url script-request-header h.js

[task_local]
0 8 * * * https://s/t.js, tag=Morning, enabled=true
0 9 * * * https://s/off.js, enabled=false

[filter_local]
host-suffix,q.com,proxy

[mitm]
hostname = a.com, b.com
"#;
        let v = parse(text);
        let rw = &v["rewrites"];
        assert_eq!(rw[0]["action"]["kind"], "image");
        assert_eq!(rw[1]["action"]["status"], 307);
        assert_eq!(
            rw[2]["action"]["ops"],
            json!([["block-regex", "", "(\\r\\n)X:1", "$1X:2"]])
        );
        assert_eq!(rw[3]["action"]["pairs"], json!([["a", "b"]]));
        assert_eq!(rw[4]["action"]["dataUrl"], "https://data/x.html");
        let s = &v["scripts"];
        assert_eq!(s[0]["response"], true);
        assert_eq!(s[0]["body"], true);
        assert_eq!(s[1]["response"], false);
        assert_eq!(s[1]["name"], "script2");
        assert_eq!(s[2]["name"], "Morning");
        assert_eq!(s[2]["cron"], "0 8 * * *");
        assert_eq!(s.as_array().unwrap().len(), 3);
        assert_eq!(v["rules"], json!(["DOMAIN-SUFFIX,q.com,PROXY"]));
        assert_eq!(v["hostnames"], json!(["a.com", "b.com"]));
    }

    #[test]
    fn stash_overrides() {
        let text = r#"name: Stash One
desc: d
http:
  mitm:
    - "a.com"
    - "-b.com"
  url-rewrite:
    - ^https://x\.com - reject
  script:
    - match: ^https://y\.com
      name: y
      type: response
      require-body: true
      timeout: 20
    - match: ^https://z\.com
      name: unknown
script-providers:
  y:
    url: https://s/y.js
  d:
    url: https://s/d.js
cron:
  script:
    - name: d
      cron: "0 8 * * *"
rules:
  - DOMAIN,r.com,DIRECT
"#;
        let v = parse(text);
        assert_eq!(v["name"], "Stash One");
        assert_eq!(v["desc"], "d");
        assert_eq!(v["hostnames"], json!(["a.com"]));
        assert_eq!(v["excluded"], json!(["b.com"]));
        assert_eq!(v["rewrites"][0]["action"]["op"], "reject");
        assert_eq!(
            v["scripts"],
            json!([
                {"name": "y", "response": true, "pattern": "^https://y\\.com", "url": "https://s/y.js",
                 "body": true, "timeout": 20},
                {"name": "d", "response": false, "pattern": "", "url": "https://s/d.js",
                 "timeout": 30, "cron": "0 8 * * *"},
            ])
        );
        assert_eq!(v["rules"], json!(["DOMAIN,r.com,DIRECT"]));
        // Not YAML: the fallback name alone.
        assert_eq!(
            parse("name: [unclosed\nrules:\n"),
            json!({"name": "fallback", "scripts": [], "rewrites": [], "hostnames": [], "rules": []})
        );
    }

    #[test]
    fn words_and_args_split_like_dart() {
        assert_eq!(
            words(r#"a "b c" k="d e" "x"y z"#),
            ["a", "b c", "k=d e", "\"x\"y", "z"]
        );
        assert_eq!(
            words(r#"^x header-add A "v \"q\"""#),
            ["^x", "header-add", "A", "v \"q\""]
        );
        assert_eq!(split_args(r#" a , "b,c" ,d"#), ["a", "b,c", "d"]);
        assert_eq!(split_args(","), [""]);
        assert!(split_args("\"\"").is_empty());
    }

    #[test]
    fn the_fallback_name() {
        assert_eq!(
            fallback_name("https://h.example/a/b.sgmodule"),
            "b.sgmodule"
        );
        assert_eq!(fallback_name("https://h.example/a/"), "");
        assert_eq!(fallback_name("https://H.example"), "h.example");
    }
}
