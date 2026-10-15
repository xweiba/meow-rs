//! A subscription refreshed the way the app refreshes it (Dart
//! `ProxyController._refresh` and `_fetch`), and what that gives merged into
//! the build input as the app's `configInput()` would hand it on. No IO and
//! no clock: the caller downloads and says what time it is.
//!
//! - [`refresh`]: the downloads one refresh makes (directly, through the
//!   core's port when that gets no answer, once more with a last `/` on a
//!   404) and what they come to: fresh lines or the app's sentence for the
//!   problem.
//! - [`Refreshed`]: what is kept of the last refresh of a subscription (the
//!   core's `paopao/subscriptions/<id>.json`).
//! - [`merge_refreshed`] / [`merge_into_input`]: the subscription after
//!   that refresh, the fields `_refresh` sets, in `Subscription.toJson`'s
//!   order without `updated`.

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use crate::dart::Dv;
use crate::model::node::ProxyNode;
use crate::model::subscription::SubRules;
use crate::model::usage::Usage;

/// No answer directly, the core off or not asked (Dart `_refresh`).
pub const UNREACHABLE: &str = "无法连接订阅地址，请检查网络后重试";
/// No answer directly nor through the core's port.
pub const UNREACHABLE_PROXY_TOO: &str = "无法连接订阅地址，经代理也无法连接，请检查网络后重试";
/// 404 / 403.
pub const GONE: &str = "订阅已失效，请向机场索取新的订阅链接";
/// 200, but no subscription the parser knows.
pub const UNREADABLE: &str = "订阅内容无法识别";
/// Entries, none of them usable.
pub const UNSUPPORTED: &str = "订阅中的节点暂不支持";
/// Nothing at all.
pub const NO_NODES: &str = "订阅中没有节点";

/// Any other status than 200, 404 and 403.
pub fn server_error(status: u16) -> String {
    format!("订阅服务器出错（{status}），请稍后再试")
}

/// One download of a subscription, as far as a refresh tells answers apart.
#[derive(Debug, Clone, PartialEq)]
pub enum Download {
    /// Could not connect, timed out (Dart: an `IOException` or a
    /// `TimeoutException`): worth trying through the core's port.
    NoAnswer,
    /// Not an address to download (Dart: anything else thrown); the
    /// core's port would not help.
    Unusable,
    /// An answer, not 200.
    Status(u16),
    /// 200, parsed: what `paopao_parse` returns with `usage` the
    /// `subscription-userinfo` header's when it has one, plus
    /// `content_disposition` and `body_sha` (the `meow paopao fetch`
    /// child's answer).
    Parsed(Value),
    /// 200, but the parser could not read it.
    Unreadable,
}

impl Download {
    fn is_200(&self) -> bool {
        matches!(self, Self::Parsed(_) | Self::Unreadable)
    }
}

/// How a download went.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Via {
    Direct,
    /// Through the core's own port.
    Proxy,
}

/// What a subscription's fresh download gave.
#[derive(Debug, Clone, PartialEq)]
pub struct Fresh {
    /// `{name, outbound}`, unsupported ones left out (Dart
    /// `ProxyNode.fromJson`).
    pub nodes: Vec<Value>,
    pub skipped: i64,
    /// [`SubRules`] as JSON; null when empty.
    pub split: Value,
    /// The header's, else what the node names say; None = unknown.
    pub usage: Option<Value>,
    /// What the provider calls the file (`Content-Disposition`), without
    /// its `.yaml` / `.txt` / `.json`.
    pub file_name: Option<String>,
    /// SHA-256 of the body, hex.
    pub body_sha: Option<String>,
}

/// One refresh: where the subscription is now (a 404 may have moved it to
/// the address with a last `/`), how the download that counted went, and
/// what came of it.
#[derive(Debug, Clone, PartialEq)]
pub struct Attempt {
    pub url: String,
    /// None when nothing answered.
    pub via: Option<Via>,
    /// Fresh lines, or the problem in the app's words.
    pub result: Result<Fresh, String>,
}

/// Refreshes the subscription at `url` as the app does: `download(url,
/// via)` directly first; when that gets no answer and `through_core` (the
/// core runs, with a port), once more through it. A 404 for an address
/// whose path does not end in `/` is tried once more with one, kept when
/// that answers 200 (some panels only answer `.../clash/`).
pub fn refresh(
    url: &str,
    through_core: bool,
    mut download: impl FnMut(&str, Via) -> Download,
) -> Attempt {
    let mut fetch = |url: &str| -> Result<(Download, Via), &'static str> {
        match download(url, Via::Direct) {
            Download::NoAnswer if through_core => match download(url, Via::Proxy) {
                Download::NoAnswer | Download::Unusable => Err(UNREACHABLE_PROXY_TOO),
                d => Ok((d, Via::Proxy)),
            },
            Download::NoAnswer | Download::Unusable => Err(UNREACHABLE),
            d => Ok((d, Via::Direct)),
        }
    };
    let mut url = url.to_owned();
    let (mut got, mut via) = match fetch(&url) {
        Ok(r) => r,
        Err(e) => {
            return Attempt {
                url,
                via: None,
                result: Err(e.into()),
            }
        }
    };
    if got == Download::Status(404) {
        if let Some(slash) = with_last_slash(&url) {
            if let Ok((again, v)) = fetch(&slash) {
                if again.is_200() {
                    (got, via) = (again, v);
                    url = slash;
                }
            }
        }
    }
    let result = match got {
        Download::Status(404 | 403) => Err(GONE.into()),
        Download::Status(s) => Err(server_error(s)),
        Download::Unreadable => Err(UNREADABLE.into()),
        Download::Parsed(v) => fresh(&v),
        // Taken care of by `fetch`.
        Download::NoAnswer | Download::Unusable => Err(UNREACHABLE.into()),
    };
    Attempt {
        url,
        via: Some(via),
        result,
    }
}

/// The lines of a parsed download; the app's sentence when there are none.
fn fresh(v: &Value) -> Result<Fresh, String> {
    let nodes: Vec<Value> = v
        .get("nodes")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(ProxyNode::from_json)
        .map(|n| n.to_json())
        .collect();
    let skipped = int_of(v.get("skipped")).unwrap_or(0);
    if nodes.is_empty() {
        return Err(if skipped > 0 { UNSUPPORTED } else { NO_NODES }.into());
    }
    let split = SubRules::from_json(v.get("split").unwrap_or(&Value::Null));
    Ok(Fresh {
        nodes,
        skipped,
        split: if split.is_empty() {
            Value::Null
        } else {
            serde_json::to_value(&split).unwrap_or(Value::Null)
        },
        usage: v
            .get("usage")
            .and_then(Usage::from_json)
            .map(|u| u.to_json()),
        file_name: v
            .get("content_disposition")
            .and_then(Value::as_str)
            .and_then(file_name_of),
        body_sha: v.get("body_sha").and_then(Value::as_str).map(str::to_owned),
    })
}

fn int_of(v: Option<&Value>) -> Option<i64> {
    v.and_then(|n| Dv::from_json(n).as_int_opt().ok().flatten())
}

/// `url` with a `/` after its path; None when the path is empty or already
/// ends in one (Dart `Uri.path`: after the authority, before `?` / `#`).
pub fn with_last_slash(url: &str) -> Option<String> {
    let after_scheme = url.find("://")? + 3;
    let rest = &url[after_scheme..];
    let path_at = after_scheme + rest.find(['/', '?', '#'])?;
    let path_end = path_at
        + url[path_at..]
            .find(['?', '#'])
            .unwrap_or(url.len() - path_at);
    let path = &url[path_at..path_end];
    if path.is_empty() || path.ends_with('/') {
        return None;
    }
    Some(format!("{}/{}", &url[..path_end], &url[path_end..]))
}

/// The provider's name for the file in a `Content-Disposition` header, as
/// the app reads it: the first `filename=` / `filename*=` (an optional
/// `UTF-8''`, optional quotes), percent-decoded, a `.yaml` / `.yml` /
/// `.txt` / `.json` ending taken off. None without one, or when it does not
/// decode (Dart's `Uri.decodeComponent` throws).
pub fn file_name_of(header: &str) -> Option<String> {
    let raw = disposition_file(header)?;
    let decoded = percent_decode(raw)?;
    for ext in [".yaml", ".yml", ".txt", ".json"] {
        if let Some(stem) = decoded.strip_suffix(ext) {
            return Some(stem.to_owned());
        }
    }
    Some(decoded)
}

/// `filename\*?=(?:UTF-8'')?"?([^";]+)`'s first match: group 1.
fn disposition_file(header: &str) -> Option<&str> {
    let value_at = |s: &str| s.find(['"', ';']).unwrap_or(s.len());
    let mut from = 0;
    while let Some(i) = header[from..].find("filename") {
        let at = from + i + "filename".len();
        from = at;
        let rest = &header[at..];
        let rest = rest.strip_prefix('*').unwrap_or(rest);
        let Some(rest) = rest.strip_prefix('=') else {
            continue;
        };
        // As the regex backtracks: with `UTF-8''` and the quote first.
        let utf8 = rest.strip_prefix("UTF-8''");
        for start in [utf8, Some(rest)].into_iter().flatten() {
            for s in [start.strip_prefix('"'), Some(start)].into_iter().flatten() {
                let n = value_at(s);
                if n > 0 {
                    return Some(&s[..n]);
                }
            }
        }
    }
    None
}

/// Dart `Uri.decodeComponent`: `%XX` to bytes, then UTF-8; None for a
/// broken escape, invalid UTF-8 or a character beyond ASCII among escapes.
fn percent_decode(s: &str) -> Option<String> {
    if !s.contains('%') && s.is_ascii() {
        return Some(s.to_owned());
    }
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'%' => {
                let hex = s.get(i + 1..i + 3)?;
                out.push(u8::from_str_radix(hex, 16).ok()?);
                i += 3;
            }
            c if c > 127 => return None,
            c => {
                out.push(c);
                i += 1;
            }
        }
    }
    String::from_utf8(out).ok()
}

/// What is kept of a subscription's last refresh (the core's
/// `paopao/subscriptions/<id>.json`): how it went and, from the last one
/// that worked, its lines. `nodes` comes last so a reader after the status
/// alone skips past them.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Refreshed {
    pub id: String,
    /// Where it was downloaded from (a 404 may have added a last `/`).
    pub url: String,
    /// The user agent asked for; None = the app's (`clash.meta`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user_agent: Option<String>,
    /// How the last download that answered went; None when none did.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub via: Option<Via>,
    /// When it was last tried, Unix ms.
    pub checked: i64,
    /// When it last worked, Unix ms.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub updated: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub usage: Option<Value>,
    /// The last try's problem in the app's words; None when it worked.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_error: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub body_sha: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub file_name: Option<String>,
    #[serde(default)]
    pub node_count: usize,
    #[serde(default)]
    pub skipped: i64,
    #[serde(default, skip_serializing_if = "Value::is_null")]
    pub split: Value,
    #[serde(default)]
    pub nodes: Vec<Value>,
}

impl Refreshed {
    /// The record of `attempt` at `now`; a failed one keeps what the
    /// `previous` record had from the last refresh that worked.
    pub fn record(
        id: &str,
        user_agent: Option<String>,
        attempt: Attempt,
        previous: Option<Self>,
        now: i64,
    ) -> Self {
        let base = Self {
            id: id.to_owned(),
            url: attempt.url,
            user_agent,
            via: attempt.via,
            checked: now,
            ..Self::default()
        };
        match attempt.result {
            Ok(f) => Self {
                updated: Some(now),
                usage: f.usage,
                body_sha: f.body_sha,
                file_name: f.file_name,
                node_count: f.nodes.len(),
                skipped: f.skipped,
                split: f.split,
                nodes: f.nodes,
                ..base
            },
            Err(e) => {
                let kept = previous.filter(|p| p.id == id).unwrap_or_default();
                Self {
                    last_error: Some(e),
                    updated: kept.updated,
                    usage: kept.usage,
                    body_sha: kept.body_sha,
                    file_name: kept.file_name,
                    node_count: kept.node_count,
                    skipped: kept.skipped,
                    split: kept.split,
                    nodes: kept.nodes,
                    ..base
                }
            }
        }
    }
}

/// The keys of Dart `Subscription.toJson`, in its order (`updated` is not
/// handed on).
const SUB_KEYS: [&str; 10] = [
    "id",
    "url",
    "name",
    "nodes",
    "skipped",
    "usage",
    "error",
    "split",
    "use_split",
    "named",
];

/// Subscription `sub` of the build input after the refresh `r` (Dart: the
/// fields `_refresh` sets): the address it answered at; when it worked, its
/// lines, skipped count, split and usage, no error, and the provider's
/// file name unless the user named it; when it failed, only the problem,
/// the old lines kept. Keys in `Subscription.toJson`'s order, others after.
pub fn merge_refreshed(sub: &Map<String, Value>, r: &Refreshed) -> Map<String, Value> {
    let mut m = sub.clone();
    m.insert("url".into(), r.url.clone().into());
    match &r.last_error {
        Some(e) => {
            m.insert("error".into(), e.clone().into());
        }
        None => {
            m.insert("nodes".into(), r.nodes.clone().into());
            m.insert("skipped".into(), r.skipped.into());
            match &r.usage {
                Some(u) => m.insert("usage".into(), u.clone()),
                None => m.remove("usage"),
            };
            m.remove("error");
            if r.split.is_null() {
                m.remove("split");
            } else {
                m.insert("split".into(), r.split.clone());
            }
            let named = m.get("named") == Some(&Value::Bool(true));
            if let (Some(name), false) = (&r.file_name, named) {
                m.insert("name".into(), name.clone().into());
            }
        }
    }
    let mut ordered = Map::new();
    for k in SUB_KEYS {
        if let Some(v) = m.remove(k) {
            ordered.insert(k.into(), v);
        }
    }
    ordered.extend(m);
    ordered
}

/// What a merge changed in the build input.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Change {
    /// Nothing (no such subscription, or the same as before).
    None,
    /// Only the problem shown: the config stays as it is.
    Error,
    /// The lines or what else the config is built from.
    Lines,
}

/// [`merge_refreshed`] on the build input's subscription `r.id`.
pub fn merge_into_input(input: &mut Value, r: &Refreshed) -> Change {
    let Some(sub) = input
        .get_mut("subscriptions")
        .and_then(Value::as_array_mut)
        .into_iter()
        .flatten()
        .filter_map(Value::as_object_mut)
        .find(|s| s.get("id").and_then(Value::as_str) == Some(r.id.as_str()))
    else {
        return Change::None;
    };
    let merged = merge_refreshed(sub, r);
    let change = if merged == *sub {
        Change::None
    } else {
        let without_error = |m: &Map<String, Value>| {
            let mut m = m.clone();
            m.remove("error");
            m
        };
        if without_error(&merged) == without_error(sub) {
            Change::Error
        } else {
            Change::Lines
        }
    };
    *sub = merged;
    change
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn parsed(nodes: usize) -> Value {
        let nodes: Vec<Value> = (0..nodes)
            .map(|i| {
                json!({"name": format!("HK {i:02}"), "outbound": {
                    "type": "shadowsocks", "server": "1.2.3.4", "server_port": 8000 + i,
                    "method": "aes-256-gcm", "password": "p"}})
            })
            .collect();
        json!({"nodes": nodes, "skipped": 0, "split": {"groups": [], "rules": []}, "usage": null})
    }

    /// Answers by address; anything else gets no answer. Records the calls.
    fn web<'a>(
        answers: &'a [(&'a str, Via, Download)],
        calls: &'a mut Vec<(String, Via)>,
    ) -> impl FnMut(&str, Via) -> Download + 'a {
        move |url, via| {
            calls.push((url.to_owned(), via));
            answers
                .iter()
                .find(|(u, v, _)| *u == url && *v == via)
                .map_or(Download::NoAnswer, |(_, _, d)| d.clone())
        }
    }

    #[test]
    fn refresh_follows_the_apps_order() {
        type Case<'a> = (
            &'a str,
            bool,
            Vec<(&'a str, Via, Download)>,
            &'a str,
            Option<Via>,
            Result<usize, &'a str>,
        );
        let u = "https://a.example/clash";
        let slash = "https://a.example/clash/";
        let cases: Vec<Case> = vec![
            (
                "direct works",
                true,
                vec![(u, Via::Direct, Download::Parsed(parsed(2)))],
                u,
                Some(Via::Direct),
                Ok(2),
            ),
            (
                "no answer, the core's port answers",
                true,
                vec![(u, Via::Proxy, Download::Parsed(parsed(1)))],
                u,
                Some(Via::Proxy),
                Ok(1),
            ),
            (
                "no answer, the core not asked",
                false,
                vec![(u, Via::Proxy, Download::Parsed(parsed(1)))],
                u,
                None,
                Err(UNREACHABLE),
            ),
            (
                "no answer either way",
                true,
                vec![],
                u,
                None,
                Err(UNREACHABLE_PROXY_TOO),
            ),
            (
                "not an address: the core's port is not tried",
                true,
                vec![
                    (u, Via::Direct, Download::Unusable),
                    (u, Via::Proxy, Download::Parsed(parsed(1))),
                ],
                u,
                None,
                Err(UNREACHABLE),
            ),
            (
                "an answer is an answer: no retry through the port",
                true,
                vec![
                    (u, Via::Direct, Download::Status(500)),
                    (u, Via::Proxy, Download::Parsed(parsed(1))),
                ],
                u,
                Some(Via::Direct),
                Err("订阅服务器出错（500），请稍后再试"),
            ),
            (
                "404, the last slash works",
                true,
                vec![
                    (u, Via::Direct, Download::Status(404)),
                    (slash, Via::Direct, Download::Parsed(parsed(3))),
                ],
                slash,
                Some(Via::Direct),
                Ok(3),
            ),
            (
                "404, the last slash answers 200 with nothing readable: kept",
                true,
                vec![
                    (u, Via::Direct, Download::Status(404)),
                    (slash, Via::Direct, Download::Unreadable),
                ],
                slash,
                Some(Via::Direct),
                Err(UNREADABLE),
            ),
            (
                "404 both ways",
                true,
                vec![
                    (u, Via::Direct, Download::Status(404)),
                    (slash, Via::Direct, Download::Status(404)),
                ],
                u,
                Some(Via::Direct),
                Err(GONE),
            ),
            (
                "404, the slash gets no answer",
                false,
                vec![(u, Via::Direct, Download::Status(404))],
                u,
                Some(Via::Direct),
                Err(GONE),
            ),
            (
                "403",
                true,
                vec![(u, Via::Direct, Download::Status(403))],
                u,
                Some(Via::Direct),
                Err(GONE),
            ),
            (
                "no lines",
                true,
                vec![(u, Via::Direct, Download::Parsed(parsed(0)))],
                u,
                Some(Via::Direct),
                Err(NO_NODES),
            ),
        ];
        for (name, through_core, answers, url, via, want) in cases {
            let mut calls = Vec::new();
            let a = refresh(u, through_core, web(&answers, &mut calls));
            assert_eq!(a.url, url, "{name}");
            assert_eq!(a.via, via, "{name}");
            match (&a.result, want) {
                (Ok(f), Ok(n)) => assert_eq!(f.nodes.len(), n, "{name}"),
                (Err(e), Err(w)) => assert_eq!(e, w, "{name}"),
                (got, want) => panic!("{name}: {got:?}, want {want:?}"),
            }
        }
    }

    #[test]
    fn unsupported_lines_are_left_out_and_counted_apart() {
        let v = json!({"nodes": [{"name": "x", "outbound": {"type": "wireguard"}}], "skipped": 2});
        let a = refresh("http://a/", false, |_, _| Download::Parsed(v.clone()));
        assert_eq!(a.result, Err(UNSUPPORTED.into()));
    }

    #[test]
    fn the_last_slash_goes_after_the_path() {
        for (url, want) in [
            ("https://a.example/clash", Some("https://a.example/clash/")),
            (
                "https://a.example/s?token=1#x",
                Some("https://a.example/s/?token=1#x"),
            ),
            ("https://a.example/clash/", None),
            ("https://a.example", None),
            ("https://a.example?x=1", None),
            ("not a url", None),
        ] {
            assert_eq!(with_last_slash(url).as_deref(), want, "{url}");
        }
    }

    #[test]
    fn file_names_read_as_the_app_reads_them() {
        for (header, want) in [
            ("attachment; filename=\"my.yaml\"", Some("my")),
            (
                "attachment; filename*=UTF-8''%E6%88%91%E7%9A%84%E6%9C%BA%E5%9C%BA.yaml",
                Some("我的机场"),
            ),
            ("attachment; filename=a.b.txt", Some("a.b")),
            ("attachment; filename=list.yml; size=3", Some("list")),
            ("attachment; filename=x.json.bak", Some("x.json.bak")),
            ("attachment; filename=\"\"; filename=b.txt", Some("b")),
            ("attachment; filename*=UTF-8''", Some("UTF-8''")),
            ("attachment; filename=bad%zz", None),
            ("attachment; filename=%E6%88", None),
            ("inline", None),
            ("attachment; FILENAME=x.yaml", None),
        ] {
            assert_eq!(file_name_of(header).as_deref(), want, "{header}");
        }
    }

    fn sub(extra: &Value) -> Map<String, Value> {
        let mut m = json!({
            "id": "a1", "url": "https://a.example/clash", "name": "a.example",
            "nodes": [{"name": "old", "outbound": {"type": "trojan", "server": "o", "server_port": 1, "password": "x"}}],
            "skipped": 1,
        })
        .as_object()
        .unwrap()
        .clone();
        m.extend(extra.as_object().unwrap().clone());
        m
    }

    fn worked(url: &str, file_name: Option<&str>, usage: Option<Value>) -> Refreshed {
        let mut p = parsed(2);
        p["usage"] = usage.unwrap_or(Value::Null);
        p["split"] =
            json!({"groups": [{"n": "G", "t": "select", "m": ["HK 00"]}], "rules": ["MATCH,G"]});
        if let Some(f) = file_name {
            p["content_disposition"] = format!("attachment; filename=\"{f}\"").into();
        }
        let a = refresh(url, false, |_, _| Download::Parsed(p.clone()));
        Refreshed::record("a1", None, a, None, 1_000)
    }

    #[test]
    fn a_refresh_that_worked_sets_what_the_app_sets_in_its_order() {
        let before = sub(&json!({"error": "old problem", "use_split": false}));
        let r = worked(
            "https://a.example/clash",
            Some("Mine.yaml"),
            Some(json!({"upload": 1, "download": 2, "total": 3})),
        );
        let after = merge_refreshed(&before, &r);
        let keys: Vec<&str> = after.keys().map(String::as_str).collect();
        assert_eq!(
            keys,
            [
                "id",
                "url",
                "name",
                "nodes",
                "skipped",
                "usage",
                "split",
                "use_split"
            ]
        );
        assert_eq!(after["name"], "Mine");
        assert_eq!(after["nodes"].as_array().unwrap().len(), 2);
        assert_eq!(after["skipped"], 0);
        assert_eq!(
            after["usage"],
            json!({"upload": 1, "download": 2, "total": 3})
        );
        assert_eq!(after["split"]["rules"], json!(["MATCH,G"]));
        assert_eq!(after["use_split"], false);
    }

    #[test]
    fn a_named_subscription_keeps_its_name_and_no_usage_drops_the_old() {
        let before = sub(
            &json!({"usage": {"upload": 0, "download": 0, "total": 9}, "named": true, "name": "Mine"}),
        );
        let after = merge_refreshed(
            &before,
            &worked("https://a.example/clash", Some("Theirs.txt"), None),
        );
        assert_eq!(after["name"], "Mine");
        assert!(!after.contains_key("usage"));
        assert_eq!(after["named"], true);
    }

    #[test]
    fn a_failed_refresh_keeps_the_lines_and_shows_the_problem() {
        let before = sub(&json!({}));
        let first = worked("https://a.example/clash", None, None);
        let failed = Refreshed::record(
            "a1",
            None,
            Attempt {
                url: "https://a.example/clash/".into(),
                via: Some(Via::Direct),
                result: Err(GONE.into()),
            },
            Some(first.clone()),
            2_000,
        );
        // What worked before stays on record.
        assert_eq!(failed.nodes, first.nodes);
        assert_eq!(failed.updated, Some(1_000));
        assert_eq!(failed.checked, 2_000);
        let after = merge_refreshed(&before, &failed);
        assert_eq!(after["nodes"], before["nodes"]);
        assert_eq!(after["skipped"], 1);
        assert_eq!(after["error"], GONE);
        assert_eq!(after["url"], "https://a.example/clash/");
    }

    #[test]
    fn merging_into_the_input_says_what_changed() {
        let mut input =
            json!({"subscriptions": [sub(&json!({})), {"id": "b", "url": "u"}], "now": 1});
        let r = worked("https://a.example/clash", None, None);
        assert_eq!(merge_into_input(&mut input, &r), Change::Lines);
        assert_eq!(merge_into_input(&mut input, &r), Change::None);
        let failed = Refreshed {
            last_error: Some(UNREACHABLE.into()),
            ..r.clone()
        };
        assert_eq!(merge_into_input(&mut input, &failed), Change::Error);
        // The other subscription and the rest are left alone.
        assert_eq!(input["subscriptions"][1], json!({"id": "b", "url": "u"}));
        assert_eq!(input["now"], 1);
        let other = Refreshed {
            id: "zz".into(),
            ..r
        };
        assert_eq!(merge_into_input(&mut input, &other), Change::None);
    }

    #[test]
    fn the_record_round_trips_with_the_lines_last() {
        let r = worked("https://a.example/clash", Some("x.yaml"), None);
        let text = serde_json::to_string(&r).unwrap();
        assert!(text.ends_with("]}"), "{text}");
        assert!(text.find("\"nodes\"").unwrap() > text.find("\"node_count\"").unwrap());
        assert_eq!(serde_json::from_str::<Refreshed>(&text).unwrap(), r);
    }
}
