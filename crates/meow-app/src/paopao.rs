//! `meow paopao parse|build|fetch|refresh|module|apply`: the child process behind
//! the API's `/paopao/…` routes and the core's own refreshes
//! ([`meow_api::paopao`]). Input on stdin, the answer on stdout, then exit:
//! what a parse or a build allocates goes with the process, never into the
//! long-running core.
//!
//! - `parse`: a subscription body → what `paopao_parse` returns.
//! - `build`: the build input (JSON) → what `paopao_build` returns.
//! - `fetch`: `{url, user_agent?, proxy?: "host:port"}` → the body fetched
//!   (HTTP(S), redirects, 30 s, at most 16 MiB) and parsed, plus `status`,
//!   `final_url`, `content_disposition` and `body_sha` (SHA-256, hex);
//!   `usage` is the `subscription-userinfo` header's when it has one (as
//!   the app does). `proxy` is an HTTP proxy (the core's mixed port),
//!   reached by `CONNECT`. Like the app: user agent `clash.meta`, and
//!   anything but 200 is an error.
//! - `refresh`: `{dir, id, url, user_agent?, proxy?}` → one subscription
//!   refreshed as the app refreshes it (`meow_paopao::refresh`, its
//!   downloads made as `fetch` makes them, through `proxy` when directly
//!   there is no answer) and its record written to the store in `dir`
//!   ([`meow_api::paopao::store`]); answers `{id, error}`, `error` the
//!   subscription's problem (null when it worked).
//! - `module`: `{dir, id, url, values?, proxy?}` → one rewrite module
//!   refreshed as the app refreshes it (`_fetchModule`: the module, then
//!   its scripts and Map Local data, each directly and through `proxy` when
//!   there is no answer; parsed with `values` by
//!   `meow_paopao::ingest::module`); once all of it arrived the scripts
//!   are written beside the core (`<home>/modules/<id>/<i>.js`, `home` the
//!   store's parent) and its record to the store. Answers `{id, error}`.
//! - `apply`: `{dir, ids, modules?, set?, config?, now, build?, keep?,
//!   picks?}` → the records of `ids` (subscriptions) and `modules` merged
//!   into the stored input, the top-level keys of `set` (measured exits, the
//!   network …) put in as they are, the input written back when that
//!   changed it; when what the config is built from changed (or `build`),
//!   the config built at `now`, its keys in `keep` (the running core's API
//!   and port) set as `keep` has them, and, when it differs from the one
//!   in `config`, written to the store's `config.next.yaml`; the build's
//!   route policies go to `policies.json`. Answers `{input_changed,
//!   rebuilt, next}`. `picks` (`[{group, member}]`, made in the running
//!   core) go into the input's settings and build nothing.
//!
//! The exit code says what the answer is ([`meow_api::paopao::EXIT_OK`],
//! `EXIT_INVALID`, `EXIT_UPSTREAM`); an error answer is `{"error": ...}`.

use std::io::{Read as _, Write as _};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use meow_api::paopao::store::{write_atomic, ModuleRecord, Store};
use meow_api::paopao::{EXIT_INVALID, EXIT_OK, EXIT_UPSTREAM};
use meow_paopao::refresh::{self, Change, Download, Refreshed, Via};
use serde_json::{json, Value};

/// What the app sends (`HttpClient.userAgent`).
const USER_AGENT: &str = "clash.meta";
/// The whole download, connect to last byte.
const FETCH_TIMEOUT: Duration = Duration::from_secs(30);
/// Largest subscription body.
const MAX_BODY: usize = 16 * 1024 * 1024;

#[derive(clap::Subcommand)]
pub enum Op {
    /// A subscription body on stdin → its nodes
    Parse,
    /// The build input on stdin → the config
    Build,
    /// `{url, user_agent?, proxy?}` on stdin → the subscription fetched and parsed
    Fetch,
    /// `{dir, id, url, user_agent?, proxy?}` on stdin → the subscription refreshed into the store
    Refresh,
    /// `{dir, id, url, values?, proxy?}` on stdin → the module refreshed into the store
    Module,
    /// `{dir, ids, modules?, set?, config?, now, build?, keep?, picks?}` on stdin → refreshes merged, the config rebuilt
    Apply,
}

/// Runs `op` over stdin and writes the answer; the process's exit code.
pub fn run(op: &Op) -> i32 {
    let mut input = Vec::new();
    let (answer, code) = match std::io::stdin().read_to_end(&mut input) {
        Err(e) => (json!({ "error": format!("cannot read the input: {e}") }), 1),
        Ok(_) => match String::from_utf8(input) {
            Err(_) => invalid("input is not UTF-8"),
            Ok(input) => answer(op, &input),
        },
    };
    let mut out = std::io::BufWriter::new(std::io::stdout().lock());
    if serde_json::to_writer(&mut out, &answer).is_err() || out.flush().is_err() {
        return 1;
    }
    code
}

/// The answer to `op` over `input` and its exit code.
pub fn answer(op: &Op, input: &str) -> (Value, i32) {
    match op {
        Op::Parse => judged(meow_paopao::parse_json(input)),
        Op::Build => judged(meow_paopao::build_json(input)),
        Op::Fetch => fetch(input),
        Op::Refresh => refresh(input),
        Op::Module => module(input),
        Op::Apply => apply(input),
    }
}

/// `{"error": ...}` is about the input.
fn judged(v: Value) -> (Value, i32) {
    let code = if v.get("error").is_some() {
        EXIT_INVALID
    } else {
        EXIT_OK
    };
    (v, code)
}

fn invalid(why: impl std::fmt::Display) -> (Value, i32) {
    (json!({ "error": why.to_string() }), EXIT_INVALID)
}

fn fetch(input: &str) -> (Value, i32) {
    let req = match serde_json::from_str::<Value>(input) {
        Ok(v) if v.is_object() => v,
        _ => return invalid("input is not a JSON object"),
    };
    let Some(url) = req.get("url").and_then(Value::as_str) else {
        return invalid("input has no url");
    };
    let scheme = url.split_once("://").map(|(s, _)| s.to_ascii_lowercase());
    if !matches!(scheme.as_deref(), Some("http" | "https")) {
        return invalid("url is not http(s)");
    }
    let agent = req
        .get("user_agent")
        .and_then(Value::as_str)
        .filter(|a| !a.is_empty())
        .unwrap_or(USER_AGENT);
    if agent.chars().any(char::is_control) {
        return invalid("user_agent has control characters");
    }
    let proxy = match req.get("proxy").and_then(Value::as_str) {
        None => None,
        Some(p) => match http_proxy(p) {
            Some(p) => Some(p),
            None => return invalid("proxy is not host:port"),
        },
    };
    let runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => return (json!({ "error": e.to_string() }), 1),
    };
    let headers = [("User-Agent".to_owned(), agent.to_owned())];
    let got = runtime.block_on(async {
        tokio::time::timeout(
            FETCH_TIMEOUT,
            meow_config::internal_http::fetch_response(url, proxy.as_ref(), &headers, MAX_BODY),
        )
        .await
    });
    let res = match got {
        Err(_) => return upstream(format!("no answer within {FETCH_TIMEOUT:?}")),
        Ok(Err(e)) => return upstream(format!("{e:#}")),
        Ok(Ok(res)) => res,
    };
    let status = res.status;
    if status != 200 {
        let mut v = json!({ "error": format!("HTTP {status}") });
        v["status"] = status.into();
        v["final_url"] = res.url.into();
        return (v, EXIT_UPSTREAM);
    }
    let userinfo = res
        .header("subscription-userinfo")
        .and_then(meow_paopao::Usage::parse);
    let disposition = res.header("content-disposition").map(str::to_owned);
    let sha = {
        use sha2::Digest as _;
        hex::encode(sha2::Sha256::digest(&res.body))
    };
    let (mut v, code) = match String::from_utf8(res.body) {
        Ok(body) => judged(meow_paopao::parse_json(&body)),
        Err(_) => invalid("the subscription is not UTF-8 text"),
    };
    if let Some(m) = v.as_object_mut() {
        // The header says it best; else what the node names say.
        if code == EXIT_OK {
            if let Some(u) = userinfo {
                m.insert("usage".into(), u.to_json());
            }
            m.insert("body_sha".into(), sha.into());
        }
        m.insert("status".into(), status.into());
        m.insert("final_url".into(), res.url.into());
        m.insert("content_disposition".into(), disposition.into());
    }
    (v, code)
}

/// What a `fetch` answer is to a refresh.
fn download_of(v: Value, code: i32) -> Download {
    let status = v
        .get("status")
        .and_then(Value::as_u64)
        .and_then(|s| u16::try_from(s).ok());
    match (code, status) {
        (EXIT_OK, _) => Download::Parsed(v),
        (EXIT_UPSTREAM, Some(s)) => Download::Status(s),
        // 200, not a subscription (or not text).
        (EXIT_INVALID, Some(_)) => Download::Unreadable,
        // Not an address to fetch.
        (EXIT_INVALID, None) => Download::Unusable,
        _ => Download::NoAnswer,
    }
}

fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_millis()).unwrap_or(i64::MAX))
}

#[derive(serde::Deserialize)]
struct RefreshRequest {
    dir: PathBuf,
    id: String,
    url: String,
    #[serde(default)]
    user_agent: Option<String>,
    #[serde(default)]
    proxy: Option<String>,
}

fn refresh(input: &str) -> (Value, i32) {
    let req: RefreshRequest = match serde_json::from_str(input) {
        Ok(r) => r,
        Err(e) => return invalid(format!("bad refresh request: {e}")),
    };
    let store = Store::new(&req.dir);
    let path = store.subscription(&req.id);
    let previous = std::fs::read(&path)
        .ok()
        .and_then(|b| serde_json::from_slice::<Refreshed>(&b).ok());
    let attempt = refresh::refresh(&req.url, req.proxy.is_some(), |url, via| {
        let proxy = match via {
            Via::Direct => None,
            Via::Proxy => req.proxy.as_deref(),
        };
        let ask = json!({ "url": url, "user_agent": req.user_agent, "proxy": proxy });
        let (v, code) = fetch(&ask.to_string());
        download_of(v, code)
    });
    let record = Refreshed::record(&req.id, req.user_agent.clone(), attempt, previous, now_ms());
    let written = serde_json::to_vec(&record)
        .map_err(std::io::Error::other)
        .and_then(|b| write_atomic(&path, &b, false));
    if let Err(e) = written {
        return invalid(format!("cannot keep the subscription's record: {e}"));
    }
    (json!({ "id": req.id, "error": record.last_error }), EXIT_OK)
}

#[derive(serde::Deserialize)]
struct ApplyRequest {
    dir: PathBuf,
    #[serde(default)]
    ids: Vec<String>,
    #[serde(default)]
    modules: Vec<String>,
    /// Top-level input keys replaced as they are.
    #[serde(default)]
    set: serde_json::Map<String, Value>,
    #[serde(default)]
    config: Option<PathBuf>,
    now: i64,
    #[serde(default)]
    build: bool,
    /// Top-level keys the config keeps as the running core has them.
    #[serde(default)]
    keep: serde_json::Map<String, Value>,
    /// Picks made in the running core (`{group, member}`), into the
    /// input's settings ([`meow_paopao::model::settings::record_pick`]):
    /// the core runs them already, nothing is built for them.
    #[serde(default)]
    picks: Vec<Pick>,
    /// Keys of the input's settings replaced as they are (the manager's
    /// switches: `tun`, `system_proxy`, `launch_at_login`). Built only
    /// with `build`: what needs a new config says so.
    #[serde(default)]
    settings: serde_json::Map<String, Value>,
}

#[derive(serde::Deserialize)]
struct Pick {
    group: String,
    member: String,
}

fn apply(input: &str) -> (Value, i32) {
    let req: ApplyRequest = match serde_json::from_str(input) {
        Ok(r) => r,
        Err(e) => return invalid(format!("bad apply request: {e}")),
    };
    let store = Store::new(&req.dir);
    let mut input: Value = match std::fs::read(store.input()) {
        Err(e) => return invalid(format!("no build input: {e}")),
        Ok(b) => match serde_json::from_slice(&b) {
            Ok(v @ Value::Object(_)) => v,
            _ => return invalid("the stored build input is not a JSON object"),
        },
    };
    let (mut changed, mut lines) = (false, false);
    for id in &req.ids {
        let Some(record) = std::fs::read(store.subscription(id))
            .ok()
            .and_then(|b| serde_json::from_slice::<Refreshed>(&b).ok())
        else {
            continue;
        };
        match refresh::merge_into_input(&mut input, &record) {
            Change::None => {}
            Change::Error => changed = true,
            Change::Lines => (changed, lines) = (true, true),
        }
    }
    for id in &req.modules {
        if merge_module(&mut input, &store, id) {
            (changed, lines) = (true, true);
        }
    }
    if let Some(settings) = input.get_mut("settings").and_then(Value::as_object_mut) {
        for p in &req.picks {
            changed |= meow_paopao::model::settings::record_pick(settings, &p.group, &p.member);
        }
    }
    if !req.settings.is_empty() {
        if let Some(m) = input.as_object_mut() {
            let settings = m
                .entry("settings")
                .or_insert_with(|| Value::Object(serde_json::Map::new()));
            if let Some(settings) = settings.as_object_mut() {
                for (k, v) in req.settings {
                    if settings.get(&k) != Some(&v) {
                        settings.insert(k, v);
                        changed = true;
                    }
                }
            }
        }
    }
    if let Some(m) = input.as_object_mut() {
        for (k, v) in req.set {
            if m.get(&k) != Some(&v) {
                m.insert(k, v);
                (changed, lines) = (true, true);
            }
        }
    }
    if changed {
        let written = serde_json::to_vec(&input)
            .map_err(std::io::Error::other)
            .and_then(|b| write_atomic(&store.input(), &b, true));
        if let Err(e) = written {
            return invalid(format!("cannot keep the build input: {e}"));
        }
    }
    if !lines && !req.build {
        return (
            json!({ "input_changed": changed, "rebuilt": false, "next": false }),
            EXIT_OK,
        );
    }
    // Built at the time it runs (usage running out, plans ending).
    input["now"] = req.now.into();
    if let Err(e) = meow_paopao::rule_profile::load(&mut input) {
        return invalid(e);
    }
    let built = meow_paopao::build(&meow_paopao::BuildInput::from_json(&input));
    drop(input);
    let policies: Vec<Value> = built
        .route_policies
        .iter()
        .map(meow_paopao::RoutePolicy::to_json)
        .collect();
    if let Err(e) = serde_json::to_vec(&policies)
        .map_err(std::io::Error::other)
        .and_then(|b| write_atomic(&store.policies(), &b, false))
    {
        return invalid(format!("cannot keep the route policies: {e}"));
    }
    let mut config = built.config;
    // The input may be from a start on other ports: the core stays where
    // it is.
    for (k, v) in req.keep {
        if let Some(slot) = config.get_mut(&k) {
            *slot = v;
        }
    }
    let config = Value::Object(config);
    let same = req
        .config
        .and_then(|p| std::fs::read(p).ok())
        .and_then(|b| serde_json::from_slice::<Value>(&b).ok())
        .is_some_and(|running| running == config);
    if !same {
        // meow reads YAML; JSON is YAML. Holds the API secret.
        let written = serde_json::to_vec(&config)
            .map_err(std::io::Error::other)
            .and_then(|b| write_atomic(&store.next_config(), &b, true));
        if let Err(e) = written {
            return invalid(format!("cannot write the new config: {e}"));
        }
    }
    (
        json!({ "input_changed": changed, "rebuilt": true, "next": !same }),
        EXIT_OK,
    )
}

/// Module `id`'s fresh record (one that worked) taken into the input's
/// module of the same address and settings: its spec and text. True when
/// that changed them.
fn merge_module(input: &mut Value, store: &Store, id: &str) -> bool {
    let Some(r) = ModuleRecord::read(&store.module(id), id).filter(ModuleRecord::worked) else {
        return false;
    };
    let Some(m) = input
        .get_mut("modules")
        .and_then(Value::as_array_mut)
        .into_iter()
        .flatten()
        .filter_map(Value::as_object_mut)
        .find(|m| m.get("id").and_then(Value::as_str) == Some(id))
    else {
        return false;
    };
    let values = m
        .get("values")
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();
    if m.get("url").and_then(Value::as_str) != Some(r.url.as_str()) || values != r.values {
        return false;
    }
    let source = r.source.clone().map(Value::String);
    if m.get("spec") == Some(&r.spec) && m.get("source") == source.as_ref() {
        return false;
    }
    m.insert("spec".into(), r.spec);
    match source {
        Some(s) => m.insert("source".into(), s),
        None => m.remove("source"),
    };
    true
}

#[derive(serde::Deserialize)]
struct ModuleRequest {
    dir: PathBuf,
    id: String,
    url: String,
    #[serde(default)]
    values: serde_json::Map<String, Value>,
    #[serde(default)]
    proxy: Option<String>,
}

/// What one download of a module's part came to.
enum Got {
    /// An answer, its status and body as text.
    Answer(u16, String),
    /// Could not connect or timed out: worth trying through the proxy.
    NoAnswer,
    /// Anything else (not an address, not text).
    Unusable,
}

fn get_text(runtime: &tokio::runtime::Runtime, url: &str, proxy: Option<&str>) -> Got {
    let proxy = match proxy {
        Some(p) => match http_proxy(p) {
            Some(p) => Some(p),
            None => return Got::Unusable,
        },
        None => None,
    };
    let scheme = url.split_once("://").map(|(s, _)| s.to_ascii_lowercase());
    if !matches!(scheme.as_deref(), Some("http" | "https")) {
        return Got::Unusable;
    }
    let headers = [("User-Agent".to_owned(), USER_AGENT.to_owned())];
    let got = runtime.block_on(async {
        tokio::time::timeout(
            FETCH_TIMEOUT,
            meow_config::internal_http::fetch_response(url, proxy.as_ref(), &headers, MAX_BODY),
        )
        .await
    });
    match got {
        Err(_) | Ok(Err(_)) => Got::NoAnswer,
        Ok(Ok(res)) => match String::from_utf8(res.body) {
            Ok(body) => Got::Answer(res.status, body),
            Err(_) => Got::Unusable,
        },
    }
}

/// Dart `_fetch`: directly, then through `proxy` when that got no answer.
/// `Err(true)`: no answer through the proxy either.
fn get_either(
    runtime: &tokio::runtime::Runtime,
    url: &str,
    proxy: Option<&str>,
) -> Result<(u16, String), bool> {
    match get_text(runtime, url, None) {
        Got::Answer(s, b) => Ok((s, b)),
        Got::NoAnswer if proxy.is_some() => match get_text(runtime, url, proxy) {
            Got::Answer(s, b) => Ok((s, b)),
            _ => Err(true),
        },
        _ => Err(false),
    }
}

/// The module's spec and its scripts, or the problem in the app's words.
fn module_parts(
    runtime: &tokio::runtime::Runtime,
    req: &ModuleRequest,
) -> Result<(Value, String, Vec<String>), String> {
    let text = match get_either(runtime, &req.url, req.proxy.as_deref()) {
        Ok((200, body)) => body,
        Ok((status, _)) => return Err(format!("模块下载失败（{status}）")),
        Err(true) => return Err("模块下载失败，经代理也无法连接，请检查链接和网络".into()),
        Err(false) => return Err("模块下载失败，请检查链接和网络".into()),
    };
    let values: Vec<(String, String)> = req
        .values
        .iter()
        .map(|(k, v)| {
            let v = v.as_str().map_or_else(|| v.to_string(), str::to_owned);
            (k.clone(), v)
        })
        .collect();
    let base =
        url::Url::parse(&req.url).map_err(|_| "模块下载失败，请检查链接和网络".to_owned())?;
    let mut spec = meow_paopao::ingest::module::parse_module(
        &text,
        &meow_paopao::ingest::module::fallback_name(&req.url),
        &values,
    );
    let list = |k: &str| spec.get(k).and_then(Value::as_array).map_or(0, Vec::len);
    if list("scripts") + list("rewrites") + list("hostnames") + list("rules") == 0 {
        return Err("这个链接中没有可用的模块内容".into());
    }
    let net = "模块中的脚本下载失败，请检查网络";
    let fetch = |rel: &str, what: &str| -> Result<String, String> {
        // The built-in location script lives in the app alone.
        let at = base.join(rel).map_err(|_| net.to_owned())?;
        match get_either(runtime, at.as_str(), req.proxy.as_deref()) {
            Ok((200, body)) => Ok(body),
            Ok((status, _)) => Err(format!("模块中的{what}下载失败（{status}）")),
            Err(_) => Err(net.to_owned()),
        }
    };
    let mut scripts = Vec::new();
    for s in spec
        .get("scripts")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        let url = s.get("url").and_then(Value::as_str).unwrap_or("");
        if url.starts_with("builtin:") {
            return Err(net.to_owned());
        }
        scripts.push(fetch(url, "脚本")?);
    }
    // [Map Local] data given by URL: kept with the module as text.
    if let Some(rewrites) = spec.get_mut("rewrites").and_then(Value::as_array_mut) {
        for r in rewrites {
            let Some(action) = r.get_mut("action").and_then(Value::as_object_mut) else {
                continue;
            };
            let Some(url) = action
                .get("dataUrl")
                .and_then(Value::as_str)
                .map(str::to_owned)
            else {
                continue;
            };
            let data = fetch(&url, "数据")?;
            action.shift_remove("dataUrl");
            action.insert("text".into(), data.into());
        }
    }
    Ok((spec, text, scripts))
}

fn module(input: &str) -> (Value, i32) {
    let req: ModuleRequest = match serde_json::from_str(input) {
        Ok(r) => r,
        Err(e) => return invalid(format!("bad module request: {e}")),
    };
    let runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => return (json!({ "error": e.to_string() }), 1),
    };
    let store = Store::new(&req.dir);
    let path = store.module(&req.id);
    let now = now_ms();
    let record = match module_parts(&runtime, &req) {
        Ok((spec, source, scripts)) => {
            let dir = store.home().join("modules").join(&req.id);
            let written = std::fs::create_dir_all(&dir).and_then(|()| {
                scripts.iter().enumerate().try_for_each(|(i, s)| {
                    write_atomic(
                        &store
                            .home()
                            .join(meow_paopao::rules::module_script_path(&req.id, i)),
                        s.as_bytes(),
                        false,
                    )
                })
            });
            if let Err(e) = written {
                return invalid(format!("cannot keep the module's scripts: {e}"));
            }
            ModuleRecord {
                id: req.id.clone(),
                url: req.url.clone(),
                checked: now,
                updated: Some(now),
                last_error: None,
                values: req.values.clone(),
                spec,
                source: Some(source),
            }
        }
        Err(problem) => {
            let kept = ModuleRecord::read(&path, &req.id).unwrap_or_default();
            ModuleRecord {
                id: req.id.clone(),
                url: req.url.clone(),
                checked: now,
                last_error: Some(problem),
                ..kept
            }
        }
    };
    let written = serde_json::to_vec(&record)
        .map_err(std::io::Error::other)
        .and_then(|b| write_atomic(&path, &b, false));
    if let Err(e) = written {
        return invalid(format!("cannot keep the module's record: {e}"));
    }
    (json!({ "id": req.id, "error": record.last_error }), EXIT_OK)
}

fn upstream(why: impl std::fmt::Display) -> (Value, i32) {
    (json!({ "error": why.to_string() }), EXIT_UPSTREAM)
}

/// An HTTP proxy at `host:port` (`[v6]:port`), dialed directly.
fn http_proxy(addr: &str) -> Option<Arc<dyn meow_common::Proxy>> {
    let (host, port) = addr.rsplit_once(':')?;
    let host = host.trim_start_matches('[').trim_end_matches(']');
    let port = port.parse::<u16>().ok().filter(|&p| p != 0)?;
    if host.is_empty() {
        return None;
    }
    let adapter = meow_proxy::HttpAdapter::new(
        "paopao-fetch",
        host,
        port,
        None,
        false,
        false,
        Vec::new(),
        Arc::new(meow_proxy::dialer::DirectDialer),
    );
    Some(Arc::new(meow_config::proxy_parser::WrappedProxy::new(
        Box::new(adapter),
    )))
}

#[cfg(test)]
mod apply_settings_tests {
    use super::*;

    #[test]
    fn the_manager_s_switches_go_into_the_input_s_settings() {
        let d = tempfile::tempdir().unwrap();
        let store = Store::new(d.path());
        std::fs::write(
            store.input(),
            r#"{"settings":{"mode":"smart","tun":false},"subscriptions":[]}"#,
        )
        .unwrap();
        let req = json!({
            "dir": d.path(),
            "settings": {"tun": true, "system_proxy": true},
            "now": 1,
        });
        let (v, code) = answer(&Op::Apply, &req.to_string());
        assert_eq!(code, EXIT_OK, "{v}");
        assert_eq!(v["input_changed"], true);
        assert_eq!(v["rebuilt"], false);
        let kept: Value = serde_json::from_slice(&std::fs::read(store.input()).unwrap()).unwrap();
        assert_eq!(
            kept["settings"],
            json!({"mode": "smart", "tun": true, "system_proxy": true})
        );
        // The same again: nothing changed.
        let (v, _) = answer(&Op::Apply, &req.to_string());
        assert_eq!(v["input_changed"], false);
    }
}
