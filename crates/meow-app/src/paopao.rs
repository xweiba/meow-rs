//! `meow paopao parse|build|fetch|refresh|apply`: the child process behind
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
//! - `apply`: `{dir, ids, config?, now, build?}` → the records of `ids`
//!   merged into the stored input (written back when that changed it);
//!   when lines changed (or `build`), the config built at `now` and, when
//!   it differs from the one in `config`, written to the store's
//!   `config.next.yaml`. Answers `{input_changed, rebuilt, next}`.
//!
//! The exit code says what the answer is ([`meow_api::paopao::EXIT_OK`],
//! `EXIT_INVALID`, `EXIT_UPSTREAM`); an error answer is `{"error": ...}`.

use std::io::{Read as _, Write as _};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use meow_api::paopao::store::{write_atomic, Store};
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
    /// `{dir, ids, config?, now, build?}` on stdin → refreshes merged, the config rebuilt
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
    config: Option<PathBuf>,
    now: i64,
    #[serde(default)]
    build: bool,
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
    let config =
        Value::Object(meow_paopao::build(&meow_paopao::BuildInput::from_json(&input)).config);
    drop(input);
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
