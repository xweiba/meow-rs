//! `meow paopao parse|build|fetch`: the child process behind the API's
//! `/paopao/…` routes ([`meow_api::paopao`]). Input on stdin, the answer
//! on stdout, then exit: what a parse or a build allocates goes with the
//! process, never into the long-running core.
//!
//! - `parse`: a subscription body → what `paopao_parse` returns.
//! - `build`: the build input (JSON) → what `paopao_build` returns.
//! - `fetch`: `{url, user_agent?, proxy?: "host:port"}` → the body fetched
//!   (HTTP(S), redirects, 30 s, at most 16 MiB) and parsed, plus `status`,
//!   `final_url` and `content_disposition`; `usage` is the
//!   `subscription-userinfo` header's when it has one (as the app does).
//!   `proxy` is an HTTP proxy (the core's mixed port), reached by
//!   `CONNECT`. Like the app: user agent `clash.meta`, and anything but
//!   200 is an error.
//!
//! The exit code says what the answer is ([`meow_api::paopao::EXIT_OK`],
//! `EXIT_INVALID`, `EXIT_UPSTREAM`); an error answer is `{"error": ...}`.

use std::io::{Read as _, Write as _};
use std::sync::Arc;
use std::time::Duration;

use meow_api::paopao::{EXIT_INVALID, EXIT_OK, EXIT_UPSTREAM};
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
        }
        m.insert("status".into(), status.into());
        m.insert("final_url".into(), res.url.into());
        m.insert("content_disposition".into(), disposition.into());
    }
    (v, code)
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
