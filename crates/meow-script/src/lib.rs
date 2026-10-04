//! Rewrite scripts the way Surge, Loon, Stash and Quantumult X run them,
//! so their community scripts work as they are:
//!
//! - `$request` (`url`, `method`, `headers`, `body`) and, for responses,
//!   `$response` (`status` / `statusCode`, `headers`, `body`);
//! - `$done(obj?)` hands back what changed (`body`, `headers`, `status`,
//!   `url`; a request script may answer with `{response: {…}}`);
//! - `$persistentStore.read/write` (Surge / Loon), `$prefs.valueForKey /
//!   setValueForKey` (Quantumult X) over one JSON store file;
//! - `$notification.post` / `$notify`, `console.log`, `$argument`,
//!   `$environment`, `$script`;
//! - with `binary-body-mode` bodies are `Uint8Array`s, otherwise strings.
//!
//! Every run gets a fresh QuickJS runtime with a memory cap and a deadline:
//! a broken or hostile script cannot hold a connection or the process.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use parking_lot::Mutex;
use rquickjs::{Context, Ctx, Function, Object, Runtime, TypedArray, Value};

/// One HTTP message as a script sees it.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Message {
    pub url: String,
    pub method: String,
    /// Responses only.
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Option<Vec<u8>>,
}

/// What a script asked for through `$done`. `None` fields stay as they
/// were.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Outcome {
    pub url: Option<String>,
    pub status: Option<u16>,
    pub headers: Option<Vec<(String, String)>>,
    pub body: Option<Vec<u8>>,
    /// A request script answered itself (`$done({response: …})`): send
    /// this back without asking the server.
    pub response: Option<Message>,
}

/// Values scripts keep between runs (`$persistentStore`, `$prefs`): one
/// JSON object in a file, shared by every script.
pub struct Store {
    path: Option<PathBuf>,
    lock: Mutex<()>,
}

impl Store {
    pub fn new(path: Option<PathBuf>) -> Self {
        Self {
            path,
            lock: Mutex::new(()),
        }
    }

    fn load(&self) -> serde_json::Map<String, serde_json::Value> {
        self.path
            .as_ref()
            .and_then(|p| std::fs::read(p).ok())
            .and_then(|b| serde_json::from_slice(&b).ok())
            .unwrap_or_default()
    }

    pub fn read(&self, key: &str) -> Option<String> {
        let _g = self.lock.lock();
        match self.load().get(key)? {
            serde_json::Value::String(s) => Some(s.clone()),
            v => Some(v.to_string()),
        }
    }

    pub fn write(&self, key: &str, value: Option<String>) -> bool {
        let Some(path) = &self.path else {
            return false;
        };
        let _g = self.lock.lock();
        let mut all = self.load();
        match value {
            Some(v) => all.insert(key.to_string(), serde_json::Value::String(v)),
            None => all.remove(key),
        };
        let Ok(data) = serde_json::to_vec_pretty(&all) else {
            return false;
        };
        let tmp = path.with_extension("tmp");
        std::fs::write(&tmp, data).is_ok() && std::fs::rename(tmp, path).is_ok()
    }
}

/// How one script runs.
#[derive(Clone)]
pub struct Options {
    /// Script name (`$script.name`, log lines).
    pub name: String,
    /// `$argument`.
    pub argument: String,
    /// Bodies as `Uint8Array` (`binary-body-mode`).
    pub binary_body: bool,
    pub timeout: Duration,
    pub store: Arc<Store>,
}

#[derive(Debug)]
pub enum Error {
    Js(String),
    Timeout,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Js(e) => write!(f, "script error: {e}"),
            Self::Timeout => write!(f, "script took too long"),
        }
    }
}

impl std::error::Error for Error {}

/// The script API in JavaScript, over a few native hooks.
const PRELUDE: &str = r#"
var __paopao_done = undefined;
var $done = function (v) { __paopao_done = (v === undefined || v === null) ? {} : v; };
var $persistentStore = {
  read: function (k) { var v = __paopao_store_read(String(k || '')); return v === undefined ? null : v; },
  write: function (v, k) { return __paopao_store_write(String(k || ''), v === undefined || v === null ? null : String(v)); },
};
var $prefs = {
  valueForKey: function (k) { return $persistentStore.read(k); },
  setValueForKey: function (v, k) { return $persistentStore.write(v, k); },
  removeValueForKey: function (k) { return __paopao_store_write(String(k), null); },
};
var $notification = { post: function (t, s, b) { __paopao_log('notify', [t, s, b].filter(Boolean).join(' | ')); } };
var $notify = function (t, s, b) { $notification.post(t, s, b); };
var console = {
  log: function () { __paopao_log('log', Array.prototype.join.call(arguments, ' ')); },
  info: function () { __paopao_log('log', Array.prototype.join.call(arguments, ' ')); },
  warn: function () { __paopao_log('warn', Array.prototype.join.call(arguments, ' ')); },
  error: function () { __paopao_log('error', Array.prototype.join.call(arguments, ' ')); },
};
var setTimeout = function (f) { var a = Array.prototype.slice.call(arguments, 2); Promise.resolve().then(function () { f.apply(null, a); }); return 0; };
var clearTimeout = function () {};
"#;

fn js_err(ctx: &Ctx<'_>, e: &rquickjs::Error) -> Error {
    if let rquickjs::Error::Exception = e {
        let v = ctx.catch();
        let msg = v
            .as_exception()
            .map(|x| {
                format!(
                    "{}\n{}",
                    x.message().unwrap_or_default(),
                    x.stack().unwrap_or_default()
                )
            })
            .or_else(|| v.as_string().and_then(|s| s.to_string().ok()))
            .unwrap_or_else(|| format!("{v:?}"));
        return Error::Js(msg);
    }
    Error::Js(e.to_string())
}

fn headers_obj<'js>(ctx: &Ctx<'js>, headers: &[(String, String)]) -> rquickjs::Result<Object<'js>> {
    let o = Object::new(ctx.clone())?;
    for (k, v) in headers {
        o.set(k.as_str(), v.as_str())?;
    }
    Ok(o)
}

fn body_value<'js>(ctx: &Ctx<'js>, body: &[u8], binary: bool) -> rquickjs::Result<Value<'js>> {
    if binary {
        Ok(TypedArray::<u8>::new(ctx.clone(), body.to_vec())?.into_value())
    } else {
        Ok(rquickjs::String::from_str(ctx.clone(), &String::from_utf8_lossy(body))?.into_value())
    }
}

fn message_obj<'js>(
    ctx: &Ctx<'js>,
    m: &Message,
    response: bool,
    binary: bool,
) -> rquickjs::Result<Object<'js>> {
    let o = Object::new(ctx.clone())?;
    if response {
        o.set("status", m.status)?;
        o.set("statusCode", m.status)?;
    } else {
        o.set("url", m.url.as_str())?;
        o.set("method", m.method.as_str())?;
    }
    o.set("headers", headers_obj(ctx, &m.headers)?)?;
    if let Some(b) = &m.body {
        o.set("body", body_value(ctx, b, binary)?)?;
        if binary {
            o.set("bodyBytes", body_value(ctx, b, true)?)?;
        }
    }
    Ok(o)
}

fn read_body(v: &Value<'_>) -> Option<Vec<u8>> {
    if let Some(s) = v.as_string() {
        return s.to_string().ok().map(String::into_bytes);
    }
    if let Ok(t) = TypedArray::<u8>::from_value(v.clone()) {
        // SAFETY: copied at once, while no JavaScript runs that could
        // resize or detach the buffer.
        return unsafe { t.as_bytes() }.map(<[u8]>::to_vec);
    }
    if let Some(o) = v.as_object() {
        if let Some(ab) = o.as_array_buffer() {
            // SAFETY: as above.
            return unsafe { ab.as_bytes() }.map(<[u8]>::to_vec);
        }
    }
    None
}

fn read_headers(v: &Value<'_>) -> Option<Vec<(String, String)>> {
    let o = v.as_object()?;
    let mut out = Vec::new();
    for item in o.props::<String, Value>() {
        let (k, v) = item.ok()?;
        let v = if let Some(s) = v.as_string() {
            s.to_string().ok()?
        } else if let Some(n) = v.as_number() {
            n.to_string()
        } else {
            continue;
        };
        out.push((k, v));
    }
    Some(out)
}

fn read_status(o: &Object<'_>) -> Option<u16> {
    for key in ["status", "statusCode"] {
        if let Ok(v) = o.get::<_, Value>(key) {
            if let Some(n) = v.as_number() {
                return Some(n as u16);
            }
            if let Some(s) = v.as_string().and_then(|s| s.to_string().ok()) {
                // Quantumult X: "HTTP/1.1 200 OK".
                if let Some(code) = s.split_whitespace().find_map(|w| w.parse::<u16>().ok()) {
                    return Some(code);
                }
            }
        }
    }
    None
}

/// Runs `source` for one request (`response` = None) or response.
pub fn run(
    source: &str,
    request: &Message,
    response: Option<&Message>,
    opts: &Options,
) -> Result<Outcome, Error> {
    let rt = Runtime::new().map_err(|e| Error::Js(e.to_string()))?;
    rt.set_memory_limit(48 << 20);
    rt.set_max_stack_size(1 << 20);
    let deadline = Instant::now() + opts.timeout;
    rt.set_interrupt_handler(Some(Box::new(move || Instant::now() > deadline)));
    let ctx = Context::full(&rt).map_err(|e| Error::Js(e.to_string()))?;

    let store = Arc::clone(&opts.store);
    let name = opts.name.clone();
    let setup = ctx.with(|ctx| -> Result<(), Error> {
        let g = ctx.globals();
        let s1 = Arc::clone(&store);
        let s2 = Arc::clone(&store);
        let setup = || -> rquickjs::Result<()> {
            g.set(
                "__paopao_store_read",
                Function::new(ctx.clone(), move |k: String| s1.read(&k))?,
            )?;
            g.set(
                "__paopao_store_write",
                Function::new(ctx.clone(), move |k: String, v: Option<String>| {
                    s2.write(&k, v)
                })?,
            )?;
            let n = name.clone();
            g.set(
                "__paopao_log",
                Function::new(ctx.clone(), move |level: String, msg: String| {
                    match level.as_str() {
                        "error" => tracing::warn!("script {n}: {msg}"),
                        "warn" | "notify" => tracing::info!("script {n}: {msg}"),
                        _ => tracing::debug!("script {n}: {msg}"),
                    }
                })?,
            )?;
            g.set("$argument", opts.argument.as_str())?;
            let script = Object::new(ctx.clone())?;
            script.set("name", opts.name.as_str())?;
            script.set(
                "type",
                if response.is_some() {
                    "http-response"
                } else {
                    "http-request"
                },
            )?;
            g.set("$script", script)?;
            let env = Object::new(ctx.clone())?;
            env.set("paopao", true)?;
            env.set("surge-version", "5.0")?;
            env.set("language", "zh-Hans")?;
            g.set("$environment", env)?;
            g.set(
                "$request",
                message_obj(&ctx, request, false, opts.binary_body)?,
            )?;
            if let Some(r) = response {
                g.set("$response", message_obj(&ctx, r, true, opts.binary_body)?)?;
            }
            ctx.eval::<(), _>(PRELUDE)?;
            Ok(())
        };
        setup().map_err(|e| js_err(&ctx, &e))?;
        ctx.eval::<(), _>(source).map_err(|e| js_err(&ctx, &e))
    });
    setup.map_err(|e| {
        if Instant::now() > deadline {
            Error::Timeout
        } else {
            e
        }
    })?;

    // Promises / setTimeout: run queued jobs until $done is called.
    loop {
        let called = ctx.with(|ctx| {
            ctx.globals()
                .get::<_, Value>("__paopao_done")
                .is_ok_and(|v| !v.is_undefined())
        });
        if called {
            break;
        }
        if Instant::now() > deadline {
            return Err(Error::Timeout);
        }
        match rt.execute_pending_job() {
            Ok(true) => {}
            // Nothing left to run and no $done: the script left things as
            // they were.
            Ok(false) => return Ok(Outcome::default()),
            Err(e) => return Err(Error::Js(e.to_string())),
        }
    }

    ctx.with(|ctx| {
        let done: Value = ctx
            .globals()
            .get("__paopao_done")
            .map_err(|e| js_err(&ctx, &e))?;
        let Some(o) = done.as_object() else {
            return Ok(Outcome::default());
        };
        let mut out = Outcome::default();
        if let Ok(v) = o.get::<_, Value>("url") {
            out.url = v.as_string().and_then(|s| s.to_string().ok());
        }
        out.status = read_status(o);
        if let Ok(v) = o.get::<_, Value>("headers") {
            out.headers = read_headers(&v);
        }
        if let Ok(v) = o.get::<_, Value>("bodyBytes") {
            out.body = read_body(&v);
        }
        if out.body.is_none() {
            if let Ok(v) = o.get::<_, Value>("body") {
                out.body = read_body(&v);
            }
        }
        if response.is_none() {
            if let Ok(v) = o.get::<_, Value>("response") {
                if let Some(r) = v.as_object() {
                    let mut m = Message {
                        status: read_status(r).unwrap_or(200),
                        ..Message::default()
                    };
                    if let Ok(h) = r.get::<_, Value>("headers") {
                        m.headers = read_headers(&h).unwrap_or_default();
                    }
                    if let Ok(b) = r.get::<_, Value>("body") {
                        m.body = read_body(&b);
                    }
                    out.response = Some(m);
                }
            }
        }
        Ok(out)
    })
}

/// Looks up headers case-insensitively.
pub fn header<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(name))
        .map(|(_, v)| v.as_str())
}

#[cfg(test)]
mod tests;
