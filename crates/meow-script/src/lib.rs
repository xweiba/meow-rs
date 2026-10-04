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
//! - with `binary-body-mode` bodies are `Uint8Array`s, otherwise strings;
//! - `$httpClient.get/post/put/delete/head/patch/options` (Surge / Loon /
//!   Stash, callbacks) and `$task.fetch` (Quantumult X, a promise), sent by
//!   the embedder's [`Options::http`] (meow sends them through itself, so
//!   the rules route them);
//! - `setTimeout` / `setInterval` with real delays (within the deadline);
//! - `$utils.ungzip`.
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
    /// Sends the script's HTTP requests; without it they fail.
    pub http: Option<HttpFn>,
}

/// A request a script sends (`$httpClient`, `$task.fetch`).
#[derive(Clone, Debug, Default)]
pub struct HttpRequest {
    pub method: String,
    pub url: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
    /// What the script allows; never past the script's own deadline.
    pub timeout: Duration,
    /// Follow redirects (the clients do unless told not to).
    pub follow_redirects: bool,
}

/// The answer, body decoded (gzip / deflate undone), as clients hand it
/// to scripts.
#[derive(Clone, Debug, Default)]
pub struct HttpResponse {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

/// Blocking: scripts run on a thread of their own.
pub type HttpFn = Arc<dyn Fn(HttpRequest) -> Result<HttpResponse, String> + Send + Sync>;

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
// The first $done counts (as in Surge): scripts often end with a bare
// $done() in a finally after answering.
var $done = function (v) { if (__paopao_done === undefined) __paopao_done = (v === undefined || v === null) ? {} : v; };
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
// Timers: the run loop calls __paopao_tick when nothing else is pending.
var __paopao_timers = [];
var __paopao_timer_id = 0;
var __paopao_add_timer = function (f, ms, args, every) {
  var id = ++__paopao_timer_id;
  ms = Math.max(0, +ms || 0);
  __paopao_timers.push({ id: id, due: Date.now() + ms, f: f, a: args, every: every ? Math.max(1, ms) : 0 });
  return id;
};
var setTimeout = function (f, ms) { return __paopao_add_timer(f, ms, Array.prototype.slice.call(arguments, 2), false); };
var setInterval = function (f, ms) { return __paopao_add_timer(f, ms, Array.prototype.slice.call(arguments, 2), true); };
var clearTimeout = function (id) { __paopao_timers = __paopao_timers.filter(function (t) { return t.id !== id; }); };
var clearInterval = clearTimeout;
var __paopao_tick = function () {
  var now = Date.now();
  var due = __paopao_timers.filter(function (t) { return t.due <= now; });
  __paopao_timers = __paopao_timers.filter(function (t) { return t.due > now; });
  due.forEach(function (t) {
    if (t.every) { t.due = now + t.every; __paopao_timers.push(t); }
    if (typeof t.f === 'function') t.f.apply(null, t.a);
  });
  if (!__paopao_timers.length) return -1;
  return Math.max(0, Math.min.apply(null, __paopao_timers.map(function (t) { return t.due; })) - Date.now());
};
// HTTP: queued here, sent by the run loop, answered through the callback.
var __paopao_http = [];
var __paopao_http_cbs = {};
var __paopao_http_id = 0;
var __paopao_http_send = function (method, o, cb) {
  if (typeof o === 'string') o = { url: o };
  o = o || {};
  var id = ++__paopao_http_id;
  __paopao_http_cbs[id] = { cb: cb, binary: !!(o['binary-mode'] || o.binaryMode) };
  var body = o.body !== undefined && o.body !== null ? o.body : (o.bodyBytes !== undefined ? o.bodyBytes : '');
  if (body instanceof ArrayBuffer) body = new Uint8Array(body);
  if (typeof body === 'object' && !(body instanceof Uint8Array)) body = JSON.stringify(body);
  __paopao_http.push({
    id: id,
    method: String(o.method || method || 'GET').toUpperCase(),
    url: String(o.url || ''),
    headers: o.headers || {},
    body: body,
    timeout: +o.timeout || 0,
    redirect: !(o['auto-redirect'] === false || (o.opts && o.opts.redirection === false)),
  });
  return id;
};
var __paopao_http_finish = function (id, err, status, headers, text, bytes) {
  var h = __paopao_http_cbs[id];
  delete __paopao_http_cbs[id];
  if (!h || typeof h.cb !== 'function') return;
  if (err) { h.cb(err, null, null); return; }
  var resp = { status: status, statusCode: status, headers: headers, body: h.binary ? bytes : text, bodyBytes: bytes.buffer };
  h.cb(null, resp, h.binary ? bytes : text);
};
var $httpClient = {};
['get', 'post', 'put', 'delete', 'head', 'patch', 'options'].forEach(function (m) {
  $httpClient[m] = function (o, cb) { __paopao_http_send(m, o, cb); };
});
var $task = {
  fetch: function (o) {
    return new Promise(function (resolve, reject) {
      __paopao_http_send((o && o.method) || 'GET', o, function (err, resp) {
        if (err) reject({ error: String(err) }); else resolve(resp);
      });
    });
  },
};
var $utils = { ungzip: function (b) { return new Uint8Array(__paopao_ungzip(b)); } };
// Surge: seconds since the epoch.
$script.startTime = Date.now() / 1000;
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

/// Takes the requests scripts queued.
fn take_http(ctx: &Ctx<'_>) -> Vec<(u32, HttpRequest)> {
    let g = ctx.globals();
    let Ok(queue) = g.get::<_, rquickjs::Array<'_>>("__paopao_http") else {
        return Vec::new();
    };
    if queue.is_empty() {
        return Vec::new();
    }
    let mut out = Vec::new();
    for item in queue.iter::<Object<'_>>().flatten() {
        let id = item.get::<_, u32>("id").unwrap_or(0);
        let text = |k: &str| item.get::<_, String>(k).unwrap_or_default();
        let body = item
            .get::<_, Value<'_>>("body")
            .ok()
            .and_then(|v| read_body(&v))
            .unwrap_or_default();
        let headers = item
            .get::<_, Value<'_>>("headers")
            .ok()
            .and_then(|v| read_headers(&v))
            .unwrap_or_default();
        let secs = item.get::<_, f64>("timeout").unwrap_or(0.0);
        out.push((
            id,
            HttpRequest {
                method: text("method"),
                url: text("url"),
                headers,
                body,
                timeout: if secs > 0.0 {
                    Duration::from_secs_f64(secs)
                } else {
                    Duration::ZERO
                },
                follow_redirects: item.get::<_, bool>("redirect").unwrap_or(true),
            },
        ));
    }
    let _ = g.set("__paopao_http", rquickjs::Array::new(ctx.clone()));
    out
}

fn finish_http(
    ctx: &Ctx<'_>,
    id: u32,
    answer: Result<HttpResponse, String>,
) -> rquickjs::Result<()> {
    let finish: Function<'_> = ctx.globals().get("__paopao_http_finish")?;
    match answer {
        Ok(r) => {
            let text = String::from_utf8_lossy(&r.body).into_owned();
            let bytes = TypedArray::<u8>::new(ctx.clone(), r.body)?;
            finish.call::<_, ()>((
                id,
                Value::new_null(ctx.clone()),
                r.status,
                headers_obj(ctx, &r.headers)?,
                text,
                bytes,
            ))
        }
        Err(e) => finish.call::<_, ()>((
            id,
            e,
            0,
            Value::new_null(ctx.clone()),
            "",
            Value::new_null(ctx.clone()),
        )),
    }
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
            g.set(
                "__paopao_ungzip",
                Function::new(ctx.clone(), |v: Value<'_>| {
                    use std::io::Read as _;
                    let input = read_body(&v).unwrap_or_default();
                    let mut out = Vec::new();
                    let _ = flate2::read::MultiGzDecoder::new(&input[..]).read_to_end(&mut out);
                    out
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

    // The event loop: promise jobs, then the script's HTTP requests, then
    // timers, until $done is called (or nothing is left to wait for).
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
            Ok(true) => continue,
            Ok(false) => {}
            Err(e) => return Err(Error::Js(e.to_string())),
        }
        let sends = ctx.with(|ctx| take_http(&ctx));
        if !sends.is_empty() {
            for (id, mut req) in sends {
                let left = deadline.saturating_duration_since(Instant::now());
                req.timeout = if req.timeout.is_zero() {
                    left
                } else {
                    req.timeout.min(left)
                };
                let answer = match &opts.http {
                    Some(f) => f(req),
                    None => Err("scripts may not use the network here".into()),
                };
                ctx.with(|ctx| finish_http(&ctx, id, answer).map_err(|e| js_err(&ctx, &e)))?;
            }
            continue;
        }
        let next = ctx.with(|ctx| -> Result<f64, Error> {
            let tick: Function<'_> = ctx
                .globals()
                .get("__paopao_tick")
                .map_err(|e| js_err(&ctx, &e))?;
            tick.call::<_, f64>(()).map_err(|e| js_err(&ctx, &e))
        })?;
        if next < 0.0 {
            // A timer that just ran may have called $done, queued jobs or
            // requests: look again before calling it a day.
            let more = ctx.with(|ctx| {
                let g = ctx.globals();
                g.get::<_, Value>("__paopao_done")
                    .is_ok_and(|v| !v.is_undefined())
                    || g.get::<_, rquickjs::Array<'_>>("__paopao_http")
                        .is_ok_and(|q| !q.is_empty())
            }) || rt.is_job_pending();
            if more {
                continue;
            }
            // Nothing left to wait for and no $done: the script left
            // things as they were.
            return Ok(Outcome::default());
        }
        let left = deadline.saturating_duration_since(Instant::now());
        let wait = Duration::from_millis(next as u64);
        if !wait.is_zero() {
            std::thread::sleep(wait.min(left));
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
        // Response scripts may also hand the changed response back as
        // `$done({response: {...}})` (Surge / Shadowrocket accept it; the
        // common script framework does it): read the fields from there.
        let nested = response
            .is_some()
            .then(|| o.get::<_, Value>("response").ok())
            .flatten()
            .and_then(Value::into_object);
        let o = nested.as_ref().unwrap_or(o);
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
                    m.body = r
                        .get::<_, Value>("bodyBytes")
                        .ok()
                        .and_then(|b| read_body(&b))
                        .or_else(|| r.get::<_, Value>("body").ok().and_then(|b| read_body(&b)));
                    out.response = Some(m);
                }
            }
            // Quantumult X answers a request with `$done({status, headers,
            // body})` (status like "HTTP/1.1 200 OK"); scripts that take
            // us for QX (we have $task) do so.
            if out.response.is_none() {
                if let Some(status) = out.status {
                    out.response = Some(Message {
                        status,
                        headers: out.headers.take().unwrap_or_default(),
                        body: out.body.take(),
                        ..Message::default()
                    });
                    out.status = None;
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
