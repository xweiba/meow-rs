//! Shared test scaffolding: a scripted local HTTP server, a connector that
//! sends every host to it, and a clock the test moves by hand. Nothing
//! here leaves the machine.
#![allow(dead_code, reason = "each test binary uses a different part")]

use async_trait::async_trait;
use meow_checkin::clock::Clock;
use meow_checkin::http::{BoxStream, Connector};
use meow_checkin::{Access, Engine, EngineConfig};
use parking_lot::Mutex;
use serde_json::{json, Value};
use std::fmt::Write as _;
use std::io;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;
use time::{OffsetDateTime, UtcOffset};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::TcpListener;

#[derive(Clone, Debug)]
pub struct Seen {
    pub method: String,
    pub path: String,
    pub headers: Vec<(String, String)>,
    pub body: String,
    /// The raw request head, to look for injected lines.
    pub raw_head: String,
}

impl Seen {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    pub fn host(&self) -> &str {
        self.header("host").unwrap_or("")
    }
}

#[derive(Clone, Debug)]
pub struct Reply {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
    pub delay: Duration,
}

impl Reply {
    pub fn json(status: u16, body: &str) -> Self {
        Self {
            status,
            headers: vec![("Content-Type".into(), "application/json".into())],
            body: body.as_bytes().to_vec(),
            delay: Duration::ZERO,
        }
    }

    pub fn html(status: u16, body: &str) -> Self {
        Self {
            status,
            headers: vec![("Content-Type".into(), "text/html; charset=utf-8".into())],
            body: body.as_bytes().to_vec(),
            delay: Duration::ZERO,
        }
    }

    pub fn redirect(status: u16, location: &str) -> Self {
        Self {
            status,
            headers: vec![("Location".into(), location.into())],
            body: Vec::new(),
            delay: Duration::ZERO,
        }
    }

    pub fn with_header(mut self, name: &str, value: &str) -> Self {
        self.headers.push((name.into(), value.into()));
        self
    }

    pub fn after(mut self, delay: Duration) -> Self {
        self.delay = delay;
        self
    }
}

type Handler = Arc<dyn Fn(&Seen) -> Reply + Send + Sync>;

/// A local HTTP server that answers what the test scripted and remembers
/// what it was sent.
pub struct Server {
    pub addr: SocketAddr,
    seen: Arc<Mutex<Vec<Seen>>>,
    active: Arc<AtomicUsize>,
    max_active: Arc<AtomicUsize>,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for Server {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl Server {
    pub async fn start(handler: impl Fn(&Seen) -> Reply + Send + Sync + 'static) -> Self {
        let handler: Handler = Arc::new(handler);
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let seen = Arc::new(Mutex::new(Vec::new()));
        let active = Arc::new(AtomicUsize::new(0));
        let max_active = Arc::new(AtomicUsize::new(0));
        let task = {
            let (seen, active, max_active) = (
                Arc::clone(&seen),
                Arc::clone(&active),
                Arc::clone(&max_active),
            );
            tokio::spawn(async move {
                loop {
                    let Ok((mut sock, _)) = listener.accept().await else {
                        return;
                    };
                    let handler = Arc::clone(&handler);
                    let (seen, active, max_active) = (
                        Arc::clone(&seen),
                        Arc::clone(&active),
                        Arc::clone(&max_active),
                    );
                    tokio::spawn(async move {
                        let Some(request) = read_request(&mut sock).await else {
                            return;
                        };
                        let now = active.fetch_add(1, Ordering::SeqCst) + 1;
                        max_active.fetch_max(now, Ordering::SeqCst);
                        seen.lock().push(request.clone());
                        let reply = handler(&request);
                        tokio::time::sleep(reply.delay).await;
                        let mut head = format!("HTTP/1.1 {} X\r\n", reply.status);
                        for (n, v) in &reply.headers {
                            let _ = write!(head, "{n}: {v}\r\n");
                        }
                        let _ = write!(
                            head,
                            "Content-Length: {}

",
                            reply.body.len()
                        );
                        let _ = sock.write_all(head.as_bytes()).await;
                        let _ = sock.write_all(&reply.body).await;
                        let _ = sock.shutdown().await;
                        active.fetch_sub(1, Ordering::SeqCst);
                    });
                }
            })
        };
        Self {
            addr,
            seen,
            active,
            max_active,
            task,
        }
    }

    pub fn seen(&self) -> Vec<Seen> {
        self.seen.lock().clone()
    }

    pub fn paths(&self) -> Vec<String> {
        self.seen.lock().iter().map(|s| s.path.clone()).collect()
    }

    /// The most requests ever in flight at once.
    pub fn max_active(&self) -> usize {
        self.max_active.load(Ordering::SeqCst)
    }
}

async fn read_request(sock: &mut tokio::net::TcpStream) -> Option<Seen> {
    let mut buf = Vec::new();
    let mut tmp = [0u8; 4096];
    let head_end = loop {
        if let Some(at) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break at + 4;
        }
        let n = sock.read(&mut tmp).await.ok()?;
        if n == 0 {
            return None;
        }
        buf.extend_from_slice(&tmp[..n]);
    };
    let raw_head = String::from_utf8_lossy(&buf[..head_end]).to_string();
    let mut lines = raw_head.split("\r\n");
    let mut request_line = lines.next()?.split(' ');
    let method = request_line.next()?.to_string();
    let path = request_line.next()?.to_string();
    let headers: Vec<(String, String)> = lines
        .filter_map(|l| l.split_once(':'))
        .map(|(n, v)| (n.trim().to_string(), v.trim().to_string()))
        .collect();
    let length: usize = headers
        .iter()
        .find(|(n, _)| n.eq_ignore_ascii_case("content-length"))
        .and_then(|(_, v)| v.parse().ok())
        .unwrap_or(0);
    while buf.len() < head_end + length {
        let n = sock.read(&mut tmp).await.ok()?;
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&tmp[..n]);
    }
    Some(Seen {
        method,
        path,
        headers,
        body: String::from_utf8_lossy(&buf[head_end..]).to_string(),
        raw_head,
    })
}

/// Sends every host to the local server, remembering who was asked for.
pub struct LocalConnector {
    addr: SocketAddr,
    pub dialed: Mutex<Vec<(Access, String, u16)>>,
    /// The policy of every dial, in the order of `dialed`.
    pub policies: Mutex<Vec<Option<String>>>,
    /// Names answered with [`meow_checkin::http::unknown_policy`].
    pub unknown: Mutex<Vec<String>>,
}

impl LocalConnector {
    pub fn new(addr: SocketAddr) -> Arc<Self> {
        Arc::new(Self {
            addr,
            dialed: Mutex::new(Vec::new()),
            policies: Mutex::new(Vec::new()),
            unknown: Mutex::new(Vec::new()),
        })
    }

    /// As the engine takes it.
    pub fn shared(self: &Arc<Self>) -> Arc<dyn Connector> {
        Arc::<Self>::clone(self)
    }

    pub fn hosts(&self) -> Vec<String> {
        self.dialed.lock().iter().map(|d| d.1.clone()).collect()
    }
}

#[async_trait]
impl Connector for LocalConnector {
    async fn connect(
        &self,
        access: Access,
        policy: Option<&str>,
        host: &str,
        port: u16,
        _allow_private: bool,
    ) -> io::Result<BoxStream> {
        self.dialed.lock().push((access, host.to_string(), port));
        self.policies.lock().push(policy.map(str::to_string));
        if policy.is_some_and(|p| self.unknown.lock().iter().any(|u| u == p)) {
            return Err(meow_checkin::http::unknown_policy());
        }
        Ok(Box::new(tokio::net::TcpStream::connect(self.addr).await?))
    }
}

/// A clock that only moves when the test says so.
pub struct FakeClock {
    now: Mutex<OffsetDateTime>,
    offset: UtcOffset,
}

impl FakeClock {
    /// `local` is the wall-clock time on the machine; its offset is the
    /// machine's time zone.
    pub fn at(local: OffsetDateTime) -> Arc<Self> {
        Arc::new(Self {
            offset: local.offset(),
            now: Mutex::new(local),
        })
    }

    /// As the engine takes it.
    pub fn shared(self: &Arc<Self>) -> Arc<dyn Clock> {
        Arc::<Self>::clone(self)
    }

    pub fn set(&self, local: OffsetDateTime) {
        *self.now.lock() = local;
    }

    pub fn advance(&self, by: time::Duration) {
        let mut now = self.now.lock();
        *now += by;
    }
}

impl Clock for FakeClock {
    fn now_utc(&self) -> OffsetDateTime {
        self.now.lock().to_offset(UtcOffset::UTC)
    }

    fn local_offset(&self, _at: OffsetDateTime) -> UtcOffset {
        self.offset
    }
}

pub fn quick_config() -> EngineConfig {
    EngineConfig {
        attach_wait: Duration::from_millis(60),
        click_timeout_ms: 300,
        // Generous: an app that does report must never lose a race against
        // this on a busy machine. The test of a silent app sets its own.
        click_report_grace: Duration::from_secs(20),
        ..EngineConfig::default()
    }
}

/// A task with a cookie variable (filled) and the given steps.
#[allow(
    clippy::needless_pass_by_value,
    reason = "call sites pass a json! literal"
)]
pub fn add_task(engine: &Engine, name: &str, home: &str, steps: Value) -> String {
    let task = engine
        .create_task(
            &json!({"name": name, "home": home, "access": "direct",
                    "minute_of_day": 510, "enabled": true}),
            false,
        )
        .unwrap();
    engine
        .save_variable(
            &task.id,
            "cookie",
            &json!({"name": "cookie", "source": "auto", "from": "cookie_header"}),
            false,
        )
        .unwrap();
    engine
        .push_variables(
            &task.id,
            &json!({"values": {"cookie": "sid=abc==; uid=7"}, "user_agent": "Mozilla/5.0 Test"}),
        )
        .unwrap();
    engine
        .save_steps(&task.id, &json!({ "steps": steps }), false)
        .unwrap();
    task.id
}

pub fn api_step(name: &str, url: &str, page: &str) -> Value {
    json!({
        "id": "", "kind": "api", "name": name, "method": "POST", "url": url,
        "headers": {"cookie": "{cookie}", "x-requested-with": "XMLHttpRequest"},
        "body": "a=1", "body_base64": false, "page": page,
        "recorded_status": 200, "recorded_content_type": "application/json"
    })
}

pub fn click_step(name: &str, page: &str) -> Value {
    json!({
        "id": "", "kind": "click", "name": name, "page": page,
        "locators": [{"kind": "role_text", "value": name}], "text": name, "tag": "button"
    })
}
