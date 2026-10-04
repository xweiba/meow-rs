use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use meow_common::{
    AdapterType, DelayHistory, MeowError, Metadata, Proxy, ProxyAdapter, ProxyConn, ProxyHealth,
    ProxyPacketConn, Result,
};
use tokio::io::{AsyncRead, AsyncWrite, DuplexStream, ReadBuf};

use super::*;

/// A connection that answers whatever is written to it (an echo server on
/// the other end of an in-memory pipe).
struct Echo(DuplexStream);

impl AsyncRead for Echo {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.0).poll_read(cx, buf)
    }
}

impl AsyncWrite for Echo {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        std::pin::Pin::new(&mut self.0).poll_write(cx, buf)
    }
    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.0).poll_flush(cx)
    }
    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.0).poll_shutdown(cx)
    }
}

impl ProxyConn for Echo {}

/// A line that connects after `delay`, or fails while `down`.
struct Line {
    name: String,
    delay: Duration,
    down: AtomicBool,
    dials: AtomicUsize,
    health: ProxyHealth,
}

impl Line {
    fn new(name: &str, delay_ms: u64) -> Arc<Self> {
        Arc::new(Self {
            name: name.into(),
            delay: Duration::from_millis(delay_ms),
            down: AtomicBool::new(false),
            dials: AtomicUsize::new(0),
            health: ProxyHealth::new(),
        })
    }
}

#[async_trait]
impl ProxyAdapter for Line {
    fn name(&self) -> &str {
        &self.name
    }
    fn adapter_type(&self) -> AdapterType {
        AdapterType::Direct
    }
    fn addr(&self) -> &str {
        ""
    }
    fn support_udp(&self) -> bool {
        false
    }
    async fn dial_tcp(&self, _m: &Metadata) -> Result<Box<dyn ProxyConn>> {
        self.dials.fetch_add(1, Ordering::Relaxed);
        tokio::time::sleep(self.delay).await;
        if self.down.load(Ordering::Relaxed) {
            return Err(MeowError::Proxy(format!("{} is down", self.name)));
        }
        let (a, mut b) = tokio::io::duplex(1024);
        tokio::spawn(async move {
            let mut buf = [0u8; 64];
            while let Ok(n) = tokio::io::AsyncReadExt::read(&mut b, &mut buf).await {
                if n == 0 {
                    break;
                }
                let _ = tokio::io::AsyncWriteExt::write_all(&mut b, &buf[..n]).await;
            }
        });
        Ok(Box::new(Echo(a)))
    }
    async fn dial_udp(&self, _m: &Metadata) -> Result<Box<dyn ProxyPacketConn>> {
        Err(MeowError::NotSupported("udp".into()))
    }
    fn health(&self) -> &ProxyHealth {
        &self.health
    }
}

impl Proxy for Line {
    fn alive(&self) -> bool {
        true
    }
    fn alive_for_url(&self, _url: &str) -> bool {
        true
    }
    fn last_delay(&self) -> u16 {
        0
    }
    fn last_delay_for_url(&self, _url: &str) -> u16 {
        0
    }
    fn delay_history(&self) -> Vec<DelayHistory> {
        Vec::new()
    }
}

fn group(lines: &[Arc<Line>]) -> SmartGroup {
    let members: Vec<Arc<dyn Proxy>> = lines
        .iter()
        .map(|l| Arc::clone(l) as Arc<dyn Proxy>)
        .collect();
    // No runtime probing in tests: build without the upkeep task.
    SmartGroup {
        shared: Arc::new(Shared {
            name: "auto".into(),
            members,
            store: Store::new(None),
            test_url: "http://127.0.0.1:9/".into(),
            now: RwLock::new(None),
            health: ProxyHealth::new(),
            usage: UsageTracker::new(),
            reprobe: AtomicI64::new(i64::MAX),
            loads: Loads::default(),
        }),
    }
}

fn site(host: &str) -> Metadata {
    Metadata {
        host: host.into(),
        dst_port: 443,
        ..Default::default()
    }
}

async fn roundtrip(g: &SmartGroup, host: &str) -> Result<String> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut c = g.dial_tcp(&site(host)).await?;
    c.write_all(b"hi").await.unwrap();
    let mut buf = [0u8; 2];
    c.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"hi");
    drop(c);
    // Let the reporting tasks run.
    tokio::time::sleep(Duration::from_millis(30)).await;
    Ok(g.current().unwrap())
}

#[tokio::test]
async fn new_site_races_and_the_fastest_wins_then_sticks() {
    let fast = Line::new("fast", 5);
    let slow = Line::new("slow", 120);
    let g = group(&[Arc::clone(&slow), Arc::clone(&fast)]);
    assert_eq!(roundtrip(&g, "www.example.com").await.unwrap(), "fast");
    // Known now: the next dials use it alone (no more racing the slow one).
    let before = slow.dials.load(Ordering::Relaxed);
    for _ in 0..5 {
        assert_eq!(roundtrip(&g, "img.example.com").await.unwrap(), "fast");
    }
    assert!(
        slow.dials.load(Ordering::Relaxed) - before <= 1,
        "still racing the slow line"
    );
    assert_eq!(
        g.unwrap_proxy(&site("example.com"), false).unwrap().name(),
        "fast"
    );
}

#[tokio::test]
async fn a_dead_line_fails_over_and_sits_out() {
    let a = Line::new("a", 5);
    let b = Line::new("b", 30);
    let g = group(&[Arc::clone(&a), Arc::clone(&b)]);
    assert_eq!(roundtrip(&g, "x.com").await.unwrap(), "a");
    a.down.store(true, Ordering::Relaxed);
    for host in ["x.com", "y.com", "z.com", "w.com"] {
        assert_eq!(roundtrip(&g, host).await.unwrap(), "b", "{host}");
    }
    assert!(
        g.bans().contains_key("a"),
        "three failures in a row: banned"
    );
    let dials = a.dials.load(Ordering::Relaxed);
    roundtrip(&g, "v.com").await.unwrap();
    assert_eq!(
        a.dials.load(Ordering::Relaxed),
        dials,
        "a banned line isn't dialed"
    );
}

#[tokio::test]
async fn every_line_down_refuses_never_around_the_proxy() {
    let a = Line::new("a", 1);
    let b = Line::new("b", 1);
    a.down.store(true, Ordering::Relaxed);
    b.down.store(true, Ordering::Relaxed);
    let g = group(&[a, b]);
    for _ in 0..4 {
        assert!(g.dial_tcp(&site("bilibili.com")).await.is_err());
    }
    // All banned: refused at once, without dialing anything.
    let start = Instant::now();
    let err = g.dial_tcp(&site("bilibili.com")).await.err().unwrap();
    assert!(start.elapsed() < Duration::from_millis(50));
    assert!(err.to_string().contains("no line available"), "{err}");
}

#[test]
fn trace_parsing() {
    let e = parse_trace("fl=1\nip=203.0.113.9\nloc=JP\ntls=off\n").unwrap();
    assert_eq!(e.ip, "203.0.113.9");
    assert_eq!(e.country, "JP");
    assert!(parse_trace("nothing").is_none());
}
