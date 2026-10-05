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

/// A line that connects after `delay`, fails while `down`, never answers
/// while `hang`.
struct Line {
    name: String,
    delay: Duration,
    down: AtomicBool,
    hang: AtomicBool,
    dials: AtomicUsize,
    health: ProxyHealth,
}

impl Line {
    fn new(name: &str, delay_ms: u64) -> Arc<Self> {
        Arc::new(Self {
            name: name.into(),
            delay: Duration::from_millis(delay_ms),
            down: AtomicBool::new(false),
            hang: AtomicBool::new(false),
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
        if self.hang.load(Ordering::Relaxed) {
            std::future::pending::<()>().await;
        }
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
            started: std::sync::atomic::AtomicBool::new(true),
            // Echo lines answer a GET with the GET: a quick failed test.
            speed_url: "http://127.0.0.1:9/__down".into(),
            speed_tests: Arc::new(Semaphore::new(SPEED_PROBE_CONCURRENCY)),
            sticky: AtomicBool::new(false),
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

/// Pins `host`'s family to `pin`, every line known good there.
fn pinned(g: &SmartGroup, host: &str, pin: &str, lines: &[&Arc<Line>]) {
    let store = &g.shared.store;
    for l in lines {
        store.report(
            "",
            &l.name,
            &Outcome {
                first_ms: 100.0,
                ..Outcome::default()
            },
        );
        store.report(
            &site_key(host),
            &l.name,
            &Outcome {
                first_ms: 100.0,
                ..Outcome::default()
            },
        );
    }
    store.use_line(&site_key(host), pin);
}

#[tokio::test(start_paused = true)]
async fn a_dead_pinned_line_is_hedged_within_the_deadline() {
    let a = Line::new("a", 5);
    let b = Line::new("b", 20);
    a.hang.store(true, Ordering::Relaxed);
    let g = group(&[Arc::clone(&a), Arc::clone(&b)]);
    pinned(&g, "rr1.googlevideo.com", "a", &[&a, &b]);
    let start = tokio::time::Instant::now();
    let c =
        meow_common::with_dial_timeout("policy:youtube", g.dial_tcp(&site("rr1.googlevideo.com")))
            .await
            .expect("the hedge connects before the caller's deadline");
    drop(c);
    let took = start.elapsed();
    assert!(
        took >= HEDGE_AFTER && took < HEDGE_AFTER + Duration::from_millis(100),
        "{took:?}"
    );
    assert_eq!(g.current().unwrap(), "b");
    // The family moved to the line that answered.
    assert_eq!(
        g.unwrap_proxy(&site("youtube.com"), false).unwrap().name(),
        "b"
    );
}

#[tokio::test(start_paused = true)]
async fn every_line_hanging_still_answers_before_the_callers_deadline() {
    let a = Line::new("a", 5);
    let b = Line::new("b", 5);
    a.hang.store(true, Ordering::Relaxed);
    b.hang.store(true, Ordering::Relaxed);
    let g = group(&[Arc::clone(&a), Arc::clone(&b)]);
    pinned(&g, "x.com", "a", &[&a, &b]);
    let err = meow_common::with_dial_timeout("auto", g.dial_tcp(&site("x.com")))
        .await
        .err()
        .unwrap();
    assert!(err.to_string().contains("all lines failed"), "{err}");
}

#[tokio::test(start_paused = true)]
async fn a_line_connecting_before_the_hedge_time_goes_alone() {
    let a = Line::new("a", 1000);
    let b = Line::new("b", 5);
    let g = group(&[Arc::clone(&a), Arc::clone(&b)]);
    pinned(&g, "x.com", "a", &[&a, &b]);
    let before = b.dials.load(Ordering::Relaxed);
    assert_eq!(roundtrip(&g, "x.com").await.unwrap(), "a");
    tokio::time::sleep(HEDGE_AFTER * 2).await;
    assert_eq!(b.dials.load(Ordering::Relaxed), before, "no hedge");
}

#[tokio::test(start_paused = true)]
async fn a_merely_slower_loser_is_no_failure() {
    let a = Line::new("a", 2000);
    let b = Line::new("b", 10);
    let g = group(&[Arc::clone(&a), Arc::clone(&b)]);
    pinned(&g, "x.com", "a", &[&a, &b]);
    assert_eq!(roundtrip(&g, "x.com").await.unwrap(), "b");
    // a connects later, in the background.
    tokio::time::sleep(Duration::from_secs(3)).await;
    assert!(g.bans().is_empty());
    let rec = g.snapshot("x.com")["a"];
    assert_eq!(rec.failure, 0.0, "{rec:?}");
    assert_eq!(rec.success, 2.0, "{rec:?}");
}

#[tokio::test]
async fn a_slow_line_moves_the_site_and_tests_others_once() {
    let a = Line::new("a", 1);
    let b = Line::new("b", 1);
    let c = Line::new("c", 1);
    let g = group(&[Arc::clone(&a), Arc::clone(&b), Arc::clone(&c)]);
    pinned(&g, "googlevideo.com", "a", &[&a, &b, &c]);
    let dials = |l: &Arc<Line>| l.dials.load(Ordering::Relaxed);
    let before = (dials(&a), dials(&b), dials(&c));
    let me = &g.shared;
    me.live("googlevideo.com", "a", Live::Slow { rate: 90_000.0 });
    tokio::time::sleep(Duration::from_millis(100)).await;
    me.live("googlevideo.com", "a", Live::Slow { rate: 80_000.0 });
    me.live("googlevideo.com", "a", Live::Stalled);
    tokio::time::sleep(Duration::from_millis(100)).await;
    // One speed test of the others, never of the slow line.
    assert_eq!(
        (dials(&a), dials(&b), dials(&c)),
        (before.0, before.1 + 1, before.2 + 1)
    );
    assert!(g.slow("rr3.googlevideo.com").contains_key("a"));
    // The family let go of a; its next connection goes elsewhere.
    assert_ne!(roundtrip(&g, "youtube.com").await.unwrap(), "a");
    assert!(g.bans().is_empty(), "slow is not banned");
}

#[tokio::test]
async fn sticky_keeps_every_site_on_one_line_and_moves_them_together() {
    let a = Line::new("a", 5);
    let b = Line::new("b", 30);
    let g = group(&[Arc::clone(&a), Arc::clone(&b)]).sticky();
    assert_eq!(roundtrip(&g, "chatgpt.com").await.unwrap(), "a");
    // A helper of another company (the captcha): on the same line, and
    // dialed there alone (no race that could land it elsewhere).
    let helper = site("challenges.cloudflare.com");
    assert_eq!(g.unwrap_proxy(&helper, false).unwrap().name(), "a");
    let before = b.dials.load(Ordering::Relaxed);
    assert_eq!(
        roundtrip(&g, "challenges.cloudflare.com").await.unwrap(),
        "a"
    );
    assert_eq!(
        b.dials.load(Ordering::Relaxed),
        before,
        "raced another line"
    );
    // The line fails: the whole group moves, together.
    a.down.store(true, Ordering::Relaxed);
    assert_eq!(roundtrip(&g, "chatgpt.com").await.unwrap(), "b");
    assert_eq!(g.unwrap_proxy(&helper, false).unwrap().name(), "b");
}
