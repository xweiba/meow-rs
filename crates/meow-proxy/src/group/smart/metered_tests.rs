use std::sync::{Arc, Mutex};

use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};

use super::*;

const KIB: u64 = 1024;

/// Feeds `pace` `chunk` bytes every `every` for `total` bytes, from `t`;
/// returns the events and the time after the last read.
fn stream(
    pace: &mut Pace,
    t: Instant,
    chunk: u64,
    every: Duration,
    total: u64,
    events: &mut Vec<Live>,
) -> Instant {
    let mut now = t;
    let mut sent = 0;
    while sent < total {
        now += every;
        pace.on_read(now, chunk, &mut |e| events.push(e));
        sent += chunk;
    }
    now
}

fn slow_count(events: &[Live]) -> usize {
    events
        .iter()
        .filter(|e| matches!(e, Live::Slow { .. }))
        .count()
}

#[test]
fn a_steady_slow_download_is_called_slow_once() {
    let mut pace = Pace::default();
    let mut ev = Vec::new();
    // 100 KiB/s: 10 KiB every 100 ms, for a minute (6 MB).
    stream(
        &mut pace,
        Instant::now(),
        10 * KIB,
        Duration::from_millis(100),
        6000 * KIB,
        &mut ev,
    );
    assert_eq!(slow_count(&ev), 1, "{ev:?}");
    let rate = pace.last_rate().unwrap();
    assert!((rate - 102_400.0).abs() < 5_000.0, "{rate}");
}

#[test]
fn small_transfers_are_never_slow() {
    let mut pace = Pace::default();
    let mut ev = Vec::new();
    // 900 KiB at 10 KiB/s: very slow, but not a download.
    stream(
        &mut pace,
        Instant::now(),
        KIB,
        Duration::from_millis(100),
        900 * KIB,
        &mut ev,
    );
    assert!(ev.is_empty(), "{ev:?}");
}

#[test]
fn idle_gaps_do_not_count_as_time() {
    let mut pace = Pace::default();
    let mut ev = Vec::new();
    let mut t = Instant::now();
    // A player: 2 MiB segments at 2 MiB/s (64 KiB every 31 ms), then the
    // buffer is full and it waits 5 s, again and again.
    for _ in 0..20 {
        t = stream(
            &mut pace,
            t,
            64 * KIB,
            Duration::from_millis(31),
            2048 * KIB,
            &mut ev,
        );
        t += Duration::from_secs(5);
    }
    assert_eq!(slow_count(&ev), 0, "{ev:?}");
    let rate = pace.last_rate().unwrap();
    assert!(rate > 1_500_000.0, "pauses counted as time: {rate}");
}

#[test]
fn fast_then_idle_is_not_slow() {
    let mut pace = Pace::default();
    let mut ev = Vec::new();
    // 5 MiB at 10 MiB/s, then only keep-alive crumbs a second apart.
    let mut t = stream(
        &mut pace,
        Instant::now(),
        100 * KIB,
        Duration::from_millis(10),
        5 * 1024 * KIB,
        &mut ev,
    );
    for _ in 0..120 {
        t += Duration::from_secs(1);
        pace.on_read(t, 40, &mut |e| ev.push(e));
    }
    assert_eq!(slow_count(&ev), 0, "{ev:?}");
}

#[test]
fn long_downloads_report_samples_along_the_way() {
    let mut pace = Pace::default();
    let mut ev = Vec::new();
    // 1 MiB/s for about 70 s: two 30 s samples.
    stream(
        &mut pace,
        Instant::now(),
        100 * KIB,
        Duration::from_millis(100),
        70 * 1024 * KIB,
        &mut ev,
    );
    let samples: Vec<(u64, f64)> = ev
        .iter()
        .filter_map(|e| match e {
            Live::Sample { bytes, active_ms } => Some((*bytes, *active_ms)),
            _ => None,
        })
        .collect();
    assert_eq!(samples.len(), 2, "{ev:?}");
    for (bytes, ms) in &samples {
        let rate = *bytes as f64 / (ms / 1000.0);
        assert!((rate - 1_048_576.0).abs() < 50_000.0, "{rate}");
    }
    assert_eq!(pace.sampled, samples.iter().map(|s| s.0).sum::<u64>());
}

/// A connection over an in-memory pipe whose far end the test drives.
struct Pipe(DuplexStream);

impl AsyncRead for Pipe {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.0).poll_read(cx, buf)
    }
}

impl AsyncWrite for Pipe {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.0).poll_write(cx, buf)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.0).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.0).poll_shutdown(cx)
    }
}

impl ProxyConn for Pipe {}

type Seen = Arc<Mutex<(Vec<Outcome>, Vec<Live>)>>;

fn metered() -> (MeteredConn, DuplexStream, Seen) {
    let (a, b) = tokio::io::duplex(4 << 20);
    let seen: Seen = Arc::default();
    let (s1, s2) = (Arc::clone(&seen), Arc::clone(&seen));
    let conn = MeteredConn::new(Box::new(Pipe(a)), Duration::from_millis(50), move |o| {
        s1.lock().unwrap().0.push(o);
    })
    .watching(move |e| s2.lock().unwrap().1.push(e));
    (conn, b, seen)
}

#[tokio::test(start_paused = true)]
async fn no_first_byte_in_time_fails_at_once_and_only_once() {
    let (mut c, _far, seen) = metered();
    c.write_all(b"GET / HTTP/1.1\r\n\r\n").await.unwrap();
    let mut buf = [0u8; 16];
    let r = tokio::time::timeout(
        FIRST_BYTE_TIMEOUT + Duration::from_secs(1),
        c.read(&mut buf),
    )
    .await;
    assert!(r.is_err(), "nothing came");
    {
        let s = seen.lock().unwrap();
        assert_eq!(s.0.len(), 1);
        assert!(s.0[0].failed);
        assert_eq!(s.1, vec![Live::Stalled]);
    }
    drop(c);
    assert_eq!(seen.lock().unwrap().0.len(), 1, "no second report at close");
}

#[tokio::test(start_paused = true)]
async fn a_bulk_transfer_stalling_while_the_client_waits_fails() {
    let (mut c, mut far, seen) = metered();
    far.write_all(&vec![7u8; 2 << 20]).await.unwrap();
    let mut buf = vec![0u8; 64 * 1024];
    let mut got = 0;
    while got < 2 << 20 {
        got += c.read(&mut buf).await.unwrap();
    }
    // The client stays quiet: an idle connection, not a stall.
    assert!(tokio::time::timeout(STALL * 3, c.read(&mut buf))
        .await
        .is_err());
    assert!(seen.lock().unwrap().0.is_empty(), "idle is no failure");
    // It asks for more and nothing comes.
    c.write_all(b"more").await.unwrap();
    assert!(
        tokio::time::timeout(STALL + Duration::from_secs(1), c.read(&mut buf))
            .await
            .is_err()
    );
    let s = seen.lock().unwrap();
    assert_eq!(s.0.len(), 1);
    assert!(s.0[0].failed);
    assert_eq!(s.1, vec![Live::Stalled]);
}

#[tokio::test(start_paused = true)]
async fn the_close_report_leaves_out_what_samples_carried() {
    let (mut c, mut far, seen) = metered();
    let writer = tokio::spawn(async move {
        // 1 MiB/s for 45 s, steady.
        for _ in 0..450 {
            far.write_all(&[1u8; 100 * 1024]).await.unwrap();
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        far
    });
    let mut buf = vec![0u8; 256 * 1024];
    let mut got = 0u64;
    while got < 450 * 100 * 1024 {
        got += c.read(&mut buf).await.unwrap() as u64;
    }
    let _far = writer.await.unwrap();
    drop(c);
    let s = seen.lock().unwrap();
    let sampled: u64 =
        s.1.iter()
            .map(|e| match e {
                Live::Sample { bytes, .. } => *bytes,
                _ => 0,
            })
            .sum();
    assert!(sampled > 0, "{:?}", s.1);
    assert_eq!(s.0.len(), 1);
    assert_eq!(s.0[0].bytes + sampled, got, "every byte counted once");
}
