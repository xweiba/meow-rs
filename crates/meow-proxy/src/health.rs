use futures::{future::BoxFuture, stream::FuturesUnordered, FutureExt, StreamExt};
use meow_common::{Proxy, ProxyAdapter};
use meow_transport::tls::{TlsConfig, TlsLayer};
use meow_transport::Transport as _;
use smol_str::SmolStr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::Semaphore;
use tracing::{debug, trace, warn};

pub use meow_common::ProxyHealth;

pub const GROUP_DELAY_CONCURRENCY: usize = 16;
pub const PROVIDER_HEALTHCHECK_CONCURRENCY: usize = 10;
pub const GLOBAL_DELAY_PROBE_CONCURRENCY: usize = 32;

#[derive(Debug)]
pub struct NamedProbeResult {
    pub name: String,
    pub delay: u16,
    pub error: Option<UrlTestError>,
}

/// Outcome of a single [`url_test`] probe. Callers distinguish transport
/// failure from deadline expiry to pick the right HTTP status code
/// (upstream: 503 vs 504 — see `docs/specs/api-delay-endpoints.md`).
#[derive(Debug, Clone)]
pub enum UrlTestError {
    Timeout,
    Transport(String),
}

/// Probe a proxy by dialing the target, issuing an HTTP/1.1 `GET`, and
/// reading the status line. Returns the total elapsed milliseconds on
/// success (status within `expected`), otherwise a classified error.
///
/// `expected` is a comma-separated list of status-code ranges
/// (e.g. `"200"`, `"200-299"`, `"200,204-206"`). When `None`, any 2xx
/// status counts as success — matching upstream Go mihomo's default in
/// `component/proxydialer/http.go::httpHealthCheck`.
///
/// `https://` targets are tunneled through a client-side TLS handshake
/// (`meow_transport::tls::TlsLayer`, BoringSSL by default) before the GET. HTTP targets go over the raw
/// dialed connection.
/// mihomo's `unified-delay`: a probe makes a second request on the
/// connection the first one opened and reports only that one — the round
/// trip through the proxy, without the dial and the handshakes (which a
/// connection pays once, and which differ by protocol more than by line).
static UNIFIED_DELAY: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// Turns `unified-delay` on or off for every probe from now on.
pub fn set_unified_delay(on: bool) {
    UNIFIED_DELAY.store(on, std::sync::atomic::Ordering::Relaxed);
}

pub fn unified_delay() -> bool {
    UNIFIED_DELAY.load(std::sync::atomic::Ordering::Relaxed)
}

pub async fn url_test(
    adapter: &dyn ProxyAdapter,
    url: &str,
    expected: Option<&str>,
    timeout: Duration,
) -> Result<u16, UrlTestError> {
    let Some(parsed) = ParsedUrl::parse(url) else {
        return Err(UrlTestError::Transport(format!("invalid url: {url}")));
    };
    let ranges = match parse_expected(expected) {
        Ok(r) => r,
        Err(e) => return Err(UrlTestError::Transport(e)),
    };

    let start = Instant::now();
    // `Tunnel` marks this dial as a health probe rather than user traffic.
    // mihomo solves the same problem by threading an explicit `touch` flag
    // through its group calls (`fast(false)` for probes); meow-rs'
    // `ProxyAdapter` trait has no such parameter, so the marker rides on
    // the metadata instead.  Groups skip the usage-generation bump for
    // these dials — counting probes as "use" would defeat lazy health
    // checks for nested groups.  No production dialer sets
    // `ConnType::Tunnel` today; `Metadata::internal` (#555) is the
    // explicit escape hatch `is_internal()` also honours, should a
    // tunnel inbound ever need to reuse the variant.
    let metadata = meow_common::Metadata {
        network: meow_common::Network::Tcp,
        conn_type: meow_common::ConnType::Tunnel,
        host: parsed.host.as_str().into(),
        dst_port: parsed.port,
        ..Default::default()
    };

    let fut = probe_once(adapter, metadata, parsed, ranges, unified_delay());
    match tokio::time::timeout(timeout, fut).await {
        Ok(Ok(second)) => {
            // `unified-delay`: the second round trip alone, when it was made.
            let took = second.unwrap_or_else(|| start.elapsed());
            let delay = took.as_millis().min(u16::MAX as u128) as u16;
            // Collapse sub-millisecond probes to 1 so callers can treat 0 as
            // the "probe did not complete" sentinel when they choose to.
            let delay = delay.max(1);
            debug!("{} URL test: {}ms", adapter.name(), delay);
            Ok(delay)
        }
        Ok(Err(e)) => {
            warn!("{} URL test transport error: {}", adapter.name(), e);
            Err(UrlTestError::Transport(e))
        }
        Err(_) => {
            warn!("{} URL test timeout after {:?}", adapter.name(), timeout);
            Err(UrlTestError::Timeout)
        }
    }
}

/// Probe a proxy and record the result in its [`ProxyHealth`].
///
/// On success the measured delay (ms) is recorded; on any failure `0` is
/// recorded so `last_delay == 0` and `alive() == false`.
pub async fn probe_and_record(
    proxy: &Arc<dyn Proxy>,
    url: &str,
    expected: Option<&str>,
    timeout: Duration,
) -> Result<u16, UrlTestError> {
    let _permit = global_delay_probe_limiter()
        .acquire()
        .await
        .expect("global delay probe semaphore is never closed");
    let adapter: &dyn ProxyAdapter = proxy.as_ref();
    let result = url_test(adapter, url, expected, timeout).await;
    match &result {
        Ok(d) => proxy.health().record_delay(*d),
        Err(_) => proxy.health().record_delay(0),
    }
    result
}

pub async fn probe_many_bounded(
    probes: Vec<(String, Arc<dyn Proxy + 'static>)>,
    url: &str,
    expected: Option<&str>,
    timeout: Duration,
    concurrency: usize,
) -> Vec<(String, u16)> {
    probe_many_bounded_detailed(probes, url, expected, timeout, concurrency)
        .await
        .into_iter()
        .map(|result| (result.name, result.delay))
        .collect()
}

pub async fn probe_many_bounded_detailed(
    probes: Vec<(String, Arc<dyn Proxy + 'static>)>,
    url: &str,
    expected: Option<&str>,
    timeout: Duration,
    concurrency: usize,
) -> Vec<NamedProbeResult> {
    let url = Arc::<str>::from(url.to_owned());
    let expected = expected.map(|s| Arc::<str>::from(s.to_owned()));
    let concurrency = concurrency.max(1);

    let mut probes = probes.into_iter();
    let mut pending = FuturesUnordered::new();
    for _ in 0..concurrency {
        let Some((name, proxy)) = probes.next() else {
            break;
        };
        pending.push(named_probe_future(
            name,
            proxy,
            Arc::clone(&url),
            expected.clone(),
            timeout,
        ));
    }

    let mut results = Vec::new();
    while let Some(result) = pending.next().await {
        results.push(result);
        if let Some((name, proxy)) = probes.next() {
            pending.push(named_probe_future(
                name,
                proxy,
                Arc::clone(&url),
                expected.clone(),
                timeout,
            ));
        }
    }

    results
}

fn named_probe_future(
    name: String,
    proxy: Arc<dyn Proxy + 'static>,
    url: Arc<str>,
    expected: Option<Arc<str>>,
    timeout: Duration,
) -> BoxFuture<'static, NamedProbeResult> {
    async move {
        match probe_and_record(&proxy, url.as_ref(), expected.as_deref(), timeout).await {
            Ok(delay) => NamedProbeResult {
                name,
                delay,
                error: None,
            },
            Err(error) => NamedProbeResult {
                name,
                delay: 0,
                error: Some(error),
            },
        }
    }
    .boxed()
}

/// The last background probe of each line that keeps no record of its own
/// (a smart group's: its [`ProxyHealth`] is left alone, so the probe never
/// marks the line dead for the other groups), by line name. Read with the
/// lines' own histories (`GET /paopao/line-health`).
fn line_probes(
) -> &'static parking_lot::Mutex<std::collections::HashMap<String, meow_common::DelayHistory>> {
    static PROBES: std::sync::OnceLock<
        parking_lot::Mutex<std::collections::HashMap<String, meow_common::DelayHistory>>,
    > = std::sync::OnceLock::new();
    PROBES.get_or_init(Default::default)
}

/// Lines kept at most in [`line_probes`] (the oldest go first).
const LINE_PROBES_MAX: usize = 8192;

/// Notes a background probe of `line`: `delay` ms, 0 = no answer.
pub fn note_line_probe(line: &str, delay: u16) {
    let mut probes = line_probes().lock();
    if probes.len() >= LINE_PROBES_MAX && !probes.contains_key(line) {
        if let Some(oldest) = probes
            .iter()
            .min_by_key(|(_, h)| h.time)
            .map(|(k, _)| k.clone())
        {
            probes.remove(&oldest);
        }
    }
    probes.insert(
        line.to_owned(),
        meow_common::DelayHistory {
            time: std::time::SystemTime::now(),
            delay,
        },
    );
}

/// The last background probe of `line` noted with [`note_line_probe`].
pub fn line_probe(line: &str) -> Option<meow_common::DelayHistory> {
    line_probes().lock().get(line).cloned()
}

fn global_delay_probe_limiter() -> &'static Semaphore {
    static LIMITER: std::sync::OnceLock<Semaphore> = std::sync::OnceLock::new();
    LIMITER.get_or_init(|| Semaphore::new(GLOBAL_DELAY_PROBE_CONCURRENCY))
}

async fn probe_once(
    adapter: &dyn ProxyAdapter,
    metadata: meow_common::Metadata,
    parsed: ParsedUrl,
    ranges: Vec<(u16, u16)>,
    unified: bool,
) -> Result<Option<Duration>, String> {
    let conn = adapter
        .dial_tcp(&metadata)
        .await
        .map_err(|e| format!("dial: {e}"))?;

    if parsed.https {
        // Same TlsLayer the proxies dial with (BoringSSL by default). Both
        // backends memoise the TLS context per (alpn, skip_cert_verify), so
        // building a layer per probe is a hash lookup, not a root-store clone.
        let tls = TlsLayer::new(&TlsConfig::new(parsed.host.to_string()))
            .map_err(|e| format!("tls sni: {e}"))?;
        let tls = tls
            .connect(Box::new(conn))
            .await
            .map_err(|e| format!("tls: {e}"))?;
        probe_stream(tls, &parsed, &ranges, unified).await
    } else {
        probe_stream(conn, &parsed, &ranges, unified).await
    }
}

/// One probe over an open stream. Plain: a `GET`, done at its status line
/// (`None`). `unified-delay`: a `HEAD` that keeps the connection, then a
/// second one timed alone (`Some`); a second one that fails leaves the
/// whole probe's time to stand, as mihomo's does.
async fn probe_stream<S>(
    mut stream: S,
    parsed: &ParsedUrl,
    ranges: &[(u16, u16)],
    unified: bool,
) -> Result<Option<Duration>, String>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    if !unified {
        return send_get_and_check(stream, parsed, ranges)
            .await
            .map(|()| None);
    }
    let accepted = |status: u16| ranges.iter().any(|(lo, hi)| status >= *lo && status <= *hi);
    write_request(&mut stream, parsed, "HEAD", "keep-alive").await?;
    let status = read_status_line(&mut stream).await?;
    if !accepted(status) {
        return Err(format!("unexpected status {status}"));
    }
    // The rest of the first answer must be off the wire before the second
    // is read (a HEAD has no body).
    if read_past_headers(&mut stream).await.is_err() {
        return Ok(None);
    }
    let second = Instant::now();
    let again = async {
        write_request(&mut stream, parsed, "HEAD", "close").await?;
        read_status_line(&mut stream).await
    };
    Ok(match again.await {
        Ok(status) if accepted(status) => Some(second.elapsed()),
        _ => None,
    })
}

/// Reads up to and including the blank line that ends a response's
/// headers (the status line is already read).
async fn read_past_headers<S>(stream: &mut S) -> Result<(), String>
where
    S: tokio::io::AsyncRead + Unpin,
{
    // The status line's own line break counts towards the blank line.
    let mut tail = [0u8, 0, b'\r', b'\n'];
    let mut byte = [0u8; 1];
    for _ in 0..16 * 1024 {
        if tail == *b"\r\n\r\n" {
            return Ok(());
        }
        let n = stream
            .read(&mut byte)
            .await
            .map_err(|e| format!("read: {e}"))?;
        if n == 0 {
            return Err("eof in headers".into());
        }
        tail.rotate_left(1);
        tail[3] = byte[0];
    }
    if tail == *b"\r\n\r\n" {
        Ok(())
    } else {
        Err("headers too long".into())
    }
}

async fn send_get_and_check<S>(
    mut stream: S,
    parsed: &ParsedUrl,
    ranges: &[(u16, u16)],
) -> Result<(), String>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    write_get(&mut stream, parsed).await?;
    let status = read_status_line(&mut stream).await?;
    trace!(status, "url_test: received status");
    if ranges.iter().any(|(lo, hi)| status >= *lo && status <= *hi) {
        Ok(())
    } else {
        Err(format!("unexpected status {status}"))
    }
}

/// Download speed through `adapter`: GETs `url` (a large file) and reads at
/// most `max_bytes` of the body within `budget` (dial included). Returns
/// body bytes per second, timed from the end of the headers so the dial
/// and handshakes don't count. Running out of time still measures what
/// came — a crawling line is exactly what this is for.
pub async fn download_rate(
    adapter: &dyn ProxyAdapter,
    url: &str,
    max_bytes: u64,
    budget: Duration,
) -> Result<f64, String> {
    let parsed = ParsedUrl::parse(url).ok_or_else(|| format!("invalid url: {url}"))?;
    let deadline = tokio::time::Instant::now() + budget;
    let metadata = meow_common::Metadata {
        network: meow_common::Network::Tcp,
        conn_type: meow_common::ConnType::Tunnel,
        host: parsed.host.as_str().into(),
        dst_port: parsed.port,
        ..Default::default()
    };
    let conn = tokio::time::timeout_at(deadline, adapter.dial_tcp(&metadata))
        .await
        .map_err(|_| "dial timeout".to_string())?
        .map_err(|e| format!("dial: {e}"))?;
    if parsed.https {
        let tls = TlsLayer::new(&TlsConfig::new(parsed.host.to_string()))
            .map_err(|e| format!("tls sni: {e}"))?;
        let tls = tokio::time::timeout_at(deadline, tls.connect(Box::new(conn)))
            .await
            .map_err(|_| "tls timeout".to_string())?
            .map_err(|e| format!("tls: {e}"))?;
        read_body_rate(tls, &parsed, max_bytes, deadline).await
    } else {
        read_body_rate(conn, &parsed, max_bytes, deadline).await
    }
}

async fn read_body_rate<S>(
    stream: S,
    parsed: &ParsedUrl,
    max_bytes: u64,
    deadline: tokio::time::Instant,
) -> Result<f64, String>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    use tokio::io::AsyncBufReadExt as _;
    let mut stream = tokio::io::BufReader::new(stream);
    let head = async {
        write_get(stream.get_mut(), parsed).await?;
        let status = read_status_line(&mut stream).await?;
        if !(200..300).contains(&status) {
            return Err(format!("unexpected status {status}"));
        }
        let mut line = String::new();
        loop {
            line.clear();
            let n = stream
                .read_line(&mut line)
                .await
                .map_err(|e| format!("read: {e}"))?;
            if n == 0 {
                return Err("eof in headers".to_string());
            }
            if line == "\r\n" || line == "\n" {
                return Ok(());
            }
        }
    };
    tokio::time::timeout_at(deadline, head)
        .await
        .map_err(|_| "timeout before the body".to_string())??;
    let start = tokio::time::Instant::now();
    let mut got = 0u64;
    let mut buf = vec![0u8; 64 * 1024];
    while got < max_bytes {
        match tokio::time::timeout_at(deadline, stream.read(&mut buf)).await {
            Ok(Ok(0)) | Err(_) => break,
            Ok(Ok(n)) => got += n as u64,
            Ok(Err(e)) => return Err(format!("read: {e}")),
        }
    }
    if got == 0 {
        return Err("empty body".to_string());
    }
    let secs = start.elapsed().as_secs_f64().max(0.001);
    Ok(got as f64 / secs)
}

async fn write_get<S>(stream: &mut S, parsed: &ParsedUrl) -> Result<(), String>
where
    S: tokio::io::AsyncWrite + Unpin,
{
    write_request(stream, parsed, "GET", "close").await
}

async fn write_request<S>(
    stream: &mut S,
    parsed: &ParsedUrl,
    method: &str,
    connection: &str,
) -> Result<(), String>
where
    S: tokio::io::AsyncWrite + Unpin,
{
    // Host header includes the non-default port so virtual-hosted origins
    // route correctly; mirrors Go net/http's default behaviour.
    use std::io::Write as _;
    let mut buf = [0u8; 512];
    let default_port = if parsed.https { 443 } else { 80 };
    let mut cursor: &mut [u8] = &mut buf;
    if parsed.port == default_port {
        write!(
            cursor,
            "{method} {path} HTTP/1.1\r\nHost: {host}\r\n\
             User-Agent: clash.meta/{ver}\r\nAccept: */*\r\nConnection: {connection}\r\n\r\n",
            path = parsed.path,
            host = parsed.host,
            ver = env!("CARGO_PKG_VERSION"),
        )
    } else {
        write!(
            cursor,
            "{method} {path} HTTP/1.1\r\nHost: {host}:{port}\r\n\
             User-Agent: clash.meta/{ver}\r\nAccept: */*\r\nConnection: {connection}\r\n\r\n",
            path = parsed.path,
            host = parsed.host,
            port = parsed.port,
            ver = env!("CARGO_PKG_VERSION"),
        )
    }
    .map_err(|_| "request too large for buffer".to_string())?;
    let remaining = cursor.len();
    let written = buf.len() - remaining;
    stream
        .write_all(&buf[..written])
        .await
        .map_err(|e| format!("write: {e}"))?;
    stream.flush().await.map_err(|e| format!("flush: {e}"))
}

async fn read_status_line<S>(stream: &mut S) -> Result<u16, String>
where
    S: tokio::io::AsyncRead + Unpin,
{
    let mut buf = [0u8; 1024];
    let mut len = 0usize;
    let mut byte = [0u8; 1];
    loop {
        let n = stream
            .read(&mut byte)
            .await
            .map_err(|e| format!("read: {e}"))?;
        if n == 0 {
            return Err("eof before status line".into());
        }
        if len < buf.len() {
            buf[len] = byte[0];
            len += 1;
        }
        if buf[..len].ends_with(b"\r\n") || len >= buf.len() {
            break;
        }
    }
    let line = std::str::from_utf8(&buf[..len]).map_err(|_| "status line not utf-8".to_string())?;
    // HTTP/1.x status line: "HTTP/1.1 204 No Content\r\n"
    let mut parts = line.split_whitespace();
    let version = parts.next().unwrap_or("");
    if !version.starts_with("HTTP/") {
        return Err(format!("malformed status line: {line:?}"));
    }
    let code_str = parts
        .next()
        .ok_or_else(|| format!("missing status code: {line:?}"))?;
    code_str
        .parse::<u16>()
        .map_err(|_| format!("bad status code: {code_str:?}"))
}

#[derive(Debug, Clone)]
struct ParsedUrl {
    https: bool,
    host: SmolStr,
    port: u16,
    path: SmolStr,
}

impl ParsedUrl {
    fn parse(url: &str) -> Option<Self> {
        let (https, rest) = if let Some(r) = url.strip_prefix("https://") {
            (true, r)
        } else {
            (false, url.strip_prefix("http://")?)
        };
        // CTL/space bytes would smuggle extra request lines or headers into
        // the probe request — reject before splitting authority/path. A
        // subscription-controlled `proxy-groups[].url` (or the `?url=` delay
        // endpoint) could otherwise write a raw `\r\n` onto the wire
        // (issue #648).
        if rest.bytes().any(|b| b <= b' ' || b == 0x7f) {
            return None;
        }
        let (authority, path) = match rest.find('/') {
            Some(i) => (&rest[..i], &rest[i..]),
            None => (rest, "/"),
        };
        if authority.is_empty() {
            return None;
        }
        // IPv6 literals wrap in `[...]`.
        let (host, port) = if let Some(rest) = authority.strip_prefix('[') {
            let end = rest.find(']')?;
            let host = &rest[..end];
            let tail = &rest[end + 1..];
            let port = if let Some(p) = tail.strip_prefix(':') {
                p.parse().ok()?
            } else if https {
                443
            } else {
                80
            };
            (SmolStr::from(host), port)
        } else if let Some((h, p)) = authority.rsplit_once(':') {
            (SmolStr::from(h), p.parse().ok()?)
        } else {
            (SmolStr::from(authority), if https { 443 } else { 80 })
        };
        Some(Self {
            https,
            host,
            port,
            path: SmolStr::from(path),
        })
    }
}

/// Parse an `expected` query-param value into inclusive status-code ranges.
/// Empty / `None` defaults to `[200..=299]`, matching upstream.
fn parse_expected(spec: Option<&str>) -> Result<Vec<(u16, u16)>, String> {
    let s = spec.unwrap_or("").trim();
    if s.is_empty() {
        return Ok(vec![(200, 299)]);
    }
    let mut out = Vec::new();
    for piece in s.split(',') {
        let piece = piece.trim();
        if piece.is_empty() {
            continue;
        }
        if let Some((lo, hi)) = piece.split_once('-') {
            let lo: u16 = lo
                .trim()
                .parse()
                .map_err(|_| format!("expected: bad range {piece:?}"))?;
            let hi: u16 = hi
                .trim()
                .parse()
                .map_err(|_| format!("expected: bad range {piece:?}"))?;
            if lo > hi {
                return Err(format!("expected: inverted range {piece:?}"));
            }
            out.push((lo, hi));
        } else {
            let code: u16 = piece
                .parse()
                .map_err(|_| format!("expected: bad code {piece:?}"))?;
            out.push((code, code));
        }
    }
    if out.is_empty() {
        return Err("expected: empty".into());
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    #[test]
    fn a_line_probe_is_kept_by_name_the_newest_wins() {
        assert!(super::line_probe("probe-test-line").is_none());
        super::note_line_probe("probe-test-line", 120);
        let first = super::line_probe("probe-test-line").expect("noted");
        assert_eq!(first.delay, 120);
        super::note_line_probe("probe-test-line", 0);
        let second = super::line_probe("probe-test-line").expect("noted");
        assert_eq!(second.delay, 0, "no answer is kept too");
        assert!(second.time >= first.time);
    }

    use super::*;

    /// A loopback server sends 3 MB with headers; the probe reads only up
    /// to its cap and reports a positive rate.
    #[tokio::test]
    async fn download_rate_reads_a_bounded_body() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            let (mut s, _) = listener.accept().await.unwrap();
            let mut req = [0u8; 512];
            let _ = s.read(&mut req).await;
            let body = vec![0u8; 3_000_000];
            let _ = s
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 3000000\r\n\r\n")
                .await;
            let _ = s.write_all(&body).await;
        });
        let direct = crate::direct::DirectAdapter::new();
        let url = format!("http://127.0.0.1:{port}/__down");
        let rate = download_rate(&direct, &url, 1 << 20, Duration::from_secs(5))
            .await
            .unwrap();
        assert!(rate > 0.0, "{rate}");
        assert!(download_rate(
            &direct,
            "http://127.0.0.1:9/",
            1 << 20,
            Duration::from_secs(2)
        )
        .await
        .is_err());
    }

    /// A server slow to answer the first request (a handshake's stand-in)
    /// and quick on the second: `unified-delay` reports the second alone,
    /// and falls back to the whole probe when there is no second answer.
    #[tokio::test]
    async fn unified_delay_times_the_second_request() {
        async fn serve(second: bool) -> u16 {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let port = listener.local_addr().unwrap().port();
            tokio::spawn(async move {
                let (mut s, _) = listener.accept().await.unwrap();
                let mut req = [0u8; 512];
                let n = s.read(&mut req).await.unwrap();
                assert!(req[..n].starts_with(b"HEAD /generate_204 HTTP/1.1\r\n"));
                tokio::time::sleep(Duration::from_millis(300)).await;
                let answer = b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n";
                s.write_all(answer).await.unwrap();
                if second {
                    let n = s.read(&mut req).await.unwrap();
                    assert!(req[..n].starts_with(b"HEAD "));
                    s.write_all(answer).await.unwrap();
                }
            });
            port
        }
        let ranges = [(200u16, 299u16)];
        for second in [true, false] {
            let port = serve(second).await;
            let parsed =
                ParsedUrl::parse(&format!("http://127.0.0.1:{port}/generate_204")).unwrap();
            let stream = tokio::net::TcpStream::connect(("127.0.0.1", port))
                .await
                .unwrap();
            let start = Instant::now();
            let took = probe_stream(stream, &parsed, &ranges, true).await.unwrap();
            assert!(start.elapsed() >= Duration::from_millis(300));
            match took {
                Some(d) => {
                    assert!(second);
                    assert!(d < Duration::from_millis(200), "{d:?}");
                }
                None => assert!(!second),
            }
        }
    }

    #[test]
    fn parsed_url_cases() {
        // (input, https, host, port, path)
        let accepted: &[(&str, bool, &str, u16, &str)] = &[
            (
                "https://www.gstatic.com/generate_204",
                true,
                "www.gstatic.com",
                443,
                "/generate_204",
            ),
            (
                "https://cp.cloudflare.com/generate_204",
                true,
                "cp.cloudflare.com",
                443,
                "/generate_204",
            ),
            ("http://example.com:8080", false, "example.com", 8080, "/"),
            ("http://[::1]:8080/x", false, "::1", 8080, "/x"),
        ];
        // CTL/whitespace bytes would inject raw request lines or headers
        // into the probe request (issue #648).
        let rejected: &[&str] = &[
            "ftp://x",
            "example.com",
            "http://victim/\r\nX-Injected: x",
            "http://victim/x y",
            "http://vic\ttim/",
            "http://vic\0tim/",
            "http://victim/\x0bz",
            "http://victim/\x7f",
            // CTL in the authority half, not just the path — these would
            // still parse (valid host + port) without the guard.
            "http://vic\ntim:8080/",
            "http://vic\rtim:8080/",
        ];

        // Collect instead of asserting inline so one bad input does not hide
        // the remaining cases.
        let mut failures = Vec::new();
        for (input, https, host, port, path) in accepted {
            match ParsedUrl::parse(input) {
                Some(p) => {
                    let got = (p.https, p.host.as_str(), p.port, p.path.as_str());
                    if got != (*https, *host, *port, *path) {
                        failures.push(format!(
                            "{input:?}: expected (https={https}, host={host:?}, port={port}, path={path:?}), got {got:?}"
                        ));
                    }
                }
                None => failures.push(format!("{input:?}: expected a parse, got None")),
            }
        }
        for input in rejected {
            if let Some(p) = ParsedUrl::parse(input) {
                failures.push(format!("{input:?}: expected None, got {p:?}"));
            }
        }
        assert!(
            failures.is_empty(),
            "ParsedUrl::parse mismatches:\n{}",
            failures.join("\n")
        );
    }

    #[test]
    fn parse_expected_cases() {
        // (label, input, expected): expected is Some(ranges) when the input
        // must parse to exactly those ranges, None when it must be rejected.
        type Case = (
            &'static str,
            Option<&'static str>,
            Option<&'static [(u16, u16)]>,
        );
        let cases: &[Case] = &[
            ("default: None is 2xx", None, Some(&[(200, 299)])),
            (
                "default: empty string is 2xx",
                Some(""),
                Some(&[(200, 299)]),
            ),
            (
                "mixed list of codes and ranges",
                Some("200,204-206,301"),
                Some(&[(200, 200), (204, 206), (301, 301)]),
            ),
            ("inverted range is rejected", Some("300-200"), None),
            ("garbage is rejected", Some("abc"), None),
        ];

        // Every case runs even if an earlier one fails, so one bad input does
        // not hide the rest.
        let mut failures = Vec::new();
        for (label, input, expected) in cases {
            match (parse_expected(*input), expected) {
                (Ok(got), Some(want)) => {
                    if got.as_slice() != *want {
                        failures.push(format!(
                            "{label} ({input:?}): expected {want:?}, got {got:?}"
                        ));
                    }
                }
                (Err(_), None) => {}
                (Ok(got), None) => {
                    failures.push(format!(
                        "{label} ({input:?}): expected an error, got {got:?}"
                    ));
                }
                (Err(e), Some(want)) => {
                    failures.push(format!(
                        "{label} ({input:?}): expected {want:?}, got error {e:?}"
                    ));
                }
            }
        }
        assert!(
            failures.is_empty(),
            "parse_expected mismatches:\n{}",
            failures.join("\n")
        );
    }
}
