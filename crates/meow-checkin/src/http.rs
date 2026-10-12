//! One HTTP/1.1 request over a connection the core dials.
//!
//! The engine never opens a socket itself: a [`Connector`] hands it a
//! stream to `host:port`, dialled either straight out or through the
//! core's rules and lines. HTTPS runs over that stream with the core's own
//! TLS layer (BoringSSL), certificates verified.
//!
//! Small on purpose: `Connection: close`, `Accept-Encoding: identity`, no
//! redirect handling (the caller decides, see [`crate::replay`]), the
//! response body capped.

use crate::model::Access;
use async_trait::async_trait;
use meow_transport::tls::{TlsConfig, TlsLayer};
use meow_transport::Transport as _;
use std::fmt;
use std::io;
use std::time::Duration;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use url::Url;

pub type BoxStream = Box<dyn meow_transport::Stream>;

/// Dials `host:port` the way `access` says.
///
/// Unless `allow_private`, the connector must not reach this machine or a
/// private network: it checks the address it actually dials (a public
/// name can resolve to `127.0.0.1`), not the name, and answers
/// [`refused_private`] instead of connecting. The engine has already
/// refused hosts that say so themselves ([`crate::site::is_internal_host`]).
#[async_trait]
pub trait Connector: Send + Sync {
    async fn connect(
        &self,
        access: Access,
        host: &str,
        port: u16,
        allow_private: bool,
    ) -> io::Result<BoxStream>;
}

/// The error a [`Connector`] answers for an address it may not dial.
pub fn refused_private() -> io::Error {
    io::Error::new(
        io::ErrorKind::PermissionDenied,
        "checkin: the address is on this machine or a private network",
    )
}

/// Dials through `meow_common`'s outbound chokepoint, whatever `access`
/// says. For a core without a tunnel (tests, tools); the running core
/// installs its own connector.
#[derive(Debug, Default, Clone, Copy)]
pub struct SystemConnector;

#[async_trait]
impl Connector for SystemConnector {
    async fn connect(
        &self,
        _access: Access,
        host: &str,
        port: u16,
        allow_private: bool,
    ) -> io::Result<BoxStream> {
        // Resolve once and dial what was checked: no second lookup for a
        // name to change its answer in.
        let addrs = meow_common::resolve_host_all(host, port).await?;
        let mut last = None;
        let mut refused = false;
        for addr in addrs {
            if !allow_private && crate::site::is_internal_ip(addr.ip()) {
                refused = true;
                continue;
            }
            match meow_common::connect_tcp(addr).await {
                Ok(stream) => return Ok(Box::new(stream)),
                Err(e) => last = Some(e),
            }
        }
        Err(match last {
            Some(e) => e,
            None if refused => refused_private(),
            None => io::Error::new(io::ErrorKind::NotFound, "no address"),
        })
    }
}

/// How a request leaves.
#[derive(Clone, Copy)]
pub struct Dial<'a> {
    pub connector: &'a dyn Connector,
    pub access: Access,
    /// See [`Connector`].
    pub allow_private: bool,
    /// Trust anchors (DER) on top of the built-in ones.
    pub extra_roots: &'a [Vec<u8>],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Limits {
    /// Dial plus TLS handshake.
    pub connect_timeout: Duration,
    /// Writing the request and reading the response.
    pub exchange_timeout: Duration,
    /// Body bytes kept; the rest is not read.
    pub max_body: usize,
    pub max_header: usize,
    pub max_redirects: u8,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            connect_timeout: Duration::from_secs(15),
            exchange_timeout: Duration::from_secs(30),
            max_body: 1024 * 1024,
            max_header: 64 * 1024,
            max_redirects: 5,
        }
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct Request {
    pub method: String,
    pub url: Url,
    /// Written in order, as given. `Host`, `Content-Length`, `Connection`
    /// and `Accept-Encoding` are written by [`send`].
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

// Headers and body can hold a login: never printed.
impl fmt::Debug for Request {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Request")
            .field("method", &self.method)
            .field("host", &self.url.host_str())
            .field("headers", &self.headers.len())
            .field("body", &self.body.len())
            .finish()
    }
}

/// Interim (`1xx`) responses read before the real one, at most.
const MAX_INTERIM: usize = 8;

#[derive(Clone, PartialEq, Eq)]
pub struct Response {
    pub status: u16,
    /// Lower-case names, in order.
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
    /// The body was longer than [`Limits::max_body`].
    pub truncated: bool,
}

// `Set-Cookie` and the body can hold a login: never printed.
impl fmt::Debug for Response {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Response")
            .field("status", &self.status)
            .field("headers", &self.headers.len())
            .field("body", &self.body.len())
            .field("truncated", &self.truncated)
            .finish()
    }
}

impl Response {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, v)| v.as_str())
    }

    pub fn headers_named<'a>(&'a self, name: &'a str) -> impl Iterator<Item = &'a str> + 'a {
        self.headers
            .iter()
            .filter(move |(n, _)| n == name)
            .map(|(_, v)| v.as_str())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HttpError {
    Connect(String),
    Tls(String),
    Timeout,
    Protocol(String),
    /// The address is on this machine or a private network.
    Private,
}

impl HttpError {
    /// One sentence for the user.
    pub fn sentence(&self) -> String {
        match self {
            Self::Connect(_) => "连不上这个网站。".to_string(),
            Self::Tls(_) => "和这个网站建立安全连接失败。".to_string(),
            Self::Timeout => "网站太久没有回应。".to_string(),
            Self::Protocol(_) => "网站的回应读不懂。".to_string(),
            Self::Private => PRIVATE_SENTENCE.to_string(),
        }
    }
}

/// What the user is told when a step points at this machine or a private
/// network.
pub const PRIVATE_SENTENCE: &str = "这个地址指向本机或内网，签到助手不会访问。";

fn host_header(url: &Url) -> String {
    let host = url.host_str().unwrap_or("");
    match url.port() {
        Some(port) => format!("{host}:{port}"),
        None => host.to_string(),
    }
}

fn has_request_body(method: &str) -> bool {
    matches!(method, "POST" | "PUT" | "PATCH")
}

/// The request as bytes on the wire.
pub fn encode(req: &Request) -> Vec<u8> {
    let path = match req.url.query() {
        Some(q) => format!("{}?{q}", req.url.path()),
        None => req.url.path().to_string(),
    };
    let mut head = format!(
        "{} {path} HTTP/1.1\r\nHost: {}\r\n",
        req.method,
        host_header(&req.url)
    );
    for (name, value) in &req.headers {
        head.push_str(name);
        head.push_str(": ");
        head.push_str(value);
        head.push_str("\r\n");
    }
    head.push_str("Accept-Encoding: identity\r\nConnection: close\r\n");
    if !req.body.is_empty() || has_request_body(&req.method) {
        head.push_str("Content-Length: ");
        head.push_str(&req.body.len().to_string());
        head.push_str("\r\n");
    }
    head.push_str("\r\n");
    let mut out = head.into_bytes();
    out.extend_from_slice(&req.body);
    out
}

/// Sends `req` and reads the answer. Does not follow redirects.
pub async fn send(dial: &Dial<'_>, req: &Request, limits: &Limits) -> Result<Response, HttpError> {
    let is_https = match req.url.scheme() {
        "https" => true,
        "http" => false,
        other => return Err(HttpError::Protocol(format!("scheme {other}"))),
    };
    let host = req
        .url
        .host_str()
        .ok_or_else(|| HttpError::Protocol("no host".into()))?
        .trim_start_matches('[')
        .trim_end_matches(']')
        .to_string();
    let port = req
        .url
        .port_or_known_default()
        .ok_or_else(|| HttpError::Protocol("no port".into()))?;

    let connect = async {
        let conn = dial
            .connector
            .connect(dial.access, &host, port, dial.allow_private)
            .await
            .map_err(|e| {
                if e.kind() == io::ErrorKind::PermissionDenied {
                    HttpError::Private
                } else {
                    HttpError::Connect(e.to_string())
                }
            })?;
        if !is_https {
            return Ok(conn);
        }
        let config = TlsConfig {
            // This client speaks HTTP/1.1 only; say so, or a server may
            // pick h2.
            alpn: vec!["http/1.1".to_string()],
            additional_roots: dial.extra_roots.to_vec(),
            ..TlsConfig::new(host.as_str())
        };
        let tls = TlsLayer::new(&config).map_err(|e| HttpError::Tls(e.to_string()))?;
        tls.connect(conn)
            .await
            .map_err(|e| HttpError::Tls(e.to_string()))
    };
    let mut stream = tokio::time::timeout(limits.connect_timeout, connect)
        .await
        .map_err(|_| HttpError::Timeout)??;

    let wire = encode(req);
    let exchange = async {
        stream
            .write_all(&wire)
            .await
            .map_err(|e| HttpError::Connect(e.to_string()))?;
        stream
            .flush()
            .await
            .map_err(|e| HttpError::Connect(e.to_string()))?;
        read_response(&mut stream, req.method == "HEAD", limits).await
    };
    tokio::time::timeout(limits.exchange_timeout, exchange)
        .await
        .map_err(|_| HttpError::Timeout)?
}

struct Head {
    status: u16,
    headers: Vec<(String, String)>,
    body_start: usize,
}

fn parse_head(buf: &[u8]) -> Result<Option<Head>, HttpError> {
    let mut headers = [httparse::EMPTY_HEADER; 96];
    let mut resp = httparse::Response::new(&mut headers);
    match resp.parse(buf) {
        Ok(httparse::Status::Complete(body_start)) => Ok(Some(Head {
            status: resp
                .code
                .ok_or_else(|| HttpError::Protocol("no status".into()))?,
            headers: resp
                .headers
                .iter()
                .map(|h| {
                    (
                        h.name.to_ascii_lowercase(),
                        String::from_utf8_lossy(h.value).trim().to_string(),
                    )
                })
                .collect(),
            body_start,
        })),
        Ok(httparse::Status::Partial) => Ok(None),
        Err(e) => Err(HttpError::Protocol(e.to_string())),
    }
}

enum Framing {
    None,
    Length(usize),
    Chunked,
    UntilClose,
}

fn framing(head: &Head, head_only: bool) -> Result<Framing, HttpError> {
    if head_only || head.status / 100 == 1 || head.status == 204 || head.status == 304 {
        return Ok(Framing::None);
    }
    let chunked = head.headers.iter().any(|(n, v)| {
        n == "transfer-encoding"
            && v.split(',')
                .any(|p| p.trim().eq_ignore_ascii_case("chunked"))
    });
    if chunked {
        return Ok(Framing::Chunked);
    }
    let mut length = None;
    for (_, v) in head.headers.iter().filter(|(n, _)| n == "content-length") {
        let n: usize = v
            .parse()
            .map_err(|_| HttpError::Protocol("content-length".into()))?;
        if length.is_some_and(|l| l != n) {
            return Err(HttpError::Protocol("content-length".into()));
        }
        length = Some(n);
    }
    Ok(length.map_or(Framing::UntilClose, Framing::Length))
}

/// What of a chunked body is in `input`: the decoded bytes (at most `cap`)
/// and whether the body is complete or the cap was reached.
fn decode_chunked(mut input: &[u8], cap: usize) -> Result<(Vec<u8>, bool, bool), HttpError> {
    let mut body = Vec::new();
    loop {
        let Some(line_end) = input.windows(2).position(|w| w == b"\r\n") else {
            return Ok((body, false, false));
        };
        let size_text = std::str::from_utf8(&input[..line_end])
            .map_err(|_| HttpError::Protocol("chunk size".into()))?;
        let size =
            usize::from_str_radix(size_text.split(';').next().unwrap_or_default().trim(), 16)
                .map_err(|_| HttpError::Protocol("chunk size".into()))?;
        input = &input[line_end + 2..];
        if size == 0 {
            return Ok((body, true, false));
        }
        let room = cap.saturating_sub(body.len());
        if size > room {
            body.extend_from_slice(&input[..room.min(input.len())]);
            return Ok((body, input.len() >= room, true));
        }
        if input.len() < size + 2 {
            body.extend_from_slice(&input[..size.min(input.len())]);
            return Ok((body, false, false));
        }
        body.extend_from_slice(&input[..size]);
        input = &input[size + 2..];
    }
}

async fn read_response<S>(
    stream: &mut S,
    head_only: bool,
    limits: &Limits,
) -> Result<Response, HttpError>
where
    S: tokio::io::AsyncRead + Unpin,
{
    let mut buf: Vec<u8> = Vec::with_capacity(16 * 1024);
    let mut tmp = [0u8; 16 * 1024];
    let mut head: Option<Head> = None;
    let mut eof = false;
    let mut interim = 0usize;
    // A chunked body is kept raw until it is whole; chunk sizes and
    // extensions cost bytes too, so the raw form gets its own bound.
    let max_raw = limits.max_body.saturating_mul(2).saturating_add(64 * 1024);
    loop {
        if head.is_none() {
            if let Some(parsed) = parse_head(&buf)? {
                // An interim response: drop it and read the real one.
                if parsed.status / 100 == 1 && parsed.status != 101 {
                    interim += 1;
                    if interim > MAX_INTERIM {
                        return Err(HttpError::Protocol("too many interim responses".into()));
                    }
                    buf.drain(..parsed.body_start);
                    continue;
                }
                head = Some(parsed);
            } else if buf.len() > limits.max_header {
                return Err(HttpError::Protocol("header too large".into()));
            }
        }
        if let Some(h) = &head {
            let body = &buf[h.body_start..];
            let done = match framing(h, head_only)? {
                Framing::None => Some((Vec::new(), false)),
                Framing::Length(n) => {
                    let want = n.min(limits.max_body);
                    (body.len() >= want || eof)
                        .then(|| (body[..want.min(body.len())].to_vec(), n > limits.max_body))
                }
                Framing::Chunked => {
                    let (decoded, complete, capped) = decode_chunked(body, limits.max_body)?;
                    let overlong = body.len() > max_raw;
                    (complete || eof || overlong).then_some((decoded, capped || overlong))
                }
                Framing::UntilClose => (eof || body.len() >= limits.max_body).then(|| {
                    (
                        body[..body.len().min(limits.max_body)].to_vec(),
                        body.len() > limits.max_body || !eof,
                    )
                }),
            };
            if let Some((body, truncated)) = done {
                let h = head.take().expect("checked above");
                return Ok(Response {
                    status: h.status,
                    headers: h.headers,
                    body,
                    truncated,
                });
            }
        } else if eof {
            // Closed without a byte: the connection never really stood
            // (through the core's rules a failed dial ends like this).
            return Err(if buf.is_empty() {
                HttpError::Connect("closed before a response".into())
            } else {
                HttpError::Protocol("closed inside the response head".into())
            });
        }
        let n = stream
            .read(&mut tmp)
            .await
            .map_err(|e| HttpError::Connect(e.to_string()))?;
        if n == 0 {
            eof = true;
        } else {
            buf.extend_from_slice(&tmp[..n]);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn parse(bytes: &[u8], max_body: usize) -> Result<Response, HttpError> {
        let limits = Limits {
            max_body,
            ..Limits::default()
        };
        let mut reader = bytes;
        read_response(&mut reader, false, &limits).await
    }

    #[tokio::test]
    async fn content_length_body() {
        let r = parse(
            b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\n{}",
            1024,
        )
        .await
        .unwrap();
        assert_eq!(r.status, 200);
        assert_eq!(r.header("content-type"), Some("application/json"));
        assert_eq!(r.body, b"{}");
        assert!(!r.truncated);
    }

    #[tokio::test]
    async fn chunked_body() {
        let r = parse(
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n2\r\nde\r\n0\r\n\r\n",
            1024,
        )
        .await
        .unwrap();
        assert_eq!(r.body, b"abcde");
        assert!(!r.truncated);
    }

    #[tokio::test]
    async fn body_until_close() {
        let r = parse(b"HTTP/1.1 200 OK\r\n\r\nhello", 1024).await.unwrap();
        assert_eq!(r.body, b"hello");
        assert!(!r.truncated);
    }

    #[tokio::test]
    async fn bodies_are_capped_not_refused() {
        let r = parse(
            b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\n0123456789",
            4,
        )
        .await
        .unwrap();
        assert_eq!(r.body, b"0123");
        assert!(r.truncated);

        let r = parse(
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n6\r\n012345\r\n0\r\n\r\n",
            4,
        )
        .await
        .unwrap();
        assert_eq!(r.body, b"0123");
        assert!(r.truncated);

        let r = parse(b"HTTP/1.1 200 OK\r\n\r\n0123456789", 4)
            .await
            .unwrap();
        assert_eq!(r.body, b"0123");
        assert!(r.truncated);
    }

    #[tokio::test]
    async fn no_body_statuses_and_interim_responses() {
        let r = parse(b"HTTP/1.1 204 No Content\r\n\r\n", 16).await.unwrap();
        assert_eq!(r.status, 204);
        assert!(r.body.is_empty());
        let r = parse(
            b"HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 302 Found\r\nLocation: /login\r\nContent-Length: 0\r\n\r\n",
            16,
        )
        .await
        .unwrap();
        assert_eq!(r.status, 302);
        assert_eq!(r.header("location"), Some("/login"));
    }

    #[tokio::test]
    async fn a_response_cannot_grow_without_bound() {
        // A head that never ends.
        let mut wire = b"HTTP/1.1 200 OK\r\n".to_vec();
        while wire.len() <= Limits::default().max_header + 32 * 1024 {
            wire.extend_from_slice(b"X-Pad: 0123456789012345678901234567890123456789\r\n");
        }
        assert!(matches!(
            parse(&wire, 16).await,
            Err(HttpError::Protocol(_))
        ));
        // More header lines than a response has any use for.
        let mut wire = b"HTTP/1.1 200 OK\r\n".to_vec();
        for i in 0..200 {
            wire.extend_from_slice(format!("X-{i}: 1\r\n").as_bytes());
        }
        wire.extend_from_slice(b"\r\n");
        assert!(matches!(
            parse(&wire, 16).await,
            Err(HttpError::Protocol(_))
        ));
        // Interim responses for ever.
        let wire = b"HTTP/1.1 100 Continue\r\n\r\n".repeat(MAX_INTERIM + 1);
        assert!(matches!(
            parse(&wire, 16).await,
            Err(HttpError::Protocol(_))
        ));
        // A chunk-size line that never ends: the body so far, cut.
        let mut wire =
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nab\r\n1;".to_vec();
        wire.resize(wire.len() + 128 * 1024, b'x');
        let r = parse(&wire, 16).await.unwrap();
        assert_eq!(r.body, b"ab");
        assert!(r.truncated);
        // A chunk size that is not one.
        assert!(matches!(
            parse(
                b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nzz\r\nab\r\n",
                16
            )
            .await,
            Err(HttpError::Protocol(_))
        ));
        // Chunked wins over a length, as the standard says.
        let r = parse(
            b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n0\r\n\r\n",
            16,
        )
        .await
        .unwrap();
        assert_eq!(r.body, b"abc");
    }

    #[test]
    fn a_response_is_not_printed() {
        let r = Response {
            status: 200,
            headers: vec![("set-cookie".into(), "sid=SECRET".into())],
            body: b"token=SECRET".to_vec(),
            truncated: false,
        };
        assert!(!format!("{r:?}").contains("SECRET"));
    }

    #[tokio::test]
    async fn garbage_and_early_close_are_errors() {
        assert!(matches!(
            parse(b"not http at all\r\n\r\n", 16).await,
            Err(HttpError::Protocol(_))
        ));
        assert!(matches!(
            parse(b"HTTP/1.1 200 OK\r\nContent-Le", 16).await,
            Err(HttpError::Protocol(_))
        ));
        assert!(matches!(
            parse(
                b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\nContent-Length: 2\r\n\r\nab",
                16
            )
            .await,
            Err(HttpError::Protocol(_))
        ));
    }

    #[test]
    fn the_request_line_and_framing_headers_are_ours() {
        let req = Request {
            method: "POST".into(),
            url: Url::parse("http://a.example:8080/p?x=1").unwrap(),
            headers: vec![("Cookie".into(), "a=1".into())],
            body: b"k=v".to_vec(),
        };
        let wire = String::from_utf8(encode(&req)).unwrap();
        assert_eq!(
            wire,
            "POST /p?x=1 HTTP/1.1\r\nHost: a.example:8080\r\nCookie: a=1\r\n\
             Accept-Encoding: identity\r\nConnection: close\r\nContent-Length: 3\r\n\r\nk=v"
        );
        let get = Request {
            method: "GET".into(),
            url: Url::parse("https://a.example/").unwrap(),
            headers: vec![],
            body: vec![],
        };
        let wire = String::from_utf8(encode(&get)).unwrap();
        assert!(!wire.contains("Content-Length"));
        assert!(wire.starts_with("GET / HTTP/1.1\r\nHost: a.example\r\n"));
    }
}
