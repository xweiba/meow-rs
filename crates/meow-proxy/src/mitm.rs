//! `type: mitm` — opens TLS for the hosts routed to it with the user's own
//! CA, so http-request / http-response scripts (Surge / Loon / Quantumult X
//! style, see meow-script) can rewrite what goes by; everything else is
//! forwarded unchanged to the real server (through `dialer-proxy` when
//! set). Devices must trust the CA (`ca-cert`, created on first use).
//!
//! HTTP/1.1 only (the hosts worth rewriting answer it; ALPN offers only
//! http/1.1). UDP is refused: route QUIC to these hosts to REJECT so
//! clients fall back to TCP.

use std::collections::HashMap;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use boring::pkey::PKey;
use boring::ssl::{AlpnError, SslAcceptor, SslMethod};
use boring::x509::X509;
use meow_common::{
    AdapterType, MeowError, Metadata, ProxyAdapter, ProxyConn, ProxyHealth, ProxyPacketConn, Result,
};
use meow_script::{HttpFn, HttpRequest, HttpResponse, Message, Options as ScriptOptions, Store};
use parking_lot::Mutex;
use smol_str::SmolStr;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tracing::{debug, info, warn};

use crate::stream_conn::StreamConn;

/// A URL pattern as the clients read it: JavaScript-style regular
/// expressions (look-arounds and back-references allowed).
#[derive(Clone, Debug)]
pub struct Pattern(fancy_regex::Regex);

impl Pattern {
    pub fn new(s: &str) -> std::result::Result<Self, String> {
        fancy_regex::Regex::new(s)
            .map(Self)
            .map_err(|e| e.to_string())
    }

    /// A pattern too costly to decide counts as no match.
    pub fn is_match(&self, s: &str) -> bool {
        self.0.is_match(s).unwrap_or(false)
    }
}

/// One script rule (`scripts:` entry).
#[derive(Clone, Debug)]
pub struct ScriptRule {
    pub name: String,
    /// Matched against `https://host[:port]/path?query`.
    pub pattern: Pattern,
    /// http-response (else http-request).
    pub response: bool,
    /// Path of the script, relative to the meow home directory.
    pub path: PathBuf,
    pub argument: String,
    pub binary_body: bool,
    pub requires_body: bool,
    pub timeout: Duration,
}

pub struct MitmAdapter {
    name: SmolStr,
    shared: Arc<Shared>,
    health: ProxyHealth,
}

struct Shared {
    ca_cert: rcgen::Certificate,
    ca_key: rcgen::KeyPair,
    leaves: Mutex<HashMap<String, SslAcceptor>>,
    scripts: Vec<ScriptRule>,
    store: Arc<Store>,
    home: PathBuf,
    skip_cert_verify: bool,
    dialer: Arc<dyn crate::dialer::TcpDialer>,
}

fn err(e: impl std::fmt::Display) -> MeowError {
    MeowError::Proxy(format!("mitm: {e}"))
}

/// Loads the CA, or makes one (10 years, "PaoPao CA") on first use.
pub fn load_or_create_ca(cert: &Path, key: &Path) -> std::result::Result<(String, String), String> {
    if let (Ok(c), Ok(k)) = (std::fs::read_to_string(cert), std::fs::read_to_string(key)) {
        return Ok((c, k));
    }
    let key_pair = rcgen::KeyPair::generate().map_err(|e| e.to_string())?;
    let mut params =
        rcgen::CertificateParams::new(Vec::<String>::new()).map_err(|e| e.to_string())?;
    params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "PaoPao CA");
    params
        .distinguished_name
        .push(rcgen::DnType::OrganizationName, "PaoPao");
    params.key_usages = vec![
        rcgen::KeyUsagePurpose::KeyCertSign,
        rcgen::KeyUsagePurpose::CrlSign,
        rcgen::KeyUsagePurpose::DigitalSignature,
    ];
    let now = time::OffsetDateTime::now_utc();
    params.not_before = now - time::Duration::days(1);
    params.not_after = now + time::Duration::days(3650);
    let ca = params.self_signed(&key_pair).map_err(|e| e.to_string())?;
    let (c, k) = (ca.pem(), key_pair.serialize_pem());
    if let Some(dir) = cert.parent() {
        let _ = std::fs::create_dir_all(dir);
    }
    std::fs::write(cert, &c).map_err(|e| format!("{}: {e}", cert.display()))?;
    std::fs::write(key, &k).map_err(|e| format!("{}: {e}", key.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(key, std::fs::Permissions::from_mode(0o600));
    }
    info!("mitm: created a CA at {}", cert.display());
    Ok((c, k))
}

impl MitmAdapter {
    #[allow(clippy::too_many_arguments, reason = "mirrors the config fields")]
    pub fn new(
        name: &str,
        ca_cert_pem: &str,
        ca_key_pem: &str,
        scripts: Vec<ScriptRule>,
        home: PathBuf,
        store_path: Option<PathBuf>,
        skip_cert_verify: bool,
        dialer: Arc<dyn crate::dialer::TcpDialer>,
    ) -> std::result::Result<Self, String> {
        let ca_key = rcgen::KeyPair::from_pem(ca_key_pem).map_err(|e| format!("ca-key: {e}"))?;
        let params = rcgen::CertificateParams::from_ca_cert_pem(ca_cert_pem)
            .map_err(|e| format!("ca-cert: {e}"))?;
        let ca_cert = params
            .self_signed(&ca_key)
            .map_err(|e| format!("ca-cert: {e}"))?;
        Ok(Self {
            name: SmolStr::from(name),
            shared: Arc::new(Shared {
                ca_cert,
                ca_key,
                leaves: Mutex::new(HashMap::new()),
                scripts,
                store: Arc::new(Store::new(store_path)),
                home,
                skip_cert_verify,
                dialer,
            }),
            health: ProxyHealth::new(),
        })
    }
}

impl Shared {
    /// A TLS acceptor presenting a certificate for `host` signed by our CA.
    fn acceptor(&self, host: &str) -> io::Result<SslAcceptor> {
        if let Some(a) = self.leaves.lock().get(host) {
            return Ok(a.clone());
        }
        let leaf_key = rcgen::KeyPair::generate().map_err(io::Error::other)?;
        let mut p =
            rcgen::CertificateParams::new(vec![host.to_string()]).map_err(io::Error::other)?;
        p.distinguished_name.push(rcgen::DnType::CommonName, host);
        p.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ServerAuth];
        let now = time::OffsetDateTime::now_utc();
        p.not_before = now - time::Duration::days(1);
        // Apple accepts at most 825 days for server certificates.
        p.not_after = now + time::Duration::days(365);
        let leaf = p
            .signed_by(&leaf_key, &self.ca_cert, &self.ca_key)
            .map_err(io::Error::other)?;
        let mut b =
            SslAcceptor::mozilla_intermediate_v5(SslMethod::tls()).map_err(io::Error::other)?;
        let cert = X509::from_der(leaf.der()).map_err(io::Error::other)?;
        let key =
            PKey::private_key_from_der(&leaf_key.serialize_der()).map_err(io::Error::other)?;
        b.set_certificate(&cert).map_err(io::Error::other)?;
        b.set_private_key(&key).map_err(io::Error::other)?;
        b.set_alpn_select_callback(|_, client| {
            boring::ssl::select_next_proto(b"\x08http/1.1", client).ok_or(AlpnError::NOACK)
        });
        let a = b.build();
        self.leaves.lock().insert(host.to_string(), a.clone());
        Ok(a)
    }

    fn script_source(&self, rule: &ScriptRule) -> Option<String> {
        let path = if rule.path.is_absolute() {
            rule.path.clone()
        } else {
            self.home.join(&rule.path)
        };
        match std::fs::read_to_string(&path) {
            Ok(s) => Some(s),
            Err(e) => {
                warn!("mitm script {}: {}: {e}", rule.name, path.display());
                None
            }
        }
    }

    /// Runs `rule` off the async workers (QuickJS blocks).
    async fn run_script(
        self: &Arc<Self>,
        rule: &ScriptRule,
        request: &Message,
        response: Option<&Message>,
    ) -> Option<meow_script::Outcome> {
        let source = self.script_source(rule)?;
        let opts = ScriptOptions {
            name: rule.name.clone(),
            argument: rule.argument.clone(),
            binary_body: rule.binary_body,
            timeout: rule.timeout,
            store: Arc::clone(&self.store),
            http: Some(self.http_fn()),
        };
        let (mut req, mut resp) = (request.clone(), response.cloned());
        if !rule.requires_body {
            req.body = None;
            if let Some(r) = &mut resp {
                r.body = None;
            }
        }
        let name = rule.name.clone();
        match tokio::task::spawn_blocking(move || {
            meow_script::run(&source, &req, resp.as_ref(), &opts)
        })
        .await
        {
            Ok(Ok(out)) => Some(out),
            Ok(Err(e)) => {
                warn!("mitm script {name}: {e}");
                None
            }
            Err(e) => {
                warn!("mitm script {name}: {e}");
                None
            }
        }
    }

    /// Plays the server for one client connection: requests go to the real
    /// server (scripts may change them), answers come back (scripts may
    /// change them too).
    async fn serve(
        self: Arc<Self>,
        client: tokio::io::DuplexStream,
        host: String,
        port: u16,
    ) -> io::Result<()> {
        let acceptor = self.acceptor(&host)?;
        let mut tls = tokio_boring::accept(&acceptor, client)
            .await
            .map_err(|e| io::Error::other(format!("client handshake (is the CA trusted?): {e}")))?;
        let mut cbuf = Vec::new();
        let mut upstream: Option<(Box<dyn meow_transport::Stream>, Vec<u8>)> = None;
        loop {
            let Some(mut req) = read_request(&mut tls, &mut cbuf).await? else {
                return Ok(());
            };
            let authority = if port == 443 {
                host.clone()
            } else {
                format!("{host}:{port}")
            };
            let mut msg = Message {
                url: format!("https://{authority}{}", req.target),
                method: req.method.clone(),
                headers: req.headers.clone(),
                body: Some(req.body.clone()),
                ..Message::default()
            };
            // http-request scripts.
            let mut answered: Option<Message> = None;
            let rules: Vec<&ScriptRule> = self
                .scripts
                .iter()
                .filter(|r| !r.response && r.pattern.is_match(&msg.url))
                .collect();
            for rule in rules {
                if let Some(out) = self.run_script(rule, &msg, None).await {
                    if let Some(r) = out.response {
                        answered = Some(r);
                        break;
                    }
                    if let Some(u) = out.url {
                        msg.url = u;
                    }
                    if let Some(h) = out.headers {
                        msg.headers = h;
                    }
                    if let Some(b) = out.body {
                        msg.body = Some(b);
                    }
                }
            }
            let close = req.close;
            let resp = if let Some(r) = answered {
                r
            } else {
                req.target = msg
                    .url
                    .strip_prefix(&format!("https://{authority}"))
                    .unwrap_or(&req.target)
                    .to_string();
                req.headers.clone_from(&msg.headers);
                req.body = msg.body.clone().unwrap_or_default();
                if upstream.is_none() {
                    upstream = Some((self.connect(&host, port).await?, Vec::new()));
                }
                let (up, ubuf) = upstream.as_mut().expect("just set");
                write_request(up, &req).await?;
                let r = read_response(up, ubuf, &req.method).await?;
                let mut resp = Message {
                    status: r.status,
                    headers: r.headers,
                    body: Some(r.body),
                    ..Message::default()
                };
                if r.close {
                    upstream = None;
                }
                // http-response scripts.
                let rules: Vec<&ScriptRule> = self
                    .scripts
                    .iter()
                    .filter(|r| r.response && r.pattern.is_match(&msg.url))
                    .collect();
                if !rules.is_empty() {
                    decode_body(&mut resp);
                    for rule in rules {
                        if let Some(out) = self.run_script(rule, &msg, Some(&resp)).await {
                            if let Some(s) = out.status {
                                resp.status = s;
                            }
                            if let Some(h) = out.headers {
                                resp.headers = h;
                            }
                            if let Some(b) = out.body {
                                resp.body = Some(b);
                            }
                        }
                    }
                }
                resp
            };
            write_response(&mut tls, &resp, close).await?;
            if close {
                let _ = tls.shutdown().await;
                return Ok(());
            }
        }
    }

    /// Scripts' `$httpClient` / `$task.fetch`: sent the way the MITM
    /// proxy sends everything (back into the core, routed by the rules),
    /// from the script's own thread.
    fn http_fn(self: &Arc<Self>) -> HttpFn {
        let shared = Arc::clone(self);
        let handle = tokio::runtime::Handle::current();
        Arc::new(move |req: HttpRequest| handle.block_on(shared.fetch(req)))
    }

    async fn fetch(&self, req: HttpRequest) -> std::result::Result<HttpResponse, String> {
        let deadline = tokio::time::Instant::now() + req.timeout;
        let (mut url, mut method, mut body) =
            (req.url.clone(), req.method.clone(), req.body.clone());
        for hop in 0..6 {
            let (https, host, port, target) = split_url(&url).ok_or(format!("bad url: {url}"))?;
            let mut headers: Vec<(String, String)> = req
                .headers
                .iter()
                .filter(|(k, _)| !k.eq_ignore_ascii_case("host") && forwarded(k))
                .cloned()
                .collect();
            let default_port = if https { 443 } else { 80 };
            headers.insert(
                0,
                (
                    "Host".into(),
                    if port == default_port {
                        host.clone()
                    } else {
                        format!("{host}:{port}")
                    },
                ),
            );
            if find(&headers, "user-agent").is_none() {
                headers.push(("User-Agent".into(), "PaoPao".into()));
            }
            headers.push(("Connection".into(), "close".into()));
            let request = Request {
                method: method.clone(),
                target,
                headers,
                body: body.clone(),
                close: true,
            };
            let once = async {
                let mut s: Box<dyn meow_transport::Stream> = if https {
                    self.connect(&host, port).await?
                } else {
                    self.dialer.dial(&host, port, false).await?
                };
                write_request(&mut s, &request).await?;
                read_response(&mut s, &mut Vec::new(), &request.method).await
            };
            let r = tokio::time::timeout_at(deadline, once)
                .await
                .map_err(|_| "timed out".to_string())?
                .map_err(|e| e.to_string())?;
            let location = find(&r.headers, "location").map(str::to_string);
            if req.follow_redirects && hop < 5 && matches!(r.status, 301 | 302 | 303 | 307 | 308) {
                if let Some(loc) = location {
                    url = join_url(&url, &loc);
                    if r.status == 303 || (matches!(r.status, 301 | 302) && method == "POST") {
                        method = "GET".into();
                        body.clear();
                    }
                    continue;
                }
            }
            let mut m = Message {
                status: r.status,
                headers: r.headers,
                body: Some(r.body),
                ..Message::default()
            };
            decode_body(&mut m);
            return Ok(HttpResponse {
                status: m.status,
                headers: m.headers,
                body: m.body.unwrap_or_default(),
            });
        }
        Err("too many redirects".into())
    }

    async fn connect(&self, host: &str, port: u16) -> io::Result<Box<dyn meow_transport::Stream>> {
        use meow_transport::Transport as _;
        let tcp = self.dialer.dial(host, port, false).await?;
        let cfg = meow_transport::tls::TlsConfig {
            skip_cert_verify: self.skip_cert_verify,
            alpn: vec!["http/1.1".into()],
            ..meow_transport::tls::TlsConfig::new(host)
        };
        let layer = meow_transport::tls::TlsLayer::new(&cfg).map_err(io::Error::other)?;
        layer.connect(tcp).await.map_err(io::Error::other)
    }
}

// ---------------------------------------------------------------- HTTP/1.1

/// `http(s)://host[:port]/path?query` → (https, host, port, target).
fn split_url(url: &str) -> Option<(bool, String, u16, String)> {
    let (https, rest) = match url.strip_prefix("https://") {
        Some(r) => (true, r),
        None => (false, url.strip_prefix("http://")?),
    };
    let (authority, target) = match rest.find(['/', '?']) {
        Some(i) if rest.as_bytes()[i] == b'/' => (&rest[..i], rest[i..].to_string()),
        Some(i) => (&rest[..i], format!("/{}", &rest[i..])),
        None => (rest, "/".to_string()),
    };
    let authority = authority.rsplit('@').next()?;
    let default_port = if https { 443 } else { 80 };
    let (host, port) = if let Some(v6) = authority.strip_prefix('[') {
        let (h, p) = v6.split_once(']')?;
        (
            h.to_string(),
            p.strip_prefix(':')
                .and_then(|p| p.parse().ok())
                .unwrap_or(default_port),
        )
    } else if let Some((h, p)) = authority.rsplit_once(':') {
        (h.to_string(), p.parse().ok()?)
    } else {
        (authority.to_string(), default_port)
    };
    (!host.is_empty()).then_some((https, host, port, target))
}

/// A `Location` against the URL it came from.
fn join_url(base: &str, location: &str) -> String {
    if location.starts_with("http://") || location.starts_with("https://") {
        return location.to_string();
    }
    let scheme_end = base.find("://").map_or(0, |i| i + 3);
    let origin_end = base[scheme_end..]
        .find('/')
        .map_or(base.len(), |i| scheme_end + i);
    if let Some(rest) = location.strip_prefix("//") {
        return format!("{}{rest}", &base[..scheme_end]);
    }
    if location.starts_with('/') {
        return format!("{}{location}", &base[..origin_end]);
    }
    let dir_end = base
        .rfind('/')
        .filter(|&i| i >= origin_end)
        .map_or(base.len(), |i| i + 1);
    let dir = if dir_end == base.len() && dir_end == origin_end {
        format!("{}/", &base[..origin_end])
    } else {
        base[..dir_end].to_string()
    };
    format!("{dir}{location}")
}

struct Request {
    method: String,
    target: String,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
    close: bool,
}

struct Response {
    status: u16,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
    close: bool,
}

const MAX_HEAD: usize = 64 << 10;
const MAX_BODY: usize = 32 << 20;

/// Reads until a full head is buffered; its length, or None at EOF.
async fn read_head<S: AsyncRead + Unpin>(
    s: &mut S,
    buf: &mut Vec<u8>,
) -> io::Result<Option<usize>> {
    loop {
        if let Some(i) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            return Ok(Some(i + 4));
        }
        if buf.len() > MAX_HEAD {
            return Err(io::Error::other("header too large"));
        }
        let mut chunk = [0u8; 8192];
        let n = s.read(&mut chunk).await?;
        if n == 0 {
            return if buf.is_empty() {
                Ok(None)
            } else {
                Err(io::ErrorKind::UnexpectedEof.into())
            };
        }
        buf.extend_from_slice(&chunk[..n]);
    }
}

fn find<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
    meow_script::header(headers, name)
}

fn wants_close(version_minor: u8, headers: &[(String, String)]) -> bool {
    match find(headers, "connection").map(str::to_ascii_lowercase) {
        Some(v) if v.contains("close") => true,
        Some(v) if v.contains("keep-alive") => false,
        _ => version_minor == 0,
    }
}

async fn fill<S: AsyncRead + Unpin>(s: &mut S, buf: &mut Vec<u8>, want: usize) -> io::Result<()> {
    while buf.len() < want {
        let mut chunk = [0u8; 16384];
        let n = s.read(&mut chunk).await?;
        if n == 0 {
            return Err(io::ErrorKind::UnexpectedEof.into());
        }
        buf.extend_from_slice(&chunk[..n]);
    }
    Ok(())
}

/// The body after a head: Content-Length, chunked, or (responses) to EOF.
async fn read_body<S: AsyncRead + Unpin>(
    s: &mut S,
    buf: &mut Vec<u8>,
    headers: &[(String, String)],
    until_eof: bool,
) -> io::Result<Vec<u8>> {
    let chunked = find(headers, "transfer-encoding")
        .is_some_and(|v| v.to_ascii_lowercase().contains("chunked"));
    if chunked {
        let mut body = Vec::new();
        loop {
            let line_end = loop {
                if let Some(i) = buf.windows(2).position(|w| w == b"\r\n") {
                    break i;
                }
                let have = buf.len();
                fill(s, buf, have + 1).await?;
            };
            let size_str = String::from_utf8_lossy(&buf[..line_end]);
            let size = usize::from_str_radix(size_str.split(';').next().unwrap_or("").trim(), 16)
                .map_err(|_| io::Error::other("bad chunk size"))?;
            buf.drain(..line_end + 2);
            if size == 0 {
                // Trailers: up to the empty line.
                loop {
                    let have = buf.len();
                    if let Some(i) = buf.windows(2).position(|w| w == b"\r\n") {
                        buf.drain(..i + 2);
                        if i == 0 {
                            break;
                        }
                        continue;
                    }
                    fill(s, buf, have + 1).await?;
                }
                return Ok(body);
            }
            if body.len() + size > MAX_BODY {
                return Err(io::Error::other("body too large"));
            }
            fill(s, buf, size + 2).await?;
            body.extend_from_slice(&buf[..size]);
            buf.drain(..size + 2);
        }
    }
    if let Some(len) = find(headers, "content-length").and_then(|v| v.trim().parse::<usize>().ok())
    {
        if len > MAX_BODY {
            return Err(io::Error::other("body too large"));
        }
        fill(s, buf, len).await?;
        return Ok(buf.drain(..len).collect());
    }
    if until_eof {
        let mut rest = std::mem::take(buf);
        s.read_to_end(&mut rest).await?;
        return Ok(rest);
    }
    Ok(Vec::new())
}

async fn read_request<S: AsyncRead + Unpin>(
    s: &mut S,
    buf: &mut Vec<u8>,
) -> io::Result<Option<Request>> {
    let Some(end) = read_head(s, buf).await? else {
        return Ok(None);
    };
    let mut hs = [httparse::EMPTY_HEADER; 128];
    let mut r = httparse::Request::new(&mut hs);
    r.parse(&buf[..end]).map_err(io::Error::other)?;
    let method = r.method.unwrap_or("GET").to_string();
    let target = r.path.unwrap_or("/").to_string();
    let minor = r.version.unwrap_or(1);
    let headers: Vec<(String, String)> = r
        .headers
        .iter()
        .map(|h| {
            (
                h.name.to_string(),
                String::from_utf8_lossy(h.value).into_owned(),
            )
        })
        .collect();
    buf.drain(..end);
    let body = read_body(s, buf, &headers, false).await?;
    Ok(Some(Request {
        close: wants_close(minor, &headers),
        method,
        target,
        headers,
        body,
    }))
}

async fn read_response<S: AsyncRead + Unpin>(
    s: &mut S,
    buf: &mut Vec<u8>,
    method: &str,
) -> io::Result<Response> {
    let end = read_head(s, buf)
        .await?
        .ok_or(io::ErrorKind::UnexpectedEof)?;
    let mut hs = [httparse::EMPTY_HEADER; 128];
    let mut r = httparse::Response::new(&mut hs);
    r.parse(&buf[..end]).map_err(io::Error::other)?;
    let status = r.code.unwrap_or(502);
    let minor = r.version.unwrap_or(1);
    let headers: Vec<(String, String)> = r
        .headers
        .iter()
        .map(|h| {
            (
                h.name.to_string(),
                String::from_utf8_lossy(h.value).into_owned(),
            )
        })
        .collect();
    buf.drain(..end);
    let no_body =
        method.eq_ignore_ascii_case("HEAD") || status == 204 || status == 304 || status / 100 == 1;
    let close = wants_close(minor, &headers);
    let body = if no_body {
        Vec::new()
    } else {
        let has_length = find(&headers, "content-length").is_some()
            || find(&headers, "transfer-encoding").is_some();
        read_body(s, buf, &headers, !has_length).await?
    };
    Ok(Response {
        status,
        close: close
            || (!no_body
                && find(&headers, "content-length").is_none()
                && find(&headers, "transfer-encoding").is_none()),
        headers,
        body,
    })
}

/// Hop-by-hop and length headers we re-emit ourselves.
fn forwarded(name: &str) -> bool {
    ![
        "content-length",
        "transfer-encoding",
        "connection",
        "keep-alive",
        "proxy-connection",
    ]
    .iter()
    .any(|h| name.eq_ignore_ascii_case(h))
}

async fn write_request<S: AsyncWrite + Unpin>(s: &mut S, r: &Request) -> io::Result<()> {
    let mut out = format!("{} {} HTTP/1.1\r\n", r.method, r.target).into_bytes();
    for (k, v) in r.headers.iter().filter(|(k, _)| forwarded(k)) {
        out.extend_from_slice(format!("{k}: {v}\r\n").as_bytes());
    }
    if !r.body.is_empty() || !matches!(r.method.as_str(), "GET" | "HEAD") {
        out.extend_from_slice(format!("Content-Length: {}\r\n", r.body.len()).as_bytes());
    }
    out.extend_from_slice(b"\r\n");
    out.extend_from_slice(&r.body);
    s.write_all(&out).await?;
    s.flush().await
}

async fn write_response<S: AsyncWrite + Unpin>(
    s: &mut S,
    m: &Message,
    close: bool,
) -> io::Result<()> {
    let reason = match m.status {
        200 => "OK",
        204 => "No Content",
        301 => "Moved Permanently",
        302 => "Found",
        304 => "Not Modified",
        400 => "Bad Request",
        403 => "Forbidden",
        404 => "Not Found",
        500 => "Internal Server Error",
        502 => "Bad Gateway",
        _ => "",
    };
    let mut out = format!("HTTP/1.1 {} {reason}\r\n", m.status).into_bytes();
    for (k, v) in m.headers.iter().filter(|(k, _)| forwarded(k)) {
        out.extend_from_slice(format!("{k}: {v}\r\n").as_bytes());
    }
    let body = m.body.as_deref().unwrap_or_default();
    out.extend_from_slice(format!("Content-Length: {}\r\n", body.len()).as_bytes());
    if close {
        out.extend_from_slice(b"Connection: close\r\n");
    }
    out.extend_from_slice(b"\r\n");
    out.extend_from_slice(body);
    s.write_all(&out).await?;
    s.flush().await
}

/// Scripts see plain bodies: gzip / deflate are undone first (the answer
/// then goes out uncompressed).
fn decode_body(m: &mut Message) {
    use std::io::Read as _;
    let Some(enc) = find(&m.headers, "content-encoding").map(str::to_ascii_lowercase) else {
        return;
    };
    let Some(body) = &m.body else {
        return;
    };
    let mut out = Vec::new();
    let ok = match enc.as_str() {
        "gzip" | "x-gzip" => flate2::read::GzDecoder::new(&body[..])
            .read_to_end(&mut out)
            .is_ok(),
        "deflate" => flate2::read::ZlibDecoder::new(&body[..])
            .read_to_end(&mut out)
            .is_ok(),
        _ => false,
    };
    if ok {
        m.body = Some(out);
        m.headers
            .retain(|(k, _)| !k.eq_ignore_ascii_case("content-encoding"));
    }
}

#[async_trait]
impl ProxyAdapter for MitmAdapter {
    fn name(&self) -> &str {
        &self.name
    }

    fn adapter_type(&self) -> AdapterType {
        AdapterType::Mitm
    }

    fn addr(&self) -> &str {
        ""
    }

    fn support_udp(&self) -> bool {
        false
    }

    async fn dial_tcp(&self, metadata: &Metadata) -> Result<Box<dyn ProxyConn>> {
        // The leaf certificate needs the name the client asked for.
        let host = if !metadata.host.is_empty() {
            metadata.host.to_string()
        } else if !metadata.sniff_host.is_empty() {
            metadata.sniff_host.to_string()
        } else {
            metadata
                .dst_ip
                .map(|ip| ip.to_string())
                .ok_or_else(|| err("no destination"))?
        };
        let port = metadata.dst_port;
        let (client, server) = tokio::io::duplex(64 << 10);
        let shared = Arc::clone(&self.shared);
        tokio::spawn(async move {
            if let Err(e) = shared.serve(server, host.clone(), port).await {
                debug!("mitm {host}: {e}");
            }
        });
        Ok(Box::new(StreamConn(Box::new(client))))
    }

    async fn dial_udp(&self, _metadata: &Metadata) -> Result<Box<dyn ProxyPacketConn>> {
        Err(MeowError::NotSupported(
            "mitm: UDP not supported (reject QUIC to these hosts)".into(),
        ))
    }

    fn health(&self) -> &ProxyHealth {
        &self.health
    }
}

#[cfg(test)]
#[path = "mitm_tests.rs"]
mod tests;
