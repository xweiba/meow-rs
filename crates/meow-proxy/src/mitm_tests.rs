use std::io::Write as _;
use std::net::SocketAddr;

use boring::ssl::{SslConnector, SslMethod, SslVerifyMode};
use boring::x509::store::X509StoreBuilder;
use tokio::net::TcpListener;

use super::*;

/// Dials one fixed address whatever the host (the "real server").
struct To(SocketAddr);

#[async_trait]
impl crate::dialer::TcpDialer for To {
    async fn dial(
        &self,
        _host: &str,
        _port: u16,
        _internal: bool,
    ) -> io::Result<Box<dyn meow_transport::Stream>> {
        Ok(Box::new(tokio::net::TcpStream::connect(self.0).await?))
    }
}

fn gzip(b: &[u8]) -> Vec<u8> {
    let mut e = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    e.write_all(b).unwrap();
    e.finish().unwrap()
}

/// A TLS server for any name (self-signed): answers `/chunked` chunked,
/// `/gzip` gzip-encoded, anything else echoing the request line and body.
async fn upstream() -> SocketAddr {
    let key = rcgen::KeyPair::generate().unwrap();
    let cert = rcgen::CertificateParams::new(vec!["example.test".into()])
        .unwrap()
        .self_signed(&key)
        .unwrap();
    let mut b = SslAcceptor::mozilla_intermediate_v5(SslMethod::tls()).unwrap();
    b.set_certificate(&X509::from_der(cert.der()).unwrap())
        .unwrap();
    b.set_private_key(&PKey::private_key_from_der(&key.serialize_der()).unwrap())
        .unwrap();
    let acceptor = b.build();
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let (tcp, _) = l.accept().await.unwrap();
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                let mut s = tokio_boring::accept(&acceptor, tcp).await.unwrap();
                let mut buf = Vec::new();
                while let Ok(Some(req)) = read_request(&mut s, &mut buf).await {
                    let out: Vec<u8> = match req.target.as_str() {
                        "/chunked" => b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n6\r\n there\r\n0\r\n\r\n".to_vec(),
                        "/gzip" => {
                            let z = gzip(b"zipped");
                            let mut o = format!(
                                "HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nContent-Length: {}\r\n\r\n",
                                z.len()
                            )
                            .into_bytes();
                            o.extend_from_slice(&z);
                            o
                        }
                        t => {
                            let body = format!(
                                "{} {t} {}",
                                req.method,
                                String::from_utf8_lossy(&req.body)
                            );
                            format!(
                                "HTTP/1.1 200 OK\r\nX-Up: 1\r\nContent-Length: {}\r\n\r\n{body}",
                                body.len()
                            )
                            .into_bytes()
                        }
                    };
                    s.write_all(&out).await.unwrap();
                }
            });
        }
    });
    addr
}

const SCRIPT_RESPONSE: &str = r#"
$notification.post('mitm', $request.url, 'seen', { url: 'https://example.test/' });
const h = $response.headers;
h['X-Arg'] = $argument;
$done({ body: $response.body + ' +script', headers: h });
"#;

/// Asks the server itself (through the proxy) and answers with that.
const SCRIPT_FETCH: &str = r#"
$httpClient.post({ url: 'https://example.test/from-script', body: 'q' }, (err, resp, data) => {
  $done({ response: { status: 200, body: err ? 'error ' + err : resp.status + ' ' + data } });
});
"#;

const SCRIPT_REQUEST: &str = r#"
if ($request.url.endsWith('/answer')) {
  $done({ response: { status: 200, headers: { 'X-Local': '1' }, body: 'from script' } });
} else {
  $done({ url: $request.url.replace('/old', '/new'), body: 'changed' });
}
"#;

fn rule(name: &str, pattern: &str, response: bool, path: &str) -> ScriptRule {
    ScriptRule {
        name: name.into(),
        pattern: Pattern::new(pattern).unwrap(),
        response,
        path: path.into(),
        argument: "lat=1".into(),
        binary_body: false,
        requires_body: true,
        timeout: Duration::from_secs(3),
        cron: None,
    }
}

async fn adapter(dir: &Path, up: SocketAddr) -> (MitmAdapter, String) {
    std::fs::write(dir.join("resp.js"), SCRIPT_RESPONSE).unwrap();
    std::fs::write(dir.join("req.js"), SCRIPT_REQUEST).unwrap();
    std::fs::write(dir.join("fetch.js"), SCRIPT_FETCH).unwrap();
    let (cert, key) = load_or_create_ca(&dir.join("ca.pem"), &dir.join("ca-key.pem")).unwrap();
    let a = MitmAdapter::new(
        "mitm",
        &cert,
        &key,
        vec![
            rule(
                "resp",
                r"^https://example\.test/(echo|chunked|gzip)",
                true,
                "resp.js",
            ),
            rule(
                "req",
                r"^https://example\.test/(old|answer)",
                false,
                "req.js",
            ),
            rule(
                "fetch",
                r"^https://example\.test/ask(?!-not)",
                false,
                "fetch.js",
            ),
        ],
        dir.to_path_buf(),
        None,
        true,
        Arc::new(To(up)),
        MitmExtras {
            notifications: Some(dir.join("notes.jsonl")),
            utc_offset_minutes: 480,
        },
    )
    .unwrap();
    (a, cert)
}

/// Opens a TLS session through the adapter, trusting only our CA.
async fn client(a: &MitmAdapter, ca: &str) -> tokio_boring::SslStream<Box<dyn ProxyConn>> {
    let md = Metadata {
        host: "example.test".into(),
        dst_port: 443,
        ..Metadata::default()
    };
    let conn = a.dial_tcp(&md).await.unwrap();
    let mut store = X509StoreBuilder::new().unwrap();
    store
        .add_cert(X509::from_pem(ca.as_bytes()).unwrap())
        .unwrap();
    let mut b = SslConnector::builder(SslMethod::tls()).unwrap();
    b.set_verify(SslVerifyMode::PEER);
    b.set_verify_cert_store(store.build()).unwrap();
    let cfg = b.build().configure().unwrap();
    tokio_boring::connect(cfg, "example.test", conn)
        .await
        .ok()
        .expect("handshake with the user's CA")
}

async fn get(
    s: &mut tokio_boring::SslStream<Box<dyn ProxyConn>>,
    buf: &mut Vec<u8>,
    method: &str,
    path: &str,
    body: &str,
) -> Response {
    let r = Request {
        method: method.into(),
        target: path.into(),
        headers: vec![("Host".into(), "example.test".into())],
        body: body.as_bytes().to_vec(),
        close: false,
    };
    write_request(s, &r).await.unwrap();
    read_response(s, buf, method).await.unwrap()
}

#[tokio::test]
async fn scripts_rewrite_through_the_users_ca() {
    let dir = tempfile::tempdir().unwrap();
    let up = upstream().await;
    let (a, ca) = adapter(dir.path(), up).await;
    let mut s = client(&a, &ca).await;
    let mut buf = Vec::new();

    // Response script, keep-alive over one session.
    let r = get(&mut s, &mut buf, "POST", "/echo", "hi").await;
    assert_eq!(r.status, 200);
    assert_eq!(String::from_utf8_lossy(&r.body), "POST /echo hi +script");
    assert_eq!(meow_script::header(&r.headers, "x-arg"), Some("lat=1"));
    assert_eq!(meow_script::header(&r.headers, "x-up"), Some("1"));

    // Chunked upstream, gzip undone before the script.
    let r = get(&mut s, &mut buf, "GET", "/chunked", "").await;
    assert_eq!(String::from_utf8_lossy(&r.body), "hello there +script");
    let r = get(&mut s, &mut buf, "GET", "/gzip", "").await;
    assert_eq!(String::from_utf8_lossy(&r.body), "zipped +script");
    assert_eq!(meow_script::header(&r.headers, "content-encoding"), None);

    // Request script: rewritten url and body; answered locally.
    let r = get(&mut s, &mut buf, "POST", "/old", "x").await;
    assert_eq!(String::from_utf8_lossy(&r.body), "POST /new changed");
    let r = get(&mut s, &mut buf, "GET", "/answer", "").await;
    assert_eq!(String::from_utf8_lossy(&r.body), "from script");
    assert_eq!(meow_script::header(&r.headers, "x-local"), Some("1"));

    // A script asking the network itself ($httpClient), through the proxy.
    let r = get(&mut s, &mut buf, "GET", "/ask", "").await;
    assert_eq!(String::from_utf8_lossy(&r.body), "200 POST /from-script q");
    // JavaScript-style look-ahead in the pattern.
    let r = get(&mut s, &mut buf, "GET", "/ask-not", "").await;
    assert_eq!(String::from_utf8_lossy(&r.body), "GET /ask-not ");

    // Notifications land where the app reads them.
    let notes = std::fs::read_to_string(dir.path().join("notes.jsonl")).unwrap();
    let first: serde_json::Value = serde_json::from_str(notes.lines().next().unwrap()).unwrap();
    assert_eq!(first["title"], "mitm");
    assert_eq!(first["body"], "seen");
    assert_eq!(first["url"], "https://example.test/");
    assert_eq!(first["script"], "resp");

    // No rule: passed through untouched.
    let r = get(&mut s, &mut buf, "GET", "/plain", "").await;
    assert_eq!(String::from_utf8_lossy(&r.body), "GET /plain ");
}

#[tokio::test]
async fn untrusted_ca_is_refused_by_clients() {
    let dir = tempfile::tempdir().unwrap();
    let up = upstream().await;
    let (a, _) = adapter(dir.path(), up).await;
    let other = tempfile::tempdir().unwrap();
    let (stranger, _) =
        load_or_create_ca(&other.path().join("c.pem"), &other.path().join("k.pem")).unwrap();
    let md = Metadata {
        host: "example.test".into(),
        dst_port: 443,
        ..Metadata::default()
    };
    let conn = a.dial_tcp(&md).await.unwrap();
    let mut store = X509StoreBuilder::new().unwrap();
    store
        .add_cert(X509::from_pem(stranger.as_bytes()).unwrap())
        .unwrap();
    let mut b = SslConnector::builder(SslMethod::tls()).unwrap();
    b.set_verify(SslVerifyMode::PEER);
    b.set_verify_cert_store(store.build()).unwrap();
    let cfg = b.build().configure().unwrap();
    assert!(tokio_boring::connect(cfg, "example.test", conn)
        .await
        .is_err());
}

#[test]
fn ca_is_made_once_and_kept() {
    let dir = tempfile::tempdir().unwrap();
    let (c1, k1) = load_or_create_ca(&dir.path().join("a.pem"), &dir.path().join("b.pem")).unwrap();
    let (c2, k2) = load_or_create_ca(&dir.path().join("a.pem"), &dir.path().join("b.pem")).unwrap();
    assert_eq!((c1, k1), (c2, k2));
}

#[tokio::test]
async fn bodies_by_length_chunks_and_eof() {
    let mut buf = Vec::new();
    let mut src: &[u8] = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3;x=1\r\nabc\r\n0\r\nT: 1\r\n\r\nHTTP/1.1 204 No Content\r\n\r\n";
    let r = read_response(&mut src, &mut buf, "GET").await.unwrap();
    assert_eq!(r.body, b"abc");
    assert!(!r.close);
    let r = read_response(&mut src, &mut buf, "GET").await.unwrap();
    assert_eq!(r.status, 204);
    let mut src: &[u8] = b"HTTP/1.0 200 OK\r\n\r\nall of it";
    let r = read_response(&mut src, &mut Vec::new(), "GET")
        .await
        .unwrap();
    assert_eq!(r.body, b"all of it");
    assert!(r.close);
}

#[test]
fn urls_split_and_join() {
    assert_eq!(
        split_url("https://a.b:8443/x?y=1"),
        Some((true, "a.b".into(), 8443, "/x?y=1".into()))
    );
    assert_eq!(
        split_url("http://a.b?q"),
        Some((false, "a.b".into(), 80, "/?q".into()))
    );
    assert_eq!(
        split_url("https://[::1]/"),
        Some((true, "::1".into(), 443, "/".into()))
    );
    assert_eq!(split_url("ftp://a"), None);
    assert_eq!(join_url("https://a.b/x/y", "/z"), "https://a.b/z");
    assert_eq!(join_url("https://a.b/x/y", "z"), "https://a.b/x/z");
    assert_eq!(join_url("https://a.b/x", "//c.d/e"), "https://c.d/e");
    assert_eq!(join_url("https://a.b", "z"), "https://a.b/z");
    assert_eq!(join_url("https://a.b/x", "http://c/"), "http://c/");
}

#[test]
fn cron_schedules() {
    use time::macros::datetime;
    let at = |c: &Cron, t| c.matches(t);
    let daily = Cron::parse("0 8 * * *").unwrap();
    assert!(at(&daily, datetime!(2026-10-05 08:00 +8)));
    assert!(!at(&daily, datetime!(2026-10-05 08:01 +8)));
    let steps = Cron::parse("*/15 9-17 * * mon-fri").unwrap();
    assert!(at(&steps, datetime!(2026-10-05 09:45 +8)), "a Monday");
    assert!(!at(&steps, datetime!(2026-10-04 09:45 +8)), "a Sunday");
    let seconds = Cron::parse("30 0 12 1,15 * *").unwrap();
    assert!(at(&seconds, datetime!(2026-10-15 12:00 +8)));
    // Both day fields restricted: either.
    let either = Cron::parse("0 0 1 * 0").unwrap();
    assert!(at(&either, datetime!(2026-10-04 00:00 +8)), "Sunday");
    assert!(at(&either, datetime!(2026-10-01 00:00 +8)), "the 1st");
    assert!(Cron::parse("0 8 * *").is_err());
    assert!(Cron::parse("61 8 * * *").is_err());
    assert!(Cron::parse("0 8 * * 7")
        .unwrap()
        .matches(datetime!(2026-10-04 08:00 +8)));
}
