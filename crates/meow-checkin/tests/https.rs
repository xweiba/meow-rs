//! A request step over HTTPS: the core's TLS stack against a local TLS
//! site. The certificate is verified (against the name, under the trust
//! anchors); a site whose certificate does not check out gets nothing.

mod support;

use meow_checkin::model::{Run, StepStatus};
use meow_checkin::{Engine, EngineConfig, SystemClock};
use parking_lot::Mutex;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use serde_json::json;
use std::net::SocketAddr;
use std::sync::Arc;
use support::{add_task, quick_config, LocalConnector};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

const HOME: &str = "https://main.example.com/user";

struct Site {
    addr: SocketAddr,
    /// The certificate, DER: its own trust anchor.
    cert: Vec<u8>,
    /// Request heads that arrived inside TLS.
    heads: Arc<Mutex<Vec<String>>>,
    /// ALPN of each handshake that completed.
    alpn: Arc<Mutex<Vec<Option<Vec<u8>>>>>,
}

/// A TLS site with a self-signed certificate for `names`, answering every
/// request `200 {"ret":1,"msg":"ok"}`.
async fn site(names: &[&str]) -> Site {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let ck = rcgen::generate_simple_self_signed(
        names.iter().map(ToString::to_string).collect::<Vec<_>>(),
    )
    .unwrap();
    let cert = ck.cert.der().to_vec();
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(ck.key_pair.serialize_der()));
    let mut config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![CertificateDer::from(cert.clone())], key)
        .unwrap();
    // A site that would rather speak h2: the client must ask for 1.1.
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    let acceptor = TlsAcceptor::from(Arc::new(config));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let heads = Arc::new(Mutex::new(Vec::new()));
    let alpn = Arc::new(Mutex::new(Vec::new()));
    {
        let (heads, alpn) = (Arc::clone(&heads), Arc::clone(&alpn));
        tokio::spawn(async move {
            loop {
                let Ok((tcp, _)) = listener.accept().await else {
                    return;
                };
                let acceptor = acceptor.clone();
                let (heads, alpn) = (Arc::clone(&heads), Arc::clone(&alpn));
                tokio::spawn(async move {
                    let Ok(mut tls) = acceptor.accept(tcp).await else {
                        return;
                    };
                    alpn.lock()
                        .push(tls.get_ref().1.alpn_protocol().map(<[u8]>::to_vec));
                    let mut buf = Vec::new();
                    let mut tmp = [0u8; 4096];
                    // The head and the three bytes of body the step sends.
                    while !buf.windows(7).any(|w| w == b"\r\n\r\na=1") {
                        match tls.read(&mut tmp).await {
                            Ok(n) if n > 0 => buf.extend_from_slice(&tmp[..n]),
                            _ => return,
                        }
                    }
                    heads.lock().push(String::from_utf8_lossy(&buf).to_string());
                    let body = r#"{"ret":1,"msg":"ok"}"#;
                    let answer = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\
                         Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
                        body.len()
                    );
                    let _ = tls.write_all(answer.as_bytes()).await;
                    let _ = tls.shutdown().await;
                });
            }
        });
    }
    Site {
        addr,
        cert,
        heads,
        alpn,
    }
}

async fn run_once(site: &Site, roots: Vec<Vec<u8>>, url: &str) -> Run {
    let dir = tempfile::tempdir().unwrap();
    let connector = LocalConnector::new(site.addr);
    let engine = Engine::open(
        dir.path(),
        connector.shared(),
        Arc::new(SystemClock),
        EngineConfig {
            extra_roots: roots,
            ..quick_config()
        },
    );
    let id = add_task(
        &engine,
        "a",
        HOME,
        json!([support::api_step("签到", url, HOME)]),
    );
    engine.run_task(&id, false).unwrap();
    engine.run_pending().await;
    assert_eq!(connector.dialed.lock()[0].2, 443);
    engine.snapshot(false).runs.remove(0)
}

#[tokio::test]
async fn a_request_step_goes_over_https_with_the_certificate_verified() {
    let s = site(&["main.example.com"]).await;
    let run = run_once(
        &s,
        vec![s.cert.clone()],
        "https://main.example.com/user/checkin",
    )
    .await;
    assert_eq!(run.steps[0].status, StepStatus::Ok, "{:?}", run.steps[0]);
    assert_eq!(run.steps[0].http_status, Some(200));
    assert_eq!(run.steps[0].summary, "200 · ret 1 · ok");
    let heads = s.heads.lock().clone();
    assert_eq!(heads.len(), 1);
    assert!(heads[0].starts_with("POST /user/checkin HTTP/1.1\r\nHost: main.example.com\r\n"));
    assert!(heads[0].contains("\r\ncookie: sid=abc==; uid=7\r\n"));
    // HTTP/1.1 was asked for, though the site prefers h2.
    assert_eq!(s.alpn.lock().clone(), [Some(b"http/1.1".to_vec())]);
}

#[tokio::test]
async fn a_certificate_that_does_not_check_out_gets_no_request() {
    // Not under any trust anchor the engine has.
    let s = site(&["main.example.com"]).await;
    let run = run_once(&s, Vec::new(), "https://main.example.com/user/checkin").await;
    assert_eq!(run.steps[0].status, StepStatus::Failed);
    assert_eq!(run.steps[0].http_status, None);
    assert_eq!(run.steps[0].summary, "和这个网站建立安全连接失败。");
    assert!(s.heads.lock().is_empty());

    // Trusted, but issued for another name.
    let s = site(&["other.example.com"]).await;
    let run = run_once(
        &s,
        vec![s.cert.clone()],
        "https://main.example.com/user/checkin",
    )
    .await;
    assert_eq!(run.steps[0].status, StepStatus::Failed);
    assert_eq!(run.steps[0].summary, "和这个网站建立安全连接失败。");
    assert!(s.heads.lock().is_empty());
}
