//! `meow paopao parse|build|fetch` (the children behind `/paopao/…`): the
//! stdin/stdout contract against the library they wrap, and the API routes
//! on a running core, against a local subscription server.

use std::process::Stdio;
use std::time::Duration;

use serde_json::{json, Value};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

const LINKS: &str = "ss://YWVzLTI1Ni1nY206cGFzcw@1.2.3.4:8388#HK%2001\n\
    vless://0b9a8b56-58a4-4a8c-9a3a-1a8f7c0d3e21@5.6.7.8:443?security=tls&sni=a.example&type=tcp#JP%2002\n";
const USERINFO: &str = "upload=1; download=2; total=1000; expire=1798732800";

/// Runs `meow paopao <op>` with `input` on stdin: (stdout, exit code).
async fn child(op: &str, input: &str) -> (String, i32) {
    let mut c = tokio::process::Command::new(env!("CARGO_BIN_EXE_meow"))
        .args(["paopao", op])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    let mut stdin = c.stdin.take().unwrap();
    stdin.write_all(input.as_bytes()).await.unwrap();
    drop(stdin);
    let out = tokio::time::timeout(Duration::from_secs(60), c.wait_with_output())
        .await
        .unwrap()
        .unwrap();
    (
        String::from_utf8(out.stdout).unwrap(),
        out.status.code().unwrap(),
    )
}

fn build_input() -> String {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../meow-paopao/tests/golden/build/regions--default--v4.json"
    );
    let golden: Value = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    golden["input"].to_string()
}

/// [`build_input`] with ten times the nodes: an answer far past what the
/// API reads whole before answering.
fn big_build_input() -> String {
    let mut input: Value = serde_json::from_str(&build_input()).unwrap();
    let nodes = input["subscriptions"][0]["nodes"].as_array_mut().unwrap();
    let base = nodes.clone();
    for i in 1..10 {
        nodes.extend(base.iter().map(|n| {
            let mut n = n.clone();
            n["name"] = format!("{} #{i}", n["name"].as_str().unwrap()).into();
            let port = n["outbound"]["server_port"].as_u64().unwrap();
            n["outbound"]["server_port"] = (port + 1000 * i).into();
            n
        }));
    }
    input.to_string()
}

#[tokio::test]
async fn parse_and_build_print_what_the_library_returns() {
    let (out, code) = child("parse", LINKS).await;
    assert_eq!(code, 0);
    assert_eq!(out, meow_paopao::parse_json(LINKS).to_string());
    assert_eq!(
        serde_json::from_str::<Value>(&out).unwrap()["nodes"]
            .as_array()
            .unwrap()
            .len(),
        2
    );

    let input = build_input();
    let (out, code) = child("build", &input).await;
    assert_eq!(code, 0);
    assert_eq!(out, meow_paopao::build_json(&input).to_string());

    // An error answer is the library's, with exit code 2.
    let (out, code) = child("build", "[1]").await;
    assert_eq!(code, 2);
    assert_eq!(out, meow_paopao::build_json("[1]").to_string());
}

/// A subscription server: `/sub` redirects to `/real`, which answers
/// [`LINKS`] with a `subscription-userinfo` header (403 to a user agent
/// that is neither the app's nor the tests'); anything else is 404.
async fn subscription_server() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((mut s, _)) = listener.accept().await else {
                return;
            };
            tokio::spawn(async move {
                let head = read_head(&mut s).await;
                let path = head.split_whitespace().nth(1).unwrap_or("").to_owned();
                let agent = head
                    .lines()
                    .find_map(|l| l.strip_prefix("user-agent: "))
                    .unwrap_or("")
                    .to_owned();
                let res = match path.as_str() {
                    // The app's user agent unless the request names one.
                    "/real" if !matches!(agent.as_str(), "clash.meta" | "paopao-test") => {
                        "HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n".to_owned()
                    }
                    "/sub" => "HTTP/1.1 302 Found\r\nLocation: /real\r\nContent-Length: 0\r\n\r\n".to_owned(),
                    "/real" => format!(
                        "HTTP/1.1 200 OK\r\nSubscription-Userinfo: {USERINFO}\r\n\
                         Content-Disposition: attachment; filename=\"my.yaml\"\r\nContent-Length: {}\r\n\r\n{LINKS}",
                        LINKS.len()
                    ),
                    _ => "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n".to_owned(),
                };
                let _ = s.write_all(res.as_bytes()).await;
                let _ = s.shutdown().await;
            });
        }
    });
    format!("http://{addr}")
}

/// The request head, lower-cased.
async fn read_head(s: &mut TcpStream) -> String {
    let mut head = Vec::new();
    let mut byte = [0u8];
    while !head.ends_with(b"\r\n\r\n") {
        if s.read(&mut byte).await.unwrap_or(0) == 0 {
            break;
        }
        head.push(byte[0]);
    }
    String::from_utf8_lossy(&head).to_ascii_lowercase()
}

/// An HTTP `CONNECT` proxy; each tunnel it opens is reported on the
/// channel.
async fn connect_proxy() -> (String, tokio::sync::mpsc::UnboundedReceiver<String>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
    tokio::spawn(async move {
        loop {
            let Ok((mut s, _)) = listener.accept().await else {
                return;
            };
            let tx = tx.clone();
            tokio::spawn(async move {
                let head = read_head(&mut s).await;
                let target = head.split_whitespace().nth(1).unwrap_or("").to_owned();
                let _ = tx.send(target.clone());
                let Ok(mut up) = TcpStream::connect(&target).await else {
                    return;
                };
                let _ = s
                    .write_all(b"HTTP/1.1 200 Connection established\r\n\r\n")
                    .await;
                let _ = tokio::io::copy_bidirectional(&mut s, &mut up).await;
            });
        }
    });
    (addr.to_string(), rx)
}

#[tokio::test]
async fn fetch_downloads_and_parses_with_the_header_usage() {
    let base = subscription_server().await;
    let (out, code) = child(
        "fetch",
        &json!({ "url": format!("{base}/sub") }).to_string(),
    )
    .await;
    assert_eq!(code, 0, "{out}");
    let v: Value = serde_json::from_str(&out).unwrap();
    let parsed = meow_paopao::parse_json(LINKS);
    assert_eq!(v["nodes"], parsed["nodes"]);
    assert_eq!(v["status"], 200);
    assert_eq!(v["final_url"], format!("{base}/real"));
    assert_eq!(v["content_disposition"], "attachment; filename=\"my.yaml\"");
    assert_eq!(
        v["usage"],
        json!({"upload": 1, "download": 2, "total": 1000, "expire": 1_798_732_800_000_i64})
    );

    // Not 200: exit 3 with the status.
    let (out, code) = child(
        "fetch",
        &json!({ "url": format!("{base}/gone") }).to_string(),
    )
    .await;
    assert_eq!(code, 3);
    let v: Value = serde_json::from_str(&out).unwrap();
    assert_eq!(v["status"], 404);
    assert!(v["error"].is_string());

    // Bad input: exit 2.
    let (_, code) = child("fetch", r#"{"url": "file:///etc/passwd"}"#).await;
    assert_eq!(code, 2);
}

#[tokio::test]
async fn fetch_goes_through_the_proxy_it_is_given() {
    let base = subscription_server().await;
    let (proxy, mut tunnels) = connect_proxy().await;
    let req = json!({ "url": format!("{base}/real"), "proxy": proxy, "user_agent": "paopao-test" });
    let (out, code) = child("fetch", &req.to_string()).await;
    assert_eq!(code, 0, "{out}");
    assert_eq!(
        tunnels.recv().await.unwrap(),
        base.trim_start_matches("http://")
    );
    let v: Value = serde_json::from_str(&out).unwrap();
    assert_eq!(v["nodes"].as_array().unwrap().len(), 2);
}

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// `method path` with `body` on the core's API over HTTP/1.0 (no chunked
/// framing to undo): (status, body).
async fn api(port: u16, path: &str, secret: Option<&str>, body: &str) -> (u16, String) {
    let mut s = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    let auth = secret.map_or(String::new(), |s| format!("Authorization: Bearer {s}\r\n"));
    let req = format!(
        "POST {path} HTTP/1.0\r\nHost: 127.0.0.1:{port}\r\n{auth}Content-Length: {}\r\n\r\n{body}",
        body.len()
    );
    s.write_all(req.as_bytes()).await.unwrap();
    let mut res = Vec::new();
    tokio::time::timeout(Duration::from_secs(60), s.read_to_end(&mut res))
        .await
        .unwrap()
        .unwrap();
    let res = String::from_utf8(res).unwrap();
    let (head, body) = res.split_once("\r\n\r\n").unwrap();
    let status = head.split_whitespace().nth(1).unwrap().parse().unwrap();
    (status, body.to_owned())
}

#[tokio::test]
async fn the_api_runs_them_in_children() {
    let base = subscription_server().await;
    let (api_port, mixed_port) = (free_port(), free_port());
    let home = tempfile::tempdir().unwrap();
    // Geodata links that fail at once: the core must not go online.
    let config = format!(
        "mixed-port: {mixed_port}\nbind-address: 127.0.0.1\nallow-lan: false\n\
         external-controller: 127.0.0.1:{api_port}\nsecret: s3cret\nlog-level: warning\n\
         geox-url: {{geoip: 'http://127.0.0.1:1/a', mmdb: 'http://127.0.0.1:1/b', \
         asn: 'http://127.0.0.1:1/c', geosite: 'http://127.0.0.1:1/d'}}\n\
         proxies: [{{name: d1, type: direct}}]\nrules: ['MATCH,DIRECT']\n"
    );
    let path = home.path().join("config.yaml");
    std::fs::write(&path, config).unwrap();
    let _core = tokio::process::Command::new(env!("CARGO_BIN_EXE_meow"))
        .arg("-f")
        .arg(&path)
        .arg("-d")
        .arg(home.path())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    let mut up = false;
    for _ in 0..200 {
        if TcpStream::connect(("127.0.0.1", api_port)).await.is_ok() {
            up = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(up, "the core's API did not come up");

    // Behind the API's auth.
    assert_eq!(api(api_port, "/paopao/parse", None, LINKS).await.0, 401);

    let (status, body) = api(api_port, "/paopao/parse", Some("s3cret"), LINKS).await;
    assert_eq!(status, 200);
    assert_eq!(body, meow_paopao::parse_json(LINKS).to_string());

    // Long enough to be streamed through.
    let input = big_build_input();
    let (status, body) = api(api_port, "/paopao/build", Some("s3cret"), &input).await;
    assert_eq!(status, 200);
    assert!(body.len() > 128 * 1024, "{}", body.len());
    assert_eq!(body, meow_paopao::build_json(&input).to_string());

    let (status, body) = api(api_port, "/paopao/build", Some("s3cret"), "nope").await;
    assert_eq!(status, 422);
    assert!(serde_json::from_str::<Value>(&body).unwrap()["error"].is_string());

    for via in ["direct", "proxy"] {
        let req = json!({ "url": format!("{base}/sub"), "via": via }).to_string();
        let (status, body) = api(api_port, "/paopao/fetch", Some("s3cret"), &req).await;
        assert_eq!(status, 200, "{via}: {body}");
        let v: Value = serde_json::from_str(&body).unwrap();
        assert_eq!(v["usage"]["total"], 1000, "{via}");
        assert_eq!(v["final_url"], format!("{base}/real"), "{via}");
    }
    let req = json!({ "url": format!("{base}/gone") }).to_string();
    let (status, body) = api(api_port, "/paopao/fetch", Some("s3cret"), &req).await;
    assert_eq!(status, 502);
    assert_eq!(serde_json::from_str::<Value>(&body).unwrap()["status"], 404);
}
