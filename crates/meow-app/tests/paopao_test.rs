//! `meow paopao parse|build|fetch|refresh|module|apply` (the children behind
//! `/paopao/…`): the stdin/stdout contract against the library they wrap,
//! and the API routes on a running core — its own refresh, rebuild and
//! reload included — against a local subscription server.

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

/// `POST path` with `body` on the core's API over HTTP/1.0 (no chunked
/// framing to undo): (status, body).
async fn api(port: u16, path: &str, secret: Option<&str>, body: &str) -> (u16, String) {
    api_call(port, "POST", path, secret, body).await
}

/// [`api`] with another method.
async fn api_call(
    port: u16,
    method: &str,
    path: &str,
    secret: Option<&str>,
    body: &str,
) -> (u16, String) {
    let mut s = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    let auth = secret.map_or(String::new(), |s| format!("Authorization: Bearer {s}\r\n"));
    let req = format!(
        "{method} {path} HTTP/1.0\r\nHost: 127.0.0.1:{port}\r\n{auth}Content-Length: {}\r\n\r\n{body}",
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

/// A core on loopback with its API at `api_port` (secret `s3cret`) and
/// its home in `home`; killed when dropped.
async fn start_core(
    api_port: u16,
    mixed_port: u16,
    home: &std::path::Path,
) -> tokio::process::Child {
    // Geodata links that fail at once: the core must not go online.
    let config = format!(
        "mixed-port: {mixed_port}\nbind-address: 127.0.0.1\nallow-lan: false\n\
         external-controller: 127.0.0.1:{api_port}\nsecret: s3cret\nlog-level: warning\n\
         geox-url: {{geoip: 'http://127.0.0.1:1/a', mmdb: 'http://127.0.0.1:1/b', \
         asn: 'http://127.0.0.1:1/c', geosite: 'http://127.0.0.1:1/d'}}\n\
         proxies: [{{name: d1, type: direct}}]\nrules: ['MATCH,DIRECT']\n"
    );
    let path = home.join("config.yaml");
    std::fs::write(&path, config).unwrap();
    let core = tokio::process::Command::new(env!("CARGO_BIN_EXE_meow"))
        .arg("-f")
        .arg(&path)
        .arg("-d")
        .arg(home)
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
    core
}

#[tokio::test]
async fn the_api_runs_them_in_children() {
    let base = subscription_server().await;
    let (api_port, mixed_port) = (free_port(), free_port());
    let home = tempfile::tempdir().unwrap();
    let _core = start_core(api_port, mixed_port, home.path()).await;

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

/// A build input as the app hands it over, small: subscription `a1` at
/// `url` with no lines yet, everything on loopback, mode global (no rule
/// data to fetch).
fn handed_over(url: &str, api_port: u16, mixed_port: u16) -> Value {
    json!({
        "subscriptions": [{"id": "a1", "url": url, "name": "127.0.0.1", "nodes": [], "skipped": 0}],
        "settings": {"mixed_port": mixed_port, "mode": "global"},
        "network": {"kind": "unknown", "addresses": []},
        "ipv6": false, "vpnOnly": false, "now": 0, "utcOffset": 0,
        "exits": {}, "resolved": {}, "strategy": "smart", "modules": [], "sshSecrets": {},
        "runtime": {"controllerPort": api_port, "secret": "s3cret", "ipv6": false},
    })
}

/// An HTTP `CONNECT` proxy that tunnels every request to `to`, whatever it
/// asks for.
async fn redirecting_proxy(to: String) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((mut s, _)) = listener.accept().await else {
                return;
            };
            let to = to.clone();
            tokio::spawn(async move {
                read_head(&mut s).await;
                let Ok(mut up) = TcpStream::connect(&to).await else {
                    return;
                };
                let _ = s
                    .write_all(b"HTTP/1.1 200 Connection established\r\n\r\n")
                    .await;
                let _ = tokio::io::copy_bidirectional(&mut s, &mut up).await;
            });
        }
    });
    addr.to_string()
}

#[tokio::test]
async fn refresh_and_apply_keep_the_store_as_the_app_would() {
    let base = subscription_server().await;
    let store = tempfile::tempdir().unwrap();
    let dir = store.path();
    let input = handed_over(&format!("{base}/sub"), 9090, 7890);
    std::fs::write(dir.join("input.json"), input.to_string()).unwrap();
    let record = |id: &str| -> Value {
        serde_json::from_str(
            &std::fs::read_to_string(dir.join(format!("subscriptions/{id}.json"))).unwrap(),
        )
        .unwrap()
    };

    let req = json!({ "dir": dir, "id": "a1", "url": format!("{base}/sub") });
    let (out, code) = child("refresh", &req.to_string()).await;
    assert_eq!(
        (code, serde_json::from_str::<Value>(&out).unwrap()),
        (0, json!({"id": "a1", "error": null}))
    );
    let r = record("a1");
    assert_eq!(r["node_count"], 2);
    assert_eq!(r["via"], "direct");
    assert_eq!(r["usage"]["total"], 1000);
    assert_eq!(r["file_name"], "my");
    assert_eq!(r["body_sha"].as_str().unwrap().len(), 64);
    assert_eq!(r["nodes"], meow_paopao::parse_json(LINKS)["nodes"]);

    // A dead link: its problem in the app's words (after trying ".../gone/").
    let req = json!({ "dir": dir, "id": "zz", "url": format!("{base}/gone") });
    let (out, code) = child("refresh", &req.to_string()).await;
    assert_eq!(code, 0);
    assert_eq!(
        serde_json::from_str::<Value>(&out).unwrap()["error"],
        meow_paopao::refresh::GONE
    );
    assert_eq!(record("zz")["last_error"], meow_paopao::refresh::GONE);

    // No answer directly: through the core's port, as the app retries.
    let (proxy, real) = (
        redirecting_proxy(base.trim_start_matches("http://").to_owned()).await,
        format!("http://127.0.0.1:{}/real", free_port()),
    );
    let req = json!({ "dir": dir, "id": "p", "url": real, "proxy": proxy });
    let (out, code) = child("refresh", &req.to_string()).await;
    assert_eq!(
        (
            code,
            serde_json::from_str::<Value>(&out).unwrap()["error"].clone()
        ),
        (0, Value::Null)
    );
    assert_eq!(record("p")["via"], "proxy");

    // Merged as the app merges, then built.
    let config = dir.join("config.yaml");
    let req = json!({ "dir": dir, "ids": ["a1", "zz"], "config": config, "now": 1_000 });
    let (out, code) = child("apply", &req.to_string()).await;
    assert_eq!(
        (code, serde_json::from_str::<Value>(&out).unwrap()),
        (
            0,
            json!({"input_changed": true, "rebuilt": true, "next": true})
        )
    );
    let kept: Value =
        serde_json::from_str(&std::fs::read_to_string(dir.join("input.json")).unwrap()).unwrap();
    let rec: meow_paopao::refresh::Refreshed = serde_json::from_value(record("a1")).unwrap();
    let want =
        meow_paopao::refresh::merge_refreshed(input["subscriptions"][0].as_object().unwrap(), &rec);
    assert_eq!(kept["subscriptions"][0], Value::Object(want));
    assert_eq!(kept["subscriptions"][0]["name"], "my");
    // The stored input keeps the time it was handed over with.
    assert_eq!(kept["now"], 0);
    let mut at = kept.clone();
    at["now"] = 1_000.into();
    let built = meow_paopao::build(&meow_paopao::BuildInput::from_json(&at)).config;
    let next: Value =
        serde_json::from_str(&std::fs::read_to_string(dir.join("config.next.yaml")).unwrap())
            .unwrap();
    assert_eq!(next, Value::Object(built));

    // Once it runs: the same lines change nothing; a forced build finds
    // the same config.
    std::fs::rename(dir.join("config.next.yaml"), &config).unwrap();
    let (out, _) = child("apply", &req.to_string()).await;
    assert_eq!(
        serde_json::from_str::<Value>(&out).unwrap(),
        json!({"input_changed": false, "rebuilt": false, "next": false})
    );
    let req = json!({ "dir": dir, "ids": [], "config": config, "now": 1_000, "build": true });
    let (out, _) = child("apply", &req.to_string()).await;
    assert_eq!(
        serde_json::from_str::<Value>(&out).unwrap(),
        json!({"input_changed": false, "rebuilt": true, "next": false})
    );
    assert!(!dir.join("config.next.yaml").exists());

    // No input: an error answer, exit 2.
    let empty = tempfile::tempdir().unwrap();
    let (out, code) = child("apply", &json!({"dir": empty.path(), "now": 1}).to_string()).await;
    assert_eq!(code, 2);
    assert!(serde_json::from_str::<Value>(&out).unwrap()["error"].is_string());
}

/// The core's configured proxies' names.
async fn proxy_names(api_port: u16) -> Vec<String> {
    let (status, body) = api_call(api_port, "GET", "/proxies", Some("s3cret"), "").await;
    assert_eq!(status, 200);
    let v: Value = serde_json::from_str(&body).unwrap();
    v["proxies"].as_object().unwrap().keys().cloned().collect()
}

#[tokio::test]
async fn the_core_refreshes_rebuilds_and_reloads_itself() {
    let base = subscription_server().await;
    let (api_port, mixed_port) = (free_port(), free_port());
    let home = tempfile::tempdir().unwrap();
    let _core = start_core(api_port, mixed_port, home.path()).await;
    let config = home.path().join("config.yaml");
    let call = |method: &'static str, path: &'static str, body: String| async move {
        let (status, body) = api_call(api_port, method, path, Some("s3cret"), &body).await;
        (
            status,
            serde_json::from_str::<Value>(&body).unwrap_or(Value::Null),
        )
    };

    let input = handed_over(&format!("{base}/sub"), api_port, mixed_port);
    assert_eq!(
        api_call(api_port, "PUT", "/paopao/input", None, "{}")
            .await
            .0,
        401
    );
    let (status, v) = call("PUT", "/paopao/input", input.to_string()).await;
    assert_eq!((status, v), (200, json!({"subscriptions": 1})));
    assert!(home.path().join("paopao/input.json").exists());
    assert!(!proxy_names(api_port).await.contains(&"HK 01".to_owned()));

    let (status, v) = call("POST", "/paopao/subscriptions/refresh?id=a1", String::new()).await;
    assert_eq!(status, 200, "{v}");
    assert_eq!(
        v,
        json!({"refreshed": [{"id": "a1"}], "input_changed": true, "rebuilt": true, "reloaded": true})
    );
    let names = proxy_names(api_port).await;
    assert!(
        names.contains(&"HK 01".to_owned()) && names.contains(&"JP 02".to_owned()),
        "{names:?}"
    );
    // The file the core runs from is the new config now.
    let running: Value = serde_json::from_str(&std::fs::read_to_string(&config).unwrap()).unwrap();
    assert_eq!(
        running["external-controller"],
        format!("127.0.0.1:{api_port}")
    );
    let (_, v) = call("GET", "/paopao/subscriptions", String::new()).await;
    assert_eq!(v["subscriptions"][0]["name"], "my");
    assert_eq!(v["subscriptions"][0]["refreshed"]["node_count"], 2);
    assert!(v["subscriptions"][0]["refreshed"].get("nodes").is_none());

    // The same lines again: nothing to reload.
    let (_, v) = call("POST", "/paopao/subscriptions/refresh?id=a1", String::new()).await;
    assert_eq!(v["reloaded"], false);

    // The link dies: its problem kept, the running config and file as
    // they were.
    let before = std::fs::read(&config).unwrap();
    let dead = handed_over(&format!("{base}/gone"), api_port, mixed_port);
    assert_eq!(call("PUT", "/paopao/input", dead.to_string()).await.0, 200);
    let (_, v) = call("POST", "/paopao/subscriptions/refresh?id=a1", String::new()).await;
    assert_eq!(v["refreshed"][0]["error"], meow_paopao::refresh::GONE);
    assert_eq!(v["reloaded"], false);
    assert_eq!(std::fs::read(&config).unwrap(), before);
    assert!(proxy_names(api_port).await.contains(&"HK 01".to_owned()));

    // The schedule: off until told; told, it runs at once (never run).
    let (_, v) = call("GET", "/paopao/schedule", String::new()).await;
    assert_eq!(
        (
            v["enabled"].clone(),
            v["minutes"].clone(),
            v["last_run"].clone()
        ),
        (json!(false), json!(720), Value::Null)
    );
    assert_eq!(call("PUT", "/paopao/input", input.to_string()).await.0, 200);
    let (status, v) = call("PUT", "/paopao/schedule", r#"{"enabled": true}"#.to_owned()).await;
    assert_eq!((status, v["enabled"].clone()), (200, json!(true)));
    let mut ran = Value::Null;
    for _ in 0..200 {
        let (_, v) = call("GET", "/paopao/schedule", String::new()).await;
        if v["last_run"].is_i64() && v["running"] == false {
            ran = v;
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(
        ran["last_run"].is_i64(),
        "the scheduled refresh did not run"
    );
    assert_eq!(ran["last_error"], Value::Null);
    assert_eq!(
        ran["next_run"],
        ran["last_run"].as_i64().unwrap() + 720 * 60_000
    );
    let (_, v) = call("GET", "/paopao/subscriptions", String::new()).await;
    assert_eq!(
        v["subscriptions"][0]["refreshed"]["last_error"],
        Value::Null
    );
}

#[tokio::test]
async fn a_rebuilt_config_keeps_the_running_cores_api_and_port() {
    let base = subscription_server().await;
    let (api_port, mixed_port) = (free_port(), free_port());
    let home = tempfile::tempdir().unwrap();
    let _core = start_core(api_port, mixed_port, home.path()).await;
    let config = home.path().join("config.yaml");

    // Handed over by a start on other ports, with another secret.
    let mut stale = handed_over(&format!("{base}/sub"), free_port(), free_port());
    stale["runtime"]["secret"] = "old".into();
    let (status, _) = api_call(
        api_port,
        "PUT",
        "/paopao/input",
        Some("s3cret"),
        &stale.to_string(),
    )
    .await;
    assert_eq!(status, 200);
    let (status, body) = api(
        api_port,
        "/paopao/subscriptions/refresh?id=a1",
        Some("s3cret"),
        "",
    )
    .await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(
        serde_json::from_str::<Value>(&body).unwrap()["reloaded"],
        true
    );

    let running: Value = serde_json::from_str(&std::fs::read_to_string(&config).unwrap()).unwrap();
    assert_eq!(
        running["external-controller"],
        format!("127.0.0.1:{api_port}")
    );
    assert_eq!(running["secret"], "s3cret");
    assert_eq!(running["mixed-port"], mixed_port);
    // Still reached where it was, with its secret; the lines are in.
    assert!(proxy_names(api_port).await.contains(&"HK 01".to_owned()));
    assert!(TcpStream::connect(("127.0.0.1", mixed_port)).await.is_ok());
}

const MODULE: &str = "#!name=Test {{{who}}}\n#!arguments=who:me\n\
    [Script]\nfix = type=http-response, pattern=^https://a\\.example/x, script-path=s.js, argument=w={{{who}}}\n\
    [Map Local]\n^https://a\\.example/ad data-type=json data=\"data.json\"\n\
    ^https://a\\.example/remote data-type=json data=\"PLACEHOLDER/data.json\"\n\
    [MITM]\nhostname = a.example\n";

/// A module server: `/m.sgmodule` ([`MODULE`]), its script `/s.js` and
/// its data `/data.json`; `/bad.sgmodule` has a script that is gone; the
/// rest 404.
async fn module_server() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let base = format!("http://{addr}");
    let module = MODULE.replace("PLACEHOLDER", &base);
    tokio::spawn(async move {
        loop {
            let Ok((mut s, _)) = listener.accept().await else {
                return;
            };
            let module = module.clone();
            tokio::spawn(async move {
                let head = read_head(&mut s).await;
                let path = head.split_whitespace().nth(1).unwrap_or("").to_owned();
                let body = match path.as_str() {
                    "/m.sgmodule" => Some(module),
                    "/bad.sgmodule" => Some(module.replace("s.js", "gone.js")),
                    "/s.js" => Some("$done({})".to_owned()),
                    "/data.json" => Some("{\"ads\":[]}".to_owned()),
                    _ => None,
                };
                let res = match body {
                    Some(b) => format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{b}", b.len()),
                    None => "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n".to_owned(),
                };
                let _ = s.write_all(res.as_bytes()).await;
                let _ = s.shutdown().await;
            });
        }
    });
    base
}

#[tokio::test]
async fn a_module_refresh_keeps_its_scripts_and_spec_as_the_app_would() {
    let base = module_server().await;
    let home = tempfile::tempdir().unwrap();
    let dir = home.path().join("paopao");
    let url = format!("{base}/m.sgmodule");
    let mut input = handed_over("http://127.0.0.1:1/sub", 9090, 7890);
    input["modules"] = json!([{"id": "m1", "url": url, "enabled": true,
        "spec": {"name": "old", "scripts": [], "rewrites": [], "hostnames": [], "rules": []},
        "source": "old", "values": {"who": "you"}}]);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("input.json"), input.to_string()).unwrap();
    let record = || -> Value {
        serde_json::from_str(&std::fs::read_to_string(dir.join("modules/m1.json")).unwrap())
            .unwrap()
    };

    let req = json!({ "dir": dir, "id": "m1", "url": url, "values": {"who": "you"} });
    let (out, code) = child("module", &req.to_string()).await;
    assert_eq!(
        (code, serde_json::from_str::<Value>(&out).unwrap()),
        (0, json!({"id": "m1", "error": null}))
    );
    let r = record();
    assert_eq!(r["spec"]["name"], "Test you");
    assert_eq!(r["spec"]["scripts"][0]["argument"], "w=you");
    assert_eq!(r["values"], json!({"who": "you"}));
    assert_eq!(r["source"], MODULE.replace("PLACEHOLDER", &base));
    assert_eq!(r["updated"], r["checked"]);
    // Map Local data by URL is kept with the module; a plain one stays.
    let rewrites = r["spec"]["rewrites"].as_array().unwrap();
    assert_eq!(rewrites[0]["action"]["text"], "data.json");
    assert_eq!(rewrites[1]["action"]["text"], "{\"ads\":[]}");
    assert!(rewrites[1]["action"].get("dataUrl").is_none());
    assert_eq!(
        std::fs::read_to_string(home.path().join("modules/m1/0.js")).unwrap(),
        "$done({})"
    );

    // Merged into the input, then built.
    let config = home.path().join("config.yaml");
    let req = json!({ "dir": dir, "modules": ["m1"], "config": config, "now": 1 });
    let (out, code) = child("apply", &req.to_string()).await;
    assert_eq!(code, 0, "{out}");
    assert_eq!(
        serde_json::from_str::<Value>(&out).unwrap()["rebuilt"],
        true
    );
    let kept: Value =
        serde_json::from_str(&std::fs::read_to_string(dir.join("input.json")).unwrap()).unwrap();
    assert_eq!(kept["modules"][0]["spec"], r["spec"]);
    assert_eq!(kept["modules"][0]["source"], r["source"]);
    assert!(dir.join("policies.json").exists());
    // Taken in already: nothing to do.
    let (out, _) = child("apply", &req.to_string()).await;
    assert_eq!(
        serde_json::from_str::<Value>(&out).unwrap()["rebuilt"],
        false
    );

    // A script gone: the problem in the app's words, the old spec kept.
    let bad = format!("{base}/bad.sgmodule");
    let req = json!({ "dir": dir, "id": "m1", "url": bad, "values": {"who": "you"} });
    let (out, _) = child("module", &req.to_string()).await;
    assert_eq!(
        serde_json::from_str::<Value>(&out).unwrap()["error"],
        "模块中的脚本下载失败（404）"
    );
    let failed = record();
    assert_eq!(failed["spec"], r["spec"]);
    assert_eq!(failed["updated"], r["updated"]);
    assert_eq!(failed["last_error"], "模块中的脚本下载失败（404）");
    // Not merged: it did not work.
    let req = json!({ "dir": dir, "modules": ["m1"], "config": config, "now": 1 });
    let (out, _) = child("apply", &req.to_string()).await;
    assert_eq!(
        serde_json::from_str::<Value>(&out).unwrap()["input_changed"],
        false
    );

    // Unreachable and not a module.
    let req =
        json!({ "dir": dir, "id": "m2", "url": format!("http://127.0.0.1:{}/x", free_port()) });
    let (out, _) = child("module", &req.to_string()).await;
    assert_eq!(
        serde_json::from_str::<Value>(&out).unwrap()["error"],
        "模块下载失败，请检查链接和网络"
    );
    let req = json!({ "dir": dir, "id": "m3", "url": format!("{base}/nope") });
    let (out, _) = child("module", &req.to_string()).await;
    assert_eq!(
        serde_json::from_str::<Value>(&out).unwrap()["error"],
        "模块下载失败（404）"
    );
    let req = json!({ "dir": dir, "id": "m4", "url": format!("{base}/s.js") });
    let (out, _) = child("module", &req.to_string()).await;
    assert_eq!(
        serde_json::from_str::<Value>(&out).unwrap()["error"],
        "这个链接中没有可用的模块内容"
    );
}

#[tokio::test]
async fn apply_puts_what_the_core_measured_into_the_input() {
    let store = tempfile::tempdir().unwrap();
    let dir = store.path();
    let input = handed_over("http://127.0.0.1:1/sub", 9090, 7890);
    std::fs::write(dir.join("input.json"), input.to_string()).unwrap();
    let set = json!({"exits": {"1.2.3.4:443": "JP"}, "network": {"kind": "wifi", "ssid": "x", "addresses": []}});
    let req = json!({ "dir": dir, "set": set, "now": 1 });
    let (out, code) = child("apply", &req.to_string()).await;
    assert_eq!(
        (code, serde_json::from_str::<Value>(&out).unwrap()),
        (
            0,
            json!({"input_changed": true, "rebuilt": true, "next": true})
        )
    );
    let kept: Value =
        serde_json::from_str(&std::fs::read_to_string(dir.join("input.json")).unwrap()).unwrap();
    assert_eq!(kept["exits"], set["exits"]);
    assert_eq!(kept["network"]["ssid"], "x");
    // The same again: nothing.
    let (out, _) = child("apply", &req.to_string()).await;
    assert_eq!(
        serde_json::from_str::<Value>(&out).unwrap()["input_changed"],
        false
    );
}

/// A plain-HTTP server answering every request as ip-api.com does, for
/// Japan.
async fn ip_api_server() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((mut s, _)) = listener.accept().await else {
                return;
            };
            tokio::spawn(async move {
                read_head(&mut s).await;
                let b = r#"{"status":"success","countryCode":"JP","city":"Osaka","query":"203.0.113.9","as":"AS1 Test"}"#;
                let res = format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{b}", b.len());
                let _ = s.write_all(res.as_bytes()).await;
                let _ = s.shutdown().await;
            });
        }
    });
    addr.to_string()
}

#[tokio::test]
async fn the_core_looks_exits_up_through_each_line() {
    // Each line is an HTTP proxy that tunnels everything to the local
    // stand-in: only ip-api.com (plain HTTP) answers; the HTTPS services
    // fail their handshake. Nothing leaves this machine.
    let server = ip_api_server().await;
    let line = redirecting_proxy(server).await;
    let line_port: u16 = line.rsplit(':').next().unwrap().parse().unwrap();
    let (api_port, mixed_port) = (free_port(), free_port());
    let home = tempfile::tempdir().unwrap();
    let config = format!(
        "mixed-port: {mixed_port}\nbind-address: 127.0.0.1\nallow-lan: false\n\
         external-controller: 127.0.0.1:{api_port}\nsecret: s3cret\nlog-level: warning\n\
         geox-url: {{geoip: 'http://127.0.0.1:1/a', mmdb: 'http://127.0.0.1:1/b', \
         asn: 'http://127.0.0.1:1/c', geosite: 'http://127.0.0.1:1/d'}}\n\
         proxies: [{{name: L1, type: http, server: 127.0.0.1, port: {line_port}}}]\n\
         proxy-groups: [{{name: speedtest, type: select, proxies: [L1]}}]\n\
         rules: ['MATCH,DIRECT']\n"
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
    for _ in 0..200 {
        if TcpStream::connect(("127.0.0.1", api_port)).await.is_ok() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let (status, body) = api(api_port, "/paopao/exits/locate", Some("s3cret"), "").await;
    assert_eq!(status, 200, "{body}");
    let v: Value = serde_json::from_str(&body).unwrap();
    assert_eq!(
        (v["asked"].clone(), v["found"].clone()),
        (json!(1), json!(1))
    );
    let (_, body) = api_call(api_port, "GET", "/paopao/exits", Some("s3cret"), "").await;
    let v: Value = serde_json::from_str(&body).unwrap();
    let exit = &v["exits"][format!("127.0.0.1:{line_port}")];
    assert_eq!(exit["cc"], "JP");
    assert_eq!(exit["city"], "Osaka");
    assert_eq!(exit["src"], "ip-api.com (1/1)");

    let (status, body) = api(
        api_port,
        "/paopao/exits/relocate?tag=L1",
        Some("s3cret"),
        "",
    )
    .await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(
        serde_json::from_str::<Value>(&body).unwrap()["result"],
        "found"
    );
}
