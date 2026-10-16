//! The jobs the core took over from the app beside the subscriptions:
//! rewrite modules, exits, the network, the route API and 虚拟定位's trip.
//! Children are shell scripts recording what they were asked; lookups,
//! resolvers and the network are stand-ins.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use axum::body::{Body, Bytes};
use axum::http::{Request, StatusCode};
use meow_config::raw::RawConfig;
use parking_lot::RwLock;
use serde_json::{json, Value};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tower::ServiceExt as _;

use super::exits::{Ask, Resolve, SERVICES};
use super::network::Net;
use super::{Reload, Runner, Service};

/// Children that are `sh -c script` (`$2` = the op).
fn sh(script: &str) -> Arc<Runner> {
    Arc::new(Runner::new("sh").with_prefix(["-c", script, "sh"]))
}

/// `apply` children that keep each request (`apply.1`, `apply.2` …) in
/// `log` and answer `answer`; `module` ones answer `{id, error: null}`.
fn children(log: &Path, answer: &str) -> Arc<Runner> {
    sh(&format!(
        r#"case $2 in
          apply) n=$(ls {log} | grep -c apply); cat > {log}/apply.$((n+1)); echo '{answer}';;
          module) cat > {log}/module.$(ls {log} | grep -c module); echo '{{"id":"m","error":null}}';;
          refresh) cat >/dev/null; echo '{{"id":"a1","error":null}}';;
          *) exit 9;;
        esac"#,
        log = log.display()
    ))
}

fn no_reload() -> Reload {
    Arc::new(|_| Box::pin(async { Ok(()) }))
}

/// Answers through each line: `tag → service url → (status, body)`.
fn web(
    answers: Vec<(&'static str, &'static str, u16, &'static str)>,
) -> (Ask, Arc<parking_lot::Mutex<Vec<String>>>) {
    let asked = Arc::new(parking_lot::Mutex::new(Vec::new()));
    let log = Arc::clone(&asked);
    let answers = Arc::new(answers);
    let ask: Ask = Arc::new(move |tag: String, url: String| {
        log.lock().push(format!("{tag} {url}"));
        let a = answers
            .iter()
            .find(|(t, u, _, _)| *t == tag && *u == url)
            .map(|(_, _, s, b)| (*s, (*b).to_owned()));
        Box::pin(async move { a })
    });
    (ask, asked)
}

fn resolver() -> Resolve {
    Arc::new(|host: String| {
        Box::pin(async move { (host == "hk.example").then(|| "9.9.9.9".to_owned()) })
    })
}

/// The running config: three lines (one by domain) in the speed-test
/// group.
fn raw() -> RawConfig {
    serde_yaml::from_str(
        r"
mixed-port: 7890
proxies:
  - {name: HK, type: ss, server: hk.example, port: 443, cipher: aes-128-gcm, password: p}
  - {name: JP, type: ss, server: 2.2.2.2, port: 8443, cipher: aes-128-gcm, password: p}
  - {name: JP2, type: ss, server: 2.2.2.2, port: 8443, cipher: aes-128-gcm, password: p}
  - {name: Gone, type: ss, server: gone.example, port: 1, cipher: aes-128-gcm, password: p}
proxy-groups:
  - {name: speedtest, type: select, proxies: [HK, JP, JP2, Gone]}
",
    )
    .unwrap()
}

struct Rig {
    dir: tempfile::TempDir,
    svc: Arc<Service>,
}

impl Rig {
    fn store(&self) -> PathBuf {
        self.dir.path().join("paopao")
    }
    fn log(&self) -> PathBuf {
        self.dir.path().join("log")
    }
    /// What the apply children were asked, in order.
    fn applies(&self) -> Vec<Value> {
        let mut out = Vec::new();
        for i in 1.. {
            let Ok(s) = std::fs::read_to_string(self.log().join(format!("apply.{i}"))) else {
                break;
            };
            out.push(serde_json::from_str(&s).unwrap());
        }
        out
    }
}

fn rig_with(ask: Ask, look: super::network::Look, try_ipv6: super::network::TryIpv6) -> Rig {
    let dir = tempfile::tempdir().unwrap();
    let log = dir.path().join("log");
    std::fs::create_dir_all(&log).unwrap();
    let runner = children(
        &log,
        r#"{"input_changed":true,"rebuilt":true,"next":false}"#,
    );
    let svc = Service::new(
        Some(runner),
        Arc::new(RwLock::new(raw())),
        dir.path().join("paopao"),
        None,
        no_reload(),
    )
    .with_minute(Duration::from_millis(400))
    .with_exits(ask, resolver())
    .with_network(look, try_ipv6);
    Rig {
        dir,
        svc: Arc::new(svc),
    }
}

fn rig(ask: Ask) -> Rig {
    rig_with(
        ask,
        Arc::new(|| Box::pin(async { Net::unknown() })),
        Arc::new(|| Box::pin(async { true })),
    )
}

const INPUT: &str = r#"{"subscriptions": [{"id": "a1", "url": "http://a/"}],
  "modules": [
    {"id": "m1", "url": "https://m/a.sgmodule", "enabled": true, "spec": {"name": "old"}, "source": "old", "values": {"k": "v"}},
    {"id": "loc", "url": "builtin:location-spoofer", "enabled": false, "spec": {}}
  ],
  "network": {"kind": "wifi", "ssid": "home", "addresses": ["192.168.1.2"]},
  "ipv6": false,
  "exits": {"7.7.7.7:1": "US"}, "resolved": {"old.example": "7.7.7.7"}}"#;

async fn call(svc: &Arc<Service>, method: &str, path: &str, body: &str) -> (StatusCode, Value) {
    let req = Request::builder()
        .method(method)
        .uri(path)
        .body(Body::from(body.to_owned()))
        .unwrap();
    let res = super::router::<()>(Arc::clone(svc))
        .oneshot(req)
        .await
        .unwrap();
    let status = res.status();
    let bytes = axum::body::to_bytes(res.into_body(), usize::MAX)
        .await
        .unwrap();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

#[tokio::test]
async fn a_refresh_of_all_refreshes_the_remote_modules_and_merges_them() {
    let (ask, _) = web(vec![]);
    let rig = rig(ask);
    rig.svc
        .store_input(Bytes::from_static(INPUT.as_bytes()))
        .await
        .unwrap();
    let report = rig.svc.refresh(None).await.unwrap();
    // The built-in module is the app's: not downloaded.
    assert_eq!(
        serde_json::to_value(&report.modules).unwrap(),
        json!([{"id": "m1"}])
    );
    let asked: Value =
        serde_json::from_str(&std::fs::read_to_string(rig.log().join("module.0")).unwrap())
            .unwrap();
    assert_eq!(asked["id"], "m1");
    assert_eq!(asked["values"], json!({"k": "v"}));
    assert_eq!(asked["proxy"], "127.0.0.1:7890");
    let apply = &rig.applies()[0];
    assert_eq!(apply["ids"], json!(["a1"]));
    assert_eq!(apply["modules"], json!(["m1"]));

    // One subscription asked for: no modules.
    let report = rig.svc.refresh(Some("a1")).await.unwrap();
    assert!(report.modules.is_empty());
    assert_eq!(rig.applies()[1]["modules"], json!([]));

    // Listed with their records, the spec and text only when asked for.
    let record = json!({"id": "m1", "url": "https://m/a.sgmodule", "checked": 5, "updated": 5,
        "values": {"k": "v"}, "spec": {"name": "new"}, "source": "new"});
    std::fs::create_dir_all(rig.store().join("modules")).unwrap();
    std::fs::write(rig.store().join("modules/m1.json"), record.to_string()).unwrap();
    let (s, v) = call(&rig.svc, "GET", "/paopao/modules", "").await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(
        v,
        json!({"modules": [
            {"id": "m1", "url": "https://m/a.sgmodule", "enabled": true, "refreshed":
                {"id": "m1", "url": "https://m/a.sgmodule", "checked": 5, "updated": 5, "values": {"k": "v"}}},
            {"id": "loc", "url": "builtin:location-spoofer", "enabled": false, "refreshed": null},
        ]})
    );
    let (_, v) = call(&rig.svc, "GET", "/paopao/modules?full=true", "").await;
    assert_eq!(v["modules"][0]["refreshed"]["source"], "new");

    // A module no longer handed over loses its record.
    let without = INPUT.replace("\"id\": \"m1\"", "\"id\": \"m9\"");
    rig.svc.store_input(Bytes::from(without)).await.unwrap();
    assert!(!rig.store().join("modules/m1.json").exists());
}

#[tokio::test]
async fn a_round_looks_each_server_up_once_and_stops_at_a_rate_limit() {
    let (ask, asked) = web(vec![
        ("HK", SERVICES[6], 200, r#"{"country":"HK","ip":"9.9.9.9"}"#),
        ("HK", SERVICES[2], 200, "ip=9.9.9.9\nloc=HK\n"),
        ("JP", SERVICES[0], 429, ""),
    ]);
    let rig = rig(ask);
    rig.svc
        .store_input(Bytes::from_static(INPUT.as_bytes()))
        .await
        .unwrap();
    let report = rig.svc.locate().await.unwrap();
    assert_eq!((report.asked, report.found, report.limited), (2, 1, true));
    // JP2 shares JP's server: never asked; "Gone" has no address.
    let tags: std::collections::BTreeSet<String> = asked
        .lock()
        .iter()
        .map(|a| a.split(' ').next().unwrap().to_owned())
        .collect();
    assert_eq!(tags.into_iter().collect::<Vec<_>>(), ["HK", "JP"]);

    let (_, v) = call(&rig.svc, "GET", "/paopao/exits", "").await;
    assert_eq!(v["exits"]["9.9.9.9:443"]["cc"], "HK");
    assert_eq!(
        v["exits"]["9.9.9.9:443"]["src"],
        "cloudflare+country.is (2/2)"
    );
    // Started from the input's countries.
    assert_eq!(v["exits"]["7.7.7.7:1"]["cc"], "US");
    assert_eq!(v["pending"], json!(["2.2.2.2:8443"]));
    assert_eq!(v["resolved"], json!({"hk.example": "9.9.9.9"}));
    assert!(v["last_run"].is_i64());

    // Handed to the build: countries, resolved domains with the input's.
    let set = &rig.applies()[0]["set"];
    assert_eq!(
        set["exits"],
        json!({"7.7.7.7:1": "US", "9.9.9.9:443": "HK"})
    );
    assert_eq!(
        set["resolved"],
        json!({"old.example": "7.7.7.7", "hk.example": "9.9.9.9"})
    );

    // Next round: only the rate-limited one again.
    asked.lock().clear();
    let report = rig.svc.locate().await.unwrap();
    assert_eq!(report.asked, 1);
    assert!(asked.lock().iter().all(|a| a.starts_with("JP ")));
    // Nothing learned: no rebuild.
    assert_eq!(rig.applies().len(), 1);
}

#[tokio::test]
async fn relocate_clear_and_the_apps_exits() {
    let (ask, _) = web(vec![(
        "JP",
        SERVICES[3],
        200,
        r#"{"status":"success","countryCode":"JP","city":"Tokyo"}"#,
    )]);
    let rig = rig(ask);
    rig.svc
        .store_input(Bytes::from_static(INPUT.as_bytes()))
        .await
        .unwrap();
    let (s, v) = call(&rig.svc, "POST", "/paopao/exits/relocate?tag=JP", "").await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["result"], "found");
    assert_eq!(v["exit"]["city"], "Tokyo");
    let (s, _) = call(&rig.svc, "POST", "/paopao/exits/relocate?tag=nope", "").await;
    assert_eq!(s, StatusCode::NOT_FOUND);
    let (_, v) = call(&rig.svc, "POST", "/paopao/exits/relocate?tag=HK", "").await;
    assert_eq!(v["result"], "failed");

    // The app's: newer ones win, older ones are dropped.
    let given = json!({"exits": {
        "2.2.2.2:8443": {"cc": "KR", "at": 1},
        "5.5.5.5:1": {"cc": "SG", "at": 9}
    }, "pending": ["6.6.6.6:1"]});
    let (s, _) = call(&rig.svc, "PUT", "/paopao/exits", &given.to_string()).await;
    assert_eq!(s, StatusCode::OK);
    let (_, v) = call(&rig.svc, "GET", "/paopao/exits", "").await;
    assert_eq!(v["exits"]["2.2.2.2:8443"]["cc"], "JP");
    assert_eq!(v["exits"]["5.5.5.5:1"]["cc"], "SG");
    assert_eq!(v["pending"], json!(["6.6.6.6:1"]));

    // Forgotten by line, then all.
    let (s, _) = call(&rig.svc, "DELETE", "/paopao/exits?tag=JP2", "").await;
    assert_eq!(s, StatusCode::OK);
    let (_, v) = call(&rig.svc, "GET", "/paopao/exits", "").await;
    assert!(v["exits"].get("2.2.2.2:8443").is_none());
    assert_eq!(v["exits"]["5.5.5.5:1"]["cc"], "SG");
    call(&rig.svc, "DELETE", "/paopao/exits", "").await;
    let (_, v) = call(&rig.svc, "GET", "/paopao/exits", "").await;
    assert_eq!(
        (v["exits"].clone(), v["pending"].clone()),
        (json!({}), json!([]))
    );
    assert_eq!(rig.applies().last().unwrap()["set"]["exits"], json!({}));
}

#[tokio::test]
async fn exits_run_once_told_after_the_hand_over_then_on_time() {
    let (ask, asked) = web(vec![("HK", SERVICES[6], 200, r#"{"country":"HK"}"#)]);
    let rig = rig(ask);
    let task = tokio::spawn(super::run_exits(Arc::clone(&rig.svc)));
    rig.svc
        .store_input(Bytes::from_static(INPUT.as_bytes()))
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(asked.lock().is_empty(), "looked up while off");
    // Told, long after the hand-over: at once.
    let (s, v) = call(&rig.svc, "PUT", "/paopao/schedule", r#"{"exits": true}"#).await;
    assert_eq!((s, v["exits"].clone()), (StatusCode::OK, json!(true)));
    assert_eq!(v["jobs"][2], "exits");
    let started = tokio::time::Instant::now();
    while asked.lock().is_empty() {
        assert!(started.elapsed() < Duration::from_secs(2), "never ran");
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    // HK found; JP (no answer) asked again by the next round.
    tokio::time::sleep(Duration::from_millis(50)).await;
    let first = asked.lock().len();
    // A hand-over: the next round a quarter minute (100 ms here) later.
    let started = tokio::time::Instant::now();
    rig.svc
        .store_input(Bytes::from_static(INPUT.as_bytes()))
        .await
        .unwrap();
    while asked.lock().len() == first {
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "never ran again"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(
        started.elapsed() >= Duration::from_millis(80),
        "{:?}",
        started.elapsed()
    );
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert!(asked
        .lock()
        .iter()
        .skip(first)
        .all(|a| a.starts_with("JP ")));
    // Then every 30 minutes (12 s here): not again soon.
    let second = asked.lock().len();
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert_eq!(asked.lock().len(), second);
    task.abort();
}

#[tokio::test]
async fn a_network_change_rebuilds_for_the_new_network() {
    let seen = Arc::new(parking_lot::Mutex::new(Net {
        kind: "wifi".into(),
        ssid: None,
        addresses: vec!["192.168.1.2".into()],
    }));
    let now = Arc::clone(&seen);
    let tried = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let tries = Arc::clone(&tried);
    let (ask, _) = web(vec![]);
    let rig = rig_with(
        ask,
        Arc::new(move || {
            let n = now.lock().clone();
            Box::pin(async move { n })
        }),
        Arc::new(move || {
            tries.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            Box::pin(async { false })
        }),
    );
    rig.svc
        .store_input(Bytes::from_static(INPUT.as_bytes()))
        .await
        .unwrap();
    // The name hidden from the core: the same network.
    assert!(!rig.svc.watch_network_once().await);
    assert!(rig.applies().is_empty());

    *seen.lock() = Net {
        kind: "wifi".into(),
        ssid: Some("cafe".into()),
        addresses: vec!["10.0.0.5".into()],
    };
    let (s, v) = call(&rig.svc, "POST", "/paopao/network/check", "").await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(v["changed"], true);
    assert_eq!(v["network"]["ssid"], "cafe");
    let set = &rig.applies()[0]["set"];
    assert_eq!(
        set,
        &json!({"network": {"kind": "wifi", "ssid": "cafe", "addresses": ["10.0.0.5"]}, "ipv6": false})
    );
    assert!(!rig.svc.watch_network_once().await);

    // A global IPv6 address: tried once; failing, the config goes without.
    *seen.lock() = Net {
        kind: "ethernet".into(),
        ssid: None,
        addresses: vec!["10.0.0.5".into(), "2409:8a00::5".into()],
    };
    assert!(rig.svc.watch_network_once().await);
    assert_eq!(rig.applies()[1]["set"]["ipv6"], false);
    assert!(!rig.svc.watch_network_once().await);
    assert_eq!(tried.load(std::sync::atomic::Ordering::Relaxed), 1);
    let (_, v) = call(&rig.svc, "GET", "/paopao/network", "").await;
    assert_eq!(v["network"]["kind"], "ethernet");
    assert_eq!(v["ipv6"], false);
}

/// `GET path` (with `auth`) on `port` over HTTP/1.0: (status, headers,
/// body).
async fn get(port: u16, path: &str, auth: Option<&str>) -> (u16, String, Vec<u8>) {
    let mut s = tokio::net::TcpStream::connect(("127.0.0.1", port))
        .await
        .unwrap();
    let auth = auth.map_or(String::new(), |k| format!("Authorization: Bearer {k}\r\n"));
    s.write_all(format!("GET {path} HTTP/1.0\r\nHost: x\r\n{auth}\r\n").as_bytes())
        .await
        .unwrap();
    let mut res = Vec::new();
    s.read_to_end(&mut res).await.unwrap();
    let at = res.windows(4).position(|w| w == b"\r\n\r\n").unwrap();
    let head = String::from_utf8_lossy(&res[..at]).to_ascii_lowercase();
    let status = head.split_whitespace().nth(1).unwrap().parse().unwrap();
    (status, head, res[at + 4..].to_vec())
}

/// `port` stops listening within a second (an aborted listener goes at
/// its next turn).
async fn closes(port: u16) -> bool {
    for _ in 0..50 {
        if tokio::net::TcpStream::connect(("127.0.0.1", port))
            .await
            .is_err()
        {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    false
}

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

#[tokio::test]
async fn the_route_api_answers_as_the_apps_did() {
    let (ask, _) = web(vec![]);
    let rig = rig(ask);
    rig.svc
        .store_input(Bytes::from_static(INPUT.as_bytes()))
        .await
        .unwrap();
    let port = free_port();
    let body = json!({"port": port, "key": "k3y", "lan": false, "policies": [
        {"id": "hk", "name": "🇭🇰 香港", "target": "region:HK", "kind": "region"}
    ]});
    let (s, v) = call(&rig.svc, "PUT", "/paopao/route", &body.to_string()).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["listening"], format!("127.0.0.1:{port}"));
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let mode = std::fs::metadata(rig.store().join("route.json"))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
    }

    let json_of = |b: &[u8]| serde_json::from_slice::<Value>(b).unwrap();
    let (s, _, b) = get(port, "/v1/policies", None).await;
    assert_eq!(
        (s, json_of(&b)),
        (401, json!({"error": "bad or missing key"}))
    );
    let (s, head, b) = get(port, "/v1/policies", Some("k3y")).await;
    assert_eq!(s, 200);
    assert!(head.contains("content-type: application/json"), "{head}");
    assert_eq!(
        json_of(&b),
        json!({"running": true, "policies": [{"id": "hk", "name": "🇭🇰 香港", "kind": "region"}]})
    );
    let (s, _, b) = get(port, "/v1/proxy?policy=hk", Some("k3y")).await;
    assert_eq!(s, 200);
    assert_eq!(
        json_of(&b),
        json!({"policy": {"id": "hk", "name": "🇭🇰 香港", "kind": "region"}, "host": "127.0.0.1",
               "port": 7890, "username": "hk", "password": "k3y",
               "socks5": "socks5://hk:k3y@127.0.0.1:7890", "http": "http://hk:k3y@127.0.0.1:7890"})
    );
    let (s, _, b) = get(port, "/v1/proxy?policy=xx", Some("k3y")).await;
    assert_eq!(
        (s, json_of(&b)),
        (404, json!({"error": "no policy \"xx\""}))
    );
    let (s, _, _) = get(port, "/v1/nope", Some("k3y")).await;
    assert_eq!(s, 404);

    // The certificate: none yet, then as PEM, DER and a profile.
    let (s, _, _) = get(port, "/ca.crt", None).await;
    assert_eq!(s, 404);
    std::fs::write(
        rig.dir.path().join("mitm-ca.pem"),
        "-----BEGIN CERTIFICATE-----\nAAEC\n-----END CERTIFICATE-----\n",
    )
    .unwrap();
    let (s, head, b) = get(port, "/ca.crt", None).await;
    assert_eq!((s, b), (200, vec![0, 1, 2]));
    assert!(
        head.contains("content-disposition: attachment; filename=\"paopao-ca.crt\""),
        "{head}"
    );
    let (_, head, b) = get(port, "/ca.mobileconfig", None).await;
    assert!(head.contains("application/x-apple-aspen-config"));
    assert!(String::from_utf8(b).unwrap().contains("<data>AAEC</data>"));

    // 虚拟定位: off until there is a point; `enabled` as the module is.
    let (s, _, _) = get(port, "/v1/location.json?key=k3y", None).await;
    assert_eq!(s, 404);
    let (s, _, _) = get(port, "/v1/location.json?key=bad", None).await;
    assert_eq!(s, 401);
    super::track::save_point(
        rig.dir.path(),
        &super::track::Point {
            lat: 1.5,
            lon: 2.0,
            acc: 25,
        },
        "u",
        true,
    )
    .unwrap();
    let (s, _, b) = get(port, "/v1/location.json?key=k3y", None).await;
    assert_eq!(s, 200);
    assert_eq!(json_of(&b)["enabled"], false);
    assert_eq!(json_of(&b)["latitude"], 1.5);

    // Handed over again (another port): moved; then stopped.
    let other = free_port();
    let body = json!({"port": other, "key": "k3y", "lan": false});
    let (s, _) = call(&rig.svc, "PUT", "/paopao/route", &body.to_string()).await;
    assert_eq!(s, StatusCode::OK);
    assert!(closes(port).await, "the old port still listens");
    // The policies stay those last handed over.
    let (_, _, b) = get(other, "/v1/policies", Some("k3y")).await;
    assert_eq!(json_of(&b)["policies"][0]["id"], "hk");
    // A port taken: refused, the listener as it was.
    let taken = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let body = json!({"port": taken.local_addr().unwrap().port(), "key": "k3y"});
    let (s, _) = call(&rig.svc, "PUT", "/paopao/route", &body.to_string()).await;
    assert_eq!(s, StatusCode::CONFLICT);
    assert_eq!(get(other, "/v1/policies", Some("k3y")).await.0, 200);
    let (s, _) = call(&rig.svc, "DELETE", "/paopao/route", "").await;
    assert_eq!(s, StatusCode::OK);
    assert!(closes(other).await, "still listening");
    let (s, _) = call(&rig.svc, "GET", "/paopao/route", "").await;
    assert_eq!(s, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn the_route_api_comes_back_with_the_core() {
    let (ask, _) = web(vec![]);
    let rig = rig(ask);
    let port = free_port();
    let conf = super::route::RouteConf {
        port,
        key: "k".into(),
        lan: false,
    };
    conf.write(&super::store::Store::new(rig.store())).unwrap();
    super::start_route(Arc::clone(&rig.svc)).await;
    let (s, _, _) = get(port, "/v1/policies", Some("k")).await;
    assert_eq!(s, 200);
}

#[tokio::test]
async fn a_trip_moves_the_point_where_the_script_looks_until_it_arrives() {
    let (ask, _) = web(vec![]);
    let rig = rig(ask);
    let task = tokio::spawn(super::run_track(Arc::clone(&rig.svc)));
    let cached = || -> Option<Value> {
        let all: Value = serde_json::from_str(
            &std::fs::read_to_string(rig.dir.path().join("modules/store.json")).ok()?,
        )
        .ok()?;
        serde_json::from_str(all[super::track::CACHE_KEY].as_str()?).ok()
    };
    // 222 m at 100 m/s, a step every 200 ms: there in about 2 s.
    let trip = json!({"points": [{"lat": 0.0, "lon": 0.0}, {"lat": 0.0, "lon": 0.002}],
        "speed": 100.0, "loop": false, "step_ms": 200, "config_url": "http://127.0.0.1:1/v1/location.json?key=k"});
    let (s, v) = call(&rig.svc, "PUT", "/paopao/location/track", &trip.to_string()).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["done"], false);
    tokio::time::sleep(Duration::from_millis(900)).await;
    let mid = cached().unwrap();
    let lon = mid["data"]["longitude"].as_f64().unwrap();
    assert!(lon > 0.0 && lon < 0.002, "{lon}");
    assert_eq!(mid["url"], "http://127.0.0.1:1/v1/location.json?key=k");
    let started = tokio::time::Instant::now();
    loop {
        let (_, v) = call(&rig.svc, "GET", "/paopao/location/track", "").await;
        if v["track"].is_null() {
            break;
        }
        assert!(started.elapsed() < Duration::from_secs(5), "never arrived");
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert_eq!(cached().unwrap()["data"]["longitude"], 0.002);

    // Ended early: the point stays where it was.
    let (s, _) = call(&rig.svc, "PUT", "/paopao/location/track", &trip.to_string()).await;
    assert_eq!(s, StatusCode::OK);
    tokio::time::sleep(Duration::from_millis(300)).await;
    call(&rig.svc, "DELETE", "/paopao/location/track", "").await;
    let stopped = cached().unwrap()["data"]["longitude"].clone();
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert_eq!(cached().unwrap()["data"]["longitude"], stopped);
    let (s, _) = call(
        &rig.svc,
        "PUT",
        "/paopao/location/track",
        r#"{"points": [], "speed": 1, "config_url": "u"}"#,
    )
    .await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    task.abort();
}

#[tokio::test]
async fn the_jobs_answer_501_where_children_are_impossible() {
    let dir = tempfile::tempdir().unwrap();
    let svc = Arc::new(Service::new(
        None,
        Arc::new(RwLock::new(raw())),
        dir.path().join("paopao"),
        None,
        no_reload(),
    ));
    for (method, path, body) in [
        ("POST", "/paopao/exits/locate", ""),
        ("POST", "/paopao/exits/relocate?tag=HK", ""),
        ("PUT", "/paopao/exits", "{}"),
        ("POST", "/paopao/network/check", ""),
        ("PUT", "/paopao/route", r#"{"port": 1, "key": "k"}"#),
        (
            "PUT",
            "/paopao/location/track",
            r#"{"points": [], "speed": 1, "config_url": "u"}"#,
        ),
    ] {
        assert_eq!(
            call(&svc, method, path, body).await.0,
            StatusCode::NOT_IMPLEMENTED,
            "{path}"
        );
    }
}
