use std::sync::Arc;
use std::time::Duration;

use super::*;

fn opts(binary: bool, store: Arc<Store>) -> Options {
    Options {
        name: "t".into(),
        argument: "lat=31.2&lon=121.5".into(),
        binary_body: binary,
        timeout: Duration::from_secs(2),
        store,
        ..Options::default()
    }
}

fn req() -> Message {
    Message {
        url: "https://example.com/a?x=1".into(),
        method: "POST".into(),
        headers: vec![("Content-Type".into(), "text/plain".into())],
        body: Some(b"hello".to_vec()),
        ..Message::default()
    }
}

fn resp(body: &[u8]) -> Message {
    Message {
        status: 200,
        headers: vec![("X-A".into(), "1".into())],
        body: Some(body.to_vec()),
        ..Message::default()
    }
}

#[test]
fn surge_style_response_rewrite() {
    let store = Arc::new(Store::new(None));
    let out = run(
        r#"
        let b = JSON.parse($response.body);
        b.vip = true;
        let h = $response.headers; h['X-B'] = '2';
        $done({ body: JSON.stringify(b), headers: h, status: 201 });
        "#,
        &req(),
        Some(&resp(br#"{"vip":false}"#)),
        &opts(false, store),
    )
    .unwrap();
    assert_eq!(out.body.unwrap(), br#"{"vip":true}"#);
    assert_eq!(out.status, Some(201));
    assert!(out.headers.unwrap().contains(&("X-B".into(), "2".into())));
}

#[test]
fn binary_bodies_are_bytes() {
    let store = Arc::new(Store::new(None));
    let out = run(
        r#"
        const b = $response.body;
        if (!(b instanceof Uint8Array)) throw new Error('not bytes');
        const o = new Uint8Array(b.length + 1);
        o.set(b); o[b.length] = 0xff;
        $done({ body: o });
        "#,
        &req(),
        Some(&resp(&[0, 1, 2])),
        &opts(true, store),
    )
    .unwrap();
    assert_eq!(out.body.unwrap(), vec![0, 1, 2, 0xff]);
}

#[test]
fn request_scripts_can_answer_themselves_and_read_arguments() {
    let store = Arc::new(Store::new(None));
    let out = run(
        r#"
        if ($request.method !== 'POST' || $request.body !== 'hello') throw new Error('bad request');
        $done({ response: { status: 200, headers: { 'Content-Type': 'text/plain' }, body: $argument } });
        "#,
        &req(),
        None,
        &opts(false, store),
    )
    .unwrap();
    let r = out.response.unwrap();
    assert_eq!(r.status, 200);
    assert_eq!(r.body.unwrap(), b"lat=31.2&lon=121.5");
}

#[test]
fn persistent_store_and_qx_prefs_share_values() {
    let dir = std::env::temp_dir().join(format!("meow-script-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let store = Arc::new(Store::new(Some(dir.join("store.json"))));
    run(
        r#"$persistentStore.write(JSON.stringify({lat: 1}), 'loc'); $done();"#,
        &req(),
        None,
        &opts(false, Arc::clone(&store)),
    )
    .unwrap();
    let out = run(
        r#"$done({ body: $prefs.valueForKey('loc') + '|' + $persistentStore.read('missing') });"#,
        &req(),
        Some(&resp(b"")),
        &opts(false, Arc::clone(&store)),
    )
    .unwrap();
    assert_eq!(out.body.unwrap(), br#"{"lat":1}|null"#);
    assert_eq!(store.read("loc").as_deref(), Some(r#"{"lat":1}"#));
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn async_scripts_finish_through_promises() {
    let store = Arc::new(Store::new(None));
    let out = run(
        r#"
        (async () => {
          await new Promise(r => setTimeout(r, 10));
          $done({ body: 'later' });
        })();
        "#,
        &req(),
        Some(&resp(b"x")),
        &opts(false, store),
    )
    .unwrap();
    assert_eq!(out.body.unwrap(), b"later");
}

#[test]
fn no_done_leaves_things_alone_errors_and_runaways_are_reported() {
    let store = Arc::new(Store::new(None));
    assert_eq!(
        run(
            "let x = 1;",
            &req(),
            Some(&resp(b"x")),
            &opts(false, Arc::clone(&store))
        )
        .unwrap(),
        Outcome::default()
    );
    let e = run(
        "throw new Error('boom')",
        &req(),
        None,
        &opts(false, Arc::clone(&store)),
    )
    .unwrap_err();
    assert!(e.to_string().contains("boom"), "{e}");
    let mut o = opts(false, store);
    o.timeout = Duration::from_millis(200);
    assert!(matches!(
        run("for(;;){}", &req(), None, &o),
        Err(Error::Timeout)
    ));
}

#[test]
fn the_first_done_counts_and_start_time_is_in_seconds() {
    let store = Arc::new(Store::new(None));
    let out = run(
        r#"
        const age = Date.now() / 1000 - $script.startTime;
        if (!(age >= 0 && age < 60)) throw new Error('startTime ' + $script.startTime);
        try {
            $done({ body: 'patched' });
        } finally {
            $done();
        }
        "#,
        &req(),
        Some(&resp(b"original")),
        &opts(false, store),
    )
    .unwrap();
    assert_eq!(out.body.unwrap(), b"patched");
}

#[test]
fn response_scripts_may_answer_with_a_response_object() {
    let store = Arc::new(Store::new(None));
    let out = run(
        r#"
        const r = $response;
        r.body = new Uint8Array([7, 8]);
        r.bodyBytes = r.body;
        r.headers['X-B'] = '1';
        $done({ response: r });
        "#,
        &req(),
        Some(&resp(&[1, 2, 3])),
        &opts(true, store),
    )
    .unwrap();
    assert_eq!(out.body.unwrap(), vec![7, 8]);
    assert!(out.headers.unwrap().contains(&("X-B".into(), "1".into())));
    assert!(out.response.is_none());
}

fn with_http(store: Arc<Store>, seen: Arc<parking_lot::Mutex<Vec<HttpRequest>>>) -> Options {
    let mut o = opts(false, store);
    o.http = Some(Arc::new(move |req: HttpRequest| {
        seen.lock().push(req.clone());
        if req.url.contains("fail") {
            return Err("connection refused".into());
        }
        Ok(HttpResponse {
            status: 200,
            headers: vec![("Content-Type".into(), "application/json".into())],
            body: serde_json::json!({
                "echo": format!("{} {}", req.method, req.url),
                "body": String::from_utf8_lossy(&req.body),
            })
            .to_string()
            .into_bytes(),
        })
    }));
    o
}

#[test]
fn http_client_callbacks_and_task_fetch_promises() {
    let store = Arc::new(Store::new(None));
    let seen = Arc::new(parking_lot::Mutex::new(Vec::new()));
    let out = run(
        r#"
        $httpClient.post({ url: 'https://api.example/a', headers: { 'X-K': 'v' }, body: 'hi', timeout: 3 }, (err, resp, data) => {
            if (err) throw new Error(err);
            const a = JSON.parse(data).echo;
            $httpClient.get('https://fail.example/', (err2, r2, d2) => {
                $task.fetch({ url: 'https://api.example/b', method: 'PUT', body: { x: 1 } }).then(r => {
                    $done({ body: [a, err2, resp.status, r.statusCode, JSON.parse(r.body).body].join('|') });
                });
            });
        });
        "#,
        &req(),
        Some(&resp(b"")),
        &with_http(store, Arc::clone(&seen)),
    )
    .unwrap();
    assert_eq!(
        String::from_utf8(out.body.unwrap()).unwrap(),
        r#"POST https://api.example/a|connection refused|200|200|{"x":1}"#
    );
    let seen = seen.lock();
    assert_eq!(seen.len(), 3);
    assert!(seen[0].headers.contains(&("X-K".into(), "v".into())));
    assert_eq!(seen[0].body, b"hi");
    assert!(
        seen[0].timeout <= Duration::from_secs(2) && seen[0].timeout > Duration::from_millis(1500),
        "3 s asked, capped by the script's own 2 s deadline: {:?}",
        seen[0].timeout
    );
    assert_eq!(seen[2].method, "PUT");
}

#[test]
fn binary_mode_and_no_network() {
    let store = Arc::new(Store::new(None));
    let seen = Arc::new(parking_lot::Mutex::new(Vec::new()));
    let out = run(
        r#"
        $httpClient.get({ url: 'https://x/', 'binary-mode': true }, (e, r, d) => {
            $done({ body: (d instanceof Uint8Array ? 'bytes ' : 'text ') + d.length });
        });
        "#,
        &req(),
        Some(&resp(b"")),
        &with_http(Arc::clone(&store), seen),
    )
    .unwrap();
    assert!(String::from_utf8(out.body.unwrap())
        .unwrap()
        .starts_with("bytes "));
    let out = run(
        r#"$httpClient.get('https://x/', (e) => $done({ body: String(e) }));"#,
        &req(),
        Some(&resp(b"")),
        &opts(false, store),
    )
    .unwrap();
    assert_eq!(out.body.unwrap(), b"scripts may not use the network here");
}

#[test]
fn timers_wait_for_real_and_intervals_stop() {
    let store = Arc::new(Store::new(None));
    let start = std::time::Instant::now();
    let out = run(
        r#"
        const order = [];
        setTimeout(() => order.push('b'), 120);
        setTimeout(() => order.push('a'), 30);
        const gone = setTimeout(() => order.push('never'), 10);
        clearTimeout(gone);
        let n = 0;
        const iv = setInterval(() => { if (++n === 3) clearInterval(iv); }, 20);
        setTimeout(() => $done({ body: order.join('') + n }), 200);
        "#,
        &req(),
        Some(&resp(b"")),
        &opts(false, store),
    )
    .unwrap();
    assert_eq!(out.body.unwrap(), b"ab3");
    assert!(start.elapsed() >= Duration::from_millis(190));
}

#[test]
fn utils_ungzip() {
    use std::io::Write as _;
    let mut z = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    z.write_all(b"plain words").unwrap();
    let store = Arc::new(Store::new(None));
    let out = run(
        r#"$done({ body: $utils.ungzip($response.body) });"#,
        &req(),
        Some(&resp(&z.finish().unwrap())),
        &opts(true, store),
    )
    .unwrap();
    assert_eq!(out.body.unwrap(), b"plain words");
}

#[test]
fn quantumult_x_requests_are_answered_with_a_status() {
    let store = Arc::new(Store::new(None));
    let out = run(
        r#"
        if (typeof $task === 'undefined') throw new Error('QX scripts look for $task');
        $done({ status: 'HTTP/1.1 200 OK', headers: { 'Content-Type': 'application/json' }, body: '{"ok":true}' });
        "#,
        &req(),
        None,
        &opts(false, store),
    )
    .unwrap();
    let r = out.response.unwrap();
    assert_eq!(r.status, 200);
    assert_eq!(r.body.unwrap(), br#"{"ok":true}"#);
    assert!(out.status.is_none());
}

#[test]
fn cron_runs_have_no_request_and_notifications_reach_the_embedder() {
    let seen = Arc::new(parking_lot::Mutex::new(Vec::new()));
    let sink = Arc::clone(&seen);
    let o = Options {
        name: "checkin".into(),
        cron: true,
        notify: Some(Arc::new(move |n| sink.lock().push(n))),
        ..Options::default()
    };
    let out = run(
        r#"
        if (typeof $request !== 'undefined') throw new Error('cron has no request');
        if ($script.type !== 'cron') throw new Error($script.type);
        $notification.post('签到', '成功', '+1', { 'open-url': 'https://example.com/' });
        $notify('QX', '', 'plain');
        $done();
        "#,
        &Message::default(),
        None,
        &o,
    )
    .unwrap();
    assert_eq!(out, Outcome::default());
    let seen = seen.lock();
    assert_eq!(
        seen[0],
        Notification {
            title: "签到".into(),
            subtitle: "成功".into(),
            body: "+1".into(),
            url: Some("https://example.com/".into()),
        }
    );
    assert_eq!(seen[1].body, "plain");
    assert_eq!(seen[1].url, None);
}

#[test]
fn loon_object_arguments() {
    let o = Options {
        argument: r#"{"lat":"31.2","on":"true"}"#.into(),
        argument_object: true,
        ..Options::default()
    };
    let out = run(
        r#"$done({ body: $argument.lat + '|' + $argument.on });"#,
        &req(),
        Some(&resp(b"")),
        &o,
    )
    .unwrap();
    assert_eq!(out.body.unwrap(), b"31.2|true");
}
