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
