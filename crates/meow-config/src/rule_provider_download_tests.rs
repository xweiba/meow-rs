use super::*;
use std::io::{Read, Write};
use std::time::Instant;

fn cfg() -> RawRuleProvider {
    serde_yaml::from_str("type: http\nbehavior: domain\nurl: http://127.0.0.1:1/rules").unwrap()
}

/// Exercise the real HTTP transport and retain all request headers for assertions.
fn scripted_http(bodies: Vec<&'static str>) -> (String, std::thread::JoinHandle<Vec<String>>) {
    scripted_http_bytes(bodies.into_iter().map(str::as_bytes).collect())
}

fn scripted_http_bytes(
    bodies: Vec<&'static [u8]>,
) -> (String, std::thread::JoinHandle<Vec<String>>) {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let task = std::thread::spawn(move || {
        let mut requests = Vec::new();
        for body in bodies {
            let deadline = Instant::now() + Duration::from_secs(8);
            let mut stream = loop {
                match listener.accept() {
                    Ok((stream, _)) => break stream,
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        assert!(Instant::now() < deadline, "HTTP request did not arrive");
                        std::thread::sleep(Duration::from_millis(5));
                    }
                    Err(e) => panic!("{e}"),
                }
            };
            stream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            let mut head = Vec::new();
            let mut b = [0; 1];
            while !head.ends_with(b"\r\n\r\n") {
                assert!(stream.read(&mut b).unwrap() > 0);
                head.push(b[0]);
            }
            requests.push(String::from_utf8(head).unwrap());
            write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            )
            .unwrap();
            stream.write_all(body).unwrap();
        }
        requests
    });
    (url, task)
}

#[tokio::test]
async fn invalid_sources_retry_on_load_refresh_and_preserve_last_good_cache() {
    const OLD: &str = "payload: ['old.example']\n";
    const NEW: &str = "payload: ['new.example']\n";
    const RECOVERED: &str = "payload: ['recovered.example']\n";
    const BAD: &str = "<html>mirror is down</html>";
    let (url, server) = scripted_http(vec![BAD, OLD, BAD, NEW, BAD, BAD, BAD, RECOVERED]);
    let dir = tempfile::tempdir().unwrap();
    let mut cfg = cfg();
    cfg.url = Some(format!("{url}/primary"));
    cfg.sources = vec![format!("{url}/secondary")];
    cfg.header = Some(HashMap::from([(
        "X-Test-Key".into(),
        crate::raw::StringOrList::Single("synthetic-value".into()),
    )]));
    let ctx = ParserContext::empty();
    let out = load_providers(
        &HashMap::from([("retry".into(), cfg)]),
        Some(dir.path()),
        &ctx,
        None,
        true,
    )
    .unwrap();
    let provider = &out["retry"];
    assert!(provider.last_error().is_none());
    assert!(provider.updated_at_secs() > 0);
    let cache = dir.path().join("rule-providers/retry.yaml");
    assert_eq!(std::fs::read_to_string(&cache).unwrap(), OLD);
    assert!(provider.matches_domain("old.example"));
    provider.refresh().await.unwrap();
    assert!(provider.matches_domain("new.example"));
    assert!(!provider.matches_domain("old.example"));
    assert_eq!(std::fs::read_to_string(&cache).unwrap(), NEW);
    let successful_at = provider.updated_at_secs();
    assert!(provider.refresh().await.is_err());
    let error = provider
        .last_error()
        .expect("background failures must remain visible");
    assert!(error.len() <= 64);
    for sensitive in [&url, "synthetic-value", "<html>", "mirror is down"] {
        assert!(!error.contains(sensitive));
    }
    assert_eq!(provider.updated_at_secs(), successful_at);
    assert!(provider.matches_domain("new.example"));
    assert_eq!(std::fs::read_to_string(&cache).unwrap(), NEW);
    provider.refresh().await.unwrap();
    assert!(provider.last_error().is_none());
    assert!(provider.matches_domain("recovered.example"));
    assert_eq!(std::fs::read_to_string(&cache).unwrap(), RECOVERED);
    let requests = server.join().unwrap();
    assert_eq!(requests.len(), 8);
    assert!(requests
        .iter()
        .all(|h| h.contains("X-Test-Key: synthetic-value")));
}

#[tokio::test]
async fn generated_mirror_never_receives_custom_headers() {
    let (url, server) = scripted_http(vec![
        "payload: ['direct.example']",
        "payload: ['mirror.example']",
    ]);
    let candidates = [
        FetchCandidate {
            url: format!("{url}/original"),
            explicit: true,
        },
        FetchCandidate {
            url: format!("{url}/mirror"),
            explicit: false,
        },
    ];
    let headers = vec![
        ("Authorization".into(), "Bearer synthetic".into()),
        ("X-Api-Key".into(), "synthetic".into()),
    ];
    for candidate in candidates {
        fetch_candidates(
            &[candidate],
            None,
            &headers,
            RuleSetBehavior::Domain,
            None,
            &ParserContext::empty(),
            true,
            None,
        )
        .await
        .unwrap();
    }
    let requests = server.join().unwrap();
    assert!(requests[0].contains("Authorization: Bearer synthetic"));
    assert!(requests[0].contains("X-Api-Key: synthetic"));
    assert!(!requests[1].to_ascii_lowercase().contains("authorization:"));
    assert!(!requests[1].to_ascii_lowercase().contains("x-api-key:"));
}

#[test]
fn mirror_candidates_expand_only_public_github_and_keep_explicit_priority() {
    let mut cfg = cfg();
    cfg.url = Some("https://raw.githubusercontent.com/org/repo/main/data.mrs".into());
    cfg.sources = vec![
        "https://github.com/org/repo/releases/download/v1/data.mrs".into(),
        "https://github.com/org/repo/data?token=synthetic".into(),
        "https://user:synthetic@github.com/org/repo/data".into(),
        "https://private.example/data".into(),
    ];
    cfg.mirrors = vec!["https://mirror.example/{url}".into()];
    let candidates = configured_candidates(&cfg).unwrap();
    assert_eq!(candidates.len(), 7);
    assert!(candidates[..5].iter().all(|c| c.explicit));
    assert!(candidates[5..]
        .iter()
        .all(|c| !c.explicit && !c.url.contains("synthetic")));
    cfg.mirrors = vec!["https://mirror.example/static".into()];
    assert!(configured_candidates(&cfg).is_err());
    cfg.mirrors = vec!["https://mirror.example/{url}?key=synthetic".into()];
    assert!(configured_candidates(&cfg).is_err());
    cfg.mirrors.clear();
    cfg.sources = vec!["file:///etc/passwd".into()];
    assert!(configured_candidates(&cfg).is_err());
}

#[test]
fn corrupt_preferred_cache_is_replaced_only_with_valid_source() {
    let dir = tempfile::tempdir().unwrap();
    let cache = dir.path().join("rule-providers/p.yaml");
    std::fs::create_dir_all(cache.parent().unwrap()).unwrap();
    std::fs::write(&cache, "<html>not rules</html>").unwrap();
    let (url, server) = scripted_http(vec!["payload: ['valid.example']"]);
    let mut cfg = cfg();
    cfg.url = Some(url);
    cfg.interval = Some(3600);
    let out = load_providers(
        &HashMap::from([("p".into(), cfg)]),
        Some(dir.path()),
        &ParserContext::empty(),
        None,
        true,
    )
    .unwrap();
    server.join().unwrap();
    assert!(out["p"].matches_domain("valid.example"));
    assert_eq!(
        std::fs::read_to_string(cache).unwrap(),
        "payload: ['valid.example']"
    );
}

#[test]
fn sing_box_formats_are_explicit_and_unsupported_fields_fail() {
    for format in ["srs", "json"] {
        let mut cfg = cfg();
        cfg.format = Some(format.into());
        assert!(parse_explicit_format(&cfg).unwrap().is_some());
    }
    assert!(parse_bytes_to_ruleset_with_format(
        b"SRS\x06data",
        RuleSetBehavior::Domain,
        Some(RuleSetFormat::Srs),
        &ParserContext::empty(),
        false
    )
    .err()
    .unwrap()
    .to_string()
    .contains("unsupported"));
    assert!(parse_bytes_to_ruleset_with_format(
        br#"{"version":2,"rules":[{"domain":"a.example","process_name":"curl"}]}"#,
        RuleSetBehavior::Classical,
        Some(RuleSetFormat::Json),
        &ParserContext::empty(),
        false
    )
    .is_err());
    assert!(parse_bytes_to_ruleset_with_format(
        b"\0\x01old-geosite",
        RuleSetBehavior::Domain,
        None,
        &ParserContext::empty(),
        false
    )
    .is_err());
}

#[test]
fn unsupported_payload_error_survives_later_transport_failure() {
    let (url, server) = scripted_http(vec!["SRS\u{6}unsupported"]);
    let closed = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let unavailable = format!("http://{}", closed.local_addr().unwrap());
    drop(closed);
    let mut cfg = cfg();
    cfg.url = Some(url);
    cfg.sources = vec![unavailable];
    let err = load_providers(
        &HashMap::from([("p".into(), cfg)]),
        None,
        &ParserContext::empty(),
        None,
        true,
    )
    .unwrap_err();
    assert!(err.to_string().contains("sing-box"));
    server.join().unwrap();
}

#[tokio::test]
async fn real_srs_http_refresh_retries_invalid_candidate_and_keeps_cache() {
    const VALID: &[u8] = include_bytes!("../../meow-rules/tests/fixtures/sing/0x0.srs");
    let (url, server) = scripted_http_bytes(vec![
        b"SRS\x06future",
        VALID,
        b"SRS\x06future",
        VALID,
        b"SRS\x06future",
        b"SRS\x06future",
    ]);
    let mut cfg = cfg();
    cfg.url = Some(format!("{url}/primary"));
    cfg.sources = vec![format!("{url}/source")];
    cfg.format = Some("srs".into());
    let dir = tempfile::tempdir().unwrap();
    let out = load_providers(
        &HashMap::from([("srs".into(), cfg)]),
        Some(dir.path()),
        &ParserContext::empty(),
        None,
        true,
    )
    .unwrap();
    let p = &out["srs"];
    assert!(p.matches_domain("www.0x0.st"));
    let cache = dir.path().join("rule-providers/srs.yaml");
    assert_eq!(std::fs::read(&cache).unwrap(), VALID);
    p.refresh().await.unwrap();
    assert!(p.last_error().is_none());
    assert!(p.refresh().await.is_err());
    assert!(p.last_error().is_some());
    assert!(p.matches_domain("www.0x0.st"));
    assert_eq!(std::fs::read(cache).unwrap(), VALID);
    server.join().unwrap();
}

#[tokio::test]
async fn json_http_refresh_does_not_drop_unknown_fields_leniently() {
    const GOOD: &str = r#"{"version":2,"rules":[{"domain_suffix":"good.example"}]}"#;
    const BAD: &str =
        r#"{"version":2,"rules":[{"domain_suffix":"bad.example","unsupported":true}]}"#;
    let (url, server) = scripted_http(vec![GOOD, BAD, GOOD]);
    let mut cfg = cfg();
    cfg.url = Some(url);
    cfg.format = Some("json".into());
    let out = load_providers(
        &HashMap::from([("json".into(), cfg)]),
        None,
        &ParserContext::empty(),
        None,
        false,
    )
    .unwrap();
    let p = &out["json"];
    assert!(p.matches_domain("good.example"));
    assert!(p.refresh().await.is_err());
    assert!(p.matches_domain("good.example"));
    assert!(!p.matches_domain("bad.example"));
    assert!(p.last_error().is_some());
    p.refresh().await.unwrap();
    assert!(p.last_error().is_none());
    server.join().unwrap();
}

#[tokio::test]
async fn explicit_failed_proxy_never_falls_back_to_direct() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let mut cfg = cfg();
    cfg.url = Some(format!(
        "http://{}/original",
        listener.local_addr().unwrap()
    ));
    cfg.sources = vec![format!(
        "http://{}/fallback",
        listener.local_addr().unwrap()
    )];
    cfg.proxy = Some("blocked".into());
    let proxy: Arc<dyn Proxy> = Arc::new(crate::proxy_parser::WrappedProxy::new(Box::new(
        meow_proxy::RejectAdapter::new(false),
    )));
    let out = load_providers_prefetched(
        &HashMap::from([("p".into(), cfg)]),
        None,
        &ParserContext::empty(),
        None,
        &|name| (name == "blocked").then(|| Arc::clone(&proxy)),
        &HashMap::new(),
        None,
        true,
    )
    .unwrap();
    assert_eq!(out["p"].rule_count(), 0);
    assert_eq!(out["p"].updated_at_secs(), 0);
    assert!(out["p"].last_error().is_some());
    assert!(out["p"].refresh().await.is_err());
    assert_eq!(out["p"].updated_at_secs(), 0);
    assert!(out["p"].last_error().unwrap().len() <= 64);
    assert_eq!(
        listener.accept().unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );
}

#[tokio::test]
async fn acquisition_empty_file_reports_unavailable_and_success_clears_it() {
    let dir = tempfile::tempdir().unwrap();
    let cfg: RawRuleProvider =
        serde_yaml::from_str("type: file\nbehavior: domain\npath: pending.yaml").unwrap();
    let out = load_providers(
        &HashMap::from([("pending".into(), cfg)]),
        Some(dir.path()),
        &ParserContext::empty(),
        None,
        true,
    )
    .unwrap();
    let p = &out["pending"];
    assert_eq!(p.updated_at_secs(), 0);
    assert!(p.last_error().unwrap().contains("unavailable"));
    assert!(p.refresh().await.is_err());
    assert_eq!(p.updated_at_secs(), 0);
    assert!(p.last_error().is_some());
    std::fs::write(
        dir.path().join("pending.yaml"),
        "payload: ['ready.example']",
    )
    .unwrap();
    p.refresh().await.unwrap();
    assert!(p.last_error().is_none());
    assert!(p.updated_at_secs() > 0);
    assert!(p.matches_domain("ready.example"));
}

#[tokio::test]
async fn stale_refresh_generation_cannot_overwrite_cache_or_live_rules() {
    let (url, server) = scripted_http(vec![
        "payload: ['current.example']",
        "payload: ['stale.example']",
        "payload: ['next.example']",
    ]);
    let dir = tempfile::tempdir().unwrap();
    let mut cfg = cfg();
    cfg.url = Some(url);
    let out = load_providers(
        &HashMap::from([("p".into(), cfg)]),
        Some(dir.path()),
        &ParserContext::empty(),
        None,
        true,
    )
    .unwrap();
    let p = &out["p"];
    // Model another refresh finishing first while this response is in flight.
    *p.cache_write_lock.lock() = 2;
    *p.install_gen.lock() = 2;
    p.refresh().await.unwrap();
    assert!(p.matches_domain("current.example"));
    let cache = dir.path().join("rule-providers/p.yaml");
    assert_eq!(
        std::fs::read_to_string(&cache).unwrap(),
        "payload: ['current.example']"
    );
    p.refresh_gen.store(3, Ordering::Relaxed);
    p.refresh().await.unwrap();
    assert!(p.matches_domain("next.example"));
    assert_eq!(
        std::fs::read_to_string(cache).unwrap(),
        "payload: ['next.example']"
    );
    server.join().unwrap();
}

#[tokio::test]
async fn provider_download_and_validation_concurrency_is_bounded() {
    use std::sync::atomic::AtomicUsize;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let active = Arc::new(AtomicUsize::new(0));
    let peak = Arc::new(AtomicUsize::new(0));
    let server_active = Arc::clone(&active);
    let server_peak = Arc::clone(&peak);
    let server = tokio::spawn(async move {
        let mut handlers = tokio::task::JoinSet::new();
        for _ in 0..8 {
            let (mut stream, _) = listener.accept().await.unwrap();
            let active = Arc::clone(&server_active);
            let peak = Arc::clone(&server_peak);
            handlers.spawn(async move {
                let n = active.fetch_add(1, Ordering::SeqCst) + 1;
                peak.fetch_max(n, Ordering::SeqCst);
                let mut b = [0; 1024];
                assert!(stream.read(&mut b).await.unwrap() > 0);
                tokio::time::sleep(Duration::from_millis(30)).await;
                let body = "payload: ['bounded.example']";
                active.fetch_sub(1, Ordering::SeqCst);
                stream.write_all(format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).as_bytes()).await.unwrap();
            });
        }
        while let Some(result) = handlers.join_next().await {
            result.unwrap();
        }
    });
    let mut tasks = tokio::task::JoinSet::new();
    for _ in 0..8 {
        let url = url.clone();
        tasks.spawn(async move {
            fetch_candidates(
                &[FetchCandidate {
                    url,
                    explicit: true,
                }],
                None,
                &[],
                RuleSetBehavior::Domain,
                None,
                &ParserContext::empty(),
                true,
                None,
            )
            .await
            .unwrap();
        });
    }
    while let Some(result) = tasks.join_next().await {
        result.unwrap();
    }
    server.await.unwrap();
    assert!((1..=2).contains(&peak.load(Ordering::SeqCst)));
    assert_eq!(active.load(Ordering::SeqCst), 0);
}

#[test]
fn prefetch_does_not_replace_last_good_cache_before_context_validation() {
    let dir = tempfile::tempdir().unwrap();
    let cache = dir.path().join("rule-providers/p.yaml");
    std::fs::create_dir_all(cache.parent().unwrap()).unwrap();
    std::fs::write(&cache, "payload: ['last-good.example']").unwrap();
    let (url, server) = scripted_http(vec!["payload: ['downloaded.example']"]);
    let mut cfg = cfg();
    cfg.url = Some(url);
    let prefetched = prefetch_payloads(
        &HashMap::from([("p".into(), cfg)]),
        Some(dir.path()),
        None,
        &|_| None,
    );
    assert!(prefetched.contains_key("p"));
    assert_eq!(
        std::fs::read_to_string(cache).unwrap(),
        "payload: ['last-good.example']"
    );
    server.join().unwrap();
}

#[test]
fn seven_background_providers_start_cache_only_without_any_http_request() {
    use std::sync::atomic::AtomicBool;
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let stop = Arc::new(AtomicBool::new(false));
    let done = Arc::clone(&stop);
    // If a regression makes startup dial, reply immediately rather than
    // letting the test itself hang for the transport's 60-second timeout.
    let server = std::thread::spawn(move || {
        let mut requests = 0;
        while !done.load(Ordering::SeqCst) {
            match listener.accept() {
                Ok((mut stream, _)) => {
                    requests += 1;
                    stream
                        .set_read_timeout(Some(Duration::from_secs(1)))
                        .unwrap();
                    let mut b = [0; 4096];
                    let _ = stream.read(&mut b);
                    let body = "payload: ['unexpected.example']";
                    let _ = write!(
                        stream,
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                        body.len()
                    );
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(2));
                }
                Err(e) => panic!("{e}"),
            }
        }
        requests
    });
    let dir = tempfile::tempdir().unwrap();
    let cache_dir = dir.path().join("rule-providers");
    std::fs::create_dir_all(&cache_dir).unwrap();
    // Valid cache is preferred even with interval=0; invalid cache must be
    // retained untouched and queued for background repair in strict mode.
    std::fs::write(cache_dir.join("p0.yaml"), "payload: ['cached.example']").unwrap();
    std::fs::write(cache_dir.join("p1.yaml"), "<html>bad-cache</html>").unwrap();
    let mut raw = HashMap::new();
    for i in 0..7 {
        let mut cfg = cfg();
        cfg.url = Some(format!("{url}/{i}"));
        cfg.background_fetch = true;
        cfg.interval = Some(if i == 0 { 0 } else { 86400 });
        if i >= 4 {
            cfg.behavior = "ipcidr".into();
        }
        raw.insert(format!("p{i}"), cfg);
    }
    let start = Instant::now();
    let prefetched = prefetch_payloads(&raw, Some(dir.path()), None, &|_| None);
    let out = load_providers_prefetched(
        &raw,
        Some(dir.path()),
        &ParserContext::empty(),
        None,
        &|_| None,
        &prefetched,
        None,
        true,
    )
    .unwrap();
    let elapsed = start.elapsed();
    stop.store(true, Ordering::SeqCst);
    let requests = server.join().unwrap();
    assert_eq!(requests, 0, "background startup must not dial HTTP at all");
    assert!(elapsed < Duration::from_secs(2), "startup took {elapsed:?}");
    assert_eq!(out.len(), 7);
    assert_eq!(prefetched.len(), 1);
    assert!(out["p0"].matches_domain("cached.example"));
    assert!(out["p0"].last_error().is_none());
    assert!(out["p0"].updated_at_secs() > 0);
    for i in 1..7 {
        let p = &out[&format!("p{i}")];
        assert!(p.background_fetch());
        assert_eq!(p.rule_count(), 0);
        assert_eq!(p.updated_at_secs(), 0);
        assert!(p.last_error().unwrap().contains("awaiting background"));
    }
    assert_eq!(
        std::fs::read_to_string(cache_dir.join("p1.yaml")).unwrap(),
        "<html>bad-cache</html>"
    );
}

#[tokio::test]
async fn background_cold_provider_captures_sources_and_recovers_on_refresh() {
    let (url, server) = scripted_http(vec![
        "<html>bad source</html>",
        "payload: ['downloaded.example']",
    ]);
    let mut cfg = cfg();
    cfg.background_fetch = true;
    cfg.url = Some(format!("{url}/primary"));
    cfg.sources = vec![format!("{url}/fallback")];
    let dir = tempfile::tempdir().unwrap();
    let out = load_providers(
        &HashMap::from([("bg".into(), cfg)]),
        Some(dir.path()),
        &ParserContext::empty(),
        None,
        true,
    )
    .unwrap();
    let p = &out["bg"];
    assert!(p.background_fetch());
    assert_eq!(p.updated_at_secs(), 0);
    assert!(p.last_error().is_some());
    p.refresh().await.unwrap();
    assert!(p.last_error().is_none());
    assert!(p.updated_at_secs() > 0);
    assert!(p.matches_domain("downloaded.example"));
    assert!(dir.path().join("rule-providers/bg.yaml").exists());
    server.join().unwrap();
}

#[test]
fn background_flag_defaults_false_and_classical_keeps_context_prefetch() {
    assert!(!cfg().background_fetch);
    let (url, server) = scripted_http(vec!["payload: ['DOMAIN,context.example']"]);
    let mut cfg = cfg();
    cfg.background_fetch = true;
    cfg.behavior = "classical".into();
    cfg.url = Some(url);
    let raw = HashMap::from([("classic".into(), cfg)]);
    let prefetched = prefetch_payloads(&raw, None, None, &|_| None);
    assert_eq!(prefetched.len(), 1);
    let out = load_providers_prefetched(
        &raw,
        None,
        &ParserContext::empty(),
        None,
        &|_| None,
        &prefetched,
        None,
        true,
    )
    .unwrap();
    assert!(!out["classic"].background_fetch());
    assert!(out["classic"].matches_domain("context.example"));
    server.join().unwrap();
}

#[test]
fn json_encoded_clash_yaml_remains_compatible_with_auto_detection() {
    let set = parse_bytes_to_ruleset_with_format(
        br#"{"payload":["compatible.example"]}"#,
        RuleSetBehavior::Domain,
        None,
        &ParserContext::empty(),
        true,
    )
    .unwrap();
    assert!(set.matches_domain("compatible.example"));
    let sing = parse_bytes_to_ruleset_with_format(
        br#"{"version":2,"rules":[{"domain":"sing.example"}]}"#,
        RuleSetBehavior::Domain,
        None,
        &ParserContext::empty(),
        true,
    )
    .unwrap();
    assert!(sing.matches_domain("sing.example"));
}
