//! The core's subscription refresh against the app's: `golden/refresh/`
//! was dumped from `ProxyController.refreshSubscription` (the core off, so
//! no retry through it) with the subscription as `configInput()` hands it
//! on before and after each refresh. Replayed here through
//! [`refresh::refresh`], [`refresh::Refreshed::record`] and
//! [`refresh::merge_refreshed`], the download answered as the `meow paopao
//! fetch` child answers it; the result must be the app's, key order
//! included.

use meow_paopao::refresh::{self, Download, Refreshed};
use serde_json::{Map, Value};

/// A download of `url` from the dumped answers, as the fetch child gives
/// it: the parse with the header's usage and the `Content-Disposition`.
fn download(web: &Map<String, Value>, url: &str) -> Download {
    let Some(res) = web.get(url) else {
        return Download::NoAnswer;
    };
    let status = res["status"].as_u64().unwrap() as u16;
    if status != 200 {
        return Download::Status(status);
    }
    let mut v = meow_paopao::parse_json(res["body"].as_str().unwrap());
    if v.get("error").is_some() {
        return Download::Unreadable;
    }
    let header = |k: &str| res["headers"].get(k).and_then(Value::as_str);
    if let Some(u) = header("subscription-userinfo").and_then(meow_paopao::Usage::parse) {
        v["usage"] = u.to_json();
    }
    v["content_disposition"] = header("content-disposition").into();
    Download::Parsed(v)
}

#[test]
fn refreshes_merge_as_the_app_merges_them() {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/golden/refresh/refresh.json"
    );
    let cases: Vec<Value> = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    assert!(cases.len() >= 10);
    for case in &cases {
        let name = case["name"].as_str().unwrap();
        let mut sub = case["before"].as_object().unwrap().clone();
        let id = sub["id"].as_str().unwrap().to_owned();
        let mut previous: Option<Refreshed> = None;
        for (i, step) in case["steps"].as_array().unwrap().iter().enumerate() {
            let web = step["web"].as_object().unwrap();
            let url = sub["url"].as_str().unwrap().to_owned();
            let attempt = refresh::refresh(&url, false, |u, _| download(web, u));
            let record = Refreshed::record(&id, None, attempt, previous.take(), i as i64);
            sub = refresh::merge_refreshed(&sub, &record);
            let want = &step["after"];
            assert_eq!(
                serde_json::to_string(&sub).unwrap(),
                serde_json::to_string(want).unwrap(),
                "{name}, step {i}"
            );
            previous = Some(record);
        }
    }
}
