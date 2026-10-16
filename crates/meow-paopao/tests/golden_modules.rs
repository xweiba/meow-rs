//! Rewrite modules parsed as the app parses them: `golden/modules/` was
//! dumped from Dart `parseModule` (`ModuleSpec.toJson`) over the app's own
//! test modules and edge cases; the core's parse must give the same JSON,
//! key order included. A case Dart throws on (a mistyped Stash field) only
//! has to parse here.

use meow_paopao::ingest::module::parse_module;
use serde_json::Value;

#[test]
fn modules_parse_as_the_app_parses_them() {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/golden/modules/modules.json"
    );
    let cases: Vec<Value> = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    assert!(cases.len() >= 20);
    for case in &cases {
        let name = case["name"].as_str().unwrap();
        let values: Vec<(String, String)> = case["values"]
            .as_object()
            .unwrap()
            .iter()
            .map(|(k, v)| (k.clone(), v.as_str().unwrap().to_owned()))
            .collect();
        let got = parse_module(
            case["text"].as_str().unwrap(),
            case["fallback"].as_str().unwrap(),
            &values,
        );
        if case["spec"].get("throws").is_some() {
            continue;
        }
        assert_eq!(
            serde_json::to_string(&got).unwrap(),
            serde_json::to_string(&case["spec"]).unwrap(),
            "{name}"
        );
    }
}
