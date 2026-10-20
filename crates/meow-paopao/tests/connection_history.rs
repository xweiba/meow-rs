//! Omission delegates to the native default; explicit limits are user choices.
use meow_paopao::{build_json, RuntimeOptions};
use serde_json::json;

#[test]
fn missing_history_limit_does_not_override_the_native_default() {
    assert_eq!(RuntimeOptions::default().connection_history, None);
    for runtime in [json!({}), json!({"connectionHistory": null})] {
        let out = build_json(&json!({"runtime": runtime}).to_string());
        assert!(out.get("configError").is_none());
        assert!(out["config"].get("connection-history-limit").is_none());
    }
}

#[test]
fn explicit_history_limits_remain_explicit_including_the_previous_default() {
    for limit in [0, 500, 1500] {
        let out = build_json(&json!({"runtime": {"connectionHistory": limit}}).to_string());
        assert!(out.get("configError").is_none());
        assert_eq!(out["config"]["connection-history-limit"], limit);
    }
}
