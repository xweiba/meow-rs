//! The C ABI round trip: `paopao_build` / `paopao_parse` called as dart:ffi
//! calls them, results freed with `paopao_free`.

#![cfg(feature = "ffi")]

mod common;

use std::ffi::{c_char, CStr, CString};

use meow_paopao::ffi::{paopao_build, paopao_explain, paopao_free, paopao_parse};
use serde_json::Value;

/// Calls `f` with `arg` as a C string, reads the result and frees it.
fn call(f: unsafe extern "C" fn(*const c_char) -> *mut c_char, arg: &str) -> Value {
    let arg = CString::new(arg).expect("no NUL");
    // SAFETY: `arg` is NUL-terminated and outlives the call; the result is
    // read before it is freed, once.
    unsafe {
        let out = f(arg.as_ptr());
        assert!(!out.is_null());
        let text = CStr::from_ptr(out).to_str().expect("UTF-8").to_owned();
        paopao_free(out);
        serde_json::from_str(&text).expect("JSON")
    }
}

#[test]
fn build_through_the_c_abi() {
    let files = common::golden_files("build");
    let case = common::read_json(&files[0]);
    let out = call(paopao_build, &case["input"].to_string());
    assert_eq!(
        common::first_diff(&out["config"], &case["expected"]["config"]),
        None
    );
    assert_eq!(
        common::first_diff(&out["pool"], &case["expected"]["pool"]),
        None
    );
    assert_eq!(
        common::first_diff(&out["tree"], &case["expected"]["tree"]),
        None
    );
    assert!(out["rules"].is_array() && out["routePolicies"].is_array());
}

#[test]
fn parse_through_the_c_abi() {
    let link = "trojan://pw@example.com:443#HK";
    let out = call(paopao_parse, link);
    assert_eq!(out["nodes"][0]["name"], "HK", "{out}");
    assert!(out.get("error").is_none());
}

#[test]
fn bad_input_is_an_error_not_a_crash() {
    assert!(call(paopao_build, "not json")["error"].is_string());
    assert!(call(paopao_build, "[1]")["error"].is_string());
    // SAFETY: a null argument is answered with an error; null is ignored
    // by `paopao_free`.
    unsafe {
        let out = paopao_build(std::ptr::null());
        assert!(!out.is_null());
        paopao_free(out);
        paopao_free(std::ptr::null_mut());
    }
}

#[test]
fn explain_through_the_c_abi() {
    let files = common::golden_files("build");
    let case = common::read_json(&files[0]);
    let input = CString::new(case["input"].to_string()).expect("no NUL");
    let query = CString::new(r#"{"host": "10.1.2.3"}"#).expect("no NUL");
    // SAFETY: both arguments are NUL-terminated and outlive the call; the
    // result is read before it is freed, once. Null arguments are answered
    // with an error.
    unsafe {
        let out = paopao_explain(input.as_ptr(), query.as_ptr());
        let text = CStr::from_ptr(out).to_str().expect("UTF-8").to_owned();
        paopao_free(out);
        let v: Value = serde_json::from_str(&text).expect("JSON");
        assert_eq!(v["rule"], "IP-CIDR,10.0.0.0/8,DIRECT,no-resolve", "{v}");
        let out = paopao_explain(input.as_ptr(), std::ptr::null());
        let text = CStr::from_ptr(out).to_str().expect("UTF-8").to_owned();
        paopao_free(out);
        assert!(text.contains("error"));
    }
}
