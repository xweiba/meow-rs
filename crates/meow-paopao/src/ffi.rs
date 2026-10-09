//! C ABI over [`crate::api`] for the Dart app (dart:ffi, synchronous):
//! NUL-terminated UTF-8 JSON in, a string this library allocated out, freed
//! with [`paopao_free`]. Entry points: `paopao_parse`, `paopao_build`,
//! `paopao_explain`. Built into `libmeow_mobile.so` on Android and into
//! the desktop `meow_paopao` library (feature `ffi`).

use std::ffi::{c_char, CStr, CString};

use serde_json::{json, Value};

/// Runs `f` on the argument; any failure (bad UTF-8, a panic) becomes
/// `{"error": ...}` so nothing unwinds into Dart. With `panic = "abort"`
/// (the workspace's release profile) a panic aborts instead: the functions
/// behind this are written not to panic.
fn call(arg: *const c_char, f: impl FnOnce(&str) -> Value) -> *mut c_char {
    call2(arg, arg, |a, _| f(a))
}

/// [`call`] with two string arguments.
fn call2(a: *const c_char, b: *const c_char, f: impl FnOnce(&str, &str) -> Value) -> *mut c_char {
    let out = match (text(a), text(b)) {
        (Ok(a), Ok(b)) => std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| f(a, b)))
            .unwrap_or_else(|_| json!({ "error": "internal error" })),
        (Err(e), _) | (_, Err(e)) => json!({ "error": e }),
    };
    // serde_json never writes a NUL byte (it escapes U+0000).
    CString::new(out.to_string()).map_or(std::ptr::null_mut(), CString::into_raw)
}

/// The argument as UTF-8 text.
fn text<'a>(arg: *const c_char) -> Result<&'a str, &'static str> {
    if arg.is_null() {
        return Err("null argument");
    }
    // SAFETY: the caller passes a valid NUL-terminated string that
    // outlives this call (dart:ffi allocates and frees it around it).
    unsafe { CStr::from_ptr(arg) }
        .to_str()
        .map_err(|_| "argument is not UTF-8")
}

/// A subscription body → `{nodes, skipped, split, usage}` (see
/// [`crate::api::parse_json`]).
///
/// # Safety
/// `body` is a valid NUL-terminated string; free the result with
/// [`paopao_free`].
#[no_mangle]
pub unsafe extern "C" fn paopao_parse(body: *const c_char) -> *mut c_char {
    call(body, crate::api::parse_json)
}

/// `ProxyController.configInput()` → `{config, pool, tree, rules,
/// routePolicies}` (see [`crate::api::build_json`]). The result holds
/// secrets (API secret, SSH credentials): free it promptly.
///
/// # Safety
/// `input` is a valid NUL-terminated string; free the result with
/// [`paopao_free`].
#[no_mangle]
pub unsafe extern "C" fn paopao_build(input: *const c_char) -> *mut c_char {
    call(input, crate::api::build_json)
}

/// Which rule decides a connection, and where it goes: `input` as for
/// [`paopao_build`], `query` `{host, port?, process?, network?}` → `{rule,
/// type, payload, target, index, path, decided}` or `null` (see
/// [`crate::api::explain_json`]).
///
/// # Safety
/// `input` and `query` are valid NUL-terminated strings; free the result
/// with [`paopao_free`].
#[no_mangle]
pub unsafe extern "C" fn paopao_explain(input: *const c_char, query: *const c_char) -> *mut c_char {
    call2(input, query, crate::api::explain_json)
}

/// Frees a string returned by this library; null is ignored.
///
/// # Safety
/// `s` came from this library and is freed once.
#[no_mangle]
pub unsafe extern "C" fn paopao_free(s: *mut c_char) {
    if !s.is_null() {
        // SAFETY: made by `CString::into_raw` above.
        drop(unsafe { CString::from_raw(s) });
    }
}
