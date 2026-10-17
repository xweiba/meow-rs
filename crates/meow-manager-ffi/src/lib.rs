//! The manager embedded in a tray program that is not Rust (PaoPao Menu,
//! macOS: `macos/menu/main.swift` in the app): two C functions. The tray
//! then talks to it over its HTTP API like any client (the token file in
//! the data directory).
//!
//! ```c
//! bool paopao_manager_start(const char *data, const char *meow,
//!                           const char *login_program,
//!                           const char *login_args_json);
//! void paopao_manager_stop(bool quit);
//! char *paopao_manager_data_dir(const char *given);
//! void paopao_manager_free(char *s);
//! ```

use meow_manager::desktop::{desktop_manager, Embedded, Options, HELPER_SOCKET};
use meow_manager::login::Launch;
use std::ffi::{c_char, CStr, CString};
use std::path::PathBuf;
use std::sync::Mutex;

static RUNNING: Mutex<Option<Embedded>> = Mutex::new(None);

/// # Safety
/// `p` is null or a NUL-terminated string.
unsafe fn text(p: *const c_char) -> Option<String> {
    if p.is_null() {
        return None;
    }
    // SAFETY: as the caller promises.
    unsafe { CStr::from_ptr(p) }
        .to_str()
        .ok()
        .map(str::to_owned)
}

/// Starts the manager (once): `data` the app's data directory, `meow` the
/// core binary, `login_program` and `login_args_json` (a JSON array of
/// strings) what 开机自启 starts at login. True once its API listens.
///
/// # Safety
/// Each argument is null or a NUL-terminated UTF-8 string.
#[no_mangle]
pub unsafe extern "C" fn paopao_manager_start(
    data: *const c_char,
    meow: *const c_char,
    login_program: *const c_char,
    login_args_json: *const c_char,
) -> bool {
    // SAFETY: as the caller promises.
    let (data, meow, program, args) = unsafe {
        (
            text(data),
            text(meow),
            text(login_program),
            text(login_args_json),
        )
    };
    let (Some(data), Some(meow), Some(program)) = (data, meow, program) else {
        return false;
    };
    let mut running = RUNNING
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if running.is_some() {
        return true;
    }
    let args: Vec<String> = args
        .and_then(|a| serde_json::from_str(&a).ok())
        .unwrap_or_default();
    let data = PathBuf::from(data);
    let options = Options {
        data: data.clone(),
        meow: meow.into(),
        launch: Launch {
            program: program.into(),
            args,
        },
        helper: cfg!(target_os = "macos").then(|| HELPER_SOCKET.into()),
    };
    match Embedded::start(desktop_manager(&options), &data) {
        Ok(e) => {
            *running = Some(e);
            true
        }
        Err(_) => false,
    }
}

/// Stops it: `quit` (退出): the core stopped and the system proxy put back,
/// 内核 off; else (logout) the same but the switches kept for next time.
#[no_mangle]
pub extern "C" fn paopao_manager_stop(quit: bool) {
    let taken = RUNNING
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .take();
    if let Some(e) = taken {
        e.shutdown(quit);
    }
}

/// The app's data directory ([`meow_manager::data::resolve`]: the old
/// one moved over first when only it exists): `given` the `--data` passed
/// in (null or empty: none). Free the result with [`paopao_manager_free`];
/// null only for a path that is no C string.
///
/// # Safety
/// `given` is null or a NUL-terminated UTF-8 string.
#[no_mangle]
pub unsafe extern "C" fn paopao_manager_data_dir(given: *const c_char) -> *mut c_char {
    // SAFETY: as the caller promises.
    let given = unsafe { text(given) }.filter(|g| !g.is_empty());
    let r = meow_manager::data::resolve(
        &meow_manager::data::Env::current(),
        given.as_deref().map(std::path::Path::new),
    );
    CString::new(r.dir.to_string_lossy().into_owned())
        .map_or(std::ptr::null_mut(), CString::into_raw)
}

/// Frees a string [`paopao_manager_data_dir`] returned; null is ignored.
///
/// # Safety
/// `s` is null or a string from this library, not freed before.
#[no_mangle]
pub unsafe extern "C" fn paopao_manager_free(s: *mut c_char) {
    if !s.is_null() {
        // SAFETY: made by CString::into_raw here.
        drop(unsafe { CString::from_raw(s) });
    }
}
