//! meow-rs for phone apps.
//!
//! Android: `app.paopao.proxy.MeowCore` (Kotlin) calls
//! - `start(config, home, fd, vpnService)`: runs the core on a thread of its
//!   own over the VPN's TUN fd; every socket the core opens goes through
//!   `vpnService.protect(fd)` first so it bypasses the VPN. Returns null
//!   when the core came up, else the reason.
//! - `stop()`, `running()`.

// The config builder's C ABI, linked in so this library exports it too.
pub use meow_paopao::ffi::{paopao_build, paopao_explain, paopao_free, paopao_parse};
use std::sync::mpsc;
use std::time::Duration;

/// The site (registrable domain, Public Suffix List) of `host`, for the app
/// in this process (dart:ffi): rules and screens group by the core's own
/// list. `host` NUL-terminated UTF-8; the site goes to `out` (`cap` bytes,
/// NUL-terminated). Returns its length, or -1 (null / not UTF-8 / no room).
///
/// # Safety
/// `host` must be NUL-terminated and `out` writable for `cap` bytes.
#[no_mangle]
pub unsafe extern "C" fn meow_site_of(
    host: *const std::ffi::c_char,
    out: *mut std::ffi::c_char,
    cap: usize,
) -> isize {
    if host.is_null() || out.is_null() {
        return -1;
    }
    // SAFETY: the caller passes a NUL-terminated string.
    let Ok(h) = unsafe { std::ffi::CStr::from_ptr(host) }.to_str() else {
        return -1;
    };
    let site = meow_proxy::group::smart::stats::site_of_host(h);
    let bytes = site.as_bytes();
    if bytes.len() + 1 > cap {
        return -1;
    }
    // SAFETY: `out` holds `cap` > len bytes; the regions do not overlap.
    unsafe {
        std::ptr::copy_nonoverlapping(bytes.as_ptr(), out.cast::<u8>(), bytes.len());
        *out.add(bytes.len()) = 0;
    }
    isize::try_from(bytes.len()).unwrap_or(-1)
}

#[cfg(test)]
mod site_tests {
    use std::ffi::{CStr, CString};

    #[test]
    fn site_through_the_c_abi() {
        let host = CString::new("api.weiba.pp.ua").unwrap();
        let mut buf = [0 as std::ffi::c_char; 64];
        let n = unsafe { super::meow_site_of(host.as_ptr(), buf.as_mut_ptr(), buf.len()) };
        assert_eq!(n, 11);
        let got = unsafe { CStr::from_ptr(buf.as_ptr()) };
        assert_eq!(got.to_str().unwrap(), "weiba.pp.ua");
        let mut small = [0 as std::ffi::c_char; 4];
        let n = unsafe { super::meow_site_of(host.as_ptr(), small.as_mut_ptr(), small.len()) };
        assert_eq!(n, -1);
    }
}

/// Starts the core on its own thread; the error when it fails at once.
pub fn start(home: String, config: String, fd: i32) -> Option<String> {
    if meow_app::embed::running() {
        meow_app::embed::stop();
        // Give the previous run a moment to release the TUN and ports.
        for _ in 0..50 {
            if !meow_app::embed::running() {
                break;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
    }
    let (tx, rx) = mpsc::channel();
    let spawned = std::thread::Builder::new()
        .name("meow-core".into())
        .spawn(move || {
            let r = meow_app::embed::run(&home, &config, fd);
            let _ = tx.send(r);
        });
    if let Err(e) = spawned {
        return Some(format!("core thread: {e}"));
    }
    // A bad config ends the run at once; a healthy core keeps running.
    match rx.recv_timeout(Duration::from_millis(1500)) {
        Ok(Err(e)) => Some(format!("{e:#}")),
        Ok(Ok(())) => Some("the core stopped right away".into()),
        Err(_) => None,
    }
}

pub fn stop() {
    meow_app::embed::stop();
}

pub fn running() -> bool {
    meow_app::embed::running()
}

#[cfg(target_os = "android")]
mod android {
    use std::os::fd::RawFd;
    use std::sync::Arc;

    use jni::objects::{GlobalRef, JClass, JObject, JString, JValue};
    use jni::sys::{jboolean, jint, jstring, JNI_FALSE, JNI_TRUE};
    use jni::{JNIEnv, JavaVM};

    /// `VpnService.protect(fd)` through JNI, from any core thread.
    struct VpnProtector {
        vm: JavaVM,
        service: GlobalRef,
    }

    impl meow_common::SocketProtector for VpnProtector {
        fn protect(&self, fd: RawFd) -> std::io::Result<()> {
            let mut env = self
                .vm
                .attach_current_thread_permanently()
                .map_err(|e| std::io::Error::other(format!("jni attach: {e}")))?;
            let ok = env
                .call_method(self.service.as_obj(), "protect", "(I)Z", &[JValue::Int(fd)])
                .and_then(|v| v.z())
                .map_err(|e| std::io::Error::other(format!("protect: {e}")))?;
            if ok {
                Ok(())
            } else {
                Err(std::io::Error::other(
                    "VpnService.protect refused the socket",
                ))
            }
        }
    }

    fn text(env: &mut JNIEnv<'_>, s: &JString<'_>) -> String {
        env.get_string(s).map(Into::into).unwrap_or_default()
    }

    #[no_mangle]
    pub extern "system" fn Java_app_paopao_proxy_MeowCore_start<'l>(
        mut env: JNIEnv<'l>,
        _class: JClass<'l>,
        config: JString<'l>,
        home: JString<'l>,
        fd: jint,
        service: JObject<'l>,
    ) -> jstring {
        let config = text(&mut env, &config);
        let home = text(&mut env, &home);
        if !service.is_null() {
            match (env.get_java_vm(), env.new_global_ref(&service)) {
                (Ok(vm), Ok(service)) => {
                    meow_common::set_socket_protector(std::sync::Arc::new(VpnProtector {
                        vm,
                        service,
                    })
                        as Arc<dyn meow_common::SocketProtector>)
                }
                _ => {
                    return env
                        .new_string("cannot reach the VPN service")
                        .map_or(std::ptr::null_mut(), |s| s.into_raw())
                }
            }
        }
        match super::start(home, config, fd) {
            None => std::ptr::null_mut(),
            Some(e) => env
                .new_string(e)
                .map_or(std::ptr::null_mut(), |s| s.into_raw()),
        }
    }

    #[no_mangle]
    pub extern "system" fn Java_app_paopao_proxy_MeowCore_stop<'l>(
        _env: JNIEnv<'l>,
        _class: JClass<'l>,
    ) {
        super::stop();
        meow_common::clear_socket_protector();
    }

    #[no_mangle]
    pub extern "system" fn Java_app_paopao_proxy_MeowCore_running<'l>(
        _env: JNIEnv<'l>,
        _class: JClass<'l>,
    ) -> jboolean {
        if super::running() {
            JNI_TRUE
        } else {
            JNI_FALSE
        }
    }
}
