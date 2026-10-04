//! meow-rs for phone apps.
//!
//! Android: `app.paopao.proxy.MeowCore` (Kotlin) calls
//! - `start(config, home, fd, vpnService)`: runs the core on a thread of its
//!   own over the VPN's TUN fd; every socket the core opens goes through
//!   `vpnService.protect(fd)` first so it bypasses the VPN. Returns null
//!   when the core came up, else the reason.
//! - `stop()`, `running()`.

use std::sync::mpsc;
use std::time::Duration;

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
                Err(std::io::Error::other("VpnService.protect refused the socket"))
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
                (Ok(vm), Ok(service)) => meow_common::set_socket_protector(std::sync::Arc::new(
                    VpnProtector { vm, service },
                )
                    as Arc<dyn meow_common::SocketProtector>),
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
