//! meow-rs for phone apps.
//!
//! Android: `app.paopao.proxy.MeowCore` (Kotlin) calls
//! - `start(config, home, fd, vpnService)`: runs the core on a thread of its
//!   own over the VPN's TUN fd; every socket the core opens goes through
//!   `vpnService.protect(fd)` first so it bypasses the VPN. Returns null
//!   when the core came up, else the reason. The same service answers
//!   which app owns a connection (`ownerUid` / `packageOf`, Android 10+),
//!   so `PROCESS-NAME,<package>` rules work.
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
    use std::net::SocketAddr;
    use std::os::fd::RawFd;
    use std::sync::Arc;

    use jni::objects::{GlobalRef, JClass, JMethodID, JObject, JString, JValue};
    use jni::signature::{Primitive, ReturnType};
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

    /// Which app owns a connection, asked from the VPN service (Kotlin
    /// `PaoPaoVpnService.ownerUid` / `packageOf`) on the core's
    /// blocking-pool threads. Method IDs are looked up once at start; any
    /// Java exception or JNI failure counts as "unknown".
    struct VpnAppOwners {
        vm: JavaVM,
        service: GlobalRef,
        owner_uid: JMethodID,
        package_of: JMethodID,
    }

    impl VpnAppOwners {
        fn new(env: &mut JNIEnv<'_>, vm: JavaVM, service: GlobalRef) -> Option<Self> {
            let class = env.get_object_class(service.as_obj()).ok()?;
            let class = env.auto_local(class);
            let owner_uid = env.get_method_id(
                &*class,
                "ownerUid",
                "(ILjava/lang/String;ILjava/lang/String;I)I",
            );
            let package_of = env.get_method_id(&*class, "packageOf", "(I)Ljava/lang/String;");
            match (owner_uid, package_of) {
                (Ok(owner_uid), Ok(package_of)) => Some(Self {
                    vm,
                    service,
                    owner_uid,
                    package_of,
                }),
                _ => {
                    // An older service without the methods: no lookup.
                    let _ = env.exception_clear();
                    None
                }
            }
        }

        /// Runs `f` on this thread's JVM env inside a local frame (core
        /// threads stay attached, so their local refs must not pile up);
        /// a pending exception is cleared and gives `None`.
        fn call<T>(&self, f: impl FnOnce(&mut JNIEnv<'_>) -> jni::errors::Result<T>) -> Option<T> {
            let mut env = self.vm.attach_current_thread_permanently().ok()?;
            let r = env.with_local_frame(8, |env| f(env));
            if env.exception_check().unwrap_or(true) {
                let _ = env.exception_clear();
                return None;
            }
            r.ok()
        }
    }

    impl meow_common::app_owner::AppOwnerLookup for VpnAppOwners {
        fn owner_uid(
            &self,
            network: meow_common::Network,
            local: SocketAddr,
            remote: SocketAddr,
        ) -> Option<u32> {
            // IPPROTO_TCP / IPPROTO_UDP, as `getConnectionOwnerUid` takes.
            let protocol = match network {
                meow_common::Network::Tcp => 6,
                meow_common::Network::Udp => 17,
            };
            let uid = self.call(|env| {
                let src = env.new_string(local.ip().to_string())?;
                let dst = env.new_string(remote.ip().to_string())?;
                let args = [
                    JValue::Int(protocol).as_jni(),
                    JValue::Object(&src).as_jni(),
                    JValue::Int(i32::from(local.port())).as_jni(),
                    JValue::Object(&dst).as_jni(),
                    JValue::Int(i32::from(remote.port())).as_jni(),
                ];
                // SAFETY: the method ID came from this object's class with
                // this exact signature; the args match it.
                unsafe {
                    env.call_method_unchecked(
                        self.service.as_obj(),
                        self.owner_uid,
                        ReturnType::Primitive(Primitive::Int),
                        &args,
                    )
                }?
                .i()
            })?;
            // -1 (Process.INVALID_UID): unknown.
            u32::try_from(uid).ok()
        }

        fn package_of(&self, uid: u32) -> Option<String> {
            let uid = i32::try_from(uid).ok()?;
            self.call(|env| {
                // SAFETY: as in `owner_uid`.
                let obj = unsafe {
                    env.call_method_unchecked(
                        self.service.as_obj(),
                        self.package_of,
                        ReturnType::Object,
                        &[JValue::Int(uid).as_jni()],
                    )
                }?
                .l()?;
                if obj.is_null() {
                    return Ok(None);
                }
                let s: String = env.get_string(&JString::from(obj))?.into();
                Ok(Some(s))
            })
            .flatten()
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
                    // A second VM handle and ref for the owner lookup.
                    match (env.get_java_vm(), env.new_global_ref(&service)) {
                        (Ok(owner_vm), Ok(owner_ref)) => {
                            match VpnAppOwners::new(&mut env, owner_vm, owner_ref) {
                                Some(o) => {
                                    meow_common::app_owner::set_app_owner_lookup(Arc::new(o))
                                }
                                None => meow_common::app_owner::clear_app_owner_lookup(),
                            }
                        }
                        _ => meow_common::app_owner::clear_app_owner_lookup(),
                    }
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
        meow_common::app_owner::clear_app_owner_lookup();
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
