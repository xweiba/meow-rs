//! The desktop parts of the manager (feature `desktop`): what the tray
//! program (paopao-tray; PaoPao Menu through `meow-manager-ffi`) embeds.
//!
//! - [`DesktopCore`]: the core as the user's child process (`meow -f
//!   <data>/meow/config.yaml -d <data>/meow`, its pid in `core.pid` as the
//!   app's MeowCore writes it); with 虚拟网卡 on macOS the privileged
//!   helper's core instead (`meow service`, root, `/var/run/paopao-core.sock`:
//!   its config in `<data>/core-service`). One runs at a time.
//! - [`ChildBuilder`]: `meow paopao apply`, the child the core's own API
//!   runs: the stored input changed, the config rebuilt.
//! - [`SysCommands`]: OS commands (no console window on Windows).
//! - [`Embedded`]: the manager, its API on 127.0.0.1 (token file
//!   `<data>/manager-api.json`) and its watch, on a thread of their own.

use serde_json::{json, Map, Value};
use std::io::{Read as _, Write as _};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::login::{Launch, OsLogin};
use crate::manager::{Builder, Core, Failure, Manager, Parts, Run};
use crate::proxy::{Commands, Os, SystemProxy};

/// The privileged helper's socket (macOS).
pub const HELPER_SOCKET: &str = "/var/run/paopao-core.sock";

/// The manager's API: where it listens (`{port, token, pid}`).
pub fn token_file(data: &Path) -> PathBuf {
    data.join("manager-api.json")
}

pub struct SysCommands;

impl Commands for SysCommands {
    fn out(&self, exe: &str, args: &[&str]) -> Option<String> {
        let mut c = Command::new(exe);
        c.args(args).stdin(Stdio::null()).stderr(Stdio::null());
        #[cfg(windows)]
        {
            use std::os::windows::process::CommandExt as _;
            c.creation_flags(0x0800_0000); // CREATE_NO_WINDOW
        }
        let out = c.output().ok()?;
        out.status
            .success()
            .then(|| String::from_utf8_lossy(&out.stdout).trim().to_owned())
    }
}

/// One JSON line to the privileged helper, its reply.
pub struct HelperClient {
    pub socket: PathBuf,
}

impl HelperClient {
    #[cfg(unix)]
    pub fn call(&self, req: &Value, timeout: Duration) -> Option<Value> {
        use std::io::{BufRead as _, BufReader};
        use std::os::unix::net::UnixStream;
        let mut s = UnixStream::connect(&self.socket).ok()?;
        s.set_read_timeout(Some(timeout)).ok()?;
        writeln!(s, "{req}").ok()?;
        let mut line = String::new();
        BufReader::new(&s).read_line(&mut line).ok()?;
        serde_json::from_str(line.trim()).ok()
    }

    #[cfg(not(unix))]
    pub fn call(&self, _req: &Value, _timeout: Duration) -> Option<Value> {
        None
    }

    pub fn installed(&self) -> bool {
        self.socket.exists()
    }

    pub fn running(&self) -> bool {
        self.call(&json!({"op": "status"}), Duration::from_secs(2))
            .is_some_and(|v| v["running"] == true)
    }
}

pub struct DesktopCore {
    meow: PathBuf,
    data: PathBuf,
    helper: Option<HelperClient>,
    child: Option<Child>,
    /// A core of an earlier tray found running (its pid), not our child.
    adopted: Option<u32>,
    on_helper: bool,
}

impl DesktopCore {
    /// `helper`: the privileged helper's socket (macOS), used for 虚拟网卡.
    pub fn new(meow: PathBuf, data: PathBuf, helper: Option<PathBuf>) -> DesktopCore {
        let mut core = DesktopCore {
            meow,
            data,
            helper: helper.map(|socket| HelperClient { socket }),
            child: None,
            adopted: None,
            on_helper: false,
        };
        core.adopt();
        core
    }

    fn user_run(&self) -> Run {
        let dir = self.data.join("meow");
        Run {
            config: dir.join("config.yaml"),
            dir,
        }
    }

    fn helper_run(&self) -> Run {
        let dir = self.data.join("core-service");
        Run {
            config: dir.join("config.json"),
            dir,
        }
    }

    /// A core left running by an earlier run of the tray (it crashed, was
    /// updated): taken on as it runs (no gap), not started again.
    fn adopt(&mut self) {
        if self.helper.as_ref().is_some_and(HelperClient::running) {
            self.on_helper = true;
            return;
        }
        let pid_file = self.user_run().dir.join("core.pid");
        let pid = std::fs::read_to_string(&pid_file)
            .ok()
            .and_then(|t| t.trim().parse::<u32>().ok());
        if let Some(pid) = pid.filter(|&p| is_core(p, &self.meow)) {
            self.adopted = Some(pid);
        }
    }

    fn stop_child(&mut self) {
        if let Some(mut c) = self.child.take() {
            terminate(c.id());
            let deadline = Instant::now() + Duration::from_secs(5);
            while Instant::now() < deadline && matches!(c.try_wait(), Ok(None)) {
                std::thread::sleep(Duration::from_millis(50));
            }
            let _ = c.kill();
            let _ = c.wait();
        }
        if let Some(pid) = self.adopted.take() {
            terminate(pid);
            let deadline = Instant::now() + Duration::from_secs(5);
            while Instant::now() < deadline && alive(pid) {
                std::thread::sleep(Duration::from_millis(50));
            }
            if alive(pid) {
                kill(pid);
            }
        }
        let _ = std::fs::remove_file(self.user_run().dir.join("core.pid"));
    }

    fn stop_helper(&mut self) {
        if self.on_helper {
            if let Some(h) = &self.helper {
                h.call(&json!({"op": "stop"}), Duration::from_secs(15));
            }
            self.on_helper = false;
        }
    }

    fn start_child(&mut self, run: &Run) -> Result<(), Failure> {
        let log_path = run.dir.join("core.log");
        std::fs::create_dir_all(&run.dir).map_err(|e| Failure::new(e.to_string()))?;
        let log = std::fs::File::create(&log_path)
            .map_err(|e| Failure::new(format!("{}: {e}", log_path.display())))?;
        let err = log.try_clone().ok();
        let mut c = Command::new(&self.meow);
        c.arg("-f")
            .arg(&run.config)
            .arg("-d")
            .arg(&run.dir)
            .stdin(Stdio::null())
            .stdout(log)
            .stderr(err.map_or_else(Stdio::null, Stdio::from));
        if let Some(dir) = self.meow.parent() {
            c.current_dir(dir);
        }
        #[cfg(windows)]
        {
            use std::os::windows::process::CommandExt as _;
            c.creation_flags(0x0800_0000);
        }
        let mut child = c
            .spawn()
            .map_err(|e| Failure::new(format!("{}: {e}", self.meow.display())))?;
        // A config the core refuses ends it at once: said with its log.
        std::thread::sleep(Duration::from_millis(600));
        if let Ok(Some(status)) = child.try_wait() {
            return Err(Failure {
                error: format!("core exited ({status})"),
                log: Some(log_tail(&log_path)),
            });
        }
        let _ = std::fs::write(run.dir.join("core.pid"), child.id().to_string());
        self.child = Some(child);
        Ok(())
    }
}

impl Core for DesktopCore {
    fn start(&mut self, run: &Run) -> Result<(), Failure> {
        // Only the key needed, streamed: the config with its lines is MBs
        // (whole, as a Value, many times that for a moment).
        let tun = Manager::read_keys(&run.config)
            .get("tun")
            .is_some_and(|t| t["enable"] == true);
        let helper = tun && self.helper.as_ref().is_some_and(HelperClient::installed);
        // One core at a time: the other one goes first.
        self.stop_child();
        self.stop_helper();
        if !helper {
            return self.start_child(run);
        }
        let Some(h) = &self.helper else {
            unreachable!()
        };
        let reply = h.call(
            // The app's own core: a helper of version 2 runs it once its
            // signature checks out (older ones run their own copy).
            &json!({"op": "start", "config": run.config, "dir": run.dir, "core": self.meow}),
            Duration::from_secs(30),
        );
        match reply {
            Some(v) if v["ok"] == true => {
                self.on_helper = true;
                Ok(())
            }
            Some(v) => Err(Failure {
                error: v["error"]
                    .as_str()
                    .unwrap_or("the core did not start")
                    .to_owned(),
                log: v["log"].as_str().map(str::to_owned),
            }),
            None => Err(Failure::new("no answer from the privileged helper")),
        }
    }

    fn stop(&mut self) {
        self.stop_child();
        self.stop_helper();
    }

    fn running(&mut self) -> bool {
        if let Some(c) = &mut self.child {
            if matches!(c.try_wait(), Ok(None)) {
                return true;
            }
            self.child = None;
        }
        if let Some(pid) = self.adopted {
            if alive(pid) {
                return true;
            }
            self.adopted = None;
        }
        self.on_helper && self.helper.as_ref().is_some_and(HelperClient::running)
    }

    fn place(&self, tun: bool) -> Option<Run> {
        let helper = self.helper.as_ref().is_some_and(HelperClient::installed);
        Some(if tun && helper {
            self.helper_run()
        } else {
            self.user_run()
        })
    }
}

/// The last lines of the core's log, colours dropped.
fn log_tail(path: &Path) -> String {
    let mut text = String::new();
    let _ = std::fs::File::open(path).and_then(|mut f| f.read_to_string(&mut text));
    let mut clean = String::with_capacity(text.len());
    let mut chars = text.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\u{1b}' && chars.peek() == Some(&'[') {
            for d in chars.by_ref() {
                if d.is_ascii_alphabetic() {
                    break;
                }
            }
        } else {
            clean.push(c);
        }
    }
    let lines: Vec<&str> = clean.lines().collect();
    lines[lines.len().saturating_sub(8)..].join("\n")
}

#[cfg(unix)]
fn terminate(pid: u32) {
    if let Ok(pid) = i32::try_from(pid) {
        // SAFETY: kill(2) with a pid we started or checked.
        unsafe { libc::kill(pid, libc::SIGTERM) };
    }
}

#[cfg(unix)]
fn kill(pid: u32) {
    if let Ok(pid) = i32::try_from(pid) {
        // SAFETY: as above.
        unsafe { libc::kill(pid, libc::SIGKILL) };
    }
}

#[cfg(unix)]
fn alive(pid: u32) -> bool {
    // SAFETY: signal 0 only checks.
    i32::try_from(pid).is_ok_and(|p| unsafe { libc::kill(p, 0) } == 0)
}

#[cfg(windows)]
fn terminate(pid: u32) {
    let _ = SysCommands.out("taskkill", &["/PID", &pid.to_string()]);
}

#[cfg(windows)]
fn kill(pid: u32) {
    let _ = SysCommands.out("taskkill", &["/F", "/PID", &pid.to_string()]);
}

#[cfg(windows)]
fn alive(pid: u32) -> bool {
    SysCommands
        .out(
            "tasklist",
            &["/FI", &format!("PID eq {pid}"), "/FO", "CSV", "/NH"],
        )
        .is_some_and(|o| o.contains(&format!("\"{pid}\"")))
}

/// Whether `pid` runs the core (`meow`), not another program given the
/// same pid since.
fn is_core(pid: u32, meow: &Path) -> bool {
    if !alive(pid) {
        return false;
    }
    #[cfg(target_os = "linux")]
    {
        let exe = std::fs::read_link(format!("/proc/{pid}/exe")).ok();
        exe.is_some_and(|e| {
            e == meow
                || e.file_name()
                    .is_some_and(|n| n.to_string_lossy().starts_with("meow"))
        })
    }
    #[cfg(target_os = "macos")]
    {
        let _ = meow;
        SysCommands
            .out("/bin/ps", &["-o", "comm=", "-p", &pid.to_string()])
            .is_some_and(|c| c == "meow" || c.ends_with("/meow"))
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let _ = meow;
        false
    }
}

/// 虚拟网卡 can be had: macOS with the helper installed and answering;
/// Linux when the core binary has its capabilities (or this is root).
pub fn can_tun(meow: &Path, helper: Option<&Path>) -> bool {
    if cfg!(target_os = "macos") {
        return helper.is_some_and(|s| {
            HelperClient {
                socket: s.to_owned(),
            }
            .call(&json!({"op": "status"}), Duration::from_secs(1))
            .is_some_and(|v| v["ok"] == true)
        });
    }
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::ffi::OsStrExt as _;
        // SAFETY: geteuid(2) has no preconditions.
        if unsafe { libc::geteuid() } == 0 {
            return true;
        }
        let Ok(path) = std::ffi::CString::new(meow.as_os_str().as_bytes()) else {
            return false;
        };
        let name = c"security.capability";
        // SAFETY: a size query (null buffer, 0 length) on valid C strings.
        let n = unsafe { libc::getxattr(path.as_ptr(), name.as_ptr(), std::ptr::null_mut(), 0) };
        n > 0
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = meow;
        false
    }
}

/// `meow paopao apply` as a child: what it allocates is given back as it
/// exits.
pub struct ChildBuilder {
    pub meow: PathBuf,
}

impl Builder for ChildBuilder {
    fn apply(
        &self,
        store: &Path,
        config: &Path,
        settings: &Map<String, Value>,
        build: bool,
        keep: &Map<String, Value>,
    ) -> Result<Option<PathBuf>, String> {
        if !store.join("input.json").exists() {
            return Err("no build input kept yet".into());
        }
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| i64::try_from(d.as_millis()).unwrap_or(i64::MAX));
        let req = json!({
            "dir": store,
            "settings": settings,
            "config": config,
            "now": now,
            "build": build,
            "keep": keep,
        });
        let mut c = Command::new(&self.meow);
        c.args(["paopao", "apply"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null());
        #[cfg(windows)]
        {
            use std::os::windows::process::CommandExt as _;
            c.creation_flags(0x0800_0000);
        }
        let mut child = c
            .spawn()
            .map_err(|e| format!("{}: {e}", self.meow.display()))?;
        if let Some(mut stdin) = child.stdin.take() {
            stdin
                .write_all(req.to_string().as_bytes())
                .map_err(|e| e.to_string())?;
        }
        let out = child.wait_with_output().map_err(|e| e.to_string())?;
        let v: Value = serde_json::from_slice(&out.stdout).unwrap_or(Value::Null);
        if !out.status.success() {
            return Err(v["error"].as_str().map_or_else(
                || format!("the rebuild failed ({})", out.status),
                str::to_owned,
            ));
        }
        Ok((v["next"] == true).then(|| store.join("config.next.yaml")))
    }
}

/// What the embedded manager needs.
pub struct Options {
    /// The app's data directory.
    pub data: PathBuf,
    /// The core binary.
    pub meow: PathBuf,
    /// What starts at login (the tray itself, its arguments).
    pub launch: Launch,
    /// The privileged helper's socket (macOS: [`HELPER_SOCKET`]).
    pub helper: Option<PathBuf>,
}

/// The manager made of the desktop parts.
pub fn desktop_manager(o: &Options) -> Manager {
    let run: Arc<dyn Commands> = Arc::new(SysCommands);
    let env = |k: &str| {
        std::env::var_os(k)
            .filter(|v| !v.is_empty())
            .map(PathBuf::from)
    };
    let home = env("HOME")
        .or_else(|| env("USERPROFILE"))
        .unwrap_or_else(|| ".".into());
    let kde5 = std::env::var("KDE_SESSION_VERSION").is_ok_and(|v| v == "5");
    let (meow, helper) = (o.meow.clone(), o.helper.clone());
    Manager::new(
        Some(o.data.join("manager.json")),
        Parts {
            core: Box::new(DesktopCore::new(
                o.meow.clone(),
                o.data.clone(),
                o.helper.clone(),
            )),
            builder: Box::new(ChildBuilder {
                meow: o.meow.clone(),
            }),
            // The app's own state file: either side puts back what the
            // other saved.
            proxy: Box::new(SystemProxy::new(
                o.data.join("system-proxy.json"),
                Os::current(),
                Arc::clone(&run),
                kde5,
            )),
            login: Box::new(OsLogin::new(
                Os::current(),
                o.launch.clone(),
                home,
                env("XDG_CONFIG_HOME"),
                run,
            )),
            can_tun: Box::new(move || can_tun(&meow, helper.as_deref())),
        },
    )
}

/// The manager running inside the tray program: its API and its watch on
/// a thread of their own.
pub struct Embedded {
    manager: crate::http::Shared,
    stop: Option<tokio::sync::oneshot::Sender<()>>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl Embedded {
    /// `manager` booted ([`Manager::boot`]: 开机自启's core up), its API
    /// listening on 127.0.0.1 with its token file in `data`.
    pub fn start(manager: Manager, data: &Path) -> std::io::Result<Embedded> {
        let shared: crate::http::Shared = Arc::new(Mutex::new(manager));
        let (tx, rx) = tokio::sync::oneshot::channel::<()>();
        let (ready_tx, ready_rx) = std::sync::mpsc::channel::<std::io::Result<()>>();
        let m = Arc::clone(&shared);
        let file = token_file(data);
        let thread = std::thread::Builder::new()
            .name("manager".into())
            .spawn(move || {
                // One thread for the API, one for the manager's work (each
                // request takes the manager's lock in turn anyway): no
                // thread per request piling up behind a slow start, no
                // allocator arena per thread.
                let rt = match tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .max_blocking_threads(1)
                    .thread_keep_alive(Duration::from_secs(60))
                    .build()
                {
                    Ok(rt) => rt,
                    Err(e) => {
                        let _ = ready_tx.send(Err(e));
                        return;
                    }
                };
                rt.block_on(async move {
                    let listener = match tokio::net::TcpListener::bind(("127.0.0.1", 0)).await {
                        Ok(l) => l,
                        Err(e) => {
                            let _ = ready_tx.send(Err(e));
                            return;
                        }
                    };
                    let token = crate::http::new_token();
                    let port = listener.local_addr().map(|a| a.port()).unwrap_or(0);
                    if let Err(e) = crate::http::write_token_file(&file, port, &token) {
                        let _ = ready_tx.send(Err(e));
                        return;
                    }
                    let _ = ready_tx.send(Ok(()));
                    let watch = Arc::clone(&m);
                    tokio::spawn(async move {
                        loop {
                            tokio::time::sleep(Duration::from_secs(2)).await;
                            let w = Arc::clone(&watch);
                            let _ = tokio::task::spawn_blocking(move || {
                                w.lock()
                                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                                    .watch();
                            })
                            .await;
                        }
                    });
                    let app = crate::http::router(m, &token);
                    let _ = axum::serve(listener, app)
                        .with_graceful_shutdown(async {
                            let _ = rx.await;
                        })
                        .await;
                    crate::http::forget_token_file(&file);
                });
            })?;
        match ready_rx.recv() {
            Ok(Ok(())) => {}
            Ok(Err(e)) => return Err(e),
            Err(_) => return Err(std::io::Error::other("the manager's thread ended")),
        }
        // The core of 开机自启 (and a leftover proxy put back) once the API
        // is there: a client asking meanwhile waits for it.
        let boot = Arc::clone(&shared);
        std::thread::spawn(move || {
            boot.lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .boot();
        });
        Ok(Embedded {
            manager: shared,
            stop: Some(tx),
            thread: Some(thread),
        })
    }

    pub fn manager(&self) -> &crate::http::Shared {
        &self.manager
    }

    /// The API closed; `quit`: 退出 (the core stopped, 内核 off) — else the
    /// program ends otherwise (logout: the switches stay for next time).
    pub fn shutdown(mut self, quit: bool) {
        if let Some(tx) = self.stop.take() {
            let _ = tx.send(());
        }
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
        let mut m = self
            .manager
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if quit {
            m.stop();
        } else {
            m.shutdown();
        }
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    /// A stand-in core: a shell script that writes its arguments and waits
    /// (or exits at once when the config says so).
    fn fake_meow(dir: &Path) -> PathBuf {
        use std::os::unix::fs::PermissionsExt as _;
        let p = dir.join("meow");
        std::fs::write(
            &p,
            "#!/bin/sh\nif [ \"$1\" = paopao ]; then cat > \"$(dirname \"$0\")/apply.json\"; \
echo '{\"next\":true}'; exit 0; fi\n\
grep -q refuse \"$2\" && { echo 'bad config' >&2; exit 3; }\n\
echo \"$@\" > \"$4/args\"; exec \"$(dirname \"$0\")/meow-sleep\" 30\n",
        )
        .unwrap();
        // As the core shows in the process list.
        std::fs::copy("/bin/sleep", dir.join("meow-sleep")).unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
        p
    }

    #[test]
    fn the_user_core_as_a_child() {
        let d = tempfile::tempdir().unwrap();
        let meow = fake_meow(d.path());
        let data = d.path().join("data");
        let mut core = DesktopCore::new(meow.clone(), data.clone(), None);
        let run = core.place(true).unwrap();
        // No helper: 虚拟网卡 or not, the user's core.
        assert!(run.config.ends_with("meow/config.yaml"));
        std::fs::create_dir_all(&run.dir).unwrap();
        std::fs::write(&run.config, "{}").unwrap();
        core.start(&run).unwrap();
        assert!(core.running());
        let pid: u32 = std::fs::read_to_string(run.dir.join("core.pid"))
            .unwrap()
            .trim()
            .parse()
            .unwrap();
        // A tray started again takes it on as it runs.
        let mut again = DesktopCore::new(meow.clone(), data.clone(), None);
        assert_eq!(again.adopted, Some(pid));
        assert!(again.running());
        again.stop();
        assert!(!core.running());
        assert!(!run.dir.join("core.pid").exists());
        // Refused: why, with its log.
        std::fs::write(&run.config, "refuse").unwrap();
        let f = core.start(&run).unwrap_err();
        assert!(f.log.unwrap().contains("bad config"), "{}", f.error);
    }

    #[test]
    fn the_builder_child() {
        let d = tempfile::tempdir().unwrap();
        let meow = fake_meow(d.path());
        let store = d.path().join("paopao");
        let b = ChildBuilder { meow: meow.clone() };
        let mut settings = Map::new();
        settings.insert("tun".into(), true.into());
        assert!(b
            .apply(&store, Path::new("/c"), &settings, true, &Map::new())
            .is_err());
        std::fs::create_dir_all(&store).unwrap();
        std::fs::write(store.join("input.json"), "{}").unwrap();
        let next = b
            .apply(&store, Path::new("/c"), &settings, true, &Map::new())
            .unwrap();
        assert_eq!(next, Some(store.join("config.next.yaml")));
        let req: Value =
            serde_json::from_slice(&std::fs::read(d.path().join("apply.json")).unwrap()).unwrap();
        assert_eq!(req["settings"]["tun"], true);
        assert_eq!(req["build"], true);
        assert_eq!(req["config"], "/c");
    }

    #[test]
    fn embedded_serves_and_shuts_down() {
        let d = tempfile::tempdir().unwrap();
        let meow = fake_meow(d.path());
        let data = d.path().join("data");
        let m = desktop_manager(&Options {
            data: data.clone(),
            meow,
            launch: Launch {
                program: "/t".into(),
                args: vec![],
            },
            helper: None,
        });
        let e = Embedded::start(m, &data).unwrap();
        let v: Value = serde_json::from_slice(&std::fs::read(token_file(&data)).unwrap()).unwrap();
        let port = v["port"].as_u64().unwrap();
        let token = v["token"].as_str().unwrap().to_owned();
        let mut s =
            std::net::TcpStream::connect(("127.0.0.1", u16::try_from(port).unwrap())).unwrap();
        write!(
            s,
            "GET /manager/status HTTP/1.1\r\nhost: x\r\nauthorization: Bearer {token}\r\nconnection: close\r\n\r\n"
        )
        .unwrap();
        let mut reply = String::new();
        s.read_to_string(&mut reply).unwrap();
        assert!(reply.starts_with("HTTP/1.1 200"), "{reply}");
        assert!(reply.contains("\"manager\":1"));
        e.shutdown(true);
        assert!(!token_file(&data).exists());
    }
}
