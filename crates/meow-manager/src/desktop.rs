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

/// The privileged helper's socket (macOS) / named pipe (Windows: the
/// service `PaoPaoCore`, meow-app `helper::win`).
pub const HELPER_SOCKET: &str = if cfg!(windows) {
    r"\\.\pipe\paopao-core"
} else {
    "/var/run/paopao-core.sock"
};

/// The build a core runs, in its run directory: the digest (sha256, hex)
/// of the binary it was started from, written once it runs.
const BUILD_FILE: &str = "core.build";

/// The privileged helper's own copy of the app's core, which it runs
/// (refreshed at each start).
fn helper_core() -> Option<PathBuf> {
    if cfg!(target_os = "macos") {
        return Some("/Library/Application Support/PaoPao/core/meow".into());
    }
    if cfg!(windows) {
        let data = std::env::var_os("ProgramData")
            .filter(|v| !v.is_empty())
            .map_or_else(|| PathBuf::from(r"C:\ProgramData"), PathBuf::from);
        return Some(data.join("PaoPao").join("core").join("meow.exe"));
    }
    None
}

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
        s.set_write_timeout(Some(timeout)).ok()?;
        writeln!(s, "{req}").ok()?;
        let mut line = String::new();
        BufReader::new(&s).read_line(&mut line).ok()?;
        serde_json::from_str(line.trim()).ok()
    }

    /// Windows: the named pipe (one client at a time: a busy one waited
    /// for), the reply read on a thread of its own so a helper that hangs
    /// is given up after `timeout`.
    #[cfg(windows)]
    pub fn call(&self, req: &Value, timeout: Duration) -> Option<Value> {
        use std::io::{BufRead as _, BufReader};
        let deadline = Instant::now() + timeout;
        let file = loop {
            match std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open(&self.socket)
            {
                Ok(f) => break f,
                // ERROR_PIPE_BUSY
                Err(e) if e.raw_os_error() == Some(231) && Instant::now() < deadline => {
                    std::thread::sleep(Duration::from_millis(20));
                }
                Err(_) => return None,
            }
        };
        let line = format!("{req}\n");
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let mut f = file;
            if f.write_all(line.as_bytes()).is_err() {
                return;
            }
            let mut reply = String::new();
            if BufReader::new(&f).read_line(&mut reply).is_ok() {
                let _ = tx.send(reply);
            }
        });
        let reply = rx
            .recv_timeout(deadline.saturating_duration_since(Instant::now()))
            .ok()?;
        serde_json::from_str(reply.trim()).ok()
    }

    #[cfg(not(any(unix, windows)))]
    pub fn call(&self, _req: &Value, _timeout: Duration) -> Option<Value> {
        None
    }

    /// Whether there is a helper to ask: its socket is there (Windows: its
    /// pipe can be opened, or is busy answering another).
    #[cfg(not(windows))]
    pub fn installed(&self) -> bool {
        self.socket.exists()
    }

    #[cfg(windows)]
    pub fn installed(&self) -> bool {
        match std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&self.socket)
        {
            Ok(_) => true,
            Err(e) => e.raw_os_error() == Some(231),
        }
    }

    pub fn running(&self) -> bool {
        self.running_status() == Some(true)
    }

    /// A helper timeout is unknown, not proof that a running core exited.
    /// The panel opening can contend with a helper request on macOS.
    fn running_status(&self) -> Option<bool> {
        self.call(&json!({"op": "status"}), Duration::from_secs(2))?
            .get("running")?
            .as_bool()
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
    /// The running core's run directory (its [`BUILD_FILE`]).
    run_dir: Option<PathBuf>,
    /// This core may have returned fake IPs; flush once after confirmed
    /// exit, including a crash while the Flutter panel is absent.
    dns_cache_pending: bool,
    digests: Digests,
}

/// A binary's digest as last read, with the size and time it had then.
struct Seen {
    path: PathBuf,
    len: u64,
    modified: Option<std::time::SystemTime>,
    hex: String,
}

/// Digests of binaries (tens of MB), read again only when a file's size or
/// time changed.
#[derive(Default)]
struct Digests(Vec<Seen>);

impl Digests {
    fn of(&mut self, path: &Path) -> Option<String> {
        let meta = std::fs::metadata(path).ok()?;
        let (len, modified) = (meta.len(), meta.modified().ok());
        if let Some(d) = self.0.iter().find(|d| d.path == path) {
            if d.len == len && d.modified == modified {
                return Some(d.hex.clone());
            }
        }
        let hex = sha256_of(path)?;
        self.0.retain(|d| d.path != path);
        self.0.push(Seen {
            path: path.to_owned(),
            len,
            modified,
            hex: hex.clone(),
        });
        Some(hex)
    }
}

fn sha256_of(path: &Path) -> Option<String> {
    use sha2::{Digest as _, Sha256};
    let mut f = std::fs::File::open(path).ok()?;
    let mut h = Sha256::new();
    std::io::copy(&mut f, &mut h).ok()?;
    Some(format!("{:x}", h.finalize()))
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
            run_dir: None,
            dns_cache_pending: false,
            digests: Digests::default(),
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
        let helper_running = self.helper.as_ref().and_then(HelperClient::running_status);
        // The first helper query can fail too, before on_helper has ever
        // been set. Retain a previous TUN run provisionally until status
        // confirms exit; otherwise boot may replace a healthy service core.
        let helper_unresolved = helper_running.is_none()
            && self.helper.as_ref().is_some_and(HelperClient::installed)
            && Manager::read_keys(&self.helper_run().config)
                .get("tun")
                .is_some_and(|t| t["enable"] == true);
        if helper_running == Some(true) || helper_unresolved {
            self.on_helper = true;
            self.run_dir = Some(self.helper_run().dir);
            self.dns_cache_pending = true;
            return;
        }
        let pid_file = self.user_run().dir.join("core.pid");
        let pid = std::fs::read_to_string(&pid_file)
            .ok()
            .and_then(|t| t.trim().parse::<u32>().ok());
        if let Some(pid) = pid.filter(|&p| is_core(p, &self.meow)) {
            self.adopted = Some(pid);
            self.run_dir = Some(self.user_run().dir);
            self.dns_cache_pending = Manager::read_keys(&self.user_run().config)
                .get("tun")
                .is_some_and(|t| t["enable"] == true);
        }
    }

    /// The build of the core just started on `dir` noted there
    /// ([`BUILD_FILE`]).
    fn note_build(&mut self, dir: &Path) {
        let file = dir.join(BUILD_FILE);
        match self.digests.of(&self.meow) {
            Some(hex) => {
                let _ = std::fs::write(file, hex);
            }
            None => {
                let _ = std::fs::remove_file(file);
            }
        }
        self.run_dir = Some(dir.to_owned());
    }

    fn finish_dns_cleanup(&mut self) {
        if self.child.is_none()
            && self.adopted.is_none()
            && !self.on_helper
            && std::mem::take(&mut self.dns_cache_pending)
        {
            crate::dns_cache::flush_after_capture();
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
            if c.wait().is_err() {
                // Do not lose the process handle or flush on an
                // unconfirmed exit; a later stop/status can retry.
                self.child = Some(c);
            }
        }
        if let Some(pid) = self.adopted.take() {
            terminate(pid);
            let deadline = Instant::now() + Duration::from_secs(5);
            while Instant::now() < deadline && alive(pid) {
                std::thread::sleep(Duration::from_millis(50));
            }
            if alive(pid) {
                kill(pid);
                let deadline = Instant::now() + Duration::from_secs(2);
                while Instant::now() < deadline && alive(pid) {
                    std::thread::sleep(Duration::from_millis(20));
                }
                if alive(pid) {
                    // Keep ownership so stop/status can retry and never
                    // flush while this generation could still return fake IPs.
                    self.adopted = Some(pid);
                }
            }
        }
        if self.adopted.is_none() && self.child.is_none() {
            let _ = std::fs::remove_file(self.user_run().dir.join("core.pid"));
        }
    }

    fn stop_helper(&mut self) {
        if self.on_helper {
            if let Some(h) = &self.helper {
                let stopped = h.call(&json!({"op": "stop"}), Duration::from_secs(15));
                if !stopped.is_some_and(|v| v["ok"] == true || v["running"] == false)
                    && h.running_status() != Some(false)
                {
                    // A timeout does not establish that interception ended.
                    tracing::warn!("helper stop not confirmed; DNS cache cleanup remains pending");
                    return;
                }
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
        self.note_build(&run.dir);
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
        if self.on_helper || self.adopted.is_some() || self.child.is_some() {
            return Err(Failure::new("previous core has not confirmed shutdown"));
        }
        self.finish_dns_cleanup();
        self.run_dir = None;
        let _ = std::fs::remove_file(run.dir.join(BUILD_FILE));
        if !helper {
            let result = self.start_child(run);
            if result.is_ok() {
                self.dns_cache_pending = tun;
            }
            return result;
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
                self.dns_cache_pending = tun;
                // The helper runs its copy of `self.meow`, made at this start.
                self.note_build(&run.dir);
                Ok(())
            }
            Some(v) => Err(Failure {
                error: v["error"]
                    .as_str()
                    .unwrap_or("the core did not start")
                    .to_owned(),
                log: v["log"].as_str().map(str::to_owned),
            }),
            None => {
                // The request may have succeeded but its reply was lost.
                // Keep ownership so status/stop can reconcile it without
                // leaking a privileged TUN core after a startup timeout.
                self.on_helper = true;
                self.dns_cache_pending = tun;
                self.run_dir = Some(run.dir.clone());
                Err(Failure::new("no answer from the privileged helper"))
            }
        }
    }

    fn stop(&mut self) {
        self.stop_child();
        self.stop_helper();
        self.finish_dns_cleanup();
        if self.child.is_none() && self.adopted.is_none() && !self.on_helper {
            self.run_dir = None;
        }
    }

    /// The build noted at its start against `self.meow` now (an update of
    /// the app replaced it meanwhile: not the same). A core started by a
    /// tray that noted none: the helper's copy is what the helper runs;
    /// a user core's cannot be told.
    fn same_build(&mut self) -> Option<bool> {
        let dir = self.run_dir.clone()?;
        let mine = self.digests.of(&self.meow)?;
        let theirs = match std::fs::read_to_string(dir.join(BUILD_FILE)) {
            Ok(t) => t.trim().to_owned(),
            Err(_) if self.on_helper => self.digests.of(&helper_core()?)?,
            Err(_) => return None,
        };
        Some(theirs == mine)
    }

    fn running(&mut self) -> bool {
        if let Some(c) = &mut self.child {
            // Failure to inspect a child is not evidence of its exit.
            if !matches!(c.try_wait(), Ok(Some(_))) {
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
        if self.on_helper {
            match self.helper.as_ref().and_then(HelperClient::running_status) {
                Some(false) => self.on_helper = false,
                // A transient API failure must never be mistaken for exit.
                _ => return true,
            }
        }
        self.finish_dns_cleanup();
        false
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
    // A zombie retains its PID until its original parent reaps it, but
    // owns no sockets/routes and cannot answer DNS. Waiting for kill(0)
    // alone prevented an adopted core from ever completing shutdown.
    #[cfg(target_os = "linux")]
    if std::fs::read_to_string(format!("/proc/{pid}/stat"))
        .ok()
        .and_then(|s| {
            s.rsplit_once(") ")
                .and_then(|(_, tail)| tail.chars().next())
        })
        .is_some_and(|state| state == 'Z' || state == 'X')
    {
        return false;
    }
    #[cfg(target_os = "macos")]
    if SysCommands
        .out("/bin/ps", &["-o", "stat=", "-p", &pid.to_string()])
        .is_some_and(|s| s.starts_with('Z'))
    {
        return false;
    }
    // SAFETY: signal 0 only checks.
    i32::try_from(pid).is_ok_and(|p| {
        p > 1
            && (unsafe { libc::kill(p, 0) } == 0
                || std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM))
    })
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
    let output = SysCommands.out(
        "tasklist",
        &["/FI", &format!("PID eq {pid}"), "/FO", "CSV", "/NH"],
    );
    tasklist_alive(pid, output.as_deref())
}

/// A failed Windows process query is unknown, just like EPERM on Unix:
/// retain ownership and defer DNS cleanup until exit is confirmed.
#[cfg(any(windows, test))]
fn tasklist_alive(pid: u32, output: Option<&str>) -> bool {
    pid > 1 && output.is_none_or(|o| o.contains(&format!("\"{pid}\"")))
}

/// Whether `pid` runs the core (`meow`), not another program given the
/// same pid since.
fn is_core(pid: u32, meow: &Path) -> bool {
    if !alive(pid) {
        return false;
    }
    #[cfg(target_os = "linux")]
    {
        let proc = PathBuf::from(format!("/proc/{pid}"));
        match std::fs::read_link(proc.join("exe")) {
            Ok(e) => {
                e == meow
                    || e.file_name()
                        .is_some_and(|n| n.to_string_lossy().starts_with("meow"))
            }
            Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
                use std::os::unix::{ffi::OsStrExt as _, fs::MetadataExt as _};
                // File capabilities make the core non-dumpable, hiding exe
                // even from its user. Require that user plus the exact
                // launch path and kernel task name; a PID/name alone is
                // insufficient evidence for adopting or terminating it.
                // SAFETY: geteuid has no preconditions.
                let uid = unsafe { libc::geteuid() };
                let same_user = std::fs::metadata(&proc).is_ok_and(|m| m.uid() == uid);
                let argv = std::fs::read(proc.join("cmdline")).unwrap_or_default();
                let comm = std::fs::read(proc.join("comm")).unwrap_or_default();
                let name = meow.file_name().map(|n| n.as_bytes()).unwrap_or_default();
                same_user
                    && !name.is_empty()
                    && argv.split(|&c| c == 0).next() == Some(meow.as_os_str().as_bytes())
                    && comm.strip_suffix(b"\n").unwrap_or(&comm) == &name[..name.len().min(15)]
            }
            Err(_) => false,
        }
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

/// 虚拟网卡 can be had: macOS and Windows with the helper installed and
/// answering; Linux when the core binary has its capabilities (or this is
/// root).
pub fn can_tun(meow: &Path, helper: Option<&Path>) -> bool {
    if cfg!(any(target_os = "macos", windows)) {
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
            && meow
                .to_str()
                .is_some_and(|exe| SysCommands.ok(exe, &["network-permissions", "check"]))
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
    /// The privileged helper's socket (macOS, Windows: [`HELPER_SOCKET`]).
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

    #[test]
    fn windows_process_query_failure_is_not_a_confirmed_exit() {
        assert!(tasklist_alive(123, None));
        assert!(tasklist_alive(123, Some(r#""meow.exe","123","Console""#)));
        assert!(!tasklist_alive(123, Some(r#""meow.exe","1234","Console""#)));
        assert!(!tasklist_alive(123, Some("INFO: No tasks are running.")));
        assert!(!tasklist_alive(0, None));
        assert!(!tasklist_alive(1, None));
    }

    /// Serve only a local protocol fixture; never start a real helper,
    /// change resolver settings, or invalidate the host's DNS caches.
    fn helper_fixture(path: &Path, replies: &[&str]) -> std::thread::JoinHandle<Vec<Value>> {
        use std::os::unix::net::UnixListener;
        let listener = UnixListener::bind(path).unwrap();
        let replies: Vec<String> = replies.iter().map(|s| (*s).to_owned()).collect();
        std::thread::spawn(move || {
            let mut requests = Vec::new();
            for reply in replies {
                let (mut stream, _) = listener.accept().unwrap();
                let mut request = String::new();
                std::io::BufRead::read_line(&mut std::io::BufReader::new(&stream), &mut request)
                    .unwrap();
                requests.push(serde_json::from_str(&request).unwrap());
                if !reply.is_empty() {
                    writeln!(stream, "{reply}").unwrap();
                }
            }
            requests
        })
    }

    #[test]
    fn first_unknown_helper_reply_preserves_a_previous_tun_run() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("helper.sock");
        let run = dir.path().join("core-service");
        std::fs::create_dir(&run).unwrap();
        let config = br#"{"tun":{"enable":true}}"#;
        std::fs::write(run.join("config.json"), config).unwrap();
        let server = helper_fixture(
            &path,
            &[
                r#"{"error":"temporarily busy"}"#,
                r#"{"running":true}"#,
                r#"{"running":false}"#,
            ],
        );
        let mut core = DesktopCore::new(dir.path().join("meow"), dir.path().into(), Some(path));
        assert!(core.on_helper);
        assert_eq!(core.run_dir, Some(run.clone()));
        assert!(core.running());
        assert!(core.dns_cache_pending);
        // Cache commands have their own injected-command tests.
        core.dns_cache_pending = false;
        assert!(!core.running());
        assert_eq!(std::fs::read(run.join("config.json")).unwrap(), config);
        assert!(server.join().unwrap().iter().all(|r| r["op"] == "status"));
    }

    #[test]
    fn lost_start_reply_keeps_helper_ownership_until_stop_is_confirmed() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("helper.sock");
        let server = helper_fixture(
            &path,
            &[
                r#"{"running":false}"#,
                "", // Start was accepted, but the connection lost its reply.
                r#"{"error":"busy"}"#,
                r#"{"error":"busy"}"#,
                r#"{"ok":true}"#,
            ],
        );
        let mut core = DesktopCore::new(dir.path().join("meow"), dir.path().into(), Some(path));
        let run = core.place(true).unwrap();
        std::fs::create_dir_all(&run.dir).unwrap();
        let config = br#"{"tun":{"enable":true}}"#;
        std::fs::write(&run.config, config).unwrap();
        assert!(core.start(&run).is_err());
        assert!(core.on_helper);
        assert!(core.dns_cache_pending);
        core.stop();
        assert!(core.on_helper, "an unconfirmed stop retains ownership");
        assert!(core.dns_cache_pending);
        assert_eq!(core.run_dir, Some(run.dir.clone()));
        core.dns_cache_pending = false;
        core.stop();
        assert!(!core.on_helper);
        assert!(core.run_dir.is_none());
        assert_eq!(std::fs::read(&run.config).unwrap(), config);
        let requests = server.join().unwrap();
        assert_eq!(
            requests
                .iter()
                .map(|r| r["op"].as_str().unwrap())
                .collect::<Vec<_>>(),
            ["status", "start", "stop", "status", "stop"]
        );
    }

    #[test]
    fn helper_unknown_status_keeps_the_confirmed_core_running() {
        use std::os::unix::net::UnixListener;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("helper.sock");
        let listener = UnixListener::bind(&path).unwrap();
        let server = std::thread::spawn(move || {
            for reply in ["{\"error\":\"temporarily busy\"}", "{\"running\":false}"] {
                let (mut stream, _) = listener.accept().unwrap();
                let mut request = String::new();
                std::io::BufRead::read_line(&mut std::io::BufReader::new(&stream), &mut request)
                    .unwrap();
                writeln!(stream, "{reply}").unwrap();
            }
        });
        let mut core = DesktopCore::new(dir.path().join("meow"), dir.path().to_owned(), None);
        core.helper = Some(HelperClient { socket: path });
        core.on_helper = true;
        assert!(core.running(), "an unknown helper reply is not a crash");
        assert!(!core.running(), "a confirmed exit must still be reported");
        server.join().unwrap();
    }

    /// A stand-in core: a shell script that writes its arguments and waits
    /// (or exits at once when the config says so).
    fn fake_meow(dir: &Path) -> PathBuf {
        use std::os::unix::fs::PermissionsExt as _;
        let p = dir.join("meow");
        let exec = if cfg!(target_os = "macos") {
            "exec \"$(dirname \"$0\")/fixture-core/meow\" \"$@\""
        } else {
            "exec \"$(dirname \"$0\")/meow-sleep\" 30"
        };
        std::fs::write(
            &p,
            [
                "#!/bin/sh\nif [ \"$1\" = paopao ]; then cat > \"$(dirname \"$0\")/apply.json\"; \
echo '{\"next\":true}'; exit 0; fi\n\
grep -q refuse \"$2\" && { echo 'bad config' >&2; exit 3; }\n\
echo \"$@\" > \"$4/args\"; ",
                exec,
                "\n",
            ]
            .concat(),
        )
        .unwrap();
        // As the core shows in the process list.
        #[cfg(not(target_os = "macos"))]
        std::fs::copy("/bin/sleep", dir.join("meow-sleep")).unwrap();
        #[cfg(target_os = "macos")]
        {
            // macOS adoption requires an actual executable named meow.
            // Keep the script for builder/digest tests, but exec an owned
            // binary with the real -f/-d arguments, not a renamed sleep.
            let child_dir = dir.join("fixture-core");
            std::fs::create_dir(&child_dir).unwrap();
            let child = child_dir.join("meow");
            let source = child_dir.join("meow.c");
            std::fs::write(
                &source,
                "#include <unistd.h>\n#include <string.h>\n#include <stdio.h>\n\
                 int main(int argc, char **argv) {\n\
                 if (argc != 5 || strcmp(argv[1], \"-f\") || strcmp(argv[3], \"-d\")) return 64;\n\
                 char marker[4096];\n\
                 int n = snprintf(marker, sizeof(marker), \"%s/fixture.ready\", argv[4]);\n\
                 if (n < 0 || n >= (int)sizeof(marker)) return 65;\n\
                 FILE *ready = fopen(marker, \"w\");\n\
                 if (!ready) return 65;\n\
                 if (fprintf(ready, \"%ld\\n\", (long)getpid()) < 0) return 65;\n\
                 if (fclose(ready)) return 65;\n\
                 sleep(30); return 0; }\n",
            )
            .unwrap();
            let status = Command::new("/usr/bin/cc")
                .arg(&source)
                .arg("-o")
                .arg(&child)
                .status()
                .expect("compile the owned macOS wait fixture");
            assert!(status.success(), "fixture compilation failed: {status}");
            let status = Command::new("/usr/bin/codesign")
                .args(["--force", "--sign", "-"])
                .arg(&child)
                .status()
                .expect("ad-hoc sign the owned macOS wait fixture");
            assert!(status.success(), "fixture codesign failed: {status}");
        }
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
        p
    }

    /// Wait for this PID's native entry point, not merely its launcher.
    /// A marker for a different PID cannot establish readiness.
    #[cfg(target_os = "macos")]
    fn wait_for_fake_meow(core: &mut DesktopCore, run: &Run) {
        let pid = core.child.as_ref().expect("fixture child started").id();
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            let ready = std::fs::read_to_string(run.dir.join("fixture.ready"))
                .ok()
                .and_then(|s| s.trim().parse::<u32>().ok());
            if ready == Some(pid) && is_core(pid, &core.meow) {
                return;
            }
            if !core.running() || Instant::now() >= deadline {
                let identity = SysCommands.out(
                    "/bin/ps",
                    &["-o", "comm=,args=,stat=", "-p", &pid.to_string()],
                );
                let log = log_tail(&run.dir.join("core.log"));
                core.stop();
                panic!(
                    "native fixture {pid} not ready: marker={ready:?}, ps={identity:?}, log={log}"
                );
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn restricted_user_core_is_adopted_by_exact_path() {
        // Root may inspect non-dumpable processes, so cannot exercise the
        // permission-denied branch. No capabilities or system changes needed.
        if unsafe { libc::geteuid() } == 0 {
            return;
        }
        let d = tempfile::tempdir().unwrap();
        let source = d.path().join("restricted.c");
        let meow = d.path().join("meow");
        std::fs::write(&source, "#include <sys/prctl.h>\n#include <unistd.h>\n#include <stdio.h>\nint main(int argc,char **argv) { if(prctl(PR_SET_DUMPABLE,0)) return 2; FILE *f=fopen(argv[1],\"w\"); if(!f) return 3; fclose(f); sleep(30); return 0; }\n").unwrap();
        assert!(Command::new("cc")
            .arg(&source)
            .arg("-o")
            .arg(&meow)
            .status()
            .unwrap()
            .success());
        let marker = d.path().join("ready");
        let mut child = Command::new(&meow).arg(&marker).spawn().unwrap();
        let result = std::panic::catch_unwind(|| {
            let deadline = Instant::now() + Duration::from_secs(3);
            while !marker.exists() && Instant::now() < deadline {
                std::thread::sleep(Duration::from_millis(10));
            }
            assert!(marker.exists(), "restricted fixture did not start");
            let error = std::fs::read_link(format!("/proc/{}/exe", child.id())).unwrap_err();
            assert_eq!(error.kind(), std::io::ErrorKind::PermissionDenied);
            assert!(is_core(child.id(), &meow));
            assert!(!is_core(child.id(), &d.path().join("other/meow")));
            let data = d.path().join("data");
            std::fs::create_dir_all(data.join("meow")).unwrap();
            std::fs::write(data.join("meow/core.pid"), child.id().to_string()).unwrap();
            let mut adopted = DesktopCore::new(meow, data, None);
            assert!(adopted.running());
            assert_eq!(adopted.adopted, Some(child.id()));
            adopted.stop();
            assert!(!adopted.running());
        });
        let _ = child.kill();
        let _ = child.wait();
        if let Err(error) = result {
            std::panic::resume_unwind(error);
        }
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
        #[cfg(target_os = "macos")]
        wait_for_fake_meow(&mut core, &run);
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
        assert_eq!(core.same_build(), None);
    }

    #[test]
    fn the_core_build_against_the_apps() {
        let d = tempfile::tempdir().unwrap();
        let meow = fake_meow(d.path());
        let data = d.path().join("data");
        let mut core = DesktopCore::new(meow.clone(), data.clone(), None);
        // None running: nothing to tell.
        assert_eq!(core.same_build(), None);
        let run = core.place(false).unwrap();
        std::fs::create_dir_all(&run.dir).unwrap();
        std::fs::write(&run.config, "{}").unwrap();
        core.start(&run).unwrap();
        #[cfg(target_os = "macos")]
        wait_for_fake_meow(&mut core, &run);
        assert_eq!(core.same_build(), Some(true));
        // A tray started again (the app the same) takes it on as the same.
        let mut again = DesktopCore::new(meow.clone(), data.clone(), None);
        assert!(again.adopted.is_some());
        assert_eq!(again.same_build(), Some(true));
        // The app updated: its core binary another one.
        let mut text = std::fs::read_to_string(&meow).unwrap();
        text.push_str("# another build\n");
        std::fs::write(&meow, text).unwrap();
        assert_eq!(again.same_build(), Some(false));
        let mut updated = DesktopCore::new(meow.clone(), data.clone(), None);
        assert_eq!(updated.same_build(), Some(false));
        // Started by a tray that noted no build: cannot be told.
        std::fs::remove_file(run.dir.join(BUILD_FILE)).unwrap();
        assert_eq!(updated.same_build(), None);
        // Started again: the app's build.
        updated.start(&run).unwrap();
        #[cfg(target_os = "macos")]
        wait_for_fake_meow(&mut updated, &run);
        assert_eq!(updated.same_build(), Some(true));
        updated.stop();
        assert_eq!(updated.same_build(), None);
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
