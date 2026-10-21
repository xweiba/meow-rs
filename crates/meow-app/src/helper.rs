//! The privileged helper an app installs once (macOS: a launchd daemon run
//! as root) so the core can open a TUN device without asking for a
//! password every time.
//!
//! `meow service --socket PATH --uid UID` listens on a Unix socket and
//! serves only that user (checked with the peer's credentials): one JSON
//! line in, one JSON line out —
//!
//! - `{"op":"start","config":"/abs/config.json","dir":"/abs/dir"}` runs
//!   this binary as the core (`-f config -d dir`), replacing a running one;
//!   with `"core":"/abs/meow"` (the app's own core) that one instead, once
//!   it passes [`trusted_core`] — so an update of the app runs its new core
//!   without installing the helper again (no new password prompt);
//! - `{"op":"stop"}`; `{"op":"status"}` (`running`, `version`: [`VERSION`],
//!   `signed`: this helper carries a developer team's signature, so the
//!   app's core is taken by its signature — unsigned, only a core that is
//!   byte for byte the helper's own);
//! - `{"op":"relocate"}` (macOS): restarts `locationd`, so the system asks
//!   for its location again (virtual location takes effect at once);
//! - `{"op":"wifi"}` (macOS): the current Wi-Fi network name, read as root
//!   with `wdutil info` (recent macOS redacts it for apps without Location
//!   permission) — `{"ok":true,"ssid":"Name"}`, or `"ssid":null` when not
//!   on Wi-Fi / not found; `{"ok":false}` on other systems.
//!
//! `meow service-call --socket PATH --op start --config … --dir …` is the
//! client: prints the reply, exits non-zero only when the helper can't be
//! reached.
//!
//! Windows ([`win`]): the same ops over the named pipe `\\.\pipe\paopao-core`
//! (its DACL: SYSTEM, Administrators and the one user), served by the
//! Windows service `PaoPaoCore` (LocalSystem, auto start) that `meow
//! service-install` sets up once (one UAC prompt), its own copy under
//! `%ProgramData%\PaoPao`.

#[cfg(unix)]
use std::io::BufRead;
#[cfg(unix)]
use std::io::BufReader;
use std::io::Read;
#[cfg(unix)]
use std::io::Write;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
#[cfg(unix)]
use std::os::unix::io::AsRawFd;
#[cfg(unix)]
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::time::Duration;
#[cfg(unix)]
use std::time::Instant;

#[cfg(unix)]
use anyhow::Context;
use anyhow::Result;
use serde_json::{json, Value};

#[cfg(windows)]
pub mod win;
#[cfg(windows)]
pub use win::{call, install, serve, uninstall};

/// The connecting process's user id.
#[cfg(unix)]
fn peer_uid(stream: &UnixStream) -> Option<u32> {
    let fd = stream.as_raw_fd();
    #[cfg(any(target_os = "macos", target_os = "ios", target_os = "freebsd"))]
    {
        let (mut uid, mut gid): (libc::uid_t, libc::gid_t) = (0, 0);
        // SAFETY: fd is a connected Unix socket owned by `stream`; uid / gid
        // are valid out-pointers.
        let r = unsafe { libc::getpeereid(fd, &raw mut uid, &raw mut gid) };
        (r == 0).then_some(uid)
    }
    #[cfg(target_os = "linux")]
    {
        let mut cred = libc::ucred {
            pid: 0,
            uid: 0,
            gid: 0,
        };
        let mut len = libc::socklen_t::try_from(std::mem::size_of::<libc::ucred>()).ok()?;
        // SAFETY: fd is a connected Unix socket; cred / len describe a
        // buffer of the size SO_PEERCRED writes.
        let r = unsafe {
            libc::getsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_PEERCRED,
                (&raw mut cred).cast(),
                &raw mut len,
            )
        };
        (r == 0).then_some(cred.uid)
    }
}

/// Log lines without terminal colors.
fn strip_ansi(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\u{1b}' && chars.peek() == Some(&'[') {
            for d in chars.by_ref() {
                if d.is_ascii_alphabetic() {
                    break;
                }
            }
        } else {
            out.push(c);
        }
    }
    out
}

/// What this helper understands: 2 = `start` takes the app's `core`.
pub const VERSION: u32 = 2;

/// Where the helper keeps the app's core it checked (root's, not the
/// user's to change between the check and the start).
fn trusted_dir() -> std::path::PathBuf {
    std::env::current_exe()
        .ok()
        .and_then(|e| e.parent().map(|d| d.join("core")))
        .unwrap_or_else(|| install_root().join("core"))
}

/// The helper's own directory (`win` is only there on Windows: a `cfg!`
/// branch would still be compiled elsewhere).
#[cfg(windows)]
fn install_root() -> std::path::PathBuf {
    win::install_dir()
}

#[cfg(not(windows))]
fn install_root() -> std::path::PathBuf {
    "/Library/Application Support/PaoPao".into()
}

/// The core's file name in [`trusted_dir`].
const CORE_NAME: &str = if cfg!(windows) { "meow.exe" } else { "meow" };

/// The app's core at `path`, made root's own copy and checked: the copy
/// (which the user cannot change any more) must be signed by the same
/// developer team as this helper (macOS `codesign`: Developer ID, the
/// team in the leaf certificate); an unsigned helper (a development
/// build) only takes a copy that is byte for byte itself. The copy's path,
/// to run; why not, otherwise.
fn trusted_core(path: &str) -> Result<std::path::PathBuf, String> {
    let src = Path::new(path);
    if !src.is_absolute() {
        return Err("core must be an absolute path".into());
    }
    let dir = trusted_dir();
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    let copy = dir.join(CORE_NAME);
    let tmp = dir.join("meow.check");
    let _ = std::fs::remove_file(&tmp);
    {
        let mut from = std::fs::File::open(src).map_err(|e| format!("{path}: {e}"))?;
        if !from.metadata().is_ok_and(|m| m.is_file()) {
            return Err(format!("{path}: not a file"));
        }
        // Root's alone until it passed (whatever was named is not shown;
        // Windows: the folder is SYSTEM's and the administrators').
        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            opts.mode(0o700);
        }
        let mut to = opts.open(&tmp).map_err(|e| e.to_string())?;
        std::io::copy(&mut from, &mut to).map_err(|e| e.to_string())?;
    }
    let me = std::env::current_exe().map_err(|e| e.to_string())?;
    let ok = match team_of(&me) {
        Some(team) => signed_by(&tmp, &team),
        None => std::fs::read(&me).ok() == std::fs::read(&tmp).ok(),
    };
    if !ok {
        let _ = std::fs::remove_file(&tmp);
        return Err("the core is not signed as this helper is".into());
    }
    #[cfg(unix)]
    std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o755))
        .map_err(|e| e.to_string())?;
    std::fs::rename(&tmp, &copy).map_err(|e| e.to_string())?;
    // The signed wintun.dll shipped beside the app's core goes beside this
    // copy too (only the one built in: the folder is root's).
    #[cfg(all(windows, feature = "listener-tun"))]
    let _ = src
        .parent()
        .map(|app| meow_listener::tun::copy_bundled_wintun(app, &dir));
    Ok(copy)
}

/// Whether this helper is signed by a developer team (looked up once).
fn signed() -> bool {
    static SIGNED: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *SIGNED.get_or_init(|| {
        std::env::current_exe()
            .ok()
            .and_then(|e| team_of(&e))
            .is_some()
    })
}

/// The developer team that signed `exe` (`TeamIdentifier=` of `codesign
/// -dv`); None unsigned, ad-hoc, or not macOS.
fn team_of(exe: &Path) -> Option<String> {
    if !cfg!(target_os = "macos") {
        return None;
    }
    let out = Command::new("/usr/bin/codesign")
        .args(["-dv", "--verbose=2"])
        .arg(exe)
        .stdin(Stdio::null())
        .output()
        .ok()?;
    // codesign describes on stderr.
    let text = String::from_utf8_lossy(&out.stderr);
    text.lines()
        .find_map(|l| l.strip_prefix("TeamIdentifier="))
        .map(str::trim)
        .filter(|t| !t.is_empty() && *t != "not set")
        .map(str::to_owned)
}

/// `exe` has a valid signature by Apple-issued certificates of `team`.
fn signed_by(exe: &Path, team: &str) -> bool {
    if !team.chars().all(|c| c.is_ascii_alphanumeric()) {
        return false;
    }
    let req = format!("=anchor apple generic and certificate leaf[subject.OU] = \"{team}\"");
    Command::new("/usr/bin/codesign")
        .args(["--verify", "--strict", "-R", &req])
        .arg(exe)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|s| s.success())
}

struct Core {
    child: Option<WatchedChild>,
}

/// The helper keeps a native exit watch even when neither panel nor tray
/// polls it. Inspection and cache invalidation share a lock with stop/start,
/// so one generation is flushed once, after reaping, before its replacement.
struct WatchedChild {
    state: std::sync::Arc<std::sync::Mutex<ChildState>>,
}

struct ChildState {
    child: Child,
    flushed: bool,
    flush: fn(),
}

impl ChildState {
    fn after_exit(&mut self) {
        if !self.flushed {
            self.flushed = true;
            (self.flush)();
        }
    }

    fn try_wait(&mut self) -> std::io::Result<Option<std::process::ExitStatus>> {
        let status = self.child.try_wait()?;
        if status.is_some() {
            self.after_exit();
        }
        Ok(status)
    }
}

impl WatchedChild {
    fn new(child: Child, flush: fn()) -> std::io::Result<Self> {
        let state = std::sync::Arc::new(std::sync::Mutex::new(ChildState {
            child,
            flushed: false,
            flush,
        }));
        let weak = std::sync::Arc::downgrade(&state);
        if let Err(e) = std::thread::Builder::new()
            .name("helper-core-exit".into())
            .spawn(move || loop {
                let Some(shared) = weak.upgrade() else { break };
                let exited = shared
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .try_wait()
                    .is_ok_and(|status| status.is_some());
                if exited {
                    break;
                }
                drop(shared);
                std::thread::sleep(Duration::from_millis(100));
            })
        {
            // An unsupervised privileged core must not escape a failed
            // start. The same exit gate handles this rollback too.
            let mut s = state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let _ = s.child.kill();
            if s.child.wait().is_ok() {
                s.after_exit();
            }
            return Err(e);
        }
        Ok(Self { state })
    }

    #[cfg(unix)]
    fn terminate(&mut self) -> std::io::Result<()> {
        let mut s = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        // Keep the watcher from reaping between the live check and signal:
        // a reaped PID could already belong to an unrelated process.
        if s.try_wait()?.is_some() {
            return Ok(());
        }
        let pid = i32::try_from(s.child.id()).map_err(std::io::Error::other)?;
        // SAFETY: this is our unreaped child, protected by the same lock
        // used by every wait operation.
        if unsafe { libc::kill(pid, libc::SIGTERM) } == 0 {
            Ok(())
        } else {
            Err(std::io::Error::last_os_error())
        }
    }

    fn try_wait(&mut self) -> std::io::Result<Option<std::process::ExitStatus>> {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .try_wait()
    }

    fn kill(&mut self) -> std::io::Result<()> {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .child
            .kill()
    }

    fn wait(&mut self) -> std::io::Result<std::process::ExitStatus> {
        let mut s = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let status = s.child.wait()?;
        s.after_exit();
        Ok(status)
    }
}

impl Core {
    fn running(&mut self) -> bool {
        match &mut self.child {
            Some(c) => !matches!(c.try_wait(), Ok(Some(_))),
            None => false,
        }
    }

    #[cfg(windows)]
    fn stop(&mut self) -> bool {
        if let Some(mut c) = self.child.take() {
            let _ = c.kill();
            if c.wait().is_err() {
                self.child = Some(c);
            }
        }
        self.child.is_none()
    }

    #[cfg(unix)]
    fn stop(&mut self) -> bool {
        if let Some(mut c) = self.child.take() {
            let _ = c.terminate();
            let deadline = Instant::now() + Duration::from_secs(5);
            while Instant::now() < deadline {
                if matches!(c.try_wait(), Ok(Some(_))) {
                    return true;
                }
                std::thread::sleep(Duration::from_millis(50));
            }
            let _ = c.kill();
            if c.wait().is_err() {
                self.child = Some(c);
            }
        }
        self.child.is_none()
    }

    fn start(&mut self, config: &str, dir: &str, core: Option<&str>) -> Value {
        if !Path::new(config).is_absolute() || !Path::new(dir).is_absolute() {
            return json!({"ok": false, "error": "config and dir must be absolute paths"});
        }
        if !self.stop() {
            return json!({"ok": false, "error": "previous core shutdown is not confirmed"});
        }
        let exe = match core {
            Some(c) => match trusted_core(c) {
                Ok(e) => e,
                Err(e) => return json!({"ok": false, "error": e}),
            },
            None => match std::env::current_exe() {
                Ok(e) => e,
                Err(e) => return json!({"ok": false, "error": e.to_string()}),
            },
        };
        let log_path = Path::new(dir).join("core.log");
        let log = match std::fs::File::create(&log_path) {
            Ok(f) => f,
            Err(e) => return json!({"ok": false, "error": format!("{}: {e}", log_path.display())}),
        };
        let err = log.try_clone().ok();
        let mut cmd = Command::new(&exe);
        cmd.args(["-f", config, "-d", dir])
            .stdin(Stdio::null())
            .stdout(log)
            .stderr(err.map_or_else(Stdio::null, Stdio::from));
        #[cfg(windows)]
        {
            use std::os::windows::process::CommandExt as _;
            cmd.creation_flags(0x0800_0000); // CREATE_NO_WINDOW
            if let Some(d) = exe.parent() {
                cmd.current_dir(d);
            }
        }
        let child = cmd.spawn();
        let mut child = match child {
            Ok(c) => match WatchedChild::new(c, meow_common::dns_cache::flush_after_capture) {
                Ok(child) => child,
                Err(e) => return json!({"ok": false, "error": e.to_string()}),
            },
            Err(e) => return json!({"ok": false, "error": e.to_string()}),
        };
        // A config the core refuses ends it at once: say why.
        std::thread::sleep(Duration::from_millis(600));
        if let Ok(Some(status)) = child.try_wait() {
            let mut tail = String::new();
            let _ = std::fs::File::open(&log_path).and_then(|mut f| f.read_to_string(&mut tail));
            let tail = strip_ansi(&tail);
            let lines: Vec<&str> = tail.lines().collect();
            let tail = lines[lines.len().saturating_sub(8)..].join("\n");
            return json!({"ok": false, "error": format!("core exited ({status})"), "log": tail});
        }
        self.child = Some(child);
        json!({"ok": true})
    }
}

#[cfg(unix)]
fn handle(core: &mut Core, stream: UnixStream, uid: u32) -> Result<()> {
    if peer_uid(&stream) != Some(uid) && peer_uid(&stream) != Some(0) {
        let mut s = stream;
        writeln!(s, "{}", json!({"ok": false, "error": "not allowed"}))?;
        return Ok(());
    }
    stream.set_read_timeout(Some(Duration::from_secs(10)))?;
    let mut line = String::new();
    BufReader::new(&stream).read_line(&mut line)?;
    let reply = answer(core, &line);
    let mut s = stream;
    writeln!(s, "{reply}")?;
    Ok(())
}

/// The reply to one request line.
fn answer(core: &mut Core, line: &str) -> Value {
    let req: Value = serde_json::from_str(line.trim()).unwrap_or(Value::Null);
    let text = |k: &str| {
        req.get(k)
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string()
    };
    match text("op").as_str() {
        "start" => {
            let c = text("core");
            core.start(
                &text("config"),
                &text("dir"),
                (!c.is_empty()).then_some(c.as_str()),
            )
        }
        "stop" => {
            if core.stop() {
                json!({"ok": true})
            } else {
                json!({"ok": false, "error": "core shutdown is not confirmed"})
            }
        }
        "status" => json!({
            "ok": true,
            "running": core.running(),
            "version": VERSION,
            "signed": signed(),
        }),
        "relocate" => relocate(),
        "wifi" => wifi(),
        other => json!({"ok": false, "error": format!("unknown op '{other}'")}),
    }
}

/// macOS: `locationd` restarted (launchd brings it back); it then looks up
/// where it is again instead of using what it had.
fn relocate() -> Value {
    if !cfg!(target_os = "macos") {
        return json!({"ok": false, "error": "macOS only"});
    }
    match Command::new("/usr/bin/killall").arg("locationd").status() {
        Ok(s) if s.success() => json!({"ok": true}),
        Ok(s) => json!({"ok": false, "error": format!("killall locationd: {s}")}),
        Err(e) => json!({"ok": false, "error": e.to_string()}),
    }
}

/// macOS: the current Wi-Fi SSID from `wdutil info` (needs root, which the
/// helper is). Never fails the service: anything unexpected is `null`.
fn wifi() -> Value {
    #[cfg(target_os = "macos")]
    {
        let ssid = Command::new("/usr/bin/wdutil")
            .arg("info")
            .stdin(Stdio::null())
            .stderr(Stdio::null())
            .output()
            .ok()
            .and_then(|o| parse_wdutil_ssid(&String::from_utf8_lossy(&o.stdout)));
        json!({"ok": true, "ssid": ssid})
    }
    #[cfg(not(target_os = "macos"))]
    {
        json!({"ok": false, "error": "macOS only"})
    }
}

/// The `SSID : <name>` line of the `WIFI` section of `wdutil info`. `None`
/// when there is no such section/line, or the value says there is no
/// network (`None`, empty) or is redacted (`<redacted>`).
#[cfg_attr(
    not(any(target_os = "macos", all(test, unix))),
    allow(dead_code, reason = "only the macOS wifi op calls it")
)]
fn parse_wdutil_ssid(text: &str) -> Option<String> {
    let mut in_wifi = false;
    for line in text.lines() {
        let t = line.trim();
        if t.is_empty() {
            continue;
        }
        let Some((key, value)) = t.split_once(':') else {
            // A section title (`WIFI`, `BLUETOOTH`, …) or a rule line made
            // of dashes: only titles switch sections.
            if t.chars().any(char::is_alphabetic) {
                in_wifi = t.eq_ignore_ascii_case("WIFI") || t.eq_ignore_ascii_case("WI-FI");
            }
            continue;
        };
        if in_wifi && key.trim() == "SSID" {
            let v = value.trim();
            return match v {
                "" | "None" | "<redacted>" | "<SSID Redacted>" => None,
                v => Some(v.to_owned()),
            };
        }
    }
    None
}

/// `meow service`: serves [`uid`] on [`socket`] until killed.
#[cfg(unix)]
pub fn serve(socket: &str, uid: u32) -> Result<()> {
    let path = Path::new(socket);
    if path.exists() {
        std::fs::remove_file(path).with_context(|| format!("removing stale {socket}"))?;
    }
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let listener = UnixListener::bind(path).with_context(|| format!("binding {socket}"))?;
    // Anyone may connect; only `uid` (and root) are answered.
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o666))?;
    let mut core = Core { child: None };
    for stream in listener.incoming() {
        match stream {
            Ok(s) => {
                if let Err(e) = handle(&mut core, s, uid) {
                    eprintln!("service: {e:#}");
                }
            }
            Err(e) => eprintln!("service: accept: {e}"),
        }
    }
    core.stop();
    Ok(())
}

/// `meow service-call`.
#[cfg(unix)]
pub fn call(socket: &str, op: &str, config: Option<&str>, dir: Option<&str>) -> Result<()> {
    let mut s = UnixStream::connect(socket).with_context(|| format!("connecting {socket}"))?;
    s.set_read_timeout(Some(Duration::from_secs(30)))?;
    let mut req = json!({"op": op});
    if let Some(c) = config {
        req["config"] = json!(c);
    }
    if let Some(d) = dir {
        req["dir"] = json!(d);
    }
    writeln!(s, "{req}")?;
    let mut reply = String::new();
    BufReader::new(&s).read_line(&mut reply)?;
    print!("{reply}");
    std::io::stdout().flush()?;
    Ok(())
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    #[test]
    fn root_cache_cleanup_follows_normal_forced_and_unexpected_exit_once() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        static FLUSHES: AtomicUsize = AtomicUsize::new(0);
        fn flushed() {
            FLUSHES.fetch_add(1, Ordering::SeqCst);
        }
        fn watched(child: Child) -> Core {
            Core {
                child: Some(WatchedChild::new(child, flushed).unwrap()),
            }
        }
        // A live child never flushes. A normal stop confirms/reaps first.
        let mut normal = watched(Command::new("/bin/sleep").arg("30").spawn().unwrap());
        assert!(normal.running());
        assert_eq!(FLUSHES.load(Ordering::SeqCst), 0);
        assert_eq!(answer(&mut normal, r#"{"op":"stop"}"#), json!({"ok": true}));
        assert_eq!(FLUSHES.load(Ordering::SeqCst), 1);
        assert!(normal.stop());
        assert_eq!(FLUSHES.load(Ordering::SeqCst), 1);

        // Read readiness before stopping so SIGTERM is certainly ignored;
        // stop must exercise its bounded force-kill/reap fallback.
        let mut child = Command::new("/bin/sh")
            .args(["-c", "trap '' TERM; echo ready; exec sleep 30"])
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        let mut ready = String::new();
        BufReader::new(child.stdout.take().unwrap())
            .read_line(&mut ready)
            .unwrap();
        assert_eq!(ready.trim(), "ready");
        let mut forced = watched(child);
        assert!(forced.stop());
        assert_eq!(FLUSHES.load(Ordering::SeqCst), 2);

        // No manager/status request: the helper's own watcher detects exit.
        let mut unexpected = watched(Command::new("/bin/sleep").arg("0.05").spawn().unwrap());
        let deadline = Instant::now() + Duration::from_secs(3);
        while FLUSHES.load(Ordering::SeqCst) < 3 && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(20));
        }
        assert_eq!(FLUSHES.load(Ordering::SeqCst), 3);
        assert!(!unexpected.running());
        assert!(unexpected.stop());
        assert_eq!(FLUSHES.load(Ordering::SeqCst), 3);
    }

    #[test]
    fn colors_are_dropped_from_the_log() {
        assert_eq!(
            strip_ansi("\u{1b}[2mtime\u{1b}[0m \u{1b}[32m INFO\u{1b}[0m x"),
            "time  INFO x"
        );
    }

    const WDUTIL_SAMPLE: &str = "\
————————————————————————————————————————————————————————————————————————
NETWORK
————————————————————————————————————————————————————————————————————————
    Primary IPv4         : en0 (Wi-Fi / 0F3A9B2C-1D2E-4F50-8A6B-7C8D9E0F1A2B)
                         : 192.168.186.42
    DNS                  : 192.168.186.1
————————————————————————————————————————————————————————————————————————
WIFI
————————————————————————————————————————————————————————————————————————
    MAC Address          : 3c:22:fb:00:11:22 (hw=3c:22:fb:00:11:22)
    Interface Name       : en0
    Power                : On [On]
    Op Mode              : STA
    SSID                 : Home Net: 5G
    BSSID                : a0:b1:c2:d3:e4:f5
    RSSI                 : -51 dBm
    Noise                : -94 dBm
    Tx Rate              : 866.0 Mbps
    Security             : WPA2 Personal
    Channel              : 5g149/80
————————————————————————————————————————————————————————————————————————
BLUETOOTH
————————————————————————————————————————————————————————————————————————
    Power                : On
    SSID                 : not-wifi
";

    #[test]
    fn wdutil_ssid_is_read_from_the_wifi_section() {
        assert_eq!(
            parse_wdutil_ssid(WDUTIL_SAMPLE).as_deref(),
            Some("Home Net: 5G")
        );
        let off = WDUTIL_SAMPLE.replace(
            "SSID                 : Home Net: 5G",
            "SSID                 : None",
        );
        assert_eq!(parse_wdutil_ssid(&off), None, "not associated");
        let redacted = WDUTIL_SAMPLE.replace("Home Net: 5G", "<redacted>");
        assert_eq!(parse_wdutil_ssid(&redacted), None);
        // No WIFI section: the BLUETOOTH `SSID` line is not taken.
        let no_wifi = WDUTIL_SAMPLE.replace("\nWIFI\n", "\nOTHER\n");
        assert_eq!(parse_wdutil_ssid(&no_wifi), None);
        assert_eq!(parse_wdutil_ssid(""), None);
        assert_eq!(parse_wdutil_ssid("garbage\n:::\n"), None);
    }

    #[test]
    fn serves_the_owner_and_answers_each_op() {
        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("h.sock");
        let s = sock.to_str().unwrap().to_string();
        // SAFETY: getuid(2) has no preconditions.
        let me = unsafe { libc::getuid() };
        let server = s.clone();
        std::thread::spawn(move || serve(&server, me));
        for _ in 0..100 {
            if sock.exists() {
                break;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        let ask = |req: &str| {
            let mut c = UnixStream::connect(&s).unwrap();
            writeln!(c, "{req}").unwrap();
            let mut line = String::new();
            BufReader::new(&c).read_line(&mut line).unwrap();
            serde_json::from_str::<Value>(&line).unwrap()
        };
        assert_eq!(
            ask(r#"{"op":"status"}"#),
            json!({"ok": true, "running": false, "version": VERSION, "signed": false})
        );
        // Another binary than the helper itself (unsigned here): refused.
        let other = dir.path().join("other");
        std::fs::write(&other, b"not the core").unwrap();
        let r = ask(&format!(
            r#"{{"op":"start","config":"/tmp/c.json","dir":"/tmp","core":"{}"}}"#,
            other.display()
        ));
        assert_eq!(r["ok"], json!(false), "{r}");
        assert_eq!(
            ask(r#"{"op":"start","config":"rel.json","dir":"/tmp"}"#)["ok"],
            json!(false),
            "relative paths refused"
        );
        assert_eq!(ask(r#"{"op":"nope"}"#)["ok"], json!(false));
        let wifi = ask(r#"{"op":"wifi"}"#);
        if cfg!(target_os = "macos") {
            assert_eq!(wifi["ok"], json!(true));
            assert!(wifi["ssid"].is_null() || wifi["ssid"].is_string());
        } else {
            assert_eq!(wifi["ok"], json!(false));
        }
        assert_eq!(ask(r#"{"op":"stop"}"#), json!({"ok": true}));
        assert_eq!(
            std::fs::metadata(&sock).unwrap().permissions().mode() & 0o777,
            0o666
        );
    }
}
