//! The privileged helper on Windows: the Windows service `PaoPaoCore`
//! (LocalSystem, auto start) answering the ops of [`super`] on the named
//! pipe [`PIPE`], whose DACL lets in SYSTEM, the Administrators and the one
//! user who installed it (`--sid`).
//!
//! - `meow service-install [--socket PIPE] [--sid SID]`: run as the user,
//!   it asks Windows once for administrator rights (UAC, `runas`) and runs
//!   itself elevated: this binary copied to `%ProgramData%\PaoPao\meow.exe`
//!   (the folder SYSTEM's and the administrators', the users may only read
//!   it), the service created (or updated) and started, and waited for
//!   until it answers. Exit code 0 when done, 1223 when the prompt was
//!   refused.
//! - `meow service-uninstall`: the service stopped and deleted,
//!   `%ProgramData%\PaoPao` removed (elevated the same way; nothing to do,
//!   nothing asked).
//! - `meow service --socket PIPE --sid SID`: the service itself (what the
//!   SCM runs); started by hand, it serves in the foreground.
//! - `meow service-call --socket PIPE --op …`: the client.
//!
//! The core it runs is its own copy of the app's (`%ProgramData%\PaoPao\
//! core\meow.exe`, refreshed at each start): only one byte for byte the
//! helper itself (no code signing here), so an updated app installs the
//! helper again (one prompt).

use super::{answer, Core};
use std::ffi::{OsStr, OsString};
use std::io::{BufRead, BufReader, Write};
use std::os::windows::ffi::OsStrExt;
use std::os::windows::io::{FromRawHandle, RawHandle};
use std::os::windows::process::CommandExt as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex, OnceLock, PoisonError};
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};
use serde_json::{json, Value};
use windows_service::service::{
    ServiceAccess, ServiceAction, ServiceActionType, ServiceControl, ServiceControlAccept,
    ServiceErrorControl, ServiceExitCode, ServiceFailureActions, ServiceFailureResetPeriod,
    ServiceInfo, ServiceStartType, ServiceState, ServiceStatus, ServiceType,
};
use windows_service::service_control_handler::{self, ServiceControlHandlerResult};
use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};
use windows_service::{define_windows_service, service_dispatcher};
use windows_sys::Win32::Foundation::{
    CloseHandle, GetLastError, LocalFree, ERROR_PIPE_CONNECTED, HANDLE, INVALID_HANDLE_VALUE,
};
use windows_sys::Win32::Security::Authorization::{
    ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
};
use windows_sys::Win32::Security::{PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES};
use windows_sys::Win32::Storage::FileSystem::{
    FlushFileBuffers, FILE_FLAG_FIRST_PIPE_INSTANCE, PIPE_ACCESS_DUPLEX,
};
use windows_sys::Win32::System::Pipes::{
    ConnectNamedPipe, CreateNamedPipeW, DisconnectNamedPipe, PIPE_READMODE_BYTE,
    PIPE_REJECT_REMOTE_CLIENTS, PIPE_TYPE_BYTE, PIPE_WAIT,
};
use windows_sys::Win32::System::Threading::{GetExitCodeProcess, WaitForSingleObject, INFINITE};
use windows_sys::Win32::UI::Shell::{ShellExecuteExW, SEE_MASK_NOCLOSEPROCESS, SHELLEXECUTEINFOW};
use windows_sys::Win32::UI::WindowsAndMessaging::SW_HIDE;

/// The service's name (`sc query PaoPaoCore`).
pub const SERVICE_NAME: &str = "PaoPaoCore";
/// What Windows' service list shows.
const DISPLAY_NAME: &str = "PaoPao Core";
const DESCRIPTION: &str =
    "Runs PaoPao Proxy's core with the rights its virtual network adapter needs";
/// The pipe it listens on.
pub const PIPE: &str = r"\\.\pipe\paopao-core";
/// The user refused the UAC prompt (`ERROR_CANCELLED`).
pub const CANCELLED: i32 = 1223;
const CREATE_NO_WINDOW: u32 = 0x0800_0000;

/// `%ProgramData%\PaoPao`: the helper's own copy, and its core's.
pub fn install_dir() -> PathBuf {
    std::env::var_os("ProgramData")
        .filter(|v| !v.is_empty())
        .map_or_else(|| PathBuf::from(r"C:\ProgramData"), PathBuf::from)
        .join("PaoPao")
}

fn wide(s: &OsStr) -> Vec<u16> {
    s.encode_wide().chain(Some(0)).collect()
}

/// A user SID as Windows writes it (`S-1-5-21-…`): nothing else goes into
/// the pipe's security descriptor.
pub fn valid_sid(s: &str) -> bool {
    s.len() < 192
        && s.strip_prefix("S-1-").is_some_and(|rest| {
            !rest.is_empty()
                && rest.chars().all(|c| c.is_ascii_digit() || c == '-')
                && !rest.contains("--")
                && !rest.ends_with('-')
        })
}

/// The pipe's DACL (SDDL): SYSTEM, the Administrators, the user; no one
/// else, not inherited.
pub fn pipe_sddl(sid: &str) -> String {
    format!("D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GA;;;{sid})")
}

/// `HANDLE` moved to the serving thread.
struct Pipe(HANDLE);
// SAFETY: a pipe handle may be used from any thread; only one does.
unsafe impl Send for Pipe {}

fn create_pipe(name: &str, sid: &str) -> Result<Pipe> {
    if !valid_sid(sid) {
        bail!("not a user SID: {sid}");
    }
    let sddl = wide(OsStr::new(&pipe_sddl(sid)));
    let mut sd: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
    // SAFETY: a NUL-terminated string; `sd` receives a LocalAlloc'd block.
    let ok = unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl.as_ptr(),
            SDDL_REVISION_1,
            &raw mut sd,
            std::ptr::null_mut(),
        )
    };
    if ok == 0 {
        return Err(std::io::Error::last_os_error()).context("pipe security descriptor");
    }
    let sa = SECURITY_ATTRIBUTES {
        nLength: u32::try_from(std::mem::size_of::<SECURITY_ATTRIBUTES>()).unwrap_or(0),
        lpSecurityDescriptor: sd,
        bInheritHandle: 0,
    };
    let wname = wide(OsStr::new(name));
    // One instance, ours from the first (none made before by another
    // program), local clients only.
    // SAFETY: valid name and attributes for the call's duration.
    let h = unsafe {
        CreateNamedPipeW(
            wname.as_ptr(),
            PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE,
            PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
            1,
            64 * 1024,
            64 * 1024,
            0,
            &raw const sa,
        )
    };
    let err = std::io::Error::last_os_error();
    // SAFETY: allocated by the conversion above, no longer used.
    unsafe { LocalFree(sd) };
    if h == INVALID_HANDLE_VALUE {
        return Err(err).with_context(|| format!("creating {name}"));
    }
    Ok(Pipe(h))
}

/// One client after another on `pipe`, until the process ends.
fn serve_on(pipe: &Pipe, core: &Mutex<Core>) {
    let h = pipe.0;
    loop {
        // SAFETY: our pipe handle; synchronous (no OVERLAPPED).
        let ok = unsafe { ConnectNamedPipe(h, std::ptr::null_mut()) };
        // SAFETY: no preconditions.
        if ok == 0 && unsafe { GetLastError() } != ERROR_PIPE_CONNECTED {
            std::thread::sleep(Duration::from_millis(50));
            continue;
        }
        // SAFETY: the handle stays ours (ManuallyDrop: not closed here).
        let file =
            std::mem::ManuallyDrop::new(unsafe { std::fs::File::from_raw_handle(h as RawHandle) });
        let mut line = String::new();
        let _ = BufReader::new(&*file).read_line(&mut line);
        // Connected and gone at once (a look whether it is there): nothing
        // to answer.
        if !line.trim().is_empty() {
            let reply = answer(
                &mut core.lock().unwrap_or_else(PoisonError::into_inner),
                &line,
            );
            let _ = writeln!(&*file, "{reply}");
            // SAFETY: our pipe handle.
            unsafe { FlushFileBuffers(h) };
        }
        // SAFETY: our pipe handle.
        unsafe { DisconnectNamedPipe(h) };
    }
}

/// What the SCM started this process with (`service --socket --sid`).
static ARGS: OnceLock<(String, String)> = OnceLock::new();

define_windows_service!(ffi_helper_main, helper_main);

/// `meow service`: the Windows service when the SCM runs it; started by
/// hand, the same in the foreground.
pub fn serve(socket: &str, sid: &str) -> Result<()> {
    let _ = ARGS.set((socket.to_owned(), sid.to_owned()));
    if service_dispatcher::start(SERVICE_NAME, ffi_helper_main).is_ok() {
        return Ok(());
    }
    let pipe = create_pipe(socket, sid)?;
    let core = Mutex::new(Core { child: None });
    serve_on(&pipe, &core);
    Ok(())
}

fn note(what: &str) {
    let _ = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(install_dir().join("service.log"))
        .and_then(|mut f| writeln!(f, "{what}"));
}

fn status(state: ServiceState, exit: ServiceExitCode) -> ServiceStatus {
    ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: state,
        controls_accepted: if state == ServiceState::Running {
            ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN
        } else {
            ServiceControlAccept::empty()
        },
        exit_code: exit,
        checkpoint: 0,
        wait_hint: Duration::from_secs(10),
        process_id: None,
    }
}

#[allow(
    clippy::needless_pass_by_value,
    reason = "the signature define_windows_service! calls"
)]
fn helper_main(_arguments: Vec<OsString>) {
    let Some((socket, sid)) = ARGS.get().cloned() else {
        return;
    };
    let (tx, rx) = std::sync::mpsc::channel::<()>();
    let handler = move |event| match event {
        ServiceControl::Stop | ServiceControl::Shutdown => {
            let _ = tx.send(());
            ServiceControlHandlerResult::NoError
        }
        ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
        _ => ServiceControlHandlerResult::NotImplemented,
    };
    let Ok(handle) = service_control_handler::register(SERVICE_NAME, handler) else {
        return;
    };
    let pipe = match create_pipe(&socket, &sid) {
        Ok(p) => p,
        Err(e) => {
            note(&format!("{e:#}"));
            let _ = handle.set_service_status(status(
                ServiceState::Stopped,
                ServiceExitCode::ServiceSpecific(1),
            ));
            return;
        }
    };
    let core = Arc::new(Mutex::new(Core { child: None }));
    let serving = Arc::clone(&core);
    std::thread::spawn(move || serve_on(&pipe, &serving));
    let _ = handle.set_service_status(status(ServiceState::Running, ServiceExitCode::NO_ERROR));
    let _ = rx.recv();
    let _ = handle.set_service_status(status(ServiceState::StopPending, ServiceExitCode::NO_ERROR));
    core.lock().unwrap_or_else(PoisonError::into_inner).stop();
    let _ = handle.set_service_status(status(ServiceState::Stopped, ServiceExitCode::NO_ERROR));
}

/// One request to the helper on `socket`, its reply line; Err when it
/// cannot be reached.
pub fn request(socket: &str, req: &Value, timeout: Duration) -> std::io::Result<String> {
    let deadline = Instant::now() + timeout;
    let file = loop {
        match std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(socket)
        {
            Ok(f) => break f,
            // ERROR_PIPE_BUSY: another client is being answered.
            Err(e) if e.raw_os_error() == Some(231) && Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(20));
            }
            Err(e) => return Err(e),
        }
    };
    writeln!(&file, "{req}")?;
    let mut reply = String::new();
    BufReader::new(&file).read_line(&mut reply)?;
    Ok(reply)
}

/// `meow service-call`.
pub fn call(socket: &str, op: &str, config: Option<&str>, dir: Option<&str>) -> Result<()> {
    let mut req = json!({"op": op});
    if let Some(c) = config {
        req["config"] = json!(c);
    }
    if let Some(d) = dir {
        req["dir"] = json!(d);
    }
    let reply = request(socket, &req, Duration::from_secs(30))
        .with_context(|| format!("connecting {socket}"))?;
    print!("{reply}");
    std::io::stdout().flush()?;
    Ok(())
}

/// The user running this (`whoami /user`).
fn current_sid() -> Result<String> {
    let out = Command::new("whoami")
        .args(["/user", "/fo", "csv", "/nh"])
        .stdin(Stdio::null())
        .creation_flags(CREATE_NO_WINDOW)
        .output()
        .context("whoami")?;
    parse_whoami_sid(&String::from_utf8_lossy(&out.stdout)).context("no user SID from whoami")
}

/// The SID of `whoami /user /fo csv /nh` (`"host\user","S-1-5-21-…"`).
pub fn parse_whoami_sid(text: &str) -> Option<String> {
    text.split(',')
        .map(|f| f.trim().trim_matches('"'))
        .find(|f| valid_sid(f))
        .map(str::to_owned)
}

/// Whether this process may create services (elevated).
fn elevated() -> bool {
    ServiceManager::local_computer(
        None::<&str>,
        ServiceManagerAccess::CONNECT | ServiceManagerAccess::CREATE_SERVICE,
    )
    .is_ok()
}

/// One command-line argument quoted as Windows parses it back.
fn quote(arg: &str) -> String {
    if !arg.is_empty() && !arg.contains([' ', '\t', '"']) {
        return arg.to_owned();
    }
    let mut out = String::from("\"");
    let mut slashes = 0;
    for c in arg.chars() {
        match c {
            '\\' => slashes += 1,
            '"' => {
                out.extend(std::iter::repeat_n('\\', slashes * 2 + 1));
                out.push('"');
                slashes = 0;
            }
            c => {
                out.extend(std::iter::repeat_n('\\', slashes));
                out.push(c);
                slashes = 0;
            }
        }
    }
    out.extend(std::iter::repeat_n('\\', slashes * 2));
    out.push('"');
    out
}

/// This binary with `args`, as administrator: Windows asks the user first
/// (UAC). Its exit code ([`CANCELLED`]: refused).
fn run_elevated(args: &[&str]) -> Result<i32> {
    let exe = std::env::current_exe()?;
    let exe = wide(exe.as_os_str());
    let params: Vec<String> = args.iter().map(|a| quote(a)).collect();
    let params = wide(OsStr::new(&params.join(" ")));
    let verb = wide(OsStr::new("runas"));
    // SAFETY: all-zero is a valid SHELLEXECUTEINFOW (null pointers, 0s).
    let mut info: SHELLEXECUTEINFOW = unsafe { std::mem::zeroed() };
    info.cbSize = u32::try_from(std::mem::size_of::<SHELLEXECUTEINFOW>()).unwrap_or(0);
    info.fMask = SEE_MASK_NOCLOSEPROCESS;
    info.lpVerb = verb.as_ptr();
    info.lpFile = exe.as_ptr();
    info.lpParameters = params.as_ptr();
    info.nShow = SW_HIDE;
    // SAFETY: `info` and the strings it points at live through the call.
    if unsafe { ShellExecuteExW(&raw mut info) } == 0 {
        let e = std::io::Error::last_os_error();
        if e.raw_os_error() == Some(CANCELLED) {
            return Ok(CANCELLED);
        }
        return Err(e).context("asking for administrator rights");
    }
    if info.hProcess.is_null() {
        return Ok(0);
    }
    let mut code: u32 = 1;
    // SAFETY: the process handle SEE_MASK_NOCLOSEPROCESS gave us.
    unsafe {
        WaitForSingleObject(info.hProcess, INFINITE);
        GetExitCodeProcess(info.hProcess, &raw mut code);
        CloseHandle(info.hProcess);
    }
    #[allow(
        clippy::cast_possible_wrap,
        reason = "exit codes as Windows gives them"
    )]
    Ok(code as i32)
}

fn quiet(cmd: &mut Command) -> bool {
    cmd.stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .creation_flags(CREATE_NO_WINDOW)
        .status()
        .is_ok_and(|s| s.success())
}

/// `dir` only SYSTEM's and the administrators' to change; the users may
/// read it (well-known SIDs: any Windows language).
fn lock_down(dir: &Path) -> Result<()> {
    let ok = quiet(Command::new("icacls").arg(dir).args([
        "/inheritance:r",
        "/grant:r",
        "*S-1-5-18:(OI)(CI)F",
        "*S-1-5-32-544:(OI)(CI)F",
        "*S-1-5-32-545:(OI)(CI)RX",
    ]));
    if !ok {
        bail!("could not set the permissions of {}", dir.display());
    }
    Ok(())
}

fn stop_and_wait(service: &windows_service::service::Service) {
    let deadline = Instant::now() + Duration::from_secs(30);
    while Instant::now() < deadline {
        match service.query_status() {
            Ok(s) if s.current_state == ServiceState::Stopped => return,
            Ok(s) if s.current_state != ServiceState::StopPending => {
                let _ = service.stop();
            }
            Ok(_) => {}
            Err(_) => return,
        }
        std::thread::sleep(Duration::from_millis(200));
    }
}

/// `f` until it works or `tries` ran out (a stopped process lets go of its
/// files a moment later).
fn retry<T>(tries: u32, mut f: impl FnMut() -> std::io::Result<T>) -> std::io::Result<T> {
    let mut last = None;
    for _ in 0..tries {
        match f() {
            Ok(v) => return Ok(v),
            Err(e) => last = Some(e),
        }
        std::thread::sleep(Duration::from_millis(250));
    }
    Err(last.unwrap_or_else(|| std::io::Error::other("no try")))
}

fn service_info(exe: &Path, socket: &str, sid: &str) -> ServiceInfo {
    ServiceInfo {
        name: OsString::from(SERVICE_NAME),
        display_name: OsString::from(DISPLAY_NAME),
        service_type: ServiceType::OWN_PROCESS,
        start_type: ServiceStartType::AutoStart,
        error_control: ServiceErrorControl::Normal,
        executable_path: exe.to_path_buf(),
        launch_arguments: vec![
            OsString::from("service"),
            OsString::from("--socket"),
            OsString::from(socket),
            OsString::from("--sid"),
            OsString::from(sid),
        ],
        dependencies: Vec::new(),
        account_name: None,
        account_password: None,
    }
}

/// `meow service-install`; as the user it runs itself elevated and ends
/// with that one's exit code.
pub fn install(socket: &str, sid: Option<&str>) -> Result<()> {
    let sid = match sid {
        Some(s) => s.to_owned(),
        None => current_sid()?,
    };
    if !valid_sid(&sid) {
        bail!("not a user SID: {sid}");
    }
    if !elevated() {
        let code = run_elevated(&["service-install", "--socket", socket, "--sid", &sid])?;
        if code != 0 {
            std::process::exit(code);
        }
        return Ok(());
    }
    let result = install_elevated(socket, &sid);
    if let Err(e) = &result {
        note(&format!("install: {e:#}"));
    }
    result
}

fn install_elevated(socket: &str, sid: &str) -> Result<()> {
    let manager = ServiceManager::local_computer(
        None::<&str>,
        ServiceManagerAccess::CONNECT | ServiceManagerAccess::CREATE_SERVICE,
    )
    .context("the Service Control Manager")?;
    let access = ServiceAccess::QUERY_STATUS
        | ServiceAccess::CHANGE_CONFIG
        | ServiceAccess::START
        | ServiceAccess::STOP;
    let existing = manager.open_service(SERVICE_NAME, access).ok();
    if let Some(s) = &existing {
        stop_and_wait(s);
    }
    // Made afresh by us: nothing a user put there before stays.
    let dir = install_dir();
    if dir.exists() {
        retry(20, || std::fs::remove_dir_all(&dir))
            .with_context(|| format!("removing {}", dir.display()))?;
    }
    std::fs::create_dir_all(&dir).with_context(|| format!("creating {}", dir.display()))?;
    lock_down(&dir)?;
    let me = std::env::current_exe()?;
    let exe = dir.join("meow.exe");
    std::fs::copy(&me, &exe).with_context(|| format!("copying to {}", exe.display()))?;
    let info = service_info(&exe, socket, sid);
    let service = match existing {
        Some(s) => {
            s.change_config(&info).context("updating the service")?;
            s
        }
        None => manager
            .create_service(&info, access)
            .context("creating the service")?,
    };
    let _ = service.set_description(DESCRIPTION);
    let _ = service.update_failure_actions(ServiceFailureActions {
        reset_period: ServiceFailureResetPeriod::After(Duration::from_secs(24 * 60 * 60)),
        reboot_msg: None,
        command: None,
        actions: Some(vec![
            ServiceAction {
                action_type: ServiceActionType::Restart,
                delay: Duration::from_secs(5),
            },
            ServiceAction {
                action_type: ServiceActionType::Restart,
                delay: Duration::from_secs(30),
            },
        ]),
    });
    service
        .start::<&OsStr>(&[])
        .context("starting the service")?;
    let deadline = Instant::now() + Duration::from_secs(20);
    while Instant::now() < deadline {
        if request(socket, &json!({"op": "status"}), Duration::from_secs(2))
            .is_ok_and(|r| r.contains("\"ok\":true"))
        {
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    bail!("the service did not answer on {socket}")
}

fn service_exists() -> bool {
    ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)
        .and_then(|m| m.open_service(SERVICE_NAME, ServiceAccess::QUERY_STATUS))
        .is_ok()
}

/// `meow service-uninstall`: nothing installed, nothing asked.
pub fn uninstall() -> Result<()> {
    let dir = install_dir();
    if !service_exists() && !dir.exists() {
        return Ok(());
    }
    if !elevated() {
        let code = run_elevated(&["service-uninstall"])?;
        if code != 0 {
            std::process::exit(code);
        }
        return Ok(());
    }
    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)?;
    if let Ok(s) = manager.open_service(
        SERVICE_NAME,
        ServiceAccess::QUERY_STATUS | ServiceAccess::STOP | ServiceAccess::DELETE,
    ) {
        stop_and_wait(&s);
        s.delete().context("deleting the service")?;
    }
    drop(manager);
    if dir.exists() {
        retry(40, || std::fs::remove_dir_all(&dir))
            .with_context(|| format!("removing {}", dir.display()))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sids_and_the_pipe_dacl() {
        assert!(valid_sid("S-1-5-21-1004336348-1177238915-682003330-1001"));
        assert!(valid_sid("S-1-5-18"));
        assert!(!valid_sid("S-1-5-21)(A;;GA;;;WD"));
        assert!(!valid_sid("S-1-"));
        assert!(!valid_sid("S-1-5--1"));
        assert!(!valid_sid("WD"));
        assert_eq!(
            pipe_sddl("S-1-5-21-1-2-3-1001"),
            "D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GA;;;S-1-5-21-1-2-3-1001)"
        );
        assert_eq!(
            parse_whoami_sid("\"pc\\me\",\"S-1-5-21-1-2-3-1001\"\r\n").as_deref(),
            Some("S-1-5-21-1-2-3-1001")
        );
        assert_eq!(parse_whoami_sid("garbage"), None);
    }

    #[test]
    fn arguments_quoted_for_the_command_line() {
        assert_eq!(quote("service-install"), "service-install");
        assert_eq!(quote(r"\\.\pipe\paopao-core"), r"\\.\pipe\paopao-core");
        assert_eq!(quote(r"C:\Program Files\x"), r#""C:\Program Files\x""#);
        assert_eq!(quote(r"C:\a b\"), r#""C:\a b\\""#);
        assert_eq!(quote(r#"a"b"#), r#""a\"b""#);
        assert_eq!(quote(""), r#""""#);
    }

    #[test]
    fn the_service_runs_the_installed_copy() {
        let exe = install_dir().join("meow.exe");
        let info = service_info(&exe, PIPE, "S-1-5-21-1-2-3-1001");
        assert_eq!(info.name, OsStr::new(SERVICE_NAME));
        assert_eq!(info.start_type, ServiceStartType::AutoStart);
        assert!(info.account_name.is_none(), "LocalSystem");
        assert_eq!(
            info.launch_arguments,
            ["service", "--socket", PIPE, "--sid", "S-1-5-21-1-2-3-1001"]
                .map(OsString::from)
                .to_vec()
        );
        assert!(install_dir().ends_with("PaoPao"));
    }

    /// The pipe served in this process (the current user's SID): each op
    /// answered, a busy pipe waited for, the app's core refused unless it
    /// is this very binary.
    #[test]
    fn serves_the_ops_on_a_pipe() {
        let sid = current_sid().unwrap();
        let name = format!(r"\\.\pipe\paopao-core-test-{}", std::process::id());
        let pipe = create_pipe(&name, &sid).unwrap();
        // A second server on the same name: refused (first instance ours).
        assert!(create_pipe(&name, &sid).is_err());
        std::thread::spawn(move || {
            let core = Mutex::new(Core { child: None });
            serve_on(&pipe, &core);
        });
        let ask = |req: Value| -> Value {
            serde_json::from_str(&request(&name, &req, Duration::from_secs(10)).unwrap()).unwrap()
        };
        let s = ask(json!({"op": "status"}));
        assert_eq!(s["ok"], json!(true), "{s}");
        assert_eq!(s["running"], json!(false));
        assert_eq!(s["version"], json!(super::super::VERSION));
        // A look (connect, close) does not stop it answering.
        drop(
            std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open(&name),
        );
        let d = tempfile::tempdir().unwrap();
        let other = d.path().join("other.exe");
        std::fs::write(&other, b"not the core").unwrap();
        let cfg = d.path().join("c.json");
        let r = ask(json!({"op": "start", "config": cfg, "dir": d.path(), "core": other}));
        assert_eq!(r["ok"], json!(false), "{r}");
        assert_eq!(
            ask(json!({"op": "start", "config": "rel.json", "dir": "x"}))["ok"],
            json!(false)
        );
        assert_eq!(ask(json!({"op": "nope"}))["ok"], json!(false));
        assert_eq!(ask(json!({"op": "stop"})), json!({"ok": true}));
        // Many at once: each waits its turn.
        let threads: Vec<_> = (0..4)
            .map(|_| {
                let n = name.clone();
                std::thread::spawn(move || {
                    request(&n, &json!({"op": "status"}), Duration::from_secs(10)).unwrap()
                })
            })
            .collect();
        for t in threads {
            assert!(t.join().unwrap().contains("\"ok\":true"));
        }
        assert!(request(r"\\.\pipe\paopao-core-none", &json!({}), Duration::ZERO).is_err());
    }
}
