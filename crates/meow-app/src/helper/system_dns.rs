//! PaoPao: while the helper runs a core with 虚拟网卡 (macOS, Windows), the
//! physical network services / adapters whose DNS is a LAN address (the
//! router) or automatic point at public resolvers ([`SERVERS`]); when the
//! core ends, however it ends, they are put back as they were.
//!
//! Why: the core captures the system's DNS with a host route through the
//! TUN for each system DNS server (`meow-listener` `tun/dns_routes.rs`). A
//! server on the local subnet escapes it — macOS's resolver reached the
//! router directly and got its (poisoned) answer while `dig @router` was
//! captured — whereas a public server is captured. Clash Verge points the
//! system DNS at a public resolver for the same reason.
//!
//! All of it is here, in the privileged helper: it outlives its core, so a
//! core that crashed is put back as soon as it exits, and what a crash of
//! the helper (or the machine) left is put back as the helper starts again.
//! What was there is written to [`backup_path`] before anything changes. A
//! setting someone else changed meanwhile stays as they set it. A local
//! resolver (a loopback server) is never replaced.
//!
//! Windows: IPv4 DNS only; putting back "automatic" resets the adapter's
//! IPv6 DNS to automatic too (`Set-DnsClientServerAddress
//! -ResetServerAddresses`).

use std::io;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, PoisonError};
use std::time::Duration;

use serde::{Deserialize, Serialize};

/// The public resolvers set while the core runs.
pub const SERVERS: [&str; 2] = ["223.5.5.5", "119.29.29.29"];

const NETWORKSETUP: &str = "/usr/sbin/networksetup";
const TCPIP: &str = r"HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\";
const COMMAND_TIMEOUT: Duration = Duration::from_secs(15);

/// Runs OS commands: tests give their own.
trait Run {
    /// Stdout when it ran and exited with 0.
    fn out(&self, exe: &str, args: &[&str]) -> Option<String>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Os {
    MacOs,
    Windows,
}

/// One service (macOS: its name) or adapter (Windows: its interface GUID)
/// changed, and its DNS before: empty = automatic (DHCP).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct Saved {
    id: String,
    servers: Vec<IpAddr>,
}

/// Where what was there is kept: beside the helper's own files.
fn backup_path() -> Option<PathBuf> {
    if cfg!(target_os = "macos") {
        Some("/Library/Application Support/PaoPao/system-dns.json".into())
    } else if cfg!(windows) {
        let data = std::env::var_os("ProgramData")
            .filter(|v| !v.is_empty())
            .map_or_else(|| PathBuf::from(r"C:\ProgramData"), PathBuf::from);
        Some(data.join("PaoPao").join("system-dns.json"))
    } else {
        None
    }
}

fn current_os() -> Option<Os> {
    if cfg!(target_os = "macos") {
        Some(Os::MacOs)
    } else if cfg!(windows) {
        Some(Os::Windows)
    } else {
        None
    }
}

/// A change and a put-back never interleave: a core that exits while its
/// change is made is put back after it.
static BUSY: Mutex<()> = Mutex::new(());

/// The core about to run on `config` has 虚拟网卡 on (`tun.enable`).
pub(super) fn tun_on(config: &Path) -> bool {
    std::fs::read_to_string(config)
        .ok()
        .and_then(|text| serde_yaml::from_str::<serde_yaml::Value>(&text).ok())
        .and_then(|v| v.get("tun")?.get("enable")?.as_bool())
        .unwrap_or(false)
}

/// The core with 虚拟网卡 started: the LAN DNS pointed at [`SERVERS`].
pub(super) fn apply() {
    let (Some(os), Some(path)) = (current_os(), backup_path()) else {
        return;
    };
    let _busy = BUSY.lock().unwrap_or_else(PoisonError::into_inner);
    // A leftover first: what is saved must be the user's own.
    restore(os, &System, &path);
    match change(os, &System, &path) {
        Ok(0) => {}
        Ok(n) => eprintln!("service: system DNS of {n} network service(s) set to {SERVERS:?}"),
        Err(e) => eprintln!("service: system DNS not changed: {e}"),
    }
}

/// The core ended (or the helper starts): what was there put back. True
/// when there was something.
pub(super) fn restore_leftover() -> bool {
    match (current_os(), backup_path()) {
        (Some(os), Some(path)) => {
            let _busy = BUSY.lock().unwrap_or_else(PoisonError::into_inner);
            restore(os, &System, &path)
        }
        _ => false,
    }
}

/// The services to change saved first, then changed. How many.
fn change(os: Os, run: &dyn Run, path: &Path) -> io::Result<usize> {
    let changes = plan(os, run);
    if changes.is_empty() {
        return Ok(0);
    }
    write_backup(path, &changes)?;
    for c in &changes {
        if !set(os, run, &c.id) {
            eprintln!("service: system DNS of {} not changed", c.id);
        }
    }
    Ok(changes.len())
}

fn restore(os: Os, run: &dyn Run, path: &Path) -> bool {
    let Ok(bytes) = std::fs::read(path) else {
        return false;
    };
    let saved: Vec<Saved> = serde_json::from_slice(&bytes).unwrap_or_default();
    for s in &saved {
        put_back(os, run, s);
    }
    if let Err(e) = std::fs::remove_file(path) {
        eprintln!("service: {} not removed: {e}", path.display());
    }
    true
}

fn write_backup(path: &Path, changes: &[Saved]) -> io::Result<()> {
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let tmp = path.with_extension("json.tmp");
    std::fs::write(&tmp, serde_json::to_vec(changes)?)?;
    std::fs::rename(&tmp, path)
}

fn ours() -> Vec<IpAddr> {
    SERVERS.iter().filter_map(|s| s.parse().ok()).collect()
}

/// Private, link-local and CGNAT addresses: a server that may sit on the
/// local network.
fn is_lan(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            v4.is_private() || v4.is_link_local() || (o[0] == 100 && (o[1] & 0xc0) == 64)
        }
        IpAddr::V6(v6) => {
            let s = v6.segments()[0];
            (s & 0xfe00) == 0xfc00 || (s & 0xffc0) == 0xfe80
        }
    }
}

/// `effective`: what the system uses now (automatic: what DHCP gave, or
/// nothing when that cannot be read).
fn needs_change(effective: &[IpAddr]) -> bool {
    !effective.iter().any(IpAddr::is_loopback)
        && (effective.is_empty() || effective.iter().copied().any(is_lan))
}

fn plan(os: Os, run: &dyn Run) -> Vec<Saved> {
    match os {
        Os::MacOs => {
            let Some(order) = run.out(NETWORKSETUP, &["-listnetworkserviceorder"]) else {
                return Vec::new();
            };
            mac_services(&order)
                .into_iter()
                .filter_map(|id| {
                    let servers = mac_get(run, &id)?;
                    needs_change(&servers).then_some(Saved { id, servers })
                })
                .collect()
        }
        Os::Windows => {
            let Some(out) = powershell(run, WINDOWS_LIST) else {
                return Vec::new();
            };
            parse_windows(&out)
                .into_iter()
                .filter(|(_, manual, dhcp)| {
                    needs_change(if manual.is_empty() { dhcp } else { manual })
                })
                .map(|(id, servers, _)| Saved { id, servers })
                .collect()
        }
    }
}

fn set(os: Os, run: &dyn Run, id: &str) -> bool {
    match os {
        Os::MacOs => {
            let mut args = vec!["-setdnsservers", id];
            args.extend(SERVERS);
            run.out(NETWORKSETUP, &args).is_some()
        }
        Os::Windows => {
            let Some(guid) = valid_guid(id) else {
                return false;
            };
            let script = format!(
                "{}; if ($a) {{ Set-DnsClientServerAddress -InterfaceIndex $a.InterfaceIndex -ServerAddresses ({}) }}",
                windows_adapter(guid),
                ps_list(&ours())
            );
            powershell(run, &script).is_some()
        }
    }
}

/// Put back when it still reads as ours; else someone set their own since.
fn put_back(os: Os, run: &dyn Run, s: &Saved) {
    match os {
        Os::MacOs => {
            if mac_get(run, &s.id) != Some(ours()) {
                return;
            }
            let list: Vec<String> = s.servers.iter().map(ToString::to_string).collect();
            let mut args = vec!["-setdnsservers", s.id.as_str()];
            if list.is_empty() {
                args.push("Empty");
            } else {
                args.extend(list.iter().map(String::as_str));
            }
            run.out(NETWORKSETUP, &args);
        }
        Os::Windows => {
            let Some(guid) = valid_guid(&s.id) else {
                return;
            };
            let back = if s.servers.is_empty() {
                "-ResetServerAddresses".to_owned()
            } else {
                format!("-ServerAddresses ({})", ps_list(&s.servers))
            };
            let script = format!(
                "{}; $p = Get-ItemProperty -Path ('{TCPIP}' + '{guid}') -ErrorAction SilentlyContinue; if ($a -and ((($p.NameServer -split '[, ]') | Where-Object {{ $_ }}) -join ',') -eq '{}') {{ Set-DnsClientServerAddress -InterfaceIndex $a.InterfaceIndex {back} }}",
                windows_adapter(guid),
                SERVERS.join(",")
            );
            powershell(run, &script);
        }
    }
}

// ---------------------------------------------------------------- macOS

/// The enabled services on a physical interface (`en*`: Wi-Fi, Ethernet,
/// USB, Thunderbolt), from `networksetup -listnetworkserviceorder`.
fn mac_services(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut name: Option<String> = None;
    for line in text.lines() {
        let Some(rest) = line.trim().strip_prefix('(') else {
            continue;
        };
        if let Some(port) = rest.strip_prefix("Hardware Port: ") {
            let device = port
                .rsplit_once("Device: ")
                .map(|(_, d)| d.trim_end_matches(')').trim());
            if let (Some(n), Some(d)) = (name.take(), device) {
                if d.starts_with("en") {
                    out.push(n);
                }
            }
        } else if let Some((num, n)) = rest.split_once(") ") {
            // "(*) Name": disabled.
            name = (!num.is_empty() && num.bytes().all(|b| b.is_ascii_digit()))
                .then(|| n.trim().to_owned());
        }
    }
    out
}

/// The service's own DNS (empty: automatic); None when it cannot be read.
fn mac_get(run: &dyn Run, service: &str) -> Option<Vec<IpAddr>> {
    let out = run.out(NETWORKSETUP, &["-getdnsservers", service])?;
    if out.contains("aren't any") {
        return Some(Vec::new());
    }
    out.lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .map(|l| l.parse().ok())
        .collect()
}

// -------------------------------------------------------------- Windows

/// Per physical adapter that is up: `if|{guid}|manual|dhcp` (the
/// registry's `NameServer`, `DhcpNameServer`).
const WINDOWS_LIST: &str = r"Get-NetAdapter -Physical -ErrorAction SilentlyContinue | Where-Object Status -eq 'Up' | ForEach-Object { $p = Get-ItemProperty -Path ('HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\' + $_.InterfaceGuid) -ErrorAction SilentlyContinue; 'if|' + $_.InterfaceGuid + '|' + $p.NameServer + '|' + $p.DhcpNameServer }";

/// (guid, manual, dhcp) per adapter.
fn parse_windows(text: &str) -> Vec<(String, Vec<IpAddr>, Vec<IpAddr>)> {
    let ips = |s: &str| -> Vec<IpAddr> {
        s.split([',', ' '])
            .filter_map(|p| p.trim().parse().ok())
            .collect()
    };
    text.lines()
        .filter_map(|l| {
            let mut f = l.trim().strip_prefix("if|")?.split('|');
            let guid = valid_guid(f.next()?)?.to_owned();
            Some((
                guid,
                ips(f.next().unwrap_or("")),
                ips(f.next().unwrap_or("")),
            ))
        })
        .collect()
}

/// `{xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx}` (it goes into a script).
fn valid_guid(s: &str) -> Option<&str> {
    let inner = s.strip_prefix('{')?.strip_suffix('}')?;
    (inner.len() == 36 && inner.bytes().all(|b| b.is_ascii_hexdigit() || b == b'-')).then_some(s)
}

fn windows_adapter(guid: &str) -> String {
    format!(
        "$a = Get-NetAdapter -ErrorAction SilentlyContinue | Where-Object {{ $_.InterfaceGuid -eq '{guid}' }} | Select-Object -First 1"
    )
}

fn ps_list(ips: &[IpAddr]) -> String {
    ips.iter()
        .map(|ip| format!("'{ip}'"))
        .collect::<Vec<_>>()
        .join(",")
}

fn powershell(run: &dyn Run, script: &str) -> Option<String> {
    run.out(
        "powershell",
        &["-NoProfile", "-NonInteractive", "-Command", script],
    )
}

// ------------------------------------------------------------ commands

struct System;

impl Run for System {
    fn out(&self, exe: &str, args: &[&str]) -> Option<String> {
        match run_with_timeout(exe, args, COMMAND_TIMEOUT) {
            Ok(out) => Some(out),
            Err(e) => {
                eprintln!("service: {exe}: {e}");
                None
            }
        }
    }
}

fn run_with_timeout(exe: &str, args: &[&str], limit: Duration) -> io::Result<String> {
    use std::process::{Command, Stdio};
    let mut cmd = Command::new(exe);
    cmd.args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt as _;
        cmd.creation_flags(0x0800_0000); // CREATE_NO_WINDOW
    }
    let mut child = cmd.spawn()?;
    let mut stdout = child
        .stdout
        .take()
        .ok_or_else(|| io::Error::other("no output pipe"))?;
    // Read on the side: a pipe that fills up would stall the command.
    let reader = std::thread::spawn(move || {
        let mut out = Vec::new();
        let _ = io::Read::read_to_end(&mut stdout, &mut out);
        out
    });
    let deadline = std::time::Instant::now() + limit;
    let status = loop {
        if let Some(status) = child.try_wait()? {
            break status;
        }
        if std::time::Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            return Err(io::Error::new(io::ErrorKind::TimedOut, "timed out"));
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    let out = reader.join().unwrap_or_default();
    if !status.success() {
        return Err(io::Error::other(format!("exit status {status}")));
    }
    Ok(String::from_utf8_lossy(&out).trim().to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::sync::Mutex;

    /// Answers by the joined command line; `networksetup -setdnsservers`
    /// changes what its getter answers; `powershell` answers `ps`.
    #[derive(Default)]
    struct Fake {
        answers: Mutex<HashMap<String, String>>,
        calls: Mutex<Vec<String>>,
    }

    impl Fake {
        fn answer(&self, line: &str, out: &str) {
            self.answers.lock().unwrap().insert(line.into(), out.into());
        }

        fn calls(&self) -> Vec<String> {
            std::mem::take(&mut *self.calls.lock().unwrap())
        }
    }

    impl Run for Fake {
        fn out(&self, exe: &str, args: &[&str]) -> Option<String> {
            let line = std::iter::once(exe)
                .chain(args.iter().copied())
                .collect::<Vec<_>>()
                .join(" ");
            self.calls.lock().unwrap().push(line.clone());
            if let ["-setdnsservers", service, servers @ ..] = args {
                let now = if servers == ["Empty"] {
                    format!("There aren't any DNS Servers set on {service}.")
                } else {
                    servers.join("\n")
                };
                self.answer(&format!("{NETWORKSETUP} -getdnsservers {service}"), &now);
                return Some(String::new());
            }
            let answers = self.answers.lock().unwrap();
            if exe == "powershell" {
                return Some(answers.get("ps").cloned().unwrap_or_default());
            }
            answers.get(&line).cloned()
        }
    }

    const ORDER: &str = "An asterisk (*) denotes that a network service is disabled.\n\
        (1) Wi-Fi\n(Hardware Port: Wi-Fi, Device: en0)\n\n\
        (2) USB 10/100/1000 LAN\n(Hardware Port: USB 10/100/1000 LAN, Device: en7)\n\n\
        (3) Tailscale\n(Hardware Port: com.tailscale.ipn.macsys, Device: )\n\n\
        (4) Thunderbolt Bridge\n(Hardware Port: Thunderbolt Bridge, Device: bridge0)\n\n\
        (*) Ethernet Off\n(Hardware Port: Ethernet, Device: en1)\n";

    fn mac(fake: &Fake) {
        fake.answer(&format!("{NETWORKSETUP} -listnetworkserviceorder"), ORDER);
        fake.answer(
            &format!("{NETWORKSETUP} -getdnsservers Wi-Fi"),
            "There aren't any DNS Servers set on Wi-Fi.",
        );
        fake.answer(
            &format!("{NETWORKSETUP} -getdnsservers USB 10/100/1000 LAN"),
            "8.8.8.8\n1.1.1.1",
        );
    }

    #[test]
    fn macos_physical_enabled_services_only() {
        assert_eq!(mac_services(ORDER), ["Wi-Fi", "USB 10/100/1000 LAN"]);
    }

    #[test]
    fn macos_sets_saves_and_puts_back_automatic() {
        let d = tempfile::tempdir().unwrap();
        let path = d.path().join("system-dns.json");
        let fake = Fake::default();
        mac(&fake);
        // Wi-Fi is automatic (the router); the USB LAN's public servers stay.
        assert_eq!(change(Os::MacOs, &fake, &path).unwrap(), 1);
        assert!(fake.calls().contains(&format!(
            "{NETWORKSETUP} -setdnsservers Wi-Fi 223.5.5.5 119.29.29.29"
        )));
        let saved: Vec<Saved> = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        assert_eq!(
            saved,
            [Saved {
                id: "Wi-Fi".into(),
                servers: vec![]
            }]
        );
        assert!(restore(Os::MacOs, &fake, &path));
        assert!(fake
            .calls()
            .contains(&format!("{NETWORKSETUP} -setdnsservers Wi-Fi Empty")));
        assert!(!path.exists());
        // Nothing saved: nothing to do.
        assert!(!restore(Os::MacOs, &fake, &path));
        assert!(fake.calls().is_empty());
    }

    #[test]
    fn macos_puts_back_manual_lan_servers() {
        let d = tempfile::tempdir().unwrap();
        let path = d.path().join("system-dns.json");
        let fake = Fake::default();
        mac(&fake);
        fake.answer(
            &format!("{NETWORKSETUP} -getdnsservers Wi-Fi"),
            "192.168.3.1\n223.6.6.6",
        );
        change(Os::MacOs, &fake, &path).unwrap();
        fake.calls();
        restore(Os::MacOs, &fake, &path);
        assert!(fake.calls().contains(&format!(
            "{NETWORKSETUP} -setdnsservers Wi-Fi 192.168.3.1 223.6.6.6"
        )));
    }

    #[test]
    fn a_setting_changed_by_someone_else_stays() {
        let d = tempfile::tempdir().unwrap();
        let path = d.path().join("system-dns.json");
        let fake = Fake::default();
        mac(&fake);
        change(Os::MacOs, &fake, &path).unwrap();
        fake.answer(&format!("{NETWORKSETUP} -getdnsservers Wi-Fi"), "9.9.9.9");
        fake.calls();
        assert!(restore(Os::MacOs, &fake, &path));
        assert!(!fake.calls().iter().any(|c| c.contains("-setdnsservers")));
        assert!(!path.exists());
    }

    #[test]
    fn what_changes() {
        let ips = |l: &[&str]| {
            l.iter()
                .map(|s| s.parse().unwrap())
                .collect::<Vec<IpAddr>>()
        };
        assert!(needs_change(&[]));
        assert!(needs_change(&ips(&["192.168.3.1"])));
        assert!(needs_change(&ips(&["10.0.0.1", "8.8.8.8"])));
        assert!(needs_change(&ips(&["100.100.100.100"])));
        assert!(needs_change(&ips(&["fe80::1"])));
        assert!(!needs_change(&ips(&["8.8.8.8"])));
        assert!(!needs_change(&ips(&["198.18.0.2"])));
        // A local resolver (dnsmasq, a corporate agent) is the user's.
        assert!(!needs_change(&ips(&["127.0.0.1", "192.168.3.1"])));
    }

    #[test]
    fn windows_adapters_and_scripts() {
        let g = "{4D36E972-E325-11CE-BFC1-08002BE10318}";
        let list = format!(
            "if|{g}||192.168.3.1\nif|{{6F1D7A2B-0000-4C1E-9A11-0123456789AB}}|8.8.8.8|192.168.1.1\nif|bad|x|y\n"
        );
        assert_eq!(parse_windows(&list).len(), 2);
        let d = tempfile::tempdir().unwrap();
        let path = d.path().join("system-dns.json");
        let fake = Fake::default();
        fake.answer("ps", &list);
        // The DHCP router is changed; a manual public server is not.
        assert_eq!(change(Os::Windows, &fake, &path).unwrap(), 1);
        let set = fake.calls().pop().unwrap();
        assert!(set.contains(g));
        assert!(set.contains("-ServerAddresses ('223.5.5.5','119.29.29.29')"));
        restore(Os::Windows, &fake, &path);
        let back = fake.calls().pop().unwrap();
        assert!(back.contains("-ResetServerAddresses"));
        assert!(back.contains("-eq '223.5.5.5,119.29.29.29'"));
        assert!(valid_guid("{x'; Remove-Item C:\\ -Recurse; '}").is_none());
    }

    #[test]
    fn tun_on_reads_json_and_yaml() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("c");
        std::fs::write(&p, r#"{"tun":{"enable":true},"mixed-port":7890}"#).unwrap();
        assert!(tun_on(&p));
        std::fs::write(&p, "tun:\n  enable: false\n").unwrap();
        assert!(!tun_on(&p));
        assert!(!tun_on(&d.path().join("none")));
    }
}
