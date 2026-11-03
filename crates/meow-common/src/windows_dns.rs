//! Recovery of Windows DNS settings written by older cores.
//!
//! New cores must never point physical adapters at loopback or a local TUN
//! address. Only an exact durable legacy record permits a restoration write;
//! missing records leave the user's DNS untouched.

use std::io;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::Duration;

use serde::{Deserialize, Serialize};

/// Private helper-provided recovery file; standalone cores use their data dir.
pub const BACKUP_ENV: &str = "MEOW_SYSTEM_DNS_BACKUP";
static BUSY: Mutex<()> = Mutex::new(());

#[derive(Clone, Debug, Deserialize, Serialize)]
struct Adapter {
    id: String,
    index: u32,
    iface: String,
    /// Empty means DHCP/automatic, separately for each address family.
    v4: Vec<IpAddr>,
    v6: Vec<IpAddr>,
    /// Effective pre-capture upstreams, including DHCP-provided addresses.
    effective: Vec<IpAddr>,
    has_v6: bool,
}

#[derive(Debug, Deserialize, Serialize)]
struct Backup {
    version: u8,
    lease: String,
    /// Published before restoration so an orphaned OS command cannot apply
    /// this generation again after the helper starts recovering it.
    #[serde(default)]
    restoring: bool,
    adapters: Vec<Adapter>,
}

trait Run {
    fn run(&self, script: &str) -> io::Result<String>;
}

fn path() -> PathBuf {
    std::env::var_os(BACKUP_ENV)
        .filter(|p| !p.is_empty())
        .map_or_else(
            || crate::resolved_home_dir().join("windows-system-dns.json"),
            PathBuf::from,
        )
}

/// Restore the standalone core's or helper-provided legacy record, if any.
pub fn restore() -> io::Result<bool> {
    restore_at(&path())
}

/// Recover a native capture record after a core exits. `false` means no
/// record, or a legacy array belonging to the helper's migration backend.
pub fn restore_at(path: &Path) -> io::Result<bool> {
    let _busy = BUSY
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let restored = restore_with(path, &System)?;
    if restored {
        crate::dns_cache::flush_after_capture();
    }
    Ok(restored)
}

/// Original upstreams for a currently captured physical interface. Readers
/// substitute these only when Windows still reports our loopback DNS.
pub fn original_servers(index: u32) -> Option<Vec<IpAddr>> {
    let _busy = BUSY
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let saved = read_backup(&path()).ok()??;
    saved
        .adapters
        .into_iter()
        .find(|a| a.index == index)
        .map(|a| a.effective)
}

fn read_backup(path: &Path) -> io::Result<Option<Backup>> {
    let bytes = match std::fs::read(path) {
        Ok(bytes) => bytes,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e),
    };
    let value: serde_json::Value = serde_json::from_slice(&bytes)
        .map_err(|_| io::Error::other("invalid DNS recovery record; preserved"))?;
    if value.is_array() {
        return Ok(None);
    }
    let saved: Backup = serde_json::from_value(value)
        .map_err(|_| io::Error::other("invalid DNS recovery record; preserved"))?;
    if saved.version != 1 || saved.adapters.iter().any(|a| !valid_guid(&a.id)) {
        return Err(io::Error::other(
            "unsupported DNS recovery record; preserved",
        ));
    }
    Ok(Some(saved))
}

fn restore_with(path: &Path, run: &dyn Run) -> io::Result<bool> {
    let Some(mut saved) = read_backup(path)? else {
        return Ok(false);
    };
    saved.restoring = true;
    let temp = path.with_extension("json.tmp");
    std::fs::write(&temp, serde_json::to_vec(&saved)?)?;
    std::fs::rename(temp, path)?;
    run.run(&restore_script(&saved))?;
    std::fs::remove_file(path)?;
    Ok(true)
}

fn valid_guid(value: &str) -> bool {
    let Some(inner) = value.strip_prefix('{').and_then(|s| s.strip_suffix('}')) else {
        return false;
    };
    inner.len() == 36
        && inner.bytes().enumerate().all(|(i, c)| {
            if [8, 13, 18, 23].contains(&i) {
                c == b'-'
            } else {
                c.is_ascii_hexdigit()
            }
        })
}

fn restore_script(saved: &Backup) -> String {
    // JSON strings are quoted for PowerShell; the only values used as OS
    // targets are validated GUIDs and parsed IP addresses, never aliases.
    let json = serde_json::to_string(&saved.adapters)
        .expect("DNS adapters serialize")
        .replace('\'', "''");
    let body = r#"# meow-dns-restore
        $registry=if($family -eq 'IPv4'){'Tcpip'}else{'Tcpip6'}
        $p=Get-ItemProperty -Path ('HKLM:\SYSTEM\CurrentControlSet\Services\'+$registry+'\Parameters\Interfaces\'+$row.id) -ErrorAction Stop
        $current=@($p.NameServer -split '[, ]+' | Where-Object { $_ } | ForEach-Object { ([Net.IPAddress]::Parse($_)).ToString() }) -join ','
        if($current -ne $ours) { continue }
        $original=if($family -eq 'IPv4'){@($row.v4)}else{@($row.v6)}
        if($original.Count -eq 0) { $d | Set-DnsClientServerAddress -ResetServerAddresses -ErrorAction Stop }
        else { $d | Set-DnsClientServerAddress -ServerAddresses $original -ErrorAction Stop }
        $p=Get-ItemProperty -Path ('HKLM:\SYSTEM\CurrentControlSet\Services\'+$registry+'\Parameters\Interfaces\'+$row.id) -ErrorAction Stop
        $after=@($p.NameServer -split '[, ]+' | Where-Object { $_ } | ForEach-Object { ([Net.IPAddress]::Parse($_)).ToString() }) -join ','
        if($after -ne ($original -join ',')) { throw 'DNS restoration readback failed' }
        "#;
    format!(
        r#"$ErrorActionPreference='Stop'; [Console]::OutputEncoding=[Text.UTF8Encoding]::new($false)
$rows=ConvertFrom-Json '{json}'
foreach($row in @($rows)) {{
  $a=Get-NetAdapter -IncludeHidden | Where-Object {{ $_.InterfaceGuid -eq $row.id }} | Select-Object -First 1
  if(-not $a) {{ throw 'DNS adapter unavailable; recovery retained' }}
  foreach($family in @('IPv4','IPv6')) {{
    if($family -eq 'IPv6' -and -not $row.has_v6) {{ continue }}
    $ours=if($family -eq 'IPv4'){{'127.0.0.1'}}else{{'::1'}}
    $d=Get-DnsClientServerAddress -InterfaceIndex $a.ifIndex -AddressFamily $family -ErrorAction Stop
    {body}
  }}
}}"#
    )
}

struct System;
impl Run for System {
    fn run(&self, script: &str) -> io::Result<String> {
        use std::io::Read;
        use std::process::{Command, Stdio};
        // Serialize recovery with an older core/helper. The durable restoring
        // bit also prevents an old capture command from applying late.
        let script = format!(
            r#"$ErrorActionPreference='Stop'
$lock=[Threading.Mutex]::new($false,'Global\MeowSystemDnsCapture')
$taken=$false
try {{
  try {{ $taken=$lock.WaitOne(15000) }} catch [Threading.AbandonedMutexException] {{ $taken=$true }}
  if(-not $taken) {{ throw 'System DNS transaction busy' }}
  try {{ {script} }} catch {{
    # Emit only the stable error identifier. No command text, recovery
    # contents or arbitrary exception message enters the core's log.
    [Console]::Error.WriteLine($_.FullyQualifiedErrorId)
    exit 1
  }}
}} finally {{ if($taken) {{ $lock.ReleaseMutex() }}; $lock.Dispose() }}"#
        );
        let mut cmd = Command::new("powershell.exe");
        cmd.args([
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            &script,
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
        #[cfg(windows)]
        {
            use std::os::windows::process::CommandExt;
            cmd.creation_flags(0x0800_0000);
        }
        let mut child = cmd.spawn()?;
        let mut stdout = child
            .stdout
            .take()
            .ok_or_else(|| io::Error::other("DNS command pipe unavailable"))?;
        let reader = std::thread::spawn(move || {
            let mut bytes = Vec::new();
            let _ = stdout.read_to_end(&mut bytes);
            bytes
        });
        let stderr = child.stderr.take().expect("piped DNS stderr");
        let errors = std::thread::spawn(move || {
            let mut bytes = Vec::new();
            let _ = stderr.take(4096).read_to_end(&mut bytes);
            bytes
        });
        let deadline = std::time::Instant::now() + Duration::from_secs(30);
        loop {
            if let Some(status) = child.try_wait()? {
                let bytes = reader.join().unwrap_or_default();
                let error = errors.join().unwrap_or_default();
                if !status.success() {
                    let id = String::from_utf8_lossy(&error);
                    // Only the identifier emitted by our catch is useful;
                    // don't log formatted PowerShell errors with script text.
                    let id = id
                        .lines()
                        .find(|line| {
                            !line.is_empty()
                                && line.len() <= 256
                                && line
                                    .chars()
                                    .all(|c| c.is_ascii_alphanumeric() || "_.,:-".contains(c))
                        })
                        .unwrap_or("unavailable");
                    return Err(io::Error::other(format!(
                        "Windows DNS restore failed ({status}; {id})"
                    )));
                }
                return String::from_utf8(bytes)
                    .map_err(|_| io::Error::other("invalid DNS command encoding"));
            }
            if std::time::Instant::now() >= deadline {
                let _ = child.kill();
                let _ = child.wait();
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "Windows DNS command timed out",
                ));
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, Ordering};

    struct Fake {
        fail_restore: AtomicBool,
    }
    impl Run for Fake {
        fn run(&self, script: &str) -> io::Result<String> {
            assert!(script.contains("# meow-dns-restore"));
            assert!(!script.contains("-ServerAddresses @($ours)"));
            assert!(script.contains("if($current -ne $ours) { continue }"));
            if self.fail_restore.load(Ordering::SeqCst) {
                return Err(io::Error::other("simulated OS refusal"));
            }
            Ok(String::new())
        }
    }

    fn legacy_record(path: &Path) {
        // The exact version-one format shipped by the former capture owner.
        std::fs::write(path, br#"{"version":1,"lease":"old-core","adapters":[{"id":"{4D36E972-E325-11CE-BFC1-08002BE10318}","index":7,"iface":"Ethernet","v4":[],"v6":["fd00::53"],"effective":["192.168.1.1","fd00::53"],"has_v6":true}]}"#).unwrap();
    }

    #[test]
    fn legacy_dhcp_and_static_ipv6_are_restored_once_without_new_capture() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("dns.json");
        let run = Fake {
            fail_restore: AtomicBool::new(false),
        };
        // A fresh installation does not even execute an OS DNS command.
        struct NoCommands;
        impl Run for NoCommands {
            fn run(&self, _: &str) -> io::Result<String> {
                panic!("no legacy record permits no DNS mutation")
            }
        }
        assert!(!restore_with(&path, &NoCommands).unwrap());
        assert!(!path.exists());
        legacy_record(&path);
        let saved = read_backup(&path).unwrap().unwrap();
        assert!(saved.adapters[0].v4.is_empty());
        assert_eq!(
            saved.adapters[0].v6[0],
            "fd00::53".parse::<IpAddr>().unwrap()
        );
        assert_eq!(saved.adapters[0].effective.len(), 2);
        let script = restore_script(&saved);
        assert!(script.contains("-ResetServerAddresses"));
        assert!(script.contains("-ServerAddresses $original"));
        assert!(restore_with(&path, &run).unwrap());
        assert!(!path.exists());
        assert!(!restore_with(&path, &NoCommands).unwrap());
    }
    #[test]
    fn failed_restore_retains_record_and_retry_finishes_recovery() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("dns.json");
        let run = Fake {
            fail_restore: AtomicBool::new(true),
        };
        legacy_record(&path);
        assert!(restore_with(&path, &run).is_err());
        assert!(path.exists());
        assert!(read_backup(&path).unwrap().unwrap().restoring);
        run.fail_restore.store(false, Ordering::SeqCst);
        assert!(restore_with(&path, &run).unwrap());
        assert!(!path.exists());
    }
    #[test]
    fn public_dns_migration_and_invalid_records_are_preserved() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("dns.json");
        let run = Fake {
            fail_restore: AtomicBool::new(false),
        };
        std::fs::write(&path, b"[]").unwrap();
        assert!(!restore_with(&path, &run).unwrap());
        assert_eq!(std::fs::read(&path).unwrap(), b"[]");
        std::fs::write(&path, b"broken").unwrap();
        assert!(restore_with(&path, &run).is_err());
        assert_eq!(std::fs::read(&path).unwrap(), b"broken");
        legacy_record(&path);
        let mut saved = read_backup(&path).unwrap().unwrap();
        saved.adapters[0].id = "not-a-guid".into();
        std::fs::write(&path, serde_json::to_vec(&saved).unwrap()).unwrap();
        assert!(restore_with(&path, &run).is_err());
        assert!(path.exists());
    }
}
