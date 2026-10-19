//! Linux DNS OUTPUT interception, including resolved's interface-bound
//! packets. Neither resolver configuration nor the physical LAN routes are
//! changed. A separate native watchdog owns the nft table and removes it
//! on pipe EOF even when the core is killed; Flutter is never involved.

use std::io::{self, BufRead, Write};
use std::process::{Child, Command, Stdio};

use meow_common::outbound_iface::{DnsCaptureBypass, DNS_CAPTURE_MARK};
use tokio::net::{TcpListener, UdpSocket};

pub(super) struct Capture {
    watchdog: Child,
    _bypass: DnsCaptureBypass,
    pub(super) udp: std::sync::Arc<UdpSocket>,
    pub(super) tcp: TcpListener,
    udp6: std::sync::Arc<UdpSocket>,
    tcp6: TcpListener,
}

impl Capture {
    pub(super) async fn setup() -> io::Result<Self> {
        // Replies must originate at the NAT redirect's loopback address.
        // A wildcard socket selects the physical source for a LAN peer,
        // which does not match conntrack's reverse NAT tuple.
        let udp = UdpSocket::bind("127.0.0.1:0").await?;
        let port = udp.local_addr()?.port();
        let tcp = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, port)).await?;
        let udp6 = UdpSocket::bind((std::net::Ipv6Addr::LOCALHOST, port)).await?;
        let tcp6 = TcpListener::bind((std::net::Ipv6Addr::LOCALHOST, port)).await?;
        let bypass = DnsCaptureBypass::install();
        let watchdog = tokio::task::spawn_blocking(move || {
            let mut child = Command::new(std::env::current_exe()?)
                .args(["dns-capture-watch", "--port", &port.to_string()])
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::inherit())
                .spawn()?;
            let mut line = String::new();
            let result = io::BufReader::new(child.stdout.take().unwrap()).read_line(&mut line);
            if result.is_err() || line.trim() != "ready" {
                drop(child.stdin.take());
                let _ = child.wait();
                return Err(io::Error::other(format!(
                    "DNS capture watchdog: {}",
                    line.trim()
                )));
            }
            Ok(child)
        })
        .await
        .map_err(io::Error::other)??;
        Ok(Self {
            watchdog,
            _bypass: bypass,
            udp: std::sync::Arc::new(udp),
            tcp,
            udp6: std::sync::Arc::new(udp6),
            tcp6,
        })
    }

    pub(super) async fn run(mut self, tunnel: meow_tunnel::Tunnel) -> io::Result<()> {
        use meow_common::Network;
        use meow_dns::DnsServer;
        use std::sync::Arc;
        let mut tasks = tokio::task::JoinSet::new();
        let permits = Arc::new(tokio::sync::Semaphore::new(256));
        let mut buf = vec![0; 65535];
        let mut buf6 = vec![0; 65535];
        let mut updates = tokio::time::interval(std::time::Duration::from_secs(2));
        let mut last_bypass = String::new();
        loop {
            tokio::select! {
                _ = updates.tick() => {
                    let bypass = vpn_servers();
                    if bypass != last_bypass {
                        if let Some(pipe) = self.watchdog.stdin.as_mut() {
                            writeln!(pipe, "{bypass}")?;
                        }
                        last_bypass = bypass;
                    }
                    if let Some(status) = self.watchdog.try_wait()? {
                        return Err(io::Error::other(format!("DNS capture watchdog exited: {status}")));
                    }
                }
                packet = async {
                    tokio::select! {
                        packet = self.udp.recv_from(&mut buf) => {
                            let (len, peer) = packet?;
                            Ok::<_, io::Error>((buf[..len].to_vec(), peer, Arc::clone(&self.udp)))
                        }
                        packet = self.udp6.recv_from(&mut buf6) => {
                            let (len, peer) = packet?;
                            Ok((buf6[..len].to_vec(), peer, Arc::clone(&self.udp6)))
                        }
                    }
                } => {
                    let (data, peer, socket) = packet?;
                    let Ok(permit) = Arc::clone(&permits).try_acquire_owned() else { continue };
                    let tunnel = tunnel.clone();
                    tasks.spawn(async move {
                        let _permit = permit;
                        let response = tokio::time::timeout(std::time::Duration::from_secs(5), async {
                            let real = tunnel.inner().is_vpn_client_source(Network::Udp, peer).await;
                            let resolver = tunnel.resolver();
                            if real { DnsServer::handle_query_real(&data, &resolver).await }
                            else { DnsServer::handle_query(&data, &resolver).await }
                        }).await;
                        if let Ok(Ok(answer)) = response { let _ = socket.send_to(&answer, peer).await; }
                    });
                }
                accepted = async {
                    tokio::select! {
                        result = self.tcp.accept() => result,
                        result = self.tcp6.accept() => result,
                    }
                } => {
                    let (mut stream, peer) = accepted?;
                    let Ok(permit) = Arc::clone(&permits).try_acquire_owned() else { continue };
                    let tunnel = tunnel.clone();
                    tasks.spawn(async move {
                        let _permit = permit;
                        let real = tunnel.inner().is_vpn_client_source(Network::Tcp, peer).await;
                        let _ = meow_dns::server::serve_tcp(&mut stream, tunnel.resolver_slot(), real).await;
                    });
                }
                _ = tasks.join_next(), if !tasks.is_empty() => {}
            }
        }
    }
}

impl Drop for Capture {
    fn drop(&mut self) {
        drop(self.watchdog.stdin.take());
        // The watchdog removes the redirect before these sockets close.
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while std::time::Instant::now() < deadline {
            if self.watchdog.try_wait().ok().flatten().is_some() { return; }
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        tracing::warn!("DNS capture watchdog is still cleaning up");
    }
}

fn vpn_servers() -> String {
    use meow_common::route_table::{iface_dns, RouteIfaceKind};
    let mut ips: Vec<_> = iface_dns().iter().filter(|d| d.kind == RouteIfaceKind::OtherVpn)
        .flat_map(|d| d.servers.iter().map(ToString::to_string)).collect();
    ips.sort();
    ips.dedup();
    ips.join(",")
}

fn rules(table: &str, port: u16, bypass: &str) -> String {
    // Only parsed IPs enter the nft program, never untrusted rule text.
    let bypass: String = bypass.split(',').filter_map(|s| s.parse::<std::net::IpAddr>().ok())
        .map(|ip| format!("{} daddr {ip} return\n", if ip.is_ipv4() { "ip" } else { "ip6" }))
        .collect();
    format!("table inet {table} {{\nchain output {{\ntype nat hook output priority -110; policy accept;\nmeta mark & {DNS_CAPTURE_MARK} != 0 return\nip daddr 127.0.0.0/8 return\nip6 daddr ::1 return\n{bypass}meta l4proto {{ tcp, udp }} th dport 53 redirect to :{port}\n}}\nchain input {{\ntype filter hook input priority -110; policy accept;\nmeta l4proto {{ tcp, udp }} th dport {port} ct original proto-dst != 53 drop\n}}\n}}\n")
}

/// Pass the core's existing CAP_NET_ADMIN to nft only. File capabilities
/// normally disappear on exec; adding broad filesystem privileges is not
/// necessary. No shell, scripts, or user-controlled executable is used.
fn nft(args: &[&str], input: Option<&str>) -> io::Result<()> {
    use std::os::unix::process::CommandExt;
    let mut cmd = Command::new("/usr/sbin/nft");
    if !std::path::Path::new("/usr/sbin/nft").exists() {
        cmd = Command::new("/usr/bin/nft");
    }
    cmd.args(args)
        .stdin(if input.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::null())
        .stderr(Stdio::piped());
    // SAFETY: only libc syscalls and stack locals after fork, before exec.
    unsafe {
        cmd.pre_exec(|| {
            #[repr(C)]
            struct Header {
                version: u32,
                pid: i32,
            }
            #[repr(C)]
            #[derive(Clone, Copy)]
            struct Caps {
                effective: u32,
                permitted: u32,
                inheritable: u32,
            }
            let header = Header {
                version: 0x20080522,
                pid: 0,
            };
            let mut data = [Caps {
                effective: 0,
                permitted: 0,
                inheritable: 0,
            }; 2];
            if libc::syscall(libc::SYS_capget, &header, data.as_mut_ptr()) != 0 {
                return Err(io::Error::last_os_error());
            }
            data[0].inheritable |= 1 << 12; // CAP_NET_ADMIN only
            if libc::syscall(libc::SYS_capset, &header, data.as_ptr()) != 0
                || libc::prctl(libc::PR_CAP_AMBIENT, libc::PR_CAP_AMBIENT_RAISE, 12, 0, 0) != 0
            {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let mut child = cmd.spawn()?;
    if let Some(input) = input {
        child.stdin.take().unwrap().write_all(input.as_bytes())?;
    }
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(4);
    while child.try_wait()?.is_none() {
        if std::time::Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            return Err(io::Error::new(io::ErrorKind::TimedOut, "nft command timed out"));
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    let result = child.wait_with_output()?;
    if !result.status.success() {
        return Err(io::Error::other(
            String::from_utf8_lossy(&result.stderr).trim().to_owned(),
        ));
    }
    Ok(())
}

/// Internal binary entry point. Only this process's uniquely named table
/// is created/deleted; EOF on the parent's pipe also covers SIGKILL.
pub fn watch(port: u16) -> io::Result<()> {
    if port == 0 {
        return Err(io::Error::other("invalid DNS capture port"));
    }
    let table = format!("paopao_dns_{}", std::process::id());
    if let Err(e) = nft(&["-f", "-"], Some(&rules(&table, port, &vpn_servers()))) {
        println!("error: {e}");
        return Err(e);
    }
    struct Cleanup(String);
    impl Drop for Cleanup {
        fn drop(&mut self) {
            if let Err(e) = nft(&["delete", "table", "inet", &self.0], None) {
                eprintln!("DNS capture cleanup failed: {e}");
            }
        }
    }
    let _cleanup = Cleanup(table.clone());
    println!("ready");
    io::stdout().flush()?;
    // The parent publishes VPN DNS changes without restarting the core.
    // This side has no in-process route snapshot of its own.
    for line in io::stdin().lock().lines() {
        let Ok(line) = line else { break };
        let replacement = format!("delete table inet {table}\n{}", rules(&table, port, &line));
        if let Err(e) = nft(&["-f", "-"], Some(&replacement)) {
            eprintln!("DNS capture VPN bypass update failed: {e}");
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn capture_only_dns_and_keep_own_upstream_out() {
        let text = rules("paopao_dns_test", 1053, "10.8.0.1,fd00::53,invalid; drop");
        assert!(text.contains("meta l4proto { tcp, udp } th dport 53"));
        assert!(text.find("meta mark").unwrap() < text.find("redirect").unwrap());
        assert!(!text.contains("223.5.5.5"));
        assert!(text.contains("ip daddr 10.8.0.1 return"));
        assert!(!text.contains("invalid; drop"));
    }
}
