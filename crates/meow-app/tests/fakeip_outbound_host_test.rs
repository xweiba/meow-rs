//! A connection to a fake IP reaches the line as the name, not an address
//! (box LAN test: "github.com went to the line as an IP").
//!
//! The chain under test is the TUN's: a fake-ip DNS answer, then a TCP flow
//! to that address through the tunnel's shared inbound tail
//! (`route_inbound_tcp`, what the TUN listener calls), an IP rule that makes
//! the core resolve the name locally first, then the line. The line is a
//! loopback SOCKS5 server that records the CONNECT target, and the local
//! resolution goes to a loopback DNS server answering a fixed address —
//! nothing leaves the machine.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use meow_common::{ConnType, Metadata, Network};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};

/// Answers every A query with `ip` (TTL 60); counts the queries.
async fn spawn_dns(ip: Ipv4Addr) -> (SocketAddr, Arc<AtomicUsize>) {
    let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = sock.local_addr().unwrap();
    let asked = Arc::new(AtomicUsize::new(0));
    tokio::spawn({
        let asked = Arc::clone(&asked);
        async move {
            let mut buf = [0u8; 1500];
            while let Ok((n, from)) = sock.recv_from(&mut buf).await {
                let q = &buf[..n];
                if n < 12 {
                    continue;
                }
                // End of the (uncompressed) question name, then type+class.
                let mut at = 12;
                while at < n && q[at] != 0 {
                    at += 1 + usize::from(q[at]);
                }
                let end = at + 5;
                if end > n {
                    continue;
                }
                let qtype = u16::from_be_bytes([q[at + 1], q[at + 2]]);
                asked.fetch_add(1, Ordering::SeqCst);
                let mut a = q[..end].to_vec();
                a[2] = 0x81;
                a[3] = 0x80;
                a[8..12].fill(0); // no authority / additional
                if qtype == 1 {
                    a[6..8].copy_from_slice(&1u16.to_be_bytes());
                    a.extend_from_slice(&[0xc0, 12, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4]);
                    a.extend_from_slice(&ip.octets());
                } else {
                    a[6..8].fill(0);
                }
                let _ = sock.send_to(&a, from).await;
            }
        }
    });
    (addr, asked)
}

/// A SOCKS5 server (no auth) that reports each CONNECT target as
/// `host:port` (a domain target) or `ip:port` (an address target), then
/// holds the connection.
async fn spawn_line() -> (SocketAddr, tokio::sync::mpsc::UnboundedReceiver<String>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
    tokio::spawn(async move {
        while let Ok((mut s, _)) = listener.accept().await {
            let tx = tx.clone();
            tokio::spawn(async move {
                let mut head = [0u8; 2];
                s.read_exact(&mut head).await.ok()?;
                let mut methods = vec![0u8; usize::from(head[1])];
                s.read_exact(&mut methods).await.ok()?;
                s.write_all(&[5, 0]).await.ok()?;
                let mut req = [0u8; 4];
                s.read_exact(&mut req).await.ok()?;
                let host = match req[3] {
                    1 => {
                        let mut ip = [0u8; 4];
                        s.read_exact(&mut ip).await.ok()?;
                        Ipv4Addr::from(ip).to_string()
                    }
                    3 => {
                        let mut len = [0u8; 1];
                        s.read_exact(&mut len).await.ok()?;
                        let mut name = vec![0u8; usize::from(len[0])];
                        s.read_exact(&mut name).await.ok()?;
                        String::from_utf8(name).ok()?
                    }
                    _ => return None,
                };
                let mut port = [0u8; 2];
                s.read_exact(&mut port).await.ok()?;
                let _ = tx.send(format!("{host}:{}", u16::from_be_bytes(port)));
                s.write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0]).await.ok()?;
                let mut sink = [0u8; 1024];
                while s.read(&mut sink).await.ok()? > 0 {}
                Some(())
            });
        }
    });
    (addr, rx)
}

/// The core as the box runs it, in miniature: fake-ip DNS, one line, an IP
/// rule ahead of the line's catch-all.
struct Core {
    tunnel: meow_tunnel::Tunnel,
    /// CONNECT targets the line was asked for.
    targets: tokio::sync::mpsc::UnboundedReceiver<String>,
    /// Queries the core's local resolver sent.
    asked: Arc<AtomicUsize>,
}

async fn core() -> Core {
    let (dns, asked) = spawn_dns(Ipv4Addr::new(9, 9, 9, 9)).await;
    let (line, targets) = spawn_line().await;
    // `IP-CIDR` without `no-resolve`: the core resolves the name locally to
    // match it (9.9.9.9 is not in 10/8) — the line must still get the name.
    let raw: meow_config::raw::RawConfig = serde_yaml::from_str(&format!(
        "mode: rule\n\
         dns:\n  enable: true\n  enhanced-mode: fake-ip\n  fake-ip-range: 198.18.0.1/16\n  \
         nameserver:\n    - {dns}\n\
         proxies:\n  - {{name: line, type: socks5, server: 127.0.0.1, port: {}}}\n\
         rules:\n  - IP-CIDR,10.0.0.0/8,DIRECT\n  - MATCH,line\n",
        line.port()
    ))
    .unwrap();
    let dns_cfg = meow_config::parse_dns_from_raw(
        &raw,
        None,
        &HashMap::new(),
        Some(&HashMap::new()),
        None,
        None,
        None,
    )
    .await
    .unwrap();
    let tunnel = meow_tunnel::Tunnel::new(Arc::clone(&dns_cfg.resolver));
    let built = meow_config::rebuild_from_raw_with_resolver(
        &raw,
        Some(&tunnel.resolver_slot()),
        None,
        &HashMap::new(),
        None,
    )
    .unwrap();
    tunnel.update_routing(built.proxies, built.rules, built.dialer_registry);
    Core {
        tunnel,
        targets,
        asked,
    }
}

/// Hands a TUN flow described by `metadata` to the tunnel; the target the
/// line is asked for.
async fn line_target(core: &mut Core, metadata: Metadata) -> String {
    let server = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let (accepted, client) = tokio::join!(
        server.accept(),
        TcpStream::connect(server.local_addr().unwrap())
    );
    let (mut inbound, _) = accepted.unwrap();
    let client = client.unwrap();
    let inner = Arc::clone(core.tunnel.inner());
    tokio::spawn(async move {
        let _client = client;
        meow_tunnel::route_inbound_tcp(&inner, &mut inbound, metadata, &[]).await;
    });
    tokio::time::timeout(std::time::Duration::from_secs(10), core.targets.recv())
        .await
        .expect("the line was dialed")
        .unwrap()
}

fn tun_flow(dst: IpAddr) -> Metadata {
    Metadata {
        network: Network::Tcp,
        conn_type: ConnType::Tun,
        src_ip: Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 114))),
        src_port: 40000,
        dst_ip: Some(dst),
        dst_port: 443,
        ..Default::default()
    }
}

#[tokio::test]
async fn fake_ip_flow_reaches_the_line_as_the_name() {
    let mut core = core().await;
    // The device's DNS answer: a fake address from the core's pool.
    let fake = core
        .tunnel
        .resolver()
        .lookup_ipv4("github.com")
        .await
        .unwrap();
    assert!(core.tunnel.resolver().in_fake_ip_range(fake), "{fake}");
    // The device connects to it; the TUN hands the flow over by address.
    let target = line_target(&mut core, tun_flow(fake)).await;
    assert_eq!(target, "github.com:443", "the line gets the name");
    assert!(
        core.asked.load(Ordering::SeqCst) > 0,
        "the IP rule made the core resolve the name locally"
    );
}

/// What the box test saw: a device that connects to a real address (an
/// answer it got before routing through the box). Without a name the line
/// can only get the address (mihomo does the same); once the TUN's sniffer
/// has put the ClientHello's site in `host` (`override-destination`), the
/// line gets the site.
#[tokio::test]
async fn real_address_flow_reaches_the_line_by_sniffed_name() {
    let mut core = core().await;
    let real: IpAddr = "20.205.243.166".parse().unwrap();
    assert_eq!(
        line_target(&mut core, tun_flow(real)).await,
        "20.205.243.166:443",
        "no name: the address"
    );
    let mut sniffed = tun_flow(real);
    sniffed.sniff_host = "github.com".into();
    sniffed.host = "github.com".into();
    assert_eq!(line_target(&mut core, sniffed).await, "github.com:443");
}
