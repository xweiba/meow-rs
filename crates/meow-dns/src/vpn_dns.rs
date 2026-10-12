//! PaoPao: names that belong to another VPN are passed through to that
//! VPN's DNS untouched.
//!
//! With our TUN up every query lands on our resolver, so "do not
//! interfere" has to be done on purpose: a name under one of the other
//! VPN's search / routing domains (see
//! [`meow_common::route_table::vpn_dns_for`]) is sent as received to the
//! VPN's own servers, out of the VPN's interface, and the answer goes back
//! as received — no fake IP, no hosts entry, no nameserver policy, no
//! cache, whatever the proxy mode.

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;

use hickory_proto::op::{Message, MessageType, OpCode, Query, ResponseCode};
use hickory_proto::rr::{Name, RData, RecordType};
use meow_common::route_table::VpnDns;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tracing::debug;

/// How long one server gets before the next is tried.
#[cfg(not(test))]
const PER_SERVER: Duration = Duration::from_secs(2);
#[cfg(test)]
const PER_SERVER: Duration = Duration::from_millis(300);
/// Servers tried per query.
const MAX_SERVERS: usize = 3;
/// Largest answer accepted over UDP.
const UDP_BUF: usize = 4096;

/// The other VPN's DNS for `domain`, if the name is one of its own.
pub fn target_for(domain: &str) -> Option<VpnDns> {
    meow_common::route_table::vpn_dns_for(domain)
}

/// Send `query` (a complete DNS message) to the VPN's servers in order and
/// return the first answer, byte for byte. `None` when no server answered.
pub async fn forward(query: &[u8], target: &VpnDns) -> Option<Vec<u8>> {
    let servers: Vec<SocketAddr> = target
        .servers
        .iter()
        .map(|ip| SocketAddr::new(*ip, 53))
        .collect();
    forward_to(query, &servers, target.iface.as_deref()).await
}

async fn forward_to(query: &[u8], servers: &[SocketAddr], iface: Option<&str>) -> Option<Vec<u8>> {
    if query.len() < 12 {
        return None;
    }
    for &server in servers.iter().take(MAX_SERVERS) {
        match exchange(query, server, iface).await {
            Ok(answer) => return Some(answer),
            Err(e) => debug!(
                "vpn dns: {server} via {} did not answer: {e}",
                iface.unwrap_or("the routed interface")
            ),
        }
    }
    None
}

/// UDP first; a truncated answer is asked again over TCP (the truncated
/// one is returned when TCP fails too — the client can retry itself).
///
/// Never spread over `tun.outbound-interfaces`, and kept out of the dial
/// scope of a connection that asked from inside its own dial.
async fn exchange(query: &[u8], server: SocketAddr, iface: Option<&str>) -> io::Result<Vec<u8>> {
    meow_common::outbound_balance::scoped(
        meow_common::outbound_balance::DialScope::unbalanced(),
        exchange_unscoped(query, server, iface),
    )
    .await
}

async fn exchange_unscoped(
    query: &[u8],
    server: SocketAddr,
    iface: Option<&str>,
) -> io::Result<Vec<u8>> {
    let answer = tokio::time::timeout(PER_SERVER, udp_exchange(query, server, iface))
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "no answer over UDP"))??;
    if answer[2] & 0x02 == 0 {
        return Ok(answer);
    }
    match tokio::time::timeout(PER_SERVER, tcp_exchange(query, server, iface)).await {
        Ok(Ok(full)) => Ok(full),
        _ => Ok(answer),
    }
}

async fn udp_exchange(
    query: &[u8],
    server: SocketAddr,
    iface: Option<&str>,
) -> io::Result<Vec<u8>> {
    let local: SocketAddr = if server.is_ipv4() {
        (Ipv4Addr::UNSPECIFIED, 0).into()
    } else {
        (Ipv6Addr::UNSPECIFIED, 0).into()
    };
    let socket = match iface {
        Some(name) => meow_common::outbound_iface::bind_udp_on(local, name)?,
        None => meow_common::bind_udp_to(local, server).await?,
    };
    socket.send_to(query, server).await?;
    let mut buf = vec![0u8; UDP_BUF];
    loop {
        let (n, from) = socket.recv_from(&mut buf).await?;
        // Our id, a response, from the server asked.
        if n >= 12
            && from.port() == server.port()
            && from.ip() == server.ip()
            && buf[..2] == query[..2]
            && buf[2] & 0x80 != 0
        {
            buf.truncate(n);
            return Ok(buf);
        }
    }
}

async fn tcp_exchange(
    query: &[u8],
    server: SocketAddr,
    iface: Option<&str>,
) -> io::Result<Vec<u8>> {
    let mut stream = match iface {
        Some(name) => meow_common::outbound_iface::connect_tcp_on(server, name).await?,
        None => meow_common::socket_protect::connect_tcp(server).await?,
    };
    let len = u16::try_from(query.len())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "query too long"))?;
    let mut framed = Vec::with_capacity(query.len() + 2);
    framed.extend_from_slice(&len.to_be_bytes());
    framed.extend_from_slice(query);
    stream.write_all(&framed).await?;
    let mut len = [0u8; 2];
    stream.read_exact(&mut len).await?;
    let mut answer = vec![0u8; usize::from(u16::from_be_bytes(len))];
    stream.read_exact(&mut answer).await?;
    if answer.len() < 12 || answer[..2] != query[..2] {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "answer does not match the query",
        ));
    }
    Ok(answer)
}

/// What one family's lookup at the VPN's DNS came to.
pub(crate) enum FamilyAnswer {
    /// Addresses and the smallest TTL among them.
    Addrs(Vec<IpAddr>, Duration),
    NoData,
    NxDomain,
    Failed,
}

/// Ask the VPN's DNS for one address family of `host` — for the kernel's
/// own dials (a program using the proxy port names an intranet host).
pub(crate) async fn lookup_family(host: &str, rtype: RecordType, target: &VpnDns) -> FamilyAnswer {
    let Ok(name) = Name::from_utf8(host) else {
        return FamilyAnswer::Failed;
    };
    let mut msg = Message::new(rand::random(), MessageType::Query, OpCode::Query);
    msg.metadata.recursion_desired = true;
    msg.add_query(Query::query(name, rtype));
    let Ok(query) = msg.to_vec() else {
        return FamilyAnswer::Failed;
    };
    let Some(raw) = forward(&query, target).await else {
        return FamilyAnswer::Failed;
    };
    let Ok(resp) = Message::from_vec(&raw) else {
        return FamilyAnswer::Failed;
    };
    match resp.metadata.response_code {
        ResponseCode::NoError => {}
        ResponseCode::NXDomain => return FamilyAnswer::NxDomain,
        _ => return FamilyAnswer::Failed,
    }
    let mut ttl = u32::MAX;
    let addrs: Vec<IpAddr> = resp
        .answers
        .iter()
        .filter_map(|rec| {
            let ip = match (&rec.data, rtype) {
                (RData::A(a), RecordType::A) => IpAddr::V4(a.0),
                (RData::AAAA(a), RecordType::AAAA) => IpAddr::V6(a.0),
                _ => return None,
            };
            ttl = ttl.min(rec.ttl);
            Some(ip)
        })
        .collect();
    if addrs.is_empty() {
        FamilyAnswer::NoData
    } else {
        FamilyAnswer::Addrs(addrs, Duration::from_secs(u64::from(ttl.max(1))))
    }
}

/// Every address of `host` at the VPN's DNS (`ipv6` adds AAAA).
/// `Ok(None)`: the name does not exist there; `Err`: nobody answered.
pub(crate) async fn resolve(
    host: &str,
    ipv6: bool,
    target: &VpnDns,
) -> io::Result<Option<Vec<IpAddr>>> {
    let v4 = lookup_family(host, RecordType::A, target);
    let (v4, v6) = if ipv6 {
        let (a, b) = tokio::join!(v4, lookup_family(host, RecordType::AAAA, target));
        (a, Some(b))
    } else {
        (v4.await, None)
    };
    let mut ips = Vec::new();
    let mut failed = false;
    for answer in [Some(v4), v6].into_iter().flatten() {
        match answer {
            FamilyAnswer::Addrs(addrs, _) => ips.extend(addrs),
            FamilyAnswer::Failed => failed = true,
            FamilyAnswer::NoData | FamilyAnswer::NxDomain => {}
        }
    }
    if !ips.is_empty() {
        Ok(Some(ips))
    } else if failed {
        Err(io::Error::other(format!(
            "the other VPN's DNS did not answer for {host}"
        )))
    } else {
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_proto::rr::rdata::A;
    use hickory_proto::rr::Record;
    use tokio::net::{TcpListener, UdpSocket};

    fn query(name: &str, id: u16) -> Vec<u8> {
        let mut msg = Message::new(id, MessageType::Query, OpCode::Query);
        msg.metadata.recursion_desired = true;
        msg.add_query(Query::query(name.parse().unwrap(), RecordType::A));
        msg.to_vec().unwrap()
    }

    fn answer(req: &[u8], ip: [u8; 4], truncated: bool) -> Vec<u8> {
        let req = Message::from_vec(req).unwrap();
        let mut resp = Message::new(req.metadata.id, MessageType::Response, OpCode::Query);
        resp.metadata.truncation = truncated;
        resp.add_queries(req.queries.iter().cloned());
        if !truncated {
            resp.add_answer(Record::from_rdata(
                req.queries[0].name.clone(),
                77,
                RData::A(A(Ipv4Addr::from(ip))),
            ));
        }
        resp.to_vec().unwrap()
    }

    /// A UDP server on loopback answering every A query with `ip`
    /// (`truncate`: TC set, no records).
    async fn udp_server(ip: [u8; 4], truncate: bool) -> SocketAddr {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = socket.local_addr().unwrap();
        tokio::spawn(async move {
            let mut buf = [0u8; 1500];
            while let Ok((n, from)) = socket.recv_from(&mut buf).await {
                let _ = socket.send_to(&answer(&buf[..n], ip, truncate), from).await;
            }
        });
        addr
    }

    #[tokio::test]
    async fn the_answer_comes_back_byte_for_byte() {
        let server = udp_server([10, 8, 0, 7], false).await;
        let q = query("git.corp.example.", 0x4242);
        let raw = forward_to(&q, &[server], None).await.expect("answered");
        assert_eq!(raw, answer(&q, [10, 8, 0, 7], false));
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn the_query_leaves_by_the_named_interface() {
        let server = udp_server([10, 8, 0, 9], false).await;
        let q = query("wiki.corp.example.", 7);
        // `lo` is the one interface a test can count on.
        let raw = forward_to(&q, &[server], Some("lo"))
            .await
            .expect("answered");
        let resp = Message::from_vec(&raw).unwrap();
        assert_eq!(resp.metadata.id, 7);
        assert_eq!(resp.answers.len(), 1);
    }

    #[tokio::test]
    async fn a_dead_server_is_skipped_and_none_means_nobody_answered() {
        // A bound socket nobody reads from never answers.
        let dead = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let dead_addr = dead.local_addr().unwrap();
        let live = udp_server([10, 8, 0, 1], false).await;
        let q = query("a.corp.example.", 9);
        let raw = forward_to(&q, &[dead_addr, live], None).await;
        assert!(raw.is_some());
        assert!(forward_to(&q, &[dead_addr], None).await.is_none());
    }

    #[tokio::test]
    async fn a_truncated_answer_is_asked_again_over_tcp() {
        // Same port for UDP (truncating) and TCP (full answer).
        let tcp = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = tcp.local_addr().unwrap();
        let udp = UdpSocket::bind(addr).await.unwrap();
        tokio::spawn(async move {
            let mut buf = [0u8; 1500];
            while let Ok((n, from)) = udp.recv_from(&mut buf).await {
                let _ = udp.send_to(&answer(&buf[..n], [0; 4], true), from).await;
            }
        });
        tokio::spawn(async move {
            while let Ok((mut s, _)) = tcp.accept().await {
                let mut len = [0u8; 2];
                s.read_exact(&mut len).await.unwrap();
                let mut q = vec![0u8; usize::from(u16::from_be_bytes(len))];
                s.read_exact(&mut q).await.unwrap();
                let a = answer(&q, [10, 8, 0, 3], false);
                s.write_all(&(a.len() as u16).to_be_bytes()).await.unwrap();
                s.write_all(&a).await.unwrap();
            }
        });
        let q = query("big.corp.example.", 11);
        let raw = forward_to(&q, &[addr], None).await.expect("answered");
        let resp = Message::from_vec(&raw).unwrap();
        assert!(!resp.metadata.truncation);
        assert_eq!(resp.answers.len(), 1);
    }
}
