//! DNS follows domain routing; only weak tunnel ownership crosses into DNS.
use crate::tunnel::{ResolvedTarget, TunnelInner};
use meow_common::{AdapterType, Metadata, Proxy};
use meow_dns::domain_route::{DomainRoute, DomainRouter, RouteFuture};
use std::{
    io,
    sync::{Arc, Weak},
};

pub(crate) struct RoutedDns(pub Weak<TunnelInner>);

impl ResolvedTarget {
    /// Select exactly once for a locally-resolved UDP dial, preserving the
    /// names along that same traversal. Reconstructing them later could see
    /// a changed selector or advance round-robin a second time. Relay is a
    /// complete path and must never be reduced to only its terminal hop.
    pub(crate) fn pin_dns_leaf(
        &mut self,
        metadata: &Metadata,
        touch: bool,
    ) -> io::Result<Option<Arc<dyn Proxy>>> {
        let mut chains = smallvec::smallvec![Arc::from(self.adapter.name())];
        let mut leaf = self.route.proxies.get(self.adapter.name()).cloned();
        if leaf.is_none() {
            leaf = self.adapter.unwrap_proxy(metadata, touch);
            if let Some(next) = &leaf {
                chains.push(Arc::from(next.name()));
            }
        }
        let Some(mut current) = leaf else {
            self.chains = chains;
            return Ok(None);
        };
        for _ in 0..16 {
            if current.adapter_type() == AdapterType::Relay {
                self.adapter = Arc::clone(&current) as Arc<dyn meow_common::ProxyAdapter>;
                chains.reverse();
                self.chains = chains;
                return Ok(Some(current));
            }
            match current.unwrap_proxy(metadata, touch) {
                Some(next) => {
                    chains.push(Arc::from(next.name()));
                    current = next;
                }
                None => {
                    self.adapter = Arc::clone(&current) as Arc<dyn meow_common::ProxyAdapter>;
                    chains.reverse();
                    self.chains = chains;
                    return Ok(Some(current));
                }
            }
        }
        Err(io::Error::other("DNS proxy selection exceeded group depth"))
    }
}

impl DomainRouter for RoutedDns {
    fn route<'a>(&'a self, domain: &'a str) -> RouteFuture<'a> {
        Box::pin(async move {
            let inner = self
                .0
                .upgrade()
                .ok_or_else(|| io::Error::other("DNS tunnel stopped"))?;
            // DNS has a domain but no application port/process context.
            // Fake-IP defers those decisions to the actual connection.
            let mut metadata = Metadata {
                host: domain.into(),
                internal: true,
                ..Default::default()
            };
            let mut target =
                meow_dns::domain_route::classify(inner.resolve_proxy_lazy(&mut metadata))
                    .await
                    .ok_or_else(|| io::Error::other("no DNS route"))?;
            let leaf = target.pin_dns_leaf(&metadata, false)?;
            match target.adapter.adapter_type() {
                AdapterType::Direct | AdapterType::Compatible => Ok(DomainRoute::Direct {
                    interface: target.adapter.dns_interface(),
                }),
                AdapterType::Reject | AdapterType::RejectDrop | AdapterType::PassRule => {
                    Ok(DomainRoute::Reject)
                }
                _ => Ok(DomainRoute::Proxy {
                    proxy: leaf
                        .ok_or_else(|| io::Error::other("DNS route has no concrete proxy"))?,
                    generation: target.route,
                }),
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Tunnel;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// Two loopback SOCKS servers give different DNS answers and echo UDP.
    /// The listener task owns its children, including persistent DNS streams.
    struct TestNode {
        port: u16,
        dns_queries: Arc<AtomicUsize>,
        udp_targets: Arc<parking_lot::Mutex<Vec<IpAddr>>>,
        tasks: Vec<tokio::task::JoinHandle<()>>,
    }

    impl Drop for TestNode {
        fn drop(&mut self) {
            for task in &self.tasks {
                task.abort();
            }
        }
    }

    async fn test_node(number: u8) -> TestNode {
        let tcp = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = tcp.local_addr().unwrap().port();
        let udp = Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let udp_addr = udp.local_addr().unwrap();
        let dns_queries = Arc::new(AtomicUsize::new(0));
        let udp_targets = Arc::new(parking_lot::Mutex::new(Vec::new()));
        let dns_task = tokio::spawn({
            let dns_queries = Arc::clone(&dns_queries);
            async move {
                let mut children = tokio::task::JoinSet::new();
                loop {
                    tokio::select! {
                        accepted = tcp.accept() => {
                            let (mut socket, _) = accepted.unwrap();
                            let dns_queries = Arc::clone(&dns_queries);
                            children.spawn(async move {
                                assert_eq!(socket.read_u8().await.unwrap(), 5);
                                let methods = socket.read_u8().await.unwrap();
                                let mut methods = vec![0; usize::from(methods)];
                                socket.read_exact(&mut methods).await.unwrap();
                                socket.write_all(&[5, 0]).await.unwrap();
                                let mut request = [0; 4];
                                socket.read_exact(&mut request).await.unwrap();
                                assert_eq!(request[0], 5);
                                let address_len = match request[3] {
                                    1 => 4,
                                    3 => usize::from(socket.read_u8().await.unwrap()),
                                    4 => 16,
                                    kind => panic!("unexpected SOCKS address kind: {kind}"),
                                };
                                let mut destination = vec![0; address_len];
                                socket.read_exact(&mut destination).await.unwrap();
                                let destination_port = socket.read_u16().await.unwrap();
                                let reply_port = if request[1] == 3 { udp_addr.port() } else { 0 };
                                let mut reply = vec![5, 0, 0, 1, 127, 0, 0, 1];
                                reply.extend_from_slice(&reply_port.to_be_bytes());
                                socket.write_all(&reply).await.unwrap();
                                if request[1] == 3 {
                                    let mut buf = Vec::new();
                                    let _ = socket.read_to_end(&mut buf).await;
                                    return;
                                }
                                assert_eq!(request[1], 1);
                                assert_eq!(destination_port, 53);
                                while let Ok(len) = socket.read_u16().await {
                                    let mut response = vec![0; usize::from(len)];
                                    socket.read_exact(&mut response).await.unwrap();
                                    assert_eq!(&response[response.len() - 4..], &[0, 1, 0, 1]);
                                    dns_queries.fetch_add(1, Ordering::SeqCst);
                                    response[2..4].copy_from_slice(&[0x81, 0x80]);
                                    response[6..12].copy_from_slice(&[0, 1, 0, 0, 0, 0]);
                                    response.extend_from_slice(&[
                                        0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4,
                                        203, 0, 113, number,
                                    ]);
                                    socket.write_u16(response.len() as u16).await.unwrap();
                                    socket.write_all(&response).await.unwrap();
                                }
                            });
                        }
                        Some(done) = children.join_next(), if !children.is_empty() => done.unwrap(),
                    }
                }
            }
        });
        let udp_task = tokio::spawn({
            let udp_targets = Arc::clone(&udp_targets);
            async move {
                let mut buf = [0; 1024];
                loop {
                    let (len, peer) = udp.recv_from(&mut buf).await.unwrap();
                    assert_eq!(&buf[..4], &[0, 0, 0, 1]);
                    udp_targets
                        .lock()
                        .push(IpAddr::V4(Ipv4Addr::new(buf[4], buf[5], buf[6], buf[7])));
                    udp.send_to(&buf[..len], peer).await.unwrap();
                }
            }
        });
        TestNode {
            port,
            dns_queries,
            udp_targets,
            tasks: vec![dns_task, udp_task],
        }
    }

    #[tokio::test]
    async fn pinned_dns_and_udp_share_one_selection_and_retain_all_upper_groups() {
        tokio::time::timeout(Duration::from_secs(10), async {
            let first = test_node(11).await;
            let second = test_node(12).await;
            let raw = meow_config::parse_raw_yaml(&format!(
                r#"
ipv6: false
dns:
  enable: true
  nameserver: [tcp://192.0.2.53:53]
  direct-nameserver: [system]
  follow-domain-rules: true
proxies:
  - {{name: first, type: socks5, server: 127.0.0.1, port: {}, udp: true}}
  - {{name: second, type: socks5, server: 127.0.0.1, port: {}, udp: true}}
proxy-groups:
  - {{name: balance, type: load-balance, strategy: round-robin, proxies: [first, second]}}
  - {{name: choice, type: select, proxies: [balance]}}
  - {{name: policy:ai, type: select, proxies: [choice, second]}}
rules: ["MATCH,policy:ai"]
"#,
                first.port, second.port
            ))
            .unwrap();
            let config = meow_config::build_config(raw, None).await.unwrap();
            let selector = Arc::clone(config.proxies.get("policy:ai").unwrap());
            let tunnel = Tunnel::new_with_slot(Arc::clone(&config.dns.resolver_slot));
            tunnel.update_routing(config.proxies, config.rules, config.dialer_registry);
            for i in 0..4 {
                let mut metadata = Metadata {
                    network: meow_common::Network::Udp,
                    host: format!("pinned-{i}.test").into(),
                    dst_port: 3478,
                    ..Default::default()
                };
                let target = tunnel
                    .inner()
                    .resolve_udp_route(&mut metadata)
                    .await
                    .unwrap();
                let (name, number, node) = if i % 2 == 0 {
                    ("first", 11, &first)
                } else {
                    ("second", 12, &second)
                };
                let expected = vec![name, "balance", "choice", "policy:ai"];
                assert_eq!(target.adapter.name(), name);
                assert_eq!(
                    target.chains.iter().map(|s| &**s).collect::<Vec<_>>(),
                    expected
                );
                let dst = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, number)), 3478);
                assert_eq!(metadata.dst_ip, Some(dst.ip()));
                // A user selection changes while the already-resolved UDP
                // flow starts: neither the path nor the node may be rebuilt.
                selector.selection().unwrap().set("second").await.unwrap();
                let conn = crate::udp::dial_tracked_udp(tunnel.inner(), &metadata, target)
                    .await
                    .unwrap();
                conn.write_packet(b"hello", &dst).await.unwrap();
                let mut buf = [0; 32];
                let (len, _) = conn.read_packet(&mut buf).await.unwrap();
                assert_eq!(&buf[..len], b"hello");
                assert_eq!(node.udp_targets.lock().last(), Some(&dst.ip()));
                let info = tunnel.statistics().active_connections().pop().unwrap();
                assert_eq!(
                    info.chains.iter().map(|s| &**s).collect::<Vec<_>>(),
                    expected
                );
                assert_eq!(info.rule, "MATCH");
                drop(conn);
                assert_eq!(tunnel.statistics().active_connection_count(), 0);
                let ended = tunnel
                    .statistics()
                    .history()
                    .delta(0)
                    .changed
                    .pop()
                    .unwrap();
                assert_eq!(
                    ended.chains.iter().map(|s| &**s).collect::<Vec<_>>(),
                    expected
                );
                selector.selection().unwrap().set("choice").await.unwrap();
            }
            // Every fresh domain was answered by its UDP node exactly once;
            // four flows alternate instead of consuming two RR picks each.
            assert_eq!(first.dns_queries.load(Ordering::SeqCst), 2);
            assert_eq!(second.dns_queries.load(Ordering::SeqCst), 2);
            assert_eq!(first.udp_targets.lock().len(), 2);
            assert_eq!(second.udp_targets.lock().len(), 2);
        })
        .await
        .expect("DNS and UDP path test must complete without leaking tasks");
    }

    #[tokio::test]
    async fn cached_dns_view_does_not_retain_its_parent_tunnel_or_resolver() {
        let raw = meow_config::parse_raw_yaml(
            r#"
dns:
  enable: true
  nameserver: [tcp://192.0.2.53:53]
  direct-nameserver: [system]
  follow-domain-rules: true
proxies:
  - {name: node, type: socks5, server: 127.0.0.1, port: 1}
rules: ["MATCH,node"]
"#,
        )
        .unwrap();
        let config = meow_config::build_config(raw, None).await.unwrap();
        let resolver = Arc::clone(&config.dns.resolver);
        let weak_resolver = Arc::downgrade(&resolver);
        let tunnel = Tunnel::new_with_slot(Arc::clone(&config.dns.resolver_slot));
        tunnel.update_routing(config.proxies, config.rules, config.dialer_registry);
        let weak_tunnel = tunnel.weak_inner();
        let result = tokio::time::timeout(
            std::time::Duration::from_secs(3),
            resolver.resolve_ips("uncached.test"),
        )
        .await;
        assert!(
            result.unwrap().is_err(),
            "closed test proxy must refuse; no direct DNS fallback"
        );
        drop(config.dns);
        drop(resolver);
        drop(tunnel);
        assert!(weak_tunnel.upgrade().is_none());
        assert!(
            weak_resolver.upgrade().is_none(),
            "a DNS view must not own the route registry that owns its resolver slot"
        );
    }
}
