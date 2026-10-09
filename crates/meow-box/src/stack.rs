//! The box's own small IP stack (smoltcp): answers ARP for its address and
//! ping, and accepts TCP on the service ports (80: the config page, 53: DNS
//! over TCP). Each accepted connection is handed to a handler task as a
//! pair of channels ([`ConnIo`]).

use std::collections::{HashMap, VecDeque};
use std::net::Ipv4Addr;
use std::sync::Arc;

use smoltcp::iface::{Config, Interface, SocketHandle, SocketSet};
use smoltcp::phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken};
use smoltcp::socket::tcp;
use smoltcp::time::{Duration as SDuration, Instant as SInstant};
use smoltcp::wire::{EthernetAddress, HardwareAddress, IpAddress, IpCidr};
use tokio::sync::{mpsc, Notify};

use crate::frame::Mac;
use crate::switch::Addr;

/// Listening sockets kept open per port (smoltcp has no backlog: each
/// listener becomes one connection, and a new one takes its place).
const LISTENERS: usize = 4;
/// Most connections at once (the page and DNS over TCP are light).
const MAX_CONNS: usize = 64;
const BUF: usize = 64 * 1024;
/// A handler that queues more than this towards a slow client is cut off.
const MAX_PENDING_OUT: usize = 4 << 20;
/// Bytes read from a connection per message to its handler.
const CHUNK: usize = 16 * 1024;

/// smoltcp's view of the wire: frames queued in, frames collected out.
/// The stack hands it one received frame per poll, so a burst of SYNs
/// finds a fresh listener for each.
#[derive(Debug, Default)]
struct Queue {
    rx: VecDeque<Vec<u8>>,
    tx: Vec<Vec<u8>>,
}

struct Rx(Vec<u8>);
struct Tx<'a>(&'a mut Vec<Vec<u8>>);

impl RxToken for Rx {
    fn consume<R, F: FnOnce(&[u8]) -> R>(self, f: F) -> R {
        f(&self.0)
    }
}

impl TxToken for Tx<'_> {
    fn consume<R, F: FnOnce(&mut [u8]) -> R>(self, len: usize, f: F) -> R {
        let mut buf = vec![0u8; len];
        let r = f(&mut buf);
        self.0.push(buf);
        r
    }
}

impl Device for Queue {
    type RxToken<'a> = Rx;
    type TxToken<'a> = Tx<'a>;

    fn receive(&mut self, _: SInstant) -> Option<(Rx, Tx<'_>)> {
        let f = self.rx.pop_front()?;
        Some((Rx(f), Tx(&mut self.tx)))
    }

    fn transmit(&mut self, _: SInstant) -> Option<Tx<'_>> {
        Some(Tx(&mut self.tx))
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut c = DeviceCapabilities::default();
        c.medium = Medium::Ethernet;
        c.max_transmission_unit = 1514;
        c
    }
}

/// What a handler sends back to the stack.
#[derive(Debug)]
enum Back {
    Data(SocketHandle, Vec<u8>),
    /// The handler is done: close once its data is out.
    Close(SocketHandle),
}

/// A connection as its handler sees it.
#[derive(Debug)]
pub struct ConnIo {
    /// The device's address.
    pub peer: Ipv4Addr,
    /// The box's port it connected to.
    pub port: u16,
    rx: mpsc::Receiver<Vec<u8>>,
    back: mpsc::UnboundedSender<Back>,
    wake: Arc<Notify>,
    handle: SocketHandle,
}

impl ConnIo {
    /// The next bytes from the device; None once it closed its side.
    pub async fn recv(&mut self) -> Option<Vec<u8>> {
        self.rx.recv().await
    }

    /// Bytes to the device; false when the connection is gone.
    pub fn send(&self, data: Vec<u8>) -> bool {
        self.sender().send(data)
    }

    /// The sending half, for a task of its own.
    pub fn sender(&self) -> ConnSender {
        ConnSender {
            back: self.back.clone(),
            wake: Arc::clone(&self.wake),
            handle: self.handle,
        }
    }
}

impl Drop for ConnIo {
    fn drop(&mut self) {
        let _ = self.back.send(Back::Close(self.handle));
        self.wake.notify_one();
    }
}

/// The sending half of a [`ConnIo`].
#[derive(Debug, Clone)]
pub struct ConnSender {
    back: mpsc::UnboundedSender<Back>,
    wake: Arc<Notify>,
    handle: SocketHandle,
}

impl ConnSender {
    /// Bytes to the device; false when the connection is gone.
    pub fn send(&self, data: Vec<u8>) -> bool {
        let ok = self.back.send(Back::Data(self.handle, data)).is_ok();
        self.wake.notify_one();
        ok
    }
}

/// Starts a handler for a new connection (spawns its task).
pub type Accept = Arc<dyn Fn(ConnIo) + Send + Sync>;

struct Conn {
    to_handler: Option<mpsc::Sender<Vec<u8>>>,
    out: VecDeque<u8>,
    handler_done: bool,
}

/// The stack.
pub struct Stack {
    iface: Interface,
    sockets: SocketSet<'static>,
    dev: Queue,
    /// Received frames not yet given to smoltcp.
    inbox: VecDeque<Vec<u8>>,
    listeners: Vec<(SocketHandle, u16)>,
    conns: HashMap<SocketHandle, Conn>,
    accept: Accept,
    back_tx: mpsc::UnboundedSender<Back>,
    back_rx: mpsc::UnboundedReceiver<Back>,
    wake: Arc<Notify>,
}

fn now_of(ms: u64) -> SInstant {
    SInstant::from_millis(i64::try_from(ms).unwrap_or(i64::MAX))
}

fn tcp_socket() -> tcp::Socket<'static> {
    let mut s = tcp::Socket::new(
        tcp::SocketBuffer::new(vec![0u8; BUF]),
        tcp::SocketBuffer::new(vec![0u8; BUF]),
    );
    s.set_timeout(Some(SDuration::from_secs(120)));
    s.set_keep_alive(Some(SDuration::from_secs(30)));
    s
}

impl Stack {
    /// A stack on `mac` accepting TCP on `ports`; `seed` randomises
    /// sequence numbers and ports.
    pub fn new(mac: Mac, ports: &[u16], accept: Accept, seed: u64, now_ms: u64) -> Self {
        let mut dev = Queue::default();
        let mut cfg = Config::new(HardwareAddress::Ethernet(EthernetAddress(mac.0)));
        cfg.random_seed = seed;
        let iface = Interface::new(cfg, &mut dev, now_of(now_ms));
        let (back_tx, back_rx) = mpsc::unbounded_channel();
        let mut s = Self {
            iface,
            sockets: SocketSet::new(Vec::new()),
            dev,
            inbox: VecDeque::new(),
            listeners: Vec::new(),
            conns: HashMap::new(),
            accept,
            back_tx,
            back_rx,
            wake: Arc::new(Notify::new()),
        };
        for &p in ports {
            for _ in 0..LISTENERS {
                s.listen(p);
            }
        }
        s
    }

    fn listen(&mut self, port: u16) {
        let mut sock = tcp_socket();
        if sock.listen(port).is_ok() {
            let h = self.sockets.add(sock);
            self.listeners.push((h, port));
        }
    }

    /// Sets (or clears) the box's address and default gateway.
    pub fn set_addr(&mut self, addr: Option<Addr>, gateway: Option<Ipv4Addr>) {
        self.iface.update_ip_addrs(|a| {
            a.clear();
            if let Some(x) = addr {
                let _ = a.push(IpCidr::new(IpAddress::Ipv4(x.ip), x.prefix));
            }
        });
        let routes = self.iface.routes_mut();
        routes.remove_default_ipv4_route();
        if let (Some(_), Some(gw)) = (addr, gateway) {
            let _ = routes.add_default_ipv4_route(gw);
        }
    }

    /// A frame the switch classed as local.
    pub fn push_frame(&mut self, frame: Vec<u8>) {
        if self.inbox.len() < 1024 {
            self.inbox.push_back(frame);
        }
    }

    /// Runs the stack at `now_ms`; returns the frames to send.
    pub fn poll(&mut self, now_ms: u64) -> Vec<Vec<u8>> {
        while let Ok(m) = self.back_rx.try_recv() {
            match m {
                Back::Data(h, d) => {
                    if let Some(c) = self.conns.get_mut(&h) {
                        c.out.extend(d);
                    }
                }
                Back::Close(h) => {
                    if let Some(c) = self.conns.get_mut(&h) {
                        c.handler_done = true;
                    }
                }
            }
        }
        let now = now_of(now_ms);
        while let Some(f) = self.inbox.pop_front() {
            self.dev.rx.push_back(f);
            self.iface.poll(now, &mut self.dev, &mut self.sockets);
            self.accept_new();
        }
        // Twice: data the first poll received may be answered right away
        // by the pumping below.
        for _ in 0..2 {
            self.pump();
            self.iface.poll(now, &mut self.dev, &mut self.sockets);
            self.accept_new();
        }
        std::mem::take(&mut self.dev.tx)
    }

    /// Milliseconds until [`Self::poll`] is due again (None: on input only).
    pub fn delay_ms(&mut self, now_ms: u64) -> Option<u64> {
        self.iface
            .poll_delay(now_of(now_ms), &self.sockets)
            .map(|d| d.total_millis())
    }

    fn accept_new(&mut self) {
        let mut opened = Vec::new();
        self.listeners.retain(|&(h, port)| {
            let s = self.sockets.get::<tcp::Socket>(h);
            if s.is_listening() {
                return true;
            }
            opened.push((h, port));
            false
        });
        for (h, port) in opened {
            self.listen(port);
            let peer = self
                .sockets
                .get::<tcp::Socket>(h)
                .remote_endpoint()
                .and_then(|e| match e.addr {
                    IpAddress::Ipv4(a) => Some(a),
                    #[allow(unreachable_patterns, reason = "IPv6 is not compiled in")]
                    _ => None,
                });
            let Some(peer) = peer.filter(|_| self.conns.len() < MAX_CONNS) else {
                self.sockets.get_mut::<tcp::Socket>(h).abort();
                self.conns.insert(
                    h,
                    Conn {
                        to_handler: None,
                        out: VecDeque::new(),
                        handler_done: true,
                    },
                );
                continue;
            };
            let (tx, rx) = mpsc::channel(16);
            self.conns.insert(
                h,
                Conn {
                    to_handler: Some(tx),
                    out: VecDeque::new(),
                    handler_done: false,
                },
            );
            (self.accept)(ConnIo {
                peer,
                port,
                rx,
                back: self.back_tx.clone(),
                wake: Arc::clone(&self.wake),
                handle: h,
            });
        }
    }

    fn pump(&mut self) {
        let mut gone = Vec::new();
        for (&h, c) in &mut self.conns {
            let s = self.sockets.get_mut::<tcp::Socket>(h);
            if let Some(tx) = &c.to_handler {
                while s.can_recv() {
                    let Ok(permit) = tx.try_reserve() else {
                        break; // handler busy: the window closes meanwhile
                    };
                    let mut buf = vec![0u8; CHUNK];
                    match s.recv_slice(&mut buf) {
                        Ok(n) if n > 0 => {
                            buf.truncate(n);
                            permit.send(buf);
                        }
                        _ => break,
                    }
                }
                let peer_done = matches!(
                    s.state(),
                    tcp::State::CloseWait
                        | tcp::State::LastAck
                        | tcp::State::Closing
                        | tcp::State::TimeWait
                        | tcp::State::Closed
                );
                if peer_done && !s.can_recv() {
                    c.to_handler = None; // the device closed its side
                }
            }
            while !c.out.is_empty() && s.can_send() {
                let (a, _) = c.out.as_slices();
                match s.send_slice(a) {
                    Ok(n) if n > 0 => {
                        c.out.drain(..n);
                    }
                    _ => break,
                }
            }
            if c.out.len() > MAX_PENDING_OUT {
                s.abort();
            } else if c.handler_done && c.out.is_empty() && s.is_open() {
                s.close();
            }
            if s.state() == tcp::State::Closed {
                gone.push(h);
            } else if c.handler_done && c.to_handler.is_none() && s.state() == tcp::State::TimeWait
            {
                // Nothing left to do with it; TIME-WAIT ends on its own,
                // but the slot is freed now.
                gone.push(h);
            }
        }
        for h in gone {
            self.conns.remove(&h);
            self.sockets.remove(h);
        }
    }

    /// Notified when a handler has data for the stack (the caller polls).
    pub fn waker(&self) -> Arc<Notify> {
        Arc::clone(&self.wake)
    }

    /// Open connections.
    #[cfg(test)]
    pub fn connections(&self) -> usize {
        self.conns.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::frame::{parse_eth, ETHERTYPE_ARP};

    const BOX: Mac = Mac([2, 0, 0, 0, 0, 0x50]);
    const BOX_IP: Ipv4Addr = Ipv4Addr::new(192, 168, 1, 50);
    const PC: [u8; 6] = [2, 0, 0, 0, 0, 0x10];
    const PC_IP: Ipv4Addr = Ipv4Addr::new(192, 168, 1, 10);

    /// A device on the LAN: another smoltcp interface.
    struct Pc {
        iface: Interface,
        dev: Queue,
        sockets: SocketSet<'static>,
    }

    impl Pc {
        fn new() -> Self {
            let mut dev = Queue::default();
            let cfg = Config::new(HardwareAddress::Ethernet(EthernetAddress(PC)));
            let mut iface = Interface::new(cfg, &mut dev, SInstant::from_millis(0));
            iface.update_ip_addrs(|a| {
                a.push(IpCidr::new(IpAddress::Ipv4(PC_IP), 24)).unwrap();
            });
            Self {
                iface,
                dev,
                sockets: SocketSet::new(Vec::new()),
            }
        }

        fn poll(&mut self, ms: u64) -> Vec<Vec<u8>> {
            self.iface
                .poll(now_of(ms), &mut self.dev, &mut self.sockets);
            std::mem::take(&mut self.dev.tx)
        }
    }

    /// Moves frames both ways until both sides are quiet (or `rounds`).
    fn run(stack: &mut Stack, pc: &mut Pc, ms: &mut u64, rounds: usize) {
        for _ in 0..rounds {
            *ms += 1;
            let a = pc.poll(*ms);
            for f in a {
                stack.push_frame(f);
            }
            let b = stack.poll(*ms);
            for f in b {
                pc.dev.rx.push_back(f);
            }
        }
    }

    fn echo_stack() -> Stack {
        let accept: Accept = Arc::new(|mut io: ConnIo| {
            tokio::spawn(async move {
                assert_eq!(io.peer, PC_IP);
                while let Some(d) = io.recv().await {
                    let mut r = format!("{}:", io.port).into_bytes();
                    r.extend_from_slice(&d);
                    io.send(r);
                }
            });
        });
        let mut s = Stack::new(BOX, &[80, 53], accept, 1, 0);
        s.set_addr(
            Some(Addr {
                ip: BOX_IP,
                prefix: 24,
            }),
            Some(Ipv4Addr::new(192, 168, 1, 1)),
        );
        s
    }

    #[test]
    fn tcp_is_bridged_to_a_handler_and_closed() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let mut stack = echo_stack();
            let mut pc = Pc::new();
            let h = pc.sockets.add(tcp_socket());
            {
                let cx = pc.iface.context();
                let s = pc.sockets.get_mut::<tcp::Socket>(h);
                s.connect(cx, (BOX_IP, 80), 50000).unwrap();
            }
            let mut ms = 0;
            run(&mut stack, &mut pc, &mut ms, 10);
            assert!(pc.sockets.get::<tcp::Socket>(h).may_send(), "connected");
            pc.sockets
                .get_mut::<tcp::Socket>(h)
                .send_slice(b"GET /")
                .unwrap();
            let mut got = Vec::new();
            for _ in 0..20 {
                run(&mut stack, &mut pc, &mut ms, 2);
                tokio::task::yield_now().await;
                let s = pc.sockets.get_mut::<tcp::Socket>(h);
                if s.can_recv() {
                    let mut b = [0u8; 64];
                    let n = s.recv_slice(&mut b).unwrap();
                    got.extend_from_slice(&b[..n]);
                }
            }
            assert_eq!(got, b"80:GET /");
            assert_eq!(stack.connections(), 1);
            // The device closes; the handler ends; the box closes too.
            pc.sockets.get_mut::<tcp::Socket>(h).close();
            for _ in 0..20 {
                run(&mut stack, &mut pc, &mut ms, 2);
                tokio::task::yield_now().await;
            }
            assert_eq!(stack.connections(), 0);
            assert!(!pc.sockets.get::<tcp::Socket>(h).is_open());
        });
    }

    #[test]
    fn other_ports_are_refused_and_listeners_refill() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let mut stack = echo_stack();
            let mut pc = Pc::new();
            let mut ms = 0;
            let h = pc.sockets.add(tcp_socket());
            {
                let cx = pc.iface.context();
                let s = pc.sockets.get_mut::<tcp::Socket>(h);
                s.connect(cx, (BOX_IP, 22), 50001).unwrap();
            }
            run(&mut stack, &mut pc, &mut ms, 10);
            assert!(!pc.sockets.get::<tcp::Socket>(h).is_open(), "reset");
            // More connections to 53 than listeners: all accepted.
            let hs: Vec<_> = (0..LISTENERS + 2)
                .map(|i| {
                    let h = pc.sockets.add(tcp_socket());
                    let cx = pc.iface.context();
                    pc.sockets
                        .get_mut::<tcp::Socket>(h)
                        .connect(cx, (BOX_IP, 53), 50010 + i as u16)
                        .unwrap();
                    h
                })
                .collect();
            run(&mut stack, &mut pc, &mut ms, 20);
            for h in hs {
                assert!(pc.sockets.get::<tcp::Socket>(h).may_send());
            }
            assert_eq!(stack.connections(), LISTENERS + 2);
        });
    }

    #[test]
    fn answers_ping() {
        use crate::frame::{build_eth, checksum, parse_ipv4, ETHERTYPE_IPV4};
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let mut stack = echo_stack();
            let mut icmp = vec![8u8, 0, 0, 0, 0x12, 0x34, 0, 1, b'p', b'i', b'n', b'g'];
            let c = checksum(&icmp);
            icmp[2..4].copy_from_slice(&c.to_be_bytes());
            let mut ip = vec![0u8; 20];
            ip[0] = 0x45;
            ip[2..4].copy_from_slice(&((20 + icmp.len()) as u16).to_be_bytes());
            ip[8] = 64;
            ip[9] = 1;
            ip[12..16].copy_from_slice(&PC_IP.octets());
            ip[16..20].copy_from_slice(&BOX_IP.octets());
            let c = checksum(&ip);
            ip[10..12].copy_from_slice(&c.to_be_bytes());
            ip.extend_from_slice(&icmp);
            // A device asks for the box's MAC before it pings.
            stack.push_frame(crate::frame::build_arp_request(Mac(PC), PC_IP, BOX_IP));
            assert_eq!(stack.poll(1).len(), 1, "ARP answered");
            stack.push_frame(build_eth(BOX, Mac(PC), ETHERTYPE_IPV4, &ip));
            let out = stack.poll(2);
            assert_eq!(out.len(), 1);
            let e = parse_eth(&out[0]).unwrap();
            assert_eq!(e.dst, Mac(PC));
            let r = parse_ipv4(e.payload).unwrap();
            assert_eq!((r.src, r.dst, r.proto), (BOX_IP, PC_IP, 1));
            let l4 = r.l4(e.payload);
            assert_eq!(l4[0], 0, "echo reply");
            assert_eq!(&l4[8..], b"ping");
        });
    }

    #[test]
    fn answers_arp_for_its_address_only_when_it_has_one() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let mut stack = echo_stack();
            let ask = crate::frame::build_arp_request(Mac(PC), PC_IP, BOX_IP);
            stack.push_frame(ask.clone());
            let out = stack.poll(1);
            assert_eq!(out.len(), 1);
            let e = parse_eth(&out[0]).unwrap();
            assert_eq!((e.ethertype, e.dst, e.src), (ETHERTYPE_ARP, Mac(PC), BOX));
            stack.set_addr(None, None);
            stack.push_frame(ask);
            assert!(stack.poll(2).is_empty());
        });
    }
}
