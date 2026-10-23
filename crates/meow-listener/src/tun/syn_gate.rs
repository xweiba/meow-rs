//! Connect before the handshake (TUN TCP to real addresses).
//!
//! lwIP answers a SYN at once, so an application behind the TUN saw every
//! connection succeed and only later learned, by a reset, that the
//! destination could not be reached. Software that tries a direct path
//! first and falls back on failure — RustDesk's TCP hole punch, then its
//! relay; P2P clients probing peers — took the instant handshake for a
//! working path and never fell back.
//!
//! The gate sits in the device → stack pump. A SYN to a real address is
//! held back while the flow is matched and dialed; only once the dial
//! succeeds is the SYN handed to lwIP, whose accepted stream then joins
//! the dialed upstream. A failed dial (unreachable, refused, `REJECT`)
//! answers the SYN with a RST, as the destination itself would: the
//! application sees "connection refused" right away. Its retransmitted
//! SYNs are dropped while the dial runs and reset for a short while after
//! it failed.
//!
//! On a port the sniffer reads, the route may depend on the name in the
//! client's first bytes, which only come after the handshake. Such a SYN
//! is held only until the tunnel has decided whether a name could matter
//! (a DIRECT or REJECT rule that reads no name decides first, such as a
//! program's or a LAN range's): if it could, the SYN goes to lwIP as
//! before and the flow is sniffed; if not, it is dialed like the others.
//!
//! Not gated, as before: fake-IP destinations (the name, not a peer, is
//! dialed), DNS hijack and the TUN's own subnet.

use std::collections::HashMap;
use std::future::Future;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::pin::Pin;
use std::sync::{Arc, Mutex, PoisonError};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use meow_common::ProxyConn;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::{mpsc, oneshot};

/// (client behind the TUN, destination).
pub(super) type FlowKey = (SocketAddr, SocketAddr);

/// How long a failed destination keeps answering the same client's SYNs
/// with a RST without dialing it again.
const REFUSED_FOR: Duration = Duration::from_secs(2);

/// How long a dialed flow waits for lwIP to complete the handshake once
/// its SYN is released. The client may have given up meanwhile.
const HANDSHAKE_WAIT: Duration = Duration::from_secs(10);

/// Most flows held at once; past it SYNs go straight to lwIP as before
/// (a SYN flood must not grow the table without bound).
const MAX_HELD: usize = 4096;

/// What the device → stack pump does with an inbound packet.
#[derive(Debug, PartialEq, Eq)]
pub(super) enum Verdict {
    /// Into the stack as usual.
    Pass,
    /// Held (or a retransmission of a held SYN): dropped here.
    Hold,
    /// Answer the client with this packet, not the stack.
    Reply(Vec<u8>),
}

/// Whether a SYN to a destination is held.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Gating {
    /// Into the stack as before.
    No,
    /// Held until its dial.
    Dial,
    /// Held until the tunnel decided whether its name could matter
    /// (a sniffed port): then dialed, or handed to the stack unrouted.
    Decide,
}

/// Packets the gate sends from outside the pump.
pub(super) enum GateOut {
    /// A held SYN whose dial succeeded: into the stack.
    ToStack(Vec<u8>),
    /// A RST for a held SYN whose dial failed: back to the client.
    ToDevice(Vec<u8>),
}

enum Flow {
    /// SYN held, dial running.
    Dialing,
    /// SYN given to lwIP; the accepted stream goes to the dialed flow.
    Handshaking(oneshot::Sender<lwip::TcpStream>),
    /// Dial failed: SYNs get a RST until then.
    Refused(Instant),
    /// Handed to lwIP undialed (its name may decide its route): the
    /// accepted stream takes the usual sniffing path. Forgotten then.
    Unrouted(Instant),
}

type Eligible = dyn Fn(SocketAddr) -> Gating + Send + Sync;

struct Shared {
    flows: Mutex<HashMap<FlowKey, Flow>>,
    eligible: Box<Eligible>,
    dial_tx: mpsc::UnboundedSender<GatedConn>,
    out_tx: mpsc::UnboundedSender<GateOut>,
}

impl Shared {
    fn flows(&self) -> std::sync::MutexGuard<'_, HashMap<FlowKey, Flow>> {
        self.flows.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

#[derive(Clone)]
pub(super) struct SynGate {
    shared: Arc<Shared>,
}

impl SynGate {
    /// `eligible(dst)`: whether (and how) a SYN to `dst` is held.
    /// Returns the gate, the flows to dial (for the accept loop) and the
    /// packets to send (for the device → stack pump).
    pub(super) fn new(
        eligible: impl Fn(SocketAddr) -> Gating + Send + Sync + 'static,
    ) -> (
        Self,
        mpsc::UnboundedReceiver<GatedConn>,
        mpsc::UnboundedReceiver<GateOut>,
    ) {
        let (dial_tx, dial_rx) = mpsc::unbounded_channel();
        let (out_tx, out_rx) = mpsc::unbounded_channel();
        let gate = Self {
            shared: Arc::new(Shared {
                flows: Mutex::new(HashMap::new()),
                eligible: Box::new(eligible),
                dial_tx,
                out_tx,
            }),
        };
        (gate, dial_rx, out_rx)
    }

    /// Called by the device → stack pump for every inbound packet.
    pub(super) fn on_packet(&self, pkt: &[u8]) -> Verdict {
        let Some(syn) = parse_syn(pkt) else {
            return Verdict::Pass;
        };
        let gating = (self.shared.eligible)(syn.dst);
        if gating == Gating::No {
            return Verdict::Pass;
        }
        let key = (syn.src, syn.dst);
        let now = Instant::now();
        let mut flows = self.shared.flows();
        match flows.get(&key) {
            Some(Flow::Dialing) => return Verdict::Hold,
            Some(Flow::Handshaking(_)) => return Verdict::Pass,
            Some(Flow::Unrouted(until)) if now < *until => return Verdict::Pass,
            Some(Flow::Refused(until)) if now < *until => {
                return Verdict::Reply(build_rst(&syn));
            }
            _ => {}
        }
        if flows.len() >= MAX_HELD {
            flows.retain(
                |_, f| !matches!(f, Flow::Refused(until) | Flow::Unrouted(until) if now >= *until),
            );
            if flows.len() >= MAX_HELD {
                return Verdict::Pass;
            }
        }
        let conn = GatedConn {
            gate: Arc::clone(&self.shared),
            key,
            syn: pkt.to_vec(),
            seq: syn.seq,
            decide: gating == Gating::Decide,
            state: Mutex::new(State::Dialing),
        };
        flows.insert(key, Flow::Dialing);
        drop(flows);
        match self.shared.dial_tx.send(conn) {
            Ok(()) => Verdict::Hold,
            Err(mpsc::error::SendError(conn)) => {
                // The accept loop is gone: nothing could dial it.
                conn.disarm();
                Verdict::Pass
            }
        }
    }

    /// Called by the accept loop for every stream lwIP accepts. A stream
    /// of a gated flow goes to its dialed upstream (`None`); any other
    /// comes back for the usual handling.
    pub(super) fn take_accepted(
        &self,
        stream: lwip::TcpStream,
        src: SocketAddr,
        dst: SocketAddr,
    ) -> Option<lwip::TcpStream> {
        let mut flows = self.shared.flows();
        match flows.get(&(src, dst)) {
            Some(Flow::Handshaking(_)) => {}
            Some(Flow::Unrouted(_)) => {
                flows.remove(&(src, dst));
                return Some(stream);
            }
            _ => return Some(stream),
        }
        if let Some(Flow::Handshaking(tx)) = flows.remove(&(src, dst)) {
            // The dialed flow gave up meanwhile: the stream just closes.
            let _ = tx.send(stream);
        }
        None
    }
}

/// The client side of a gated flow, handed to the tunnel's TCP path in
/// place of the lwIP stream that does not exist yet.
///
/// `route_inbound_tcp` first matches and dials, then relays; it touches
/// the client connection only once the dial succeeded. So the first poll
/// releases the held SYN and waits for lwIP's stream, and a connection
/// dropped without ever being polled is a failed (or rejected) dial: its
/// SYN gets a RST.
pub(super) struct GatedConn {
    gate: Arc<Shared>,
    key: FlowKey,
    syn: Vec<u8>,
    seq: u32,
    /// [`Gating::Decide`]: see [`Self::needs_decision`].
    decide: bool,
    state: Mutex<State>,
}

enum State {
    Dialing,
    Waiting {
        rx: oneshot::Receiver<lwip::TcpStream>,
        deadline: Pin<Box<tokio::time::Sleep>>,
    },
    Open(lwip::TcpStream),
    Failed,
    /// Nothing to do on drop.
    Disarmed,
}

impl GatedConn {
    pub(super) fn src(&self) -> SocketAddr {
        self.key.0
    }

    pub(super) fn dst(&self) -> SocketAddr {
        self.key.1
    }

    /// A sniffed port's flow: the caller asks the tunnel first whether its
    /// name could matter, and if so hands it over with [`Self::unrouted`].
    pub(super) fn needs_decision(&self) -> bool {
        self.decide
    }

    /// Its name may decide its route: the SYN goes to lwIP undialed and
    /// the accepted stream takes the usual path (sniffed, then dialed).
    pub(super) fn unrouted(self) {
        if self
            .gate
            .out_tx
            .send(GateOut::ToStack(self.syn.clone()))
            .is_ok()
        {
            self.gate
                .flows()
                .insert(self.key, Flow::Unrouted(Instant::now() + HANDSHAKE_WAIT));
        } else {
            self.gate.flows().remove(&self.key);
        }
        *self.state.lock().unwrap_or_else(PoisonError::into_inner) = State::Disarmed;
    }

    fn disarm(self) {
        self.gate.flows().remove(&self.key);
        *self.state.lock().unwrap_or_else(PoisonError::into_inner) = State::Disarmed;
    }

    fn poll_open<T>(
        &self,
        cx: &mut Context<'_>,
        f: impl FnOnce(Pin<&mut lwip::TcpStream>, &mut Context<'_>) -> Poll<io::Result<T>>,
    ) -> Poll<io::Result<T>> {
        let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        loop {
            match &mut *state {
                State::Dialing => {
                    // The dial succeeded: let lwIP have the SYN.
                    let (tx, rx) = oneshot::channel();
                    self.gate.flows().insert(self.key, Flow::Handshaking(tx));
                    if self
                        .gate
                        .out_tx
                        .send(GateOut::ToStack(self.syn.clone()))
                        .is_err()
                    {
                        *state = State::Failed;
                        continue;
                    }
                    *state = State::Waiting {
                        rx,
                        deadline: Box::pin(tokio::time::sleep(HANDSHAKE_WAIT)),
                    };
                }
                State::Waiting { rx, deadline } => {
                    if let Poll::Ready(got) = Pin::new(rx).poll(cx) {
                        *state = match got {
                            Ok(stream) => State::Open(stream),
                            Err(_) => State::Failed,
                        };
                        continue;
                    }
                    if deadline.as_mut().poll(cx).is_ready() {
                        self.forget();
                        *state = State::Failed;
                        continue;
                    }
                    return Poll::Pending;
                }
                State::Open(stream) => return f(Pin::new(stream), cx),
                State::Failed | State::Disarmed => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::NotConnected,
                        "TUN client did not complete the handshake",
                    )));
                }
            }
        }
    }

    /// Drop a Handshaking entry that is still ours.
    fn forget(&self) {
        let mut flows = self.gate.flows();
        if matches!(flows.get(&self.key), Some(Flow::Handshaking(_))) {
            flows.remove(&self.key);
        }
    }
}

impl Drop for GatedConn {
    fn drop(&mut self) {
        let state = self.state.get_mut().unwrap_or_else(PoisonError::into_inner);
        match state {
            State::Dialing => {
                // Never polled: the dial failed or the rule rejected it.
                self.gate
                    .flows()
                    .insert(self.key, Flow::Refused(Instant::now() + REFUSED_FOR));
                let syn = Syn {
                    src: self.key.0,
                    dst: self.key.1,
                    seq: self.seq,
                };
                let _ = self.gate.out_tx.send(GateOut::ToDevice(build_rst(&syn)));
            }
            State::Waiting { .. } | State::Failed => self.forget(),
            State::Open(_) | State::Disarmed => {}
        }
    }
}

impl AsyncRead for GatedConn {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        self.poll_open(cx, |s, cx| s.poll_read(cx, buf))
    }
}

impl AsyncWrite for GatedConn {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.poll_open(cx, |s, cx| s.poll_write(cx, buf))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.poll_open(cx, AsyncWrite::poll_flush)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.poll_open(cx, AsyncWrite::poll_shutdown)
    }
}

impl ProxyConn for GatedConn {}

/// A TCP SYN (without ACK) from a client behind the TUN.
#[derive(Debug, PartialEq, Eq)]
struct Syn {
    src: SocketAddr,
    dst: SocketAddr,
    seq: u32,
}

const TCP: u8 = 6;
const FLAG_SYN: u8 = 0x02;
const FLAG_RST: u8 = 0x04;
const FLAG_ACK: u8 = 0x10;

/// The SYN in an IPv4 or IPv6 packet (IPv6 without extension headers;
/// fragments are never SYNs worth holding).
fn parse_syn(pkt: &[u8]) -> Option<Syn> {
    let (src, dst, tcp) = match pkt.first()? >> 4 {
        4 => {
            let ihl = usize::from(pkt[0] & 0x0f) * 4;
            if ihl < 20 || pkt.len() < ihl + 20 || pkt[9] != TCP {
                return None;
            }
            // More fragments, or not the first fragment.
            if u16::from_be_bytes([pkt[6], pkt[7]]) & 0x3fff != 0 {
                return None;
            }
            let src = IpAddr::V4(Ipv4Addr::new(pkt[12], pkt[13], pkt[14], pkt[15]));
            let dst = IpAddr::V4(Ipv4Addr::new(pkt[16], pkt[17], pkt[18], pkt[19]));
            (src, dst, &pkt[ihl..])
        }
        6 => {
            if pkt.len() < 40 + 20 || pkt[6] != TCP {
                return None;
            }
            let src = IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(&pkt[8..24]).ok()?));
            let dst = IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(&pkt[24..40]).ok()?));
            (src, dst, &pkt[40..])
        }
        _ => return None,
    };
    if tcp[13] & (FLAG_SYN | FLAG_ACK | FLAG_RST) != FLAG_SYN {
        return None;
    }
    let sport = u16::from_be_bytes([tcp[0], tcp[1]]);
    let dport = u16::from_be_bytes([tcp[2], tcp[3]]);
    let seq = u32::from_be_bytes([tcp[4], tcp[5], tcp[6], tcp[7]]);
    Some(Syn {
        src: SocketAddr::new(src, sport),
        dst: SocketAddr::new(dst, dport),
        seq,
    })
}

/// The RST+ACK the destination would send for `syn` (RFC 9293 §3.10.7.1).
fn build_rst(syn: &Syn) -> Vec<u8> {
    let mut tcp = [0u8; 20];
    tcp[0..2].copy_from_slice(&syn.dst.port().to_be_bytes());
    tcp[2..4].copy_from_slice(&syn.src.port().to_be_bytes());
    // seq 0; ack = the SYN's sequence number + 1.
    tcp[8..12].copy_from_slice(&syn.seq.wrapping_add(1).to_be_bytes());
    tcp[12] = 5 << 4;
    tcp[13] = FLAG_RST | FLAG_ACK;
    match (syn.dst.ip(), syn.src.ip()) {
        (IpAddr::V4(from), IpAddr::V4(to)) => {
            let mut sum = Checksum::default();
            sum.add(&from.octets());
            sum.add(&to.octets());
            sum.add(&[0, TCP, 0, 20]);
            sum.add(&tcp);
            tcp[16..18].copy_from_slice(&sum.finish().to_be_bytes());

            let mut ip = [0u8; 20];
            ip[0] = 0x45;
            ip[2..4].copy_from_slice(&40u16.to_be_bytes());
            ip[6] = 0x40; // DF
            ip[8] = 64;
            ip[9] = TCP;
            ip[12..16].copy_from_slice(&from.octets());
            ip[16..20].copy_from_slice(&to.octets());
            let mut sum = Checksum::default();
            sum.add(&ip);
            ip[10..12].copy_from_slice(&sum.finish().to_be_bytes());
            [&ip[..], &tcp[..]].concat()
        }
        (from, to) => {
            let from = to_v6(from);
            let to = to_v6(to);
            let mut sum = Checksum::default();
            sum.add(&from.octets());
            sum.add(&to.octets());
            sum.add(&[0, 0, 0, 20, 0, 0, 0, TCP]);
            sum.add(&tcp);
            tcp[16..18].copy_from_slice(&sum.finish().to_be_bytes());

            let mut ip = [0u8; 40];
            ip[0] = 0x60;
            ip[4..6].copy_from_slice(&20u16.to_be_bytes());
            ip[6] = TCP;
            ip[7] = 64;
            ip[8..24].copy_from_slice(&from.octets());
            ip[24..40].copy_from_slice(&to.octets());
            [&ip[..], &tcp[..]].concat()
        }
    }
}

fn to_v6(ip: IpAddr) -> Ipv6Addr {
    match ip {
        IpAddr::V4(v4) => v4.to_ipv6_mapped(),
        IpAddr::V6(v6) => v6,
    }
}

/// RFC 1071 one's-complement sum over 16-bit words.
#[derive(Default)]
struct Checksum(u32);

impl Checksum {
    fn add(&mut self, bytes: &[u8]) {
        let (words, rest) = bytes.as_chunks::<2>();
        for w in words {
            self.0 += u32::from(u16::from_be_bytes(*w));
        }
        if let [last] = rest {
            self.0 += u32::from(*last) << 8;
        }
    }

    fn finish(mut self) -> u16 {
        while self.0 > 0xffff {
            self.0 = (self.0 & 0xffff) + (self.0 >> 16);
        }
        !(self.0 as u16)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v4_syn(src: SocketAddr, dst: SocketAddr, seq: u32, flags: u8) -> Vec<u8> {
        let (IpAddr::V4(s), IpAddr::V4(d)) = (src.ip(), dst.ip()) else {
            unreachable!()
        };
        let mut p = vec![0u8; 40];
        p[0] = 0x45;
        p[2..4].copy_from_slice(&40u16.to_be_bytes());
        p[8] = 64;
        p[9] = TCP;
        p[12..16].copy_from_slice(&s.octets());
        p[16..20].copy_from_slice(&d.octets());
        p[20..22].copy_from_slice(&src.port().to_be_bytes());
        p[22..24].copy_from_slice(&dst.port().to_be_bytes());
        p[24..28].copy_from_slice(&seq.to_be_bytes());
        p[32] = 5 << 4;
        p[33] = flags;
        p
    }

    fn v6_syn(src: SocketAddr, dst: SocketAddr, seq: u32) -> Vec<u8> {
        let (IpAddr::V6(s), IpAddr::V6(d)) = (src.ip(), dst.ip()) else {
            unreachable!()
        };
        let mut p = vec![0u8; 60];
        p[0] = 0x60;
        p[4..6].copy_from_slice(&20u16.to_be_bytes());
        p[6] = TCP;
        p[7] = 64;
        p[8..24].copy_from_slice(&s.octets());
        p[24..40].copy_from_slice(&d.octets());
        p[40..42].copy_from_slice(&src.port().to_be_bytes());
        p[42..44].copy_from_slice(&dst.port().to_be_bytes());
        p[44..48].copy_from_slice(&seq.to_be_bytes());
        p[52] = 5 << 4;
        p[53] = FLAG_SYN;
        p
    }

    fn sum_ok(bytes: &[u8]) -> bool {
        let mut c = Checksum::default();
        c.add(bytes);
        c.finish() == 0
    }

    const CLIENT: &str = "172.19.0.1:56136";
    const PEER: &str = "117.154.85.62:16611";

    #[test]
    fn only_a_bare_syn_is_parsed() {
        let (c, p) = (CLIENT.parse().unwrap(), PEER.parse().unwrap());
        assert_eq!(
            parse_syn(&v4_syn(c, p, 7, FLAG_SYN)),
            Some(Syn {
                src: c,
                dst: p,
                seq: 7
            })
        );
        assert_eq!(parse_syn(&v4_syn(c, p, 7, FLAG_SYN | FLAG_ACK)), None);
        assert_eq!(parse_syn(&v4_syn(c, p, 7, FLAG_ACK)), None);
        let mut frag = v4_syn(c, p, 7, FLAG_SYN);
        frag[6] = 0x20; // more fragments
        assert_eq!(parse_syn(&frag), None);
        let mut udp = v4_syn(c, p, 7, FLAG_SYN);
        udp[9] = 17;
        assert_eq!(parse_syn(&udp), None);
        assert_eq!(parse_syn(&[0x45, 0, 0]), None);
    }

    #[test]
    fn v4_rst_answers_the_syn() {
        let (c, p): (SocketAddr, SocketAddr) = (CLIENT.parse().unwrap(), PEER.parse().unwrap());
        let rst = build_rst(&parse_syn(&v4_syn(c, p, u32::MAX, FLAG_SYN)).unwrap());
        assert_eq!(rst.len(), 40);
        assert!(sum_ok(&rst[..20]), "IPv4 header checksum");
        let mut pseudo = rst[12..20].to_vec();
        pseudo.extend_from_slice(&[0, TCP, 0, 20]);
        pseudo.extend_from_slice(&rst[20..]);
        assert!(sum_ok(&pseudo), "TCP checksum");
        assert_eq!(&rst[12..16], &[117, 154, 85, 62]);
        assert_eq!(&rst[16..20], &[172, 19, 0, 1]);
        assert_eq!(u16::from_be_bytes([rst[20], rst[21]]), 16611);
        assert_eq!(u16::from_be_bytes([rst[22], rst[23]]), 56136);
        assert_eq!(u32::from_be_bytes([rst[28], rst[29], rst[30], rst[31]]), 0);
        assert_eq!(rst[33], FLAG_RST | FLAG_ACK);
    }

    #[test]
    fn v6_rst_answers_the_syn() {
        let c: SocketAddr = "[fdfe:dcba:9876::1]:40000".parse().unwrap();
        let p: SocketAddr = "[2001:db8::5]:443".parse().unwrap();
        let syn = parse_syn(&v6_syn(c, p, 41)).unwrap();
        let rst = build_rst(&syn);
        assert_eq!(rst.len(), 60);
        let mut pseudo = rst[8..40].to_vec();
        pseudo.extend_from_slice(&[0, 0, 0, 20, 0, 0, 0, TCP]);
        pseudo.extend_from_slice(&rst[40..]);
        assert!(sum_ok(&pseudo), "TCP checksum");
        assert_eq!(parse_syn(&rst), None, "a RST is not a SYN");
        assert_eq!(u32::from_be_bytes([rst[48], rst[49], rst[50], rst[51]]), 42);
    }

    #[tokio::test]
    async fn a_failed_dial_resets_the_syn_and_its_retries() {
        let (gate, mut dials, mut out) = SynGate::new(|_| Gating::Dial);
        let (c, p) = (CLIENT.parse().unwrap(), PEER.parse().unwrap());
        let syn = v4_syn(c, p, 9, FLAG_SYN);
        assert_eq!(gate.on_packet(&syn), Verdict::Hold);
        let conn = dials.try_recv().expect("a dial");
        assert_eq!((conn.src(), conn.dst()), (c, p));
        // Retransmission while dialing: dropped, no second dial.
        assert_eq!(gate.on_packet(&syn), Verdict::Hold);
        assert!(dials.try_recv().is_err());
        // The tunnel drops the connection unpolled: the dial failed.
        drop(conn);
        let Ok(GateOut::ToDevice(rst)) = out.try_recv() else {
            panic!("a RST to the client")
        };
        assert_eq!(rst[33], FLAG_RST | FLAG_ACK);
        // Its retries are refused without another dial.
        assert!(matches!(gate.on_packet(&syn), Verdict::Reply(_)));
        assert!(dials.try_recv().is_err());
        // Other packets are untouched.
        assert_eq!(gate.on_packet(&v4_syn(c, p, 9, FLAG_ACK)), Verdict::Pass);
    }

    #[tokio::test]
    async fn a_successful_dial_releases_the_syn_on_first_poll() {
        let (gate, mut dials, mut out) = SynGate::new(|_| Gating::Dial);
        let (c, p) = (CLIENT.parse().unwrap(), PEER.parse().unwrap());
        let syn = v4_syn(c, p, 9, FLAG_SYN);
        assert_eq!(gate.on_packet(&syn), Verdict::Hold);
        let mut conn = dials.try_recv().unwrap();
        let mut buf = [0u8; 4];
        let mut rb = ReadBuf::new(&mut buf);
        let waker = futures::task::noop_waker();
        let mut cx = Context::from_waker(&waker);
        assert!(Pin::new(&mut conn).poll_read(&mut cx, &mut rb).is_pending());
        let Ok(GateOut::ToStack(released)) = out.try_recv() else {
            panic!("the SYN goes to the stack")
        };
        assert_eq!(released, syn);
        // lwIP's own retransmission handling takes over.
        assert_eq!(gate.on_packet(&syn), Verdict::Pass);
        // The client never finishes: no RST, the entry goes with it.
        drop(conn);
        assert!(out.try_recv().is_err());
        assert_eq!(gate.on_packet(&syn), Verdict::Hold, "a fresh attempt");
    }

    #[test]
    fn an_unrouted_flow_takes_the_usual_path() {
        let (gate, mut dials, mut out) = SynGate::new(|_| Gating::Decide);
        let (c, p) = (CLIENT.parse().unwrap(), "1.1.1.1:443".parse().unwrap());
        let syn = v4_syn(c, p, 3, FLAG_SYN);
        assert_eq!(gate.on_packet(&syn), Verdict::Hold);
        let conn = dials.try_recv().unwrap();
        assert!(conn.needs_decision());
        conn.unrouted();
        let Ok(GateOut::ToStack(released)) = out.try_recv() else {
            panic!("the SYN goes to the stack undialed")
        };
        assert_eq!(released, syn);
        // No RST on drop, and its retransmissions reach lwIP.
        assert!(out.try_recv().is_err());
        assert_eq!(gate.on_packet(&syn), Verdict::Pass);
        assert!(dials.try_recv().is_err());
    }

    #[test]
    fn ineligible_destinations_pass() {
        let (gate, mut dials, _out) = SynGate::new(|dst| {
            if dst.port() == 443 {
                Gating::No
            } else {
                Gating::Dial
            }
        });
        let c = CLIENT.parse().unwrap();
        let syn = v4_syn(c, "1.1.1.1:443".parse().unwrap(), 1, FLAG_SYN);
        assert_eq!(gate.on_packet(&syn), Verdict::Pass);
        assert!(dials.try_recv().is_err());
    }
}
