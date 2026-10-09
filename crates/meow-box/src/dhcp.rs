//! The box's DHCPv4 client: discover, request, renew, rebind, release.
//!
//! Its own (not smoltcp's) for two reasons: on Wi-Fi the box borrows the
//! host's MAC, so it must name itself by a client identifier of its own or
//! the server hands it the host's lease; and leaving must release the
//! lease. A pure state machine: frames in, frames out, time passed in.

use std::net::Ipv4Addr;
use std::time::Duration;

use crate::frame::{build_eth, build_ipv4_udp, parse_eth, parse_ipv4, Mac, ETHERTYPE_IPV4};

const MAGIC: [u8; 4] = [99, 130, 83, 99];
const DISCOVER: u8 = 1;
const OFFER: u8 = 2;
const REQUEST: u8 = 3;
const ACK: u8 = 5;
const NAK: u8 = 6;
const RELEASE: u8 = 7;

/// What the server granted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Lease {
    pub ip: Ipv4Addr,
    /// Subnet prefix length (from the mask; 24 when the server sent none).
    pub prefix: u8,
    pub router: Option<Ipv4Addr>,
    pub dns: Vec<Ipv4Addr>,
    pub server: Ipv4Addr,
    /// The server's (or relay's) MAC: renewals and the release are unicast.
    pub server_mac: Mac,
    pub lease: Duration,
    pub renew: Duration,
    pub rebind: Duration,
}

/// A change the caller acts on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event {
    /// A new or renewed lease (the address may be unchanged).
    Bound(Lease),
    /// The lease ran out or the server refused it: no address now.
    Lost,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum State {
    Discovering,
    Requesting { offer: Ipv4Addr, server: Ipv4Addr },
    Bound { lease: Lease, at: Duration },
    Renewing { lease: Lease, at: Duration },
    Rebinding { lease: Lease, at: Duration },
}

/// The DHCP client.
#[derive(Debug)]
pub struct Client {
    /// The frames' source MAC and the `chaddr` (the host's on Wi-Fi).
    mac: Mac,
    /// Client identifier (option 61): the box's own MAC, so a server tells
    /// it from the host even when they share a MAC.
    client_id: Mac,
    xid: u32,
    state: State,
    next_send: Duration,
    tries: u32,
}

/// What a server's message says.
#[derive(Debug)]
struct Reply {
    kind: u8,
    yiaddr: Ipv4Addr,
    server: Option<Ipv4Addr>,
    mask: Option<Ipv4Addr>,
    router: Option<Ipv4Addr>,
    dns: Vec<Ipv4Addr>,
    lease: Option<u32>,
    t1: Option<u32>,
    t2: Option<u32>,
}

fn ip4(b: &[u8]) -> Option<Ipv4Addr> {
    (b.len() >= 4).then(|| Ipv4Addr::new(b[0], b[1], b[2], b[3]))
}

fn u32_of(b: &[u8]) -> Option<u32> {
    (b.len() >= 4).then(|| u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
}

fn prefix_of(mask: Ipv4Addr) -> u8 {
    u8::try_from(u32::from(mask).leading_ones()).unwrap_or(24)
}

impl Client {
    /// A client sending as `mac`, identifying as `client_id`; `xid` seeds
    /// the transaction ids.
    pub fn new(mac: Mac, client_id: Mac, xid: u32) -> Self {
        Self {
            mac,
            client_id,
            xid,
            state: State::Discovering,
            next_send: Duration::ZERO,
            tries: 0,
        }
    }

    /// The lease held now.
    pub fn lease(&self) -> Option<&Lease> {
        match &self.state {
            State::Bound { lease, .. }
            | State::Renewing { lease, .. }
            | State::Rebinding { lease, .. } => Some(lease),
            _ => None,
        }
    }

    /// When [`Self::poll`] has something to do next.
    pub fn next_wake(&self) -> Duration {
        self.next_send
    }

    fn backoff(&mut self, now: Duration) {
        // 4 s, 8 s, 16 s, then every 32 s.
        let secs = 4u64 << self.tries.min(3);
        self.tries += 1;
        self.next_send = now + Duration::from_secs(secs);
    }

    /// Timers: (re)sends, renews, rebinds and expiry. Returns a frame to
    /// send and/or an event.
    pub fn poll(&mut self, now: Duration) -> (Option<Vec<u8>>, Option<Event>) {
        if now < self.next_send {
            return (None, None);
        }
        match self.state.clone() {
            State::Discovering => {
                if self.tries == 0 {
                    self.xid = self.xid.wrapping_add(1);
                }
                let f = self.message(DISCOVER, None, None, None, None);
                self.backoff(now);
                (Some(f), None)
            }
            State::Requesting { offer, server } => {
                if self.tries >= 4 {
                    self.restart(now);
                    return self.poll(now);
                }
                let f = self.message(REQUEST, None, Some(offer), Some(server), None);
                self.backoff(now);
                (Some(f), None)
            }
            State::Bound { lease, at } => {
                if now >= at + lease.renew {
                    self.state = State::Renewing { lease, at };
                    self.next_send = now;
                    return self.poll(now);
                }
                self.next_send = at + lease.renew;
                (None, None)
            }
            State::Renewing { lease, at } | State::Rebinding { lease, at }
                if now >= at + lease.lease =>
            {
                self.restart(now);
                (None, Some(Event::Lost))
            }
            State::Renewing { lease, at } => {
                if now >= at + lease.rebind {
                    self.state = State::Rebinding { lease, at };
                    self.next_send = now;
                    return self.poll(now);
                }
                let f = self.message(
                    REQUEST,
                    Some(lease.ip),
                    None,
                    None,
                    Some((lease.server, lease.server_mac)),
                );
                self.retry_before(now, at + lease.rebind);
                (Some(f), None)
            }
            State::Rebinding { lease, at } => {
                let f = self.message(REQUEST, Some(lease.ip), None, None, None);
                self.retry_before(now, at + lease.lease);
                (Some(f), None)
            }
        }
    }

    /// Next retry: half the time left to `deadline`, at least 60 s (RFC
    /// 2131 4.4.5), never past it.
    fn retry_before(&mut self, now: Duration, deadline: Duration) {
        let left = deadline.saturating_sub(now);
        self.next_send = now + (left / 2).max(Duration::from_secs(60)).min(left);
    }

    fn restart(&mut self, now: Duration) {
        self.state = State::Discovering;
        self.tries = 0;
        self.next_send = now;
    }

    /// A received frame the switch classed as DHCP.
    pub fn on_frame(&mut self, frame: &[u8], now: Duration) -> Option<Event> {
        let eth = parse_eth(frame)?;
        let ip = parse_ipv4(eth.payload)?;
        let udp = ip.l4(eth.payload);
        let reply = self.parse(udp.get(8..)?)?;
        match (self.state.clone(), reply.kind) {
            (State::Discovering, OFFER) => {
                let server = reply.server?;
                self.state = State::Requesting {
                    offer: reply.yiaddr,
                    server,
                };
                self.tries = 0;
                self.next_send = now;
                None
            }
            (State::Requesting { .. }, ACK)
            | (State::Renewing { .. }, ACK)
            | (State::Rebinding { .. }, ACK) => {
                let lease = Self::lease_of(&reply, eth.src)?;
                self.state = State::Bound {
                    lease: lease.clone(),
                    at: now,
                };
                self.tries = 0;
                self.next_send = now + lease.renew;
                Some(Event::Bound(lease))
            }
            (State::Requesting { .. }, NAK) => {
                self.restart(now);
                None
            }
            (State::Renewing { .. } | State::Rebinding { .. }, NAK) => {
                self.restart(now);
                Some(Event::Lost)
            }
            _ => None,
        }
    }

    fn lease_of(r: &Reply, server_mac: Mac) -> Option<Lease> {
        if r.yiaddr.is_unspecified() {
            return None;
        }
        let lease = r.lease.unwrap_or(3600).max(60);
        let renew = r.t1.unwrap_or(lease / 2).min(lease);
        let rebind = r.t2.unwrap_or(lease / 8 * 7).clamp(renew, lease);
        Some(Lease {
            ip: r.yiaddr,
            prefix: r.mask.map_or(24, prefix_of),
            router: r.router,
            dns: r.dns.clone(),
            server: r.server?,
            server_mac,
            lease: Duration::from_secs(lease.into()),
            renew: Duration::from_secs(renew.into()),
            rebind: Duration::from_secs(rebind.into()),
        })
    }

    fn parse(&self, m: &[u8]) -> Option<Reply> {
        if m.len() < 240 || m[0] != 2 || m[236..240] != MAGIC {
            return None;
        }
        if u32::from_be_bytes([m[4], m[5], m[6], m[7]]) != self.xid || m[28..34] != self.mac.0 {
            return None;
        }
        let mut r = Reply {
            kind: 0,
            yiaddr: ip4(&m[16..20])?,
            server: None,
            mask: None,
            router: None,
            dns: Vec::new(),
            lease: None,
            t1: None,
            t2: None,
        };
        let mut opts = &m[240..];
        while let Some((&code, rest)) = opts.split_first() {
            match code {
                0 => {
                    opts = rest;
                    continue;
                }
                255 => break,
                _ => {}
            }
            let (&len, rest) = rest.split_first()?;
            let len = usize::from(len);
            let v = rest.get(..len)?;
            match code {
                1 => r.mask = ip4(v),
                3 => r.router = ip4(v),
                6 => r.dns = v.as_chunks::<4>().0.iter().filter_map(|c| ip4(c)).collect(),
                51 => r.lease = u32_of(v),
                53 => r.kind = *v.first()?,
                54 => r.server = ip4(v),
                58 => r.t1 = u32_of(v),
                59 => r.t2 = u32_of(v),
                _ => {}
            }
            opts = &rest[len..];
        }
        (r.kind != 0).then_some(r)
    }

    /// A message as a frame. `ciaddr`: the address held (renew, rebind,
    /// release); `requested` + `server`: answering an offer; `unicast`:
    /// to the server directly.
    fn message(
        &self,
        kind: u8,
        ciaddr: Option<Ipv4Addr>,
        requested: Option<Ipv4Addr>,
        server: Option<Ipv4Addr>,
        unicast: Option<(Ipv4Addr, Mac)>,
    ) -> Vec<u8> {
        let mut m = vec![0u8; 240];
        m[0] = 1; // BOOTREQUEST
        m[1] = 1; // Ethernet
        m[2] = 6;
        m[4..8].copy_from_slice(&self.xid.to_be_bytes());
        if ciaddr.is_none() {
            // Replies broadcast: no address to unicast them to yet (and a
            // Wi-Fi host's MAC is shared, so broadcast is what reaches us).
            m[10] = 0x80;
        }
        let ci = ciaddr.unwrap_or(Ipv4Addr::UNSPECIFIED);
        m[12..16].copy_from_slice(&ci.octets());
        m[28..34].copy_from_slice(&self.mac.0);
        m[236..240].copy_from_slice(&MAGIC);
        m.extend_from_slice(&[53, 1, kind]);
        m.extend_from_slice(&[61, 7, 1]);
        m.extend_from_slice(&self.client_id.0);
        if kind != RELEASE {
            m.extend_from_slice(&[12, 10]);
            m.extend_from_slice(b"paopao-box");
            m.extend_from_slice(&[55, 7, 1, 3, 6, 15, 51, 58, 59]);
            m.extend_from_slice(&[57, 2, 0x05, 0xdc]);
        }
        if let Some(r) = requested {
            m.push(50);
            m.push(4);
            m.extend_from_slice(&r.octets());
        }
        if let Some(s) = server {
            m.push(54);
            m.push(4);
            m.extend_from_slice(&s.octets());
        }
        m.push(255);
        if m.len() < 300 {
            m.resize(300, 0);
        }
        let (dst_ip, dst_mac) = unicast.unwrap_or((Ipv4Addr::BROADCAST, Mac::BROADCAST));
        let packet = build_ipv4_udp(ci, dst_ip, 68, 67, &m, 0);
        build_eth(dst_mac, self.mac, ETHERTYPE_IPV4, &packet)
    }

    /// The release to send when leaving (None without a lease).
    pub fn release(&self) -> Option<Vec<u8>> {
        let l = self.lease()?;
        Some(self.message(
            RELEASE,
            Some(l.ip),
            None,
            Some(l.server),
            Some((l.server, l.server_mac)),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const HOST: Mac = Mac([0x3c, 1, 2, 3, 4, 5]);
    const BOXID: Mac = Mac([2, 9, 9, 9, 9, 9]);
    const SERVER_MAC: Mac = Mac([0xaa, 0, 0, 0, 0, 1]);
    const SERVER: Ipv4Addr = Ipv4Addr::new(192, 168, 1, 1);
    const OFFERED: Ipv4Addr = Ipv4Addr::new(192, 168, 1, 50);

    /// The DHCP message inside a frame the client sent.
    fn msg(frame: &[u8]) -> (Mac, Ipv4Addr, Vec<u8>) {
        let e = parse_eth(frame).unwrap();
        let ip = parse_ipv4(e.payload).unwrap();
        assert_eq!(ip.ports(e.payload), Some((68, 67)));
        (e.dst, ip.dst, ip.l4(e.payload)[8..].to_vec())
    }

    fn option(m: &[u8], code: u8) -> Option<Vec<u8>> {
        let mut o = &m[240..];
        while let [c, rest @ ..] = o {
            if *c == 255 {
                return None;
            }
            if *c == 0 {
                o = rest;
                continue;
            }
            let len = rest[0] as usize;
            if *c == code {
                return Some(rest[1..1 + len].to_vec());
            }
            o = &rest[1 + len..];
        }
        None
    }

    fn server_reply(c: &Client, kind: u8, opts: &[(u8, &[u8])]) -> Vec<u8> {
        let mut m = vec![0u8; 240];
        m[0] = 2;
        m[1] = 1;
        m[2] = 6;
        m[4..8].copy_from_slice(&c.xid.to_be_bytes());
        m[16..20].copy_from_slice(&OFFERED.octets());
        m[28..34].copy_from_slice(&HOST.0);
        m[236..240].copy_from_slice(&MAGIC);
        m.extend_from_slice(&[53, 1, kind]);
        for (code, v) in opts {
            m.push(*code);
            m.push(v.len() as u8);
            m.extend_from_slice(v);
        }
        m.push(255);
        let p = build_ipv4_udp(SERVER, Ipv4Addr::BROADCAST, 67, 68, &m, 9);
        build_eth(Mac::BROADCAST, SERVER_MAC, ETHERTYPE_IPV4, &p)
    }

    fn std_opts() -> Vec<(u8, &'static [u8])> {
        vec![
            (54, &[192, 168, 1, 1]),
            (1, &[255, 255, 255, 0]),
            (3, &[192, 168, 1, 1]),
            (6, &[192, 168, 1, 1, 223, 5, 5, 5]),
            (51, &[0, 0, 0x0e, 0x10]), // 3600 s
        ]
    }

    fn bound() -> Client {
        let mut c = Client::new(HOST, BOXID, 7);
        c.poll(Duration::ZERO);
        c.on_frame(&server_reply(&c, OFFER, &std_opts()), Duration::ZERO);
        c.poll(Duration::ZERO);
        let ev = c.on_frame(&server_reply(&c, ACK, &std_opts()), Duration::ZERO);
        assert!(matches!(ev, Some(Event::Bound(_))));
        c
    }

    #[test]
    fn discover_offer_request_ack() {
        let mut c = Client::new(HOST, BOXID, 7);
        let (f, ev) = c.poll(Duration::ZERO);
        assert!(ev.is_none());
        let (dst, dst_ip, m) = msg(&f.unwrap());
        assert_eq!((dst, dst_ip), (Mac::BROADCAST, Ipv4Addr::BROADCAST));
        assert_eq!(option(&m, 53).unwrap(), [DISCOVER]);
        assert_eq!(m[10], 0x80, "broadcast flag");
        assert_eq!(&m[28..34], &HOST.0, "chaddr is the frames' MAC");
        let id = option(&m, 61).unwrap();
        assert_eq!((id[0], &id[1..]), (1, &BOXID.0[..]), "own client id");

        // Retries back off.
        assert!(c.poll(Duration::from_secs(3)).0.is_none());
        assert!(c.poll(Duration::from_secs(4)).0.is_some());

        // A reply to another transaction is ignored.
        let mut other = server_reply(&c, OFFER, &std_opts());
        other[14 + 20 + 8 + 4] ^= 1;
        assert!(c.on_frame(&other, Duration::from_secs(5)).is_none());
        assert!(c.lease().is_none());

        c.on_frame(
            &server_reply(&c, OFFER, &std_opts()),
            Duration::from_secs(5),
        );
        let (f, _) = c.poll(Duration::from_secs(5));
        let (_, _, m) = msg(&f.unwrap());
        assert_eq!(option(&m, 53).unwrap(), [REQUEST]);
        assert_eq!(option(&m, 50).unwrap(), OFFERED.octets());
        assert_eq!(option(&m, 54).unwrap(), SERVER.octets());

        let ev = c.on_frame(&server_reply(&c, ACK, &std_opts()), Duration::from_secs(6));
        let Some(Event::Bound(l)) = ev else {
            panic!("bound expected")
        };
        assert_eq!((l.ip, l.prefix, l.router), (OFFERED, 24, Some(SERVER)));
        assert_eq!(l.dns, [SERVER, Ipv4Addr::new(223, 5, 5, 5)]);
        assert_eq!(l.lease, Duration::from_secs(3600));
        assert_eq!(
            (l.renew, l.rebind),
            (Duration::from_secs(1800), Duration::from_secs(3150))
        );
        assert_eq!(l.server_mac, SERVER_MAC);
    }

    #[test]
    fn renew_is_unicast_then_rebind_broadcast_then_lost() {
        let mut c = bound();
        assert!(c.poll(Duration::from_secs(1799)).0.is_none());
        let (f, _) = c.poll(Duration::from_secs(1800));
        let (dst, dst_ip, m) = msg(&f.unwrap());
        assert_eq!((dst, dst_ip), (SERVER_MAC, SERVER));
        assert_eq!(&m[12..16], &OFFERED.octets(), "ciaddr");
        assert!(option(&m, 50).is_none() && option(&m, 54).is_none());
        // Server silent: rebinding by broadcast.
        let (f, _) = c.poll(Duration::from_secs(3150));
        let (dst, _, _) = msg(&f.unwrap());
        assert_eq!(dst, Mac::BROADCAST);
        // Still silent: the lease ends.
        let (_, ev) = c.poll(Duration::from_secs(3600));
        assert_eq!(ev, Some(Event::Lost));
        assert!(c.lease().is_none());
    }

    #[test]
    fn renewal_ack_extends_and_nak_loses() {
        let mut c = bound();
        c.poll(Duration::from_secs(1800));
        let ev = c.on_frame(
            &server_reply(&c, ACK, &std_opts()),
            Duration::from_secs(1801),
        );
        assert!(matches!(ev, Some(Event::Bound(_))));
        assert!(c.poll(Duration::from_secs(3600)).1.is_none(), "renewed");
        c.poll(Duration::from_secs(1801 + 1800));
        let ev = c.on_frame(&server_reply(&c, NAK, &[]), Duration::from_secs(3602));
        assert_eq!(ev, Some(Event::Lost));
    }

    #[test]
    fn release_is_unicast_to_the_server() {
        assert!(Client::new(HOST, BOXID, 1).release().is_none());
        let c = bound();
        let (dst, dst_ip, m) = msg(&c.release().unwrap());
        assert_eq!((dst, dst_ip), (SERVER_MAC, SERVER));
        assert_eq!(option(&m, 53).unwrap(), [RELEASE]);
        assert_eq!(option(&m, 54).unwrap(), SERVER.octets());
        assert_eq!(&m[12..16], &OFFERED.octets());
    }

    #[test]
    fn request_gives_up_after_four_tries() {
        let mut c = Client::new(HOST, BOXID, 7);
        c.poll(Duration::ZERO);
        c.on_frame(&server_reply(&c, OFFER, &std_opts()), Duration::ZERO);
        let mut t = Duration::ZERO;
        for _ in 0..4 {
            let (f, _) = c.poll(t);
            assert_eq!(option(&msg(&f.unwrap()).2, 53).unwrap(), [REQUEST]);
            t = c.next_wake();
        }
        let (f, _) = c.poll(t);
        assert_eq!(option(&msg(&f.unwrap()).2, 53).unwrap(), [DISCOVER]);
    }
}
