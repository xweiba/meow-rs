//! The splitter between the wire and the box's parts: decides per received
//! frame whether it is for the box itself, its DHCP client, its DNS front,
//! or traffic a LAN device sends through the box as its gateway; learns
//! which MAC each LAN address has; and turns the core's replies (IP
//! packets from the TUN) back into frames, asking by ARP first when the
//! address is new.

use std::collections::{HashMap, VecDeque};
use std::net::Ipv4Addr;

use crate::frame::{
    build_arp_request, build_eth, parse_arp, parse_eth, parse_ipv4, Mac, ARP_REPLY, ETHERTYPE_ARP,
    ETHERTYPE_IPV4, PROTO_UDP,
};

/// Where a received frame goes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// The box's own stack: ARP for its address, ping, TCP (the config
    /// page, DNS over TCP), anything else addressed to it.
    Local,
    /// A DHCP server's answer (UDP 67 → 68).
    Dhcp,
    /// A DNS query over UDP to the box's address.
    Dns,
    /// A LAN device's traffic routed through the box: into the core.
    Forward,
    /// Not for the box.
    Drop,
}

/// The box's IPv4 address and prefix length.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Addr {
    pub ip: Ipv4Addr,
    pub prefix: u8,
}

impl Addr {
    fn mask(self) -> u32 {
        if self.prefix == 0 {
            0
        } else {
            u32::MAX << (32 - u32::from(self.prefix.min(32)))
        }
    }

    /// `ip` is on this subnet.
    pub fn contains(self, ip: Ipv4Addr) -> bool {
        u32::from(ip) & self.mask() == u32::from(self.ip) & self.mask()
    }

    /// The subnet's broadcast address.
    pub fn broadcast(self) -> Ipv4Addr {
        Ipv4Addr::from(u32::from(self.ip) | !self.mask())
    }
}

/// A learnt LAN device.
#[derive(Debug, Clone, Copy)]
struct Neighbor {
    mac: Mac,
    /// Last frame from it (ms).
    seen: u64,
    /// Last time it sent traffic through the box (ms), if ever.
    gateway_at: Option<u64>,
}

/// Replies waiting for an address's MAC.
#[derive(Debug)]
struct Pending {
    packets: VecDeque<Vec<u8>>,
    first: u64,
    asked: u64,
}

/// Neighbours remembered at most (oldest forgotten first).
const MAX_NEIGHBORS: usize = 4096;
/// Replies queued per address while asking for its MAC.
const MAX_PENDING_PER_IP: usize = 16;
/// Addresses asked for at once.
const MAX_PENDING_IPS: usize = 256;
/// ARP is repeated this often while replies wait (ms)…
const ARP_RETRY_MS: u64 = 1000;
/// …and the replies are dropped after this long (ms).
const PENDING_TTL_MS: u64 = 3000;
/// A device counts as using the box as its gateway this long after its
/// last routed packet (ms).
const GATEWAY_TTL_MS: u64 = 30 * 60 * 1000;

/// The splitter's state.
#[derive(Debug)]
pub struct Switch {
    /// The box's MAC.
    pub mac: Mac,
    /// The box's address; None until DHCP binds.
    pub addr: Option<Addr>,
    /// The host's own addresses on the interface (Wi-Fi: the box shares
    /// the host's MAC, so frames for these belong to the host).
    pub host_ips: Vec<Ipv4Addr>,
    neighbors: HashMap<Ipv4Addr, Neighbor>,
    pending: HashMap<Ipv4Addr, Pending>,
    /// Frames ready to send (a learnt MAC released queued replies, ARP
    /// requests); drained by the caller.
    outbox: Vec<Vec<u8>>,
}

impl Switch {
    /// A switch for `mac`, no address yet.
    pub fn new(mac: Mac) -> Self {
        Self {
            mac,
            addr: None,
            host_ips: Vec::new(),
            neighbors: HashMap::new(),
            pending: HashMap::new(),
            outbox: Vec::new(),
        }
    }

    /// Frames to send now (after [`Self::classify`], [`Self::reply`],
    /// [`Self::tick`]).
    pub fn drain(&mut self) -> Vec<Vec<u8>> {
        std::mem::take(&mut self.outbox)
    }

    /// Where `frame` goes; learns its sender's MAC on the way.
    pub fn classify(&mut self, frame: &[u8], now: u64) -> Verdict {
        let Some(eth) = parse_eth(frame) else {
            return Verdict::Drop;
        };
        if eth.src == self.mac || eth.src.is_group() {
            return Verdict::Drop;
        }
        let to_us = eth.dst == self.mac;
        if !to_us && !eth.dst.is_group() {
            return Verdict::Drop;
        }
        match eth.ethertype {
            ETHERTYPE_ARP => {
                let Some(arp) = parse_arp(eth.payload) else {
                    return Verdict::Drop;
                };
                if !arp.sender_ip.is_unspecified() && self.on_link(arp.sender_ip) {
                    self.learn(arp.sender_ip, arp.sender_mac, now, false);
                }
                let mine = self.addr.is_some_and(|a| a.ip == arp.target_ip);
                if mine && (arp.op != ARP_REPLY || to_us) {
                    Verdict::Local
                } else {
                    Verdict::Drop
                }
            }
            ETHERTYPE_IPV4 => self.classify_ipv4(eth.payload, eth.src, to_us, now),
            _ => Verdict::Drop,
        }
    }

    fn classify_ipv4(&mut self, p: &[u8], src_mac: Mac, to_us: bool, now: u64) -> Verdict {
        let Some(ip) = parse_ipv4(p) else {
            return Verdict::Drop;
        };
        if ip.proto == PROTO_UDP && ip.ports(p).is_some_and(|ports| ports == (67, 68)) {
            return Verdict::Dhcp;
        }
        let Some(addr) = self.addr else {
            return Verdict::Drop;
        };
        if !to_us {
            // Broadcast / multicast IP: nothing the box answers.
            return Verdict::Drop;
        }
        if ip.dst == addr.ip {
            if addr.contains(ip.src) {
                self.learn(ip.src, src_mac, now, false);
            }
            return match ip.ports(p) {
                Some((_, 53)) if ip.proto == PROTO_UDP => Verdict::Dns,
                _ => Verdict::Local,
            };
        }
        let dst = ip.dst;
        if !addr.contains(ip.src)
            || ip.src == addr.ip
            || self.host_ips.contains(&dst)
            || dst == addr.broadcast()
            || dst.is_broadcast()
            || dst.is_multicast()
            || dst.is_unspecified()
            || dst.is_loopback()
        {
            return Verdict::Drop;
        }
        self.learn(ip.src, src_mac, now, true);
        Verdict::Forward
    }

    fn on_link(&self, ip: Ipv4Addr) -> bool {
        self.addr.is_none_or(|a| a.contains(ip))
    }

    fn learn(&mut self, ip: Ipv4Addr, mac: Mac, now: u64, via_gateway: bool) {
        let n = self.neighbors.entry(ip).or_insert(Neighbor {
            mac,
            seen: now,
            gateway_at: None,
        });
        n.mac = mac;
        n.seen = now;
        if via_gateway {
            n.gateway_at = Some(now);
        }
        if let Some(p) = self.pending.remove(&ip) {
            for packet in p.packets {
                self.outbox
                    .push(build_eth(mac, self.mac, ETHERTYPE_IPV4, &packet));
            }
        }
        if self.neighbors.len() > MAX_NEIGHBORS {
            if let Some(oldest) = self
                .neighbors
                .iter()
                .min_by_key(|(_, n)| n.seen)
                .map(|(ip, _)| *ip)
            {
                self.neighbors.remove(&oldest);
            }
        }
    }

    /// `ip` sent traffic through the box in the last 30 minutes.
    pub fn uses_gateway(&self, ip: Ipv4Addr, now: u64) -> bool {
        self.neighbors
            .get(&ip)
            .and_then(|n| n.gateway_at)
            .is_some_and(|t| now.saturating_sub(t) < GATEWAY_TTL_MS)
    }

    /// How many devices use the box as their gateway now.
    pub fn gateway_users(&self, now: u64) -> usize {
        self.neighbors
            .values()
            .filter(|n| {
                n.gateway_at
                    .is_some_and(|t| now.saturating_sub(t) < GATEWAY_TTL_MS)
            })
            .count()
    }

    /// The MAC learnt for `ip`.
    #[cfg(test)]
    pub fn mac_of(&self, ip: Ipv4Addr) -> Option<Mac> {
        self.neighbors.get(&ip).map(|n| n.mac)
    }

    /// A reply from the core (an IP packet) as a frame to its LAN device;
    /// when the device's MAC is not known yet the packet waits and an ARP
    /// request goes out (both via [`Self::drain`]).
    pub fn reply(&mut self, packet: &[u8], now: u64) -> Option<Vec<u8>> {
        let ip = parse_ipv4(packet)?;
        let addr = self.addr?;
        if !addr.contains(ip.dst) || ip.dst == addr.ip || ip.dst == addr.broadcast() {
            return None;
        }
        if let Some(n) = self.neighbors.get(&ip.dst) {
            return Some(build_eth(
                n.mac,
                self.mac,
                ETHERTYPE_IPV4,
                &packet[..ip.total_len],
            ));
        }
        if !self.pending.contains_key(&ip.dst) && self.pending.len() >= MAX_PENDING_IPS {
            return None;
        }
        let p = self.pending.entry(ip.dst).or_insert_with(|| {
            self.outbox
                .push(build_arp_request(self.mac, addr.ip, ip.dst));
            Pending {
                packets: VecDeque::new(),
                first: now,
                asked: now,
            }
        });
        if p.packets.len() < MAX_PENDING_PER_IP {
            p.packets.push_back(packet[..ip.total_len].to_vec());
        }
        None
    }

    /// Repeats ARP requests for waiting replies and drops the ones waited
    /// on too long. Call about every second.
    pub fn tick(&mut self, now: u64) {
        let Some(addr) = self.addr else {
            self.pending.clear();
            return;
        };
        self.pending
            .retain(|_, p| now.saturating_sub(p.first) < PENDING_TTL_MS);
        for (ip, p) in &mut self.pending {
            if now.saturating_sub(p.asked) >= ARP_RETRY_MS {
                p.asked = now;
                self.outbox.push(build_arp_request(self.mac, addr.ip, *ip));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::frame::{build_ipv4_udp, ARP_REQUEST};

    const BOX: Mac = Mac([2, 0, 0, 0, 0, 0x50]);
    const PHONE: Mac = Mac([0x3c, 0, 0, 0, 0, 0x10]);
    const BOX_IP: Ipv4Addr = Ipv4Addr::new(192, 168, 1, 50);
    const PHONE_IP: Ipv4Addr = Ipv4Addr::new(192, 168, 1, 10);
    const NET: Ipv4Addr = Ipv4Addr::new(1, 1, 1, 1);

    fn sw() -> Switch {
        let mut s = Switch::new(BOX);
        s.addr = Some(Addr {
            ip: BOX_IP,
            prefix: 24,
        });
        s
    }

    fn udp(dst_mac: Mac, src: Ipv4Addr, dst: Ipv4Addr, sport: u16, dport: u16) -> Vec<u8> {
        build_eth(
            dst_mac,
            PHONE,
            ETHERTYPE_IPV4,
            &build_ipv4_udp(src, dst, sport, dport, b"x", 1),
        )
    }

    fn arp(op: u16, dst: Mac, target: Ipv4Addr) -> Vec<u8> {
        let mut f = build_arp_request(PHONE, PHONE_IP, target);
        f[0..6].copy_from_slice(&dst.0);
        f[ETH_ARP_OP..ETH_ARP_OP + 2].copy_from_slice(&op.to_be_bytes());
        f
    }
    const ETH_ARP_OP: usize = 14 + 6;

    #[test]
    fn frames_split_by_destination() {
        let mut s = sw();
        assert_eq!(
            s.classify(&udp(BOX, PHONE_IP, BOX_IP, 5000, 53), 0),
            Verdict::Dns
        );
        assert_eq!(
            s.classify(&udp(BOX, PHONE_IP, BOX_IP, 5000, 123), 0),
            Verdict::Local
        );
        assert_eq!(
            s.classify(&udp(BOX, PHONE_IP, NET, 5000, 443), 0),
            Verdict::Forward
        );
        assert_eq!(
            s.classify(
                &udp(
                    Mac::BROADCAST,
                    Ipv4Addr::UNSPECIFIED,
                    Ipv4Addr::BROADCAST,
                    67,
                    68
                ),
                0
            ),
            Verdict::Dhcp
        );
        // Another device's unicast frame (seen in promiscuous mode).
        let other = Mac([2, 9, 9, 9, 9, 9]);
        assert_eq!(
            s.classify(&udp(other, PHONE_IP, NET, 1, 2), 0),
            Verdict::Drop
        );
        // Broadcast IP / subnet broadcast / from another subnet.
        let bc = Ipv4Addr::new(192, 168, 1, 255);
        assert_eq!(
            s.classify(&udp(Mac::BROADCAST, PHONE_IP, bc, 1, 2), 0),
            Verdict::Drop
        );
        assert_eq!(s.classify(&udp(BOX, PHONE_IP, bc, 1, 2), 0), Verdict::Drop);
        let far = Ipv4Addr::new(10, 0, 0, 2);
        assert_eq!(s.classify(&udp(BOX, far, NET, 1, 2), 0), Verdict::Drop);
        // Our own frames coming back.
        let mut own = udp(BOX, PHONE_IP, NET, 1, 2);
        own[6..12].copy_from_slice(&BOX.0);
        assert_eq!(s.classify(&own, 0), Verdict::Drop);
        // Non-IPv4.
        let v6 = build_eth(BOX, PHONE, 0x86dd, &[0; 40]);
        assert_eq!(s.classify(&v6, 0), Verdict::Drop);
    }

    #[test]
    fn arp_for_us_is_local_and_learnt() {
        let mut s = sw();
        assert_eq!(
            s.classify(&arp(ARP_REQUEST, Mac::BROADCAST, BOX_IP), 5),
            Verdict::Local
        );
        assert_eq!(s.mac_of(PHONE_IP), Some(PHONE));
        let other = Ipv4Addr::new(192, 168, 1, 1);
        assert_eq!(
            s.classify(&arp(ARP_REQUEST, Mac::BROADCAST, other), 5),
            Verdict::Drop
        );
        assert_eq!(s.classify(&arp(ARP_REPLY, BOX, BOX_IP), 5), Verdict::Local);
        // A reply to someone else that names our IP (gratuitous) stays out.
        assert_eq!(
            s.classify(&arp(ARP_REPLY, Mac::BROADCAST, BOX_IP), 5),
            Verdict::Drop
        );
    }

    #[test]
    fn nothing_but_dhcp_before_an_address() {
        let mut s = Switch::new(BOX);
        assert_eq!(
            s.classify(&udp(BOX, PHONE_IP, BOX_IP, 5000, 53), 0),
            Verdict::Drop
        );
        assert_eq!(
            s.classify(&udp(BOX, PHONE_IP, NET, 5000, 53), 0),
            Verdict::Drop
        );
        assert_eq!(
            s.classify(&arp(ARP_REQUEST, Mac::BROADCAST, BOX_IP), 0),
            Verdict::Drop
        );
        assert_eq!(s.classify(&udp(BOX, NET, BOX_IP, 67, 68), 0), Verdict::Dhcp);
    }

    #[test]
    fn host_addresses_stay_with_the_host() {
        // Wi-Fi: the box answers on the host's MAC.
        let mut s = sw();
        let host = Ipv4Addr::new(192, 168, 1, 7);
        s.host_ips = vec![host];
        assert_eq!(
            s.classify(&udp(BOX, PHONE_IP, host, 1, 22), 0),
            Verdict::Drop
        );
    }

    #[test]
    fn gateway_users_are_the_ones_routing_through_us() {
        let mut s = sw();
        s.classify(&udp(BOX, PHONE_IP, BOX_IP, 5000, 53), 0);
        assert!(!s.uses_gateway(PHONE_IP, 0), "DNS alone is not the gateway");
        s.classify(&udp(BOX, PHONE_IP, NET, 5000, 443), 10);
        assert!(s.uses_gateway(PHONE_IP, 10));
        assert_eq!(s.gateway_users(10), 1);
        assert!(!s.uses_gateway(PHONE_IP, 10 + GATEWAY_TTL_MS));
        assert_eq!(s.gateway_users(10 + GATEWAY_TTL_MS), 0);
    }

    #[test]
    fn replies_to_known_devices_are_framed() {
        let mut s = sw();
        s.classify(&udp(BOX, PHONE_IP, NET, 5000, 443), 0);
        let reply = build_ipv4_udp(NET, PHONE_IP, 443, 5000, b"ok", 2);
        let f = s.reply(&reply, 1).unwrap();
        let e = parse_eth(&f).unwrap();
        assert_eq!((e.dst, e.src, e.ethertype), (PHONE, BOX, ETHERTYPE_IPV4));
        assert_eq!(&e.payload[..reply.len()], &reply[..]);
        // Not on our subnet: nowhere to send it.
        let off = build_ipv4_udp(NET, Ipv4Addr::new(10, 0, 0, 1), 1, 2, b"", 3);
        assert!(s.reply(&off, 1).is_none());
    }

    #[test]
    fn unknown_devices_are_asked_by_arp_first() {
        let mut s = sw();
        let reply = build_ipv4_udp(NET, PHONE_IP, 443, 5000, b"ok", 2);
        assert!(s.reply(&reply, 0).is_none());
        assert!(s.reply(&reply, 0).is_none());
        let out = s.drain();
        assert_eq!(out.len(), 1, "one ARP request for two waiting replies");
        let a = parse_arp(parse_eth(&out[0]).unwrap().payload).unwrap();
        assert_eq!(
            (a.op, a.sender_ip, a.target_ip),
            (ARP_REQUEST, BOX_IP, PHONE_IP)
        );
        s.tick(500);
        assert!(s.drain().is_empty());
        s.tick(1000);
        assert_eq!(s.drain().len(), 1, "asked again");
        // The answer releases both replies.
        s.classify(&arp(ARP_REPLY, BOX, BOX_IP), 1200);
        let out = s.drain();
        assert_eq!(out.len(), 2);
        assert_eq!(parse_eth(&out[0]).unwrap().dst, PHONE);
        // A device that never answers: dropped after the TTL.
        let ghost = Ipv4Addr::new(192, 168, 1, 99);
        s.reply(&build_ipv4_udp(NET, ghost, 1, 2, b"", 4), 2000);
        s.drain();
        s.tick(2000 + PENDING_TTL_MS);
        assert!(s.drain().is_empty());
        s.classify(
            &{
                let mut f = arp(ARP_REPLY, BOX, BOX_IP);
                f[14 + 14..14 + 18].copy_from_slice(&ghost.octets());
                f
            },
            9000,
        );
        assert!(s.drain().is_empty(), "nothing left to release");
    }

    #[test]
    fn addr_math() {
        let a = Addr {
            ip: BOX_IP,
            prefix: 24,
        };
        assert!(a.contains(PHONE_IP));
        assert!(!a.contains(NET));
        assert_eq!(a.broadcast(), Ipv4Addr::new(192, 168, 1, 255));
        let any = Addr {
            ip: BOX_IP,
            prefix: 0,
        };
        assert!(any.contains(NET));
    }
}
