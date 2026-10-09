//! Ethernet, ARP, IPv4, UDP and TCP on the wire: just the fields the box
//! reads and the few frames it builds itself (ARP requests, DNS replies,
//! DHCP). Pure functions over byte slices.

use std::fmt;
use std::net::Ipv4Addr;

/// Ethernet header length (no VLAN tag).
pub const ETH_HDR: usize = 14;
/// Shortest Ethernet frame without the FCS; shorter frames are padded.
const ETH_MIN: usize = 60;
/// EtherType: IPv4.
pub const ETHERTYPE_IPV4: u16 = 0x0800;
/// EtherType: ARP.
pub const ETHERTYPE_ARP: u16 = 0x0806;
/// IP protocol: TCP.
pub const PROTO_TCP: u8 = 6;
/// IP protocol: UDP.
pub const PROTO_UDP: u8 = 17;

/// A MAC address.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct Mac(pub [u8; 6]);

impl Mac {
    /// ff:ff:ff:ff:ff:ff.
    pub const BROADCAST: Self = Self([0xff; 6]);

    /// Broadcast or multicast (group bit set).
    pub fn is_group(self) -> bool {
        self.0[0] & 1 == 1
    }

    /// `aa:bb:cc:dd:ee:ff` (case-insensitive); None when malformed.
    pub fn parse(s: &str) -> Option<Self> {
        let mut out = [0u8; 6];
        let mut parts = s.trim().split(':');
        for b in &mut out {
            *b = u8::from_str_radix(parts.next()?, 16).ok()?;
        }
        parts.next().is_none().then_some(Self(out))
    }

    /// A random locally administered unicast address (`x2:…`, `x6:…`, …).
    pub fn random_local(mut bytes: [u8; 6]) -> Self {
        bytes[0] = (bytes[0] & 0xfc) | 0x02;
        Self(bytes)
    }
}

impl fmt::Display for Mac {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let m = self.0;
        write!(
            f,
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            m[0], m[1], m[2], m[3], m[4], m[5]
        )
    }
}

impl fmt::Debug for Mac {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

/// An Ethernet frame's header and payload.
#[derive(Debug, Clone, Copy)]
pub struct Eth<'a> {
    pub dst: Mac,
    pub src: Mac,
    pub ethertype: u16,
    pub payload: &'a [u8],
}

fn mac_at(b: &[u8], at: usize) -> Mac {
    let mut m = [0u8; 6];
    m.copy_from_slice(&b[at..at + 6]);
    Mac(m)
}

fn ip_at(b: &[u8], at: usize) -> Ipv4Addr {
    Ipv4Addr::new(b[at], b[at + 1], b[at + 2], b[at + 3])
}

fn u16_at(b: &[u8], at: usize) -> u16 {
    u16::from_be_bytes([b[at], b[at + 1]])
}

/// The Ethernet header; None when shorter than one.
pub fn parse_eth(frame: &[u8]) -> Option<Eth<'_>> {
    if frame.len() < ETH_HDR {
        return None;
    }
    Some(Eth {
        dst: mac_at(frame, 0),
        src: mac_at(frame, 6),
        ethertype: u16_at(frame, 12),
        payload: &frame[ETH_HDR..],
    })
}

/// An Ethernet frame: header + payload, padded to the 60-byte minimum.
pub fn build_eth(dst: Mac, src: Mac, ethertype: u16, payload: &[u8]) -> Vec<u8> {
    let mut f = Vec::with_capacity((ETH_HDR + payload.len()).max(ETH_MIN));
    f.extend_from_slice(&dst.0);
    f.extend_from_slice(&src.0);
    f.extend_from_slice(&ethertype.to_be_bytes());
    f.extend_from_slice(payload);
    if f.len() < ETH_MIN {
        f.resize(ETH_MIN, 0);
    }
    f
}

/// ARP opcode: request.
pub const ARP_REQUEST: u16 = 1;
/// ARP opcode: reply.
pub const ARP_REPLY: u16 = 2;

/// An Ethernet/IPv4 ARP packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Arp {
    pub op: u16,
    pub sender_mac: Mac,
    pub sender_ip: Ipv4Addr,
    pub target_mac: Mac,
    pub target_ip: Ipv4Addr,
}

/// An Ethernet/IPv4 ARP packet (the Ethernet payload); None otherwise.
pub fn parse_arp(p: &[u8]) -> Option<Arp> {
    if p.len() < 28 || u16_at(p, 0) != 1 || u16_at(p, 2) != ETHERTYPE_IPV4 || p[4] != 6 || p[5] != 4
    {
        return None;
    }
    Some(Arp {
        op: u16_at(p, 6),
        sender_mac: mac_at(p, 8),
        sender_ip: ip_at(p, 14),
        target_mac: mac_at(p, 18),
        target_ip: ip_at(p, 24),
    })
}

/// A broadcast "who has `target`" frame from `mac` / `ip`.
pub fn build_arp_request(mac: Mac, ip: Ipv4Addr, target: Ipv4Addr) -> Vec<u8> {
    let mut p = Vec::with_capacity(28);
    p.extend_from_slice(&1u16.to_be_bytes());
    p.extend_from_slice(&ETHERTYPE_IPV4.to_be_bytes());
    p.extend_from_slice(&[6, 4]);
    p.extend_from_slice(&ARP_REQUEST.to_be_bytes());
    p.extend_from_slice(&mac.0);
    p.extend_from_slice(&ip.octets());
    p.extend_from_slice(&[0; 6]);
    p.extend_from_slice(&target.octets());
    build_eth(Mac::BROADCAST, mac, ETHERTYPE_ARP, &p)
}

/// The IPv4 header fields the box looks at.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ipv4 {
    pub src: Ipv4Addr,
    pub dst: Ipv4Addr,
    pub proto: u8,
    /// Header length in bytes.
    pub header_len: usize,
    /// Total length from the header (≤ the slice).
    pub total_len: usize,
    /// A fragment other than the first (no transport header in it).
    pub later_fragment: bool,
    /// More fragments follow, or this is a later one.
    pub fragmented: bool,
}

impl Ipv4 {
    /// The transport header + payload of `packet`.
    pub fn l4<'a>(&self, packet: &'a [u8]) -> &'a [u8] {
        &packet[self.header_len..self.total_len]
    }

    /// (source port, destination port) of a TCP / UDP packet's first
    /// fragment; None otherwise.
    pub fn ports(&self, packet: &[u8]) -> Option<(u16, u16)> {
        if self.later_fragment || !matches!(self.proto, PROTO_TCP | PROTO_UDP) {
            return None;
        }
        let l4 = self.l4(packet);
        (l4.len() >= 4).then(|| (u16_at(l4, 0), u16_at(l4, 2)))
    }
}

/// An IPv4 packet's header; None when not a sane IPv4 packet.
pub fn parse_ipv4(p: &[u8]) -> Option<Ipv4> {
    if p.len() < 20 || p[0] >> 4 != 4 {
        return None;
    }
    let header_len = usize::from(p[0] & 0x0f) * 4;
    let total_len = usize::from(u16_at(p, 2));
    if header_len < 20 || total_len < header_len || total_len > p.len() {
        return None;
    }
    let frag = u16_at(p, 6);
    let offset = frag & 0x1fff;
    let more = frag & 0x2000 != 0;
    Some(Ipv4 {
        src: ip_at(p, 12),
        dst: ip_at(p, 16),
        proto: p[9],
        header_len,
        total_len,
        later_fragment: offset != 0,
        fragmented: more || offset != 0,
    })
}

/// Ones' complement sum of `data` folded into 16 bits, starting at `sum`.
fn sum16(mut sum: u32, data: &[u8]) -> u32 {
    let (pairs, rest) = data.as_chunks::<2>();
    for c in pairs {
        sum += u32::from(u16::from_be_bytes(*c));
    }
    if let [last] = rest {
        sum += u32::from(*last) << 8;
    }
    sum
}

fn fold(mut sum: u32) -> u16 {
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

/// The Internet checksum of `data`.
pub fn checksum(data: &[u8]) -> u16 {
    fold(sum16(0, data))
}

/// Recomputes the IPv4 header checksum in place.
fn fill_ip_checksum(p: &mut [u8], header_len: usize) {
    p[10] = 0;
    p[11] = 0;
    let c = checksum(&p[..header_len]);
    p[10..12].copy_from_slice(&c.to_be_bytes());
}

/// TCP / UDP checksum over the pseudo-header and `l4` (with its checksum
/// field zeroed by the caller).
fn l4_checksum(src: Ipv4Addr, dst: Ipv4Addr, proto: u8, l4: &[u8]) -> u16 {
    let mut pseudo = [0u8; 12];
    pseudo[0..4].copy_from_slice(&src.octets());
    pseudo[4..8].copy_from_slice(&dst.octets());
    pseudo[9] = proto;
    let len = u16::try_from(l4.len()).unwrap_or(u16::MAX);
    pseudo[10..12].copy_from_slice(&len.to_be_bytes());
    fold(sum16(sum16(0, &pseudo), l4))
}

/// Recomputes the IPv4 header and TCP / UDP checksums of `packet` in
/// place: a NIC that offloads checksums hands frames from local guests
/// (veth, bridges) to packet sockets with them unfinished. Unfragmented
/// TCP / UDP only; anything else keeps its transport checksum.
pub fn fill_checksums(packet: &mut [u8]) {
    let Some(ip) = parse_ipv4(packet) else {
        return;
    };
    fill_ip_checksum(packet, ip.header_len);
    if ip.fragmented {
        return;
    }
    let at = match ip.proto {
        PROTO_TCP if ip.total_len - ip.header_len >= 20 => 16,
        PROTO_UDP if ip.total_len - ip.header_len >= 8 => 6,
        _ => return,
    };
    let l4 = &mut packet[ip.header_len..ip.total_len];
    l4[at] = 0;
    l4[at + 1] = 0;
    let mut c = l4_checksum(ip.src, ip.dst, ip.proto, l4);
    if ip.proto == PROTO_UDP && c == 0 {
        c = 0xffff;
    }
    l4[at..at + 2].copy_from_slice(&c.to_be_bytes());
}

/// An IPv4 + UDP packet with both checksums (TTL 64, DF set).
pub fn build_ipv4_udp(
    src: Ipv4Addr,
    dst: Ipv4Addr,
    sport: u16,
    dport: u16,
    payload: &[u8],
    id: u16,
) -> Vec<u8> {
    let total = 20 + 8 + payload.len();
    let mut p = vec![0u8; total];
    p[0] = 0x45;
    p[2..4].copy_from_slice(&u16::try_from(total).unwrap_or(u16::MAX).to_be_bytes());
    p[4..6].copy_from_slice(&id.to_be_bytes());
    p[6] = 0x40;
    p[8] = 64;
    p[9] = PROTO_UDP;
    p[12..16].copy_from_slice(&src.octets());
    p[16..20].copy_from_slice(&dst.octets());
    let udp_len = u16::try_from(8 + payload.len()).unwrap_or(u16::MAX);
    p[20..22].copy_from_slice(&sport.to_be_bytes());
    p[22..24].copy_from_slice(&dport.to_be_bytes());
    p[24..26].copy_from_slice(&udp_len.to_be_bytes());
    p[28..].copy_from_slice(payload);
    fill_checksums(&mut p);
    p
}

/// Splits an IPv4 TCP packet longer than `mtu` into segments that fit
/// (sequence numbers advanced, FIN / PSH on the last one only, checksums
/// recomputed). Receive offload (GRO) merges a flow's segments before a
/// packet socket sees them; the core's TUN takes at most one MTU. Anything
/// else, or a packet that already fits, comes back unchanged.
pub fn segment_tcp(packet: &[u8], mtu: usize) -> Vec<Vec<u8>> {
    let Some(ip) = parse_ipv4(packet) else {
        return vec![packet.to_vec()];
    };
    if ip.total_len <= mtu || ip.proto != PROTO_TCP || ip.fragmented {
        return vec![packet[..ip.total_len].to_vec()];
    }
    let l4 = ip.l4(packet);
    if l4.len() < 20 {
        return vec![packet[..ip.total_len].to_vec()];
    }
    let tcp_len = usize::from(l4[12] >> 4) * 4;
    if tcp_len < 20 || tcp_len > l4.len() || ip.header_len + tcp_len >= mtu {
        return vec![packet[..ip.total_len].to_vec()];
    }
    let data = &l4[tcp_len..];
    let mss = mtu - ip.header_len - tcp_len;
    let seq = u32::from_be_bytes([l4[4], l4[5], l4[6], l4[7]]);
    let flags = l4[13];
    let id = u16_at(packet, 4);
    let chunks: Vec<&[u8]> = data.chunks(mss).collect();
    let last = chunks.len() - 1;
    chunks
        .iter()
        .enumerate()
        .map(|(i, chunk)| {
            let mut p = Vec::with_capacity(ip.header_len + tcp_len + chunk.len());
            p.extend_from_slice(&packet[..ip.header_len]);
            p.extend_from_slice(&l4[..tcp_len]);
            p.extend_from_slice(chunk);
            let total = u16::try_from(p.len()).unwrap_or(u16::MAX);
            p[2..4].copy_from_slice(&total.to_be_bytes());
            let n = u16::try_from(i).unwrap_or(0);
            p[4..6].copy_from_slice(&id.wrapping_add(n).to_be_bytes());
            let t = ip.header_len;
            let off = u32::try_from(i * mss).unwrap_or(0);
            p[t + 4..t + 8].copy_from_slice(&seq.wrapping_add(off).to_be_bytes());
            if i != last {
                // FIN 0x01, PSH 0x08: only the last segment carries them.
                p[t + 13] = flags & !0x09;
            }
            fill_checksums(&mut p);
            p
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    const A: Ipv4Addr = Ipv4Addr::new(192, 168, 1, 10);
    const B: Ipv4Addr = Ipv4Addr::new(192, 168, 1, 50);

    fn tcp_packet(payload_len: usize, flags: u8) -> Vec<u8> {
        let total = 20 + 20 + payload_len;
        let mut p = vec![0u8; total];
        p[0] = 0x45;
        p[2..4].copy_from_slice(&(total as u16).to_be_bytes());
        p[4..6].copy_from_slice(&7u16.to_be_bytes());
        p[8] = 64;
        p[9] = PROTO_TCP;
        p[12..16].copy_from_slice(&A.octets());
        p[16..20].copy_from_slice(&B.octets());
        p[20..22].copy_from_slice(&40000u16.to_be_bytes());
        p[22..24].copy_from_slice(&443u16.to_be_bytes());
        p[24..28].copy_from_slice(&1000u32.to_be_bytes());
        p[32] = 5 << 4;
        p[33] = flags;
        for (i, b) in p[40..].iter_mut().enumerate() {
            *b = i as u8;
        }
        fill_checksums(&mut p);
        p
    }

    fn checksums_ok(p: &[u8]) -> bool {
        let ip = parse_ipv4(p).unwrap();
        checksum(&p[..ip.header_len]) == 0 && l4_checksum(ip.src, ip.dst, ip.proto, ip.l4(p)) == 0
    }

    #[test]
    fn mac_parse_print_and_local() {
        let m = Mac::parse("02:AB:cd:00:01:ff").unwrap();
        assert_eq!(m.to_string(), "02:ab:cd:00:01:ff");
        assert!(Mac::parse("02:ab:cd:00:01").is_none());
        assert!(Mac::parse("02:ab:cd:00:01:ff:00").is_none());
        let r = Mac::random_local([0xff; 6]);
        assert_eq!(r.0[0], 0xfe, "local bit on, group bit off");
        assert!(!r.is_group());
        assert!(Mac::BROADCAST.is_group());
    }

    #[test]
    fn arp_request_round_trip() {
        let mac = Mac([2, 0, 0, 0, 0, 1]);
        let f = build_arp_request(mac, B, A);
        assert_eq!(f.len(), 60, "padded");
        let e = parse_eth(&f).unwrap();
        assert_eq!(e.dst, Mac::BROADCAST);
        assert_eq!(e.ethertype, ETHERTYPE_ARP);
        let a = parse_arp(e.payload).unwrap();
        assert_eq!(a.op, ARP_REQUEST);
        assert_eq!((a.sender_mac, a.sender_ip, a.target_ip), (mac, B, A));
    }

    #[test]
    fn udp_build_parse_and_checksums() {
        let p = build_ipv4_udp(B, A, 53, 5353, b"hello", 1);
        let ip = parse_ipv4(&p).unwrap();
        assert_eq!((ip.src, ip.dst, ip.proto), (B, A, PROTO_UDP));
        assert_eq!(ip.ports(&p), Some((53, 5353)));
        assert_eq!(&ip.l4(&p)[8..], b"hello");
        assert!(checksums_ok(&p));
    }

    #[test]
    fn checksum_fill_repairs_offloaded_packets() {
        let mut p = tcp_packet(100, 0x18);
        p[36] ^= 0xff; // a partial (pseudo-header only) checksum
        assert!(!checksums_ok(&p));
        fill_checksums(&mut p);
        assert!(checksums_ok(&p));
    }

    #[test]
    fn ipv4_rejects_short_and_bad_lengths() {
        assert!(parse_ipv4(&[0x45; 10]).is_none());
        let mut p = tcp_packet(0, 0x02);
        p[2..4].copy_from_slice(&999u16.to_be_bytes());
        assert!(parse_ipv4(&p).is_none());
        let mut p = tcp_packet(0, 0x02);
        p[6] = 0x20; // more fragments
        let ip = parse_ipv4(&p).unwrap();
        assert!(ip.fragmented && !ip.later_fragment);
        p[7] = 1; // offset 8
        let ip = parse_ipv4(&p).unwrap();
        assert!(ip.later_fragment);
        assert_eq!(ip.ports(&p), None);
    }

    #[test]
    fn oversized_tcp_is_segmented() {
        let p = tcp_packet(3000, 0x19); // FIN|PSH|ACK
        let segs = segment_tcp(&p, 1500);
        assert_eq!(segs.len(), 3);
        let mut data = Vec::new();
        for (i, s) in segs.iter().enumerate() {
            assert!(s.len() <= 1500);
            assert!(checksums_ok(s));
            let seq = u32::from_be_bytes([s[24], s[25], s[26], s[27]]);
            assert_eq!(seq as usize, 1000 + i * 1460);
            let last = i == segs.len() - 1;
            assert_eq!(s[33], if last { 0x19 } else { 0x10 });
            data.extend_from_slice(&s[40..]);
        }
        assert_eq!(data, p[40..]);
        assert_eq!(segment_tcp(&tcp_packet(10, 0x18), 1500).len(), 1);
    }
}
