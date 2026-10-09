//! Linux system pieces: the interface's facts, the raw (AF_PACKET) socket
//! the box lives on, and the socket pair that stands in for a TUN device.
//! Nothing here changes the host's settings: the promiscuous membership
//! belongs to the socket and ends with it.

use std::ffi::CString;
use std::fs;
use std::io;
use std::mem::{size_of, zeroed};
use std::net::Ipv4Addr;
use std::os::fd::{AsRawFd, FromRawFd as _, OwnedFd, RawFd};
use std::path::Path;

use anyhow::{bail, Context as _};

use crate::frame::Mac;

// Kernel ABI (linux/if_packet.h); stable, spelled out so the box does not
// depend on a libc release that has them.
const SOL_PACKET: libc::c_int = 263;
const PACKET_ADD_MEMBERSHIP: libc::c_int = 1;
const PACKET_AUXDATA: libc::c_int = 8;
const PACKET_IGNORE_OUTGOING: libc::c_int = 23;
const PACKET_MR_PROMISC: libc::c_ushort = 1;
const PACKET_OUTGOING: u8 = 4;
const TP_STATUS_CSUMNOTREADY: u32 = 1 << 3;
const TP_STATUS_VLAN_VALID: u32 = 1 << 4;
const ETH_P_ALL: u16 = 0x0003;

#[repr(C)]
struct PacketMreq {
    mr_ifindex: libc::c_int,
    mr_type: libc::c_ushort,
    mr_alen: libc::c_ushort,
    mr_address: [u8; 8],
}

#[repr(C)]
#[derive(Clone, Copy)]
struct TpacketAuxdata {
    tp_status: u32,
    tp_len: u32,
    tp_snaplen: u32,
    tp_mac: u16,
    tp_net: u16,
    tp_vlan_tci: u16,
    tp_vlan_tpid: u16,
}

/// Facts about the network interface the box joins.
#[derive(Debug, Clone)]
pub struct Iface {
    pub name: String,
    pub index: i32,
    /// The host's MAC on it.
    pub mac: Mac,
    /// A Wi-Fi interface (one MAC per station: the box borrows the host's).
    pub wireless: bool,
}

/// The interface of the host's IPv4 default route.
pub fn default_iface() -> Option<String> {
    let text = fs::read_to_string("/proc/net/route").ok()?;
    text.lines().skip(1).find_map(|l| {
        let f: Vec<&str> = l.split_whitespace().collect();
        (f.len() > 2 && f[1] == "00000000").then(|| f[0].to_owned())
    })
}

/// Reads `name`'s facts.
pub fn iface(name: &str) -> anyhow::Result<Iface> {
    let base = Path::new("/sys/class/net").join(name);
    if !base.exists() {
        bail!("网卡 {name} 不存在（用 --iface 指定，例如 eth0）");
    }
    let cname = CString::new(name).context("bad interface name")?;
    // SAFETY: a valid NUL-terminated string.
    let index = unsafe { libc::if_nametoindex(cname.as_ptr()) };
    if index == 0 {
        bail!("网卡 {name} 不存在");
    }
    let mac = fs::read_to_string(base.join("address"))
        .ok()
        .and_then(|s| Mac::parse(&s))
        .with_context(|| format!("网卡 {name} 没有以太网地址"))?;
    Ok(Iface {
        name: name.to_owned(),
        index: i32::try_from(index).unwrap_or(i32::MAX),
        mac,
        wireless: base.join("wireless").exists() || base.join("phy80211").exists(),
    })
}

/// The host forwards IPv4 between interfaces (`net.ipv4.ip_forward`).
pub fn ip_forward() -> bool {
    fs::read_to_string("/proc/sys/net/ipv4/ip_forward").is_ok_and(|s| s.trim() == "1")
}

/// The host's own IPv4 addresses on `name`.
pub fn host_ips(name: &str) -> Vec<Ipv4Addr> {
    let mut out = Vec::new();
    let mut ifap: *mut libc::ifaddrs = std::ptr::null_mut();
    // SAFETY: getifaddrs fills a list freed below with freeifaddrs.
    if unsafe { libc::getifaddrs(&mut ifap) } != 0 {
        return out;
    }
    let mut cur = ifap;
    while !cur.is_null() {
        // SAFETY: a node of the list getifaddrs returned.
        let ifa = unsafe { &*cur };
        cur = ifa.ifa_next;
        if ifa.ifa_addr.is_null() || ifa.ifa_name.is_null() {
            continue;
        }
        // SAFETY: NUL-terminated name from the kernel.
        let n = unsafe { std::ffi::CStr::from_ptr(ifa.ifa_name) };
        // SAFETY: ifa_addr is non-null; its family says its type.
        let fam = i32::from(unsafe { (*ifa.ifa_addr).sa_family });
        if n.to_bytes() != name.as_bytes() || fam != libc::AF_INET {
            continue;
        }
        // SAFETY: AF_INET → sockaddr_in.
        let sin = unsafe { &*ifa.ifa_addr.cast::<libc::sockaddr_in>() };
        out.push(Ipv4Addr::from(u32::from_be(sin.sin_addr.s_addr)));
    }
    // SAFETY: the list from getifaddrs above.
    unsafe { libc::freeifaddrs(ifap) };
    out
}

fn cvt(r: libc::c_int) -> io::Result<libc::c_int> {
    if r < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(r)
    }
}

fn setsockopt<T>(fd: RawFd, level: libc::c_int, name: libc::c_int, v: &T) -> io::Result<()> {
    // SAFETY: `v` is a live value of the option's type.
    cvt(unsafe {
        libc::setsockopt(
            fd,
            level,
            name,
            std::ptr::from_ref(v).cast(),
            libc::socklen_t::try_from(size_of::<T>()).unwrap_or(0),
        )
    })
    .map(drop)
}

/// A received frame's facts.
#[derive(Debug, Clone, Copy)]
pub struct Received {
    pub len: usize,
    /// The sender offloaded its checksums (a local guest): fill them in.
    pub csum_not_ready: bool,
}

/// An AF_PACKET socket bound to one interface. Dropping it closes the
/// socket, which also ends the promiscuous membership.
#[derive(Debug)]
pub struct RawSocket {
    fd: OwnedFd,
}

impl AsRawFd for RawSocket {
    fn as_raw_fd(&self) -> RawFd {
        self.fd.as_raw_fd()
    }
}

impl RawSocket {
    /// Opens a non-blocking packet socket on `ifindex` that skips the
    /// host's own outgoing frames; `promisc`: also receive frames for other
    /// MACs (the box's own).
    pub fn open(ifindex: i32, promisc: bool) -> anyhow::Result<Self> {
        // SAFETY: plain socket(2).
        let fd = cvt(unsafe {
            libc::socket(
                libc::AF_PACKET,
                libc::SOCK_RAW | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC,
                libc::c_int::from(ETH_P_ALL.to_be()),
            )
        })
        .map_err(|e| {
            if e.raw_os_error() == Some(libc::EPERM) {
                anyhow::anyhow!("需要 root（或 CAP_NET_RAW）才能接入网卡：{e}")
            } else {
                anyhow::anyhow!("cannot open the raw socket: {e}")
            }
        })?;
        // SAFETY: a fresh descriptor we own.
        let fd = unsafe { OwnedFd::from_raw_fd(fd) };
        let raw = fd.as_raw_fd();
        // SAFETY: zeroed sockaddr_ll is valid; fields set below.
        let mut sll: libc::sockaddr_ll = unsafe { zeroed() };
        sll.sll_family = libc::AF_PACKET as u16;
        sll.sll_protocol = ETH_P_ALL.to_be();
        sll.sll_ifindex = ifindex;
        // SAFETY: binding to a sockaddr_ll of the right size.
        cvt(unsafe {
            libc::bind(
                raw,
                std::ptr::from_ref(&sll).cast(),
                libc::socklen_t::try_from(size_of::<libc::sockaddr_ll>()).unwrap_or(0),
            )
        })
        .context("cannot bind the raw socket to the interface")?;
        // Older kernels lack it: outgoing frames are then skipped by type.
        let _ = setsockopt(raw, SOL_PACKET, PACKET_IGNORE_OUTGOING, &1i32);
        setsockopt(raw, SOL_PACKET, PACKET_AUXDATA, &1i32).context("PACKET_AUXDATA")?;
        let _ = setsockopt(raw, libc::SOL_SOCKET, libc::SO_RCVBUF, &(4i32 << 20));
        if promisc {
            let mreq = PacketMreq {
                mr_ifindex: ifindex,
                mr_type: PACKET_MR_PROMISC,
                mr_alen: 0,
                mr_address: [0; 8],
            };
            setsockopt(raw, SOL_PACKET, PACKET_ADD_MEMBERSHIP, &mreq)
                .context("cannot put the interface in promiscuous mode")?;
        }
        Ok(Self { fd })
    }

    /// One frame into `buf`; Ok(None) for frames to skip (the host's
    /// outgoing ones, VLAN-tagged ones). `WouldBlock` when none is waiting.
    pub fn recv(&self, buf: &mut [u8]) -> io::Result<Option<Received>> {
        // SAFETY: zeroed C structs, filled by recvmsg below.
        let mut sll: libc::sockaddr_ll = unsafe { zeroed() };
        let mut cmsg = [0u64; 16];
        let mut iov = libc::iovec {
            iov_base: buf.as_mut_ptr().cast(),
            iov_len: buf.len(),
        };
        // SAFETY: as above.
        let mut msg: libc::msghdr = unsafe { zeroed() };
        msg.msg_name = std::ptr::from_mut(&mut sll).cast();
        msg.msg_namelen = libc::socklen_t::try_from(size_of::<libc::sockaddr_ll>()).unwrap_or(0);
        msg.msg_iov = &mut iov;
        msg.msg_iovlen = 1;
        msg.msg_control = cmsg.as_mut_ptr().cast();
        msg.msg_controllen = size_of::<[u64; 16]>();
        // SAFETY: every pointer in `msg` is live for the call.
        let n = unsafe { libc::recvmsg(self.fd.as_raw_fd(), &mut msg, libc::MSG_TRUNC) };
        if n < 0 {
            return Err(io::Error::last_os_error());
        }
        let n = usize::try_from(n).unwrap_or(0);
        if sll.sll_pkttype == PACKET_OUTGOING || n > buf.len() {
            return Ok(None);
        }
        let mut status = 0u32;
        // SAFETY: walking the control messages recvmsg wrote.
        unsafe {
            let mut c = libc::CMSG_FIRSTHDR(&msg);
            while !c.is_null() {
                if (*c).cmsg_level == SOL_PACKET && (*c).cmsg_type == PACKET_AUXDATA {
                    let aux = std::ptr::read_unaligned(libc::CMSG_DATA(c).cast::<TpacketAuxdata>());
                    status = aux.tp_status;
                }
                c = libc::CMSG_NXTHDR(&msg, c);
            }
        }
        if status & TP_STATUS_VLAN_VALID != 0 {
            // Another VLAN's frame (tag stripped by the NIC): not our LAN.
            return Ok(None);
        }
        Ok(Some(Received {
            len: n,
            csum_not_ready: status & TP_STATUS_CSUMNOTREADY != 0,
        }))
    }

    /// Sends one frame. `WouldBlock` when the queue is full.
    pub fn send(&self, frame: &[u8]) -> io::Result<()> {
        // SAFETY: a live buffer of the given length.
        let n = unsafe {
            libc::send(
                self.fd.as_raw_fd(),
                frame.as_ptr().cast(),
                frame.len(),
                libc::MSG_DONTWAIT,
            )
        };
        if n < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(())
        }
    }
}

/// The TUN stand-in: a datagram socket pair, one IP packet per datagram.
/// The first end is the box's (non-blocking), the second the core's.
pub fn tun_pair() -> anyhow::Result<(OwnedFd, OwnedFd)> {
    let mut fds = [0 as RawFd; 2];
    // SAFETY: socketpair(2) fills `fds`.
    cvt(unsafe {
        libc::socketpair(
            libc::AF_UNIX,
            libc::SOCK_DGRAM | libc::SOCK_CLOEXEC,
            0,
            fds.as_mut_ptr(),
        )
    })
    .context("socketpair")?;
    // SAFETY: two fresh descriptors we own.
    let (a, b) = unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) };
    for fd in [&a, &b] {
        let _ = setsockopt(
            fd.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_SNDBUF,
            &(2i32 << 20),
        );
        let _ = setsockopt(
            fd.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_RCVBUF,
            &(2i32 << 20),
        );
    }
    set_nonblocking(a.as_raw_fd())?;
    Ok((a, b))
}

/// Puts `fd` in non-blocking mode.
pub fn set_nonblocking(fd: RawFd) -> io::Result<()> {
    // SAFETY: fcntl on a descriptor we hold.
    let flags = cvt(unsafe { libc::fcntl(fd, libc::F_GETFL) })?;
    // SAFETY: as above.
    cvt(unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) }).map(drop)
}

/// A datagram from the box's end of the pair (`WouldBlock` when none).
pub fn dgram_recv(fd: RawFd, buf: &mut [u8]) -> io::Result<usize> {
    // SAFETY: a live buffer of the given length.
    let n = unsafe { libc::recv(fd, buf.as_mut_ptr().cast(), buf.len(), 0) };
    usize::try_from(n).map_err(|_| io::Error::last_os_error())
}

/// A datagram to the core's end of the pair.
pub fn dgram_send(fd: RawFd, packet: &[u8]) -> io::Result<()> {
    // SAFETY: a live buffer of the given length.
    let n = unsafe { libc::send(fd, packet.as_ptr().cast(), packet.len(), libc::MSG_DONTWAIT) };
    if n < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

/// The local time zone's offset from UTC in minutes.
pub fn utc_offset_minutes() -> i64 {
    // SAFETY: time + localtime_r into a zeroed tm.
    unsafe {
        let t = libc::time(std::ptr::null_mut());
        let mut tm: libc::tm = zeroed();
        if libc::localtime_r(&t, &mut tm).is_null() {
            return 0;
        }
        tm.tm_gmtoff / 60
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_pair_carries_datagrams_whole() {
        let (ours, core) = tun_pair().unwrap();
        let mut buf = [0u8; 2048];
        assert_eq!(
            dgram_recv(ours.as_raw_fd(), &mut buf).unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
        dgram_send(ours.as_raw_fd(), &[1, 2, 3]).unwrap();
        dgram_send(ours.as_raw_fd(), &[4; 1500]).unwrap();
        // SAFETY: plain recv on the core's end (blocking; data is queued).
        let n = unsafe { libc::recv(core.as_raw_fd(), buf.as_mut_ptr().cast(), buf.len(), 0) };
        assert_eq!(n, 3);
        let n = unsafe { libc::recv(core.as_raw_fd(), buf.as_mut_ptr().cast(), buf.len(), 0) };
        assert_eq!(n, 1500);
        let n = unsafe { libc::send(core.as_raw_fd(), [9u8; 40].as_ptr().cast(), 40, 0) };
        assert_eq!(n, 40);
        assert_eq!(dgram_recv(ours.as_raw_fd(), &mut buf).unwrap(), 40);
    }

    #[test]
    fn loopback_facts() {
        // `lo` exists everywhere; no MAC of note but a readable entry.
        let lo = iface("lo").unwrap();
        assert!(lo.index > 0);
        assert!(!lo.wireless);
        assert!(host_ips("lo").contains(&Ipv4Addr::LOCALHOST));
        assert!(iface("no-such-if0").is_err());
    }

    #[test]
    fn offset_is_sane() {
        assert!(utc_offset_minutes().abs() <= 14 * 60);
    }
}
