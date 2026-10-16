//! PaoPao: the system's own byte counters of network interfaces.
//!
//! Traffic the system routes straight into another VPN's interface never
//! passes through the core, so no connection of ours accounts for it. The
//! interface's totals are all there is to show (`GET /network/vpns`).
//!
//! Each platform has a reader ([`read_iface_bytes`]) and a pure parser of
//! what the system hands out, tested on samples on every host.

use std::collections::HashMap;

/// Bytes an interface has received and sent since it came up, as the
/// system counts them.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct IfaceBytes {
    pub rx: u64,
    pub tx: u64,
}

/// Every interface's counters by name (Windows: by alias, the name the
/// route table uses). Empty when the system does not hand them out; an
/// interface that is missing has none.
#[must_use]
pub fn read_iface_bytes() -> HashMap<String, IfaceBytes> {
    platform::read().into_iter().collect()
}

/// Linux `/proc/net/dev`: two header lines, then one line per interface
/// (`name: rx_bytes rx_packets … (8 fields) tx_bytes …`). Lines that do
/// not read that way are skipped.
#[must_use]
pub fn parse_proc_net_dev(text: &str) -> Vec<(String, IfaceBytes)> {
    /// `tx_bytes` comes after the eight receive fields.
    const TX_BYTES: usize = 8;
    text.lines()
        .filter_map(|line| {
            let (name, rest) = line.rsplit_once(':')?;
            let name = name.trim();
            if name.is_empty() {
                return None;
            }
            let mut fields = rest.split_ascii_whitespace();
            let rx = fields.next()?.parse().ok()?;
            let tx = fields.nth(TX_BYTES - 1)?.parse().ok()?;
            Some((name.to_owned(), IfaceBytes { rx, tx }))
        })
        .collect()
}

/// macOS `sysctl(CTL_NET, PF_ROUTE, 0, 0, NET_RT_IFLIST2, 0)`: a run of
/// routing messages. The `RTM_IFINFO2` ones (`struct if_msghdr2`) carry an
/// interface's 64-bit counters (`struct if_data64`) and, after the header,
/// its `sockaddr_dl` with the name. Anything else, or cut short, is
/// skipped.
#[must_use]
pub fn parse_iflist2(buf: &[u8]) -> Vec<(String, IfaceBytes)> {
    // `struct if_msghdr2` (net/if.h) and `struct if_data64` (net/if_var.h,
    // `#pragma pack(4)`); part of the system's ABI.
    const RTM_IFINFO2: u8 = 0x12;
    const IFM_TYPE: usize = 3;
    const IFM_ADDRS: usize = 4;
    const IFM_DATA: usize = 32;
    const IFI_IBYTES: usize = IFM_DATA + 64;
    const IFI_OBYTES: usize = IFM_DATA + 72;
    const HEADER: usize = IFM_DATA + 128;
    const RTA_IFP: u32 = 0x10;
    const AF_LINK: u8 = 18;
    /// `sockaddr_dl`: `sdl_family` at 1, `sdl_nlen` at 5, the name at 8.
    const SDL_FAMILY: usize = 1;
    const SDL_NLEN: usize = 5;
    const SDL_DATA: usize = 8;

    fn u64_at(msg: &[u8], at: usize) -> Option<u64> {
        Some(u64::from_ne_bytes(msg.get(at..at + 8)?.try_into().ok()?))
    }
    fn info(msg: &[u8]) -> Option<(String, IfaceBytes)> {
        let addrs = u32::from_ne_bytes(msg.get(IFM_ADDRS..IFM_ADDRS + 4)?.try_into().ok()?);
        if addrs & RTA_IFP == 0 {
            return None;
        }
        let bytes = IfaceBytes {
            rx: u64_at(msg, IFI_IBYTES)?,
            tx: u64_at(msg, IFI_OBYTES)?,
        };
        // The addresses follow in the order of their bits, each padded to
        // four bytes (an empty one takes four).
        let mut at = HEADER;
        for bit in 0..RTA_IFP.trailing_zeros() {
            if addrs & (1 << bit) != 0 {
                let len = usize::from(*msg.get(at)?);
                at += if len == 0 { 4 } else { len.div_ceil(4) * 4 };
            }
        }
        let sdl = msg.get(at..)?;
        if *sdl.get(SDL_FAMILY)? != AF_LINK {
            return None;
        }
        let nlen = usize::from(*sdl.get(SDL_NLEN)?);
        let name = std::str::from_utf8(sdl.get(SDL_DATA..SDL_DATA + nlen)?).ok()?;
        (!name.is_empty()).then(|| (name.to_owned(), bytes))
    }

    let mut out = Vec::new();
    let mut rest = buf;
    while rest.len() >= 4 {
        let len = usize::from(u16::from_ne_bytes([rest[0], rest[1]]));
        if len < 4 || len > rest.len() {
            break;
        }
        let (msg, tail) = rest.split_at(len);
        if msg[IFM_TYPE] == RTM_IFINFO2 {
            out.extend(info(msg));
        }
        rest = tail;
    }
    out
}

/// Windows `GetIfTable2`: of every row its alias (UTF-16, up to the first
/// NUL), `InOctets` and `OutOctets`. An alias listed twice keeps its first
/// row; a row without one is skipped.
#[must_use]
pub fn parse_if_rows<'a>(
    rows: impl IntoIterator<Item = (&'a [u16], u64, u64)>,
) -> Vec<(String, IfaceBytes)> {
    let mut out: Vec<(String, IfaceBytes)> = Vec::new();
    for (alias, rx, tx) in rows {
        let end = alias.iter().position(|c| *c == 0).unwrap_or(alias.len());
        let name = String::from_utf16_lossy(&alias[..end]);
        if name.is_empty() || out.iter().any(|(n, _)| *n == name) {
            continue;
        }
        out.push((name, IfaceBytes { rx, tx }));
    }
    out
}

#[cfg(any(target_os = "linux", target_os = "android"))]
mod platform {
    use super::{parse_proc_net_dev, IfaceBytes};

    pub(super) fn read() -> Vec<(String, IfaceBytes)> {
        std::fs::read_to_string("/proc/net/dev")
            .map(|text| parse_proc_net_dev(&text))
            .unwrap_or_default()
    }
}

#[cfg(target_os = "macos")]
mod platform {
    use super::{parse_iflist2, IfaceBytes};

    pub(super) fn read() -> Vec<(String, IfaceBytes)> {
        // CTL_NET, PF_ROUTE, 0, 0 (every address family), NET_RT_IFLIST2, 0.
        let mut mib: [libc::c_int; 6] = [4, 17, 0, 0, 6, 0];
        // Interfaces may appear between asking for the size and reading:
        // ask again a few times with room to spare.
        for _ in 0..3 {
            let mut len: libc::size_t = 0;
            // SAFETY: `mib` holds six ints; a null buffer asks for the size,
            // written to `len`.
            let sized = unsafe {
                libc::sysctl(
                    mib.as_mut_ptr(),
                    6,
                    std::ptr::null_mut(),
                    &raw mut len,
                    std::ptr::null_mut(),
                    0,
                )
            };
            if sized != 0 || len == 0 {
                return Vec::new();
            }
            let mut buf = vec![0u8; len + len / 4 + 1024];
            let mut got: libc::size_t = buf.len();
            // SAFETY: `buf` is writable for `got` bytes; the system writes
            // at most that many and stores the count in `got`.
            let read = unsafe {
                libc::sysctl(
                    mib.as_mut_ptr(),
                    6,
                    buf.as_mut_ptr().cast(),
                    &raw mut got,
                    std::ptr::null_mut(),
                    0,
                )
            };
            if read == 0 {
                buf.truncate(got.min(buf.len()));
                return parse_iflist2(&buf);
            }
        }
        Vec::new()
    }
}

#[cfg(target_os = "windows")]
mod platform {
    use super::{parse_if_rows, IfaceBytes};
    use windows_sys::Win32::NetworkManagement::IpHelper::{
        FreeMibTable, GetIfTable2, MIB_IF_ROW2, MIB_IF_TABLE2,
    };

    pub(super) fn read() -> Vec<(String, IfaceBytes)> {
        let mut table: *mut MIB_IF_TABLE2 = std::ptr::null_mut();
        // SAFETY: `table` is a valid out-pointer; on success the system
        // stores a table there that is freed below.
        if unsafe { GetIfTable2(&raw mut table) } != 0 || table.is_null() {
            return Vec::new();
        }
        // SAFETY: the table holds `NumEntries` rows starting at `Table`,
        // alive until `FreeMibTable`.
        let rows: &[MIB_IF_ROW2] = unsafe {
            std::slice::from_raw_parts(
                (&raw const (*table).Table).cast::<MIB_IF_ROW2>(),
                (*table).NumEntries as usize,
            )
        };
        let out = parse_if_rows(
            rows.iter()
                .map(|row| (&row.Alias[..], row.InOctets, row.OutOctets)),
        );
        // SAFETY: `table` came from `GetIfTable2` and `rows` is not used
        // after this.
        unsafe { FreeMibTable(table.cast()) };
        out
    }
}

#[cfg(not(any(
    target_os = "linux",
    target_os = "android",
    target_os = "macos",
    target_os = "windows"
)))]
mod platform {
    use super::IfaceBytes;

    pub(super) fn read() -> Vec<(String, IfaceBytes)> {
        Vec::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bytes(rx: u64, tx: u64) -> IfaceBytes {
        IfaceBytes { rx, tx }
    }

    #[test]
    fn proc_net_dev_gives_received_and_sent_bytes_per_interface() {
        let text = "\
Inter-|   Receive                                                |  Transmit
 face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed
    lo: 8245264473 6957794    0    0    0     0          0         0 8245264473 6957794    0    0    0     0       0          0
enp0s31f6: 4038717103 5147487    0 6980    0     0          0    155727 3108418756 4054210    0  118    0     0       0          0
 wlan0:       0       0    0    0    0     0          0         0        0       0    0    0    0     0       0          0
  tun0:18446744073709551615 12 0 0 0 0 0 0 2048 9 0 0 0 0 0 0
";
        assert_eq!(
            parse_proc_net_dev(text),
            vec![
                ("lo".to_owned(), bytes(8_245_264_473, 8_245_264_473)),
                ("enp0s31f6".to_owned(), bytes(4_038_717_103, 3_108_418_756)),
                ("wlan0".to_owned(), bytes(0, 0)),
                ("tun0".to_owned(), bytes(u64::MAX, 2048)),
            ]
        );
    }

    #[test]
    fn proc_net_dev_skips_what_is_not_an_interface_line() {
        assert_eq!(parse_proc_net_dev(""), vec![]);
        let text = "\
 face |bytes packets
  tun0: 1 2 3
  tun1: x 0 0 0 0 0 0 0 5 0 0 0 0 0 0 0
  tun2: 7 0 0 0 0 0 0 0 -5 0 0 0 0 0 0 0
      : 7 0 0 0 0 0 0 0 5 0 0 0 0 0 0 0
  tun3: 7 0 0 0 0 0 0 0 5
";
        assert_eq!(
            parse_proc_net_dev(text),
            vec![("tun3".to_owned(), bytes(7, 5))]
        );
    }

    /// One routing message as macOS lays it out: `if_msghdr2` (160 bytes
    /// with its `if_data64`), then the addresses.
    fn ifinfo2(kind: u8, addrs: u32, rx: u64, tx: u64, tail: &[u8]) -> Vec<u8> {
        let mut msg = vec![0u8; 160];
        msg[2] = 5; // RTM_VERSION
        msg[3] = kind;
        msg[4..8].copy_from_slice(&addrs.to_ne_bytes());
        msg[12..14].copy_from_slice(&7u16.to_ne_bytes());
        // if_data64: ipackets … collisions before the byte counters.
        msg[32 + 24..32 + 32].copy_from_slice(&111u64.to_ne_bytes());
        msg[32 + 64..32 + 72].copy_from_slice(&rx.to_ne_bytes());
        msg[32 + 72..32 + 80].copy_from_slice(&tx.to_ne_bytes());
        msg.extend_from_slice(tail);
        let len = u16::try_from(msg.len()).unwrap();
        msg[0..2].copy_from_slice(&len.to_ne_bytes());
        msg
    }

    /// A `sockaddr_dl` naming an interface, padded to four bytes.
    fn sockaddr_dl(name: &str) -> Vec<u8> {
        let mut sa = vec![0u8; 8];
        sa[1] = 18; // AF_LINK
        sa[2..4].copy_from_slice(&7u16.to_ne_bytes());
        sa[5] = u8::try_from(name.len()).unwrap();
        sa[6] = 6; // a link-layer address after the name
        sa.extend_from_slice(name.as_bytes());
        sa.extend_from_slice(&[0xaa; 6]);
        sa[0] = u8::try_from(sa.len()).unwrap();
        sa.resize(sa.len().div_ceil(4) * 4, 0);
        sa
    }

    #[test]
    fn iflist2_gives_the_64_bit_counters_of_each_interface() {
        let mut buf = ifinfo2(0x12, 0x10, 5_000_000_000, 123, &sockaddr_dl("utun6"));
        // An address message of that interface (RTM_NEWADDR), not counters.
        let mut addr = vec![0u8; 20];
        addr[0..2].copy_from_slice(&20u16.to_ne_bytes());
        addr[3] = 0x0c;
        buf.extend_from_slice(&addr);
        buf.extend(ifinfo2(0x12, 0x10, 42, 7, &sockaddr_dl("en0")));
        assert_eq!(
            parse_iflist2(&buf),
            vec![
                ("utun6".to_owned(), bytes(5_000_000_000, 123)),
                ("en0".to_owned(), bytes(42, 7)),
            ]
        );
    }

    #[test]
    fn iflist2_walks_past_addresses_before_the_name() {
        // RTA_DST (an empty one: four bytes) and RTA_NETMASK (six bytes,
        // padded to eight) come before RTA_IFP.
        let mut tail = vec![0u8; 4];
        tail.extend_from_slice(&[6, 2, 0, 0, 0, 0, 0, 0]);
        tail.extend(sockaddr_dl("ipsec0"));
        let buf = ifinfo2(0x12, 0x10 | 0x4 | 0x1, 9, 8, &tail);
        assert_eq!(
            parse_iflist2(&buf),
            vec![("ipsec0".to_owned(), bytes(9, 8))]
        );
    }

    #[test]
    fn iflist2_skips_what_is_cut_short_or_has_no_name() {
        assert_eq!(parse_iflist2(&[]), vec![]);
        assert_eq!(parse_iflist2(&[1, 2, 3]), vec![]);
        // No RTA_IFP: nothing names the interface.
        assert_eq!(
            parse_iflist2(&ifinfo2(0x12, 0, 1, 2, &sockaddr_dl("en0"))),
            vec![]
        );
        // Not a link address where the name should be.
        let mut other = sockaddr_dl("en0");
        other[1] = 2;
        assert_eq!(parse_iflist2(&ifinfo2(0x12, 0x10, 1, 2, &other)), vec![]);
        // The header without its address.
        assert_eq!(parse_iflist2(&ifinfo2(0x12, 0x10, 1, 2, &[])), vec![]);
        // A name longer than the message.
        let mut long = sockaddr_dl("en0");
        long[5] = 200;
        assert_eq!(parse_iflist2(&ifinfo2(0x12, 0x10, 1, 2, &long)), vec![]);
        // A length running past the buffer ends the walk; what came before
        // stays.
        let mut buf = ifinfo2(0x12, 0x10, 1, 2, &sockaddr_dl("en0"));
        let mut cut = ifinfo2(0x12, 0x10, 3, 4, &sockaddr_dl("en1"));
        cut.truncate(100);
        buf.extend(cut);
        assert_eq!(parse_iflist2(&buf), vec![("en0".to_owned(), bytes(1, 2))]);
        // A zero length would never advance.
        assert_eq!(parse_iflist2(&[0, 0, 5, 0x12, 0, 0, 0, 0]), vec![]);
    }

    #[test]
    fn if_rows_are_read_by_alias() {
        /// `MIB_IF_ROW2.Alias`: 257 UTF-16 units, NUL-terminated.
        fn alias(name: &str) -> Vec<u16> {
            let mut a: Vec<u16> = name.encode_utf16().collect();
            a.resize(257, 0);
            a
        }
        let (vpn, lan, again, none) = (
            alias("OpenVPN TAP"),
            alias("以太网 2"),
            alias("以太网 2"),
            alias(""),
        );
        let full: Vec<u16> = "Wi-Fi".encode_utf16().collect();
        let rows: Vec<(&[u16], u64, u64)> = vec![
            (&vpn, 6_000_000_000, 10),
            (&lan, 1, 2),
            (&again, 0, 0),
            (&none, 5, 5),
            (&full, 3, 4),
        ];
        assert_eq!(
            parse_if_rows(rows),
            vec![
                ("OpenVPN TAP".to_owned(), bytes(6_000_000_000, 10)),
                ("以太网 2".to_owned(), bytes(1, 2)),
                ("Wi-Fi".to_owned(), bytes(3, 4)),
            ]
        );
    }

    /// The host's reader agrees with the system: loopback is there.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn reads_this_hosts_counters() {
        let loopback = if cfg!(target_os = "macos") {
            "lo0"
        } else {
            "lo"
        };
        let all = read_iface_bytes();
        assert!(all.contains_key(loopback), "{all:?}");
    }
}
