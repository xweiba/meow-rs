# meow-box

`meow box`: the core as a small side router (旁路由) on the LAN. Linux only;
on other systems the crate is a stub that says so.

```sh
meow box                                 # DHCP on the default-route NIC
meow box --iface eth0 --ip 192.168.1.50/24 --gateway 192.168.1.1
```

At start it prints:

```
PaoPao 旁路由已就绪 · IP 192.168.1.50 · 管理 http://192.168.1.50 · 账号 admin · 密码 … · 把设备的网关和 DNS 设为 192.168.1.50
```

Needs root (or `CAP_NET_RAW`). It changes no host setting: the
promiscuous membership belongs to the raw socket and ends with it; the
DHCP lease is released on Ctrl-C / SIGTERM.

## Shape

- **Subcommand, not a binary.** `meow-app` gets a `box` feature
  (`embed` + this crate); `src/box_host.rs` there runs the embedded core
  (`embed::run`, the phones' TUN-fd path) and supplies the core's direct HTTP
  client for subscriptions. This crate depends on neither: it sees them
  through the `CoreHost` trait, so its tests build without BoringSSL.
- **Wire.** AF_PACKET socket on `--iface`. Wired: a random locally
  administered MAC saved in `box.json`. Wi-Fi (`/sys/class/net/<if>/wireless`):
  the host's MAC, refused while `net.ipv4.ip_forward=1`.
- **Switch** (`switch.rs`): per frame → own stack (ARP, ping, TCP 80/53),
  DHCP client, DNS front (UDP 53 to the box), or the core's TUN (routed
  traffic); learns IP→MAC; frames the core's replies, ARPs on a miss.
  Checksums left to offload by local guests are filled in; GRO-merged TCP is
  split to the TUN MTU.
- **TUN** = `socketpair(AF_UNIX, SOCK_DGRAM)`; each core start gets a
  duplicate of the core's end (the core closes what it owns).
- **Own stack**: smoltcp 0.12.0 (pinned; 0BSD; 0.13+ need Rust 1.91) for ARP,
  ping and TCP. TCP 80 is bridged to the page server on 127.0.0.1.
- **DHCP**: its own client (`dhcp.rs`), not smoltcp's: it sends a client
  identifier of its own (the box MAC) so a Wi-Fi box sharing the host's MAC
  gets a lease of its own, and it releases the lease on exit.
- **Config**: `meow_paopao::build` on `settings.json` (the app's
  ProxySettings JSON, `{}` = app defaults) and `subscriptions.json`, as a
  VPN-only device (TUN + fake-ip DNS). Then the box's runtime: TUN fd,
  `dns.listen` on 127.0.0.1, controller on 127.0.0.1, no mixed port. Changes
  hot-reload over `PUT /configs` (the TUN section stays the same, so the
  listener is kept).
- **DNS front**: a device that routes through the box (seen in the last
  30 min) gets the core's answers (fake-ip); any other device gets real
  addresses (hosts entries, cache, upstreams `223.5.5.5` / `119.29.29.29`,
  editable under 高级).
- **Page**: one embedded HTML page + JSON API (axum), Basic auth `admin` /
  the random password in `box.json` (0600).

## Data directory

`/var/lib/paopao-box` as root (`--data` to change): `box.json`,
`settings.json`, `subscriptions.json`, `core/` (the core's home).

## Known limits

- The host itself cannot reach the box's IP (its frames leave the NIC; a
  bridge does not send them back). Use another device.
- IPv4 only; IPv6 frames are not handled.
- Promiscuous mode copies all LAN frames to the process (dropped early); a
  BPF filter would cut that.
