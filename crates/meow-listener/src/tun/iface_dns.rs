//! PaoPao: per-interface DNS (another VPN's DNS servers and search
//! domains), read with the route snapshot.
//!
//! The result is published in `meow_common::route_table` — process-global,
//! so it survives a resolver swap on config reload — and is what lets the
//! DNS path pass another VPN's names through to that VPN's own servers.
//!
//! One reader per platform; what each reads is turned into [`Found`] rows
//! by a pure parser (tested on samples here, on every host), and
//! [`attribute`] ties the rows to interfaces.

// Phones have no reader: the parsers here are only compiled for the tests.
#![cfg_attr(
    not(any(target_os = "linux", target_os = "macos", target_os = "windows", test)),
    allow(dead_code, unused_imports)
)]

use std::net::IpAddr;

use meow_common::route_table::{self, IfaceDns, RouteIfaceKind, RouteTable};

/// One resolver configuration as a platform source reported it.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub(super) struct Found {
    /// `None`: the source does not say — the route to the first server
    /// decides.
    pub iface: Option<String>,
    pub servers: Vec<IpAddr>,
    pub domains: Vec<String>,
}

/// A search / routing domain in match form: lower case, no `~` (routing
/// only), no surrounding dots. The catch-all (`.` / `~.`) is dropped — it
/// says "everything", which is the full-tunnel question, not a name.
pub(super) fn clean_domain(raw: &str) -> Option<String> {
    let d = raw
        .trim()
        .trim_start_matches('~')
        .trim_start_matches("*.")
        .trim_matches('.')
        .to_ascii_lowercase();
    (!d.is_empty() && !d.contains(char::is_whitespace)).then_some(d)
}

fn push_unique<T: PartialEq>(list: &mut Vec<T>, item: T) {
    if !list.contains(&item) {
        list.push(item);
    }
}

/// An address as these sources write it (`fe80::1%en0` loses its zone).
fn parse_ip(raw: &str) -> Option<IpAddr> {
    raw.trim().split('%').next()?.parse().ok()
}

/// `/run/systemd/resolve/netif/<ifindex>` (systemd-resolved's per-link
/// state): `SERVERS=` and `DOMAINS=` are space separated; routing-only
/// domains carry a `~`.
#[cfg_attr(not(any(target_os = "linux", test)), allow(dead_code))]
pub(super) fn parse_resolved_netif(text: &str) -> (Vec<IpAddr>, Vec<String>) {
    let mut servers = Vec::new();
    let mut domains = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if let Some(v) = line.strip_prefix("SERVERS=") {
            for s in v.split_whitespace() {
                // `10.0.0.1:53#name` / `[fd00::1]:53` forms carry more
                // than the address.
                let s = s.split('#').next().unwrap_or(s);
                let s = s
                    .strip_prefix('[')
                    .and_then(|r| r.split(']').next())
                    .unwrap_or(s);
                let ip = parse_ip(s).or_else(|| parse_ip(s.rsplit_once(':')?.0));
                if let Some(ip) = ip {
                    push_unique(&mut servers, ip);
                }
            }
        } else if let Some(v) = line.strip_prefix("DOMAINS=") {
            for d in v.split_whitespace().filter_map(clean_domain) {
                push_unique(&mut domains, d);
            }
        }
    }
    (servers, domains)
}

/// `resolv.conf`: `nameserver` lines and the last `search` / `domain`.
#[cfg_attr(not(any(target_os = "linux", test)), allow(dead_code))]
pub(super) fn parse_resolv_conf(text: &str) -> (Vec<IpAddr>, Vec<String>) {
    let mut servers = Vec::new();
    let mut domains = Vec::new();
    for line in text.lines() {
        let line = line.split(['#', ';']).next().unwrap_or("").trim();
        let mut words = line.split_whitespace();
        match words.next() {
            Some("nameserver") => {
                if let Some(ip) = words.next().and_then(parse_ip) {
                    push_unique(&mut servers, ip);
                }
            }
            Some("search") | Some("domain") => {
                domains = Vec::new();
                for d in words.filter_map(clean_domain) {
                    push_unique(&mut domains, d);
                }
            }
            _ => {}
        }
    }
    (servers, domains)
}

/// Per-link DNS as exposed by resolved's public CLI (its internal netif
/// state files are absent on many distributions). Global servers have no
/// interface and are attributed by the original route snapshot.
#[cfg_attr(not(any(target_os = "linux", test)), allow(dead_code))]
pub(super) fn parse_resolvectl(dns: &str, domains: &str) -> Vec<Found> {
    fn row(line: &str) -> Option<(Option<String>, &str)> {
        let (label, values) = line.split_once(':')?;
        if label.trim() == "Global" {
            return Some((None, values));
        }
        if !label.trim().starts_with("Link ") {
            return None;
        }
        let iface = label.split_once('(')?.1.split_once(')')?.0;
        Some((Some(iface.to_owned()), values))
    }
    dns.lines()
        .filter_map(|line| {
            let (iface, values) = row(line)?;
            let servers: Vec<_> = values
                .split_whitespace()
                .filter_map(|s| {
                    let s = s.split('#').next()?;
                    s.parse::<std::net::SocketAddr>()
                        .ok()
                        .map(|a| a.ip())
                        .or_else(|| parse_ip(s))
                })
                .collect();
            if servers.is_empty() {
                return None;
            }
            let domains = domains
                .lines()
                .filter_map(row)
                .filter(|(name, _)| *name == iface)
                .flat_map(|(_, values)| values.split_whitespace().filter_map(clean_domain))
                .collect();
            Some(Found {
                iface,
                servers,
                domains,
            })
        })
        .collect()
}

#[cfg(test)]
mod resolved_cli_tests {
    use super::*;
    #[test]
    fn physical_and_vpn_dns_keep_their_interface_and_search_domains() {
        let rows = parse_resolvectl(
            "Global:\nLink 2 (enp0s31f6): 192.168.1.1\nLink 4 (tun0): 10.8.0.1 fd00::53\n",
            "Global:\nLink 2 (enp0s31f6): ~.\nLink 4 (tun0): ~corp.example\n",
        );
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].iface.as_deref(), Some("enp0s31f6"));
        assert!(rows[0].domains.is_empty());
        assert_eq!(rows[1].servers.len(), 2);
        assert_eq!(rows[1].domains, ["corp.example"]);
    }
}

/// Preserve the legacy search-line parsing regression without compiling
/// a helper for the removed resolver-write path into production.
#[cfg(test)]
fn resolv_conf_search_lines(text: &str) -> Vec<&str> {
    text.lines()
        .map(str::trim)
        .filter(|l| matches!(l.split_whitespace().next(), Some("search") | Some("domain")))
        .collect()
}

/// `scutil --dns` (macOS): one row per `resolver #N` block. Multicast
/// resolvers (`options : mdns`) are not DNS servers and are skipped.
#[cfg_attr(not(any(target_os = "macos", test)), allow(dead_code))]
pub(super) fn parse_scutil_dns(text: &str) -> Vec<Found> {
    fn flush(cur: &mut Option<(Found, bool)>, out: &mut Vec<Found>) {
        if let Some((found, mdns)) = cur.take() {
            if !mdns && !found.servers.is_empty() {
                out.push(found);
            }
        }
    }
    let mut out = Vec::new();
    let mut cur: Option<(Found, bool)> = None;
    for line in text.lines() {
        let line = line.trim();
        if line.starts_with("resolver #") {
            flush(&mut cur, &mut out);
            cur = Some((Found::default(), false));
            continue;
        }
        let Some((found, mdns)) = cur.as_mut() else {
            continue;
        };
        let Some((key, value)) = line.split_once(':') else {
            continue;
        };
        let (key, value) = (key.trim(), value.trim());
        if key == "domain" || key.starts_with("search domain[") {
            if let Some(d) = clean_domain(value) {
                push_unique(&mut found.domains, d);
            }
        } else if key.starts_with("nameserver[") {
            if let Some(ip) = parse_ip(value) {
                push_unique(&mut found.servers, ip);
            }
        } else if key == "if_index" {
            // `12 (utun3)`
            found.iface = value
                .split_once('(')
                .and_then(|(_, r)| r.split(')').next())
                .map(|n| n.trim().to_string())
                .filter(|n| !n.is_empty());
        } else if key == "options" && value.split_whitespace().any(|o| o == "mdns") {
            *mdns = true;
        }
    }
    flush(&mut cur, &mut out);
    out
}

/// The Windows reader's line format (see `WINDOWS_SCRIPT`):
/// `if|<alias>|<connection suffix>|<server>,<server>` per adapter and
/// `nrpt|<namespace>,<namespace>|<server>,<server>` per effective Name
/// Resolution Policy rule (how AnyConnect-style clients push split DNS).
#[cfg_attr(not(any(windows, test)), allow(dead_code))]
pub(super) fn parse_windows_dns(text: &str) -> Vec<Found> {
    let list = |s: &str| -> Vec<String> {
        s.split([',', ' ', ';'])
            .map(str::trim)
            .filter(|p| !p.is_empty())
            .map(str::to_string)
            .collect()
    };
    let mut out = Vec::new();
    for line in text.lines() {
        let parts: Vec<&str> = line.trim().split('|').collect();
        let (iface, domains, servers) = match parts.as_slice() {
            ["if", alias, suffix, servers] if !alias.trim().is_empty() => {
                (Some(alias.trim().to_string()), list(suffix), list(servers))
            }
            ["nrpt", namespaces, servers] => (None, list(namespaces), list(servers)),
            _ => continue,
        };
        let servers: Vec<IpAddr> = servers.iter().filter_map(|s| parse_ip(s)).collect();
        if servers.is_empty() {
            continue;
        }
        out.push(Found {
            iface,
            servers,
            domains: domains.iter().filter_map(|d| clean_domain(d)).collect(),
        });
    }
    out
}

/// Tie the rows to interfaces: a row without one belongs to the interface
/// the route snapshot sends its first server through (dropped when that is
/// only the default route — nothing says whose it is). Rows of one
/// interface merge; our own TUN's are dropped.
pub(super) fn attribute(
    found: Vec<Found>,
    table: &RouteTable,
    kind: impl Fn(&str) -> RouteIfaceKind,
) -> Vec<IfaceDns> {
    let mut out: Vec<IfaceDns> = Vec::new();
    for row in found {
        let iface = match row.iface {
            Some(name) => name,
            None => {
                let Some(hit) = row.servers.first().and_then(|ip| table.lookup(*ip)) else {
                    continue;
                };
                hit.iface.to_string()
            }
        };
        let k = kind(&iface);
        if k == RouteIfaceKind::OwnTun {
            continue;
        }
        let at = match out.iter().position(|d| d.iface == iface) {
            Some(i) => i,
            None => {
                out.push(IfaceDns {
                    iface,
                    kind: k,
                    servers: Vec::new(),
                    domains: Vec::new(),
                });
                out.len() - 1
            }
        };
        for s in row.servers {
            push_unique(&mut out[at].servers, s);
        }
        for d in row.domains {
            push_unique(&mut out[at].domains, d);
        }
    }
    out.sort_by(|a, b| a.iface.cmp(&b.iface));
    out
}

/// Read every interface's DNS configuration and publish it. `changed`:
/// the route snapshot differs from the previous one (the readers that
/// spawn a process only run then, or after [`SLOW_READER_EVERY`]).
#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
pub(super) fn refresh(table: &RouteTable, changed: bool) {
    if !platform::due(changed) {
        return;
    }
    let found = platform::read(table);
    let list = attribute(found, table, super::route::route_kind);
    if route_table::publish_iface_dns(list) {
        for d in route_table::iface_dns().iter() {
            if d.kind == RouteIfaceKind::OtherVpn {
                tracing::info!(
                    "per-interface dns: '{}' has servers {:?}, domains {:?}",
                    d.iface,
                    d.servers,
                    d.domains
                );
            }
        }
    }
}

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
pub(super) fn refresh(_table: &RouteTable, _changed: bool) {}

/// How often a reader that has to spawn a process runs when nothing in the
/// routing table changed.
#[cfg(any(target_os = "macos", target_os = "windows"))]
const SLOW_READER_EVERY: std::time::Duration = std::time::Duration::from_secs(20);

/// How long a reader's helper program (`scutil`, PowerShell) gets. The
/// readers run on the thread that keeps the outbound binding on the right
/// interface: a helper that hangs must not stop that.
#[cfg_attr(not(any(target_os = "macos", target_os = "windows")), allow(dead_code))]
const READER_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(8);

/// Run `cmd` and return its exit status and standard output, killing it
/// when it has not finished after `limit`.
#[cfg_attr(
    not(any(target_os = "macos", target_os = "windows", test)),
    allow(dead_code)
)]
fn run_with_timeout(
    mut cmd: std::process::Command,
    limit: std::time::Duration,
) -> std::io::Result<(std::process::ExitStatus, Vec<u8>)> {
    use std::process::Stdio;
    use std::time::Instant;

    let deadline = Instant::now() + limit;
    let mut child = cmd
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()?;
    let give_up = |child: &mut std::process::Child, why: &str| {
        let _ = child.kill();
        let _ = child.wait();
        std::io::Error::new(std::io::ErrorKind::TimedOut, why.to_string())
    };
    let Some(mut stdout) = child.stdout.take() else {
        return Err(give_up(&mut child, "no output pipe"));
    };
    // Read on the side: a pipe that fills up would stall the helper.
    let (tx, rx) = std::sync::mpsc::channel();
    let reader = std::thread::Builder::new()
        .name("iface-dns-read".into())
        .spawn(move || {
            let mut out = Vec::new();
            let _ = std::io::Read::read_to_end(&mut stdout, &mut out);
            let _ = tx.send(out);
        });
    if reader.is_err() {
        return Err(give_up(&mut child, "no reader thread"));
    }
    let Ok(out) = rx.recv_timeout(limit) else {
        return Err(give_up(&mut child, "no answer in time"));
    };
    // Output is complete; the exit follows at once.
    loop {
        if let Some(status) = child.try_wait()? {
            return Ok((status, out));
        }
        if Instant::now() >= deadline {
            return Err(give_up(&mut child, "did not exit in time"));
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
}

#[cfg(any(target_os = "macos", target_os = "windows"))]
fn slow_reader_due(changed: bool) -> bool {
    use std::time::Instant;
    static LAST: parking_lot::Mutex<Option<Instant>> = parking_lot::Mutex::new(None);
    let mut last = LAST.lock();
    if changed || last.is_none_or(|t| t.elapsed() >= SLOW_READER_EVERY) {
        *last = Some(Instant::now());
        true
    } else {
        false
    }
}

#[cfg(target_os = "linux")]
mod platform {
    use super::*;

    /// Reading a few small files: every pass.
    pub(super) fn due(_changed: bool) -> bool {
        true
    }

    /// systemd-resolved's per-link state where it exists; otherwise the
    /// `resolv.conf` the system had before we rewrote it (its nameservers
    /// are tied to interfaces by route, its `search` list goes to them).
    pub(super) fn read(table: &RouteTable) -> Vec<Found> {
        let mut found = Vec::new();
        let mut seen: Vec<u32> = Vec::new();
        for entry in table.entries() {
            if entry.kind == RouteIfaceKind::OwnTun || seen.contains(&entry.index) {
                continue;
            }
            seen.push(entry.index);
            let path = format!("/run/systemd/resolve/netif/{}", entry.index);
            let Ok(text) = std::fs::read_to_string(path) else {
                continue;
            };
            let (servers, domains) = parse_resolved_netif(&text);
            if !servers.is_empty() {
                found.push(Found {
                    iface: Some(entry.iface.to_string()),
                    servers,
                    domains,
                });
            }
        }
        if !found.is_empty() {
            return found;
        }
        // Only read-only queries. The core never changes resolved's DNS
        // configuration; cache subprocess results to keep the monitor cheap.
        static CACHE: parking_lot::Mutex<Option<(std::time::Instant, Vec<Found>)>> =
            parking_lot::Mutex::new(None);
        let mut cache = CACHE.lock();
        if cache
            .as_ref()
            .is_none_or(|(at, _)| at.elapsed().as_secs() >= 5)
        {
            let query = |what| {
                let mut cmd = std::process::Command::new("resolvectl");
                cmd.arg(what);
                run_with_timeout(cmd, std::time::Duration::from_secs(2))
                    .ok()
                    .filter(|(s, _)| s.success())
                    .map(|(_, out)| String::from_utf8_lossy(&out).into_owned())
            };
            if let Some(dns) = query("dns") {
                let domains = query("domain").unwrap_or_default();
                *cache = Some((std::time::Instant::now(), parse_resolvectl(&dns, &domains)));
            }
        }
        if let Some((_, rows)) = cache.as_ref() {
            found.extend(rows.iter().cloned());
        }
        drop(cache);
        let Some(text) = super::super::dns::original_resolv_conf() else {
            return found;
        };
        let (servers, domains) = parse_resolv_conf(&text);
        // One row per server: each is tied to its own interface.
        for server in servers {
            found.push(Found {
                iface: None,
                servers: vec![server],
                domains: domains.clone(),
            });
        }
        found
    }
}

#[cfg(target_os = "macos")]
mod platform {
    use super::*;

    pub(super) fn due(changed: bool) -> bool {
        slow_reader_due(changed)
    }

    pub(super) fn read(_table: &RouteTable) -> Vec<Found> {
        let mut cmd = std::process::Command::new("/usr/sbin/scutil");
        cmd.arg("--dns");
        match run_with_timeout(cmd, READER_TIMEOUT) {
            Ok((status, out)) if status.success() => {
                parse_scutil_dns(&String::from_utf8_lossy(&out))
            }
            Ok((status, _)) => {
                tracing::debug!("per-interface dns: scutil --dns exited {status}");
                Vec::new()
            }
            Err(e) => {
                tracing::debug!("per-interface dns: scutil --dns: {e}");
                Vec::new()
            }
        }
    }
}

#[cfg(target_os = "windows")]
mod platform {
    use super::*;

    /// Per adapter: alias, connection-specific suffix, servers. Then the
    /// effective NRPT rules. Output format: see [`parse_windows_dns`].
    const WINDOWS_SCRIPT: &str = r#"Get-DnsClient -ErrorAction SilentlyContinue | ForEach-Object { $s = (Get-DnsClientServerAddress -InterfaceIndex $_.InterfaceIndex -ErrorAction SilentlyContinue | ForEach-Object { $_.ServerAddresses }) -join ','; 'if|' + $_.InterfaceAlias + '|' + $_.ConnectionSpecificSuffix + '|' + $s }; Get-DnsClientNrptPolicy -Effective -ErrorAction SilentlyContinue | ForEach-Object { 'nrpt|' + ($_.Namespace -join ',') + '|' + ($_.NameServers -join ',') }"#;

    pub(super) fn due(changed: bool) -> bool {
        slow_reader_due(changed)
    }

    pub(super) fn read(_table: &RouteTable) -> Vec<Found> {
        let mut cmd = std::process::Command::new("powershell");
        cmd.args(["-NoProfile", "-Command", WINDOWS_SCRIPT]);
        match run_with_timeout(cmd, READER_TIMEOUT) {
            Ok((_, out)) => parse_windows_dns(&String::from_utf8_lossy(&out))
                .into_iter()
                // Our own loopback takeover is not somebody's DNS.
                .filter(|f| !f.servers.iter().all(|s| s.is_loopback()))
                .collect(),
            Err(e) => {
                tracing::debug!("per-interface dns: powershell: {e}");
                Vec::new()
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use meow_common::route_table::RawRoute;

    fn ips(list: &[&str]) -> Vec<IpAddr> {
        list.iter().map(|s| s.parse().unwrap()).collect()
    }

    fn kind(name: &str) -> RouteIfaceKind {
        if name == "Meow" || name == "utun9" {
            RouteIfaceKind::OwnTun
        } else if ["tun", "utun", "wg", "Cisco"]
            .iter()
            .any(|p| name.starts_with(p))
        {
            RouteIfaceKind::OtherVpn
        } else {
            RouteIfaceKind::Physical
        }
    }

    fn table(routes: &[(&str, &str)]) -> RouteTable {
        let raw: Vec<RawRoute> = routes
            .iter()
            .map(|(net, iface)| RawRoute {
                net: net.parse().unwrap(),
                iface: iface.to_string(),
                index: iface.len() as u32,
                gateway: None,
                metric: 0,
                table: None,
                scoped: false,
            })
            .collect();
        RouteTable::build(raw, |n| kind(n) == RouteIfaceKind::OwnTun, kind)
    }

    #[test]
    fn systemd_resolved_link_file() {
        let text = "# This is private data. Do not parse.\n\
                    LLMNR=yes\nMDNS=no\n\
                    SERVERS=10.8.0.1 10.8.0.2:53#dns.corp.example [fd00::53]:53\n\
                    DOMAINS=corp.example.com ~internal.example ~.\n\
                    DEFAULT_ROUTE=no\n";
        let (servers, domains) = parse_resolved_netif(text);
        assert_eq!(servers, ips(&["10.8.0.1", "10.8.0.2", "fd00::53"]));
        assert_eq!(domains, ["corp.example.com", "internal.example"]);
        assert_eq!(parse_resolved_netif("LLMNR=yes\n"), (vec![], vec![]));
    }

    #[test]
    fn resolv_conf_as_a_vpn_script_writes_it() {
        let text = "# Generated by vpnc-script\n\
                    search corp.example.com Lab.Example.\n\
                    nameserver 10.8.0.1 # vpn\n\
                    nameserver 192.168.1.1\n\
                    options ndots:1\n";
        let (servers, domains) = parse_resolv_conf(text);
        assert_eq!(servers, ips(&["10.8.0.1", "192.168.1.1"]));
        assert_eq!(domains, ["corp.example.com", "lab.example"]);
        assert_eq!(
            resolv_conf_search_lines(text),
            ["search corp.example.com Lab.Example."]
        );
        assert!(resolv_conf_search_lines("nameserver 1.1.1.1\n").is_empty());
    }

    #[test]
    fn resolv_conf_servers_are_tied_to_interfaces_by_route() {
        let table = table(&[("10.8.0.0/16", "tun0"), ("192.168.1.0/24", "enp3s0")]);
        let found = vec![
            Found {
                iface: None,
                servers: ips(&["10.8.0.1"]),
                domains: vec!["corp.example.com".into()],
            },
            Found {
                iface: None,
                servers: ips(&["192.168.1.1"]),
                domains: vec!["corp.example.com".into()],
            },
            // Only reachable by the default route: nobody's in particular.
            Found {
                iface: None,
                servers: ips(&["8.8.8.8"]),
                domains: vec!["corp.example.com".into()],
            },
        ];
        let list = attribute(found, &table, kind);
        assert_eq!(list.len(), 2);
        assert_eq!(list[1].iface, "tun0");
        assert_eq!(list[1].kind, RouteIfaceKind::OtherVpn);
        assert_eq!(list[1].servers, ips(&["10.8.0.1"]));
        assert_eq!(list[0].kind, RouteIfaceKind::Physical);
    }

    const SCUTIL: &str = "DNS configuration\n\
\n\
resolver #1\n\
  search domain[0] : lan\n\
  nameserver[0] : 198.18.0.1\n\
  if_index : 6 (en0)\n\
  flags    : Request A records\n\
  reach    : 0x00000002 (Reachable)\n\
\n\
resolver #2\n\
  domain   : corp.example.com\n\
  nameserver[0] : 10.8.0.1\n\
  nameserver[1] : 10.8.0.2\n\
  if_index : 12 (utun3)\n\
  flags    : Supplemental, Request A records\n\
  reach    : 0x00000003 (Reachable,Transient Connection)\n\
  order    : 101000\n\
\n\
resolver #3\n\
  domain   : local\n\
  options  : mdns\n\
  timeout  : 5\n\
  flags    : Request A records\n\
  reach    : 0x00000000 (Not Reachable)\n\
  order    : 300000\n\
\n\
resolver #4\n\
  domain   : dev.example\n\
  nameserver[0] : fe80::1%utun3\n\
  flags    : Supplemental\n\
\n\
DNS configuration (for scoped queries)\n\
\n\
resolver #1\n\
  search domain[0] : corp.example.com\n\
  search domain[1] : lab.example\n\
  nameserver[0] : 10.8.0.1\n\
  if_index : 12 (utun3)\n\
  flags    : Scoped, Request A records\n\
  reach    : 0x00000003 (Reachable,Transient Connection)\n";

    #[test]
    fn scutil_dns_blocks() {
        let found = parse_scutil_dns(SCUTIL);
        assert_eq!(found.len(), 4, "the mdns resolver is skipped: {found:?}");
        assert_eq!(found[1].iface.as_deref(), Some("utun3"));
        assert_eq!(found[1].servers, ips(&["10.8.0.1", "10.8.0.2"]));
        assert_eq!(found[1].domains, ["corp.example.com"]);
        assert_eq!(found[2].iface, None);
        assert_eq!(found[2].servers, ips(&["fe80::1"]));

        // Rows of one interface merge; the row without an interface and
        // without a route to its server is dropped.
        let list = attribute(found, &table(&[("10.8.0.0/16", "utun3")]), kind);
        let vpn = list.iter().find(|d| d.iface == "utun3").unwrap();
        assert_eq!(vpn.servers, ips(&["10.8.0.1", "10.8.0.2"]));
        assert_eq!(vpn.domains, ["corp.example.com", "lab.example"]);
        assert_eq!(list.len(), 2);
    }

    #[test]
    fn windows_adapter_and_nrpt_lines() {
        let text = "if|Ethernet||192.168.1.1\r\n\
                    if|Cisco AnyConnect|corp.example.com|10.8.0.1,10.8.0.2\r\n\
                    if|Meow||127.0.0.1\r\n\
                    if|Bluetooth||\r\n\
                    nrpt|.lab.example,.dev.example|10.8.0.1\r\n\
                    garbage\r\n";
        let found = parse_windows_dns(text);
        assert_eq!(found.len(), 4);
        assert_eq!(found[3].iface, None);
        assert_eq!(found[3].domains, ["lab.example", "dev.example"]);

        let list = attribute(found, &table(&[("10.8.0.0/16", "Cisco AnyConnect")]), kind);
        // Our own adapter is dropped; the NRPT rule joins the adapter its
        // server is routed through.
        assert_eq!(list.len(), 2);
        assert_eq!(list[0].iface, "Cisco AnyConnect");
        assert_eq!(
            list[0].domains,
            ["corp.example.com", "lab.example", "dev.example"]
        );
        assert_eq!(list[1].iface, "Ethernet");
    }

    /// A helper program's output comes back whole; one that hangs is
    /// killed at the limit instead of holding the monitor thread.
    #[cfg(unix)]
    #[test]
    fn a_helper_that_hangs_is_given_up_on() {
        use std::time::{Duration, Instant};
        let mut echo = std::process::Command::new("sh");
        echo.args(["-c", "printf 'resolver #1\\n'; exit 3"]);
        let (status, out) = run_with_timeout(echo, Duration::from_secs(10)).unwrap();
        assert_eq!(status.code(), Some(3));
        assert_eq!(out, b"resolver #1\n");

        let mut hang = std::process::Command::new("sleep");
        hang.arg("30");
        let started = Instant::now();
        let err = run_with_timeout(hang, Duration::from_millis(200)).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::TimedOut);
        assert!(started.elapsed() < Duration::from_secs(5));

        let missing = std::process::Command::new("/nonexistent/zz-no-such-helper");
        assert!(run_with_timeout(missing, Duration::from_secs(1)).is_err());
    }

    #[test]
    fn domains_are_normalised_and_the_catch_all_dropped() {
        assert_eq!(clean_domain("~Corp.Example."), Some("corp.example".into()));
        assert_eq!(clean_domain(".lab.example"), Some("lab.example".into()));
        assert_eq!(clean_domain("~."), None);
        assert_eq!(clean_domain("."), None);
        assert_eq!(clean_domain(""), None);
    }
}
