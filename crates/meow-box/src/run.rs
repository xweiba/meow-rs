//! Wiring: the raw socket's receive loop through the switch to the stack,
//! the DHCP client, the DNS front and the core's TUN; the core's replies
//! back to the wire; the config page; subscription refreshes; the start
//! banner; a clean exit (lease released, socket closed, core stopped).

use std::net::{Ipv4Addr, SocketAddr};
use std::os::fd::{AsRawFd as _, OwnedFd};
use std::path::PathBuf;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use anyhow::{bail, Context as _};
use rand::Rng as _;
use tokio::io::unix::AsyncFd;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _, Interest};
use tokio::net::TcpStream;
use tokio::sync::{mpsc, watch, Semaphore};
use tokio::task::JoinSet;
use tracing::{debug, warn};

use crate::app::{w, AddrSource, App, Net};
use crate::config::TUN_MTU;
use crate::dhcp::{Client, Event};
use crate::dns::{truncate, MAX_UDP_ANSWER};
use crate::frame::{
    build_arp_request, build_eth, build_ipv4_udp, fill_checksums, parse_eth, parse_ipv4,
    segment_tcp, Mac, ETHERTYPE_IPV4, ETH_HDR,
};
use crate::stack::{Accept, ConnIo, Stack};
use crate::store::{Store, ADMIN_USER};
use crate::switch::{Addr, Switch, Verdict};
use crate::sys::{self, RawSocket};
use crate::{CoreHost, Options};

/// Subscriptions are downloaded again this often (seconds).
pub const REFRESH_SECS: u64 = 12 * 3600;
/// DNS queries over UDP answered at once (more are dropped).
const DNS_INFLIGHT: usize = 256;

/// Milliseconds since the process started (monotonic).
pub fn now_ms() -> u64 {
    static START: OnceLock<Instant> = OnceLock::new();
    u64::try_from(START.get_or_init(Instant::now).elapsed().as_millis()).unwrap_or(u64::MAX)
}

/// `192.168.1.50/24` (or a bare address: /24).
pub fn parse_static(s: &str) -> anyhow::Result<Addr> {
    let (ip, prefix) = s.split_once('/').unwrap_or((s, "24"));
    let ip: Ipv4Addr = ip
        .trim()
        .parse()
        .with_context(|| format!("--ip 要写 dhcp 或 IP/前缀，例如 192.168.1.50/24，而不是 {s}"))?;
    let prefix: u8 = prefix
        .trim()
        .parse()
        .ok()
        .filter(|p| (1..=30).contains(p))
        .with_context(|| format!("--ip 的前缀不对：{s}"))?;
    if ip.is_unspecified() || ip.is_broadcast() || ip.is_multicast() || ip.is_loopback() {
        bail!("--ip 不能用 {ip}");
    }
    Ok(Addr { ip, prefix })
}

/// The start banner.
pub fn banner(ip: Ipv4Addr, password: &str) -> String {
    format!(
        "PaoPao 旁路由已就绪 · IP {ip} · 管理 http://{ip} · 账号 {ADMIN_USER} · 密码 {password} · 把设备的网关和 DNS 设为 {ip}"
    )
}

fn default_data_dir() -> PathBuf {
    // SAFETY: geteuid has no preconditions.
    if unsafe { libc::geteuid() } == 0 {
        return PathBuf::from("/var/lib/paopao-box");
    }
    std::env::var_os("HOME").map_or_else(
        || PathBuf::from("paopao-box"),
        |h| PathBuf::from(h).join(".local/share/paopao-box"),
    )
}

type Raw = Arc<AsyncFd<RawSocket>>;

/// Sends one frame (waits while the socket's queue is full).
async fn send_frame(raw: &AsyncFd<RawSocket>, f: &[u8]) {
    if let Err(e) = raw.async_io(Interest::WRITABLE, |s| s.send(f)).await {
        debug!("frame not sent: {e}");
    }
}

/// What the loops share.
struct Ctx {
    app: Arc<App>,
    raw: Raw,
    switch: Arc<Mutex<Switch>>,
    addr_tx: mpsc::UnboundedSender<(Option<Addr>, Option<Ipv4Addr>)>,
}

impl Ctx {
    fn lock(&self) -> std::sync::MutexGuard<'_, Switch> {
        self.switch
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// The box's address changed (or went away).
    async fn set_net(&self, net: Option<Net>) {
        let mac = {
            let mut sw = self.lock();
            sw.addr = net.map(|n| n.addr);
            sw.mac
        };
        *w!(self.app.net) = net;
        let _ = self
            .addr_tx
            .send((net.map(|n| n.addr), net.and_then(|n| n.gateway)));
        let Some(n) = net else {
            eprintln!("PaoPao 旁路由的地址租约失效了，正在重新获取…");
            return;
        };
        // Tell the LAN at once (stale ARP entries from a previous run).
        send_frame(&self.raw, &build_arp_request(mac, n.addr.ip, n.addr.ip)).await;
        println!("{}", banner(n.addr.ip, &self.app.password()));
        let app = Arc::clone(&self.app);
        tokio::spawn(async move {
            if let Err(e) = app.apply().await {
                warn!("config rebuild failed: {e:#}");
            }
        });
    }
}

/// Runs the box until Ctrl-C / SIGTERM.
pub fn run(opts: &Options, host: Arc<dyn CoreHost>) -> anyhow::Result<()> {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .thread_name("meow-box")
        .build()?;
    rt.block_on(run_async(opts, host))
}

async fn run_async(opts: &Options, host: Arc<dyn CoreHost>) -> anyhow::Result<()> {
    now_ms();
    let name = opts
        .iface
        .clone()
        .or_else(sys::default_iface)
        .context("找不到默认网卡，请用 --iface 指定（例如 --iface eth0）")?;
    let iface = sys::iface(&name)?;
    let fixed = match opts.ip.trim() {
        "" | "dhcp" => None,
        s => Some(parse_static(s)?),
    };
    if fixed.is_none() && opts.gateway.is_some() {
        bail!("--gateway 只在指定 --ip 地址时使用");
    }
    let store = Store::open(&opts.data.clone().unwrap_or_else(default_data_dir))?;
    let own_mac = store.box_file()?.mac;
    let mac = if iface.wireless {
        if sys::ip_forward() {
            bail!(
                "这台机器开着 IP 转发（net.ipv4.ip_forward=1），Wi-Fi 下旁路由要借用本机网卡地址，请先关闭转发（sysctl -w net.ipv4.ip_forward=0）再启动"
            );
        }
        iface.mac
    } else {
        own_mac
    };
    // Wired: receive the box's own MAC too (the membership ends with the
    // socket). Wi-Fi: frames come to the host's MAC anyway.
    let raw: Raw = Arc::new(AsyncFd::new(RawSocket::open(
        iface.index,
        !iface.wireless,
    )?)?);
    let (ours, core_end) = sys::tun_pair()?;
    let ours = Arc::new(AsyncFd::new(ours)?);
    let mut sw = Switch::new(mac);
    sw.host_ips = sys::host_ips(&name);
    let switch = Arc::new(Mutex::new(sw));
    let app = Arc::new(App::new(
        store,
        iface.clone(),
        host,
        Arc::clone(&switch),
        core_end,
    )?);

    println!(
        "PaoPao 旁路由启动中：网卡 {name}（{}），{}…",
        if iface.wireless {
            "Wi-Fi，借用本机网卡地址".to_owned()
        } else {
            format!("独立网卡地址 {mac}")
        },
        fixed.map_or_else(
            || "正在通过 DHCP 获取地址".to_owned(),
            |a| format!("使用地址 {}/{}", a.ip, a.prefix)
        )
    );
    app.apply().await.context("内核没有启动")?;

    let mut tasks = JoinSet::new();
    let admin = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let admin_addr = admin.local_addr()?;
    let router = crate::admin::router(Arc::clone(&app));
    tasks.spawn(async move {
        if let Err(e) = axum::serve(admin, router).await {
            warn!("config page server stopped: {e}");
        }
    });

    let (addr_tx, addr_rx) = mpsc::unbounded_channel();
    let ctx = Arc::new(Ctx {
        app: Arc::clone(&app),
        raw: Arc::clone(&raw),
        switch: Arc::clone(&switch),
        addr_tx,
    });

    let accept: Accept = {
        let ctx = Arc::clone(&ctx);
        Arc::new(move |io: ConnIo| {
            let ctx = Arc::clone(&ctx);
            match io.port {
                80 => drop(tokio::spawn(bridge(io, admin_addr))),
                53 => drop(tokio::spawn(dns_tcp(ctx, io))),
                _ => {}
            }
        })
    };
    let seed = rand::rng().random();
    let stack = Stack::new(mac, &[80, 53], accept, seed, now_ms());
    let (local_tx, local_rx) = mpsc::channel(1024);
    tasks.spawn(stack_loop(stack, local_rx, addr_rx, Arc::clone(&raw)));

    let (dhcp_tx, dhcp_rx) = mpsc::channel(64);
    tasks.spawn(rx_loop(
        Arc::clone(&ctx),
        local_tx,
        dhcp_tx,
        Arc::clone(&ours),
    ));
    tasks.spawn(tun_loop(Arc::clone(&ctx), ours));
    {
        let ctx = Arc::clone(&ctx);
        tasks.spawn(async move {
            let mut t = tokio::time::interval(Duration::from_secs(1));
            loop {
                t.tick().await;
                let out = {
                    let mut sw = ctx.lock();
                    sw.tick(now_ms());
                    sw.drain()
                };
                for f in out {
                    send_frame(&ctx.raw, &f).await;
                }
            }
        });
    }

    let (stop_tx, stop_rx) = watch::channel(false);
    let dhcp = match fixed {
        Some(addr) => {
            ctx.set_net(Some(Net {
                addr,
                gateway: opts.gateway,
                source: AddrSource::Static,
            }))
            .await;
            None
        }
        None => Some(tokio::spawn(dhcp_loop(
            Arc::clone(&ctx),
            dhcp_rx,
            own_mac,
            stop_rx,
        ))),
    };

    {
        let app = Arc::clone(&app);
        tasks.spawn(async move {
            loop {
                if let Err(e) = app.refresh_subscriptions().await {
                    warn!("subscription refresh: {e:#}");
                }
                tokio::time::sleep(Duration::from_secs(REFRESH_SECS)).await;
            }
        });
    }

    wait_for_signal().await;
    println!("PaoPao 旁路由正在退出…");
    let _ = stop_tx.send(true);
    if let Some(d) = dhcp {
        let _ = tokio::time::timeout(Duration::from_secs(2), d).await;
    }
    app.stop_core().await;
    tasks.shutdown().await;
    drop(ctx);
    Ok(())
}

async fn wait_for_signal() {
    let term = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut s) => {
                s.recv().await;
            }
            Err(_) => std::future::pending::<()>().await,
        }
    };
    tokio::select! {
        _ = tokio::signal::ctrl_c() => {}
        () = term => {}
    }
}

async fn stack_loop(
    mut stack: Stack,
    mut local_rx: mpsc::Receiver<Vec<u8>>,
    mut addr_rx: mpsc::UnboundedReceiver<(Option<Addr>, Option<Ipv4Addr>)>,
    raw: Raw,
) {
    let wake = stack.waker();
    loop {
        let now = now_ms();
        for f in stack.poll(now) {
            send_frame(&raw, &f).await;
        }
        let delay = stack.delay_ms(now).unwrap_or(1000).min(1000);
        tokio::select! {
            f = local_rx.recv() => {
                let Some(f) = f else { return };
                stack.push_frame(f);
                while let Ok(f) = local_rx.try_recv() {
                    stack.push_frame(f);
                }
            }
            a = addr_rx.recv() => {
                let Some((addr, gw)) = a else { return };
                stack.set_addr(addr, gw);
            }
            () = wake.notified() => {}
            () = tokio::time::sleep(Duration::from_millis(delay)) => {}
        }
    }
}

async fn rx_loop(
    ctx: Arc<Ctx>,
    local_tx: mpsc::Sender<Vec<u8>>,
    dhcp_tx: mpsc::Sender<Vec<u8>>,
    tun: Arc<AsyncFd<OwnedFd>>,
) {
    let dns_slots = Arc::new(Semaphore::new(DNS_INFLIGHT));
    let mut buf = vec![0u8; 65536 + ETH_HDR];
    loop {
        let got = ctx
            .raw
            .async_io(Interest::READABLE, |s| s.recv(&mut buf))
            .await;
        let r = match got {
            Ok(Some(r)) => r,
            Ok(None) => continue,
            Err(e) => {
                warn!("raw socket: {e}");
                tokio::time::sleep(Duration::from_millis(100)).await;
                continue;
            }
        };
        let frame = &mut buf[..r.len];
        if r.csum_not_ready && frame.len() > ETH_HDR {
            fill_checksums(&mut frame[ETH_HDR..]);
        }
        let now = now_ms();
        let (verdict, out) = {
            let mut sw = ctx.lock();
            (sw.classify(frame, now), sw.drain())
        };
        for f in out {
            send_frame(&ctx.raw, &f).await;
        }
        match verdict {
            Verdict::Local => {
                let _ = local_tx.try_send(frame.to_vec());
            }
            Verdict::Dhcp => {
                let _ = dhcp_tx.try_send(frame.to_vec());
            }
            Verdict::Dns => {
                let Ok(slot) = Arc::clone(&dns_slots).try_acquire_owned() else {
                    continue;
                };
                let frame = frame.to_vec();
                let ctx = Arc::clone(&ctx);
                tokio::spawn(async move {
                    if let Some(reply) = dns_udp(&ctx, &frame).await {
                        send_frame(&ctx.raw, &reply).await;
                    }
                    drop(slot);
                });
            }
            Verdict::Forward => forward(&tun, &frame[ETH_HDR..]),
            Verdict::Drop => {}
        }
    }
}

/// A routed packet into the core's TUN (split to its MTU when the NIC
/// merged segments). Dropped when the TUN's queue is full.
fn forward(tun: &AsyncFd<OwnedFd>, packet: &[u8]) {
    let Some(ip) = parse_ipv4(packet) else {
        return;
    };
    let fd = tun.get_ref().as_raw_fd();
    if ip.total_len <= TUN_MTU {
        let _ = sys::dgram_send(fd, &packet[..ip.total_len]);
        return;
    }
    for seg in segment_tcp(packet, TUN_MTU) {
        let _ = sys::dgram_send(fd, &seg);
    }
}

async fn tun_loop(ctx: Arc<Ctx>, tun: Arc<AsyncFd<OwnedFd>>) {
    let mut buf = vec![0u8; 65536];
    loop {
        let got = tun
            .async_io(Interest::READABLE, |fd| {
                sys::dgram_recv(fd.as_raw_fd(), &mut buf)
            })
            .await;
        let n = match got {
            Ok(n) => n,
            Err(e) => {
                warn!("tun: {e}");
                tokio::time::sleep(Duration::from_millis(100)).await;
                continue;
            }
        };
        let (frame, out) = {
            let mut sw = ctx.lock();
            (sw.reply(&buf[..n], now_ms()), sw.drain())
        };
        for f in out.into_iter().chain(frame) {
            send_frame(&ctx.raw, &f).await;
        }
    }
}

/// A DNS query over UDP to the box → the answer frame.
async fn dns_udp(ctx: &Ctx, frame: &[u8]) -> Option<Vec<u8>> {
    let eth = parse_eth(frame)?;
    let ip = parse_ipv4(eth.payload)?;
    let (sport, _) = ip.ports(eth.payload)?;
    let query = ip.l4(eth.payload).get(8..)?;
    let (fake, mac, ours) = {
        let sw = ctx.lock();
        (sw.uses_gateway(ip.src, now_ms()), sw.mac, sw.addr?.ip)
    };
    let answer = truncate(ctx.app.dns.answer(query, fake).await?, MAX_UDP_ANSWER);
    let id: u16 = rand::rng().random();
    let packet = build_ipv4_udp(ours, ip.src, 53, sport, &answer, id);
    Some(build_eth(eth.src, mac, ETHERTYPE_IPV4, &packet))
}

/// DNS over TCP to the box (length-prefixed messages).
async fn dns_tcp(ctx: Arc<Ctx>, mut io: ConnIo) {
    let fake = ctx.lock().uses_gateway(io.peer, now_ms());
    let mut buf: Vec<u8> = Vec::new();
    while let Ok(Some(d)) = tokio::time::timeout(Duration::from_secs(30), io.recv()).await {
        buf.extend_from_slice(&d);
        while buf.len() >= 2 {
            let len = usize::from(u16::from_be_bytes([buf[0], buf[1]]));
            if buf.len() < 2 + len {
                break;
            }
            let query: Vec<u8> = buf.drain(..2 + len).skip(2).collect();
            if let Some(a) = ctx.app.dns.answer(&query, fake).await {
                let n = u16::try_from(a.len()).unwrap_or(u16::MAX);
                let mut out = n.to_be_bytes().to_vec();
                out.extend_from_slice(&a);
                io.send(out);
            }
        }
    }
}

/// A page connection ⇄ the page server on 127.0.0.1.
async fn bridge(mut io: ConnIo, to: SocketAddr) {
    let Ok(stream) = TcpStream::connect(to).await else {
        return;
    };
    let (mut r, mut w) = stream.into_split();
    let sender = io.sender();
    let down = async move {
        let mut b = vec![0u8; 16 * 1024];
        loop {
            match r.read(&mut b).await {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if !sender.send(b[..n].to_vec()) {
                        break;
                    }
                }
            }
        }
    };
    let up = async {
        while let Some(d) = io.recv().await {
            if w.write_all(&d).await.is_err() {
                break;
            }
        }
        let _ = w.shutdown().await;
        // The device may half-close after its request: keep the answer
        // flowing until the server is done.
        std::future::pending::<()>().await;
    };
    tokio::select! {
        () = down => {}
        () = up => {}
    }
}

async fn dhcp_loop(
    ctx: Arc<Ctx>,
    mut rx: mpsc::Receiver<Vec<u8>>,
    client_id: Mac,
    mut stop: watch::Receiver<bool>,
) {
    let mac = ctx.lock().mac;
    let mut c = Client::new(mac, client_id, rand::rng().random());
    let start = tokio::time::Instant::now();
    let mut current: Option<Net> = None;
    loop {
        let (f, ev) = c.poll(start.elapsed());
        if let Some(f) = f {
            send_frame(&ctx.raw, &f).await;
        }
        let mut events = Vec::from_iter(ev);
        tokio::select! {
            m = rx.recv() => {
                let Some(f) = m else { return };
                events.extend(c.on_frame(&f, start.elapsed()));
            }
            () = tokio::time::sleep_until(start + c.next_wake()) => {}
            _ = stop.changed() => {
                if let Some(f) = c.release() {
                    send_frame(&ctx.raw, &f).await;
                }
                return;
            }
        }
        for ev in events {
            let next = match ev {
                Event::Bound(l) => Some(Net {
                    addr: Addr {
                        ip: l.ip,
                        prefix: l.prefix,
                    },
                    gateway: l.router,
                    source: AddrSource::Dhcp,
                }),
                Event::Lost => None,
            };
            if next != current {
                current = next;
                ctx.set_net(next).await;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn static_addresses() {
        let a = parse_static("192.168.1.50/24").unwrap();
        assert_eq!((a.ip, a.prefix), (Ipv4Addr::new(192, 168, 1, 50), 24));
        assert_eq!(parse_static("10.0.0.9").unwrap().prefix, 24);
        assert!(parse_static("10.0.0.9/33").is_err());
        assert!(parse_static("dhcpp").is_err());
        assert!(parse_static("0.0.0.0/24").is_err());
        assert!(parse_static("224.0.0.1/24").is_err());
    }

    #[test]
    fn banner_says_everything_a_beginner_needs() {
        assert_eq!(
            banner(Ipv4Addr::new(192, 168, 1, 50), "Abc234xyz789"),
            "PaoPao 旁路由已就绪 · IP 192.168.1.50 · 管理 http://192.168.1.50 · 账号 admin · 密码 Abc234xyz789 · 把设备的网关和 DNS 设为 192.168.1.50"
        );
    }

    #[test]
    fn clock_moves_forward() {
        let a = now_ms();
        std::thread::sleep(Duration::from_millis(5));
        assert!(now_ms() > a);
    }
}
