//! 三类 socket 封装（global/interface/multicast）+ 发送辅助。

use crate::log::Logger;
use std::net::{Ipv4Addr, SocketAddr};
use std::os::fd::{AsRawFd, BorrowedFd, FromRawFd, IntoRawFd};
use std::sync::Arc;
use tokio::net::UdpSocket;

fn make_udp() -> socket2::Socket {
    socket2::Socket::new(socket2::Domain::IPV4, socket2::Type::DGRAM, None)
        .expect("create udp socket")
}

/// 绑定后拆双份：tokio 版（recv_loop 用）+ socket2 版（SocketSet 同步 send_to 用）。
/// 同 fd 的 dup，共享阻塞模式；recv 侧先转非阻塞。
fn to_pair(sock: socket2::Socket) -> std::io::Result<(UdpSocket, socket2::Socket)> {
    let dup = sock.try_clone()?;
    sock.set_nonblocking(true)?;
    let std_sock = unsafe { std::net::UdpSocket::from_raw_fd(sock.into_raw_fd()) };
    Ok((UdpSocket::from_std(std_sock)?, dup))
}

/// C# isFreeUdpPort 语义：无 REUSEADDR 试绑判断占用。
fn probe_port_in_use(port: u16) -> bool {
    std::net::UdpSocket::bind(("0.0.0.0", port)).is_err()
}

/// C# listenUdpGlobal：固定端口被占时 port_sharing=true → warn 并带 REUSEADDR 继续；
/// false → warn 并放弃（返回 Ok(None)）。所有 socket 一律 SO_REUSEADDR（C# 绑定前无条件设置）。
pub fn udp_bind_global(
    port: u16,
    port_sharing: bool,
    logger: &Logger,
    task_id: u32,
) -> crate::Result<Option<(UdpSocket, socket2::Socket)>> {
    if probe_port_in_use(port) {
        if !port_sharing {
            logger.warn(
                task_id,
                &format!("port {port} in use; port_sharing off, skipping global socket"),
            );
            return Ok(None);
        }
        logger.warn(
            task_id,
            &format!("port {port} in use; sharing via SO_REUSEADDR"),
        );
    }
    let sock = make_udp();
    sock.set_reuse_address(true)?;
    sock.bind(&SocketAddr::from((Ipv4Addr::UNSPECIFIED, port)).into())?;
    sock.set_broadcast(true)?;
    Ok(Some(to_pair(sock)?))
}

/// C# listenUdpInterfaces：每个网卡 IPv4 地址绑 <ip>:free_port。
pub fn udp_bind_interface(
    addr: Ipv4Addr,
    port: u16,
) -> crate::Result<(SocketAddr, UdpSocket, socket2::Socket)> {
    let sock = make_udp();
    sock.set_reuse_address(true)?;
    let local = SocketAddr::from((addr, port));
    sock.bind(&local.into())?;
    sock.set_broadcast(true)?;
    let (tokio_sock, sync_sock) = to_pair(sock)?;
    Ok((local, tokio_sock, sync_sock))
}

/// C# listenMulticast：0.0.0.0:port + 每个有 IPv4 的网卡 IP_ADD_MEMBERSHIP。
pub fn udp_bind_multicast(
    group: Ipv4Addr,
    port: u16,
    iface_ips: &[Ipv4Addr],
    logger: &Logger,
    task_id: u32,
) -> crate::Result<(UdpSocket, socket2::Socket)> {
    let sock = make_udp();
    sock.set_reuse_address(true)?;
    sock.bind(&SocketAddr::from((Ipv4Addr::UNSPECIFIED, port)).into())?;
    for iface in iface_ips {
        if let Err(e) = sock.join_multicast_v4(&group, iface) {
            logger.warn(task_id, &format!("join {group} on {iface} failed: {e}"));
        } else {
            logger.info(
                task_id,
                &format!("joining group {group} on interface {iface}"),
            );
        }
    }
    sock.set_broadcast(true)?;
    to_pair(sock).map_err(Into::into)
}

pub fn leave_multicast(sock: &UdpSocket, group: Ipv4Addr, iface_ips: &[Ipv4Addr]) {
    for iface in iface_ips {
        // SAFETY: sock owns the fd for the duration of this call.
        let dup = unsafe { BorrowedFd::borrow_raw(sock.as_raw_fd()) }.try_clone_to_owned();
        if let Ok(cloned) = dup {
            let s = socket2::Socket::from(cloned);
            let _ = s.leave_multicast_v4(&group, iface);
        }
    }
}

/// C# send()：从所有活动 socket 各发一份。
pub async fn send_from_all(sockets: &[&UdpSocket], to: SocketAddr, data: &[u8]) {
    for s in sockets {
        let _ = s.send_to(data, to).await;
    }
}

/// 共享接收循环：select! 取消/收包；pcap tap + debug 日志 + parse + report（spec §2 trait 注释）。
pub async fn recv_loop(
    ctx: Arc<crate::engine::EngineContext>,
    engine: Arc<dyn crate::engine::ScanEngine>,
    sock: UdpSocket,
) {
    let local = sock
        .local_addr()
        .unwrap_or_else(|_| "0.0.0.0:0".parse().unwrap());
    let mut buf = vec![0u8; 65535];
    loop {
        tokio::select! {
            _ = ctx.cancel.cancelled() => break,
            res = sock.recv_from(&mut buf) => {
                let (n, from) = match res {
                    Ok(r) => r,
                    Err(_) => continue,
                };
                let data = &buf[..n];
                if let Some(p) = &ctx.pcap {
                    let _ = p.append_udp(std::time::SystemTime::now(), from, local, data);
                }
                ctx.logger.debug(ctx.task_id, &format!("<- {from} ({}B)", data.len()));
                for dev in engine.parse(from, data) {
                    let _ = ctx.reporter.send(dev);
                }
            }
        }
    }
}

/// C# ScanEngine 的 socket 列表 + send() 的"从所有活动 socket 各发一份"。
/// 存 socket2::Socket（同步 send_to，与 tokio 版同 fd 共享非阻塞模式）；
/// recv 侧仍用对应的 tokio UdpSocket（recv_loop）。
#[derive(Default)]
pub struct SocketSet {
    socks: std::sync::Mutex<Vec<socket2::Socket>>,
}

impl SocketSet {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add(&self, sock: socket2::Socket) {
        self.socks.lock().unwrap().push(sock);
    }

    pub fn len(&self) -> usize {
        self.socks.lock().unwrap().len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// 每个活动 socket 各发一份（C# send 的逐 socket try/catch 尽力发）。
    /// 返回失败 socket 数，由调用方记 warn（尽力发、失败记 warn）。
    fn send_to_all(&self, to: SocketAddr, data: &[u8]) -> usize {
        let socks = self.socks.lock().unwrap();
        let to: socket2::SockAddr = to.into();
        socks
            .iter()
            .filter(|s| s.send_to(data, &to).is_err())
            .count()
    }

    /// C# sendBroadcast(port)
    pub fn send_broadcast(&self, port: u16, data: &[u8]) -> usize {
        let ip: Ipv4Addr = "255.255.255.255".parse().unwrap();
        let to: SocketAddr = (ip, port).into();
        self.send_to_all(to, data)
    }

    /// C# sendMulticast(dest, port)
    pub fn send_multicast(&self, group: Ipv4Addr, port: u16, data: &[u8]) -> usize {
        self.send_to_all(SocketAddr::from((group, port)), data)
    }

    /// C# sendUnicast(dest, port)
    pub fn send_unicast(&self, ip: Ipv4Addr, port: u16, data: &[u8]) -> usize {
        self.send_to_all(SocketAddr::from((ip, port)), data)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn bind_global_and_send_recv() {
        let l = Arc::new(crate::log::Logger::new(crate::log::Level::Debug));
        // with_used(&[]) 种子固定：并行测试会撞同一候选端口，被占则取下一个。
        let mut pp = crate::ports::PortProvider::with_used(&[]);
        let (sock, port) = loop {
            let port = pp.free_port().expect("free port");
            if let Ok(Some((sock, _sync))) = udp_bind_global(port, true, &l, 1) {
                break (sock, port);
            }
        };
        assert_eq!(
            sock.local_addr().unwrap(),
            SocketAddr::from((std::net::Ipv4Addr::UNSPECIFIED, port))
        );

        let peer = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        peer.send_to(b"ping", sock.local_addr().unwrap()).unwrap();
        let mut buf = [0u8; 64];
        let (n, from) = sock.recv_from(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"ping");
        assert_eq!(from.ip(), "127.0.0.1".parse::<std::net::IpAddr>().unwrap());
    }

    #[tokio::test]
    async fn busy_port_no_sharing_gives_none() {
        let l = Arc::new(crate::log::Logger::new(crate::log::Level::Debug));
        // 同上：候选端口被并行测试占用时取下一个。
        let mut pp = crate::ports::PortProvider::with_used(&[]);
        let (port, holder) = loop {
            let port = pp.free_port().expect("free port");
            match std::net::UdpSocket::bind(("0.0.0.0", port)) {
                Ok(holder) => break (port, holder),
                Err(_) => continue,
            }
        };
        let r = udp_bind_global(port, false, &l, 1).unwrap();
        assert!(r.is_none());
        drop(holder);
        // port_sharing=true 时带 REUSEADDR 继续（并行测试的试绑探针可能瞬时占着该端口，重试）。
        let mut bound = false;
        for _ in 0..8 {
            if let Ok(Some(_)) = udp_bind_global(port, true, &l, 1) {
                bound = true;
                break;
            }
        }
        assert!(bound);
    }

    #[tokio::test]
    async fn multicast_join_on_loopback() {
        let l = Arc::new(crate::log::Logger::new(crate::log::Level::Debug));
        let group: Ipv4Addr = "239.255.255.250".parse().unwrap();
        let ifaces: [Ipv4Addr; 1] = ["127.0.0.1".parse().unwrap()];
        // 同上：候选端口被并行测试占用时取下一个。
        let mut pp = crate::ports::PortProvider::with_used(&[]);
        let (sock, port) = loop {
            let port = pp.free_port().expect("free port");
            match udp_bind_multicast(group, port, &ifaces, &l, 1) {
                Ok((sock, _sync)) => break (sock, port),
                Err(_) => continue,
            }
        };
        assert_eq!(sock.local_addr().unwrap().port(), port);
        drop(sock);
    }
}
