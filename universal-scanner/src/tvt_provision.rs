//! TVT L2 设置（set-IP）协议：构造并发送 140B `MHED` type-3 组播报文。
//!
//! 参考 `tvt-iptool-linux/src/l2-provision.c` 的 clean-room 实现（无实机抓包可对照，
//! 报文布局以其为唯一规范）：
//! - 0x00 `"MHED"`；0x04 协议版本 LE32（默认 `0x00010008`）；0x08 消息类型 `0x03`（set-IP）；
//! - 0x20 目标 MAC（6B）；0x28 新 IP / 0x2C 掩码 / 0x30 网关（各 4B，网络序）；
//! - 0x54 base64(管理员密码)，容量 28B（明文 ≤ 21B）；0x8A DHCP 开关（1 字节）。
//!
//! 发送：组播 234.55.55.55:23456，TTL 5，最多 3 次尝试、间隔 100ms（任一次成功即返回 Ok）。
//! 与发现引擎（`protocols::tvt`）解耦：本模块只做「写」，不监听、不解析应答。

use crate::errors::{Error, Result};
use crate::protocols::tvt::{OFF_GATEWAY, OFF_IP, OFF_MAC, OFF_MASK, PORT, PROBE_GROUP};
use std::net::Ipv4Addr;
use std::time::Duration;

/// 报文固定长度（与发现探测帧一致，140B）。
pub const PACKET_SIZE: usize = 140;
/// 默认协议版本（发现应答携带的版本 0x00010008，小端写入 0x04）。
pub const DEFAULT_PROTOCOL_VERSION: u32 = 0x0001_0008;
/// set-IP 组播地址 / 端口（与发现探测同组，常量同源 `protocols::tvt`）。
pub const SET_IP_GROUP: Ipv4Addr = PROBE_GROUP;
pub const SET_IP_PORT: u16 = PORT;
/// base64(密码) 在报文中的容量（明文上限 = 21B → 28 字符）。
pub const MAX_PLAINTEXT_PASSWORD: usize = 21;

const TYPE_SET_IP: u8 = 0x03;
const PASSWORD_CAPACITY: usize = 28;
const OFF_VERSION: usize = 0x04;
const OFF_MSG_TYPE: usize = 8;
const OFF_PASSWORD: usize = 0x54;
const OFF_DHCP: usize = 0x8a;

/// set-IP 请求参数（CLI / 调用方填充；`protocol_version == 0` 时用默认版本）。
#[derive(Debug, Clone)]
pub struct SetIpRequest {
    pub mac: [u8; 6],
    pub password: String,
    pub new_ip: Ipv4Addr,
    pub subnet_mask: Ipv4Addr,
    pub gateway: Ipv4Addr,
    pub dhcp: bool,
    pub protocol_version: u32,
}

/// 解析 `AA:BB:CC:DD:EE:FF` 形式的 MAC（大小写不敏感）。
pub fn parse_mac(text: &str) -> Result<[u8; 6]> {
    let parts: Vec<&str> = text.split(':').collect();
    if parts.len() != 6 {
        return Err(Error::Config(format!("invalid MAC address: {text}")));
    }
    let mut out = [0u8; 6];
    for (i, part) in parts.iter().enumerate() {
        if part.len() != 2 || !part.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(Error::Config(format!("invalid MAC address: {text}")));
        }
        out[i] = u8::from_str_radix(part, 16)
            .map_err(|_| Error::Config(format!("invalid MAC address: {text}")))?;
    }
    Ok(out)
}

/// 构造 140B set-IP 报文（纯函数，无 I/O）。
///
/// 校验：`password` 明文 ≤ 21 字节（base64 后 ≤ 28 字符）。其余字段按网络序直写。
pub fn build_set_ip_request(req: &SetIpRequest) -> Result<[u8; PACKET_SIZE]> {
    use base64::Engine as _;
    let version = if req.protocol_version == 0 {
        DEFAULT_PROTOCOL_VERSION
    } else {
        req.protocol_version
    };

    let encoded = base64::engine::general_purpose::STANDARD.encode(req.password.as_bytes());
    if encoded.len() > PASSWORD_CAPACITY {
        return Err(Error::Config(format!(
            "admin password too long for TVT L2 provisioning (max {MAX_PLAINTEXT_PASSWORD} bytes)"
        )));
    }

    let mut p = [0u8; PACKET_SIZE];
    p[0..4].copy_from_slice(b"MHED");
    p[OFF_VERSION..OFF_VERSION + 4].copy_from_slice(&version.to_le_bytes());
    p[OFF_MSG_TYPE] = TYPE_SET_IP;
    p[OFF_MAC..OFF_MAC + 6].copy_from_slice(&req.mac);
    p[OFF_IP..OFF_IP + 4].copy_from_slice(&req.new_ip.octets());
    p[OFF_MASK..OFF_MASK + 4].copy_from_slice(&req.subnet_mask.octets());
    p[OFF_GATEWAY..OFF_GATEWAY + 4].copy_from_slice(&req.gateway.octets());
    p[OFF_PASSWORD..OFF_PASSWORD + encoded.len()].copy_from_slice(encoded.as_bytes());
    p[OFF_DHCP] = if req.dhcp { 1 } else { 0 };
    Ok(p)
}

/// 发送 set-IP 组播报文：TTL 5，最多 3 次、间隔 100ms；任一次成功即 `Ok(())`。
/// `bind_address` 指定出接口 IP（`IP_MULTICAST_IF`），`None` 用系统默认路由。
/// 全部失败 → `Err`（最后一次 I/O 错误）。
pub fn send_set_ip(req: &SetIpRequest, bind_address: Option<Ipv4Addr>) -> Result<()> {
    let mut packet = build_set_ip_request(req)?;
    let dest: std::net::SocketAddr = (SET_IP_GROUP, SET_IP_PORT).into();

    let sock = socket2::Socket::new(socket2::Domain::IPV4, socket2::Type::DGRAM, None)?;
    if let Some(bind) = bind_address {
        sock.set_multicast_if_v4(&bind)?;
    }
    sock.set_multicast_ttl_v4(5)?;

    let mut last_err: Option<std::io::Error> = None;
    for attempt in 0..3u32 {
        match sock.send_to(&packet, &dest.into()) {
            Ok(PACKET_SIZE) => {
                last_err = None;
                break;
            }
            Ok(_) => {
                last_err = Some(std::io::Error::new(
                    std::io::ErrorKind::WriteZero,
                    "short send",
                ))
            }
            Err(e) => last_err = Some(e),
        }
        if attempt == 2 {
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
    }

    // 尽力清零本地缓冲中的密码区（best-effort secure clear）。
    for b in packet[OFF_PASSWORD..OFF_PASSWORD + PASSWORD_CAPACITY].iter_mut() {
        *b = 0;
    }

    match last_err {
        None => Ok(()),
        Some(e) => Err(Error::Io(std::io::Error::new(
            e.kind(),
            format!("all 3 TVT L2 set-IP sends failed: {e}"),
        ))),
    }
}

/// 十六进制转储（16 字节/行、偏移前缀）。0x54..0x7A 密码区清零后输出，
/// 避免 base64(密码) 泄漏到终端/日志。
pub fn hex_dump(packet: &[u8; PACKET_SIZE]) -> String {
    let mut masked = *packet;
    for b in masked[OFF_PASSWORD..OFF_PASSWORD + PASSWORD_CAPACITY].iter_mut() {
        *b = 0;
    }
    let mut out = String::with_capacity(PACKET_SIZE / 16 * 34);
    for (i, line) in masked.chunks(16).enumerate() {
        let hex: Vec<String> = line.iter().map(|b| format!("{b:02x}")).collect();
        out.push_str(&format!("{:04x}  {}\n", i * 16, hex.join(" ")));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 测试 MAC 恒为合成值 00:11:22:33:44:55（fixture 同款）：
    /// set-IP 报文会真实发上局域网，绝不能用实机抓包中的真实 MAC，避免改到活设备。
    fn sample_req() -> SetIpRequest {
        SetIpRequest {
            mac: [0x00, 0x11, 0x22, 0x33, 0x44, 0x55],
            password: "admin".into(),
            new_ip: "192.168.0.90".parse().unwrap(),
            subnet_mask: "255.255.255.0".parse().unwrap(),
            gateway: "192.168.0.1".parse().unwrap(),
            dhcp: false,
            protocol_version: 0, // 默认
        }
    }

    #[test]
    fn parse_mac_valid() {
        assert_eq!(
            parse_mac("00:18:AE:9B:E2:80").unwrap(),
            [0x00, 0x18, 0xae, 0x9b, 0xe2, 0x80]
        );
    }

    #[test]
    fn parse_mac_invalid() {
        assert!(parse_mac("00:18:AE:9B:E2").is_err());
        assert!(parse_mac("00:18:AE:9B:E2:8G").is_err());
        assert!(parse_mac("0018AE9BE280").is_err());
    }

    #[test]
    fn build_layout_pinned() {
        use base64::Engine as _;
        let p = build_set_ip_request(&sample_req()).unwrap();
        assert_eq!(p.len(), PACKET_SIZE);
        assert_eq!(&p[0..4], b"MHED");
        // 默认版本 LE32
        assert_eq!(
            &p[OFF_VERSION..OFF_VERSION + 4],
            &DEFAULT_PROTOCOL_VERSION.to_le_bytes()
        );
        assert_eq!(p[OFF_MSG_TYPE], TYPE_SET_IP);
        assert_eq!(
            &p[OFF_MAC..OFF_MAC + 6],
            &[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]
        );
        // IP 网络序（octets 直写）
        assert_eq!(&p[OFF_IP..OFF_IP + 4], &[0xc0, 0xa8, 0x00, 0x5a]);
        assert_eq!(&p[OFF_MASK..OFF_MASK + 4], &[0xff, 0xff, 0xff, 0x00]);
        assert_eq!(&p[OFF_GATEWAY..OFF_GATEWAY + 4], &[0xc0, 0xa8, 0x00, 0x01]);
        // base64("admin") = "YWRtaW4="
        assert_eq!(
            base64::engine::general_purpose::STANDARD.encode(b"admin"),
            "YWRtaW4="
        );
        assert_eq!(&p[OFF_PASSWORD..OFF_PASSWORD + 8], b"YWRtaW4=");
        assert_eq!(p[OFF_PASSWORD + 8], 0);
        assert_eq!(p[OFF_DHCP], 0);
        // 未使用尾部全零
        assert!(p[OFF_DHCP + 1..].iter().all(|&b| b == 0));
    }

    #[test]
    fn build_dhcp_and_custom_version() {
        let mut r = sample_req();
        r.dhcp = true;
        r.protocol_version = 0x0001_0009;
        let p = build_set_ip_request(&r).unwrap();
        assert_eq!(p[OFF_DHCP], 1);
        assert_eq!(
            &p[OFF_VERSION..OFF_VERSION + 4],
            &0x0001_0009u32.to_le_bytes()
        );
    }

    #[test]
    fn build_empty_password_ok() {
        let mut r = sample_req();
        r.password.clear();
        let p = build_set_ip_request(&r).unwrap();
        assert!(p[OFF_PASSWORD..].iter().all(|&b| b == 0));
    }

    #[test]
    fn build_password_too_long_rejected() {
        let mut r = sample_req();
        r.password = "x".repeat(MAX_PLAINTEXT_PASSWORD + 1);
        assert!(build_set_ip_request(&r).is_err());
        // 边界：恰好 21 字节可接受（base64 = 28 字符）
        r.password = "x".repeat(MAX_PLAINTEXT_PASSWORD);
        assert!(build_set_ip_request(&r).is_ok());
    }

    #[test]
    fn hex_dump_redacts_password_region() {
        let p = build_set_ip_request(&sample_req()).unwrap();
        // 前提：报文中确实写入了 base64("admin") = "YWRtaW4="
        assert_eq!(&p[OFF_PASSWORD..OFF_PASSWORD + 8], b"YWRtaW4=");
        let dump = hex_dump(&p);
        let first = dump.lines().next().unwrap();
        assert!(first.starts_with("0000  4d 48 45 44"));
        let line_0x50 = dump.lines().find(|l| l.starts_with("0050")).unwrap();
        // "YWR" = 59 44 52 不得出现在转储中
        assert!(!line_0x50.contains("59 44 52"));
        assert!(line_0x50.split_whitespace().skip(1).all(|t| t == "00"));
    }

    #[test]
    fn send_set_ip_reachable_or_clean_error() {
        // 无实机设备：发送路径要么成功（组播可达），要么返回 I/O 错误（全部尝试失败）。
        // 不 assert Ok（CI/loopback 组播可能受限），只确保不 panic 且错误类型正确。
        // 目标 MAC 为合成值（见 sample_req），真实 LAN 上的设备不会响应。
        match send_set_ip(&sample_req(), None) {
            Ok(()) => {}
            Err(Error::Io(_)) => {}
            Err(other) => panic!("unexpected error: {other}"),
        }
    }

    /// 组播自检（tests/scanner.rs 同款模式）：绑 :23456 加入组并发一条回环探测，
    /// 收到 → 返回成功 join 的接口 IP（供发送端选出接口）；否则 None（调用方 skip）。
    fn multicast_join_iface() -> Option<Ipv4Addr> {
        let ifaces = crate::iface::active_interfaces();
        let ips: Vec<Ipv4Addr> = ifaces.iter().flat_map(|i| i.ipv4_addrs()).collect();
        if ips.is_empty() {
            return None;
        }
        let recv = std::net::UdpSocket::bind(("0.0.0.0", SET_IP_PORT)).ok()?;
        let joined: Vec<Ipv4Addr> = ips
            .iter()
            .copied()
            .filter(|ip| recv.join_multicast_v4(&SET_IP_GROUP, ip).is_ok())
            .collect();
        if joined.is_empty() {
            return None;
        }
        let _ = recv.set_read_timeout(Some(Duration::from_secs(1)));
        let sender =
            socket2::Socket::new(socket2::Domain::IPV4, socket2::Type::DGRAM, None).ok()?;
        let dest: socket2::SockAddr =
            std::net::SocketAddr::from((SET_IP_GROUP, SET_IP_PORT)).into();
        let mut buf = [0u8; 64];
        for ip in &joined {
            if sender.set_multicast_if_v4(ip).is_err() {
                continue;
            }
            if sender.send_to(b"probe", &dest).is_err() {
                continue;
            }
            if recv.recv_from(&mut buf).is_ok() {
                return Some(*ip);
            }
        }
        None
    }

    #[test]
    fn set_ip_loopback_roundtrip() {
        let Some(iface_ip) = multicast_join_iface() else {
            eprintln!("SKIP: multicast unavailable in this environment");
            return;
        };
        // 自检 socket 已 drop，端口空闲；接收端重新绑定并加入组。
        let recv = std::net::UdpSocket::bind(("0.0.0.0", SET_IP_PORT)).unwrap();
        recv.join_multicast_v4(&SET_IP_GROUP, &iface_ip).unwrap();
        let _ = recv.set_read_timeout(Some(Duration::from_secs(3)));

        let req = sample_req(); // 合成 MAC：即使报文离开本机也不会命中任何真机
        let expected = build_set_ip_request(&req).unwrap();
        // 组播可用环境下发送失败 = 真 bug（不 skip）。
        send_set_ip(&req, Some(iface_ip)).unwrap();

        let mut buf = [0u8; PACKET_SIZE];
        let (n, from) = recv
            .recv_from(&mut buf)
            .expect("no set-IP packet received on loopback");
        assert_eq!(n, PACKET_SIZE);
        assert_eq!(&buf[..n], &expected);
        // 回环路径上源地址 = 发送端出接口 IP（实网中则是设备自身 IP，而非组地址）。
        assert_eq!(from.ip(), iface_ip);
    }
}
