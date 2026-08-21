//! Panasonic 引擎（T34）：52B 发现帧 + TLV 应答（自偏移 53），逐行对齐 C# Panasonic.reciever。

use crate::devices::Device;
use crate::engine::{EngineContext, ScanEngine};
use crate::net::SocketSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use tokio::task::JoinHandle;

const PROBE_PORT: u16 = 10670; // C# port：探测目的端口（sendBroadcast(port)）
const ANSWER_PORT: u16 = 10669; // C# answerPort：global 监听端口
const HEADER_SIZE: usize = 52; // C# PanasonicDiscovery 结构体大小（0x34）
const TLV_START: usize = 53; // C# parsePacket：i = 53

const TLV_IPV4: u16 = 0x0020; // AnswerValues.ipv4
const TLV_FULLNAME: u16 = 0x00A7; // AnswerValues.fullname
const TLV_SHORTNAME: u16 = 0x00A8; // AnswerValues.shortname

/// C# sender()：52B 发现帧，字段逐字节照抄 PanasonicDiscovery 构造函数。
/// C# sendBroadcast(port) 的 dest 为 255.255.255.255，ip 字段按 BE 填充目标 IP。
fn build_probe() -> [u8; HEADER_SIZE] {
    let mut probe = [0u8; HEADER_SIZE];
    probe[0x00..0x04].copy_from_slice(&0x00010000u32.to_be_bytes()); // headerMagic
    probe[0x04..0x08].copy_from_slice(&0x000D0000u32.to_be_bytes()); // _uint32_04
                                                                     // _uint32_08 = 0
    probe[0x0C..0x12].copy_from_slice(&[0xFF; 6]); // 目标 MAC ff:ff:ff:ff:ff:ff
    let ip: Ipv4Addr = "255.255.255.255".parse().unwrap();
    probe[0x12..0x16].copy_from_slice(&u32::from(ip).to_be_bytes());
    probe[0x16..0x1A].copy_from_slice(&0x00012011u32.to_be_bytes()); // _uint32_16
    probe[0x1A..0x1E].copy_from_slice(&0x1E11231Fu32.to_be_bytes()); // _uint32_1A
    probe[0x1E..0x22].copy_from_slice(&0x1E191300u32.to_be_bytes()); // _uint32_1E
    probe[0x22..0x26].copy_from_slice(&0x00020000u32.to_be_bytes()); // _uint32_22
                                                                     // _uint32_26 / _uint32_2A = 0
    probe[0x2E..0x32].copy_from_slice(&0x0000FFFFu32.to_be_bytes()); // _uint32_2E
    probe[0x32..0x34].copy_from_slice(&0u16.to_be_bytes()); // checksum = 0
    probe
}

pub struct Panasonic {
    socks: SocketSet,
}

impl Default for Panasonic {
    fn default() -> Self {
        Self {
            socks: SocketSet::new(),
        }
    }
}

impl ScanEngine for Panasonic {
    fn name(&self) -> &str {
        "Panasonic"
    }
    fn used_ports(&self) -> &[u16] {
        &[PROBE_PORT] // C# getUsedPort：预占**探测端口** 10670
    }
    fn color(&self) -> u32 {
        0x000000 // Color.Black.ToArgb() → 低 24 位
    }

    fn listen(&self, ctx: Arc<EngineContext>) -> crate::Result<Vec<JoinHandle<()>>> {
        let ifaces = crate::iface::active_interfaces();
        let nic_ips: Vec<Ipv4Addr> = ifaces.iter().flat_map(|i| i.ipv4_addrs()).collect();
        // recv_loop 只调用 parse()（纯函数），用新实例即可，无需自引用。
        let e: Arc<dyn ScanEngine> = Arc::new(Self::default());
        let mut handles = Vec::new();
        // C# listenUdpGlobal(answerPort)：G 绑**监听端口** 10669
        if let Some((gsock, gsync)) = crate::net::udp_bind_global(
            ANSWER_PORT,
            ctx.config.port_sharing,
            &ctx.logger,
            ctx.task_id,
        )? {
            self.socks.add(gsync);
            handles.push(tokio::spawn(crate::net::recv_loop(
                ctx.clone(),
                Arc::clone(&e),
                gsock,
            )));
        }
        // C# listenUdpInterfaces：每网卡取 free_port（耗尽则跳过）
        for ip in nic_ips {
            let Some(p) = ctx.ports.lock().unwrap().free_port() else {
                ctx.logger
                    .warn(ctx.task_id, "no free port; skipping interface socket");
                continue;
            };
            let (_local, isock, isync) = crate::net::udp_bind_interface(ip, p)?;
            self.socks.add(isync);
            handles.push(tokio::spawn(crate::net::recv_loop(
                ctx.clone(),
                Arc::clone(&e),
                isock,
            )));
        }
        Ok(handles)
    }

    fn scan(&self, ctx: &EngineContext) -> crate::Result<()> {
        // C# Panasonic.scan：sendBroadcast(port)——发往**探测端口** 10670（与监听 10669 不同）
        let probe = build_probe();
        let failed = self.socks.send_broadcast(PROBE_PORT, &probe);
        if failed > 0 {
            ctx.logger
                .warn(ctx.task_id, &format!("{} Panasonic sends failed", failed));
        }
        Ok(())
    }

    fn parse(&self, _from: SocketAddr, data: &[u8]) -> Vec<Device> {
        // C# reciever：长度 ≤52 → warn+丢弃（纯函数不记日志）
        if data.len() <= HEADER_SIZE {
            return Vec::new();
        }
        // MAC@6 → serial（C# String.Format "{0:X2}:..." 大写冒号格式）
        let serial = format!(
            "{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
            data[6], data[7], data[8], data[9], data[10], data[11]
        );
        // C# parsePacket：TLV 自偏移 53，key(2B BE)+len(2B BE)+value
        let mut tlv: Vec<(u16, &[u8])> = Vec::new();
        let mut i = TLV_START;
        while i < data.len() - 4 {
            let key = u16::from_be_bytes([data[i], data[i + 1]]);
            let length = u16::from_be_bytes([data[i + 2], data[i + 3]]) as usize;
            i += 4;
            // C#：i + length >= data.Length → warn "packet overflow" 并返回已解析部分
            if i + length >= data.len() {
                break;
            }
            // C# Dictionary.Add 遇重复 key 抛异常；纯函数不可抛 → 首个生效
            if !tlv.iter().any(|(k, _)| *k == key) {
                tlv.push((key, &data[i..i + length]));
            }
            i += length;
        }
        let get = |k: u16| tlv.iter().find(|(key, _)| *key == k).map(|(_, v)| *v);
        // C#：fullname → 回退 shortname（UTF-8）
        let model = get(TLV_FULLNAME)
            .or_else(|| get(TLV_SHORTNAME))
            .map(|v| String::from_utf8_lossy(v).into_owned());
        // C#：new IPAddress(byte[]) 接受 4B（IPv4）或 16B（IPv6），其他长度抛异常 → 无 ip。
        // 字节**直接**按网络序构造，无翻转
        let ip: Option<IpAddr> = get(TLV_IPV4).and_then(|v| match v.len() {
            4 => Some(IpAddr::V4(Ipv4Addr::new(v[0], v[1], v[2], v[3]))),
            16 => {
                let mut a = [0u8; 16];
                a.copy_from_slice(v);
                Some(IpAddr::V6(Ipv6Addr::from(a)))
            }
            _ => None,
        });
        // C#：model 与 ipv4 均存在才上报；version 1
        let (Some(model), Some(ip)) = (model, ip) else {
            return Vec::new();
        };
        vec![Device {
            mac: serial.clone(),
            protocol: "Panasonic".into(),
            version: 1,
            ip,
            device_type: model,
            serial,
        }]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;

    /// 按 C# parsePacket 的 TLV 起始偏移 53 构造应答帧（53B 头 + TLV + 4B 尾部）。
    /// 尾部 4 字节与真实抓包一致（fixture 末尾即有 4B 尾随数据）：C# 越界规则
    /// `i + length >= data.Length` 要求末 TLV 值后至少留 1 字节，否则该 TLV 被丢弃。
    fn panasonic_frame(mac: [u8; 6], tlv: &[(u16, &[u8])]) -> Vec<u8> {
        let mut d = vec![0u8; TLV_START];
        d[0..4].copy_from_slice(&0x0001_0000u32.to_be_bytes());
        d[6..12].copy_from_slice(&mac);
        for (k, v) in tlv {
            d.extend_from_slice(&k.to_be_bytes());
            d.extend_from_slice(&(v.len() as u16).to_be_bytes());
            d.extend_from_slice(v);
        }
        d.extend_from_slice(&[0u8; 4]);
        d
    }

    #[test]
    fn panasonic_full() {
        let f = panasonic_frame(
            [0x00, 0x11, 0x22, 0x33, 0x44, 0x55],
            &[(0x0020, &[192, 168, 1, 50]), (0x00A7, b"KX-A")],
        );
        let from: SocketAddr = "240.0.15.0:1024".parse().unwrap();
        let devs = Panasonic::default().parse(from, &f);
        assert_eq!(devs.len(), 1);
        assert_eq!(devs[0].protocol, "Panasonic");
        assert_eq!(devs[0].version, 1);
        assert_eq!(devs[0].ip, "192.168.1.50".parse::<IpAddr>().unwrap());
        assert_eq!(devs[0].device_type, "KX-A");
        assert_eq!(devs[0].mac, "00:11:22:33:44:55");
        assert_eq!(devs[0].serial, "00:11:22:33:44:55");
    }

    #[test]
    fn panasonic_no_ipv4_not_reported() {
        // 只有 fullname TLV → 无 ipv4 → 不上报
        let f = panasonic_frame([0; 6], &[(0x00A7, b"KX-A")]);
        let from: SocketAddr = "240.0.15.0:1024".parse().unwrap();
        assert!(Panasonic::default().parse(from, &f).is_empty());
    }

    #[test]
    fn panasonic_header_only_dropped() {
        // 恰 52 字节（无 TLV）→ 长度 ≤52 丢弃
        let f = vec![0u8; HEADER_SIZE];
        let from: SocketAddr = "240.0.15.0:1024".parse().unwrap();
        assert!(Panasonic::default().parse(from, &f).is_empty());
    }

    #[test]
    fn panasonic_shortname_fallback() {
        // 只有 shortname(0x00A8) → model 取 shortname
        let f = panasonic_frame([0; 6], &[(0x0020, &[10, 0, 0, 1]), (0x00A8, b"KX-S")]);
        let from: SocketAddr = "240.0.15.0:1024".parse().unwrap();
        let devs = Panasonic::default().parse(from, &f);
        assert_eq!(devs.len(), 1);
        assert_eq!(devs[0].device_type, "KX-S");
        assert_eq!(devs[0].ip, "10.0.0.1".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn panasonic_tlv_overflow_returns_parsed() {
        // 值越界（i + length >= len）→ 返回已解析部分（前面的 TLV 生效）
        let mut f = panasonic_frame([0; 6], &[(0x0020, &[192, 168, 1, 50]), (0x00A7, b"KX-A")]);
        // 追加一个声明长度越界的 TLV：key 0x0021，len 0x00FF
        f.extend_from_slice(&0x0021u16.to_be_bytes());
        f.extend_from_slice(&0x00FFu16.to_be_bytes());
        f.push(0);
        let from: SocketAddr = "240.0.15.0:1024".parse().unwrap();
        let devs = Panasonic::default().parse(from, &f);
        assert_eq!(devs.len(), 1);
        assert_eq!(devs[0].device_type, "KX-A");
    }

    #[test]
    fn panasonic_ipv6_sixteen_bytes() {
        // C# new IPAddress(byte[16]) → IPv6：16B 值同样上报
        let f = panasonic_frame(
            [0; 6],
            &[
                (
                    0x0020,
                    &[0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
                ),
                (0x00A7, b"KX-A"),
            ],
        );
        let from: SocketAddr = "240.0.15.0:1024".parse().unwrap();
        let devs = Panasonic::default().parse(from, &f);
        assert_eq!(devs.len(), 1);
        assert_eq!(devs[0].ip, "fe80::1".parse::<IpAddr>().unwrap());
        assert_eq!(devs[0].device_type, "KX-A");
    }

    #[test]
    fn panasonic_bad_ip_length_not_reported() {
        // ip 值既非 4B 也非 16B → C# new IPAddress 抛异常 → 不上报
        let f = panasonic_frame(
            [0; 6],
            &[(0x0020, &[1, 2, 3, 4, 5, 6, 7, 8]), (0x00A7, b"KX-A")],
        );
        let from: SocketAddr = "240.0.15.0:1024".parse().unwrap();
        assert!(Panasonic::default().parse(from, &f).is_empty());
    }

    #[tokio::test]
    async fn fixture_replay() {
        let data = tokio::fs::read(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/Panasonic.selftest"
        ))
        .await
        .unwrap();
        let from: SocketAddr = "240.0.15.0:1024".parse().unwrap();
        let devs = Panasonic::default().parse(from, &data);
        // 期望值：对照 C# Panasonic.reciever 规则手工核定后填入（注释出处：Panasonic.cs reciever/parsePacket）
        // C# Panasonic.reciever：Encoding.UTF8.GetString(values[fullname]) 保留 NUL → "Virtual"+9×NUL
        assert_eq!(devs.len(), 1);
        assert_eq!(devs[0].protocol, "Panasonic");
        assert_eq!(devs[0].version, 1);
        assert_eq!(devs[0].ip.to_string(), "240.0.15.0");
        assert_eq!(devs[0].device_type, "Virtual\0\0\0\0\0\0\0\0\0");
        assert_eq!(devs[0].mac, "00:11:22:33:44:55");
        assert_eq!(devs[0].serial, "00:11:22:33:44:55");
    }
}
