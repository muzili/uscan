//! Bosch 引擎（T24）：双格式 parse（32B 二进制 / XML）逐行对齐 C# Bosch.reciever。

use crate::devices::Device;
use crate::engine::{EngineContext, ScanEngine};
use crate::net::SocketSet;
use chrono::Timelike;
use std::net::SocketAddr;
use tokio::task::JoinHandle;

const REQUEST_PORT: u16 = 1757; // C# requestPort：探测目的端口
const ANSWER_PORT: u16 = 1758; // C# answerPort：global 监听端口
const BINARY_ANSWER_SIZE: usize = 0x20; // C# BoschBinaryAnswer 结构体大小
const ANSWER_MAGIC: u32 = 0x9939a427;
const REQUEST_MAGIC: u32 = 0xff0006de;

/// C# sender()：magic BE + transactionID（UTC 编码）BE + requestMagic BE，共 12B。
fn build_probe() -> Vec<u8> {
    let now = chrono::Utc::now();
    // C#：(Hour << 24) | (Minute << 16) | (Second << 8) | (Millisecond / 10)
    let t = (now.hour() << 24)
        | (now.minute() << 16)
        | (now.second() << 8)
        | (now.timestamp_subsec_millis() / 10);
    let mut probe = Vec::with_capacity(12);
    probe.extend_from_slice(&ANSWER_MAGIC.to_be_bytes());
    probe.extend_from_slice(&t.to_be_bytes());
    probe.extend_from_slice(&REQUEST_MAGIC.to_be_bytes());
    probe
}

pub struct Bosch {
    socks: SocketSet,
}

impl Default for Bosch {
    fn default() -> Self {
        Self {
            socks: SocketSet::new(),
        }
    }
}

impl ScanEngine for Bosch {
    fn name(&self) -> &str {
        "Bosch"
    }
    fn used_ports(&self) -> &[u16] {
        &[ANSWER_PORT]
    }
    fn color(&self) -> u32 {
        0xff0000 // Color.Red
    }

    fn listen(&self, ctx: std::sync::Arc<EngineContext>) -> crate::Result<Vec<JoinHandle<()>>> {
        let ifaces = crate::iface::active_interfaces();
        let nic_ips: Vec<std::net::Ipv4Addr> = ifaces.iter().flat_map(|i| i.ipv4_addrs()).collect();
        // recv_loop 只调用 parse()（纯函数），用新实例即可，无需自引用。
        let e: std::sync::Arc<dyn ScanEngine> = std::sync::Arc::new(Self::default());
        let mut handles = Vec::new();
        // C# listenUdpGlobal(answerPort)：G 绑**监听端口** 1758
        if let Some((gsock, gsync)) = crate::net::udp_bind_global(
            ANSWER_PORT,
            ctx.config.port_sharing,
            &ctx.logger,
            ctx.task_id,
        )? {
            self.socks.add(gsync);
            handles.push(tokio::spawn(crate::net::recv_loop(
                ctx.clone(),
                std::sync::Arc::clone(&e),
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
                std::sync::Arc::clone(&e),
                isock,
            )));
        }
        Ok(handles)
    }

    fn scan(&self, ctx: &EngineContext) -> crate::Result<()> {
        // C# Bosch.scan：sendBroadcast(requestPort)——发往**探测端口** 1757（与监听 1758 不同）
        let probe = build_probe();
        let failed = self.socks.send_broadcast(REQUEST_PORT, &probe);
        if failed > 0 {
            ctx.logger
                .warn(ctx.task_id, &format!("{} Bosch sends failed", failed));
        }
        Ok(())
    }

    fn parse(&self, from: SocketAddr, data: &[u8]) -> Vec<Device> {
        // C# reciever：包长恰等于二进制应答结构体大小 → 二进制分支，否则 XML 分支
        if data.len() == BINARY_ANSWER_SIZE {
            // C# bigEndian32(binary.magic)（LE 平台 = swap）== 0x9939a427，不符丢弃
            let magic = u32::from_le_bytes([data[0], data[1], data[2], data[3]]).swap_bytes();
            if magic != ANSWER_MAGIC {
                return Vec::new();
            }
            // C# littleEndian32 在 LE 平台是恒等：LE 读出后按 new IPAddress 的
            // **网络序**语义取 ip（C# quirk，照抄；二进制分支无 0 回退）
            let ip_raw = u32::from_le_bytes([data[0x10], data[0x11], data[0x12], data[0x13]]);
            let b = ip_raw.to_be_bytes();
            let serial = format!(
                "{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
                data[0x08], data[0x09], data[0x0A], data[0x0B], data[0x0C], data[0x0D]
            );
            return vec![Device {
                mac: serial.clone(),
                protocol: "Bosch".into(),
                version: 1,
                ip: std::net::IpAddr::V4(std::net::Ipv4Addr::new(b[0], b[1], b[2], b[3])),
                device_type: "Bosch".into(),
                serial,
            }];
        }
        // XML 分支（C# 各正则均为 `<Tag>([^<]*)</Tag>` 手工提取）
        let xml = String::from_utf8_lossy(data).into_owned();
        let device_model = extract_xml_string(&xml, "friendlyName").unwrap_or_default();
        let device_serial = extract_xml_string(&xml, "serialNumber")
            .or_else(|| extract_xml_string(&xml, "physAddress"))
            .unwrap_or_default();
        let mac = extract_xml_string(&xml, "physAddress")
            .map(|m| crate::devices::normalize_mac(&m))
            .unwrap_or_default();
        let ipv4_str = extract_xml_string(&xml, "unitIPAddress").unwrap_or_default();
        let ipv6_str = extract_xml_string(&xml, "unitIPv6Address").unwrap_or_default();
        // C# IPAddress.TryParse 接受 v4/v6；失败 → from（warn 由 T48 侧记）
        let ip = ipv4_str
            .parse::<std::net::IpAddr>()
            .unwrap_or_else(|_| from.ip());
        let mut devs = vec![Device {
            mac: mac.clone(),
            protocol: "Bosch".into(),
            version: 2,
            ip,
            device_type: device_model.clone(),
            serial: device_serial.clone(),
        }];
        // IPv6 解析成功 → 另报一条（version 2）
        if let Ok(ip6) = ipv6_str.parse::<std::net::IpAddr>() {
            devs.push(Device {
                mac,
                protocol: "Bosch".into(),
                version: 2,
                ip: ip6,
                device_type: device_model,
                serial: device_serial,
            });
        }
        devs
    }
}

/// C# 正则 `<{tag}>([^<]*)</{tag}>` 的手工等价（内容不含 '<'，开标签后紧跟 `</tag>`）。
fn extract_xml_string(xml: &str, tag: &str) -> Option<String> {
    let open = format!("<{tag}>");
    let close = format!("</{tag}>");
    let mut cursor = 0usize;
    while let Some(off) = xml[cursor..].find(&open) {
        let start = cursor + off + open.len();
        // 开标签后无 '<' → 无任何闭合候选，直接无匹配
        let rel = xml[start..].find('<')?;
        let end = start + rel;
        if xml[end..].starts_with(&close) {
            return Some(xml[start..end].to_string());
        }
        cursor = start;
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;

    /// 按 C# BoschBinaryAnswer 布局构造 32B 包：magic、transactionID、MAC@0x08、ipv4@0x10。
    fn binary(magic_wire: [u8; 4], mac: [u8; 6], ip_wire: [u8; 4]) -> Vec<u8> {
        let mut d = vec![0u8; BINARY_ANSWER_SIZE];
        d[0x00..0x04].copy_from_slice(&magic_wire);
        d[0x08..0x0E].copy_from_slice(&mac);
        d[0x10..0x14].copy_from_slice(&ip_wire);
        d
    }

    #[test]
    fn binary_packet_reports_v1() {
        // 结构体 LE 读出 0xC0A80164（wire 64 01 A8 C0）→ new IPAddress 网络序 → 192.168.1.100
        let from: SocketAddr = "240.0.7.0:1024".parse().unwrap();
        let devs = Bosch::default().parse(
            from,
            &binary(
                [0x99, 0x39, 0xA4, 0x27],
                [0, 0x11, 0x22, 0x33, 0x44, 0x55],
                [0x64, 0x01, 0xA8, 0xC0],
            ),
        );
        assert_eq!(devs.len(), 1);
        assert_eq!(devs[0].protocol, "Bosch");
        assert_eq!(devs[0].version, 1);
        assert_eq!(devs[0].ip, "192.168.1.100".parse::<IpAddr>().unwrap());
        assert_eq!(devs[0].mac, "00:11:22:33:44:55");
        assert_eq!(devs[0].device_type, "Bosch");
        assert_eq!(devs[0].serial, "00:11:22:33:44:55");
    }

    #[test]
    fn binary_wrong_magic_discarded() {
        let from: SocketAddr = "240.0.7.0:1024".parse().unwrap();
        assert!(Bosch::default()
            .parse(from, &binary([0x00, 0x00, 0x00, 0x00], [0; 6], [0; 4]))
            .is_empty());
    }

    #[test]
    fn xml_packet_reports_v2() {
        let xml = b"<?xml version=\"1.0\"?><root><friendlyName>Cam (XML)</friendlyName><serialNumber>SN-99</serialNumber><physAddress>aa-bb-cc-dd-ee-ff</physAddress><unitIPAddress>192.168.9.9</unitIPAddress></root>";
        let from: SocketAddr = "240.0.7.0:1024".parse().unwrap();
        let devs = Bosch::default().parse(from, xml);
        assert_eq!(devs.len(), 1);
        assert_eq!(devs[0].protocol, "Bosch");
        assert_eq!(devs[0].version, 2);
        assert_eq!(devs[0].ip, "192.168.9.9".parse::<IpAddr>().unwrap());
        assert_eq!(devs[0].mac, "AA:BB:CC:DD:EE:FF");
        assert_eq!(devs[0].device_type, "Cam (XML)");
        assert_eq!(devs[0].serial, "SN-99");
    }

    #[tokio::test]
    async fn fixture_replay_bin() {
        let data = tokio::fs::read(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/Bosch.bin.selftest"
        ))
        .await
        .unwrap();
        let from: SocketAddr = "240.0.7.0:1024".parse().unwrap();
        let devs = Bosch::default().parse(from, &data);
        // 期望值：对照 C# Bosch.reciever 规则手工核定后填入（注释出处：Bosch.cs reciever 二进制分支/BoschBinaryAnswer）
        // C# Bosch.reciever 二进制分支：littleEndian32(ipv4)→0.7.0.240（LE quirk），deviceType=name="Bosch"，version 1
        assert_eq!(devs.len(), 1);
        assert_eq!(devs[0].protocol, "Bosch");
        assert_eq!(devs[0].version, 1);
        assert_eq!(devs[0].ip.to_string(), "0.7.0.240");
        assert_eq!(devs[0].mac, "00:11:22:33:44:55");
        assert_eq!(devs[0].device_type, "Bosch");
        assert_eq!(devs[0].serial, "00:11:22:33:44:55");
    }

    #[tokio::test]
    async fn fixture_replay_xml() {
        let data = tokio::fs::read(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/Bosch.xml.selftest"
        ))
        .await
        .unwrap();
        let from: SocketAddr = "240.0.7.0:1024".parse().unwrap();
        let devs = Bosch::default().parse(from, &data);
        // 期望值：对照 C# Bosch.reciever 规则手工核定后填入（注释出处：Bosch.cs reciever XML 分支）
        // C# Bosch.reciever XML 分支：version 2；IPv4(240.0.7.1)+IPv6(fe80::1) 两条
        assert_eq!(devs.len(), 2);
        assert_eq!(devs[0].protocol, "Bosch");
        assert_eq!(devs[0].version, 2);
        assert_eq!(devs[0].ip.to_string(), "240.0.7.1");
        assert_eq!(devs[0].mac, "00:11:22:33:44:55");
        assert_eq!(devs[0].device_type, "Virtual (XML)");
        assert_eq!(devs[0].serial, "12345678:12345678");
        assert_eq!(devs[1].protocol, "Bosch");
        assert_eq!(devs[1].version, 2);
        assert_eq!(devs[1].ip.to_string(), "fe80::1");
        assert_eq!(devs[1].device_type, "Virtual (XML)");
        assert_eq!(devs[1].serial, "12345678:12345678");
    }
}
