//! GigEVision 引擎（T23）：parse 按 C# GigEVisionAckn 结构体偏移读取，probe 对齐 sender()。

use crate::devices::Device;
use crate::engine::{EngineContext, ScanEngine};
use crate::net::SocketSet;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicU32, Ordering};
use tokio::task::JoinHandle;

const PORT: u16 = 3956;
const ACKN_SIZE: usize = 0x100; // C# GigEVisionAckn 结构体大小（256B）

pub struct GigEVision {
    socks: SocketSet,
    /// C# requestCounter（UInt16 前置自增，从 0 起）；u32 存储、取低 16 位。
    request_counter: AtomicU32,
}

impl Default for GigEVision {
    fn default() -> Self {
        Self {
            socks: SocketSet::new(),
            request_counter: AtomicU32::new(0),
        }
    }
}

impl ScanEngine for GigEVision {
    fn name(&self) -> &str {
        "GigEVision"
    }
    fn used_ports(&self) -> &[u16] {
        &[PORT] // C# getUsedPort() = {3956}（注释 "not mandatory"，但 Scanner 仍预占）
    }
    fn color(&self) -> u32 {
        0xff0000 // Color.Red
    }

    fn listen(&self, ctx: std::sync::Arc<EngineContext>) -> crate::Result<Vec<JoinHandle<()>>> {
        let ifaces = crate::iface::active_interfaces();
        let nic_ips: Vec<Ipv4Addr> = ifaces.iter().flat_map(|i| i.ipv4_addrs()).collect();
        // recv_loop 只调用 parse()（纯函数），用新实例即可，无需自引用。
        let e: std::sync::Arc<dyn ScanEngine> = std::sync::Arc::new(Self::default());
        let mut handles = Vec::new();
        // C# GigEVision.listen：仅 listenUdpInterfaces()（无 global/multicast）
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
        // C# sender：requestCounter++（前置自增，0 起 → 首个探测 requestId=1）；
        // 8B 请求：42 11 | cmd=0x0002（线上 BE）| payloadLen=0 | requestId（线上 LE）。
        let id = (self.request_counter.fetch_add(1, Ordering::Relaxed) + 1) & 0xFFFF;
        let probe = [
            0x42u8,
            0x11,
            0x00,
            0x02,
            0x00,
            0x00,
            (id & 0xFF) as u8,
            (id >> 8) as u8,
        ];
        // C# GigEVision.scan：仅 sendBroadcast(3956)
        let failed = self.socks.send_broadcast(PORT, &probe);
        if failed > 0 {
            ctx.logger
                .warn(ctx.task_id, &format!("{} GigEVision sends failed", failed));
        }
        Ok(())
    }

    fn parse(&self, from: SocketAddr, data: &[u8]) -> Vec<Device> {
        // C# reciever：包长必须恰 256B
        if data.len() != ACKN_SIZE {
            return Vec::new();
        }
        // C# 结构体 LE 读 + NetworkToHostOrder16（LE 平台 swap）≡ wire 按 BE 读
        let payload_len = u16::from_be_bytes([data[4], data[5]]);
        if payload_len != (data.len() - 8) as u16 {
            return Vec::new();
        }
        // C# version 字段 ≠ 0x00010002 仅 warn 不丢弃 → parse 纯函数直接继续
        let _version = (u16::from_be_bytes([data[8], data[9]]) as u32) << 16
            | u16::from_be_bytes([data[0x0A], data[0x0B]]) as u32;
        // plIPCurrentAddr：结构体 LE 读出后按 new IPAddress 的**网络序**语义取 ip（C# quirk，照抄）
        let ip_raw = u32::from_le_bytes([data[0x2C], data[0x2D], data[0x2E], data[0x2F]]);
        let ip = if ip_raw != 0 {
            let b = ip_raw.to_be_bytes();
            std::net::IpAddr::V4(std::net::Ipv4Addr::new(b[0], b[1], b[2], b[3]))
        } else {
            from.ip()
        };
        let mac = format!(
            "{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
            data[0x12], data[0x13], data[0x14], data[0x15], data[0x16], data[0x17]
        );
        let mut serial = cstring(&data[0xE0..0xF0]); // plSerialNumber
        if serial.is_empty() {
            serial = mac.clone();
        }
        let mut vendor = cstring(&data[0x50..0x70]); // plManufacturer
        if vendor.is_empty() {
            vendor = "GigEVision".into();
        }
        let mut model = cstring(&data[0x70..0x90]); // plModel
        if model.is_empty() {
            model = cstring(&data[0xF0..0x100]); // 回退 plUsername
        }
        vec![Device {
            mac,
            protocol: vendor,
            version: 0,
            ip,
            device_type: model,
            serial,
        }]
    }
}

/// C# MemoryUtils.GetString（结构体扩展）：首个 NUL 截断，首字节 NUL → ""。
fn cstring(bytes: &[u8]) -> String {
    let len = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    String::from_utf8_lossy(&bytes[..len]).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;

    #[test]
    fn size_255_discarded() {
        let from: SocketAddr = "240.0.17.0:1024".parse().unwrap();
        assert!(GigEVision::default().parse(from, &[0u8; 255]).is_empty());
    }

    #[test]
    fn size_257_discarded() {
        let from: SocketAddr = "240.0.17.0:1024".parse().unwrap();
        assert!(GigEVision::default().parse(from, &[0u8; 257]).is_empty());
    }

    #[test]
    fn all_zero_payload_len_discarded() {
        // C# 校验 payloadLen == len-8：全零 256B 包 payloadLen=0 ≠ 248 → 丢弃
        let from: SocketAddr = "240.0.17.0:1024".parse().unwrap();
        assert!(GigEVision::default().parse(from, &[0u8; 256]).is_empty());
    }

    #[test]
    fn zero_ip_falls_back_to_from() {
        let mut data = vec![0u8; ACKN_SIZE];
        data[4..6].copy_from_slice(&248u16.to_be_bytes()); // payloadLen = 256-8
        let from: SocketAddr = "240.0.17.0:1024".parse().unwrap();
        let devs = GigEVision::default().parse(from, &data);
        assert_eq!(devs.len(), 1);
        assert_eq!(devs[0].protocol, "GigEVision"); // 厂商空 → 回退
        assert_eq!(devs[0].version, 0);
        assert_eq!(devs[0].ip, from.ip());
        assert_eq!(devs[0].mac, "00:00:00:00:00:00");
        assert_eq!(devs[0].serial, "00:00:00:00:00:00"); // serial 空 → MAC
        assert_eq!(devs[0].device_type, ""); // model/username 均空
    }

    #[test]
    fn full_fields_reported() {
        let mut data = vec![0u8; ACKN_SIZE];
        data[4..6].copy_from_slice(&248u16.to_be_bytes()); // payloadLen
        data[8..10].copy_from_slice(&1u16.to_be_bytes()); // plMajorVersion
        data[10..12].copy_from_slice(&2u16.to_be_bytes()); // plMinorVersion
        data[0x12..0x18].copy_from_slice(&[0x11, 0x22, 0x33, 0x44, 0x55, 0x66]); // MAC
                                                                                 // plIPCurrentAddr：结构体 LE 读出 0xC0A80709（wire 09 07 A8 C0）
                                                                                 // → C# new IPAddress 按网络序解释 → 192.168.7.9
        data[0x2C..0x30].copy_from_slice(&0xC0A80709u32.to_le_bytes());
        data[0x50..0x54].copy_from_slice(b"GigA"); // plManufacturer
        data[0x70..0x72].copy_from_slice(b"M1"); // plModel
        data[0xE0..0xE4].copy_from_slice(b"S123"); // plSerialNumber
        let from: SocketAddr = "240.0.17.0:1024".parse().unwrap();
        let devs = GigEVision::default().parse(from, &data);
        assert_eq!(devs.len(), 1);
        assert_eq!(devs[0].protocol, "GigA"); // protocol 列 = 厂商名
        assert_eq!(devs[0].version, 0);
        assert_eq!(devs[0].ip, "192.168.7.9".parse::<IpAddr>().unwrap());
        assert_eq!(devs[0].mac, "11:22:33:44:55:66");
        assert_eq!(devs[0].device_type, "M1");
        assert_eq!(devs[0].serial, "S123");
    }

    #[tokio::test]
    async fn fixture_replay() {
        let data = tokio::fs::read(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/GigEVision.selftest"
        ))
        .await
        .unwrap();
        let from: SocketAddr = "240.0.17.0:1024".parse().unwrap();
        let devs = GigEVision::default().parse(from, &data);
        // 期望值：对照 C# GigEVision.reciever 规则手工核定后填入（注释出处：GigEVision.cs reciever/GigEVisionAckn）
        // C# GigEVision.reciever：new IPAddress(plIPCurrentAddr)（long 网络序）→0.17.0.240 反转；version 0（vendor 名）
        assert_eq!(devs.len(), 1);
        assert_eq!(devs[0].protocol, "GigEVision");
        assert_eq!(devs[0].version, 0);
        assert_eq!(devs[0].ip.to_string(), "0.17.0.240");
        assert_eq!(devs[0].mac, "00:11:22:33:44:55");
        assert_eq!(devs[0].device_type, "Virtual device");
        assert_eq!(devs[0].serial, "123456789");
    }
}
