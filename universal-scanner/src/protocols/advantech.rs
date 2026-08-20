//! Advantech 引擎（T38）：60B "MADA" 探测 + 0x38 头应答，逐行对齐 C# Advantech.reciever。

use crate::devices::Device;
use crate::engine::{EngineContext, ScanEngine};
use crate::net::SocketSet;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use tokio::task::JoinHandle;

const PORT: u16 = 5048; // C# port
const HEADER_SIZE: usize = 0x38; // C# AdvantechHeader 结构体大小
const MIN_LEN: usize = HEADER_SIZE + 0x32; // C# 外层长度检查（0x6A）
const MSG_PRODUCT_TYPE: u8 = 0x20; // C# MessageType.ProductType

/// C# `request` 字面量：60B，照抄 Advantech.cs（messageType=0x20 @0x35）。
fn build_probe() -> [u8; 60] {
    [
        0x4d, 0x41, 0x44, 0x41, 0x00, 0x00, 0x00, 0x83, 0x01, 0x00, 0x50, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ]
}

pub struct Advantech {
    socks: SocketSet,
}

impl Default for Advantech {
    fn default() -> Self {
        Self {
            socks: SocketSet::new(),
        }
    }
}

impl ScanEngine for Advantech {
    fn name(&self) -> &str {
        "Advantech"
    }
    fn used_ports(&self) -> &[u16] {
        &[] // C# getUsedPort 为空：仅 I，无固定端口预占
    }
    fn color(&self) -> u32 {
        0x008080 // Color.DarkCyan.ToArgb() → 低 24 位
    }

    fn listen(&self, ctx: Arc<EngineContext>) -> crate::Result<Vec<JoinHandle<()>>> {
        let ifaces = crate::iface::active_interfaces();
        let nic_ips: Vec<Ipv4Addr> = ifaces.iter().flat_map(|i| i.ipv4_addrs()).collect();
        // recv_loop 只调用 parse()（纯函数），用新实例即可，无需自引用。
        let e: Arc<dyn ScanEngine> = Arc::new(Self::default());
        let mut handles = Vec::new();
        // C# Advantech.listen：仅 listenUdpInterfaces()（无 global socket）
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
        // C# Advantech.scan：sendBroadcast(port) 5048
        let probe = build_probe();
        let failed = self.socks.send_broadcast(PORT, &probe);
        if failed > 0 {
            ctx.logger
                .warn(ctx.task_id, &format!("{} Advantech sends failed", failed));
        }
        Ok(())
    }

    fn parse(&self, from: SocketAddr, data: &[u8]) -> Vec<Device> {
        // C# reciever：外层长度检查 < 0x6A → 不上报（连非 0x20 消息也不报）
        // C# 不校验 headerMagic（parity：同样不校验）
        if data.len() < MIN_LEN {
            return Vec::new();
        }
        // C# mac @0x0D → MacAddress.ToString() 大写冒号
        let serial = format!(
            "{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
            data[0x0D], data[0x0E], data[0x0F], data[0x10], data[0x11], data[0x12]
        );
        // C# messageType@0x35 == ProductType(0x20) → model = UTF8(data[0x6A..])
        //（lossy、不剥 NUL；否则 "Unknown"）；ip 恒为 from；version 1
        let model = if data[0x35] == MSG_PRODUCT_TYPE {
            String::from_utf8_lossy(&data[MIN_LEN..]).into_owned()
        } else {
            "Unknown".to_string()
        };
        vec![Device {
            protocol: "Advantech".into(),
            version: 1,
            ip: from.ip(),
            device_type: model,
            serial,
        }]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn probe_bytes_pinned() {
        // C# request 字面量逐字节钉死（60B，messageType 0x20 @0x35）
        let p = build_probe();
        assert_eq!(p.len(), 60);
        assert_eq!(
            &p[0..12],
            &[0x4d, 0x41, 0x44, 0x41, 0x00, 0x00, 0x00, 0x83, 0x01, 0x00, 0x50, 0x00]
        );
        assert!(p[12..53].iter().all(|&b| b == 0));
        assert_eq!(p[0x35], 0x20);
        assert!(p[0x36..60].iter().all(|&b| b == 0));
    }
    use std::net::IpAddr;

    /// 构造 0x38 头 + pad 字节填充的应答帧：mac @0x0D、messageType @0x35；
    /// tail 追加于 0x6A 处（C# dataIndex = 0x38 + 0x32），即 model 载荷。
    fn advantech_frame(message_type: u8, mac: [u8; 6], pad: usize, tail: &[u8]) -> Vec<u8> {
        let mut d = vec![0u8; HEADER_SIZE + pad];
        d[0x0D..0x13].copy_from_slice(&mac);
        d[0x35] = message_type;
        d.extend_from_slice(tail);
        d
    }

    #[test]
    fn advantech_short_0x69_dropped() {
        // 0x69 字节（< 0x6A）→ 不上报
        let f = advantech_frame(0x20, [0; 6], 0x31, &[]);
        assert_eq!(f.len(), 0x69);
        let from: SocketAddr = "240.0.25.0:1024".parse().unwrap();
        assert!(Advantech::default().parse(from, &f).is_empty());
    }

    #[test]
    fn advantech_product_type() {
        // 0x6A 字节基帧 + messageType=0x20 + 尾部 "ABCD" → model="ABCD"、serial=mac@0x0D
        let f = advantech_frame(0x20, [0x00, 0x11, 0x22, 0x33, 0x44, 0x55], 0x32, b"ABCD");
        assert_eq!(f.len(), 0x6A + 4);
        let from: SocketAddr = "240.0.25.0:1024".parse().unwrap();
        let devs = Advantech::default().parse(from, &f);
        assert_eq!(devs.len(), 1);
        assert_eq!(devs[0].protocol, "Advantech");
        assert_eq!(devs[0].version, 1);
        assert_eq!(devs[0].ip, "240.0.25.0".parse::<IpAddr>().unwrap());
        assert_eq!(devs[0].device_type, "ABCD");
        assert_eq!(devs[0].serial, "00:11:22:33:44:55");
    }

    #[test]
    fn advantech_non_product_type_still_reported() {
        // messageType≠0x20 → model="Unknown"，但仍上报
        let f = advantech_frame(0x10, [0x00, 0x11, 0x22, 0x33, 0x44, 0x55], 0x32, &[]);
        assert_eq!(f.len(), 0x6A);
        let from: SocketAddr = "240.0.25.0:1024".parse().unwrap();
        let devs = Advantech::default().parse(from, &f);
        assert_eq!(devs.len(), 1);
        assert_eq!(devs[0].device_type, "Unknown");
        assert_eq!(devs[0].serial, "00:11:22:33:44:55");
    }

    #[tokio::test]
    async fn fixture_replay() {
        let data = tokio::fs::read(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/Advantech.selftest"
        ))
        .await
        .unwrap();
        let from: SocketAddr = "240.0.25.0:1024".parse().unwrap();
        let devs = Advantech::default().parse(from, &data);
        // 期望值：对照 C# Advantech.reciever 规则手工核定后填入（注释出处：Advantech.cs reciever）
        assert!(
            !devs.is_empty(),
            "Advantech fixture should yield >=1 device"
        );
        // TODO(T50): 填入完整 (protocol, version, ip, type, serial) 断言
    }
}
