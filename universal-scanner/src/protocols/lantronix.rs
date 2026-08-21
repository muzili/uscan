//! Lantronix 引擎（T30，worked example 2）：parse 逐行对齐 C# Lantronix.reciever，
//! 含 Vauban/VaubanOld 分支与"条件不满足落穿"控制流。

use crate::devices::Device;
use crate::engine::{EngineContext, ScanEngine};
use crate::net::SocketSet;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::task::JoinHandle;

const PORT: u16 = 30718;
const PROBE: [u8; 4] = [0x00, 0x00, 0x00, 0xF6]; // C# discover[]
const ANSWER_LEN: usize = 0x1E;
const MSG_REPLY: u8 = 0xF7;
const MAGIC_VAUBAN: u8 = 0x15;
const MAGIC_VAUBAN_OLD: u8 = 0x13;

pub struct Lantronix {
    socks: SocketSet,
}

impl Default for Lantronix {
    fn default() -> Self {
        Self {
            socks: SocketSet::new(),
        }
    }
}

impl ScanEngine for Lantronix {
    fn name(&self) -> &str {
        "Lantronix"
    }
    fn used_ports(&self) -> &[u16] {
        &[PORT]
    }
    fn color(&self) -> u32 {
        0xFFA500 // Color.DarkOrange
    }

    fn listen(&self, ctx: Arc<EngineContext>) -> crate::Result<Vec<JoinHandle<()>>> {
        let ifaces = crate::iface::active_interfaces();
        let nic_ips: Vec<std::net::Ipv4Addr> = ifaces.iter().flat_map(|i| i.ipv4_addrs()).collect();
        // recv_loop 只调用 parse()（纯函数），用新实例即可，无需自引用。
        let e: Arc<dyn ScanEngine> = Arc::new(Self::default());
        let mut handles = Vec::new();
        // C# listenUdpGlobal(port)：G 绑监听端口 30718
        if let Some((gsock, gsync)) =
            crate::net::udp_bind_global(PORT, ctx.config.port_sharing, &ctx.logger, ctx.task_id)?
        {
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
        // C# Lantronix.scan：sendBroadcast(port)
        let failed = self.socks.send_broadcast(PORT, &PROBE);
        if failed > 0 {
            ctx.logger
                .warn(ctx.task_id, &format!("{} Lantronix sends failed", failed));
        }
        Ok(())
    }

    fn parse(&self, from: SocketAddr, data: &[u8]) -> Vec<Device> {
        // C# reciever：长度须恰 0x1E（LantronixAnswer 结构体大小），不符静默丢弃
        if data.len() != ANSWER_LEN {
            return Vec::new();
        }
        // C#：messageType(data[3]) 须 0xF7（reply），不符 warn 后丢弃
        if data[3] != MSG_REPLY {
            return Vec::new();
        }
        // MAC = data[0x18..0x1E]，大写冒号格式 → serial
        let serial = format!(
            "{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
            data[0x18], data[0x19], data[0x1A], data[0x1B], data[0x1C], data[0x1D]
        );
        // VaubanPayload 自 0x04：modelMajor=绝对 0x0C，modelMinor=绝对 0x0D
        match data[2] {
            MAGIC_VAUBAN => {
                let (major, minor) = (data[0x0C], data[0x0D]);
                if major == 2 && minor < 10 {
                    let mut model = String::from("Verso+");
                    // C# 内层 major switch 是死代码（major 恒 2）；minor 2/4 加后缀
                    match minor {
                        2 => model.push_str(" 2"),
                        4 => model.push_str(" 4"),
                        _ => {}
                    }
                    return vec![Device {
                        mac: serial.clone(),
                        protocol: "Vauban".into(),
                        version: 1,
                        ip: from.ip(),
                        device_type: model,
                        serial,
                    }];
                }
                // 条件不满足 → 落穿（C# if 无 else-return）
            }
            MAGIC_VAUBAN_OLD => {
                return vec![Device {
                    mac: serial.clone(),
                    protocol: "Vauban".into(),
                    version: 1,
                    ip: from.ip(),
                    device_type: "unknown".into(),
                    serial,
                }];
            }
            _ => {}
        }
        vec![Device {
            mac: serial.clone(),
            protocol: "Lantronix".into(),
            version: 1,
            ip: from.ip(),
            device_type: "unknown".into(),
            serial,
        }]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn frame(byte03: u8, msg: u8, major: u8, minor: u8) -> Vec<u8> {
        let mut d = vec![0u8; 0x1E];
        d[2] = byte03;
        d[3] = msg;
        d[0x0C] = major; // VaubanPayload.modelMajor（payload 偏移 0x08，绝对 0x0C）
        d[0x0D] = minor; // VaubanPayload.modelMinor
        d[0x18..].copy_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
        d
    }

    #[test]
    fn lantronix_fixture() {
        // 00 00 00 f7 … mac 00:11:22:33:44:55；_byte_03=0x00 → Lantronix/unknown
        let data = include_bytes!("../../tests/fixtures/Lantronix.selftest");
        let from: SocketAddr = "240.0.23.0:1024".parse().unwrap();
        let devs = Lantronix::default().parse(from, data);
        assert_eq!(devs.len(), 1);
        assert_eq!(
            (
                devs[0].protocol.as_str(),
                devs[0].version,
                devs[0].device_type.as_str()
            ),
            ("Lantronix", 1, "unknown")
        );
        assert_eq!(devs[0].serial, "00:11:22:33:44:55");
        assert_eq!(devs[0].mac, "00:11:22:33:44:55");
        assert_eq!(devs[0].ip.to_string(), "240.0.23.0");
    }

    #[test]
    fn vauban_fixture_minor4() {
        // _byte_03=0x15, major=2, minor=4 → Vauban / "Verso+ 4"
        let data = include_bytes!("../../tests/fixtures/Vauban.selftest");
        let from: SocketAddr = "240.0.23.1:1024".parse().unwrap();
        let devs = Lantronix::default().parse(from, data);
        assert_eq!(devs.len(), 1);
        assert_eq!(
            (devs[0].protocol.as_str(), devs[0].device_type.as_str()),
            ("Vauban", "Verso+ 4")
        );
        assert_eq!(devs[0].serial, "00:11:22:33:44:55");
        assert_eq!(devs[0].mac, "00:11:22:33:44:55");
    }

    #[test]
    fn wrong_length_dropped() {
        let from: SocketAddr = "240.0.23.0:1024".parse().unwrap();
        let d = frame(0x00, 0xF7, 0, 0);
        assert!(Lantronix::default().parse(from, &d[..0x1D]).is_empty());
    }

    #[test]
    fn wrong_message_type_dropped() {
        let from: SocketAddr = "240.0.23.0:1024".parse().unwrap();
        assert!(Lantronix::default()
            .parse(from, &frame(0x00, 0xF6, 0, 0))
            .is_empty());
    }

    #[test]
    fn vauban_old() {
        let from: SocketAddr = "240.0.23.0:1024".parse().unwrap();
        let devs = Lantronix::default().parse(from, &frame(0x13, 0xF7, 0, 0));
        assert_eq!(
            (devs[0].protocol.as_str(), devs[0].device_type.as_str()),
            ("Vauban", "unknown")
        );
    }

    #[test]
    fn vauban_minor2_and_4_names() {
        let from: SocketAddr = "240.0.23.0:1024".parse().unwrap();
        let p = Lantronix::default();
        assert_eq!(
            p.parse(from, &frame(0x15, 0xF7, 2, 2))[0].device_type,
            "Verso+ 2"
        );
        assert_eq!(
            p.parse(from, &frame(0x15, 0xF7, 2, 5))[0].device_type,
            "Verso+"
        );
    }

    #[test]
    fn vauban_major_mismatch_falls_through() {
        // _byte_03=0x15 但 major=3 → 落穿到 Lantronix/unknown（C# 控制流）
        let from: SocketAddr = "240.0.23.0:1024".parse().unwrap();
        let devs = Lantronix::default().parse(from, &frame(0x15, 0xF7, 3, 0));
        assert_eq!(devs[0].protocol, "Lantronix");
    }
}
