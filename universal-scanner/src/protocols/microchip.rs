//! Microchip 引擎（T31）：ASCII 文本 parse（GCE 变体），逐行对齐 C# Microchip.reciever。
//! probe 逐字抄 C# sender()（"Discover GCE Devices"）。

use crate::devices::Device;
use crate::engine::{EngineContext, ScanEngine};
use crate::net::SocketSet;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::task::JoinHandle;

const PORT: u16 = 30303;
const PROBE: &str = "Discover GCE Devices"; // C# requestMagic（纯 ASCII）

pub struct Microchip {
    socks: SocketSet,
}

impl Default for Microchip {
    fn default() -> Self {
        Self {
            socks: SocketSet::new(),
        }
    }
}

impl ScanEngine for Microchip {
    fn name(&self) -> &str {
        "Microchip"
    }
    fn used_ports(&self) -> &[u16] {
        &[PORT]
    }
    fn color(&self) -> u32 {
        0xFF0000 // Color.Red
    }

    fn listen(&self, ctx: Arc<EngineContext>) -> crate::Result<Vec<JoinHandle<()>>> {
        let ifaces = crate::iface::active_interfaces();
        let nic_ips: Vec<std::net::Ipv4Addr> = ifaces.iter().flat_map(|i| i.ipv4_addrs()).collect();
        // recv_loop 只调用 parse()（纯函数），用新实例即可，无需自引用。
        let e: Arc<dyn ScanEngine> = Arc::new(Self::default());
        let mut handles = Vec::new();
        // C# listenUdpGlobal(port)：G 绑监听端口 30303
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
        // C# Microchip.scan：sendBroadcast(port)
        let failed = self.socks.send_broadcast(PORT, PROBE.as_bytes());
        if failed > 0 {
            ctx.logger
                .warn(ctx.task_id, &format!("{} Microchip sends failed", failed));
        }
        Ok(())
    }

    fn parse(&self, from: SocketAddr, data: &[u8]) -> Vec<Device> {
        // C# try：Encoding.UTF8.GetString 对非法 UTF-8 抛异常 → catch 置 product="Unknown"
        //（manufacturer 保持 "Microchip"、mac 保持 ""）
        let Ok(text) = std::str::from_utf8(data) else {
            return vec![Device {
                protocol: "Microchip".into(),
                version: 1,
                ip: from.ip(),
                device_type: "Unknown".into(),
                serial: String::new(),
            }];
        };
        // C#：整体等于自身请求串（回显）→ 丢弃
        if text == PROBE {
            return Vec::new();
        }
        // C# Regex.Split(lines_string, "\r\n|\r|\n")：先并 \r\n，再并孤立 \r，按 \n 切分
        let normalized = text.replace("\r\n", "\n").replace('\r', "\n");
        let lines: Vec<&str> = normalized.split('\n').collect();
        // C# 行序：hostname, mac, port, product, other
        let (protocol, device_type, serial) = if lines.len() >= 4 {
            ("GCE", lines[3].trim(), lines[1].trim())
        } else if lines.len() >= 2 {
            ("Microchip", lines[0].trim(), lines[1].trim())
        } else {
            // spec 决定：<2 行不上报（C# 实为无条件上报空 model/serial 的 device）
            return Vec::new();
        };
        vec![Device {
            protocol: protocol.into(),
            version: 1,
            ip: from.ip(),
            device_type: device_type.to_string(),
            serial: serial.to_string(),
        }]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gce_four_lines() {
        // ≥4 行（hostname/mac/port/product）→ GCE，model=第 4 行，serial=第 2 行
        let body = b"hostname\n00-11-22-33-44-55\n80\nVirtual";
        let from: SocketAddr = "240.0.24.0:1024".parse().unwrap();
        let devs = Microchip::default().parse(from, body);
        assert_eq!(devs.len(), 1);
        assert_eq!(devs[0].protocol, "GCE");
        assert_eq!(devs[0].version, 1);
        assert_eq!(devs[0].device_type, "Virtual");
        assert_eq!(devs[0].serial, "00-11-22-33-44-55");
        assert_eq!(devs[0].ip.to_string(), "240.0.24.0");
    }

    #[test]
    fn microchip_two_lines() {
        // ≥2 行 → Microchip，model=第 1 行，serial=第 2 行
        let body = b"Virtual\n00-11-22-33-44-55";
        let from: SocketAddr = "240.0.24.0:1024".parse().unwrap();
        let devs = Microchip::default().parse(from, body);
        assert_eq!(devs.len(), 1);
        assert_eq!(devs[0].protocol, "Microchip");
        assert_eq!(devs[0].version, 1);
        assert_eq!(devs[0].device_type, "Virtual");
        assert_eq!(devs[0].serial, "00-11-22-33-44-55");
        assert_eq!(devs[0].ip.to_string(), "240.0.24.0");
    }

    #[test]
    fn echo_discarded() {
        // 整体等于自身请求串（回显）→ 丢弃
        let from: SocketAddr = "240.0.24.0:1024".parse().unwrap();
        assert!(Microchip::default()
            .parse(from, b"Discover GCE Devices")
            .is_empty());
    }

    #[test]
    fn invalid_utf8_unknown() {
        // C# catch 语义：GetString 对非法 UTF-8 抛异常 → product="Unknown"
        let from: SocketAddr = "240.0.24.0:1024".parse().unwrap();
        let devs = Microchip::default().parse(from, &[0xFF, 0xFE]);
        assert_eq!(devs.len(), 1);
        assert_eq!(devs[0].protocol, "Microchip");
        assert_eq!(devs[0].device_type, "Unknown");
        assert_eq!(devs[0].serial, "");
    }

    #[tokio::test]
    async fn fixture_replay_microchip() {
        let data = tokio::fs::read(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/Microchip.selftest"
        ))
        .await
        .unwrap();
        let from: SocketAddr = "240.0.24.0:1024".parse().unwrap();
        let devs = Microchip::default().parse(from, &data);
        // 期望值：对照 C# Microchip.reciever 规则手工核定后填入（注释出处：Microchip.cs reciever）
        assert!(
            !devs.is_empty(),
            "Microchip fixture should yield >=1 device"
        );
        // TODO(T50): 填入完整 (protocol, version, ip, type, serial) 断言
    }

    #[tokio::test]
    async fn fixture_replay_gce() {
        let data = tokio::fs::read(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/GCE.selftest"
        ))
        .await
        .unwrap();
        let from: SocketAddr = "240.0.24.0:1024".parse().unwrap();
        let devs = Microchip::default().parse(from, &data);
        // 期望值：对照 C# Microchip.reciever 规则手工核定后填入（注释出处：Microchip.cs reciever GCE 分支）
        assert!(!devs.is_empty(), "GCE fixture should yield >=1 device");
        // TODO(T50): 填入完整 (protocol, version, ip, type, serial) 断言
    }
}
