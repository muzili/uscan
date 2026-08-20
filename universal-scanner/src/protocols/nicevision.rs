//! NiceVision 引擎（T33）：12 字节 'NICE' 探测（transactionId 自增），
//! 定长 0x5A parse（含 `new IPAddress(UInt32)` 字节翻转 quirk），对齐 C# NiceVision。

use crate::devices::Device;
use crate::engine::{EngineContext, ScanEngine};
use crate::net::SocketSet;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicU16, Ordering};
use std::sync::Arc;
use tokio::task::JoinHandle;

const REQUEST_PORT: u16 = 2007; // C# requestPort：探测目的端口
const ANSWER_SIZE: usize = 0x5A; // C# NiceVisionAnswer 结构体大小
const PROBE_SIZE: usize = 0x0C; // C# NiceVisionRequest 结构体大小（answerPort 在 0x0C 之外不发送）

/// C# sender()：'NICE' magic BE + transactionId BE + payload 0x01080000 BE + 2B gap（0x0A-0x0B）。
/// transactionId 自增（C# 构造为 0，sender 先 ++ 再用 → 首次为 1）。
fn build_probe(tx: u16) -> [u8; PROBE_SIZE] {
    let mut probe = [0u8; PROBE_SIZE];
    probe[0x00..0x04].copy_from_slice(&0x4E494345u32.to_be_bytes()); // 'NICE'
    probe[0x04..0x06].copy_from_slice(&tx.to_be_bytes());
    probe[0x06..0x0A].copy_from_slice(&0x01080000u32.to_be_bytes()); // payload
                                                                     // probe[0x0A..0x0C] 保持 0（C# 结构体 gap，未覆盖字段）
    probe
}

pub struct NiceVision {
    socks: SocketSet,
    transaction_id: AtomicU16,
}

impl Default for NiceVision {
    fn default() -> Self {
        Self {
            socks: SocketSet::new(),
            transaction_id: AtomicU16::new(0),
        }
    }
}

impl ScanEngine for NiceVision {
    fn name(&self) -> &str {
        "NiceVision"
    }
    fn used_ports(&self) -> &[u16] {
        &[] // C# getUsedPort 为空：无固定端口预占
    }
    fn color(&self) -> u32 {
        0x32948E // C# 裸字面量 0x0032948E → 低 24 位
    }

    fn listen(&self, ctx: Arc<EngineContext>) -> crate::Result<Vec<JoinHandle<()>>> {
        let ifaces = crate::iface::active_interfaces();
        let nic_ips: Vec<Ipv4Addr> = ifaces.iter().flat_map(|i| i.ipv4_addrs()).collect();
        // recv_loop 只调用 parse()（纯函数），用新实例即可，无需自引用。
        let e: Arc<dyn ScanEngine> = Arc::new(Self::default());
        let mut handles = Vec::new();
        // C# listenUdpGlobal()（无参）：G 绑 PortProvider 的 free_port（answerPort 不发送）
        match ctx.ports.lock().unwrap().free_port() {
            Some(p) => {
                if let Some((gsock, gsync)) = crate::net::udp_bind_global(
                    p,
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
            }
            None => {
                ctx.logger
                    .warn(ctx.task_id, "no free port; skipping global socket");
            }
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
        // C# NiceVision.scan：transactionId++ 后 sendBroadcast(requestPort)
        // wrapping：C# UInt16 回绕（0xFFFF→0），debug 构建不得 panic
        let tx = self
            .transaction_id
            .fetch_add(1, Ordering::SeqCst)
            .wrapping_add(1);
        let probe = build_probe(tx);
        let failed = self.socks.send_broadcast(REQUEST_PORT, &probe);
        if failed > 0 {
            ctx.logger
                .warn(ctx.task_id, &format!("{} NiceVision sends failed", failed));
        }
        Ok(())
    }

    fn parse(&self, _from: SocketAddr, data: &[u8]) -> Vec<Device> {
        // C# reciever：定长 0x5A 结构体（不校验 magic）；短包跳过
        //（C# GetStruct 对短包返回 default 全零结构体，此处按定长语义直接丢弃）
        if data.len() < ANSWER_SIZE {
            return Vec::new();
        }
        // MAC@0x0A → serial（C# MacAddress.ToString()：大写冒号格式）
        let serial = format!(
            "{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
            data[0x0A], data[0x0B], data[0x0C], data[0x0D], data[0x0E], data[0x0F]
        );
        // C# quirk（照抄）：ipv4@0x10 LE 读出后 new IPAddress(UInt32) 按**网络序**
        // 解释 → 等价于包内 4 字节整体翻转（wire C0 A8 01 05 → 5.1.168.192）；
        // 4 字节恒成 IPv4，无 from 回退
        let ip_raw = u32::from_le_bytes([data[0x10], data[0x11], data[0x12], data[0x13]]);
        let ip = Ipv4Addr::from(ip_raw.to_be_bytes());
        // name[16]@0x4A：首个 NUL 截断的 UTF-8 → model（C# MemoryUtils.GetString）
        let device_type = cstring(&data[0x4A..0x5A]);
        vec![Device {
            protocol: "NiceVision".into(),
            version: 1,
            ip: std::net::IpAddr::V4(ip),
            device_type,
            serial,
        }]
    }
}

/// C# 定长串语义：首个 NUL 截断（全零/首字节 NUL → ""）。
fn cstring(bytes: &[u8]) -> String {
    let len = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    String::from_utf8_lossy(&bytes[..len]).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nicevision_ip_quirk_reverses_octets() {
        let mut d = vec![0u8; 0x5A];
        d[0x0A..0x10].copy_from_slice(&[0, 0x11, 0x22, 0x33, 0x44, 0x55]);
        d[0x10..0x14].copy_from_slice(&[0xC0, 0xA8, 0x01, 0x05]); // 包内网络序 192.168.1.5
        d[0x4A..0x50].copy_from_slice(b"NV-900"); // 余 0x50..0x5A 保持 NUL（C# NUL 截断）
        let from: SocketAddr = "240.0.14.0:1024".parse().unwrap();
        let devs = NiceVision::default().parse(from, &d);
        assert_eq!(devs.len(), 1);
        assert_eq!(devs[0].protocol, "NiceVision");
        assert_eq!(devs[0].version, 1);
        assert_eq!(devs[0].serial, "00:11:22:33:44:55");
        assert_eq!(devs[0].ip.to_string(), "5.1.168.192"); // quirk：字节翻转
        assert_eq!(devs[0].device_type, "NV-900");
    }

    #[test]
    fn short_packet_skipped() {
        // 89 字节（< 0x5A）→ 跳过
        let d = vec![0u8; 0x5A - 1];
        let from: SocketAddr = "240.0.14.0:1024".parse().unwrap();
        assert!(NiceVision::default().parse(from, &d).is_empty());
    }

    #[tokio::test]
    async fn fixture_replay() {
        let data = tokio::fs::read(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/NiceVision.selftest"
        ))
        .await
        .unwrap();
        let from: SocketAddr = "240.0.14.0:1024".parse().unwrap();
        let devs = NiceVision::default().parse(from, &data);
        // 期望值：对照 C# NiceVision.reciever 规则手工核定后填入（注释出处：NiceVision.cs reciever/NiceVisionAnswer）；
        // 注意 ip 按 `new IPAddress(UInt32)` 字节翻转 quirk 核定
        assert!(
            !devs.is_empty(),
            "NiceVision fixture should yield >=1 device"
        );
        // TODO(T50): 填入完整 (protocol, version, ip, type, serial) 断言
    }
}
