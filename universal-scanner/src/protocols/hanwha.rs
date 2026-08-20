//! Hanwha 引擎（T29）：0x106 定长结构体 parse（短包零填充 = C# GetStruct 语义），
//! 监听 7711 / 探测 7701（Bosch 式 listen/probe 端口分离）。

use crate::devices::Device;
use crate::engine::{EngineContext, ScanEngine};
use crate::net::SocketSet;
use std::net::{Ipv4Addr, SocketAddr};
use tokio::task::JoinHandle;

const ANSWER_PORT: u16 = 7711; // C# answerPort：global 监听端口
const REQUEST_PORT: u16 = 7701; // C# requestPort：探测目的端口
const HEADER_SIZE: usize = 0x106; // C# HanwhaHeader 结构体大小
const MAC_OFF: usize = 0x13; // C# mac_address（String18bytes）
const IP_OFF: usize = 0x25; // C# ip_address（String16bytes）
const TYPE_OFF: usize = 0x6D; // C# device_type（String10bytes）

/// C# sender()：HanwhaHeader 结构体，仅 packet_type=0x01（request），其余全零。
fn build_probe() -> Vec<u8> {
    let mut probe = vec![0u8; HEADER_SIZE];
    probe[0] = 0x01; // C# packet_type_request
    probe
}

pub struct Hanwha {
    socks: SocketSet,
}

impl Default for Hanwha {
    fn default() -> Self {
        Self {
            socks: SocketSet::new(),
        }
    }
}

impl ScanEngine for Hanwha {
    fn name(&self) -> &str {
        "Hanwha"
    }
    fn used_ports(&self) -> &[u16] {
        &[ANSWER_PORT]
    }
    fn color(&self) -> u32 {
        0xff8c00 // Color.DarkOrange
    }

    fn listen(&self, ctx: std::sync::Arc<EngineContext>) -> crate::Result<Vec<JoinHandle<()>>> {
        let ifaces = crate::iface::active_interfaces();
        let nic_ips: Vec<Ipv4Addr> = ifaces.iter().flat_map(|i| i.ipv4_addrs()).collect();
        // recv_loop 只调用 parse()（纯函数），用新实例即可，无需自引用。
        let e: std::sync::Arc<dyn ScanEngine> = std::sync::Arc::new(Self::default());
        let mut handles = Vec::new();
        // C# listenUdpGlobal(answerPort)：G 绑**监听端口** 7711
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
        // C# Hanwha.scan：sendBroadcast(requestPort)——发往**探测端口** 7701（与监听 7711 不同）
        let probe = build_probe();
        let failed = self.socks.send_broadcast(REQUEST_PORT, &probe);
        if failed > 0 {
            ctx.logger
                .warn(ctx.task_id, &format!("{} Hanwha sends failed", failed));
        }
        Ok(())
    }

    fn parse(&self, from: SocketAddr, data: &[u8]) -> Vec<Device> {
        // C# reciever 无长度校验：短包经 GetStruct 得全零结构体（Marshal.Copy 越界 → default）
        let serial = cstring(&struct_field(data, MAC_OFF, 18)); // C# mac_address
        let ip_str = cstring(&struct_field(data, IP_OFF, 16)); // C# ip_address
        let device_type = cstring(&struct_field(data, TYPE_OFF, 10)); // C# device_type
                                                                      // C#：IPAddress.TryParse 失败 → ip = from.Address（warn 由 T48 侧记）
        let ip = ip_str
            .parse::<std::net::IpAddr>()
            .unwrap_or_else(|_| from.ip());
        vec![Device {
            protocol: "Hanwha".into(),
            version: 1,
            ip,
            device_type,
            serial,
        }]
    }
}

/// C# GetStruct 的短包语义：包长不足时越界部分按 0 填充。
fn struct_field(data: &[u8], off: usize, len: usize) -> Vec<u8> {
    let mut out = vec![0u8; len];
    if off < data.len() {
        let end = std::cmp::min(off + len, data.len());
        out[..end - off].copy_from_slice(&data[off..end]);
    }
    out
}

/// C# MemoryUtils.GetString（结构体扩展）：首个 NUL 截断，全零/首字节 NUL → ""。
fn cstring(bytes: &[u8]) -> String {
    let len = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    String::from_utf8_lossy(&bytes[..len]).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 按 C# HanwhaHeader 布局构造 0x106 应答：packet_type=0x0b（reply）、
    /// mac@0x13、ip@0x25、device_type@0x6D（均 NUL 结尾定长串）。
    fn build(ip: &str, mac: &str, device_type: &str) -> Vec<u8> {
        let mut d = vec![0u8; HEADER_SIZE];
        d[0] = 0x0b; // C# packet_type_reply
        let m = mac.as_bytes();
        d[MAC_OFF..MAC_OFF + m.len()].copy_from_slice(m);
        let i = ip.as_bytes();
        d[IP_OFF..IP_OFF + i.len()].copy_from_slice(i);
        let t = device_type.as_bytes();
        d[TYPE_OFF..TYPE_OFF + t.len()].copy_from_slice(t);
        d
    }

    #[test]
    fn normal_packet_full_tuple() {
        let from: SocketAddr = "240.0.9.0:1024".parse().unwrap();
        let devs = Hanwha::default().parse(
            from,
            &build("192.168.1.50", "00:11:22:33:44:55", "Hanwha cam"),
        );
        assert_eq!(devs.len(), 1);
        assert_eq!(devs[0].protocol, "Hanwha");
        assert_eq!(devs[0].version, 1);
        assert_eq!(
            devs[0].ip,
            "192.168.1.50".parse::<std::net::IpAddr>().unwrap()
        );
        assert_eq!(devs[0].device_type, "Hanwha cam");
        assert_eq!(devs[0].serial, "00:11:22:33:44:55");
    }

    #[test]
    fn invalid_ip_string_falls_back_to_from() {
        // C#：IPAddress.TryParse 失败 → ip = from.Address（+ warn，T48 侧记）
        let from: SocketAddr = "240.0.9.0:1024".parse().unwrap();
        let devs =
            Hanwha::default().parse(from, &build("999.999.999.999", "00:11:22:33:44:55", "Cam"));
        assert_eq!(devs.len(), 1);
        assert_eq!(devs[0].ip, from.ip());
        assert_eq!(devs[0].serial, "00:11:22:33:44:55");
    }

    #[test]
    fn short_packet_zero_padded() {
        // C# GetStruct 对短包抛异常 → default（全零）结构体 → ip 串空 → TryParse 失败 → from
        let from: SocketAddr = "240.0.9.0:1024".parse().unwrap();
        let devs = Hanwha::default().parse(from, &[0x0b, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        assert_eq!(devs.len(), 1);
        assert_eq!(devs[0].ip, from.ip());
        assert_eq!(devs[0].device_type, "");
        assert_eq!(devs[0].serial, "");
    }

    #[tokio::test]
    async fn fixture_replay() {
        let data = tokio::fs::read(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/Hanwha.selftest"
        ))
        .await
        .unwrap();
        let from: SocketAddr = "240.0.9.0:1024".parse().unwrap();
        let devs = Hanwha::default().parse(from, &data);
        // 期望值：对照 C# Hanwha.reciever 规则手工核定后填入（注释出处：Hanwha.cs reciever/HanwhaHeader）
        assert!(!devs.is_empty(), "Hanwha fixture should yield >=1 device");
        // TODO(T50): 填入完整 (protocol, version, ip, type, serial) 断言
    }
}
