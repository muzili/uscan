//! VStarcam 引擎（T40）：4B requestMagic 探测 + 0x100 定长头应答，逐行对齐 C# Vstarcam.reciever。

use crate::devices::Device;
use crate::engine::{EngineContext, ScanEngine};
use crate::net::SocketSet;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use tokio::task::JoinHandle;

const PORT: u16 = 8600; // C# port
const ANSWER_MAGIC: u32 = 0x44480108; // C# answerMagic（包内 BE）
const HEADER_SIZE: usize = 0x100; // C# VSCAnswerHeader 结构体大小
const IP_OFF: usize = 0x04; // C# String16bytes ip
const SERIAL_OFF: usize = 0x5C; // C# String32bytes serial
const NAME_OFF: usize = 0x7C; // C# String32bytes name

/// C# sender()：HostToNetworkOrder32(0x44480101) + BitConverter（双翻转正，
/// 净效果 = 网络序字节）。
fn build_probe() -> [u8; 4] {
    [0x44, 0x48, 0x01, 0x01]
}

pub struct Vstarcam {
    socks: SocketSet,
}

impl Default for Vstarcam {
    fn default() -> Self {
        Self {
            socks: SocketSet::new(),
        }
    }
}

impl ScanEngine for Vstarcam {
    fn name(&self) -> &str {
        "VStarcam"
    }
    fn used_ports(&self) -> &[u16] {
        &[PORT] // C# getUsedPort：预占 8600
    }
    fn color(&self) -> u32 {
        0x00008B // Color.DarkBlue.ToArgb() → 低 24 位
    }

    fn listen(&self, ctx: Arc<EngineContext>) -> crate::Result<Vec<JoinHandle<()>>> {
        let ifaces = crate::iface::active_interfaces();
        let nic_ips: Vec<Ipv4Addr> = ifaces.iter().flat_map(|i| i.ipv4_addrs()).collect();
        // recv_loop 只调用 parse()（纯函数），用新实例即可，无需自引用。
        let e: Arc<dyn ScanEngine> = Arc::new(Self::default());
        let mut handles = Vec::new();
        // C# listenUdpGlobal(port)：G 绑 8600
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
        // C# Vstarcam.scan：sendBroadcast(port) 8600
        let probe = build_probe();
        let failed = self.socks.send_broadcast(PORT, &probe);
        if failed > 0 {
            ctx.logger
                .warn(ctx.task_id, &format!("{} VStarcam sends failed", failed));
        }
        Ok(())
    }

    fn parse(&self, from: SocketAddr, data: &[u8]) -> Vec<Device> {
        // C# reciever：包长 < 0x100 → warn+丢弃（纯函数不记日志）
        if data.len() < HEADER_SIZE {
            return Vec::new();
        }
        // C# answerMagic（BE @0x00）不符 → warn+丢弃
        let magic = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
        if magic != ANSWER_MAGIC {
            return Vec::new();
        }
        // C# MemoryUtils.GetString（结构体扩展）：首个 NUL 截断，全零/首字节 NUL → ""
        //（12B mac 字段 @0x54 C# 不使用，跳过）
        let model = cstring(&data[NAME_OFF..NAME_OFF + 32]);
        let serial = cstring(&data[SERIAL_OFF..SERIAL_OFF + 32]);
        // C# IPAddress.TryParse 失败 → from.Address（**仍上报**）。
        // 注：C# TryParse 更宽松（先 trim 空白、接受简写），Rust 严格解析——
        // 极端非标 ip 串的 IP 值可能不同，但两侧仍上报。
        let ip = cstring(&data[IP_OFF..IP_OFF + 16])
            .parse::<IpAddr>()
            .unwrap_or_else(|_| from.ip());
        // C#：version 1
        vec![Device {
            protocol: "VStarcam".into(),
            version: 1,
            ip,
            device_type: model,
            serial,
        }]
    }
}

/// C# MemoryUtils.GetString（结构体扩展）：首个 NUL 截断，全零/首字节 NUL → ""。
fn cstring(bytes: &[u8]) -> String {
    let len = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    String::from_utf8_lossy(&bytes[..len]).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn probe_bytes_pinned() {
        // C# requestMagic 0x44480101 BE → 44 48 01 01
        assert_eq!(build_probe(), [0x44, 0x48, 0x01, 0x01]);
    }

    /// 0x100 定长头应答帧：ip(16B @0x04)、serial(32B @0x5C)、name(32B @0x7C)；
    /// 各字段必须恰为 16/32/32 字节（NUL 填充由调用方给出）。
    fn vstarcam_frame(ip: &[u8; 16], serial: &[u8; 32], name: &[u8; 32]) -> Vec<u8> {
        let mut d = vec![0u8; HEADER_SIZE];
        d[0x00..0x04].copy_from_slice(&ANSWER_MAGIC.to_be_bytes());
        d[IP_OFF..IP_OFF + 16].copy_from_slice(ip);
        d[SERIAL_OFF..SERIAL_OFF + 32].copy_from_slice(serial);
        d[NAME_OFF..NAME_OFF + 32].copy_from_slice(name);
        d
    }

    fn padded<const N: usize>(s: &str) -> [u8; N] {
        let mut a = [0u8; N];
        a[..s.len()].copy_from_slice(s.as_bytes());
        a
    }

    #[test]
    fn vstarcam_short_packet_dropped() {
        // 包长 < 0x100 → warn+丢弃
        let mut f = vec![0u8; 0xFF];
        f[0..4].copy_from_slice(&ANSWER_MAGIC.to_be_bytes());
        let from: SocketAddr = "240.0.18.0:1024".parse().unwrap();
        assert!(Vstarcam::default().parse(from, &f).is_empty());
    }

    #[test]
    fn vstarcam_wrong_magic_dropped() {
        // answerMagic（BE）不符 → warn+丢弃
        let mut f = vec![0u8; HEADER_SIZE];
        f[0..4].copy_from_slice(&0x44480101u32.to_be_bytes());
        let from: SocketAddr = "240.0.18.0:1024".parse().unwrap();
        assert!(Vstarcam::default().parse(from, &f).is_empty());
    }

    #[test]
    fn vstarcam_ip_field_parsed_after_nul_truncation() {
        // ip 串经 NUL 截断后解析成功 → ip = 192.168.1.10
        let f = vstarcam_frame(&padded("192.168.1.10"), &padded("SN-001"), &padded("CamX"));
        let from: SocketAddr = "240.0.18.0:1024".parse().unwrap();
        let devs = Vstarcam::default().parse(from, &f);
        assert_eq!(devs.len(), 1);
        assert_eq!(devs[0].protocol, "VStarcam");
        assert_eq!(devs[0].version, 1);
        assert_eq!(devs[0].ip, "192.168.1.10".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn vstarcam_unparseable_ip_falls_back_to_from() {
        // ip 串（截断后）仍非法 → ip = from，仍上报
        let mut ip = [0u8; 16];
        ip[..8].copy_from_slice(b"1.2.3.4x");
        let f = vstarcam_frame(&ip, &padded("SN-001"), &padded("CamX"));
        let from: SocketAddr = "240.0.18.0:1024".parse().unwrap();
        let devs = Vstarcam::default().parse(from, &f);
        assert_eq!(devs.len(), 1);
        assert_eq!(devs[0].ip, "240.0.18.0".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn vstarcam_nul_truncated_fields() {
        // name/serial 的 NUL 填充经 C# MemoryUtils.GetString 语义截断
        let f = vstarcam_frame(&padded("10.0.0.9"), &padded("SN1"), &padded("Cam"));
        let from: SocketAddr = "240.0.18.0:1024".parse().unwrap();
        let devs = Vstarcam::default().parse(from, &f);
        assert_eq!(devs.len(), 1);
        assert_eq!(devs[0].device_type, "Cam");
        assert_eq!(devs[0].serial, "SN1");
        // 全 NUL 字段 → ""
        let f = vstarcam_frame(&padded("10.0.0.9"), &[0u8; 32], &[0u8; 32]);
        let devs = Vstarcam::default().parse(from, &f);
        assert_eq!(devs[0].device_type, "");
        assert_eq!(devs[0].serial, "");
    }

    #[tokio::test]
    async fn fixture_replay() {
        let data = tokio::fs::read(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/Vstarcam.selftest"
        ))
        .await
        .unwrap();
        let from: SocketAddr = "240.0.18.0:1024".parse().unwrap();
        let devs = Vstarcam::default().parse(from, &data);
        // 期望值：对照 C# Vstarcam.reciever 规则手工核定后填入
        //（注释出处：Vstarcam.cs reciever；ip 字段 NUL 填充 → 两侧均回退 from）
        assert!(!devs.is_empty(), "VStarcam fixture should yield >=1 device");
        // TODO(T50): 填入完整 (protocol, version, ip, type, serial) 断言
    }
}
