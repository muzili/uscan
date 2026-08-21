//! TVT 摄像机发现引擎（registry id 31，逆向自实机抓包 tvt.pcapng，无 C# 对应物）。
//!
//! 协议（"MHED"，UDP 23456）：
//! - probe（140B）：`"MHED" + 09 00 01 00 01` + 零填充 → 组播 234.55.55.55:23456；
//! - 应答/心跳（240B）：`"MHED" + 08 00 01 00 02 00 00 00` + 设备信息 → 组播 234.55.55.56:23456
//!   （实机应答发往探测组的**下一个**地址 .56，故两个组都需 join）：
//!   deviceType@0x0C（C 串）、MAC@0x20、IP@0x28、掩码@0x2C、网关@0x30（均网络序）、
//!   序列号@0x8C（12B C 串）、固件@0x9C、deviceType2@0xC4、厂商分类@0xD4（"Customer"）。

use crate::devices::Device;
use crate::engine::{EngineContext, ScanEngine};
use crate::net::SocketSet;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use tokio::task::JoinHandle;

/// 端口与组播组（set-IP 设置协议 `crate::tvt_provision` 共用）。
pub(crate) const PORT: u16 = 23456;
pub(crate) const PROBE_GROUP: Ipv4Addr = Ipv4Addr::new(234, 55, 55, 55);
/// 实机应答组（探测组 +1）
const ANSWER_GROUP: Ipv4Addr = Ipv4Addr::new(234, 55, 55, 56);
const PROBE_LEN: usize = 140;
const ANSWER_MIN_LEN: usize = 152; // 覆盖到序列号字段（0x8C + 12）

/// 消息类型（LE32@8）：1=探测，2=应答/心跳，3=set-IP 设置。
const OFF_MSG_TYPE: usize = 8;
const MSG_TYPE_PROBE: u8 = 0x01;
const MSG_TYPE_ANSWER: u8 = 0x02;
const OFF_TYPE1: usize = 0x0C;
/// MAC/IP/掩码/网关偏移（set-IP 设置报文同布局，`crate::tvt_provision` 复用）。
pub(crate) const OFF_MAC: usize = 0x20;
pub(crate) const OFF_IP: usize = 0x28;
pub(crate) const OFF_MASK: usize = 0x2c;
pub(crate) const OFF_GATEWAY: usize = 0x30;
const OFF_SERIAL: usize = 0x8C;
const OFF_TYPE2: usize = 0xC4;

/// C 串（首个 NUL 截断）。
fn cstring(bytes: &[u8]) -> String {
    let len = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    String::from_utf8_lossy(&bytes[..len]).into_owned()
}

/// 140B 探测帧：`"MHED" + 09 00 01 00 01` + 零填充（抓包逐字节）。
fn build_probe() -> [u8; PROBE_LEN] {
    let mut p = [0u8; PROBE_LEN];
    p[0..4].copy_from_slice(b"MHED");
    p[4] = 0x09; // 版本 LE32 = 0x00010009（实机探测版本，比应答的 0x00010008 高 1）
    p[6] = 0x01;
    p[OFF_MSG_TYPE] = MSG_TYPE_PROBE;
    p
}

/// 应答帧（测试用）：240B，与实机布局一致。
#[cfg(test)]
fn build_answer(ip: Ipv4Addr, mac: [u8; 6], serial: &str, dev_type: &str) -> [u8; 240] {
    let mut a = [0u8; 240];
    a[0..4].copy_from_slice(b"MHED");
    a[4] = 0x08; // 版本 LE32 = 0x00010008（实机应答版本）
    a[6] = 0x01;
    a[OFF_MSG_TYPE] = MSG_TYPE_ANSWER;
    a[OFF_TYPE1..OFF_TYPE1 + dev_type.len()].copy_from_slice(dev_type.as_bytes());
    a[OFF_MAC..OFF_MAC + 6].copy_from_slice(&mac);
    a[OFF_IP..OFF_IP + 4].copy_from_slice(&ip.octets());
    a[OFF_MASK..OFF_MASK + 4].copy_from_slice(&[255, 255, 255, 0]); // 掩码
    a[OFF_GATEWAY..OFF_GATEWAY + 4].copy_from_slice(&[192, 168, 0, 1]); // 网关
    let s = serial.as_bytes();
    a[OFF_SERIAL..OFF_SERIAL + s.len().min(12)].copy_from_slice(&s[..s.len().min(12)]);
    a
}

pub struct Tvt {
    socks: SocketSet,
}

impl Default for Tvt {
    fn default() -> Self {
        Self {
            socks: SocketSet::new(),
        }
    }
}

impl ScanEngine for Tvt {
    fn name(&self) -> &str {
        "TVT"
    }
    fn used_ports(&self) -> &[u16] {
        &[PORT]
    }
    fn color(&self) -> u32 {
        0x9932CC // DarkOrchid（自选）
    }

    fn listen(&self, ctx: Arc<EngineContext>) -> crate::Result<Vec<JoinHandle<()>>> {
        let ifaces = crate::iface::active_interfaces();
        let nic_ips: Vec<Ipv4Addr> = ifaces.iter().flat_map(|i| i.ipv4_addrs()).collect();
        // recv_loop 只调用 parse()（纯函数），用新实例即可，无需自引用。
        let e: Arc<dyn ScanEngine> = Arc::new(Self::default());
        let mut handles = Vec::new();
        // 实机应答发往 234.55.55.56，保险起见两个组都 join
        for group in [PROBE_GROUP, ANSWER_GROUP] {
            let (msock, msync) =
                crate::net::udp_bind_multicast(group, PORT, &nic_ips, &ctx.logger, ctx.task_id)?;
            self.socks.add(msync);
            handles.push(tokio::spawn(crate::net::recv_loop(
                ctx.clone(),
                Arc::clone(&e),
                msock,
            )));
        }
        // 每网卡接口 socket（回退接收路径）
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
        // 抓包观测：仅组播 234.55.55.55:23456
        let probe = build_probe();
        let failed = self.socks.send_multicast(PROBE_GROUP, PORT, &probe);
        if failed > 0 {
            ctx.logger
                .warn(ctx.task_id, &format!("{} TVT sends failed", failed));
        }
        Ok(())
    }

    fn parse(&self, from: SocketAddr, data: &[u8]) -> Vec<Device> {
        // 长度须覆盖到序列号字段；magic / 版本（0x08）/ 消息类型（LE32@8==2 应答）不符 → 丢弃
        if data.len() < ANSWER_MIN_LEN
            || &data[0..4] != b"MHED"
            || data[4] != 0x08
            || data[OFF_MSG_TYPE..OFF_MSG_TYPE + 4] != [MSG_TYPE_ANSWER, 0, 0, 0]
        {
            return Vec::new();
        }
        // IP@0x28 网络序直读；0.0.0.0 → 回退 from
        let ip_bytes = [
            data[OFF_IP],
            data[OFF_IP + 1],
            data[OFF_IP + 2],
            data[OFF_IP + 3],
        ];
        let ip: IpAddr = if ip_bytes == [0, 0, 0, 0] {
            from.ip()
        } else {
            IpAddr::V4(Ipv4Addr::from(ip_bytes))
        };
        // 设备类型：主字段为空 → 备用字段
        let device_type = {
            let t1 = cstring(&data[OFF_TYPE1..OFF_TYPE1 + 8]);
            if data.len() >= OFF_TYPE2 + 8 && t1.is_empty() {
                cstring(&data[OFF_TYPE2..OFF_TYPE2 + 8])
            } else {
                t1
            }
        };
        // MAC 大写冒号格式（序列号为空时也用作回退）
        let mac = format!(
            "{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
            data[OFF_MAC],
            data[OFF_MAC + 1],
            data[OFF_MAC + 2],
            data[OFF_MAC + 3],
            data[OFF_MAC + 4],
            data[OFF_MAC + 5]
        );
        let serial = {
            let s = cstring(&data[OFF_SERIAL..OFF_SERIAL + 12]);
            if s.is_empty() {
                mac.clone()
            } else {
                s
            }
        };
        vec![Device {
            mac,
            protocol: "TVT".into(),
            version: 1,
            ip,
            device_type,
            serial,
        }]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;

    #[test]
    fn probe_bytes_pinned() {
        let p = build_probe();
        assert_eq!(p.len(), 140);
        assert_eq!(&p[0..9], b"MHED\x09\x00\x01\x00\x01");
        assert!(p[9..].iter().all(|&b| b == 0));
    }

    #[test]
    fn answer_parsed() {
        let a = build_answer(
            "192.168.0.88".parse().unwrap(),
            [0x00, 0x18, 0xAE, 0x9B, 0xE2, 0x80],
            "IE280042L467",
            "IPC",
        );
        let from: SocketAddr = "240.0.31.0:1024".parse().unwrap();
        let devs = Tvt::default().parse(from, &a);
        assert_eq!(devs.len(), 1);
        assert_eq!(devs[0].protocol, "TVT");
        assert_eq!(devs[0].version, 1);
        assert_eq!(devs[0].ip, "192.168.0.88".parse::<IpAddr>().unwrap());
        assert_eq!(devs[0].mac, "00:18:AE:9B:E2:80");
        assert_eq!(devs[0].device_type, "IPC");
        assert_eq!(devs[0].serial, "IE280042L467");
    }

    #[test]
    fn zero_ip_falls_back_to_from() {
        let mut a = build_answer("0.0.0.0".parse().unwrap(), [0; 6], "SN1", "IPC");
        a[OFF_IP] = 0;
        let from: SocketAddr = "240.0.31.0:1024".parse().unwrap();
        let devs = Tvt::default().parse(from, &a);
        assert_eq!(devs.len(), 1);
        assert_eq!(devs[0].ip, from.ip());
    }

    #[test]
    fn empty_serial_falls_back_to_mac() {
        let a = build_answer(
            "10.0.0.9".parse().unwrap(),
            [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF],
            "",
            "IPC",
        );
        let from: SocketAddr = "240.0.31.0:1024".parse().unwrap();
        let devs = Tvt::default().parse(from, &a);
        assert_eq!(devs[0].serial, "AA:BB:CC:DD:EE:FF");
        assert_eq!(devs[0].mac, "AA:BB:CC:DD:EE:FF");
    }

    #[test]
    fn bad_packets_discarded() {
        let from: SocketAddr = "240.0.31.0:1024".parse().unwrap();
        // 短包 / 错 magic / 探测帧（0x09）回显 → 空
        assert!(Tvt::default().parse(from, &build_probe()).is_empty());
        let mut a = build_answer("1.2.3.4".parse().unwrap(), [0; 6], "SN", "IPC");
        a[0] = b'X';
        assert!(Tvt::default().parse(from, &a).is_empty());
        assert!(Tvt::default().parse(from, &a[..100]).is_empty());
    }

    #[tokio::test]
    async fn fixture_replay() {
        let data = tokio::fs::read(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/TVT.selftest"
        ))
        .await
        .unwrap();
        let from: SocketAddr = "240.0.31.0:1024".parse().unwrap();
        let devs = Tvt::default().parse(from, &data);
        // 期望值：脱敏合成 fixture（IP→240.0.31.0、序列号→Virtual-1234、类型 IPC）
        assert_eq!(devs.len(), 1);
        assert_eq!(devs[0].protocol, "TVT");
        assert_eq!(devs[0].ip, "240.0.31.0".parse::<IpAddr>().unwrap());
        assert_eq!(devs[0].mac, "00:11:22:33:44:55");
        assert_eq!(devs[0].device_type, "IPC");
        assert_eq!(devs[0].serial, "Virtual-1234");
    }
}
