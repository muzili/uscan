//! Vivotek 引擎（T39）：5B session+magic 探测 + TLV 应答，逐行对齐 C# Vivotek.reciever。

use crate::devices::Device;
use crate::engine::{EngineContext, ScanEngine};
use crate::net::SocketSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::Arc;
use tokio::task::JoinHandle;

const PORT: u16 = 10000; // C# port
const MAGIC: u32 = 0x4A5D8F1C; // C# magic（包内 BE）
const HEADER_SIZE: usize = 5; // C# VivotekHeader 结构体大小

const TLV_LONG_NAME: u8 = 0x01; // C# VivotekValue.longName（解析但不使用）
const TLV_MAC: u8 = 0x02; // C# VivotekValue.macAddress
const TLV_IP: u8 = 0x03; // C# VivotekValue.IPAddress
const TLV_TYPE04: u8 = 0x04; // C# VivotekValue._type04（特殊：值 = size 字节本身）
const TLV_SHORT_NAME: u8 = 0x09; // C# VivotekValue.shortName

pub struct Vivotek {
    socks: SocketSet,
    session: AtomicU8, // C# sessionCounter（byte，自 1 起，自增回绕）
}

impl Default for Vivotek {
    fn default() -> Self {
        Self {
            socks: SocketSet::new(),
            session: AtomicU8::new(1),
        }
    }
}

impl Vivotek {
    /// C# sender()：header = new VivotekHeader(sessionCounter++)；
    /// byte++ 回绕 → AtomicU8::fetch_add（wrapping 语义）。
    fn build_probe(&self) -> [u8; 5] {
        let s = self.session.fetch_add(1, Ordering::Relaxed);
        let mut probe = [0u8; 5];
        probe[0] = s;
        probe[1..5].copy_from_slice(&MAGIC.to_be_bytes());
        probe
    }
}

impl ScanEngine for Vivotek {
    fn name(&self) -> &str {
        "Vivotek"
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
        // C# Vivotek.listen：仅 listenUdpInterfaces()（无 global socket）
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
        // C# Vivotek.scan：sendBroadcast(port) 10000
        let probe = self.build_probe();
        let failed = self.socks.send_broadcast(PORT, &probe);
        if failed > 0 {
            ctx.logger
                .warn(ctx.task_id, &format!("{} Vivotek sends failed", failed));
        }
        Ok(())
    }

    fn parse(&self, _from: SocketAddr, data: &[u8]) -> Vec<Device> {
        // C# GetStruct<VivotekHeader> 对 <5B 数据抛异常 → 不上报
        if data.len() < HEADER_SIZE {
            return Vec::new();
        }
        // C# magic（BE）不匹配 → warn+丢弃（纯函数不记日志）
        let magic = u32::from_be_bytes([data[1], data[2], data[3], data[4]]);
        if magic != MAGIC {
            return Vec::new();
        }
        // C#：mac/model 缺省空串、IPv4 缺省 null
        let mut mac = String::new();
        let mut model = String::new();
        let mut ip: Option<IpAddr> = None;
        let mut position = HEADER_SIZE;
        // C# readNextValue：返回 0x00（typeNull 或截断）→ 整包丢弃
        while position < data.len() {
            if position + 2 >= data.len() {
                return Vec::new();
            }
            let vtype = data[position];
            let size = data[position + 1] as usize;
            position += 2;
            // C# type 0x04 特殊：value = size 字节本身（1B），不消耗数据区
            //（该分支在截断检查**之前**，0x04 不触发越界检查）
            if vtype == TLV_TYPE04 {
                continue;
            }
            if position + size > data.len() {
                return Vec::new();
            }
            let value = &data[position..position + size];
            position += size;
            match vtype {
                0x00 => return Vec::new(), // typeNull → 整包丢弃
                TLV_IP => {
                    // C# new IPAddress(value)：仅 4B/16B，其他长度抛异常 → 整包丢弃
                    match value.len() {
                        4 => {
                            ip = Some(IpAddr::V4(Ipv4Addr::new(
                                value[0], value[1], value[2], value[3],
                            )))
                        }
                        16 => {
                            let mut a = [0u8; 16];
                            a.copy_from_slice(value);
                            ip = Some(IpAddr::V6(Ipv6Addr::from(a)))
                        }
                        _ => return Vec::new(),
                    }
                }
                TLV_MAC => {
                    // C# value[0..5] 越界抛异常 → 整包丢弃
                    if value.len() < 6 {
                        return Vec::new();
                    }
                    mac = format!(
                        "{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
                        value[0], value[1], value[2], value[3], value[4], value[5]
                    );
                }
                TLV_SHORT_NAME => model = String::from_utf8_lossy(value).into_owned(),
                // C# case longName：存入 deviceName 但从不使用
                TLV_LONG_NAME => {}
                _ => {} // 其余类型：C# switch 无对应 case
            }
        }
        // C#：有 IP 才上报；version 1
        let Some(ip) = ip else {
            return Vec::new();
        };
        vec![Device {
            protocol: "Vivotek".into(),
            version: 1,
            ip,
            device_type: model,
            serial: mac,
        }]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn probe_bytes_pinned() {
        // C# sender：session=1 起步 + magic 0x4A5D8F1C BE → 01 4A 5D 8F 1C
        assert_eq!(
            Vivotek::default().build_probe(),
            [0x01, 0x4A, 0x5D, 0x8F, 0x1C]
        );
    }

    /// 5B 头（session=1 + magic BE）+ 原始 TLV 字节。
    fn vi_frame(tlv: &[u8]) -> Vec<u8> {
        let mut d = vec![1u8];
        d.extend_from_slice(&MAGIC.to_be_bytes());
        d.extend_from_slice(tlv);
        d
    }

    #[test]
    fn vivotek_full() {
        let mut tlv = Vec::new();
        tlv.extend_from_slice(&[TLV_MAC, 6]);
        tlv.extend_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]); // mac
        tlv.extend_from_slice(&[TLV_IP, 4]);
        tlv.extend_from_slice(&[192, 168, 1, 60]); // IP
        tlv.extend_from_slice(&[TLV_SHORT_NAME, 4]);
        tlv.extend_from_slice(b"V410"); // shortName
        let from: SocketAddr = "240.0.10.0:1024".parse().unwrap();
        let devs = Vivotek::default().parse(from, &vi_frame(&tlv));
        assert_eq!(devs.len(), 1);
        assert_eq!(devs[0].protocol, "Vivotek");
        assert_eq!(devs[0].version, 1);
        assert_eq!(devs[0].ip, "192.168.1.60".parse::<IpAddr>().unwrap());
        assert_eq!(devs[0].device_type, "V410");
        assert_eq!(devs[0].serial, "00:11:22:33:44:55");
    }

    #[test]
    fn vivotek_null_type_drops() {
        // 含 type 0x00 → 整包丢弃
        let tlv = [TLV_LONG_NAME, 2, b'A', b'B', 0x00u8, 2, b'C', b'D'];
        let from: SocketAddr = "240.0.10.0:1024".parse().unwrap();
        assert!(Vivotek::default().parse(from, &vi_frame(&tlv)).is_empty());
    }

    #[test]
    fn vivotek_type04_uses_size_byte() {
        // [0x04, 0x07] → value=0x07，不消耗数据区；后续 TLV 正常解析
        let mut tlv = vec![TLV_TYPE04, 0x07];
        tlv.extend_from_slice(&[TLV_IP, 4]);
        tlv.extend_from_slice(&[10, 0, 0, 1]);
        let from: SocketAddr = "240.0.10.0:1024".parse().unwrap();
        let devs = Vivotek::default().parse(from, &vi_frame(&tlv));
        assert_eq!(devs.len(), 1);
        assert_eq!(devs[0].ip, "10.0.0.1".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn vivotek_no_ip_not_reported() {
        // 只有 mac+name → 无 IP → 不上报
        let mut tlv = Vec::new();
        tlv.extend_from_slice(&[TLV_MAC, 6]);
        tlv.extend_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
        tlv.extend_from_slice(&[TLV_SHORT_NAME, 4]);
        tlv.extend_from_slice(b"V410");
        let from: SocketAddr = "240.0.10.0:1024".parse().unwrap();
        assert!(Vivotek::default().parse(from, &vi_frame(&tlv)).is_empty());
    }

    #[test]
    fn vivotek_short_len_dropped() {
        // 包长 <5 → C# GetStruct 抛异常 → 不上报
        let from: SocketAddr = "240.0.10.0:1024".parse().unwrap();
        assert!(Vivotek::default()
            .parse(from, &[1, 0x4A, 0x5D, 0x8F])
            .is_empty());
    }

    #[test]
    fn vivotek_ip_bad_length_dropped() {
        // IP 值非 4B/16B → C# new IPAddress 抛异常 → 整包丢弃
        let mut tlv = Vec::new();
        tlv.extend_from_slice(&[TLV_IP, 5]);
        tlv.extend_from_slice(&[1, 2, 3, 4, 5]);
        let from: SocketAddr = "240.0.10.0:1024".parse().unwrap();
        assert!(Vivotek::default().parse(from, &vi_frame(&tlv)).is_empty());
    }

    #[test]
    fn vivotek_mac_short_dropped() {
        // mac 值 <6B → C# value[5] 越界抛异常 → 整包丢弃
        let mut tlv = Vec::new();
        tlv.extend_from_slice(&[TLV_MAC, 5]);
        tlv.extend_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44]);
        tlv.extend_from_slice(&[TLV_IP, 4]);
        tlv.extend_from_slice(&[10, 0, 0, 1]);
        let from: SocketAddr = "240.0.10.0:1024".parse().unwrap();
        assert!(Vivotek::default().parse(from, &vi_frame(&tlv)).is_empty());
    }

    #[tokio::test]
    async fn fixture_replay() {
        let data = tokio::fs::read(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/Vivotek.selftest"
        ))
        .await
        .unwrap();
        let from: SocketAddr = "240.0.10.0:1024".parse().unwrap();
        let devs = Vivotek::default().parse(from, &data);
        // 期望值：对照 C# Vivotek.reciever/readNextValue 规则手工核定后填入
        //（注释出处：Vivotek.cs reciever/readNextValue）
        // C# Vivotek.reciever/readNextValue：{0:X2}:... 大写 hex MAC
        assert_eq!(devs.len(), 1);
        assert_eq!(devs[0].protocol, "Vivotek");
        assert_eq!(devs[0].version, 1);
        assert_eq!(devs[0].ip.to_string(), "240.0.10.0");
        assert_eq!(devs[0].device_type, "Virtual");
        assert_eq!(devs[0].serial, "00:11:22:33:44:55");
    }
}
