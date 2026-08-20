//! Ubiquiti 引擎（T36）：4B LE 版本探测 + 0x0206 BE 头 / LE 类型 TLV 应答，
//! 逐行对齐 C# Ubiquiti.reciever（含"magic 不匹配仅 warn"的 parity 保留）。

use crate::devices::Device;
use crate::engine::{EngineContext, ScanEngine};
use crate::net::SocketSet;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use tokio::task::JoinHandle;

const PORT: u16 = 10001; // C# port
const MULTICAST_GROUP: Ipv4Addr = Ipv4Addr::new(233, 89, 188, 1); // C# multicastIP
const REQUEST_VERSION: u32 = 1; // C# requestVersion
const HEADER_SIZE: usize = 4; // C# UbiquitiHeader 结构体大小（magic 0x0206 仅 warn，不校验）

const TLV_TYPE_NULL: u16 = 0x0000; // C# typeNull
const TLV_MAC1: u16 = 0x0001; // C# macAddress1（实际 6 字节）
const TLV_MAC_IPV4: u16 = 0x0002; // C# macIPv4（10 字节：MAC+IP）
const TLV_MODEL1: u16 = 0x000C; // C# model1
const TLV_MODEL2: u16 = 0x0015; // C# model2
const TLV_MAC2: u16 = 0x0013; // C# macAddress2（实际 6 字节）

/// C# sender()：littleEndian32(requestVersion)，共 4B。
fn build_probe() -> [u8; 4] {
    REQUEST_VERSION.to_le_bytes()
}

pub struct Ubiquiti {
    socks: SocketSet,
}

impl Default for Ubiquiti {
    fn default() -> Self {
        Self {
            socks: SocketSet::new(),
        }
    }
}

impl ScanEngine for Ubiquiti {
    fn name(&self) -> &str {
        "Ubiquiti"
    }
    fn used_ports(&self) -> &[u16] {
        &[PORT]
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
        // C# listenUdpGlobal(port)：G 绑 10001（C# 不 join 组播组，此处同样不 join）
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
        // C# Ubiquiti.scan：sendMulticast(233.89.188.1, 10001) + sendBroadcast(10001)
        let probe = build_probe();
        let mut failed = self.socks.send_multicast(MULTICAST_GROUP, PORT, &probe);
        failed += self.socks.send_broadcast(PORT, &probe);
        if failed > 0 {
            ctx.logger
                .warn(ctx.task_id, &format!("{} Ubiquiti sends failed", failed));
        }
        Ok(())
    }

    fn parse(&self, from: SocketAddr, data: &[u8]) -> Vec<Device> {
        // C# reciever：len < 4 → warn+丢弃（纯函数不记日志）
        if data.len() < HEADER_SIZE {
            return Vec::new();
        }
        // C#：magic(0x0206) 不匹配**仅 warn 不丢弃**（C# 注释 "not enough tested ...
        // disabling return"；纯函数不记日志，故此处不校验）
        // C#：packetSize BE ≠ len-4 → warn+丢弃
        let packet_size = u16::from_be_bytes([data[2], data[3]]) as usize;
        if packet_size != data.len() - HEADER_SIZE {
            return Vec::new();
        }
        let mut pos = HEADER_SIZE;
        let mut mac: Option<[u8; 6]> = None;
        let mut ip: Option<Ipv4Addr> = None;
        let mut model: Option<String> = None;
        while pos < data.len() {
            // C# readNextValue：头部截断（position+3 >= len）→ 返回 type 0x0000
            if pos + 3 >= data.len() {
                return Vec::new();
            }
            // C# vtype = data[pos] | (data[pos+1] << 8) → LE16
            let vtype = u16::from_le_bytes([data[pos], data[pos + 1]]);
            let size = data[pos + 2] as usize;
            pos += 3;
            // C# readNextValue：值截断（position+size > len）→ 返回 type 0x0000
            if pos + size > data.len() {
                return Vec::new();
            }
            let value = &data[pos..pos + size];
            pos += size;
            match vtype {
                // C# typeNull → warn+丢弃整包
                TLV_TYPE_NULL => return Vec::new(),
                // C#：size ≠ 6 → warn+跳过（不取用）；首个 mac 生效
                TLV_MAC1 | TLV_MAC2 if value.len() == 6 && mac.is_none() => {
                    mac = Some([value[0], value[1], value[2], value[3], value[4], value[5]]);
                }
                // C#：size ≠ 10 → warn+跳过；前 6 = MAC、后 4 = IP（首个生效）
                TLV_MAC_IPV4 if value.len() == 10 => {
                    if mac.is_none() {
                        mac = Some([value[0], value[1], value[2], value[3], value[4], value[5]]);
                    }
                    if ip.is_none() {
                        // C# new IPAddress(byte[4])：4 字节直接按网络序，无翻转
                        ip = Some(Ipv4Addr::new(value[6], value[7], value[8], value[9]));
                    }
                }
                // C#：model == "" 时取 UTF8(value)（空值不覆盖，首个非空生效）
                TLV_MODEL1 | TLV_MODEL2 if model.is_none() && !value.is_empty() => {
                    model = Some(String::from_utf8_lossy(value).into_owned());
                }
                _ => {}
            }
        }
        // C#：无 mac 不上报（IPv4 恒有值：无则回退 from）
        let Some(mac) = mac else {
            return Vec::new();
        };
        // C#：MAC 大写冒号格式（String.Format "{0:X2}"）
        let serial = format!(
            "{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
            mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
        );
        // C#：model 缺省 "unknown"
        let device_type = model.unwrap_or_else(|| "unknown".to_string());
        // C#：无 macIPv4 的 IP → from.Address（v4/v6 均按原样）
        let ip = ip.map(std::net::IpAddr::V4).unwrap_or_else(|| from.ip());
        vec![Device {
            protocol: "Ubiquiti".into(),
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

    fn ubt_frame(body: &[u8], magic: u16) -> Vec<u8> {
        let mut d = vec![0u8; 4];
        d[0..2].copy_from_slice(&magic.to_be_bytes());
        d[2..4].copy_from_slice(&((body.len() + 4) as u16 - 4).to_be_bytes()); // packetSize = len-4
        d.extend_from_slice(body);
        d
    }

    #[test]
    fn ubiquiti_mac_and_ip() {
        let mut body = Vec::new();
        body.extend_from_slice(&0x0001u16.to_le_bytes());
        body.push(6);
        body.extend_from_slice(&[0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);
        let f = ubt_frame(&body, 0x0206);
        let from: SocketAddr = "240.0.12.0:1024".parse().unwrap();
        let devs = Ubiquiti::default().parse(from, &f);
        assert_eq!(devs.len(), 1);
        assert_eq!(devs[0].protocol, "Ubiquiti");
        assert_eq!(devs[0].version, 1);
        // C# String.Format("{0:X2}") → 大写（plan 测试的小写断言与 C# 不符，按 C# 核定）
        assert_eq!(devs[0].serial, "AA:BB:CC:DD:EE:FF");
        assert_eq!(devs[0].ip, "240.0.12.0".parse::<IpAddr>().unwrap()); // 无 macIPv4 → from
        assert_eq!(devs[0].device_type, "unknown");
    }

    #[test]
    fn ubiquiti_zero_type_drops_whole() {
        // 含 type 0x0000 TLV → 整包丢弃（即使 mac 在前）
        let mut body = Vec::new();
        body.extend_from_slice(&0x0001u16.to_le_bytes());
        body.push(6);
        body.extend_from_slice(&[0; 6]);
        body.extend_from_slice(&0x0000u16.to_le_bytes());
        body.push(0);
        let f = ubt_frame(&body, 0x0206);
        let from: SocketAddr = "240.0.12.0:1024".parse().unwrap();
        assert!(Ubiquiti::default().parse(from, &f).is_empty());
    }

    #[test]
    fn ubiquiti_bad_packetsize_dropped() {
        // packetSize 错误 → 空
        let mut body = Vec::new();
        body.extend_from_slice(&0x0001u16.to_le_bytes());
        body.push(6);
        body.extend_from_slice(&[0; 6]);
        let mut f = ubt_frame(&body, 0x0206);
        f[2] = f[2].wrapping_add(1); // 破坏 packetSize
        let from: SocketAddr = "240.0.12.0:1024".parse().unwrap();
        assert!(Ubiquiti::default().parse(from, &f).is_empty());
    }

    #[test]
    fn ubiquiti_bad_magic_warn_only() {
        // magic=0x0205 → C# 仅 warn 不丢弃（"insufficient testing" parity）→ 仍上报
        let mut body = Vec::new();
        body.extend_from_slice(&0x0001u16.to_le_bytes());
        body.push(6);
        body.extend_from_slice(&[0; 6]);
        let f = ubt_frame(&body, 0x0205);
        let from: SocketAddr = "240.0.12.0:1024".parse().unwrap();
        assert_eq!(Ubiquiti::default().parse(from, &f).len(), 1);
    }

    #[test]
    fn ubiquiti_mac_ipv4_and_models() {
        // macIPv4(0x0002, 10B)：前 6 MAC、后 4 IP（网络序直接构造）；
        // model1 先于 model2 生效（首个生效）
        let mut body = Vec::new();
        body.extend_from_slice(&0x0002u16.to_le_bytes());
        body.push(10);
        body.extend_from_slice(&[0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);
        body.extend_from_slice(&[192, 168, 1, 77]);
        body.extend_from_slice(&0x0015u16.to_le_bytes());
        body.push(3);
        body.extend_from_slice(b"UAP"); // model2（model1 缺省时生效）
        let f = ubt_frame(&body, 0x0206);
        let from: SocketAddr = "240.0.12.0:1024".parse().unwrap();
        let devs = Ubiquiti::default().parse(from, &f);
        assert_eq!(devs.len(), 1);
        assert_eq!(devs[0].ip, "192.168.1.77".parse::<IpAddr>().unwrap());
        assert_eq!(devs[0].serial, "AA:BB:CC:DD:EE:FF");
        assert_eq!(devs[0].device_type, "UAP");
    }

    #[test]
    fn ubiquiti_mac_from_mac_ipv4_only() {
        // 无 0x0001/0x0013 mac TLV：mac 取自 macIPv4 前 6 字节（C# 语义）→ 仍上报
        let mut body = Vec::new();
        body.extend_from_slice(&0x0002u16.to_le_bytes());
        body.push(10);
        body.extend_from_slice(&[0; 6]);
        body.extend_from_slice(&[10, 0, 0, 1]);
        let f = ubt_frame(&body, 0x0206);
        let from: SocketAddr = "240.0.12.0:1024".parse().unwrap();
        let devs = Ubiquiti::default().parse(from, &f);
        assert_eq!(devs.len(), 1);
        assert_eq!(devs[0].serial, "00:00:00:00:00:00");
        assert_eq!(devs[0].ip, "10.0.0.1".parse::<IpAddr>().unwrap());
    }

    #[tokio::test]
    async fn fixture_replay() {
        let data = tokio::fs::read(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/Ubiquiti.selftest"
        ))
        .await
        .unwrap();
        let from: SocketAddr = "240.0.12.0:1024".parse().unwrap();
        let devs = Ubiquiti::default().parse(from, &data);
        // 期望值：对照 C# Ubiquiti.reciever/readNextValue 规则手工核定后填入（注释出处：Ubiquiti.cs reciever）
        assert!(!devs.is_empty(), "Ubiquiti fixture should yield >=1 device");
        // TODO(T50): 填入完整 (protocol, version, ip, type, serial) 断言
    }
}
