//! CyberPower 引擎（T25）：流式游标 parse 逐行对齐 C# CyberPower.reciever，
//! probe 照发 C# 双重赋值 bug 的实际字节（spec §8.1）。

use crate::devices::Device;
use crate::engine::{EngineContext, ScanEngine};
use crate::net::SocketSet;
use std::net::{Ipv4Addr, SocketAddr};
use tokio::task::JoinHandle;

const PORT: u16 = 53566; // C# port（监听 + 探测同端口）
const ANSWER_MAGIC: u8 = 0x51; // C# answerMagic
                               // C# sender()：result[1]=0x01 被 result[1]=result[2] 覆盖 → 实际发出 [0x11,0x00,0x00]
                               // （spec §8.1 parity 照发）
const PROBE: [u8; 3] = [0x11, 0x00, 0x00];

pub struct CyberPower {
    socks: SocketSet,
}

impl Default for CyberPower {
    fn default() -> Self {
        Self {
            socks: SocketSet::new(),
        }
    }
}

impl ScanEngine for CyberPower {
    fn name(&self) -> &str {
        "CyberPower"
    }
    fn used_ports(&self) -> &[u16] {
        &[PORT]
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
        // C# listenUdpGlobal(port)：被占且 port_sharing 关闭时放弃（Ok(None)）
        if let Some((gsock, gsync)) =
            crate::net::udp_bind_global(PORT, ctx.config.port_sharing, &ctx.logger, ctx.task_id)?
        {
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
        // C# CyberPower.scan：sendBroadcast(53566)
        let failed = self.socks.send_broadcast(PORT, &PROBE);
        if failed > 0 {
            ctx.logger
                .warn(ctx.task_id, &format!("{} CyberPower sends failed", failed));
        }
        Ok(())
    }

    fn parse(&self, _from: SocketAddr, data: &[u8]) -> Vec<Device> {
        match parse_stream(data) {
            Some(dev) => vec![dev],
            None => Vec::new(),
        }
    }
}

/// C# reciever 流式读取；任一读取越界（C# throw → 上层捕获）→ 整包丢弃（None）。
fn parse_stream(data: &[u8]) -> Option<Device> {
    let mut pos = 0usize;
    let magic = read_u8(data, &mut pos)?;
    // C#：magic != ANSWER_MAGIC 仅 warn，仍继续解析并上报
    //（parse 纯函数 → 省略日志，T48 统一接入）
    let _ = magic != ANSWER_MAGIC;
    let key = read_u8(data, &mut pos)?;
    let _hash = read_string(data, &mut pos)?;
    let _uint32_1 = read_u32_be(data, &mut pos)?;
    let _uptime1 = read_u32_be(data, &mut pos)?;
    // C# xor(data, key, position, data.Length-1)：用 key 解密余下部分
    let mut buf = data.to_vec();
    for b in &mut buf[pos..] {
        *b ^= key;
    }
    let _byte_1 = read_u8(&buf, &mut pos)?;
    let mac = read_mac(&buf, &mut pos)?;
    let _byte_2 = read_u8(&buf, &mut pos)?;
    let ip_int = read_u32_be(&buf, &mut pos)?;
    let _mask = read_u32_be(&buf, &mut pos)?;
    let _gw = read_u32_be(&buf, &mut pos)?;
    let _version = read_u32_be(&buf, &mut pos)?;
    let device_name = read_string(&buf, &mut pos)?;
    let _device_location = read_string(&buf, &mut pos)?;
    let _username = read_string(&buf, &mut pos)?;
    let _byte_3 = read_u8(&buf, &mut pos)?;
    let _uptime2 = read_u32_be(&buf, &mut pos)?;
    // C# new IPAddress(NetworkToHostOrder32(ip_int))：BE → host
    let ip = Ipv4Addr::from(ip_int.to_be_bytes());
    Some(Device {
        mac: format!(
            "{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
            mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
        ),
        protocol: "CyberPower".into(),
        version: 1,
        ip: ip.into(),
        // NOTE: replace deviceName by devideModel and try to detect it
        // NOTE: known type values are 2=ATS / 3=BM / 4=Data Logger / 1=PDU / 0=UPS
        device_type: device_name,
        // C# PhysicalAddress.ToString()（.NET Framework）：大写 hex、无分隔符
        serial: format!(
            "{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}",
            mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
        ),
    })
}

/// C# read8：越界 None。
fn read_u8(data: &[u8], pos: &mut usize) -> Option<u8> {
    let b = *data.get(*pos)?;
    *pos += 1;
    Some(b)
}

/// C# read32：大端，越界 None。
fn read_u32_be(data: &[u8], pos: &mut usize) -> Option<u32> {
    let b: [u8; 4] = [
        *data.get(*pos)?,
        *data.get(*pos + 1)?,
        *data.get(*pos + 2)?,
        *data.get(*pos + 3)?,
    ];
    *pos += 4;
    Some(u32::from_be_bytes(b))
}

/// C# readMAC：6 字节，越界 None。
fn read_mac(data: &[u8], pos: &mut usize) -> Option<[u8; 6]> {
    let end = pos.checked_add(6)?;
    if end > data.len() {
        return None;
    }
    let mut mac = [0u8; 6];
    mac.copy_from_slice(&data[*pos..end]);
    *pos = end;
    Some(mac)
}

/// C# readString：1B 长度 + N 字节 UTF-8，越界 None。
fn read_string(data: &[u8], pos: &mut usize) -> Option<String> {
    let len = read_u8(data, pos)? as usize;
    let end = pos.checked_add(len)?;
    if end > data.len() {
        return None;
    }
    let s = String::from_utf8_lossy(&data[*pos..end]).into_owned();
    *pos = end;
    Some(s)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 按 C# reciever 布局构造完整包：magic | key | hash 串 | u32×2(BE) |
    /// XOR 区（byte1 | mac6 | byte2 | ip4 | mask4 | gw4 | version4 |
    /// name/loc/user 串 | byte3 | uptime2），XOR 区每字节 ^key。
    fn build(magic: u8, key: u8, device_name: &str) -> Vec<u8> {
        let mut plain = Vec::new();
        plain.push(0);
        plain.extend_from_slice(&[0, 0x11, 0x22, 0x33, 0x44, 0x55]); // MAC
        plain.push(0);
        plain.extend_from_slice(&0xF0001C00u32.to_be_bytes()); // ip 240.0.28.0 (BE)
        plain.extend_from_slice(&0xFFFFFFFFu32.to_be_bytes()); // mask
        plain.extend_from_slice(&0xF0002000u32.to_be_bytes()); // gw 240.0.32.0
        plain.extend_from_slice(&1u32.to_be_bytes()); // version 字段
        for s in [device_name, "loc", "user"] {
            plain.push(s.len() as u8);
            plain.extend_from_slice(s.as_bytes());
        }
        plain.push(0);
        plain.extend_from_slice(&7u32.to_be_bytes());

        let mut out = Vec::new();
        out.push(magic);
        out.push(key);
        out.push(4);
        out.extend_from_slice(b"hash"); // C# readString：1B 长度 + 内容
        out.extend_from_slice(&1u32.to_be_bytes());
        out.extend_from_slice(&2u32.to_be_bytes());
        for b in plain {
            out.push(b ^ key);
        }
        out
    }

    #[test]
    fn full_packet_reported() {
        let from: SocketAddr = "240.0.28.0:1024".parse().unwrap();
        let devs = CyberPower::default().parse(from, &build(0x51, 0x5A, "PDU1"));
        assert_eq!(devs.len(), 1);
        assert_eq!(devs[0].protocol, "CyberPower");
        assert_eq!(devs[0].version, 1);
        assert_eq!(
            devs[0].ip,
            "240.0.28.0".parse::<std::net::IpAddr>().unwrap()
        );
        assert_eq!(devs[0].device_type, "PDU1");
        assert_eq!(devs[0].mac, "00:11:22:33:44:55");
        assert_eq!(devs[0].serial, "001122334455"); // C# PhysicalAddress.ToString()（无分隔符）
    }

    #[test]
    fn wrong_magic_still_reported() {
        // C#：magic 不匹配仅 warn，仍继续解析并上报
        let from: SocketAddr = "240.0.28.0:1024".parse().unwrap();
        let devs = CyberPower::default().parse(from, &build(0x00, 0x00, "UPS"));
        assert!(!devs.is_empty(), "bad magic must still yield 1 entry");
        assert_eq!(devs[0].device_type, "UPS");
    }

    #[test]
    fn truncated_xor_region_empty() {
        // 头（magic/key/hash/u32×2）后 XOR 区只剩 4 字节：MAC 读取越界 → 整包丢弃
        let mut pkt = build(0x51, 0x00, "UPS");
        let header_len = 1 + 1 + 1 + 4 + 4 + 4;
        pkt.truncate(header_len + 4);
        let from: SocketAddr = "240.0.28.0:1024".parse().unwrap();
        assert!(CyberPower::default().parse(from, &pkt).is_empty());
    }

    #[tokio::test]
    async fn fixture_replay() {
        let data = tokio::fs::read(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/CyberPower.selftest"
        ))
        .await
        .unwrap();
        let from: SocketAddr = "240.0.28.0:1024".parse().unwrap();
        let devs = CyberPower::default().parse(from, &data);
        // 期望值：对照 C# CyberPower.reciever 规则手工核定后填入（注释出处：CyberPower.cs reciever/readString/xor）
        // C# CyberPower.reciever：mac.ToString()（PhysicalAddress）→大写 12 hex 无分隔 "001122334455"
        assert_eq!(devs.len(), 1);
        assert_eq!(devs[0].protocol, "CyberPower");
        assert_eq!(devs[0].version, 1);
        assert_eq!(devs[0].ip.to_string(), "240.0.28.0");
        assert_eq!(devs[0].mac, "00:11:22:33:44:55");
        assert_eq!(devs[0].device_type, "Virtual");
        assert_eq!(devs[0].serial, "001122334455");
    }
}
