//! Dahua1 引擎（T21）：parse 逐行对齐 C# Dahua1.reciever，probe 逐字节抄 C# sender() 数组。

use crate::devices::Device;
use crate::engine::{EngineContext, ScanEngine};
use crate::net::SocketSet;
use std::net::SocketAddr;
use tokio::task::JoinHandle;

const PORT: u16 = 5050;
const ANSWER_MAGIC: u8 = 0xb3;
const SECTION1_LEN: usize = 0x78;
const MAC_MAX: usize = 17; // "00:11:22:33:44:55".len()

/// C# discover 数组（Dahua1.cs 逐字节）。
const DISCOVER: [u8; 32] = [
    0xa3, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];

pub struct Dahua1 {
    socks: SocketSet,
}

impl Default for Dahua1 {
    fn default() -> Self {
        Self {
            socks: SocketSet::new(),
        }
    }
}

impl ScanEngine for Dahua1 {
    fn name(&self) -> &str {
        "Dahua"
    }
    fn used_ports(&self) -> &[u16] {
        &[PORT]
    }
    fn color(&self) -> u32 {
        0x8b0000 // Color.DarkRed
    }

    fn listen(&self, ctx: std::sync::Arc<EngineContext>) -> crate::Result<Vec<JoinHandle<()>>> {
        let ifaces = crate::iface::active_interfaces();
        let nic_ips: Vec<std::net::Ipv4Addr> = ifaces.iter().flat_map(|i| i.ipv4_addrs()).collect();
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
        // C# Dahua1.scan：仅 sendBroadcast(5050)
        let failed = self.socks.send_broadcast(PORT, &DISCOVER);
        if failed > 0 {
            ctx.logger
                .warn(ctx.task_id, &format!("{} Dahua sends failed", failed));
        }
        Ok(())
    }

    fn parse(&self, from: SocketAddr, data: &[u8]) -> Vec<Device> {
        if data.len() < SECTION1_LEN {
            return Vec::new();
        }
        if data[0] != ANSWER_MAGIC {
            return Vec::new();
        }
        let section2_len = data[2] as usize;
        let section3_len = u16::from_le_bytes([data[0x14], data[0x15]]) as usize;
        if SECTION1_LEN + section2_len + section3_len != data.len() {
            return Vec::new();
        }
        // C# quirk（**有意偏离并修正**，spec §8.2）：C# littleEndian32 在 LE 主机上恒等，
        // 再经 new IPAddress(u32) 网络序解释 → 实际把 wire 字节**反转**（真实设备
        // 192.168.1.110 被报成 110.1.168.192）。此处按 wire 顺序解释：
        let ip_raw = u32::from_le_bytes([data[0x38], data[0x39], data[0x3A], data[0x3B]]);
        let ip = if ip_raw != 0 {
            std::net::IpAddr::V4(std::net::Ipv4Addr::new(
                data[0x38], data[0x39], data[0x3A], data[0x3B],
            ))
        } else {
            from.ip()
        };
        // deviceModel：section1.deviceType（16B 结构体字段，NUL 截断）
        let mut device_model = cstring(&data[0x28..0x38]);
        let mut device_ipv6: Option<String> = None;
        // section 2：≤17B MAC 串（byte[]，不截 NUL），余下字节覆盖 type
        let mut index = SECTION1_LEN;
        let mac_size = std::cmp::min(MAC_MAX, section2_len);
        let mut device_serial =
            String::from_utf8_lossy(&data[index..index + mac_size]).into_owned();
        index += mac_size;
        if section2_len > mac_size {
            let override_len = section2_len - mac_size;
            device_model = String::from_utf8_lossy(&data[index..index + override_len]).into_owned();
            index += override_len;
        }
        // section 3：k:v 行，取 SerialNo / IPv6Addr
        if section3_len > 0 {
            let values = parse_section3(&data[index..index + section3_len]);
            if let Some(sn) = values.get("SerialNo") {
                device_serial = sn.clone();
            }
            if let Some(v6) = values.get("IPv6Addr") {
                let mut s = v6.clone();
                if let Some(i) = s.find(';') {
                    s = s[..i].to_string();
                }
                if let Some(i) = s.find('/') {
                    s = s[..i].to_string();
                }
                device_ipv6 = Some(s);
            }
        }
        let mut devs = vec![Device {
            protocol: "Dahua".into(),
            version: 1,
            ip,
            device_type: device_model.clone(),
            serial: device_serial.clone(),
        }];
        // IPv6 解析成功 → 另报 version 2 条目
        if let Some(v6) = device_ipv6 {
            if let Ok(ip6) = v6.parse::<std::net::IpAddr>() {
                devs.push(Device {
                    protocol: "Dahua".into(),
                    version: 2,
                    ip: ip6,
                    device_type: device_model,
                    serial: device_serial,
                });
            }
        }
        devs
    }
}

/// C# parseSection3：按 \r\n / \n 分行（去空行），首个 ':' 处切 key:value（后者覆盖前者）。
fn parse_section3(data: &[u8]) -> std::collections::HashMap<String, String> {
    let text = String::from_utf8_lossy(data);
    let mut out = std::collections::HashMap::new();
    for line in text.split(['\r', '\n']).filter(|l| !l.is_empty()) {
        if let Some((s, _)) = line.char_indices().find(|(_, c)| *c == ':') {
            out.insert(line[..s].to_string(), line[s + 1..].to_string());
        }
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
    use std::net::IpAddr;

    /// 按 C# Dahua1Section1 显式布局构造 section1（120B）：
    /// 0x00 magic、0x02 section2Len、0x14 section3Len(LE16)、0x28 deviceType[16]、0x38 ip(LE32)。
    fn section1(section2_len: u8, section3_len: u16, device_type: &str, ip_u32: u32) -> Vec<u8> {
        let mut s = vec![0u8; SECTION1_LEN];
        s[0] = ANSWER_MAGIC;
        s[2] = section2_len;
        s[0x14..0x16].copy_from_slice(&section3_len.to_le_bytes());
        let dt = device_type.as_bytes();
        s[0x28..0x28 + dt.len()].copy_from_slice(dt); // 余下保持 0（NUL padding）
        s[0x38..0x3C].copy_from_slice(&ip_u32.to_le_bytes());
        s
    }

    #[test]
    fn bad_magic_discarded() {
        let mut frame = section1(0, 0, "", 0);
        frame[0] = 0x00;
        let from: SocketAddr = "240.0.3.0:1024".parse().unwrap();
        assert!(Dahua1::default().parse(from, &frame).is_empty());
    }

    #[test]
    fn bad_length_discarded() {
        // section2Len=24 / section3Len=88 声称 232B，实际只给 231B
        let mut frame = section1(24, 88, "", 0);
        frame.resize(120 + 24 + 88 - 1, 0);
        let from: SocketAddr = "240.0.3.0:1024".parse().unwrap();
        assert!(Dahua1::default().parse(from, &frame).is_empty());
    }

    #[test]
    fn correct_frame_reports_v4() {
        // wire 按网络序写 192.168.1.100（真实设备行为；section1 以 LE 写 u32 → 传 0x6401A8C0）
        let mut frame = section1(25, 18, "AB", 0x6401A8C0);
        frame.extend_from_slice(b"00:11:22:33:44:55Override"); // sec2：17B MAC + 8B type 覆盖
        frame.extend_from_slice(b"SerialNo:SN12345\r\n"); // sec3
        let from: SocketAddr = "240.0.3.0:1024".parse().unwrap();
        let devs = Dahua1::default().parse(from, &frame);
        assert_eq!(devs.len(), 1);
        assert_eq!(devs[0].protocol, "Dahua");
        assert_eq!(devs[0].version, 1);
        assert_eq!(devs[0].ip, "192.168.1.100".parse::<IpAddr>().unwrap());
        assert_eq!(devs[0].device_type, "Override"); // sec2 余下字节覆盖 type
        assert_eq!(devs[0].serial, "SN12345"); // sec3 SerialNo 覆盖 MAC
    }

    #[test]
    fn zero_ip_falls_back_to_from() {
        // ip=0 → 回退 from；sec2 仅 17B MAC（无覆盖）；无 sec3
        let mut frame = section1(17, 0, "CamY", 0);
        frame.extend_from_slice(b"00:11:22:33:44:55");
        let from: SocketAddr = "240.0.3.0:1024".parse().unwrap();
        let devs = Dahua1::default().parse(from, &frame);
        assert_eq!(devs.len(), 1);
        assert_eq!(devs[0].ip, from.ip());
        assert_eq!(devs[0].device_type, "CamY");
        assert_eq!(devs[0].serial, "00:11:22:33:44:55");
    }

    #[test]
    fn ipv6_reports_second_entry_v2() {
        let sec3 = b"IPv6Addr:fe80::1/64;gateway:fe80::\r\nSerialNo:SN1\r\n";
        let mut frame = section1(17, sec3.len() as u16, "CamZ", 0x6401A8C0);
        frame.extend_from_slice(b"00:11:22:33:44:55");
        frame.extend_from_slice(sec3);
        let from: SocketAddr = "240.0.3.0:1024".parse().unwrap();
        let devs = Dahua1::default().parse(from, &frame);
        assert_eq!(devs.len(), 2);
        assert_eq!(devs[0].version, 1);
        assert_eq!(devs[1].version, 2);
        assert_eq!(devs[1].ip, "fe80::1".parse::<IpAddr>().unwrap());
    }

    #[tokio::test]
    async fn fixture_replay() {
        let data = tokio::fs::read(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/Dahua1.selftest"
        ))
        .await
        .unwrap();
        let from: SocketAddr = "240.0.3.0:1024".parse().unwrap();
        let devs = Dahua1::default().parse(from, &data);
        // 期望值：对照 C# Dahua1.reciever 规则手工核定后填入（注释出处：Dahua1.cs reciever/parseSection3）
        // Dahua1 修正后：wire 顺序 240.0.3.0（C# 会反转为 0.3.0.240，spec §8.2 有意偏离）；v4(v1)+v6(v2) 两条
        assert_eq!(devs.len(), 2);
        assert_eq!(devs[0].protocol, "Dahua");
        assert_eq!(devs[0].version, 1);
        assert_eq!(devs[0].ip.to_string(), "240.0.3.0");
        assert_eq!(devs[0].device_type, "Virtual");
        assert_eq!(devs[0].serial, "123456789");
        assert_eq!(devs[1].protocol, "Dahua");
        assert_eq!(devs[1].version, 2);
        assert_eq!(devs[1].ip.to_string(), "fe80::1");
        assert_eq!(devs[1].device_type, "Virtual");
        assert_eq!(devs[1].serial, "123456789");
    }
}
