//! Foscam 引擎（T28）：0x57 结构体 parse（含 cipheredXor XOR 解密分支），
//! 逐行对齐 C# Foscam.reciever，probe 逐字节抄 C# sender()。

use crate::devices::Device;
use crate::engine::{EngineContext, ScanEngine};
use crate::net::SocketSet;
use std::net::{Ipv4Addr, SocketAddr};
use tokio::task::JoinHandle;

const PORT: u16 = 10000; // C# port（监听 + 探测同端口）
const MAGIC: u32 = 0x4d4f5f49; // C# magic（线上 BE）
const HEADER_SIZE: usize = 0x17; // C# FoscamHeader 结构体大小
const ANSWER_SIZE: usize = 0x57; // C# FoscamAnwser 结构体大小

// C# FoscamRequest（0x1B）：FoscamHeader(packetSize=4, requestType=0) + value=1 BE
const PROBE: [u8; 0x1B] = [
    0x4D, 0x4F, 0x5F, 0x49, // magic 0x4D4F5F49 BE
    0x00, 0x00, // requestType = 0
    0x00, // cipheredXor = 0
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // cipherKey
    0x04, // packetSize = 4
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // byte10..byte16
    0x00, 0x00, 0x00, 0x01, // value = 1 BE
];

pub struct Foscam {
    socks: SocketSet,
}

impl Default for Foscam {
    fn default() -> Self {
        Self {
            socks: SocketSet::new(),
        }
    }
}

impl ScanEngine for Foscam {
    fn name(&self) -> &str {
        "Foscam"
    }
    fn used_ports(&self) -> &[u16] {
        &[PORT]
    }
    fn color(&self) -> u32 {
        0xff0000 // Color.Red
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
        // C# Foscam.scan：sendBroadcast(10000)
        let failed = self.socks.send_broadcast(PORT, &PROBE);
        if failed > 0 {
            ctx.logger
                .warn(ctx.task_id, &format!("{} Foscam sends failed", failed));
        }
        Ok(())
    }

    fn parse(&self, _from: SocketAddr, data: &[u8]) -> Vec<Device> {
        // C#：包长 < 0x57 → warn + 丢弃
        if data.len() < ANSWER_SIZE {
            return Vec::new();
        }
        let mut buf = data.to_vec();
        // C#：NetworkToHostOrder32(header.magic) != 0x4d4f5f49 → warn + 丢弃（≡ 线上 BE 读）
        let magic = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]);
        if magic != MAGIC {
            return Vec::new();
        }
        // C#：cipheredXor != 0 → 从偏移 0x17 起用 8 字节 cipherKey 循环 XOR 解密后重读结构体
        if buf[0x06] != 0 {
            let mut key = [0u8; 8];
            key.copy_from_slice(&buf[0x07..0x0F]);
            for (i, b) in buf[HEADER_SIZE..].iter_mut().enumerate() {
                *b ^= key[i % 8];
            }
        }
        let serial = cstring(&buf[0x17..0x24]);
        // C# 解析 name[21] 但不使用（parity）
        let _name = cstring(&buf[0x24..0x39]);
        // C# quirk（照抄）：ip 字段 LE 读出后按 ipBytes[0]=LSB 填 4 字节数组再
        // new IPAddress(ipBytes)（首元素 = 首 octet）→ 等价于 ip_raw 的 LE 字节序
        let ip_raw = u32::from_le_bytes([buf[0x39], buf[0x3A], buf[0x3B], buf[0x3C]]);
        let device_type = buf[0x49];
        vec![Device {
            mac: String::new(),
            protocol: "Foscam".into(),
            version: 1,
            ip: std::net::IpAddr::V4(Ipv4Addr::from(ip_raw.to_le_bytes())),
            device_type: format!("Type {device_type}"),
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

    /// 按 C# FoscamAnwser 布局构造 0x57 应答；ciphered=true 时置 cipheredXor=1、
    /// 写入 8 字节 key 并按 C# 语义对 0x17 起内容做预加密。
    fn answer(ciphered: bool) -> Vec<u8> {
        let key = *b"_Foscam_";
        let mut d = vec![0u8; ANSWER_SIZE];
        d[0..4].copy_from_slice(&MAGIC.to_be_bytes());
        d[4..6].copy_from_slice(&1u16.to_be_bytes()); // requestType（recv 路径不读）
        d[6] = u8::from(ciphered);
        if ciphered {
            d[0x07..0x0F].copy_from_slice(&key);
        }
        d[0x0F] = 0x40; // packetSize（recv 路径不读）
        d[0x17..0x21].copy_from_slice(b"0123456789"); // serial[13]（10 字符，余 NUL）
        d[0x24..0x32].copy_from_slice(b"Virtual device"); // name[21]
        d[0x39..0x3D].copy_from_slice(&[0xF0, 0x00, 0x14, 0x00]); // ip → 240.0.20.0
        if ciphered {
            for (i, b) in d[HEADER_SIZE..].iter_mut().enumerate() {
                *b ^= key[i % 8];
            }
        }
        d
    }

    #[test]
    fn wrong_magic_discarded() {
        let mut d = answer(false);
        d[0] = 0x00;
        let from: SocketAddr = "240.0.20.0:1024".parse().unwrap();
        assert!(Foscam::default().parse(from, &d).is_empty());
    }

    #[test]
    fn short_packet_discarded() {
        let d = answer(false);
        let from: SocketAddr = "240.0.20.0:1024".parse().unwrap();
        assert!(Foscam::default()
            .parse(from, &d[..ANSWER_SIZE - 1])
            .is_empty());
    }

    #[test]
    fn plain_and_ciphered_same_serial() {
        let from: SocketAddr = "240.0.20.0:1024".parse().unwrap();
        let plain = Foscam::default().parse(from, &answer(false));
        let ciphered = Foscam::default().parse(from, &answer(true));
        assert_eq!(plain.len(), 1);
        assert_eq!(ciphered.len(), 1);
        assert_eq!(plain[0].protocol, "Foscam");
        assert_eq!(plain[0].version, 1);
        assert_eq!(plain[0].serial, "0123456789");
        assert_eq!(ciphered[0].serial, "0123456789"); // 解密后同一 serial
        assert_eq!(
            plain[0].ip,
            "240.0.20.0".parse::<std::net::IpAddr>().unwrap()
        );
        assert_eq!(ciphered[0].ip, plain[0].ip);
        assert_eq!(plain[0].device_type, "Type 0");
        assert_eq!(ciphered[0].device_type, "Type 0");
    }

    #[tokio::test]
    async fn fixture_replay() {
        let data = tokio::fs::read(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/Foscam.selftest"
        ))
        .await
        .unwrap();
        let from: SocketAddr = "240.0.20.0:1024".parse().unwrap();
        let devs = Foscam::default().parse(from, &data);
        // 期望值：对照 C# Foscam.reciever 规则手工核定后填入（注释出处：Foscam.cs reciever/FoscamAnwser）
        // C# Foscam.reciever：deviceType→"Type 8"；ipBytes 低位在前（identity 序）→240.0.20.0；version 1
        assert_eq!(devs.len(), 1);
        assert_eq!(devs[0].protocol, "Foscam");
        assert_eq!(devs[0].version, 1);
        assert_eq!(devs[0].ip.to_string(), "240.0.20.0");
        assert_eq!(devs[0].device_type, "Type 8");
        assert_eq!(devs[0].serial, "0123456789");
    }

    #[tokio::test]
    async fn fixture_replay_cipher() {
        let data = tokio::fs::read(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/Foscam_cipher.selftest"
        ))
        .await
        .unwrap();
        let from: SocketAddr = "240.0.20.0:1024".parse().unwrap();
        let devs = Foscam::default().parse(from, &data);
        // 期望值：对照 C# Foscam.reciever 规则手工核定后填入（注释出处：Foscam.cs reciever cipheredXor 分支）
        // C# Foscam.recipher：cipherKey XOR 解密后 ipBytes→240.0.20.1
        assert_eq!(devs.len(), 1);
        assert_eq!(devs[0].protocol, "Foscam");
        assert_eq!(devs[0].version, 1);
        assert_eq!(devs[0].ip.to_string(), "240.0.20.1");
        assert_eq!(devs[0].device_type, "Type 8");
        assert_eq!(devs[0].serial, "0123456789");
    }
}
