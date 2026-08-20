//! Sony 引擎（T35）：0x02/0xFF/0x03 定界 `key:value` 行协议，逐行对齐 C# Sony.reciever。

use crate::devices::Device;
use crate::engine::{EngineContext, ScanEngine};
use crate::net::SocketSet;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use tokio::task::JoinHandle;

const PORT: u16 = 2380; // C# port
const MARKER_START: u8 = 0x02; // C# marker_start
const MARKER_END: u8 = 0x03; // C# marker_end
const MARKER_EOS: u8 = 0xFF; // C# marker_EOS（每行结束）

/// C# sender()：writePacket(["ENQ:allinfo"]) = start + 行 + EOS + end。
fn build_probe() -> Vec<u8> {
    let mut probe = vec![MARKER_START];
    probe.extend_from_slice(b"ENQ:allinfo");
    probe.push(MARKER_EOS);
    probe.push(MARKER_END);
    probe
}

pub struct Sony {
    socks: SocketSet,
}

impl Default for Sony {
    fn default() -> Self {
        Self {
            socks: SocketSet::new(),
        }
    }
}

impl ScanEngine for Sony {
    fn name(&self) -> &str {
        "Sony"
    }
    fn used_ports(&self) -> &[u16] {
        &[] // C# getUsedPort 为空：仅 I，无固定端口预占
    }
    fn color(&self) -> u32 {
        0x000000 // Color.Black.ToArgb() → 低 24 位
    }

    fn listen(&self, ctx: Arc<EngineContext>) -> crate::Result<Vec<JoinHandle<()>>> {
        let ifaces = crate::iface::active_interfaces();
        let nic_ips: Vec<Ipv4Addr> = ifaces.iter().flat_map(|i| i.ipv4_addrs()).collect();
        // recv_loop 只调用 parse()（纯函数），用新实例即可，无需自引用。
        let e: Arc<dyn ScanEngine> = Arc::new(Self::default());
        let mut handles = Vec::new();
        // C# Sony.listen：仅 listenUdpInterfaces()（无 global socket）
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
        // C# Sony.scan：sendBroadcast(port) 2380
        let probe = build_probe();
        let failed = self.socks.send_broadcast(PORT, &probe);
        if failed > 0 {
            ctx.logger
                .warn(ctx.task_id, &format!("{} Sony sends failed", failed));
        }
        Ok(())
    }

    fn parse(&self, from: SocketAddr, data: &[u8]) -> Vec<Device> {
        // C# readPacket：各检查失败 → warn+空（纯函数不记日志）
        if data.len() < 2 {
            return Vec::new();
        }
        if data[0] != MARKER_START || data[data.len() - 1] != MARKER_END {
            return Vec::new();
        }
        // C# readPacket：按 0xFF 切行（start 之后、end 之前）
        let mut lines: Vec<String> = Vec::new();
        let mut last_marker = 0usize;
        for (i, &b) in data[1..data.len() - 1].iter().enumerate() {
            if b == MARKER_EOS {
                // C# Encoding.UTF8.GetString 对非法字节替换 U+FFFD → from_utf8_lossy
                lines.push(String::from_utf8_lossy(&data[last_marker + 1..i + 1]).into_owned());
                last_marker = i + 1;
            }
        }
        // C# reciever：`key:value`（恰一个 ':'），键 ToLower().Trim()；值不 trim
        let mut model: Option<&str> = None;
        let mut serial: Option<&str> = None;
        let mut mac: Option<&str> = None;
        let mut ipv4: Option<&str> = None;
        for line in &lines {
            let parts: Vec<&str> = line.splitn(3, ':').collect();
            if parts.len() == 2 {
                let variable = parts[0].to_ascii_lowercase();
                let value = parts[1];
                match variable.trim() {
                    "model" => model = Some(value),
                    "serial" => serial = Some(value),
                    "mac" => mac = Some(value),
                    "ipadr" => ipv4 = Some(value),
                    _ => {}
                }
            }
        }
        // C#：须有 ipadr 且 model 才上报
        let (Some(ipv4), Some(model)) = (ipv4, model) else {
            return Vec::new();
        };
        // C# serial 回退链：serial → mac → "unkonwn"（C# 原文拼写，保留）
        let serial = serial.or(mac).unwrap_or("unkonwn").to_string();
        // C# IPAddress.TryParse（v4/v6 均可）失败 → from（warn 由 T48 侧记）。
        // 注：C# TryParse 更宽松（接受 "1.2.3"、前导零等简写），Rust 拒绝这些形式而
        // 回退 from——两侧仍上报，仅非标 ipadr 字符串的 IP 值可能不同。
        let ip = ipv4
            .parse::<std::net::IpAddr>()
            .unwrap_or_else(|_| from.ip());
        vec![Device {
            protocol: "Sony".into(),
            version: 1,
            ip,
            device_type: model.to_string(),
            serial,
        }]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;

    /// C# writePacket 语义：start + 每行(EOS) + end。
    fn sony_frame(lines: &[&str]) -> Vec<u8> {
        let mut d = vec![MARKER_START];
        for l in lines {
            d.extend_from_slice(l.as_bytes());
            d.push(MARKER_EOS);
        }
        d.push(MARKER_END);
        d
    }

    #[test]
    fn sony_full() {
        // 完整四键 → 完整元组
        let f = sony_frame(&[
            "MAC:aa-bb-cc-dd-ee-ff",
            "MODEL:Virtual",
            "SERIAL:123456789",
            "IPADR:240.0.11.0",
        ]);
        let from: SocketAddr = "240.0.11.0:1024".parse().unwrap();
        let devs = Sony::default().parse(from, &f);
        assert_eq!(devs.len(), 1);
        assert_eq!(devs[0].protocol, "Sony");
        assert_eq!(devs[0].version, 1);
        assert_eq!(devs[0].ip, "240.0.11.0".parse::<IpAddr>().unwrap());
        assert_eq!(devs[0].device_type, "Virtual");
        assert_eq!(devs[0].serial, "123456789");
    }

    #[test]
    fn sony_missing_ipadr_not_reported() {
        // 缺 ipadr → 空
        let f = sony_frame(&["MODEL:Virtual", "SERIAL:123456789"]);
        let from: SocketAddr = "240.0.11.0:1024".parse().unwrap();
        assert!(Sony::default().parse(from, &f).is_empty());
    }

    #[test]
    fn sony_serial_falls_back_to_mac() {
        // 缺 serial、有 mac → serial 取 mac
        let f = sony_frame(&[
            "MAC:aa-bb-cc-dd-ee-ff",
            "MODEL:Virtual",
            "IPADR:192.168.0.9",
        ]);
        let from: SocketAddr = "240.0.11.0:1024".parse().unwrap();
        let devs = Sony::default().parse(from, &f);
        assert_eq!(devs.len(), 1);
        assert_eq!(devs[0].serial, "aa-bb-cc-dd-ee-ff");
    }

    #[test]
    fn sony_serial_unknown_misspelling() {
        // 缺 serial+mac → "unkonwn"（C# 原文拼写，保留）
        let f = sony_frame(&["MODEL:Virtual", "IPADR:192.168.0.9"]);
        let from: SocketAddr = "240.0.11.0:1024".parse().unwrap();
        let devs = Sony::default().parse(from, &f);
        assert_eq!(devs.len(), 1);
        assert_eq!(devs[0].serial, "unkonwn");
    }

    #[test]
    fn sony_bad_markers_discarded() {
        // 缺 start/end 定界符 → 空
        let from: SocketAddr = "240.0.11.0:1024".parse().unwrap();
        let frame = sony_frame(&["MODEL:V", "IPADR:1.2.3.4"]);
        let mut bad_start = frame.clone();
        bad_start[0] = 0x00;
        assert!(Sony::default().parse(from, &bad_start).is_empty());
        let mut bad_end = frame;
        bad_end.pop();
        bad_end.push(0x00);
        assert!(Sony::default().parse(from, &bad_end).is_empty());
    }

    #[tokio::test]
    async fn fixture_replay() {
        let data = tokio::fs::read(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/Sony.selftest"
        ))
        .await
        .unwrap();
        let from: SocketAddr = "240.0.11.0:1024".parse().unwrap();
        let devs = Sony::default().parse(from, &data);
        // 期望值：对照 C# Sony.reciever/readPacket 规则手工核定后填入（注释出处：Sony.cs reciever/readPacket）
        assert!(!devs.is_empty(), "Sony fixture should yield >=1 device");
        // TODO(T50): 填入完整 (protocol, version, ip, type, serial) 断言
    }
}
