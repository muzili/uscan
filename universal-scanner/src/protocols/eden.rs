//! Eden 引擎（T27）：`签名|<xml>` 拆分 + 手工标签提取，逐行对齐 C# EdenOptima.reciever。

use crate::devices::Device;
use crate::engine::{EngineContext, ScanEngine};
use crate::net::SocketSet;
use std::net::{Ipv4Addr, SocketAddr};
use tokio::task::JoinHandle;

const PORT: u16 = 8088; // C# port（监听 + 探测同端口）
                        // C# requestMagic / answerMagic（逐字）
const PROBE: &[u8] = b"DETECT BOX";
const ANSWER_MAGIC: &str = "BOX";

pub struct Eden {
    socks: SocketSet,
}

impl Default for Eden {
    fn default() -> Self {
        Self {
            socks: SocketSet::new(),
        }
    }
}

impl ScanEngine for Eden {
    fn name(&self) -> &str {
        "Eden"
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
        // C# EdenOptima.scan：sendBroadcast(8088)
        let failed = self.socks.send_broadcast(PORT, PROBE);
        if failed > 0 {
            ctx.logger
                .warn(ctx.task_id, &format!("{} Eden sends failed", failed));
        }
        Ok(())
    }

    fn parse(&self, from: SocketAddr, data: &[u8]) -> Vec<Device> {
        let text = String::from_utf8_lossy(data).into_owned();
        let fields: Vec<&str> = text.split('|').collect();
        // C#：fields[0] 须等于 answerMagic，否则 warn + return（parse 纯函数 → 直接丢弃）
        if fields[0] != ANSWER_MAGIC {
            return Vec::new();
        }
        // C#：无 '|' 时取 fields[1] 抛 IndexOutOfRangeException → 上层捕获，不上报
        let Some(body) = fields.get(1) else {
            return Vec::new();
        };
        // C#：extractXMLString 无匹配 → null（serial 以空串呈现）
        let device_serial = extract_xml_string(body, "serialNumber").unwrap_or_default();
        let device_ip = extract_xml_string(body, "adresseIP").unwrap_or_default();
        // C#：IPAddress.TryParse 失败 → 回退 from（warn 由 T48 侧记）
        let ip = device_ip
            .parse::<std::net::IpAddr>()
            .unwrap_or_else(|_| from.ip());
        vec![Device {
            protocol: "Eden".into(),
            version: 1,
            ip,
            device_type: "Optima box".into(),
            serial: device_serial,
        }]
    }
}

/// C# 正则 `<{tag}>([^<]*)</{tag}>` 的手工等价（内容不含 '<'，开标签后紧跟 `</tag>`）。
fn extract_xml_string(xml: &str, tag: &str) -> Option<String> {
    let open = format!("<{tag}>");
    let close = format!("</{tag}>");
    let mut cursor = 0usize;
    while let Some(off) = xml[cursor..].find(&open) {
        let start = cursor + off + open.len();
        // 开标签后无 '<' → 无任何闭合候选，直接无匹配
        let rel = xml[start..].find('<')?;
        let end = start + rel;
        if xml[end..].starts_with(&close) {
            return Some(xml[start..end].to_string());
        }
        cursor = start;
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bad_signature_discarded() {
        // C#：fields[0] != answerMagic → warn + return（不上报）
        let pkt =
            b"FOO|<root><serialNumber>S1</serialNumber><adresseIP>240.0.26.0</adresseIP></root>";
        let from: SocketAddr = "240.0.26.0:1024".parse().unwrap();
        assert!(Eden::default().parse(from, pkt).is_empty());
    }

    #[test]
    fn missing_pipe_discarded() {
        // C#：无 '|' 时取 fields[1] 抛 IndexOutOfRangeException → 上层捕获，不上报
        let pkt = b"BOX";
        let from: SocketAddr = "240.0.26.0:1024".parse().unwrap();
        assert!(Eden::default().parse(from, pkt).is_empty());
    }

    #[test]
    fn good_signature_reports_optima_box() {
        let pkt = b"BOX|<root><serialNumber>00:11:22:33:44:55</serialNumber><adresseIP>240.0.26.0</adresseIP></root>";
        let from: SocketAddr = "240.0.26.0:1024".parse().unwrap();
        let devs = Eden::default().parse(from, pkt);
        assert_eq!(devs.len(), 1);
        assert_eq!(devs[0].protocol, "Eden");
        assert_eq!(devs[0].version, 1);
        assert_eq!(
            devs[0].ip,
            "240.0.26.0".parse::<std::net::IpAddr>().unwrap()
        );
        assert_eq!(devs[0].device_type, "Optima box");
        assert_eq!(devs[0].serial, "00:11:22:33:44:55");
    }

    #[test]
    fn invalid_ip_falls_back_to_from() {
        let pkt =
            b"BOX|<root><serialNumber>S1</serialNumber><adresseIP>not-an-ip</adresseIP></root>";
        let from: SocketAddr = "240.0.26.0:1024".parse().unwrap();
        let devs = Eden::default().parse(from, pkt);
        assert_eq!(devs.len(), 1);
        assert_eq!(devs[0].ip, from.ip());
        assert_eq!(devs[0].serial, "S1");
    }

    #[tokio::test]
    async fn fixture_replay() {
        let data = tokio::fs::read(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/Eden.selftest"
        ))
        .await
        .unwrap();
        let from: SocketAddr = "240.0.26.0:1024".parse().unwrap();
        let devs = Eden::default().parse(from, &data);
        // 期望值：对照 C# EdenOptima.reciever 规则手工核定后填入（注释出处：EdenOptima.cs reciever/extractXMLString）
        assert!(!devs.is_empty(), "Eden fixture should yield >=1 device");
        // TODO(T50): 填入完整 (protocol, version, ip, type, serial) 断言
    }
}
