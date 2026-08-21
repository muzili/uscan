//! Hikvision 引擎（T20）：parse 逐行对齐 C# Hikvision.reciever，probe 逐字对齐 sender()。

use crate::devices::Device;
use crate::engine::{EngineContext, ScanEngine};
use crate::net::SocketSet;
use std::net::{Ipv4Addr, SocketAddr};
use tokio::task::JoinHandle;

const GROUP: Ipv4Addr = Ipv4Addr::new(239, 255, 255, 250);
const PORT: u16 = 37020;

/// C# getAssemblyUUID：固定 C# assembly GUID（spec §8.2 保留原样，不每次随机）。
const PROBE: &str = "<?xml version=\"1.0\" encoding=\"utf-8\"?><Probe><Uuid>6a0eaae3-897b-4472-a692-ca0b08e09cd1</Uuid><Types>inquiry</Types></Probe>";

pub struct Hikvision {
    socks: SocketSet,
}

impl Default for Hikvision {
    fn default() -> Self {
        Self {
            socks: SocketSet::new(),
        }
    }
}

impl ScanEngine for Hikvision {
    fn name(&self) -> &str {
        "Hikvision"
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
        // 组播（本引擎无 global）
        let (msock, msync) =
            crate::net::udp_bind_multicast(GROUP, PORT, &nic_ips, &ctx.logger, ctx.task_id)?;
        self.socks.add(msync);
        handles.push(tokio::spawn(crate::net::recv_loop(
            ctx.clone(),
            std::sync::Arc::clone(&e),
            msock,
        )));
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
        // C# Hikvision.scan：仅 sendMulticast(239.255.255.250, 37020)，无广播。
        let probe = PROBE.as_bytes().to_vec();
        let failed = self.socks.send_multicast(GROUP, PORT, &probe);
        if failed > 0 {
            ctx.logger
                .warn(ctx.task_id, &format!("{} Hikvision sends failed", failed));
        }
        Ok(())
    }

    fn parse(&self, from: SocketAddr, data: &[u8]) -> Vec<Device> {
        let xml = String::from_utf8_lossy(data).into_owned();
        // C# reciever：不含 <ProbeMatch> → 丢弃
        if !xml.contains("<ProbeMatch>") {
            return Vec::new();
        }
        let device_type = extract_xml_string(&xml, "DeviceDescription").unwrap_or_default();
        let device_sn = extract_xml_string(&xml, "DeviceSN").unwrap_or_default();
        let ipv4_str =
            extract_xml_string(&xml, "IPv4Address").unwrap_or_else(|| from.ip().to_string());
        let ipv6_str = extract_xml_string(&xml, "IPv6Address");
        // C# IPAddress.TryParse 接受 v4/v6；解析失败 → 回退 from（warn 由 T48 侧记）
        let ip = ipv4_str
            .parse::<std::net::IpAddr>()
            .unwrap_or_else(|_| from.ip());
        let mut devs = vec![Device {
            protocol: "Hikvision".into(),
            version: 1,
            ip,
            device_type: device_type.clone(),
            serial: device_sn.clone(),
        }];
        // IPv6 tag 存在且解析成功 → 另报一条 IPv6 条目
        if let Some(v6) = ipv6_str {
            if let Ok(ip6) = v6.parse::<std::net::IpAddr>() {
                devs.push(Device {
                    protocol: "Hikvision".into(),
                    version: 1,
                    ip: ip6,
                    device_type,
                    serial: device_sn,
                });
            }
        }
        devs
    }
}

/// C# extractXMLString：正则 `<{tag}>([^<]*)</{tag}>` 的手工等价
///（内容不含 '<'；开标签后紧跟 `</tag>` 才算命中）。
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
    fn no_probe_match_discarded() {
        let from: SocketAddr = "240.0.5.0:1024".parse().unwrap();
        // 探测串本身（无 <ProbeMatch>）→ 丢弃
        let xml = PROBE.as_bytes();
        assert!(Hikvision::default().parse(from, xml).is_empty());
    }

    #[test]
    fn minimal_probe_match_reports_v4() {
        let from: SocketAddr = "240.0.5.0:1024".parse().unwrap();
        let xml = b"<ProbeMatch><DeviceDescription>DH-IPC</DeviceDescription><DeviceSN>SN12345</DeviceSN><IPv4Address>192.168.1.50</IPv4Address></ProbeMatch>";
        let devs = Hikvision::default().parse(from, xml);
        assert_eq!(devs.len(), 1);
        assert_eq!(devs[0].protocol, "Hikvision");
        assert_eq!(devs[0].version, 1);
        assert_eq!(
            devs[0].ip,
            "192.168.1.50".parse::<std::net::IpAddr>().unwrap()
        );
        assert_eq!(devs[0].device_type, "DH-IPC");
        assert_eq!(devs[0].serial, "SN12345");
    }

    #[test]
    fn ipv6_branch_reports_two_entries() {
        let from: SocketAddr = "240.0.5.0:1024".parse().unwrap();
        let xml = b"<ProbeMatch><DeviceDescription>DH-IPC</DeviceDescription><DeviceSN>SN12345</DeviceSN><IPv4Address>192.168.1.50</IPv4Address><IPv6Address>fe80::1</IPv6Address></ProbeMatch>";
        let devs = Hikvision::default().parse(from, xml);
        assert_eq!(devs.len(), 2);
        assert_eq!(
            devs[0].ip,
            "192.168.1.50".parse::<std::net::IpAddr>().unwrap()
        );
        assert_eq!(devs[1].ip, "fe80::1".parse::<std::net::IpAddr>().unwrap());
        assert_eq!(devs[1].version, 1);
    }

    #[tokio::test]
    async fn fixture_replay() {
        let data = tokio::fs::read(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/Hikvision.selftest"
        ))
        .await
        .unwrap();
        let from: SocketAddr = "240.0.5.0:1024".parse().unwrap();
        let devs = Hikvision::default().parse(from, &data);
        // 期望值：对照 C# Hikvision.reciever 规则手工核定后填入（注释出处：Hikvision.cs reciever/extractXMLString）
        // C# Hikvision.reciever：version 1；IPv4 + IPv6（fixture 中为 "::"，TryParse 成功）两条
        assert_eq!(devs.len(), 2);
        assert_eq!(devs[0].protocol, "Hikvision");
        assert_eq!(devs[0].version, 1);
        assert_eq!(devs[0].ip.to_string(), "240.0.5.0");
        assert_eq!(devs[0].device_type, "Virtual");
        assert_eq!(devs[0].serial, "Virtual-123456789");
        assert_eq!(devs[1].protocol, "Hikvision");
        assert_eq!(devs[1].version, 1);
        assert_eq!(devs[1].ip.to_string(), "::");
        assert_eq!(devs[1].device_type, "Virtual");
        assert_eq!(devs[1].serial, "Virtual-123456789");
    }
}
