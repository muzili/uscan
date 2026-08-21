//! ARP/GARP 发现引擎（registry id 30，Rust 新增，spec §3.6）。
use crate::arp::capture::{ArpCapture, ArpNic};
use crate::arp::frame;
use crate::devices::Device;
use crate::engine::{EngineContext, ScanEngine};
use crate::iface;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use tokio::sync::mpsc::unbounded_channel;
use tokio::task::JoinHandle;

/// ARP/GARP 发现引擎。`nics` 存 `listen` 打开的每网卡注入通道，`scan` 复用以发 sweep 帧。
pub struct Arp {
    nics: std::sync::Mutex<Vec<ArpNic>>,
}

impl Default for Arp {
    fn default() -> Self {
        Self {
            nics: std::sync::Mutex::new(Vec::new()),
        }
    }
}

/// 纯解析：非 ARP 帧 → 空；GARP → device_type "GARP"，否则 "ARP"；serial = sender MAC 冒号小写。
pub fn arp_parse(frame_bytes: &[u8]) -> Vec<Device> {
    let p = match frame::parse(frame_bytes) {
        Some(p) => p,
        None => return Vec::new(),
    };
    let device_type = if frame::is_garp(&p) { "GARP" } else { "ARP" };
    let serial = p
        .src_mac
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join(":");
    vec![Device {
        protocol: "ARP".to_string(),
        version: 0,
        ip: IpAddr::V4(p.sender_ip),
        device_type: device_type.to_string(),
        serial,
    }]
}

/// 过滤本机 sender_ip（listen 时快照的 local_ips）。
pub fn filter_local(devs: Vec<Device>, local_ips: &[Ipv4Addr]) -> Vec<Device> {
    devs.into_iter()
        .filter(|d| match d.ip {
            IpAddr::V4(v4) => !local_ips.contains(&v4),
            IpAddr::V6(_) => true,
        })
        .collect()
}

/// sweep 目标主机：`subnet_hosts(ip, mask, 254)` 跳过接口自身地址（纯函数，spec §3.6）。
pub fn sweep_plan(ip: Ipv4Addr, mask: Ipv4Addr) -> Vec<Ipv4Addr> {
    iface::subnet_hosts(ip, mask, 254)
        .into_iter()
        .filter(|h| *h != ip)
        .collect()
}

/// 经匹配网卡的 mpsc 通道非阻塞发送一帧（尽力发；通道满/降级 → warn 后跳过）。
fn send_to_nic(nics: &[ArpNic], name: &str, frame_bytes: &[u8], ctx: &EngineContext) {
    let nic = match nics.iter().find(|n| n.name == name) {
        Some(n) => n,
        None => return, // 该接口无捕获线程（降级），不重复 warn
    };
    if nic.tx.send(frame_bytes.to_vec()).is_err() {
        ctx.logger.warn(
            ctx.task_id,
            &format!("ARP sweep: inject channel closed on {name}"),
        );
    }
}

impl ScanEngine for Arp {
    fn name(&self) -> &str {
        "ARP"
    }

    fn used_ports(&self) -> &[u16] {
        &[]
    }

    fn color(&self) -> u32 {
        0x0000FF
    }

    fn listen(&self, ctx: Arc<EngineContext>) -> crate::Result<Vec<JoinHandle<()>>> {
        if !ctx.config.arp_enabled {
            return Ok(Vec::new());
        }
        // 重入保护：捕获线程只能经 ctx.cancel 终止，重复 listen 会泄漏整套线程
        if !self.nics.lock().unwrap().is_empty() {
            return Ok(Vec::new());
        }
        let ifaces = iface::active_interfaces();
        let local_ips: Vec<Ipv4Addr> = ifaces.iter().flat_map(|i| i.ipv4_addrs()).collect();
        let names: Vec<String> = ifaces
            .into_iter()
            .filter(|i| i.ipv4_addrs().next().is_some())
            .map(|i| i.name)
            .collect();
        let (tx, mut rx) = unbounded_channel::<Vec<u8>>();
        let (nics, _handles) =
            ArpCapture::start(&names, tx, ctx.cancel.clone(), &ctx.logger, ctx.task_id);
        *self.nics.lock().unwrap() = nics;
        let reporter = ctx.reporter.clone();
        let handle = tokio::spawn(async move {
            while let Some(frame_bytes) = rx.recv().await {
                for dev in filter_local(arp_parse(&frame_bytes), &local_ips) {
                    let _ = reporter.send(dev);
                }
            }
        });
        Ok(vec![handle])
    }

    fn scan(&self, ctx: &EngineContext) -> crate::Result<()> {
        if !ctx.config.arp_enabled {
            return Ok(());
        }
        // 克隆通道句柄，避免整个 sweep 期间持有锁（通道发送端可克隆）
        let nics = self.nics.lock().unwrap().clone();
        if nics.is_empty() {
            return Ok(()); // 未 listen 或全部网卡降级
        }
        for ifc in iface::active_interfaces() {
            let mac = match iface::mac_of(&ifc.name) {
                Some(m) => m,
                None => {
                    ctx.logger.warn(
                        ctx.task_id,
                        &format!("ARP sweep skipped {}: no MAC", ifc.name),
                    );
                    continue;
                }
            };
            let mut bcast_ip = None; // 每接口首个私有 IP 用于广播
            for ip in ifc.ipv4_addrs() {
                if !iface::is_private(IpAddr::V4(ip)) {
                    continue; // 仅私有接口（含 169.254/16）
                }
                if bcast_ip.is_none() {
                    bcast_ip = Some(ip);
                }
                let mask = iface::mask_of(ip);
                for host in sweep_plan(ip, mask) {
                    send_to_nic(
                        &nics,
                        ifc.name.as_str(),
                        &frame::build_request(mac, ip, host),
                        ctx,
                    );
                }
            }
            // 每接口再发 1 个广播（C# spec §3.6 ②）
            if let Some(ip) = bcast_ip {
                let bcast = Ipv4Addr::new(255, 255, 255, 255);
                send_to_nic(
                    &nics,
                    ifc.name.as_str(),
                    &frame::build_request(mac, ip, bcast),
                    ctx,
                );
            }
        }
        Ok(())
    }

    fn parse(&self, _from: SocketAddr, data: &[u8]) -> Vec<Device> {
        arp_parse(data)
    }
}

#[cfg(test)]
mod tests {
    use super::{arp_parse, filter_local, sweep_plan};
    use crate::arp::frame;
    use std::net::Ipv4Addr;

    #[test]
    fn arp_parse_garp_fixture() {
        let data = std::fs::read(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/Arp.selftest"
        ))
        .unwrap();
        let devs = arp_parse(&data);
        assert_eq!(devs.len(), 1);
        let d = &devs[0];
        assert_eq!(d.protocol, "ARP");
        assert_eq!(d.version, 0);
        assert_eq!(d.ip.to_string(), "192.168.1.50");
        assert_eq!(d.device_type, "GARP");
        assert_eq!(d.serial, "00:11:22:33:44:55");
    }

    #[test]
    fn arp_parse_reply_type() {
        let f = frame::build_reply(
            [0xCC; 6],
            "10.0.0.8".parse().unwrap(),
            [0xDD; 6],
            "10.0.0.1".parse().unwrap(),
        );
        let devs = arp_parse(&f);
        assert_eq!(devs.len(), 1);
        assert_eq!(devs[0].device_type, "ARP");
        assert_eq!(devs[0].ip.to_string(), "10.0.0.8");
    }

    #[test]
    fn arp_parse_non_arp_empty() {
        let mut f = frame::build_request(
            [0xAA; 6],
            "1.2.3.4".parse().unwrap(),
            "1.2.3.5".parse().unwrap(),
        );
        f[12] = 0x08;
        f[13] = 0x00; // IPv4 ethertype
        assert!(arp_parse(&f).is_empty());
    }

    #[test]
    fn local_sender_filtered() {
        let fixture = std::fs::read(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/Arp.selftest"
        ))
        .unwrap();
        let mut devs = arp_parse(&fixture); // GARP 192.168.1.50
        let f60 = frame::build_request(
            [0x11; 6],
            "192.168.1.60".parse().unwrap(),
            "192.168.1.99".parse().unwrap(),
        );
        devs.extend(arp_parse(&f60));
        let local: [Ipv4Addr; 1] = ["192.168.1.50".parse().unwrap()];
        let kept = filter_local(devs, &local);
        assert_eq!(kept.len(), 1);
        assert_eq!(kept[0].ip.to_string(), "192.168.1.60");
    }

    #[test]
    fn sweep_plan_skips_self_and_caps_254() {
        // /32 → 空
        let h32 = sweep_plan(
            "192.168.1.5".parse().unwrap(),
            "255.255.255.255".parse().unwrap(),
        );
        assert!(h32.is_empty());
        // /24 → 253 且不含自身
        let h24 = sweep_plan(
            "192.168.1.5".parse().unwrap(),
            "255.255.255.0".parse().unwrap(),
        );
        assert_eq!(h24.len(), 253);
        assert!(!h24.contains(&"192.168.1.5".parse::<Ipv4Addr>().unwrap()));
        // /8 → 恰 254
        let h8 = sweep_plan("192.168.1.5".parse().unwrap(), "255.0.0.0".parse().unwrap());
        assert_eq!(h8.len(), 254);
    }
}
