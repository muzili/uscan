//! Axis 引擎（T41）：mDNS 消费者。listen 向 broker 注册两个域名、scan 每域名 1 次 PTR 查询（C# Axis）。

use crate::devices::Device;
use crate::engine::{EngineContext, ScanEngine};
use crate::mdns::MdnsAnswer;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use tokio::task::JoinHandle;

const DOMAINS: [&str; 2] = ["_axis-nvr._tcp.local", "_axis-video._tcp.local"]; // C# domains

pub struct Axis;

/// C# axisDeviceFound（纯函数，逐条对应）：
/// A/AAAA → 地址；首个 PTR → model（首个 `.` 前，无 `.` 全名）；首个 TXT → serial（txt[0]，含 `=` 取首个 `=` 后）；
/// TXT 数组为空 → C# typeTXT[0] 越界异常 → 整包无上报（parity：返回空）；地址空 → 不上报。
pub fn axis_convert(answers: &[MdnsAnswer], cfg: &crate::Config) -> Vec<Device> {
    let mut addresses: Vec<IpAddr> = Vec::new();
    let mut model: Option<String> = None;
    let mut serial: Option<String> = None;
    for a in answers {
        match &a.data {
            crate::mdns::MdnsData::A(ip) => addresses.push(*ip),
            crate::mdns::MdnsData::AAAA(ip) => addresses.push(*ip),
            // C# if (deviceModel == null)：仅首个 PTR
            crate::mdns::MdnsData::Ptr(n) if model.is_none() => {
                // C# IndexOf('.')：首个 `.` 前；无 `.` 取全名
                model = Some(
                    n.split('.')
                        .next()
                        .map(str::to_string)
                        .unwrap_or_else(|| n.clone()),
                );
            }
            // C# if (serial == null)：仅首个 TXT（serial 已设时后续 TXT 整体跳过，含空数组也不越界）
            crate::mdns::MdnsData::Txt(txt) if serial.is_none() => {
                // C# typeTXT[0]：空数组越界异常 → 整包无上报（parity）
                let first = match txt.first() {
                    Some(s) => s,
                    None => return Vec::new(),
                };
                // C# IndexOf('=')：首个 `=` 后（无 `=` 取全值）
                serial = Some(
                    first
                        .split_once('=')
                        .map(|(_, v)| v)
                        .unwrap_or(first)
                        .to_string(),
                );
            }
            _ => {}
        }
    }
    if addresses.is_empty() {
        return Vec::new();
    }
    let mut model = model.unwrap_or_else(|| "unknown".into());
    // C# IndexOf(" - ")：serial 未设置时取 " - " 之后（trim）；model 恒截为 " - " 之前（trim）
    if let Some(pos) = model.find(" - ") {
        if serial.is_none() {
            serial = Some(model[pos + " - ".len()..].trim().to_string());
        }
        model = model[..pos].trim().to_string();
    }
    let serial = serial.unwrap_or_else(|| "unknown".into());
    crate::mdns::report_addresses("Axis", 1, &addresses, &model, &serial, cfg)
}

impl ScanEngine for Axis {
    fn name(&self) -> &str {
        "Axis"
    }
    fn used_ports(&self) -> &[u16] {
        &[] // C# getUsedPort() = dnsBroker.getUsedPort()：5353 由 broker 自管
    }
    fn color(&self) -> u32 {
        0x806000 // C# Axis.color 字面量 0x806000（非 Color.X）
    }

    fn listen(&self, ctx: Arc<EngineContext>) -> crate::Result<Vec<JoinHandle<()>>> {
        for d in DOMAINS {
            let cfg = ctx.config.clone();
            let reporter = ctx.reporter.clone();
            ctx.mdns.register_domain(
                d,
                Arc::new(move |_dom, answers| {
                    for dev in axis_convert(answers, &cfg) {
                        let _ = reporter.send(dev);
                    }
                }),
            );
        }
        Ok(vec![]) // 无自有 socket（C# Axis.listen 仅向 broker 注册域名）
    }

    fn scan(&self, ctx: &EngineContext) -> crate::Result<()> {
        let ifaces = crate::iface::active_interfaces();
        let nic_ips: Vec<Ipv4Addr> = ifaces.iter().flat_map(|i| i.ipv4_addrs()).collect();
        for d in DOMAINS {
            ctx.mdns.scan(d, &nic_ips)?;
        }
        Ok(())
    }

    fn parse(&self, _from: SocketAddr, _data: &[u8]) -> Vec<Device> {
        Vec::new() // C# reciever 抛 NotImplementedException；包经 broker 分发
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mdns::{MdnsBroker, MdnsData};
    use crate::ports::PortProvider;

    /// 构造测试用 EngineContext（C# selfTest 语义：源地址 240.0.x.y、task_id 0）。
    fn ctx_with(
        mdns: Arc<MdnsBroker>,
    ) -> (
        Arc<EngineContext>,
        tokio::sync::mpsc::UnboundedReceiver<Device>,
    ) {
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
        let ctx = Arc::new(EngineContext {
            config: Arc::new(crate::Config::default()),
            ports: Arc::new(std::sync::Mutex::new(PortProvider::new())),
            reporter: tx,
            mdns,
            logger: Arc::new(crate::log::Logger::new(crate::log::Level::Debug)),
            pcap: None,
            cancel: tokio_util::sync::CancellationToken::new(),
            task_id: 0,
            sweeps: Arc::new(std::sync::Mutex::new(Vec::new())),
        });
        (ctx, rx)
    }

    fn a(ip: &str) -> MdnsAnswer {
        MdnsAnswer {
            rrtype: 1,
            name: "cam.local".into(),
            data: MdnsData::A(ip.parse::<IpAddr>().unwrap()),
        }
    }

    fn ptr(name: &str) -> MdnsAnswer {
        MdnsAnswer {
            rrtype: 12,
            name: "cam.local".into(),
            data: MdnsData::Ptr(name.into()),
        }
    }

    fn txt(entries: &[&str]) -> MdnsAnswer {
        MdnsAnswer {
            rrtype: 16,
            name: "cam.local".into(),
            data: MdnsData::Txt(entries.iter().map(|s| s.to_string()).collect()),
        }
    }

    #[test]
    fn axis_basic() {
        let cfg = crate::Config::default();
        let answers = vec![
            a("192.168.1.50"),
            ptr("cam123.axis-video._tcp.local"),
            txt(&["SN=ABC123"]),
        ];
        let devs = axis_convert(&answers, &cfg);
        assert_eq!(devs.len(), 1);
        assert_eq!(devs[0].protocol, "Axis");
        assert_eq!(devs[0].version, 1);
        assert_eq!(devs[0].ip, "192.168.1.50".parse::<IpAddr>().unwrap());
        assert_eq!(devs[0].device_type, "cam123");
        assert_eq!(devs[0].serial, "ABC123");
    }

    #[test]
    fn axis_ptr_without_dot_keeps_whole_name() {
        let cfg = crate::Config::default();
        let answers = vec![a("192.168.1.50"), ptr("camplain")];
        let devs = axis_convert(&answers, &cfg);
        assert_eq!(devs.len(), 1);
        assert_eq!(devs[0].device_type, "camplain");
        // 无 TXT → serial 缺省 "unknown"
        assert_eq!(devs[0].serial, "unknown");
    }

    #[test]
    fn axis_dash_mac_fallback() {
        // C#：仅当无 TXT 应答时 serial 为 null，" - " 之后（trim）才作为 serial。
        // PTR "cam1 - A1B2C3D4E5F6.axis-video._tcp.local"，无 TXT 应答
        let cfg = crate::Config::default();
        let answers = vec![
            a("192.168.1.5"),
            ptr("cam1 - A1B2C3D4E5F6.axis-video._tcp.local"),
        ];
        let devs = axis_convert(&answers, &cfg);
        assert_eq!(devs.len(), 1);
        assert_eq!(devs[0].device_type, "cam1");
        assert_eq!(devs[0].serial, "A1B2C3D4E5F6");
    }

    #[test]
    fn axis_txt_wins_over_dash() {
        // TXT 已设 serial（含 '='）时 " - " 不再覆盖 serial，model 仍截为 " - " 之前
        let cfg = crate::Config::default();
        let answers = vec![
            a("192.168.1.5"),
            ptr("cam1 - A1B2C3D4E5F6.axis-video._tcp.local"),
            txt(&["SN=ABC123"]),
        ];
        let devs = axis_convert(&answers, &cfg);
        assert_eq!(devs.len(), 1);
        assert_eq!(devs[0].device_type, "cam1");
        assert_eq!(devs[0].serial, "ABC123");
    }

    #[test]
    fn axis_txt_no_eq_keeps_whole_value() {
        // TXT[0] 无 '=' → serial = 整个 txt[0]（C# IndexOf('=') < 0 不截断）
        let cfg = crate::Config::default();
        let answers = vec![a("192.168.1.5"), txt(&["plainserial"])];
        let devs = axis_convert(&answers, &cfg);
        assert_eq!(devs.len(), 1);
        assert_eq!(devs[0].serial, "plainserial");
    }

    #[test]
    fn axis_empty_txt_aborts() {
        // A + Txt(vec![]) → C# typeTXT[0] 越界 → 整包无上报
        let cfg = crate::Config::default();
        let answers = vec![a("192.168.1.5"), txt(&[])];
        assert!(axis_convert(&answers, &cfg).is_empty());
    }

    #[test]
    fn axis_empty_addresses_no_report() {
        // 仅 PTR/TXT、无 A/AAAA → 不上报
        let cfg = crate::Config::default();
        let answers = vec![ptr("cam123.axis-video._tcp.local"), txt(&["SN=ABC123"])];
        assert!(axis_convert(&answers, &cfg).is_empty());
    }

    #[test]
    fn axis_autoconf_filtered_by_default() {
        // A(169.254.1.1 自动配置) + A(192.168.1.5)：默认 cfg（force_zeroconf=false）→ 只报 192.168.1.5
        let cfg = crate::Config::default();
        let answers = vec![a("169.254.1.1"), a("192.168.1.5")];
        let devs = axis_convert(&answers, &cfg);
        assert_eq!(devs.len(), 1);
        assert_eq!(devs[0].ip, "192.168.1.5".parse::<IpAddr>().unwrap());
        assert_eq!(devs[0].device_type, "unknown");
        assert_eq!(devs[0].serial, "unknown");
        // force_zeroconf=true → 两个都报（先全部非 autoconf，再 autoconf）
        let cfg2 = crate::Config {
            force_zeroconf: true,
            ..cfg
        };
        let devs = axis_convert(&answers, &cfg2);
        assert_eq!(devs.len(), 2);
        assert_eq!(devs[0].ip, "192.168.1.5".parse::<IpAddr>().unwrap());
        assert_eq!(devs[1].ip, "169.254.1.1".parse::<IpAddr>().unwrap());
    }

    #[tokio::test]
    async fn fixture_replay_via_broker() {
        // broker.new_for_test + register axis handler（接 UnboundedSender）+
        // on_packet（Axis.selftest 原始 DNS 字节）→ 收集设备
        let mdns = MdnsBroker::new_for_test();
        let (ctx, mut rx) = ctx_with(mdns);
        Axis.listen(ctx.clone()).unwrap();
        let data = tokio::fs::read(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/Axis.selftest"
        ))
        .await
        .unwrap();
        ctx.mdns.on_packet(&data);
        let mut devs = Vec::new();
        while let Ok(d) = rx.try_recv() {
            devs.push(d);
        }
        // 期望值：对照 C# Axis.axisDeviceFound 规则手工核定后填入
        //（PTR "Virtual - 001122334455.*"、TXT macaddress=001122334455、
        // A 240.0.6.0 + A 169.254.65.120（autoconf，默认过滤））
        // C# Axis.axisDeviceFound：PTR "Virtual - 001122334455.*" → type "Virtual"，serial "001122334455"
        assert_eq!(devs.len(), 1);
        assert_eq!(devs[0].protocol, "Axis");
        assert_eq!(devs[0].version, 1);
        assert_eq!(devs[0].ip.to_string(), "240.0.6.0");
        assert_eq!(devs[0].device_type, "Virtual");
        assert_eq!(devs[0].serial, "001122334455");
    }
}
