//! GoogleCast 引擎（T42）：mDNS 消费者，无 autoconf 过滤（C# GoogleCast；name "Google"）。

use crate::devices::Device;
use crate::engine::{EngineContext, ScanEngine};
use crate::mdns::{MdnsAnswer, MdnsData};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use tokio::task::JoinHandle;

const DOMAIN: &str = "_googlecast._tcp.local"; // C# domain

pub struct GoogleCast;

/// C# googlecastDeviceFound（纯函数，逐条对应）：
/// deviceType/deviceID 初始 "unknown"（**永不为 null** → C# PTR 分支为死代码，不实现 model-from-PTR）；
/// 首个 A → ipv4；首个 AAAA → ipv6（C# 误读 typeA 的 bug，spec §8.2 修正为真实 IPv6）；
/// TXT：数组为空 → C# typeTXT[0] 越界 → 整包无上报；txt[0] 不含 '=' → 跳过该 TXT；
/// 否则逐项 Split('=') **恰 2 段**时：`fn`→deviceID、`md`→deviceType（值均 trim）；
/// 无 autoconf 过滤：ipv4 非空报一条、ipv6 非空再报一条（同 model/serial）；version 1。
pub fn googlecast_convert(answers: &[MdnsAnswer]) -> Vec<Device> {
    let mut ipv4: Option<IpAddr> = None;
    let mut ipv6: Option<IpAddr> = None;
    let mut device_type = "unknown".to_string();
    let mut device_id = "unknown".to_string();
    for a in answers {
        match &a.data {
            MdnsData::A(ip) => {
                if ipv4.is_none() {
                    ipv4 = Some(*ip);
                }
            }
            // C# 此处误读 typeA（bug）；spec §8.2 修正为真实 IPv6 值
            MdnsData::AAAA(ip) => {
                if ipv6.is_none() {
                    ipv6 = Some(*ip);
                }
            }
            // C# PTR 分支为死代码（deviceType 初始 "unknown" 永不为 null）→ 不实现
            // C# 对**每个** TXT 应答处理（无"仅首个"守卫）
            MdnsData::Txt(txt) => {
                // C# typeTXT[0]：空数组越界异常 → 整包无上报（parity）
                let Some(first) = txt.first() else {
                    return Vec::new();
                };
                if first.contains('=') {
                    for entry in txt {
                        // C# Split('=')：恰 2 段才取值（"a=b=c" → 3 段忽略）
                        let parts: Vec<&str> = entry.split('=').collect();
                        if parts.len() == 2 {
                            match parts[0].trim() {
                                "fn" => device_id = parts[1].trim().to_string(),
                                "md" => device_type = parts[1].trim().to_string(),
                                _ => {}
                            }
                        }
                    }
                }
            }
            _ => {}
        }
    }
    // C#：ipv4 非空报一条、ipv6 非空再报一条（同 model/serial）；无 autoconf 过滤
    let mut out = Vec::new();
    if let Some(ip) = ipv4 {
        out.push(Device {
            protocol: "Google".into(),
            version: 1,
            ip,
            device_type: device_type.clone(),
            serial: device_id.clone(),
        });
    }
    if let Some(ip) = ipv6 {
        out.push(Device {
            protocol: "Google".into(),
            version: 1,
            ip,
            device_type,
            serial: device_id,
        });
    }
    out
}

impl ScanEngine for GoogleCast {
    fn name(&self) -> &str {
        "Google" // C# GoogleCast.name
    }
    fn used_ports(&self) -> &[u16] {
        &[] // C# getUsedPort() = dnsBroker.getUsedPort()：5353 由 broker 自管
    }
    fn color(&self) -> u32 {
        0x00008B // Color.DarkBlue.ToArgb() → 低 24 位
    }

    fn listen(&self, ctx: Arc<EngineContext>) -> crate::Result<Vec<JoinHandle<()>>> {
        let reporter = ctx.reporter.clone();
        ctx.mdns.register_domain(
            DOMAIN,
            Arc::new(move |_dom, answers| {
                for dev in googlecast_convert(answers) {
                    let _ = reporter.send(dev);
                }
            }),
        );
        Ok(vec![]) // 无自有 socket（C# GoogleCast.listen 仅向 broker 注册域名）
    }

    fn scan(&self, ctx: &EngineContext) -> crate::Result<()> {
        let ifaces = crate::iface::active_interfaces();
        let nic_ips: Vec<Ipv4Addr> = ifaces.iter().flat_map(|i| i.ipv4_addrs()).collect();
        ctx.mdns.scan(DOMAIN, &nic_ips)
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

    fn aaaa(ip: &str) -> MdnsAnswer {
        MdnsAnswer {
            rrtype: 28,
            name: "cam.local".into(),
            data: MdnsData::AAAA(ip.parse::<IpAddr>().unwrap()),
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
    fn googlecast_a_and_aaaa_two_devices() {
        // 无 autoconf 过滤：A + AAAA → 2 条（含 link-local v6 也报）
        let answers = vec![a("192.168.1.7"), aaaa("fe80::1")];
        let devs = googlecast_convert(&answers);
        assert_eq!(devs.len(), 2);
        assert_eq!(devs[0].ip, "192.168.1.7".parse::<IpAddr>().unwrap());
        assert_eq!(devs[1].ip, "fe80::1".parse::<IpAddr>().unwrap());
        // AAAA 读真实 IPv6（C# 误读 typeA 的 bug，spec §8.2 修正）
        for d in &devs {
            assert_eq!(d.protocol, "Google");
            assert_eq!(d.version, 1);
            assert_eq!(d.device_type, "unknown");
            assert_eq!(d.serial, "unknown");
        }
    }

    #[test]
    fn googlecast_only_first_a_and_aaaa() {
        // 仅首个 A / 首个 AAAA 生效
        let answers = vec![
            a("192.168.1.7"),
            a("192.168.1.8"),
            aaaa("fe80::1"),
            aaaa("fe80::2"),
        ];
        let devs = googlecast_convert(&answers);
        assert_eq!(devs.len(), 2);
        assert_eq!(devs[0].ip, "192.168.1.7".parse::<IpAddr>().unwrap());
        assert_eq!(devs[1].ip, "fe80::1".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn googlecast_txt_fn_md() {
        let answers = vec![
            a("192.168.1.7"),
            txt(&["fn=Chromecast One", "md=Cast Audio"]),
        ];
        let devs = googlecast_convert(&answers);
        assert_eq!(devs.len(), 1);
        assert_eq!(devs[0].device_type, "Cast Audio");
        assert_eq!(devs[0].serial, "Chromecast One");
    }

    #[test]
    fn googlecast_txt_multi_eq_ignored() {
        // "a=b=c" Split('=') 长度 3 → 忽略 → model 保持 "unknown"
        let answers = vec![a("192.168.1.7"), txt(&["a=b=c"])];
        let devs = googlecast_convert(&answers);
        assert_eq!(devs.len(), 1);
        assert_eq!(devs[0].device_type, "unknown");
        assert_eq!(devs[0].serial, "unknown");
    }

    #[test]
    fn googlecast_txt_no_eq_skipped() {
        // txt[0] 不含 '=' → 整个 TXT 应答跳过（含后续条目）
        let answers = vec![a("192.168.1.7"), txt(&["plain", "md=Cast Audio"])];
        let devs = googlecast_convert(&answers);
        assert_eq!(devs.len(), 1);
        assert_eq!(devs[0].device_type, "unknown");
        assert_eq!(devs[0].serial, "unknown");
    }

    #[test]
    fn googlecast_txt_key_trimmed() {
        // key 两侧 trim（C# keyPair[0].Trim()）
        let answers = vec![
            a("192.168.1.7"),
            txt(&[" fn =Cast Audio ", "  md =Cast 2 "]),
        ];
        let devs = googlecast_convert(&answers);
        assert_eq!(devs.len(), 1);
        assert_eq!(devs[0].device_type, "Cast 2");
        assert_eq!(devs[0].serial, "Cast Audio");
    }

    #[test]
    fn googlecast_empty_txt_aborts() {
        // A + Txt(vec![]) → C# typeTXT[0] 越界 → 整包无上报
        let answers = vec![a("192.168.1.7"), txt(&[])];
        assert!(googlecast_convert(&answers).is_empty());
    }

    #[test]
    fn googlecast_no_address_no_report() {
        // 仅 TXT（无 A/AAAA）→ ipv4/ipv6 均 null → 不上报
        let answers = vec![txt(&["fn=Chromecast One"])];
        assert!(googlecast_convert(&answers).is_empty());
    }

    #[tokio::test]
    async fn fixture_replay_via_broker() {
        // broker.new_for_test + register googlecast handler（接 UnboundedSender）+
        // on_packet（GoogleCast.selftest 原始 DNS 字节）→ 收集设备
        let mdns = MdnsBroker::new_for_test();
        let (ctx, mut rx) = ctx_with(mdns);
        GoogleCast.listen(ctx.clone()).unwrap();
        let data = tokio::fs::read(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/GoogleCast.selftest"
        ))
        .await
        .unwrap();
        ctx.mdns.on_packet(&data);
        let mut devs = Vec::new();
        while let Ok(d) = rx.try_recv() {
            devs.push(d);
        }
        // 期望值：对照 C# GoogleCast.googlecastDeviceFound 规则手工核定后填入
        //（TXT md=Google Virtual / fn=Google Virtual、A 240.0.8.0、无 AAAA）
        assert!(
            !devs.is_empty(),
            "GoogleCast fixture should yield >=1 device"
        );
        // TODO(T50): 填入完整 (protocol, version, ip, type, serial) 断言（源地址 240.0.0.0，task_id 0）
    }
}
