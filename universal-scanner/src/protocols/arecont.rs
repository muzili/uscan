//! Arecont 引擎（T43）：mDNS 消费者，4 次 PTR 探测（间隔 750ms，spawn 任务、新一轮取消上一轮）。

use crate::devices::Device;
use crate::engine::{EngineContext, ScanEngine};
use crate::mdns::MdnsAnswer;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::sync::Mutex;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

const DOMAIN: &str = "_arec._tcp.local"; // C# domain
const SWEEP_INTERVAL_MS: u64 = 750; // C# multiScanThread Thread.Sleep(750)
const SWEEP_COUNT: u32 = 4; // C# for (i=0; i < 4; i++)

pub struct Arecont {
    /// 当前 sweep 的取消令牌；新一轮 scan 先取消上一轮（plan 指定的 Thread.Abort 语义，见模块注释）。
    sweep: Mutex<Option<CancellationToken>>,
}

impl Default for Arecont {
    fn default() -> Self {
        Self {
            sweep: Mutex::new(None),
        }
    }
}

/// C# mdnsReplyReciever（纯函数，逐条对应）：
/// A/AAAA → 地址；首个 PTR → model（首个 `.` 前，无 `.` 全名）；TXT 逐项按**首个** `=` 拆
/// name/value、**同名取首个**（variables 表；空数组 foreach 无操作，**不**像 Axis/GoogleCast 越界）；
/// 地址空 → 不上报；model 缺省 "unknown"。
/// method 1：model 含 `-`：serial 未设置时 = 首个 `-` 之后（trim）；model = 首个 `-` 之前（trim）。
/// method 2：variables 有 "MAC"：值含 `/` → model = "AV"+`/` 之后（**无条件覆盖**）；
/// serial 未设置且值含 `-` → model = `-` 之前（C# 原样赋给 model 而非 serial，parity 保留）。
/// C# serial.Replace("AV","001A07")：serial 为 null 时 C# NRE → 整包丢弃；
/// Rust（spec §8.2）：serial 缺失时跳过替换、仍上报（serial=""）；有值则全局替换 "AV"→"001A07"。
pub fn arecont_convert(answers: &[MdnsAnswer], cfg: &crate::Config) -> Vec<Device> {
    let mut addresses: Vec<IpAddr> = Vec::new();
    let mut model: Option<String> = None;
    let mut serial: Option<String> = None;
    // C# Hashtable variables：同名取首个（(name, value) 列表保序，any 判重）
    let mut variables: Vec<(String, String)> = Vec::new();
    for a in answers {
        match &a.data {
            crate::mdns::MdnsData::A(ip) => addresses.push(*ip),
            crate::mdns::MdnsData::AAAA(ip) => addresses.push(*ip),
            // C# if (deviceModel == null)：仅首个 PTR；首个 `.` 前（无 `.` 全名）
            crate::mdns::MdnsData::Ptr(n) if model.is_none() => {
                model = Some(
                    n.split('.')
                        .next()
                        .map(str::to_string)
                        .unwrap_or_else(|| n.clone()),
                );
            }
            // C# foreach（空数组无操作，不越界）；逐项首个 `=` 拆 name/value
            crate::mdns::MdnsData::Txt(txt) => {
                for entry in txt {
                    if let Some((name, value)) = entry.split_once('=') {
                        if !variables.iter().any(|(n, _)| n == name) {
                            variables.push((name.to_string(), value.to_string()));
                        }
                    }
                }
            }
            _ => {}
        }
    }
    if addresses.is_empty() {
        return Vec::new();
    }
    let mut model = model.unwrap_or_else(|| "unknown".into());
    // method 1：model 首个 `-`；serial 未设置时取之后（trim），model 恒截为之前（trim）
    if let Some(pos) = model.find('-') {
        if serial.is_none() {
            serial = Some(model[pos + 1..].trim().to_string());
        }
        model = model[..pos].trim().to_string();
    }
    // method 2（更准确）：MAC 变量
    if let Some((_, mac)) = variables.iter().find(|(n, _)| n == "MAC") {
        if let Some(slash) = mac.find('/') {
            // C# 无条件覆盖 model（不 trim）
            model = format!("AV{}", &mac[slash + 1..]);
        }
        // C# quirk：赋给 model 而非 serial（parity 保留，不 trim）
        if serial.is_none() {
            if let Some(dash) = mac.find('-') {
                model = mac[..dash].to_string();
            }
        }
    }
    // C# serial.Replace("AV","001A07")：serial 为 null 时 NRE → 整包丢弃；
    // Rust（spec §8.2）：serial 缺失 → 跳过替换、仍上报（serial=""）
    let serial = match serial {
        Some(s) => s.replace("AV", "001A07"),
        None => String::new(),
    };
    crate::mdns::report_addresses("Arecont", 1, &addresses, &model, &serial, cfg)
}

impl ScanEngine for Arecont {
    fn name(&self) -> &str {
        "Arecont"
    }
    fn used_ports(&self) -> &[u16] {
        &[] // C# getUsedPort() = dnsBroker.getUsedPort()：5353 由 broker 自管
    }
    fn color(&self) -> u32 {
        0x00008B // Color.DarkBlue.ToArgb() → 低 24 位
    }

    fn listen(&self, ctx: Arc<EngineContext>) -> crate::Result<Vec<JoinHandle<()>>> {
        let cfg = ctx.config.clone();
        let reporter = ctx.reporter.clone();
        ctx.mdns.register_domain(
            DOMAIN,
            Arc::new(move |_dom, answers| {
                for dev in arecont_convert(answers, &cfg) {
                    let _ = reporter.send(dev);
                }
            }),
        );
        Ok(vec![]) // 无自有 socket（C# Arecont.listen 仅向 broker 注册域名）
    }

    fn scan(&self, ctx: &EngineContext) -> crate::Result<()> {
        // C# multiScanThread：4 次 PTR、间隔 750ms（首次立即）；spawn 任务立即返回。
        // plan 指定：新一轮 scan 先取消上一轮 sweep（"Thread.Abort 语义"）。
        let cancel = CancellationToken::new();
        {
            let mut sweep = self.sweep.lock().unwrap();
            if let Some(old) = sweep.replace(cancel.clone()) {
                old.cancel();
            }
        }
        let mdns = ctx.mdns.clone();
        let logger = ctx.logger.clone();
        let ctx_cancel = ctx.cancel.clone();
        let task_id = ctx.task_id;
        let ifaces = crate::iface::active_interfaces();
        let nic_ips: Vec<Ipv4Addr> = ifaces.iter().flat_map(|i| i.ipv4_addrs()).collect();
        let handle = tokio::spawn(async move {
            for i in 0..SWEEP_COUNT {
                if i > 0 {
                    tokio::select! {
                        _ = cancel.cancelled() => return,
                        _ = ctx_cancel.cancelled() => return,
                        _ = tokio::time::sleep(std::time::Duration::from_millis(SWEEP_INTERVAL_MS)) => {}
                    }
                }
                if let Err(e) = mdns.scan(DOMAIN, &nic_ips) {
                    logger.warn(task_id, &format!("Arecont sweep: scan failed: {e}"));
                }
            }
        });
        // 句柄登记进 ctx.sweeps：Scanner::stop() 取消后 join，避免悬空任务
        ctx.sweeps.lock().unwrap().push(handle);
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
            ports: Arc::new(Mutex::new(PortProvider::new())),
            reporter: tx,
            mdns,
            logger: Arc::new(crate::log::Logger::new(crate::log::Level::Debug)),
            pcap: None,
            cancel: CancellationToken::new(),
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
    fn arecont_method1_dash() {
        // PTR "AV1234-SN99.arec._tcp.local" + A → method1: model="AV1234", serial="SN99"
        // → 替换：serial 不含 "AV" → 不变
        let cfg = crate::Config::default();
        let answers = vec![a("192.168.1.50"), ptr("AV1234-SN99.arec._tcp.local")];
        let devs = arecont_convert(&answers, &cfg);
        assert_eq!(devs.len(), 1);
        assert_eq!(devs[0].protocol, "Arecont");
        assert_eq!(devs[0].version, 1);
        assert_eq!(devs[0].ip, "192.168.1.50".parse::<IpAddr>().unwrap());
        assert_eq!(devs[0].device_type, "AV1234");
        assert_eq!(devs[0].serial, "SN99");
    }

    #[test]
    fn arecont_mac_slash_overwrites_model() {
        // PTR 无 '-'（method1 不动），MAC="AV1234/5678" → model="AV5678"（无条件覆盖）
        let cfg = crate::Config::default();
        let answers = vec![
            a("192.168.1.50"),
            ptr("plain.arec._tcp.local"),
            txt(&["MAC=AV1234/5678"]),
        ];
        let devs = arecont_convert(&answers, &cfg);
        assert_eq!(devs.len(), 1);
        assert_eq!(devs[0].device_type, "AV5678");
        assert_eq!(devs[0].serial, "");
    }

    #[test]
    fn arecont_mac_dash_prefix_when_no_serial() {
        // PTR 无 '-'（method1 不动），MAC="ABCD-1234" 且 serial 空 → model="ABCD"（C# 赋给 model）
        let cfg = crate::Config::default();
        let answers = vec![
            a("192.168.1.50"),
            ptr("plain.arec._tcp.local"),
            txt(&["MAC=ABCD-1234"]),
        ];
        let devs = arecont_convert(&answers, &cfg);
        assert_eq!(devs.len(), 1);
        assert_eq!(devs[0].device_type, "ABCD");
        assert_eq!(devs[0].serial, "");
    }

    #[test]
    fn arecont_serial_av_replace() {
        // PTR "x-AV5" + A → method1 serial="AV5" → 全局替换 "AV"→"001A07" → "001A075"
        let cfg = crate::Config::default();
        let answers = vec![a("192.168.1.50"), ptr("x-AV5.arec._tcp.local")];
        let devs = arecont_convert(&answers, &cfg);
        assert_eq!(devs.len(), 1);
        assert_eq!(devs[0].device_type, "x");
        assert_eq!(devs[0].serial, "001A075");
    }

    #[test]
    fn arecont_null_serial_still_reported() {
        // A + PTR "plain"（无 '-'、无 MAC 变量）→ 1 条、serial=""
        //（C# serial.Replace 会 NRE 整包丢弃；Rust 偏离见 spec §8.2）
        let cfg = crate::Config::default();
        let answers = vec![a("192.168.1.50"), ptr("plain")];
        let devs = arecont_convert(&answers, &cfg);
        assert_eq!(devs.len(), 1);
        assert_eq!(devs[0].device_type, "plain");
        assert_eq!(devs[0].serial, "");
    }

    #[test]
    fn arecont_variables_first_wins() {
        // 同名变量取首个（C# Hashtable ContainsKey 守卫）
        let cfg = crate::Config::default();
        let answers = vec![
            a("192.168.1.50"),
            ptr("plain.arec._tcp.local"),
            txt(&["MAC=AB/1", "MAC=CD/2"]),
        ];
        let devs = arecont_convert(&answers, &cfg);
        assert_eq!(devs.len(), 1);
        assert_eq!(devs[0].device_type, "AV1");
    }

    #[test]
    fn arecont_empty_txt_harmless() {
        // 空 TXT 数组：C# foreach 无操作（**不**越界，区别于 Axis/GoogleCast）→ 正常上报
        let cfg = crate::Config::default();
        let answers = vec![a("192.168.1.50"), ptr("plain"), txt(&[])];
        let devs = arecont_convert(&answers, &cfg);
        assert_eq!(devs.len(), 1);
        assert_eq!(devs[0].device_type, "plain");
        assert_eq!(devs[0].serial, "");
    }

    #[test]
    fn arecont_empty_addresses_no_report() {
        // 仅 PTR/TXT、无 A/AAAA → 不上报
        let cfg = crate::Config::default();
        let answers = vec![ptr("AV1234-SN99.arec._tcp.local"), txt(&["MAC=AV1/2"])];
        assert!(arecont_convert(&answers, &cfg).is_empty());
    }

    #[test]
    fn arecont_autoconf_filtered() {
        // A(169.254.1.1) + A(192.168.1.5)：默认 cfg → 只报 192.168.1.5；force_zeroconf → 两个
        let cfg = crate::Config::default();
        let answers = vec![a("169.254.1.1"), a("192.168.1.5")];
        let devs = arecont_convert(&answers, &cfg);
        assert_eq!(devs.len(), 1);
        assert_eq!(devs[0].ip, "192.168.1.5".parse::<IpAddr>().unwrap());
        assert_eq!(devs[0].device_type, "unknown");
        // Arecont serial 缺失 → ""（spec §8.2 偏离；不同于 Axis 的 "unknown" 缺省）
        assert_eq!(devs[0].serial, "");
        let cfg2 = crate::Config {
            force_zeroconf: true,
            ..cfg
        };
        let devs = arecont_convert(&answers, &cfg2);
        assert_eq!(devs.len(), 2);
        assert_eq!(devs[0].ip, "192.168.1.5".parse::<IpAddr>().unwrap());
        assert_eq!(devs[1].ip, "169.254.1.1".parse::<IpAddr>().unwrap());
    }

    #[tokio::test]
    async fn fixture_replay_via_broker() {
        // broker.new_for_test + register arecont handler（接 UnboundedSender）+
        // on_packet（Arecont.selftest 原始 DNS 字节）→ 收集设备
        let mdns = MdnsBroker::new_for_test();
        let (ctx, mut rx) = ctx_with(mdns);
        Arecont::default().listen(ctx.clone()).unwrap();
        let data = tokio::fs::read(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/Arecont.selftest"
        ))
        .await
        .unwrap();
        ctx.mdns.on_packet(&data);
        let mut devs = Vec::new();
        while let Ok(d) = rx.try_recv() {
            devs.push(d);
        }
        // 期望值：对照 C# Arecont.mdnsReplyReciever 规则手工核定后填入
        //（PTR "ARECONT AV 1000-AV334455.*"、MAC 变量含 '/' → model 无条件 "AV"+其后、
        // method1 serial "AV334455" → 替换 "001A07334455"、A 240.0.16.0）
        // C# Arecont.mdnsReplyReciever：PTR 首 '.' 前 "AV1000-VIRTUAL   "（含 3 尾空格）；
        // serial "AV334455".Replace("AV","001A07") → "001A07334455"；A 240.0.16.0
        assert_eq!(devs.len(), 1);
        assert_eq!(devs[0].protocol, "Arecont");
        assert_eq!(devs[0].version, 1);
        assert_eq!(devs[0].ip.to_string(), "240.0.16.0");
        assert_eq!(devs[0].device_type, "AV1000-VIRTUAL   ");
        assert_eq!(devs[0].serial, "001A07334455");
    }
}
