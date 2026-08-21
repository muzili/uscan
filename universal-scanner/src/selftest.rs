//! selftest fixture 加载与协议解析回归测试工具。
//!
//! C# `Program.selfTest` 的 Rust 等价：`replays()` 给出全部重放项（fixture + 源地址 + 引擎），
//! `replay()` 执行单次重放（UDP → `engine.parse`；mDNS 消费者 → broker 分发；ARP → `Arp::parse`），
//! `replay_all()` 全量重放（CLI selftest / 集成测试用）。
//!
//! 源地址沿用 C# 语义：UDP 引擎 `240.0.<id>.0:1024`（id = 注册表 ID）；
//! mDNS 消费者（broker 未注册 id=0）`240.0.0.0:1024`；ARP `240.0.30.0:1024`。
//! 例外逐条见 `replays()` 内注释（对照 C# 各引擎 `#if DEBUG selfTest(...)`）。

use crate::devices::Device;
use crate::engine::{EngineContext, ScanEngine};
use crate::mdns::MdnsBroker;
use crate::ports::PortProvider;
use std::net::{Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use tokio_util::sync::CancellationToken;

/// 一次 fixture 重放（C# DEBUG selfTest 调用的一条记录）。
pub struct Replay {
    /// 注册表 name（显示用）。Dahua1/Dahua2 同名 "Dahua"，靠 fixture 区分引擎。
    pub engine_name: String,
    /// tests/fixtures/<fixture>
    pub fixture: String,
    /// 重放源地址（C# selfTest 发送地址）。
    pub source: SocketAddr,
}

impl Replay {
    /// 240.0.<id>.<minor>（UDP 引擎默认 id=注册表 ID）。
    fn addr(id: u8, minor: u8) -> SocketAddr {
        SocketAddr::new(Ipv4Addr::new(240, 0, id, minor).into(), 1024)
    }
}

fn fixture_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
}

/// 完整映射（C# DEBUG selfTest 行为，spec §5.4）。源端口统一 1024。
///
/// 逐行对照 C# 各引擎 `#if DEBUG selfTest(...)`：
/// - 24 个默认引擎：`<name>.selftest`，源 `240.0.<id>.0`（id = 注册表 ID）。
/// - Dahua1/Dahua2：注册表 name 是 "Dahua"，C# 用类名显式文件，源 240.0.3.0 / 240.0.4.0。
/// - Bosch：两条重放（bin + xml），源 240.0.7.0。
/// - Microchip：两条重放（Microchip + GCE），源 240.0.24.0。
/// - Lantronix / Vauban：源 240.0.23.0 / 240.0.23.1（Vauban minor=1）。
/// - Foscam：两条重放（Foscam + Foscam_cipher），源 240.0.20.0（Rust 用实际大小写）。
/// - Axis / Google / Arecont：mDNS 消费者，broker 未注册 id=0 → 源 240.0.0.0。
/// - ARP：合成 fixture，源 240.0.30.0（T45）。
pub fn replays() -> Vec<Replay> {
    let r = |engine_name: &str, fixture: &str, id: u8, minor: u8| Replay {
        engine_name: engine_name.to_string(),
        fixture: fixture.to_string(),
        source: Replay::addr(id, minor),
    };
    vec![
        // 1..5（Dahua 用类名文件）
        r("SSDP", "SSDP.selftest", 1, 0),
        r("WSDiscovery", "Wsdiscovery.selftest", 2, 0),
        r("Dahua", "Dahua1.selftest", 3, 0),
        r("Dahua", "Dahua2.selftest", 4, 0),
        r("Hikvision", "Hikvision.selftest", 5, 0),
        // 6 Axis（mDNS，broker id=0）
        r("Axis", "Axis.selftest", 0, 0),
        // 7 Bosch（两条）
        r("Bosch", "Bosch.bin.selftest", 7, 0),
        r("Bosch", "Bosch.xml.selftest", 7, 0),
        // 8 Google（mDNS，broker id=0）
        r("Google", "GoogleCast.selftest", 0, 0),
        // 9..16
        r("Hanwha", "Hanwha.selftest", 9, 0),
        r("Vivotek", "Vivotek.selftest", 10, 0),
        r("Sony", "Sony.selftest", 11, 0),
        r("Ubiquiti", "Ubiquiti.selftest", 12, 0),
        r("360Vision", "360Vision.selftest", 13, 0),
        r("NiceVision", "NiceVision.selftest", 14, 0),
        r("Panasonic", "Panasonic.selftest", 15, 0),
        r("Arecont", "Arecont.selftest", 0, 0),
        // 17..20（Foscam 两条）
        r("GigEVision", "GigEVision.selftest", 17, 0),
        r("VStarcam", "Vstarcam.selftest", 18, 0),
        r("Eaton", "Eaton.selftest", 19, 0),
        r("Foscam", "Foscam.selftest", 20, 0),
        r("Foscam", "Foscam_cipher.selftest", 20, 0),
        // 21/22 空位（Dlink/Hid，C# 已禁用）
        // 23 Lantronix + Vauban（Vauban minor=1）
        r("Lantronix", "Lantronix.selftest", 23, 0),
        r("Lantronix", "Vauban.selftest", 23, 1),
        // 24 Microchip + GCE
        r("Microchip", "Microchip.selftest", 24, 0),
        r("Microchip", "GCE.selftest", 24, 0),
        // 25..29
        r("Advantech", "Advantech.selftest", 25, 0),
        r("Eden", "Eden.selftest", 26, 0),
        // 27 空位（Microsens）
        r("CyberPower", "CyberPower.selftest", 28, 0),
        r("MSSQL", "MSSQL.selftest", 29, 0),
        // 30 ARP
        r("ARP", "Arp.selftest", 30, 0),
    ]
}

/// 按 Replay 选引擎。Dahua（同名两引擎）与 Lantronix（Lantronix/Vauban 共用引擎）靠 fixture 区分。
fn engine_for(re: &Replay) -> Arc<dyn ScanEngine> {
    use crate::protocols;
    match re.engine_name.as_str() {
        "SSDP" => Arc::new(protocols::ssdp::Ssdp::default()),
        "WSDiscovery" => Arc::new(protocols::wsd::Wsd::default()),
        "Dahua" if re.fixture.starts_with("Dahua1") => {
            Arc::new(protocols::dahua1::Dahua1::default())
        }
        "Dahua" => Arc::new(protocols::dahua2::Dahua2::default()),
        "Hikvision" => Arc::new(protocols::hikvision::Hikvision::default()),
        "Bosch" => Arc::new(protocols::bosch::Bosch::default()),
        "Hanwha" => Arc::new(protocols::hanwha::Hanwha::default()),
        "Vivotek" => Arc::new(protocols::vivotek::Vivotek::default()),
        "Sony" => Arc::new(protocols::sony::Sony::default()),
        "Ubiquiti" => Arc::new(protocols::ubiquiti::Ubiquiti::default()),
        "360Vision" => Arc::new(protocols::vision360::Vision360::default()),
        "NiceVision" => Arc::new(protocols::nicevision::NiceVision::default()),
        "Axis" => Arc::new(protocols::axis::Axis),
        "Google" => Arc::new(protocols::googlecast::GoogleCast),
        "Arecont" => Arc::new(protocols::arecont::Arecont::default()),
        "Panasonic" => Arc::new(protocols::panasonic::Panasonic::default()),
        "GigEVision" => Arc::new(protocols::gige::GigEVision::default()),
        "VStarcam" => Arc::new(protocols::vstarcam::Vstarcam::default()),
        "Eaton" => Arc::new(protocols::eaton::Eaton::default()),
        "Foscam" => Arc::new(protocols::foscam::Foscam::default()),
        "Lantronix" => Arc::new(protocols::lantronix::Lantronix::default()),
        "Microchip" => Arc::new(protocols::microchip::Microchip::default()),
        "Advantech" => Arc::new(protocols::advantech::Advantech::default()),
        "Eden" => Arc::new(protocols::eden::Eden::default()),
        "CyberPower" => Arc::new(protocols::cyberpower::CyberPower::default()),
        "MSSQL" => Arc::new(protocols::mssql::Mssql::default()),
        other => panic!("unknown selftest engine: {other}"),
    }
}

/// mDNS 消费者重放：新 broker + 引擎 listen 注册 handler（接测试 reporter 通道）+ broker.on_packet。
/// C# selfTest 语义：源地址 240.0.0.0，task_id 0。
fn replay_mdns(re: &Replay, bytes: &[u8]) -> Vec<Device> {
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
    let mdns = MdnsBroker::new(
        Arc::new(crate::log::Logger::new(crate::log::Level::Fatal)),
        CancellationToken::new(),
    );
    let ctx = Arc::new(EngineContext {
        config: Arc::new(crate::Config::default()),
        ports: Arc::new(Mutex::new(PortProvider::new())),
        reporter: tx,
        mdns,
        logger: Arc::new(crate::log::Logger::new(crate::log::Level::Fatal)),
        pcap: None,
        cancel: CancellationToken::new(),
        task_id: 0,
        sweeps: Arc::new(Mutex::new(Vec::new())),
    });
    let engine = engine_for(re);
    engine
        .listen(ctx.clone())
        .expect("mdns listen (register domain)");
    ctx.mdns.on_packet(bytes);
    let mut devs = Vec::new();
    while let Ok(d) = rx.try_recv() {
        devs.push(d);
    }
    devs
}

/// 执行一次重放：UDP 引擎 → `engine.parse(source, bytes)`；
/// mDNS 消费者 → broker 分发（源 240.0.0.0）；ARP → `Arp.parse`（源 240.0.30.0）。
pub fn replay(re: &Replay) -> crate::Result<Vec<Device>> {
    let bytes = std::fs::read(fixture_dir().join(&re.fixture))?;
    let devs = match re.engine_name.as_str() {
        "Axis" | "Google" | "Arecont" => replay_mdns(re, &bytes),
        "ARP" => {
            let engine = crate::protocols::arp::Arp::default();
            engine.parse(re.source, &bytes)
        }
        _ => engine_for(re).parse(re.source, &bytes),
    };
    Ok(devs)
}

/// 全部重放（CLI selftest 命令用）。
pub fn replay_all() -> crate::Result<Vec<(Replay, Vec<Device>)>> {
    replays()
        .into_iter()
        .map(|re| replay(&re).map(|devs| (re, devs)))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 覆盖性：tests/fixtures 下每个 *.selftest 文件都在 replays() 中出现（不多不少）。
    #[test]
    fn replays_cover_every_fixture_file() {
        let mut listed: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
        for entry in std::fs::read_dir(fixture_dir()).unwrap() {
            let p = entry.unwrap().path();
            if let Some(name) = p.file_name().and_then(|n| n.to_str()) {
                if name.ends_with(".selftest") {
                    listed.insert(name.to_string());
                }
            }
        }
        let mut mapped: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
        for re in replays() {
            assert!(
                fixture_dir().join(&re.fixture).exists(),
                "replay fixture missing on disk: {}",
                re.fixture
            );
            mapped.insert(re.fixture.clone());
        }
        let missing_in_map: Vec<String> = listed.difference(&mapped).cloned().collect();
        let extra_in_map: Vec<String> = mapped.difference(&listed).cloned().collect();
        assert!(
            missing_in_map.is_empty(),
            "fixture files without a replay entry: {missing_in_map:?}"
        );
        assert!(
            extra_in_map.is_empty(),
            "replay entries without a fixture file: {extra_in_map:?}"
        );
    }
}
