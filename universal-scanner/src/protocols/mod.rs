//! 引擎注册表（T17 框架；各协议模块随任务逐个创建，T18 起）。

pub mod advantech;
pub mod arecont;
pub mod axis;
pub mod bosch;
pub mod cyberpower;
pub mod dahua1;
pub mod dahua2;
pub mod eaton;
pub mod eden;
pub mod foscam;
pub mod gige;
pub mod googlecast;
pub mod hanwha;
pub mod hikvision;
pub mod lantronix;
pub mod microchip;
pub mod mssql;
pub mod nicevision;
pub mod panasonic;
pub mod sony;
pub mod ssdp;
pub mod ubiquiti;
pub mod vision360;
pub mod vivotek;
pub mod vstarcam;
pub mod wsd;

pub type EngineBuilder = fn() -> std::sync::Arc<dyn crate::engine::ScanEngine>;

/// 顺序与 ID 沿用 C# Program.cs（ID 决定 selftest 源地址 240.0.<id>.<minor>）。
/// 21/22/27 为 C# 已禁用空位（Dlink/Hid/Microsens），不出现。
/// 表从空开始，T18–T43 每完成一个引擎任务按 ID 升序追加条目。
pub fn registry() -> Vec<(u16, std::sync::Arc<dyn crate::engine::ScanEngine>)> {
    // 增量填充（按 ID 升序追加）
    let builders: Vec<(u16, EngineBuilder)> = vec![
        (1, || std::sync::Arc::new(ssdp::Ssdp::default())),
        (2, || std::sync::Arc::new(wsd::Wsd::default())),
        (3, || std::sync::Arc::new(dahua1::Dahua1::default())),
        (4, || std::sync::Arc::new(dahua2::Dahua2::default())),
        (5, || std::sync::Arc::new(hikvision::Hikvision::default())),
        (6, || std::sync::Arc::new(axis::Axis)),
        (7, || std::sync::Arc::new(bosch::Bosch::default())),
        (8, || std::sync::Arc::new(googlecast::GoogleCast)),
        (9, || std::sync::Arc::new(hanwha::Hanwha::default())),
        (10, || std::sync::Arc::new(vivotek::Vivotek::default())),
        (11, || std::sync::Arc::new(sony::Sony::default())),
        (12, || std::sync::Arc::new(ubiquiti::Ubiquiti::default())),
        (13, || std::sync::Arc::new(vision360::Vision360::default())),
        (
            14,
            || std::sync::Arc::new(nicevision::NiceVision::default()),
        ),
        (15, || std::sync::Arc::new(panasonic::Panasonic::default())),
        (16, || std::sync::Arc::new(arecont::Arecont::default())),
        (17, || std::sync::Arc::new(gige::GigEVision::default())),
        (18, || std::sync::Arc::new(vstarcam::Vstarcam::default())),
        (19, || std::sync::Arc::new(eaton::Eaton::default())),
        (20, || std::sync::Arc::new(foscam::Foscam::default())),
        (23, || std::sync::Arc::new(lantronix::Lantronix::default())),
        (24, || std::sync::Arc::new(microchip::Microchip::default())),
        (25, || std::sync::Arc::new(advantech::Advantech::default())),
        (26, || std::sync::Arc::new(eden::Eden::default())),
        (
            28,
            || std::sync::Arc::new(cyberpower::CyberPower::default()),
        ),
        (29, || std::sync::Arc::new(mssql::Mssql::default())),
    ];
    builders.iter().map(|(id, b)| (*id, b())).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    const EXPECTED_IDS: [u16; 27] = [
        1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 23, 24, 25, 26, 28,
        29, 30,
    ];
    const EXPECTED_NAMES: [&str; 27] = [
        "SSDP",
        "WSDiscovery",
        "Dahua",
        "Dahua",
        "Hikvision",
        "Axis",
        "Bosch",
        "Google",
        "Hanwha",
        "Vivotek",
        "Sony",
        "Ubiquiti",
        "360Vision",
        "NiceVision",
        "Panasonic",
        "Arecont",
        "GigEVision",
        "VStarcam",
        "Eaton",
        "Foscam",
        "Lantronix",
        "Microchip",
        "Advantech",
        "Eden",
        "CyberPower",
        "MSSQL",
        "ARP",
    ];

    /// T43 收尾（恢复 T17 放宽的完整断言）：名称列表 + ID 集合全量比对（按 ID 升序）。
    /// 注：plan 的最终目标是 27 引擎（含 ARP id 30）；ARP 由 T44–T47 添加，
    /// 故当前断言现有 26 引擎 [1..=20, 23..=26, 28, 29]（自最终表剔除 id 30 派生，
    /// T44–T47 加 ARP 后去掉过滤即恢复 27 全量比对）。`list-protocols` 数据源就绪。
    #[test]
    fn registry_complete() {
        let reg = registry();
        let ids: Vec<u16> = reg.iter().map(|(id, _)| *id).collect();
        let current_ids: Vec<u16> = EXPECTED_IDS
            .iter()
            .copied()
            .filter(|id| *id != 30) // ARP 未实现（T44–T47）
            .collect();
        assert_eq!(ids, current_ids);
        let names: Vec<&str> = reg.iter().map(|(_, e)| e.name()).collect();
        let current_names: Vec<&str> = EXPECTED_IDS
            .iter()
            .zip(EXPECTED_NAMES.iter())
            .filter(|(id, _)| **id != 30)
            .map(|(_, n)| *n)
            .collect();
        assert_eq!(names, current_names);
    }
}
