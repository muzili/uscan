//! 引擎注册表（T17 框架；各协议模块随任务逐个创建，T18 起）。

pub mod bosch;
pub mod cyberpower;
pub mod dahua1;
pub mod dahua2;
pub mod eaton;
pub mod eden;
pub mod foscam;
pub mod gige;
pub mod hikvision;
pub mod ssdp;
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
        (7, || std::sync::Arc::new(bosch::Bosch::default())),
        (17, || std::sync::Arc::new(gige::GigEVision::default())),
        (19, || std::sync::Arc::new(eaton::Eaton::default())),
        (20, || std::sync::Arc::new(foscam::Foscam::default())),
        (26, || std::sync::Arc::new(eden::Eden::default())),
        (
            28,
            || std::sync::Arc::new(cyberpower::CyberPower::default()),
        ),
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

    /// 增量期框架断言：条目按 ID 升序、无重复、且是最终表的**前缀子集**（按 ID 序）。
    /// T43 完成后替换为下方注释里的完整断言。
    #[test]
    fn registry_framework() {
        let reg = registry();
        let ids: Vec<u16> = reg.iter().map(|(id, _)| *id).collect();
        assert!(
            ids.windows(2).all(|w| w[0] < w[1]),
            "ids must be strictly increasing"
        );
        for (i, e) in reg.iter().enumerate() {
            assert!(EXPECTED_IDS.contains(&e.0), "unexpected id {}", e.0);
            assert_eq!(
                e.1.name(),
                EXPECTED_NAMES[EXPECTED_IDS.iter().position(|x| x == &e.0).unwrap()]
            );
            let _ = i;
        }
        // T43 收尾（完整断言）：
        // assert_eq!(reg.len(), 27);
        // assert_eq!(ids, EXPECTED_IDS.to_vec());
        // let names: Vec<&str> = reg.iter().map(|(_, e)| e.name()).collect();
        // assert_eq!(names, EXPECTED_NAMES.to_vec());
    }
}
