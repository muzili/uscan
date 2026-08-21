//! 集成测试：replays() 全量重放 + 期望元组核定（T50）。
//!
//! 每条期望元组对照 C# 各引擎 `reciever`（`/home/joshua/ws/UniversalScanner/UniversalScanner/*.cs`）
//! 推演而来：长度/魔数校验 → 字段偏移 → 回退链 → 上报条件。
//! `expected_tuples()` 与 `replays()` 的 (engine_name, fixture) 键集必须双向一致（无兜底分支），
//! 31 个 fixture（27 引擎 + Bosch/Microchip/Lantronix/Foscam 的第二 fixture）各有显式期望。

use std::collections::{BTreeMap, BTreeSet};

/// 期望元组 (protocol, version, ip, device_type, serial)
type Tuple = (String, u32, String, String, String);
/// 期望表键 (engine_name, fixture)
type Key = (String, String);

fn expected_tuples() -> BTreeMap<Key, Vec<Tuple>> {
    let mut m = BTreeMap::new();
    // (protocol, version, ip, device_type, serial)
    m.insert(
        ("SSDP".into(), "SSDP.selftest".into()),
        vec![(
            "SSDP".into(),
            0,
            "240.0.1.0".into(),
            "Virtual/1.0".into(),
            "unique-id-12345678".into(),
        )],
    );
    // Wsdiscovery.cs：name="WSDiscovery"，version 0
    m.insert(
        ("WSDiscovery".into(), "Wsdiscovery.selftest".into()),
        vec![(
            "WSDiscovery".into(),
            0,
            "240.0.2.0".into(),
            "Virtual Device".into(),
            "11223344-5566-7788-9900-000000000002".into(),
        )],
    );
    // Dahua1：wire 顺序 240.0.3.0（C# 反转 quirk 已修正，spec §8.2）；v4(v1)+v6(v2)
    m.insert(
        ("Dahua".into(), "Dahua1.selftest".into()),
        vec![
            (
                "Dahua".into(),
                1,
                "240.0.3.0".into(),
                "Virtual".into(),
                "123456789".into(),
            ),
            (
                "Dahua".into(),
                2,
                "fe80::1".into(),
                "Virtual".into(),
                "123456789".into(),
            ),
        ],
    );
    // Dahua2.cs（JSON）：DeviceType="Virtual (JSON)"，version 2，IP 取 JSON 字符串（非 LE）
    m.insert(
        ("Dahua".into(), "Dahua2.selftest".into()),
        vec![
            (
                "Dahua".into(),
                2,
                "240.0.4.0".into(),
                "Virtual (JSON)".into(),
                "123456789".into(),
            ),
            (
                "Dahua".into(),
                2,
                "fe80::".into(),
                "Virtual (JSON)".into(),
                "123456789".into(),
            ),
        ],
    );
    // Hikvision.cs：version 1；IPv4 + IPv6("::" 解析成功) 两条
    m.insert(
        ("Hikvision".into(), "Hikvision.selftest".into()),
        vec![
            (
                "Hikvision".into(),
                1,
                "240.0.5.0".into(),
                "Virtual".into(),
                "Virtual-123456789".into(),
            ),
            (
                "Hikvision".into(),
                1,
                "::".into(),
                "Virtual".into(),
                "Virtual-123456789".into(),
            ),
        ],
    );
    // Axis.cs（broker，源 240.0.0.0）：PTR→"Virtual"，serial "001122334455"
    m.insert(
        ("Axis".into(), "Axis.selftest".into()),
        vec![(
            "Axis".into(),
            1,
            "240.0.6.0".into(),
            "Virtual".into(),
            "001122334455".into(),
        )],
    );
    // Bosch.cs 二进制：littleEndian32(ipv4)→0.7.0.240（LE quirk），deviceType=name="Bosch"
    m.insert(
        ("Bosch".into(), "Bosch.bin.selftest".into()),
        vec![(
            "Bosch".into(),
            1,
            "0.7.0.240".into(),
            "Bosch".into(),
            "00:11:22:33:44:55".into(),
        )],
    );
    // Bosch.cs XML：version 2；IPv4(240.0.7.1)+IPv6(fe80::1) 两条
    m.insert(
        ("Bosch".into(), "Bosch.xml.selftest".into()),
        vec![
            (
                "Bosch".into(),
                2,
                "240.0.7.1".into(),
                "Virtual (XML)".into(),
                "12345678:12345678".into(),
            ),
            (
                "Bosch".into(),
                2,
                "fe80::1".into(),
                "Virtual (XML)".into(),
                "12345678:12345678".into(),
            ),
        ],
    );
    // GoogleCast.cs（broker）：friendlyName="Google Virtual"
    m.insert(
        ("Google".into(), "GoogleCast.selftest".into()),
        vec![(
            "Google".into(),
            1,
            "240.0.8.0".into(),
            "Google Virtual".into(),
            "Google Virtual".into(),
        )],
    );
    m.insert(
        ("Hanwha".into(), "Hanwha.selftest".into()),
        vec![(
            "Hanwha".into(),
            1,
            "240.0.9.0".into(),
            "Virtual".into(),
            "00:11:22:33:44:55".into(),
        )],
    );
    // Vivotek.cs：{0:X2}:... 大写 hex MAC
    m.insert(
        ("Vivotek".into(), "Vivotek.selftest".into()),
        vec![(
            "Vivotek".into(),
            1,
            "240.0.10.0".into(),
            "Virtual".into(),
            "00:11:22:33:44:55".into(),
        )],
    );
    m.insert(
        ("Sony".into(), "Sony.selftest".into()),
        vec![(
            "Sony".into(),
            1,
            "240.0.11.0".into(),
            "Virtual".into(),
            "123456789".into(),
        )],
    );
    // Ubiquiti.cs：{0:X2}:... 大写 hex MAC
    m.insert(
        ("Ubiquiti".into(), "Ubiquiti.selftest".into()),
        vec![(
            "Ubiquiti".into(),
            1,
            "240.0.12.0".into(),
            "VIRTUAL".into(),
            "00:11:22:33:44:55".into(),
        )],
    );
    m.insert(
        ("360Vision".into(), "360Vision.selftest".into()),
        vec![(
            "360Vision".into(),
            1,
            "240.0.13.0".into(),
            "IPDOME".into(),
            "00:11:22:33:44:55".into(),
        )],
    );
    // NiceVision.cs：new IPAddress(uint 网络序)→0.14.0.240（反转 quirk）
    m.insert(
        ("NiceVision".into(), "NiceVision.selftest".into()),
        vec![(
            "NiceVision".into(),
            1,
            "0.14.0.240".into(),
            "Virtual".into(),
            "00:11:22:33:44:55".into(),
        )],
    );
    // Panasonic.cs：Encoding.UTF8.GetString(values[fullname]) 保留 NUL→"Virtual"+9×NUL
    m.insert(
        ("Panasonic".into(), "Panasonic.selftest".into()),
        vec![(
            "Panasonic".into(),
            1,
            "240.0.15.0".into(),
            "Virtual\0\0\0\0\0\0\0\0\0".into(),
            "00:11:22:33:44:55".into(),
        )],
    );
    // Arecont.cs（broker）：PTR 首 '.' 前含 3 尾空格；serial Replace("AV","001A07")
    m.insert(
        ("Arecont".into(), "Arecont.selftest".into()),
        vec![(
            "Arecont".into(),
            1,
            "240.0.16.0".into(),
            "AV1000-VIRTUAL   ".into(),
            "001A07334455".into(),
        )],
    );
    // GigEVision.cs：new IPAddress(long 网络序)→0.17.0.240（反转 quirk）；version 0（vendor 名）
    m.insert(
        ("GigEVision".into(), "GigEVision.selftest".into()),
        vec![(
            "GigEVision".into(),
            0,
            "0.17.0.240".into(),
            "Virtual device".into(),
            "123456789".into(),
        )],
    );
    m.insert(
        ("VStarcam".into(), "Vstarcam.selftest".into()),
        vec![(
            "VStarcam".into(),
            1,
            "240.0.18.0".into(),
            "Virtual Camera".into(),
            "123456789".into(),
        )],
    );
    m.insert(
        ("Eaton".into(), "Eaton.selftest".into()),
        vec![(
            "Eaton".into(),
            1,
            "240.0.19.0".into(),
            "Eaton Virtual".into(),
            "123456789".into(),
        )],
    );
    // Foscam.cs：deviceType→"Type 8"；ipBytes 低位在前（identity 序）
    m.insert(
        ("Foscam".into(), "Foscam.selftest".into()),
        vec![(
            "Foscam".into(),
            1,
            "240.0.20.0".into(),
            "Type 8".into(),
            "0123456789".into(),
        )],
    );
    // Foscam_cipher：cipherKey XOR 解密后 ipBytes→240.0.20.1
    m.insert(
        ("Foscam".into(), "Foscam_cipher.selftest".into()),
        vec![(
            "Foscam".into(),
            1,
            "240.0.20.1".into(),
            "Type 8".into(),
            "0123456789".into(),
        )],
    );
    // Lantronix.cs 非 Vauban 分支：device_type="unknown"
    m.insert(
        ("Lantronix".into(), "Lantronix.selftest".into()),
        vec![(
            "Lantronix".into(),
            1,
            "240.0.23.0".into(),
            "unknown".into(),
            "00:11:22:33:44:55".into(),
        )],
    );
    // Lantronix.cs Vauban 分支：model→"Verso+ 4"（Vauban.selftest[0x0C]=02 [0x0D]=04）
    m.insert(
        ("Lantronix".into(), "Vauban.selftest".into()),
        vec![(
            "Vauban".into(),
            1,
            "240.0.23.1".into(),
            "Verso+ 4".into(),
            "00:11:22:33:44:55".into(),
        )],
    );
    // Microchip.cs：manufacturer→protocol，product→device_type，mac 文本（短横）
    m.insert(
        ("Microchip".into(), "Microchip.selftest".into()),
        vec![(
            "Microchip".into(),
            1,
            "240.0.24.0".into(),
            "Virtual".into(),
            "00-11-22-33-44-55".into(),
        )],
    );
    m.insert(
        ("Microchip".into(), "GCE.selftest".into()),
        vec![(
            "GCE".into(),
            1,
            "240.0.24.0".into(),
            "Virtual".into(),
            "00-11-22-33-44-55".into(),
        )],
    );
    // Advantech.cs：Encoding.UTF8.GetString(deviceModelBinary) 保留 NUL→"Virtual device\0"
    m.insert(
        ("Advantech".into(), "Advantech.selftest".into()),
        vec![(
            "Advantech".into(),
            1,
            "240.0.25.0".into(),
            "Virtual device\0".into(),
            "00:11:22:33:44:55".into(),
        )],
    );
    // EdenOptima.cs：device_type 硬编码 "Optima box"
    m.insert(
        ("Eden".into(), "Eden.selftest".into()),
        vec![(
            "Eden".into(),
            1,
            "240.0.26.0".into(),
            "Optima box".into(),
            "00:11:22:33:44:55".into(),
        )],
    );
    // CyberPower.cs：mac.ToString()（PhysicalAddress）→大写 12 hex 无分隔
    m.insert(
        ("CyberPower".into(), "CyberPower.selftest".into()),
        vec![(
            "CyberPower".into(),
            1,
            "240.0.28.0".into(),
            "Virtual".into(),
            "001122334455".into(),
        )],
    );
    // MSSQL.cs：InstanceName→device_type，ServerName→serial
    m.insert(
        ("MSSQL".into(), "MSSQL.selftest".into()),
        vec![(
            "MSSQL".into(),
            1,
            "240.0.29.0".into(),
            "MSSQL".into(),
            "Server123456".into(),
        )],
    );
    // Arp 引擎 parse（源 240.0.30.0）：arp_reply 解析
    m.insert(
        ("ARP".into(), "Arp.selftest".into()),
        vec![(
            "ARP".into(),
            0,
            "192.168.1.50".into(),
            "GARP".into(),
            "00:11:22:33:44:55".into(),
        )],
    );
    m
}

#[test]
fn selftest_all_fixtures() {
    let expected = expected_tuples();
    let all = universal_scanner::selftest::replay_all().unwrap();
    assert_eq!(all.len(), 31, "replays() must list all 31 fixtures");

    // 双向覆盖（无兜底）：replays() 的 (engine_name, fixture) 键集 == expected 的键集。
    let replay_keys: BTreeSet<(String, String)> = all
        .iter()
        .map(|(re, _)| (re.engine_name.clone(), re.fixture.clone()))
        .collect();
    let expected_keys: BTreeSet<(String, String)> = expected.keys().cloned().collect();
    assert_eq!(
        replay_keys, expected_keys,
        "replays() 与期望表必须双向一致（每个 fixture 都有显式期望，无遗漏/多余）"
    );

    for (re, devs) in &all {
        let exp = expected
            .get(&(re.engine_name.clone(), re.fixture.clone()))
            .expect("expected tuple missing for replay");
        assert_eq!(devs.len(), exp.len(), "{}: 设备条数不符", re.fixture);
        for (i, (d, e)) in devs.iter().zip(exp.iter()).enumerate() {
            assert_eq!(
                (
                    d.protocol.as_str(),
                    d.version,
                    d.device_type.as_str(),
                    d.serial.as_str()
                ),
                (e.0.as_str(), e.1, e.3.as_str(), e.4.as_str()),
                "{}[{}]: (protocol,version,type,serial) 元组不符（C# 核定）",
                re.fixture,
                i
            );
            assert_eq!(
                d.ip.to_string(),
                e.2,
                "{}[{}]: ip 元组不符（C# 核定）",
                re.fixture,
                i
            );
        }
    }
}
