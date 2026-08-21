use std::collections::BTreeMap;
use std::net::IpAddr;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Device {
    pub protocol: String,
    pub version: u32,
    pub ip: IpAddr,
    /// 大写冒号格式（`AA:BB:CC:DD:EE:FF`）；协议应答不含 MAC 时为空串。
    pub mac: String,
    pub device_type: String,
    pub serial: String,
}

/// 把各协议 MAC 字符串（冒号/短横/无分隔、大小写混用）统一为输出列格式
/// `AA:BB:CC:DD:EE:FF`；剥离分隔符后不足 12 个 hex 位 → 原样返回（协议原始值）。
pub fn normalize_mac(raw: &str) -> String {
    let hex: String = raw
        .chars()
        .filter(|c| c.is_ascii_hexdigit())
        .collect::<String>()
        .to_ascii_uppercase();
    if hex.len() == 12 {
        (0..6)
            .map(|i| &hex[i * 2..i * 2 + 2])
            .collect::<Vec<_>>()
            .join(":")
    } else {
        raw.to_string()
    }
}

/// 对应 C# UI `addDevice`：去重（IP 或 protocol+IP）、版本择优（严格大于）、地址族过滤。
/// 键使用 IP 的 canonical 字符串（`IpAddr` Display 形式）。
pub struct DeviceTable {
    force_generic: bool,
    entries: BTreeMap<String, Device>,
    order: Vec<String>, // 发现顺序（--batch 输出用）
}

impl DeviceTable {
    pub fn new(force_generic_protocols: bool) -> Self {
        Self {
            force_generic: force_generic_protocols,
            entries: BTreeMap::new(),
            order: Vec::new(),
        }
    }

    /// Some(device) = 应输出一行（新增或更新）；None = 过滤/无变化。
    pub fn add(&mut self, device: Device, enable_ipv4: bool, enable_ipv6: bool) -> Option<Device> {
        let family_ok = match device.ip {
            IpAddr::V4(_) => enable_ipv4,
            IpAddr::V6(_) => enable_ipv6,
        };
        if !family_ok {
            return None;
        }
        let key = if self.force_generic {
            format!("{}|{}", device.protocol, device.ip)
        } else {
            device.ip.to_string()
        };
        match self.entries.get(&key) {
            None => {
                self.order.push(key.clone());
                let d = device.clone();
                self.entries.insert(key, d.clone());
                Some(d)
            }
            Some(existing) if device.version > existing.version => {
                // mac 择优：新值空 → 保留旧值（尽量不丢 MAC，与 ip 保留语义一致）
                let mac = if device.mac.is_empty() {
                    existing.mac.clone()
                } else {
                    device.mac
                };
                let updated = Device {
                    protocol: device.protocol,
                    version: device.version,
                    ip: existing.ip,
                    mac,
                    device_type: device.device_type,
                    serial: device.serial,
                };
                self.entries.insert(key, updated.clone());
                Some(updated)
            }
            _ => None,
        }
    }

    /// 发现顺序返回全部条目（--batch）。
    pub fn all(&self) -> Vec<&Device> {
        self.order
            .iter()
            .filter_map(|k| self.entries.get(k))
            .collect()
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;

    fn dev(proto: &str, version: u32, ip: &str, ty: &str, serial: &str) -> Device {
        Device {
            protocol: proto.into(),
            version,
            ip: ip.parse::<IpAddr>().unwrap(),
            mac: String::new(),
            device_type: ty.into(),
            serial: serial.into(),
        }
    }

    fn dev_with_mac(mac: &str) -> Device {
        let mut d = dev("X", 1, "10.0.0.5", "t", "s");
        d.mac = mac.into();
        d
    }

    #[test]
    fn new_device_emitted() {
        let mut t = DeviceTable::new(false);
        let d = dev("SSDP", 0, "10.0.0.5", "t", "s");
        assert_eq!(t.add(d.clone(), true, false), Some(d));
    }

    // 注意：版本择优是严格大于（C# UI 语义 version > 现有）。ARP v0 → 厂商 v1 才替换。
    #[test]
    fn same_version_dropped() {
        let mut t = DeviceTable::new(false);
        t.add(
            dev("ARP", 0, "10.0.0.5", "ARP", "aa:bb:cc:dd:ee:ff"),
            true,
            false,
        );
        let d = dev("SSDP", 0, "10.0.0.5", "cam", "SN1");
        assert_eq!(t.add(d.clone(), true, false), None); // 同 IP 同 version：0 vs 0 → None
    }

    #[test]
    fn arp_v0_then_vendor_v1() {
        let mut t = DeviceTable::new(false);
        t.add(
            dev("ARP", 0, "10.0.0.5", "ARP", "aa:bb:cc:dd:ee:ff"),
            true,
            false,
        );
        let d = dev("Dahua", 1, "10.0.0.5", "cam", "SN1");
        assert_eq!(t.add(d.clone(), true, false), Some(d));
        // 之后再来 ARP v0 → 不输出
        assert_eq!(
            t.add(
                dev("ARP", 0, "10.0.0.5", "ARP", "aa:bb:cc:dd:ee:ff"),
                true,
                false
            ),
            None
        );
    }

    // mac 择优（版本更新时）：新值非空 → 取新；新值空 → 保留旧值。
    #[test]
    fn mac_retained_when_new_empty() {
        let mut t = DeviceTable::new(false);
        t.add(dev_with_mac("AA:BB:CC:DD:EE:FF"), true, false);
        let higher = dev("Y", 2, "10.0.0.5", "t", "s2");
        let updated = t.add(higher, true, false).unwrap();
        assert_eq!(updated.mac, "AA:BB:CC:DD:EE:FF");
    }

    #[test]
    fn mac_replaced_when_new_nonempty() {
        let mut t = DeviceTable::new(false);
        t.add(dev("X", 1, "10.0.0.5", "t", "s"), true, false);
        let mut higher = dev_with_mac("11:22:33:44:55:66");
        higher.version = 2;
        let updated = t.add(higher, true, false).unwrap();
        assert_eq!(updated.mac, "11:22:33:44:55:66");
    }

    #[test]
    fn normalize_mac_variants() {
        assert_eq!(normalize_mac("aa-bb-cc-dd-ee-ff"), "AA:BB:CC:DD:EE:FF");
        assert_eq!(normalize_mac("001122334455"), "00:11:22:33:44:55");
        assert_eq!(normalize_mac("00:11:22:33:44:55"), "00:11:22:33:44:55");
        assert_eq!(normalize_mac("AA-BB-CC-DD-EE-FF"), "AA:BB:CC:DD:EE:FF");
        // 非 12 hex → 原样（不误伤序列号之类的串）
        assert_eq!(normalize_mac("123456789"), "123456789");
        assert_eq!(normalize_mac(""), "");
    }

    #[test]
    fn lower_or_equal_version_dropped() {
        let mut t = DeviceTable::new(false);
        t.add(dev("Dahua", 2, "10.0.0.5", "cam", "SN1"), true, false);
        assert_eq!(
            t.add(dev("SSDP", 0, "10.0.0.5", "t", "s"), true, false),
            None
        );
        assert_eq!(
            t.add(dev("Dahua", 2, "10.0.0.5", "cam", "SN2"), true, false),
            None
        );
    }

    #[test]
    fn generic_mode_splits_by_protocol() {
        let mut t = DeviceTable::new(true);
        assert!(t
            .add(dev("ARP", 0, "10.0.0.5", "ARP", "m"), true, false)
            .is_some());
        assert!(t
            .add(dev("SSDP", 0, "10.0.0.5", "t", "s"), true, false)
            .is_some());
    }

    #[test]
    fn family_filter() {
        let mut t = DeviceTable::new(false);
        assert_eq!(t.add(dev("X", 1, "fe80::1", "t", "s"), true, false), None);
        assert_eq!(t.add(dev("X", 1, "10.0.0.9", "t", "s"), false, true), None);
        assert!(t
            .add(dev("X", 1, "fe80::1", "t", "s"), true, true)
            .is_some());
    }

    #[test]
    fn batch_order_is_discovery_order() {
        let mut t = DeviceTable::new(false);
        t.add(dev("A", 1, "10.0.0.2", "t", "s"), true, false);
        t.add(dev("B", 1, "10.0.0.1", "t", "s"), true, false);
        let ips: Vec<String> = t.all().iter().map(|d| d.ip.to_string()).collect();
        assert_eq!(ips, vec!["10.0.0.2".to_string(), "10.0.0.1".to_string()]);
    }
}
