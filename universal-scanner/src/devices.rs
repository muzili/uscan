use std::collections::BTreeMap;
use std::net::IpAddr;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Device {
    pub protocol: String,
    pub version: u32,
    pub ip: IpAddr,
    pub device_type: String,
    pub serial: String,
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
                let updated = Device {
                    protocol: device.protocol,
                    version: device.version,
                    ip: existing.ip,
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
            device_type: ty.into(),
            serial: serial.into(),
        }
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
