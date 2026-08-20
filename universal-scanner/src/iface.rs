//! 活跃网卡枚举（if-addrs）与子网主机枚举（纯 u32 位运算，C# 对齐）。

use if_addrs::{get_if_addrs, IfAddr};
use std::net::{IpAddr, Ipv4Addr};

#[derive(Debug, Clone)]
pub struct Iface {
    pub name: String,
    pub is_up: bool,
    pub is_loopback: bool,
    /// 该接口的全部地址（if-addrs 按 (接口,地址) 逐条返回，此处按 name 聚合）
    pub addrs: Vec<IfAddr>,
}

impl Iface {
    pub fn ipv4_addrs(&self) -> impl Iterator<Item = Ipv4Addr> + '_ {
        self.addrs.iter().filter_map(|a| match a {
            IfAddr::V4(v) => Some(v.ip),
            _ => None,
        })
    }
}

/// 活动网卡（oper status up；包含 loopback，C# 同）。
pub fn active_interfaces() -> Vec<Iface> {
    let entries = get_if_addrs().unwrap_or_default();
    let mut out: Vec<Iface> = Vec::new();
    for e in entries {
        match out.iter_mut().find(|i| i.name == e.name) {
            Some(i) => i.addrs.push(e.addr),
            None => out.push(Iface {
                name: e.name.clone(),
                is_up: e.is_oper_up(),
                is_loopback: e.is_loopback(),
                addrs: vec![e.addr],
            }),
        }
    }
    out.into_iter().filter(|i| i.is_up).collect()
}

/// 接口 MAC（if-addrs 无此字段）：
/// Linux 读 `/sys/class/net/<name>/address`；macOS 解析 `ifconfig <name>` 的 `ether` 行；
/// 失败 → None（ARP sweep 降级跳过该接口，见 T47）。
#[cfg(target_os = "linux")]
pub fn mac_of(name: &str) -> Option<[u8; 6]> {
    let s = std::fs::read_to_string(format!("/sys/class/net/{name}/address")).ok()?;
    parse_mac(s.trim())
}

#[cfg(not(target_os = "linux"))]
pub fn mac_of(name: &str) -> Option<[u8; 6]> {
    let out = std::process::Command::new("ifconfig")
        .arg(name)
        .output()
        .ok()?;
    let text = String::from_utf8_lossy(&out.stdout);
    text.lines()
        .find_map(|l| l.trim().strip_prefix("ether"))
        .and_then(|l| parse_mac(l.trim()))
}

fn parse_mac(s: &str) -> Option<[u8; 6]> {
    let parts: Vec<&str> = s.split(':').collect();
    if parts.len() != 6 {
        return None;
    }
    let mut m = [0u8; 6];
    for (i, p) in parts.iter().enumerate() {
        m[i] = u8::from_str_radix(p, 16).ok()?;
    }
    Some(m)
}

/// C# NetworkUtils.isPrivate：10/8、172.16/12、192.168/16、169.254/16、fd00::/8、fe80::/10。
pub fn is_private(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            o[0] == 10
                || (o[0] == 172 && (16..=31).contains(&o[1]))
                || (o[0] == 192 && o[1] == 168)
                || (o[0] == 169 && o[1] == 254)
        }
        IpAddr::V6(v6) => {
            let s = v6.segments();
            (s[0] & 0xff00) == 0xfd00 || (s[0] & 0xffc0) == 0xfe80
        }
    }
}

/// C# isAutoConf：169.254/16（IPv4）或 fe80::/10（IPv6）。
pub fn is_autoconf(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            o[0] == 169 && o[1] == 254
        }
        IpAddr::V6(v6) => (v6.segments()[0] & 0xffc0) == 0xfe80,
    }
}

pub fn mask_from_prefix(prefix: u8) -> Ipv4Addr {
    let bits = if prefix == 0 {
        0u32
    } else {
        u32::MAX << (32 - prefix as u32)
    };
    Ipv4Addr::from(bits.to_be_bytes())
}

/// 接口掩码（C# getMaskOfAddressIPv4）；找不到 → 255.255.255.255。
pub fn mask_of(ip: Ipv4Addr) -> Ipv4Addr {
    for i in active_interfaces() {
        for a in &i.addrs {
            if let IfAddr::V4(v4) = a {
                if v4.ip == ip {
                    return mask_from_prefix(v4.prefixlen);
                }
            }
        }
    }
    Ipv4Addr::new(255, 255, 255, 255)
}

/// 子网主机枚举（C# subNetListIPv4Addresses）：network+1 .. broadcast-1，上限 max。
pub fn subnet_hosts(addr: Ipv4Addr, mask: Ipv4Addr, max: u32) -> Vec<Ipv4Addr> {
    let a = u32::from(addr);
    let m = u32::from(mask);
    let first = (a & m).wrapping_add(1);
    let last = (a | !m).wrapping_sub(1);
    if last < first {
        return Vec::new();
    }
    let len = std::cmp::min(last - first + 1, max);
    (0..len)
        .map(|i| Ipv4Addr::from(first.wrapping_add(i)))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    fn v4(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(a, b, c, d))
    }

    #[test]
    fn is_private_covers_csharp_ranges() {
        // C# NetworkUtils.isPrivate: 10/8, 172.16/12, 192.168/16, 169.254/16
        assert!(is_private(v4(10, 1, 2, 3)));
        assert!(is_private(v4(172, 16, 0, 1)));
        assert!(is_private(v4(172, 31, 255, 254)));
        assert!(!is_private(v4(172, 32, 0, 1)));
        assert!(is_private(v4(192, 168, 1, 1)));
        assert!(is_private(v4(169, 254, 10, 10)));
        assert!(!is_private(v4(8, 8, 8, 8)));
        assert!(!is_private(v4(11, 0, 0, 1)));
        // IPv6: fd00::/8, fe80::/10（按前 32 位）
        assert!(is_private(IpAddr::V6(Ipv6Addr::new(
            0xfd12, 0, 0, 0, 0, 0, 0, 1
        ))));
        assert!(is_private(IpAddr::V6(Ipv6Addr::new(
            0xfe80, 0, 0, 0, 0, 0, 0, 1
        ))));
        assert!(is_private(IpAddr::V6(Ipv6Addr::new(
            0xfebf, 0, 0, 0, 0, 0, 0, 1
        ))));
        assert!(!is_private(IpAddr::V6(Ipv6Addr::new(
            0xfec0, 0, 0, 0, 0, 0, 0, 1
        ))));
        assert!(!is_private(IpAddr::V6(Ipv6Addr::new(
            0x2001, 0xdb8, 0, 0, 0, 0, 0, 1
        ))));
    }

    #[test]
    fn is_autoconf_cases() {
        assert!(is_autoconf(v4(169, 254, 1, 1)));
        assert!(!is_autoconf(v4(192, 168, 1, 1)));
        assert!(is_autoconf(IpAddr::V6(Ipv6Addr::new(
            0xfe80, 0, 0, 0, 0, 0, 0, 1
        ))));
        assert!(!is_autoconf(IpAddr::V6(Ipv6Addr::new(
            0xfd00, 0, 0, 0, 0, 0, 0, 1
        ))));
    }

    #[test]
    fn mask_from_prefix_cases() {
        assert_eq!(mask_from_prefix(24), Ipv4Addr::new(255, 255, 255, 0));
        assert_eq!(mask_from_prefix(12), Ipv4Addr::new(255, 240, 0, 0));
        assert_eq!(mask_from_prefix(32), Ipv4Addr::new(255, 255, 255, 255));
        assert_eq!(mask_from_prefix(0), Ipv4Addr::UNSPECIFIED);
    }

    #[test]
    fn subnet_hosts_24() {
        let hosts = subnet_hosts(
            Ipv4Addr::new(192, 168, 1, 5),
            Ipv4Addr::new(255, 255, 255, 0),
            254,
        );
        assert_eq!(hosts.len(), 254);
        assert_eq!(hosts[0], Ipv4Addr::new(192, 168, 1, 1));
        assert_eq!(hosts[253], Ipv4Addr::new(192, 168, 1, 254));
    }

    #[test]
    fn subnet_hosts_30() {
        let hosts = subnet_hosts(
            Ipv4Addr::new(10, 0, 0, 1),
            Ipv4Addr::new(255, 255, 255, 252),
            254,
        );
        assert_eq!(
            hosts,
            vec![Ipv4Addr::new(10, 0, 0, 1), Ipv4Addr::new(10, 0, 0, 2)]
        );
    }

    #[test]
    fn subnet_hosts_capped_at_max() {
        let hosts = subnet_hosts(
            Ipv4Addr::new(10, 0, 0, 1),
            Ipv4Addr::new(255, 255, 0, 0),
            254,
        );
        assert_eq!(hosts.len(), 254);
        assert_eq!(hosts[0], Ipv4Addr::new(10, 0, 0, 1));
    }

    #[test]
    fn subnet_hosts_degenerate_empty() {
        // /31 与 /32：last < first → 空（C# 此处会 UInt32 下溢回卷，Rust 有意不复刻，spec §8.2 注记）
        assert!(subnet_hosts(
            Ipv4Addr::new(10, 0, 0, 0),
            Ipv4Addr::new(255, 255, 255, 254),
            254
        )
        .is_empty());
        assert!(subnet_hosts(
            Ipv4Addr::new(10, 0, 0, 1),
            Ipv4Addr::new(255, 255, 255, 255),
            254
        )
        .is_empty());
    }
}
