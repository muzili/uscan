//! PortProvider：1024–65533 随机空闲端口分配与预占。

use std::collections::BTreeSet;

/// C# PortProvider: Enumerable.Range(1024, 65534-1024) 左闭右开 → 实际上限 65533。
pub const PORT_MIN: u16 = 1024;
pub const PORT_MAX: u16 = 65533;

/// 无依赖随机源（splitmix64），种子来自时间+pid，可测试。
#[derive(Debug)]
pub struct SplitMix64(u64);

impl SplitMix64 {
    pub fn new(seed: u64) -> Self {
        Self(seed)
    }
    pub fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }
    pub fn pick(&mut self) -> u16 {
        PORT_MIN + (self.next_u64() % (PORT_MAX - PORT_MIN + 1) as u64) as u16
    }
}

/// 解析 /proc/net/udp{,6}：数据行 field 1 为 "HEXIP:HEXPORT"。
pub fn parse_proc_net_udp(text: &str) -> Vec<u16> {
    text.lines()
        .skip(1)
        .filter_map(|line| {
            let fields: Vec<&str> = line.split_whitespace().collect();
            let local = fields.get(1)?;
            let port_hex = local.rsplit(':').next()?;
            u16::from_str_radix(port_hex, 16).ok().filter(|p| *p != 0)
        })
        .collect()
}

pub struct PortProvider {
    used: BTreeSet<u16>,
    state: u64,
}

impl Default for PortProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl PortProvider {
    pub fn new() -> Self {
        let mut used = BTreeSet::new();
        for path in ["/proc/net/udp", "/proc/net/udp6"] {
            if let Ok(text) = std::fs::read_to_string(path) {
                used.extend(parse_proc_net_udp(&text));
            }
        }
        let t = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0);
        Self {
            used,
            state: t ^ ((std::process::id() as u64) << 32),
        }
    }

    /// 测试用构造：给定已用端口集合。
    pub fn with_used(ports: &[u16]) -> Self {
        Self {
            used: ports.iter().copied().collect(),
            state: 0xC0FFEE,
        }
    }

    /// 预占固定端口（重复预占无害，C# 同）。
    pub fn reserve(&mut self, ports: &[u16]) {
        for &p in ports {
            self.used.insert(p);
        }
    }

    /// 随机空闲端口（排除已用+已占），test-bind 验证；64 次无果返回 None。
    pub fn free_port(&mut self) -> Option<u16> {
        let mut rng = SplitMix64::new(self.state);
        for _ in 0..64 {
            let candidate = rng.pick();
            if self.used.contains(&candidate) {
                continue;
            }
            // 无 REUSEADDR 的试绑：端口被独占占用时失败。
            if std::net::UdpSocket::bind(("0.0.0.0", candidate)).is_ok() {
                self.state = rng.0;
                self.used.insert(candidate);
                return Some(candidate);
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn proc_net_udp_parse() {
        let text = "  sl  local_address rem_address st
   0: 00000000:1F90 00000000:0000 07
   1: 0100007F:0050 00000000:0000 0A
   2: 00000000:0000 00000000:0000 07";
        assert_eq!(parse_proc_net_udp(text), vec![0x1F90u16, 0x0050]);
    }

    #[test]
    fn pick_within_range() {
        let mut rng = SplitMix64::new(42);
        for _ in 0..1000 {
            let p = rng.pick();
            assert!((1024..=65533).contains(&p));
        }
    }

    #[test]
    fn reserved_ports_never_returned() {
        let mut pp = PortProvider::with_used(&[5000u16, 1900]);
        for _ in 0..200 {
            if let Some(p) = pp.free_port() {
                assert_ne!(p, 5000);
                assert_ne!(p, 1900);
            }
        }
    }

    #[test]
    fn reserve_then_excluded() {
        let mut pp = PortProvider::with_used(&[]);
        pp.reserve(&[12345]);
        for _ in 0..200 {
            if let Some(p) = pp.free_port() {
                assert_ne!(p, 12345);
            }
        }
    }
}
