use serde::{Deserialize, Serialize};

/// 默认值与 C# Config 构造函数逐项一致（另加 arp_enabled）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub enable_ipv4: bool,
    pub enable_ipv6: bool,
    pub force_link_local: bool,
    pub force_zeroconf: bool,
    pub force_generic_protocols: bool,
    pub debug_mode: bool,
    pub port_sharing: bool,
    pub onvif_verbatim: bool,
    pub dahua_net_scan: bool,
    pub arp_enabled: bool,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            enable_ipv4: true,
            enable_ipv6: false,
            force_link_local: true,
            force_zeroconf: false,
            force_generic_protocols: false,
            debug_mode: false,
            port_sharing: true,
            onvif_verbatim: false,
            dahua_net_scan: false,
            arp_enabled: true,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_match_csharp() {
        let c = Config::default();
        assert!(c.enable_ipv4);
        assert!(!c.enable_ipv6);
        assert!(c.force_link_local);
        assert!(!c.force_zeroconf);
        assert!(!c.force_generic_protocols);
        assert!(!c.debug_mode);
        assert!(c.port_sharing);
        assert!(!c.onvif_verbatim);
        assert!(!c.dahua_net_scan);
        assert!(c.arp_enabled); // Rust 新增
    }
}
