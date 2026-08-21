//! 配置合并：CLI flag > TOML 文件 > 内置默认（Config::default）。T52。
//!
//! 文件查找顺序：--config > $UNIVERSAL_SCANNER_CONFIG >
//! $XDG_CONFIG_HOME/universal-scanner/config.toml > ~/.config/universal-scanner/config.toml。
//! 不存在 = 静默跳过。TOML 解析用 serde(deny_unknown_fields)，未知键 → Err（含键名）。

use crate::cli::ScanArgs;
use anyhow::Context;
use serde::Deserialize;
use std::path::{Path, PathBuf};
use universal_scanner::Config;

/// 加载并合并配置：CLI > TOML > 默认。
pub fn load_config(cli_config: Option<&Path>, args: &ScanArgs) -> anyhow::Result<Config> {
    let path = resolve_config_path(cli_config);
    let mut config = match &path {
        Some(p) => {
            let text = std::fs::read_to_string(p)
                .with_context(|| format!("failed to read config file {}", p.display()))?;
            // 解析为 PartialConfig（全 Option + deny_unknown_fields）；
            // 未知键 → Err（含键名），缺失键 → None（不覆盖默认）。
            // 错误信息合并底层 toml 报错（含键名 + 行号），便于 CLI 直接展示。
            let partial: PartialConfig = toml::from_str(&text)
                .map_err(|e| anyhow::anyhow!("invalid TOML config {}: {e}", p.display()))?;
            partial.merge()
        }
        None => Config::default(),
    };
    apply_flags(&mut config, args)?;
    Ok(config)
}

/// TOML 中间结构：全 Option，deny_unknown_fields → 未知键报错（含键名）。
/// 仅出现于配置文件中的键才覆盖内置默认（Config::default）。
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct PartialConfig {
    enable_ipv4: Option<bool>,
    enable_ipv6: Option<bool>,
    force_link_local: Option<bool>,
    force_zeroconf: Option<bool>,
    force_generic_protocols: Option<bool>,
    debug_mode: Option<bool>,
    port_sharing: Option<bool>,
    onvif_verbatim: Option<bool>,
    dahua_net_scan: Option<bool>,
    arp_enabled: Option<bool>,
}

impl PartialConfig {
    fn merge(self) -> Config {
        let mut c = Config::default();
        if let Some(v) = self.enable_ipv4 {
            c.enable_ipv4 = v;
        }
        if let Some(v) = self.enable_ipv6 {
            c.enable_ipv6 = v;
        }
        if let Some(v) = self.force_link_local {
            c.force_link_local = v;
        }
        if let Some(v) = self.force_zeroconf {
            c.force_zeroconf = v;
        }
        if let Some(v) = self.force_generic_protocols {
            c.force_generic_protocols = v;
        }
        if let Some(v) = self.debug_mode {
            c.debug_mode = v;
        }
        if let Some(v) = self.port_sharing {
            c.port_sharing = v;
        }
        if let Some(v) = self.onvif_verbatim {
            c.onvif_verbatim = v;
        }
        if let Some(v) = self.dahua_net_scan {
            c.dahua_net_scan = v;
        }
        if let Some(v) = self.arp_enabled {
            c.arp_enabled = v;
        }
        c
    }
}

/// 按优先级查找配置文件，返回第一个存在的；都不存在 → None（静默跳过）。
fn resolve_config_path(cli: Option<&Path>) -> Option<PathBuf> {
    let mut candidates: Vec<PathBuf> = Vec::new();
    if let Some(p) = cli {
        candidates.push(p.to_path_buf());
    }
    if let Ok(s) = std::env::var("UNIVERSAL_SCANNER_CONFIG") {
        candidates.push(PathBuf::from(s));
    }
    if let Ok(xdg) = std::env::var("XDG_CONFIG_HOME") {
        candidates.push(
            PathBuf::from(xdg)
                .join("universal-scanner")
                .join("config.toml"),
        );
    }
    if let Some(home) = std::env::var_os("HOME").map(PathBuf::from) {
        candidates.push(
            home.join(".config")
                .join("universal-scanner")
                .join("config.toml"),
        );
    }
    candidates.into_iter().find(|p| p.is_file())
}

/// 应用 10 对对称 flag：任一 set → 覆盖；成对同时 set → Err "conflicting flags"。
fn apply_flags(config: &mut Config, a: &ScanArgs) -> anyhow::Result<()> {
    apply_bool(
        &mut config.enable_ipv4,
        a.enable_ipv4,
        a.disable_ipv4,
        "--enable-ipv4",
        "--disable-ipv4",
    )?;
    apply_bool(
        &mut config.enable_ipv6,
        a.enable_ipv6,
        a.disable_ipv6,
        "--enable-ipv6",
        "--disable-ipv6",
    )?;
    apply_bool(
        &mut config.force_link_local,
        a.force_link_local,
        a.no_force_link_local,
        "--force-link-local",
        "--no-force-link-local",
    )?;
    apply_bool(
        &mut config.force_zeroconf,
        a.force_zeroconf,
        a.no_force_zeroconf,
        "--force-zeroconf",
        "--no-force-zeroconf",
    )?;
    apply_bool(
        &mut config.force_generic_protocols,
        a.force_generic_protocols,
        a.no_force_generic_protocols,
        "--force-generic-protocols",
        "--no-force-generic-protocols",
    )?;
    apply_bool(
        &mut config.debug_mode,
        a.debug,
        a.no_debug,
        "--debug",
        "--no-debug",
    )?;
    apply_bool(
        &mut config.port_sharing,
        a.port_sharing,
        a.no_port_sharing,
        "--port-sharing",
        "--no-port-sharing",
    )?;
    apply_bool(
        &mut config.onvif_verbatim,
        a.onvif_verbatim,
        a.no_onvif_verbatim,
        "--onvif-verbatim",
        "--no-onvif-verbatim",
    )?;
    apply_bool(
        &mut config.dahua_net_scan,
        a.dahua_net_scan,
        a.no_dahua_net_scan,
        "--dahua-net-scan",
        "--no-dahua-net-scan",
    )?;
    apply_bool(
        &mut config.arp_enabled,
        a.arp,
        a.no_arp,
        "--arp",
        "--no-arp",
    )?;
    Ok(())
}

fn apply_bool(
    field: &mut bool,
    on: bool,
    off: bool,
    on_flag: &str,
    off_flag: &str,
) -> anyhow::Result<()> {
    if on && off {
        anyhow::bail!("conflicting flags: {on_flag} and {off_flag}");
    }
    if on {
        *field = true;
    } else if off {
        *field = false;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn write_tmp(toml: &str) -> tempfile::NamedTempFile {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        f.write_all(toml.as_bytes()).unwrap();
        f
    }

    #[test]
    fn config_unknown_key_errors() {
        let f = write_tmp("enbale_ipv4 = true\n");
        let args = ScanArgs::default();
        let e = load_config(Some(f.path()), &args).expect_err("unknown key must error");
        assert!(
            e.to_string().contains("enbale_ipv4"),
            "error should name the offending key: {e}"
        );
    }

    #[test]
    fn config_priority_cli_over_toml_over_default() {
        // TOML 显式 false（默认 true）→ 合并后 false
        let f = write_tmp("force_link_local = false\n");
        let args = ScanArgs::default();
        let c = load_config(Some(f.path()), &args).unwrap();
        assert!(!c.force_link_local, "TOML must override default");

        // TOML false + CLI --no-force-link-local → 仍 false
        let args = ScanArgs {
            no_force_link_local: true,
            ..Default::default()
        };
        let c = load_config(Some(f.path()), &args).unwrap();
        assert!(!c.force_link_local);

        // 无 TOML + 无 flag → 默认 true
        let c = load_config(None, &ScanArgs::default()).unwrap();
        assert!(c.force_link_local, "default must apply");
    }

    #[test]
    fn cli_overrides_toml() {
        // TOML force_link_local = false，CLI --force-link-local → true
        let f = write_tmp("force_link_local = false\n");
        let args = ScanArgs {
            force_link_local: true,
            ..Default::default()
        };
        let c = load_config(Some(f.path()), &args).unwrap();
        assert!(c.force_link_local, "CLI must override TOML");
    }

    #[test]
    fn conflicting_flag_pair_errors() {
        let args = ScanArgs {
            enable_ipv4: true,
            disable_ipv4: true,
            ..Default::default()
        };
        assert!(
            load_config(None, &args).is_err(),
            "both --enable-ipv4 and --disable-ipv4 must error"
        );
    }

    #[test]
    fn arp_pair_applied() {
        let args = ScanArgs {
            no_arp: true,
            ..Default::default()
        };
        let c = load_config(None, &args).unwrap();
        assert!(!c.arp_enabled);
    }
}
