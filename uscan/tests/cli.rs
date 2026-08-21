//! CLI 集成测试（assert_cmd）：list-protocols / selftest / 配置合并 / 版本帮助 / 实时扫描。
//!
//! 约定（spec §5）：离线命令（list-protocols / selftest / 配置合并 / version / help）无条件运行；
//! 实时扫描命令在无 IPv4 接口时自动 skip（受限 CI 无权限/无接口）。实时扫描不需 root：
//! ARP 捕获缺失时引擎优雅降级，其余引擎照常。

use std::io::Write;
use std::time::Duration;

use predicates::prelude::*;

fn uscan() -> assert_cmd::Command {
    assert_cmd::Command::cargo_bin("uscan").unwrap()
}

/// 无 IPv4 接口 → 自动 skip（exit 0），让受限 CI 不失败。
fn require_network() {
    let has_v4 = universal_scanner::iface::active_interfaces()
        .iter()
        .any(|i| i.ipv4_addrs().next().is_some());
    if !has_v4 {
        eprintln!("SKIP: no active IPv4 interface (restricted CI)");
        std::process::exit(0);
    }
}

fn write_toml(contents: &str) -> tempfile::NamedTempFile {
    let mut f = tempfile::NamedTempFile::new().unwrap();
    f.write_all(contents.as_bytes()).unwrap();
    f
}

#[test]
fn list_protocols_all_engines() {
    let assert = uscan().arg("list-protocols").assert().success();
    let out = assert.get_output();
    let stdout = String::from_utf8(out.stdout.clone()).unwrap();
    for name in [
        "SSDP",
        "WSDiscovery",
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
    ] {
        assert!(stdout.contains(name), "missing protocol name: {name}");
    }
    assert!(stdout.contains("mDNS broker"), "missing mDNS broker line");
    // 28 个引擎行（Dahua 双引擎；末位 broker 说明行不计）
    let rows = stdout
        .lines()
        .filter(|l| l.chars().next().is_some_and(|c| c.is_ascii_digit()))
        .count();
    assert_eq!(rows, 28, "expected 28 engine rows, got {rows}:\n{stdout}");
}

#[test]
fn selftest_all_exit_zero() {
    uscan().arg("selftest").assert().success();
}

#[test]
fn selftest_lantronix_shows_vauban() {
    uscan()
        .args(["selftest", "Lantronix"])
        .assert()
        .success()
        .stdout(predicates::str::contains("Vauban"));
}

#[test]
fn scan_timeout_csv_exit_zero() {
    require_network();
    uscan()
        .args(["scan", "--timeout", "1", "--format", "csv"])
        .timeout(Duration::from_secs(20))
        .assert()
        .success()
        .stdout(predicates::str::contains(
            "protocol,version,ip,mac,type,serial",
        ));
}

#[test]
fn scan_unknown_protocol_errors() {
    uscan()
        .args(["scan", "--protocols", "nope"])
        .assert()
        .failure()
        .stderr(predicates::str::contains("unknown protocol"));
}

#[test]
fn tvt_set_dry_run_prints_hex_with_password_redacted() {
    uscan()
        .args([
            "tvt-set",
            "--mac",
            "00:11:22:33:44:55",
            "--ip",
            "192.168.0.90",
            "--password",
            "admin",
            "--dry-run",
        ])
        .assert()
        .success()
        .stdout(
            // 首行固定：MHED + 版本 0x00010008 (LE32) + 类型 0x03 (LE32)
            predicates::str::contains("0000  4d 48 45 44 08 00 01 00 03 00 00 00")
                .and(predicates::str::contains("00 11 22 33 44 55"))
                .and(predicates::str::contains("c0 a8 00 5a"))
                .and(predicates::str::contains("YWRtaW4=").not()),
        );
}

#[test]
fn tvt_set_bad_mac_errors() {
    uscan()
        .args(["tvt-set", "--mac", "nope", "--ip", "192.168.0.90"])
        .assert()
        .failure()
        .code(1)
        .stderr(predicates::str::contains("MAC"));
}

#[test]
fn tvt_set_password_too_long_errors() {
    let args: Vec<String> = vec![
        "tvt-set".into(),
        "--mac".into(),
        "00:11:22:33:44:55".into(),
        "--ip".into(),
        "192.168.0.90".into(),
        "--password".into(),
        "x".repeat(22),
    ];
    uscan()
        .args(&args)
        .assert()
        .failure()
        .code(1)
        .stderr(predicates::str::contains("password"));
}

#[test]
fn config_unknown_key_errors() {
    let f = write_toml("enbale_ipv4 = true\n");
    uscan()
        .args(["scan", "--config", f.path().to_str().unwrap()])
        .assert()
        .failure()
        .stderr(predicates::str::contains("enbale_ipv4"));
}

#[test]
fn cli_overrides_toml() {
    require_network();
    let f = write_toml("debug_mode = true\n");
    let cfg = f.path().to_str().unwrap();
    // TOML debug=true + CLI --no-debug → 无 DEBUG 级日志
    uscan()
        .args(["scan", "--timeout", "1", "--config", cfg, "--no-debug"])
        .timeout(Duration::from_secs(20))
        .assert()
        .success()
        .stderr(predicates::str::contains("DEBUG").not());
    // CLI --debug → 有 DEBUG 级日志（对照）
    uscan()
        .args(["scan", "--timeout", "1", "--config", cfg, "--debug"])
        .timeout(Duration::from_secs(20))
        .assert()
        .success()
        .stderr(predicates::str::contains("DEBUG"));
}

#[test]
fn no_color_output_has_no_ansi() {
    require_network();
    let assert = uscan()
        .args(["scan", "--timeout", "1", "--format", "table", "--no-color"])
        .timeout(Duration::from_secs(20))
        .assert()
        .success();
    let out = assert.get_output();
    let stdout = String::from_utf8(out.stdout.clone()).unwrap();
    assert!(
        !stdout.contains("\x1b["),
        "stdout must not contain ANSI with --no-color: {stdout:?}"
    );
}

#[test]
fn help_and_version() {
    uscan()
        .arg("--help")
        .assert()
        .success()
        .stdout(predicates::str::contains("uscan"));
    uscan()
        .arg("--version")
        .assert()
        .success()
        .stdout(predicates::str::contains("uscan"));
}
