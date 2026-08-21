//! 输出渲染器：table/csv/json/tsv + 批量（T53）。
//!
//! - CSV/TSV：表头恒为 `protocol,version,ip,type,serial`（version 恒含，对齐 C# 隐藏列导出）。
//! - JSON：JSON Lines，每行固定字段 protocol/version/ip/type/serial。
//! - Table：列 Protocol | (Version) | IP | Type | Serial；Version 默认隐藏，
//!   --show-version 显示；Protocol 按引擎 color 着色（owo-colors），--no-color/NO_COLOR 禁用。
//! - --batch：streaming 阶段只喂 DeviceTable，结束时按发现顺序一次性输出全部行。

use crate::cli::OutputFormat;
use owo_colors::OwoColorize;
use std::collections::HashMap;
use std::sync::OnceLock;
use universal_scanner::{Device, DeviceTable};

pub const CSV_HEADER: &str = "protocol,version,ip,type,serial";
pub const TSV_HEADER: &str = "protocol\tversion\tip\ttype\tserial";

/// 表头（仅 CSV/TSV 有；JSON Lines / Table 无）。
pub fn header(format: OutputFormat) -> Option<String> {
    match format {
        OutputFormat::Csv => Some(CSV_HEADER.to_string()),
        OutputFormat::Tsv => Some(TSV_HEADER.to_string()),
        OutputFormat::Json | OutputFormat::Table => None,
    }
}

/// 渲染一行设备（流式/逐行调用）。
pub fn render_row(d: &Device, format: OutputFormat, show_version: bool, color: bool) -> String {
    match format {
        OutputFormat::Csv => render_csv(d),
        OutputFormat::Tsv => render_tsv(d),
        OutputFormat::Json => render_json(d),
        OutputFormat::Table => render_table(d, show_version, color),
    }
}

/// 批量渲染：表头（CSV/TSV）+ 按发现顺序的全部行。
pub fn batch_lines(
    table: &DeviceTable,
    format: OutputFormat,
    show_version: bool,
    color: bool,
) -> Vec<String> {
    let mut out = Vec::new();
    if let Some(h) = header(format) {
        out.push(h);
    }
    for d in table.all() {
        out.push(render_row(d, format, show_version, color));
    }
    out
}

fn render_csv(d: &Device) -> String {
    // C# exportAsCSV：每字段双引号包裹，内部 `"` 翻倍（UniversalScanner.cs）
    let q = |f: &str| format!("\"{}\"", f.replace('"', "\"\""));
    format!(
        "{},{},{},{},{}",
        q(&d.protocol),
        q(&d.version.to_string()),
        q(&d.ip.to_string()),
        q(&d.device_type),
        q(&d.serial)
    )
}

fn render_tsv(d: &Device) -> String {
    format!(
        "{}\t{}\t{}\t{}\t{}",
        d.protocol, d.version, d.ip, d.device_type, d.serial
    )
}

fn render_json(d: &Device) -> String {
    serde_json::json!({
        "protocol": d.protocol,
        "version": d.version,
        "ip": d.ip.to_string(),
        "type": d.device_type,
        "serial": d.serial,
    })
    .to_string()
}

fn render_table(d: &Device, show_version: bool, color: bool) -> String {
    let proto = colorize(
        d.protocol.as_str(),
        color,
        protocol_color(d.protocol.as_str()),
    );
    let parts: Vec<String> = if show_version {
        vec![
            proto,
            d.version.to_string(),
            d.ip.to_string(),
            d.device_type.clone(),
            d.serial.clone(),
        ]
    } else {
        vec![
            proto,
            d.ip.to_string(),
            d.device_type.clone(),
            d.serial.clone(),
        ]
    };
    parts.join(" | ")
}

/// 协议名 → 引擎 color（registry）；未知 → 白。
fn protocol_color(name: &str) -> u32 {
    *color_map().get(name).unwrap_or(&0xFFFFFF)
}

fn color_map() -> &'static HashMap<String, u32> {
    static MAP: OnceLock<HashMap<String, u32>> = OnceLock::new();
    MAP.get_or_init(|| {
        let mut m = HashMap::new();
        for (_id, e) in universal_scanner::protocols::registry() {
            // 显式 trait 方法（OwoColorize::color 同名冲突，须全限定）。
            m.insert(
                e.name().to_string(),
                universal_scanner::ScanEngine::color(e.as_ref()),
            );
        }
        m
    })
}

/// 按引擎 color 着色；color=false → 原样（无 ANSI）。
fn colorize(s: &str, color: bool, rgb: u32) -> String {
    if !color {
        return s.to_string();
    }
    let r = ((rgb >> 16) & 0xff) as u8;
    let g = ((rgb >> 8) & 0xff) as u8;
    let b = (rgb & 0xff) as u8;
    format!("{}", s.truecolor(r, g, b))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;

    fn dev(protocol: &str, version: u32, ip: &str, ty: &str, serial: &str) -> Device {
        Device {
            protocol: protocol.into(),
            version,
            ip: ip.parse::<IpAddr>().unwrap(),
            device_type: ty.into(),
            serial: serial.into(),
        }
    }

    #[test]
    fn csv_header_and_row() {
        assert_eq!(
            header(OutputFormat::Csv).unwrap(),
            "protocol,version,ip,type,serial"
        );
        let d = dev("SSDP", 0, "1.2.3.4", "X", "SN");
        assert_eq!(
            render_row(&d, OutputFormat::Csv, false, false),
            "\"SSDP\",\"0\",\"1.2.3.4\",\"X\",\"SN\""
        );
        // C# 转义：字段含 `,`/`"` 时引号内翻倍
        let d = dev("SSDP", 0, "1.2.3.4", "Cam, \"pro\"", "SN,9");
        assert_eq!(
            render_row(&d, OutputFormat::Csv, false, false),
            "\"SSDP\",\"0\",\"1.2.3.4\",\"Cam, \"\"pro\"\"\",\"SN,9\""
        );
    }

    #[test]
    fn tsv_header_and_row() {
        assert_eq!(
            header(OutputFormat::Tsv).unwrap(),
            "protocol\tversion\tip\ttype\tserial"
        );
        let d = dev("SSDP", 0, "1.2.3.4", "X", "SN");
        assert_eq!(
            render_row(&d, OutputFormat::Tsv, false, false),
            "SSDP\t0\t1.2.3.4\tX\tSN"
        );
    }

    #[test]
    fn json_lines_fields() {
        let d = dev("SSDP", 2, "1.2.3.4", "X", "SN");
        let line = render_row(&d, OutputFormat::Json, false, false);
        let v: serde_json::Value = serde_json::from_str(&line).unwrap();
        assert_eq!(v["protocol"], "SSDP");
        assert_eq!(v["version"], 2);
        assert_eq!(v["ip"], "1.2.3.4");
        assert_eq!(v["type"], "X");
        assert_eq!(v["serial"], "SN");
    }

    #[test]
    fn table_hides_version_by_default() {
        let d = dev("SSDP", 7, "1.2.3.4", "X", "SN");
        let hidden = render_row(&d, OutputFormat::Table, false, false);
        assert!(!hidden.contains("7"), "version must be hidden: {hidden}");
        let shown = render_row(&d, OutputFormat::Table, true, false);
        assert!(shown.contains("7"), "version must be shown: {shown}");
    }

    #[test]
    fn no_color_strips_ansi() {
        let d = dev("SSDP", 0, "1.2.3.4", "X", "SN");
        let colored = render_row(&d, OutputFormat::Table, false, true);
        assert!(
            colored.contains("\x1b["),
            "colored output must contain ANSI: {colored:?}"
        );
        let plain = render_row(&d, OutputFormat::Table, false, false);
        assert!(
            !plain.contains("\x1b["),
            "plain output must not contain ANSI: {plain:?}"
        );
    }

    #[test]
    fn batch_orders_by_discovery() {
        let mut t = DeviceTable::new(false);
        t.add(dev("SSDP", 0, "1.2.3.4", "X", "A"), true, false);
        t.add(dev("Lantronix", 0, "5.6.7.8", "Y", "B"), true, false);
        let lines = batch_lines(&t, OutputFormat::Csv, false, false);
        assert_eq!(lines.len(), 3); // header + 2
        assert_eq!(lines[0], "protocol,version,ip,type,serial");
        assert_eq!(lines[1], "\"SSDP\",\"0\",\"1.2.3.4\",\"X\",\"A\"");
        assert_eq!(lines[2], "\"Lantronix\",\"0\",\"5.6.7.8\",\"Y\",\"B\"");
    }
}
