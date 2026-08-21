//! MAC OUI（IEEE 厂家）查询：懒加载系统 oui.txt（`ieee-data` 包）。
//!
//! 文件不存在时查询返回 None（ARP 输出不追加厂家，其余行为不变）。

use std::collections::HashMap;
use std::path::Path;
use std::sync::OnceLock;

/// 常见 oui.txt 安装位置（按序探测第一个存在的）。
const OUI_PATHS: [&str; 3] = [
    "/usr/share/misc/oui.txt",
    "/var/lib/ieee-data/oui.txt",
    "/usr/share/ieee-data/oui.txt",
];

type OuiMap = HashMap<[u8; 3], String>;

fn load() -> Option<OuiMap> {
    let path = OUI_PATHS.iter().find(|p| Path::new(p).exists())?;
    parse_oui_file(std::fs::read_to_string(path).ok()?)
}

/// 解析 oui.txt：形如 `847B57     (base 16)\tTP-Link Systems Inc.` 的行
/// （仅取 base-16 / 24 位 OUI 行；MA-M/MA-S 28/36 位行忽略）。
fn parse_oui_file(text: String) -> Option<OuiMap> {
    const MARKER: &str = "(base 16)";
    let mut map = OuiMap::new();
    for line in text.lines() {
        let line = line.trim_end();
        let Some(marker_at) = line.find(MARKER) else {
            continue;
        };
        if marker_at < 6 {
            continue;
        }
        let prefix = &line[..6];
        // 前缀与标记之间应全为空白（排除 MA-M/MA-S 的 6+2/6+3 位形式）
        if !line[6..marker_at].trim().is_empty() || !prefix.bytes().all(|b| b.is_ascii_hexdigit()) {
            continue;
        }
        let oui = [
            u8::from_str_radix(&line[0..2], 16).ok()?,
            u8::from_str_radix(&line[2..4], 16).ok()?,
            u8::from_str_radix(&line[4..6], 16).ok()?,
        ];
        let vendor = line[marker_at + MARKER.len()..].trim().to_string();
        if !vendor.is_empty() {
            map.insert(oui, vendor);
        }
    }
    if map.is_empty() {
        None
    } else {
        Some(map)
    }
}

/// 查 MAC 前 3 字节对应的厂家；无数据库或未命中 → None。
pub fn lookup(mac: [u8; 6]) -> Option<String> {
    static MAP: OnceLock<Option<OuiMap>> = OnceLock::new();
    let map = MAP.get_or_init(load).as_ref()?;
    map.get(&[mac[0], mac[1], mac[2]]).cloned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_base16_lines() {
        let text = "\n\
             847B57     (base 16)\tTP-Link Systems Inc.\n\
             3CEFA5     (base 16)\tHuawei Technologies Co.,Ltd\n\
             001122     (base 16)\tFake     Vendor  \n\
             junk line without marker\n\
             0011A2     (base 18)\tignored radix\n";
        let map = parse_oui_file(text.to_string()).unwrap();
        assert_eq!(map.len(), 3);
        assert_eq!(
            map.get(&[0x84, 0x7b, 0x57]).unwrap(),
            "TP-Link Systems Inc."
        );
        assert_eq!(
            map.get(&[0x3c, 0xef, 0xa5]).unwrap(),
            "Huawei Technologies Co.,Ltd"
        );
        // 尾随空白剥除
        assert_eq!(map.get(&[0x00, 0x11, 0x22]).unwrap(), "Fake     Vendor");
    }

    #[test]
    fn empty_or_invalid_file_is_none() {
        assert!(parse_oui_file(String::new()).is_none());
        assert!(parse_oui_file("no markers here\n".to_string()).is_none());
    }
}
