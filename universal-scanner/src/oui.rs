//! MAC OUI（IEEE 厂家）查询。
//!
//! 数据源优先级：系统 `ieee-data` 包 → 用户缓存（`uscan update-oui` 下载）
//! → **内置压缩数据库**（`oui_data/compact.txt.gz`，随源码提交，恒可用）。
//! 未命中 OUI 前缀时返回 None。

use std::collections::HashMap;
use std::io::Read;
use std::sync::OnceLock;

/// IEEE 官方 base-16 OUI 数据库（`uscan update-oui` 的下载源，也是内置库的生成源）。
pub const OUI_URL: &str = "https://standards-oui.ieee.org/oui/oui.txt";

/// 常见 oui.txt 安装位置（按序探测第一个存在的）。
const OUI_PATHS: [&str; 3] = [
    "/usr/share/misc/oui.txt",
    "/var/lib/ieee-data/oui.txt",
    "/usr/share/ieee-data/oui.txt",
];

/// 内置精简库（`HEX\tVendor` 行，gzip；生成方式见 `oui_data/README.md`）。
static EMBEDDED: &[u8] = include_bytes!("oui_data/compact.txt.gz");

type OuiMap = HashMap<[u8; 3], String>;

/// 用户缓存路径：`$XDG_CACHE_HOME/uscan/oui.txt`（缺省 `~/.cache/uscan/oui.txt`）。
pub fn cache_path() -> Option<std::path::PathBuf> {
    let dir = std::env::var_os("XDG_CACHE_HOME")
        .map(std::path::PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| std::path::PathBuf::from(h).join(".cache")))?;
    Some(dir.join("uscan").join("oui.txt"))
}

fn load() -> Option<OuiMap> {
    let mut candidates: Vec<std::path::PathBuf> =
        OUI_PATHS.iter().map(std::path::PathBuf::from).collect();
    if let Some(c) = cache_path() {
        candidates.push(c);
    }
    // 系统/缓存数据（可能更新）优先；全缺时回退内置压缩库
    if let Some(text) = candidates
        .iter()
        .find_map(|p| std::fs::read_to_string(p).ok())
    {
        return parse_oui_file(text);
    }
    load_embedded()
}

/// 解压并解析内置库。
fn load_embedded() -> Option<OuiMap> {
    let mut gz = flate2::read::GzDecoder::new(EMBEDDED);
    let mut text = String::new();
    gz.read_to_string(&mut text).ok()?;
    parse_compact(&text)
}

/// 解析官方 oui.txt：形如 `847B57     (base 16)\tIntel Corporate` 的行
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

/// 解析内置精简格式：`847B57\tIntel Corporate` 行。
fn parse_compact(text: &str) -> Option<OuiMap> {
    let mut map = OuiMap::new();
    for line in text.lines() {
        let Some((hex, vendor)) = line.split_once('\t') else {
            continue;
        };
        if hex.len() != 6 || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
            continue;
        }
        let oui = [
            u8::from_str_radix(&hex[0..2], 16).ok()?,
            u8::from_str_radix(&hex[2..4], 16).ok()?,
            u8::from_str_radix(&hex[4..6], 16).ok()?,
        ];
        map.insert(oui, vendor.trim().to_string());
    }
    if map.is_empty() {
        None
    } else {
        Some(map)
    }
}

/// 查 MAC 前 3 字节对应的厂家；未命中 → None（内置库恒存在，不会因缺数据失败）。
pub fn lookup(mac: [u8; 6]) -> Option<String> {
    static MAP: OnceLock<Option<OuiMap>> = OnceLock::new();
    let map = MAP.get_or_init(load).as_ref()?;
    map.get(&[mac[0], mac[1], mac[2]]).cloned()
}

/// 下载官方 OUI 数据库到缓存路径（`uscan update-oui`）。
/// 已存在时先删除（IEEE 会原地更新该 URL）。
pub fn download() -> crate::Result<std::path::PathBuf> {
    let dest = cache_path().ok_or_else(|| {
        crate::errors::Error::Config("no HOME/XDG_CACHE_HOME to place cache".into())
    })?;
    let dir = dest
        .parent()
        .ok_or_else(|| crate::errors::Error::Config("invalid cache path".into()))?;
    std::fs::create_dir_all(dir)?;
    let tmp = dest.with_extension("tmp");
    let body = ureq::get(OUI_URL)
        // standards-oui.ieee.org 拒绝非浏览器 UA（418），伪装常规浏览器 UA
        .set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) uscan/0.1")
        .call()
        .map_err(|e| {
            crate::errors::Error::Io(std::io::Error::other(format!("OUI download failed: {e}")))
        })?
        .into_string()
        .map_err(|e| {
            crate::errors::Error::Io(std::io::Error::other(format!("OUI read failed: {e}")))
        })?;
    if parse_oui_file(body.clone()).is_none() {
        return Err(crate::errors::Error::Config(
            "downloaded OUI data has no base-16 entries (unexpected format)".into(),
        ));
    }
    std::fs::write(&tmp, body)?;
    std::fs::rename(&tmp, &dest)?; // 原子替换
    Ok(dest)
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
    fn parses_compact_lines() {
        let map = parse_compact("847B57\tIntel Corporate\n3CEFA5\tCLOUD NETWORK\nbad\n0011\tX\n")
            .unwrap();
        assert_eq!(map.len(), 2);
        assert_eq!(map.get(&[0x84, 0x7b, 0x57]).unwrap(), "Intel Corporate");
    }

    #[test]
    fn embedded_db_loads_and_hits() {
        // 内置库恒可用：条目量级 + 已知 OUI 命中
        let map = load_embedded().expect("embedded OUI db must parse");
        assert!(map.len() > 30_000, "embedded db too small: {}", map.len());
        assert_eq!(map.get(&[0x84, 0x7b, 0x57]).unwrap(), "Intel Corporate");
        assert!(map.contains_key(&[0x3c, 0xef, 0xa5]));
    }

    #[test]
    fn empty_or_invalid_file_is_none() {
        assert!(parse_oui_file(String::new()).is_none());
        assert!(parse_oui_file("no markers here\n".to_string()).is_none());
        assert!(parse_compact("").is_none());
    }

    #[test]
    fn cache_path_under_xdg() {
        // 仅验证形状：以 uscan/oui.txt 结尾
        if let Some(p) = cache_path() {
            assert!(p.ends_with("uscan/oui.txt"));
        }
    }
}
