//! 360Vision 引擎（T37）：`DISCOVER\n` 探测 + KEY=VALUE 文本应答（手工正则等价、
//! 含首个 `\n` 截断 quirk），逐行对齐 C# _360Vision.reciever。

use crate::devices::Device;
use crate::engine::{EngineContext, ScanEngine};
use crate::net::SocketSet;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use tokio::task::JoinHandle;

const PORT: u16 = 3600; // C# port
const REQUEST: &str = "DISCOVER\n"; // C# request（探测与回显判定共用）

pub struct Vision360 {
    socks: SocketSet,
}

impl Default for Vision360 {
    fn default() -> Self {
        Self {
            socks: SocketSet::new(),
        }
    }
}

impl ScanEngine for Vision360 {
    fn name(&self) -> &str {
        "360Vision"
    }
    fn used_ports(&self) -> &[u16] {
        &[PORT]
    }
    fn color(&self) -> u32 {
        0x800080 // Color.Purple.ToArgb() → 低 24 位
    }

    fn listen(&self, ctx: Arc<EngineContext>) -> crate::Result<Vec<JoinHandle<()>>> {
        let ifaces = crate::iface::active_interfaces();
        let nic_ips: Vec<Ipv4Addr> = ifaces.iter().flat_map(|i| i.ipv4_addrs()).collect();
        // recv_loop 只调用 parse()（纯函数），用新实例即可，无需自引用。
        let e: Arc<dyn ScanEngine> = Arc::new(Self::default());
        let mut handles = Vec::new();
        // C# listenUdpGlobal(port)：G 绑 3600
        if let Some((gsock, gsync)) =
            crate::net::udp_bind_global(PORT, ctx.config.port_sharing, &ctx.logger, ctx.task_id)?
        {
            self.socks.add(gsync);
            handles.push(tokio::spawn(crate::net::recv_loop(
                ctx.clone(),
                Arc::clone(&e),
                gsock,
            )));
        }
        // C# listenUdpInterfaces：每网卡取 free_port（耗尽则跳过）
        for ip in nic_ips {
            let Some(p) = ctx.ports.lock().unwrap().free_port() else {
                ctx.logger
                    .warn(ctx.task_id, "no free port; skipping interface socket");
                continue;
            };
            let (_local, isock, isync) = crate::net::udp_bind_interface(ip, p)?;
            self.socks.add(isync);
            handles.push(tokio::spawn(crate::net::recv_loop(
                ctx.clone(),
                Arc::clone(&e),
                isock,
            )));
        }
        Ok(handles)
    }

    fn scan(&self, ctx: &EngineContext) -> crate::Result<()> {
        // C# 360Vision.scan：sendBroadcast(port) 3600，probe = "DISCOVER\n"
        let failed = self.socks.send_broadcast(PORT, REQUEST.as_bytes());
        if failed > 0 {
            ctx.logger
                .warn(ctx.task_id, &format!("{} 360Vision sends failed", failed));
        }
        Ok(())
    }

    fn parse(&self, from: SocketAddr, data: &[u8]) -> Vec<Device> {
        // C# reciever：UTF-8 文本 == 自身请求 → 回显丢弃
        let text = String::from_utf8_lossy(data);
        if text.as_ref() == REQUEST {
            return Vec::new();
        }
        // C# quirk：首个 \n 位置 EOS > 0 时 text = text[..EOS-1]
        //（连带丢掉换行前一个字符；EOS == 0 或无 \n 不截断）
        let trimmed: std::borrow::Cow<str> = match text.find('\n') {
            Some(p) if p > 0 => std::borrow::Cow::Borrowed(&text[..p - 1]),
            _ => std::borrow::Cow::Borrowed(&text),
        };
        // C# readKeyValuePairs：TYPE → model、KEY → serial（缺省 "Unknown"）
        let pairs = key_value_pairs(&trimmed);
        let get = |k: &str| {
            pairs
                .iter()
                .find(|(key, _)| key == k)
                .map(|(_, v)| v.clone())
        };
        let device_type = get("TYPE").unwrap_or_else(|| "Unknown".to_string());
        let serial = get("KEY").unwrap_or_else(|| "Unknown".to_string());
        // C#：ip 恒为 from；version 1
        vec![Device {
            protocol: "360Vision".into(),
            version: 1,
            ip: from.ip(),
            device_type,
            serial,
        }]
    }
}

/// C# readKeyValuePairs 正则 `([a-zA-Z_][a-zA-Z0-9_]*)=('[^']*'|"[^"]*"|[^ ]*)`
/// 的手工等价（非重叠匹配，value 备选按 单引号串/双引号串/非空白串 顺序）。
/// 返回 (key, 未剥引号的 value) 序列；重复 key 由调用方按 C# Dictionary.Add
/// 抛异常的语义取首个（纯函数不可抛）。
fn key_value_pairs(text: &str) -> Vec<(String, String)> {
    let b = text.as_bytes();
    let mut out: Vec<(String, String)> = Vec::new();
    let mut i = 0usize;
    while i < b.len() {
        // 键必须以字母/下划线开头；否则该位置不可能起匹配
        if !(b[i].is_ascii_alphabetic() || b[i] == b'_') {
            i += 1;
            continue;
        }
        let key_start = i;
        while i < b.len() && (b[i].is_ascii_alphanumeric() || b[i] == b'_') {
            i += 1;
        }
        let key = &text[key_start..i];
        // 键后无 '=' → 该位置及键内均不可能起匹配（贪婪键回退也不可能命中）
        if i >= b.len() || b[i] != b'=' {
            continue;
        }
        i += 1;
        // value 备选：'...' | "..." | [^ ]*（按此顺序）
        let (value, next) = match b[i] {
            b'\'' | b'"' => {
                let q = b[i];
                match b[i + 1..].iter().position(|&c| c == q) {
                    Some(rel) => {
                        let end = i + 1 + rel + 1;
                        (text[i..end].to_string(), end)
                    }
                    None => {
                        // 无配对引号 → 落回 [^ ]*（含开头的引号）
                        let end = skip_non_space(b, i);
                        (text[i..end].to_string(), end)
                    }
                }
            }
            _ => {
                let end = skip_non_space(b, i);
                (text[i..end].to_string(), end)
            }
        };
        // C#：成对引号（首尾各一）剥除
        let value = strip_paired_quotes(&value);
        if !out.iter().any(|(k, _)| k == key) {
            out.push((key.to_string(), value));
        }
        i = next;
    }
    out
}

fn skip_non_space(b: &[u8], start: usize) -> usize {
    let mut end = start;
    while end < b.len() && b[end] != b' ' {
        end += 1;
    }
    end
}

/// C#：len ≥ 2 且首尾同为 `'` 或同为 `"` → 剥除。
fn strip_paired_quotes(value: &str) -> String {
    let b = value.as_bytes();
    if b.len() >= 2
        && ((b[0] == b'\'' && b[b.len() - 1] == b'\'') || (b[0] == b'"' && b[b.len() - 1] == b'"'))
    {
        value[1..b.len() - 1].to_string()
    } else {
        value.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;

    #[test]
    fn echo_dropped() {
        let from: SocketAddr = "240.0.13.0:1024".parse().unwrap();
        assert!(Vision360::default().parse(from, b"DISCOVER\n").is_empty());
    }

    #[test]
    fn newline_quirk_drops_char() {
        // 首个 \n 在位置 9 → text[..8] = "TYPE=CAM"（丢 '1'），KEY 行被整个丢掉
        let from: SocketAddr = "240.0.13.0:1024".parse().unwrap();
        let devs = Vision360::default().parse(from, b"TYPE=CAM1\nKEY=SN123\n");
        assert_eq!(devs.len(), 1);
        assert_eq!(devs[0].protocol, "360Vision");
        assert_eq!(devs[0].version, 1);
        assert_eq!(devs[0].device_type, "CAM");
        assert_eq!(devs[0].serial, "Unknown");
    }

    #[test]
    fn quotes_stripped_without_newline() {
        // 无 \n（EOS 不存在）→ 不截断；成对引号剥除
        let from: SocketAddr = "240.0.13.0:1024".parse().unwrap();
        let devs = Vision360::default().parse(from, br#"TYPE="T9" KEY='SN-9'"#);
        assert_eq!(devs.len(), 1);
        assert_eq!(devs[0].device_type, "T9");
        assert_eq!(devs[0].serial, "SN-9");
    }

    #[test]
    fn defaults_when_no_keys() {
        // 非回显但无 TYPE/KEY → "Unknown"/"Unknown"，ip = from
        let from: SocketAddr = "240.0.13.0:1024".parse().unwrap();
        let devs = Vision360::default().parse(from, b"hello");
        assert_eq!(devs.len(), 1);
        assert_eq!(devs[0].device_type, "Unknown");
        assert_eq!(devs[0].serial, "Unknown");
        assert_eq!(devs[0].ip, "240.0.13.0".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn key_value_pairs_manual_regex() {
        // 手工正则等价性抽查（引号备选顺序：'...' 优先于 "..."，再 [^ ]*）
        let pairs = key_value_pairs("TYPE=IPDOME KEY='00:11' ID=123 X=\"d\"");
        assert_eq!(
            pairs,
            vec![
                ("TYPE".to_string(), "IPDOME".to_string()),
                ("KEY".to_string(), "00:11".to_string()),
                ("ID".to_string(), "123".to_string()),
                ("X".to_string(), "d".to_string()),
            ]
        );
    }

    #[test]
    fn key_value_unterminated_quote_falls_back() {
        // 值以 ' 开头但无配对闭引号 → 落回 [^ ]*（含开头引号，不剥除）
        let pairs = key_value_pairs("Q='abc");
        assert_eq!(pairs, vec![("Q".to_string(), "'abc".to_string())]);
    }

    #[tokio::test]
    async fn fixture_replay() {
        let data = tokio::fs::read(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/360Vision.selftest"
        ))
        .await
        .unwrap();
        let from: SocketAddr = "240.0.13.0:1024".parse().unwrap();
        let devs = Vision360::default().parse(from, &data);
        // 期望值：对照 C# _360Vision.reciever/readKeyValuePairs 规则手工核定后填入
        //（注意 ip 恒为 from、文本按首个 \n 截断 quirk 核定）
        assert!(
            !devs.is_empty(),
            "360Vision fixture should yield >=1 device"
        );
        // TODO(T50): 填入完整 (protocol, version, ip, type, serial) 断言
    }
}
