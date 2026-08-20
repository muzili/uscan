//! mDNS broker：设备发现广播与响应处理。

/// 占位类型：T12 引入以便 `engine.rs` 编译；T16 替换为真实实现。
pub struct MdnsBroker;

/// C# IdnMapping.GetAscii 的等价：ASCII 域小写原样；非 ASCII label 转 xn--<punycode>。
/// UTS#46 完整规范化超出范围：真实注册域均为 ASCII；非 ASCII label 做小写 + punycode。
pub fn idn_ascii(domain: &str) -> String {
    domain
        .to_ascii_lowercase()
        .split('.')
        .map(|label| {
            if label.is_ascii() {
                label.to_string()
            } else {
                format!("xn--{}", punycode(label))
            }
        })
        .collect::<Vec<_>>()
        .join(".")
}

/// RFC 3492 Punycode 编码器（basic form；以 RFC §6.3/Appendix C 参考实现为准校对）。
/// 全 basic 输入按 RFC 追加尾随分隔符（§7.1 例 S）。
pub fn punycode(input: &str) -> String {
    let input: Vec<u32> = input.chars().map(|c| c as u32).collect();
    let mut output = String::new();
    for &cp in &input {
        if cp < 0x80 {
            output.push(cp as u8 as char);
        }
    }
    let b = input.iter().filter(|&&cp| cp < 0x80).count() as u32;
    let mut h = b;
    if b > 0 {
        output.push('-');
    }
    let mut n: u32 = 0x80;
    let mut delta: u32 = 0;
    let mut bias: u32 = 72;
    let len = input.len() as u32;
    while h < len {
        // m = 输入中最小的 ≥ n 的码点（h < len 时必然存在）
        let m = input
            .iter()
            .copied()
            .filter(|&cp| cp >= n)
            .min()
            .unwrap_or(0x11_0000);
        delta = delta.saturating_add((m - n).saturating_mul(h + 1));
        n = m;
        for &cp in &input {
            if cp < n {
                delta = delta.saturating_add(1);
            }
            if cp == n {
                let mut q = delta;
                let mut k: u32 = 36;
                loop {
                    let t = if k <= bias {
                        1
                    } else if k >= bias + 26 {
                        26
                    } else {
                        k - bias
                    };
                    if q < t {
                        break;
                    }
                    output.push(digit_char(t + (q - t) % (36 - t)));
                    q = (q - t) / (36 - t);
                    k += 36;
                }
                output.push(digit_char(q));
                bias = adapt(delta, h + 1, h == b);
                delta = 0;
                h += 1;
            }
        }
        delta = delta.saturating_add(1);
        n = n.saturating_add(1);
    }
    output
}

/// RFC 3492 encode_digit（小写）：0..25 → a..z，26..35 → 0..9。
fn digit_char(d: u32) -> char {
    (d + 22 + 75 * u32::from(d < 26)) as u8 as char
}

/// RFC 3492 §6.1 偏置适应（base=36, tmin=1, tmax=26, skew=38, damp=700）。
fn adapt(delta: u32, numpoints: u32, firsttime: bool) -> u32 {
    let delta = if firsttime { delta / 700 } else { delta / 2 };
    let delta = delta + delta / numpoints.max(1);
    let mut k = 0u32;
    let mut d = delta;
    while d > ((36 - 1) * 26) / 2 {
        d /= 36 - 1;
        k += 36;
    }
    k + (36 - 1 + 1) * d / (d + 38)
}

/// DNS 名字编码（labels + NULL）。
pub fn encode_name(domain: &str) -> Vec<u8> {
    let mut out = Vec::new();
    for label in domain.split('.') {
        let b = label.as_bytes();
        out.push(b.len() as u8);
        out.extend_from_slice(b);
    }
    out.push(0);
    out
}

#[cfg(test)]
mod tests {
    //! DNS 名字编码 + Punycode（T13）。

    use super::*;

    #[test]
    fn encode_ascii_labels() {
        assert_eq!(
            encode_name("_axis-video._tcp.local"),
            vec![
                0x0b, b'_', b'a', b'x', b'i', b's', b'-', b'v', b'i', b'd', b'e', b'o', 0x04, b'_',
                b't', b'c', b'p', 0x05, b'l', b'o', b'c', b'a', b'l', 0x00,
            ]
        );
    }

    #[test]
    fn punycode_basic() {
        // 向量以 RFC 3492 参考实现（Appendix C）为准校对。
        assert_eq!(punycode("müller"), "mller-kva");
        assert_eq!(punycode("bücher"), "bcher-kva");
        // 全 ASCII 输入：basic 段 + 尾随分隔符（RFC 3492 §7.1 例 S）。
        assert_eq!(punycode("hello"), "hello-");
    }

    #[test]
    fn idn_label() {
        // 非 ASCII label → xn--<punycode>（.NET IdnMapping.GetAscii 的 ASCII 域简化等价）
        assert_eq!(idn_ascii("müller.local"), "xn--mller-kva.local");
        assert_eq!(idn_ascii("axis.local"), "axis.local");
    }

    #[test]
    fn rfc3492_cjk_examples() {
        // RFC 3492 §7.1/§7.3 官方样例（CJK 防回归）。
        assert_eq!(punycode("他们为什么不说中文"), "ihqwcrb4cv8a8dqg056pqjye");
        assert_eq!(punycode("3年B組金八先生"), "3B-ww4c5e180e575a65lsy2b");
    }
}
