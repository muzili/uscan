//! mDNS broker：设备发现广播与响应处理。

use crate::errors::Error;
use crate::ports::PortProvider;
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::os::fd::{AsRawFd, BorrowedFd};
use std::sync::{Arc, Mutex, RwLock};
use tokio::net::UdpSocket;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

pub type DomainHandler = Arc<dyn Fn(&str, &[MdnsAnswer]) + Send + Sync>;

const MDNS_GROUP: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 251);
const MDNS_PORT: u16 = 5353;

/// mDNS 发现 broker：域名注册 + 组播/网卡 socket 接收 + PTR 查询 + 应答分发。
pub struct MdnsBroker {
    handlers: RwLock<HashMap<String, DomainHandler>>,
    cancel: CancellationToken,
    logger: Arc<crate::log::Logger>,
    /// listen 保存的网卡 socket；scan 复用它们发送（C# interfacesListerner 语义）。
    send_sockets: Mutex<Vec<Arc<UdpSocket>>>,
}

impl MdnsBroker {
    pub fn new(logger: Arc<crate::log::Logger>, cancel: CancellationToken) -> Arc<Self> {
        Arc::new(Self {
            handlers: RwLock::new(HashMap::new()),
            cancel,
            logger,
            send_sockets: Mutex::new(Vec::new()),
        })
    }

    #[cfg(test)]
    pub fn new_for_test() -> Arc<Self> {
        Self::new(
            Arc::new(crate::log::Logger::new(crate::log::Level::Debug)),
            CancellationToken::new(),
        )
    }

    pub fn register_domain(&self, filter: &str, handler: DomainHandler) {
        self.handlers
            .write()
            .unwrap()
            .insert(filter.to_string(), handler);
    }

    pub fn is_empty(&self) -> bool {
        self.handlers.read().unwrap().is_empty()
    }

    /// C# mDNS.getUsedPort：固定 5353（broker 端口由 broker 管理，T41 透传）。
    pub fn get_used_ports(&self) -> &[u16] {
        &[MDNS_PORT]
    }

    /// 接收路径（纯）：解析 → 首个匹配注册域名的 answer 触发**整包** answers 分发（C# triggerName 语义）。
    pub fn on_packet(&self, data: &[u8]) {
        let parsed = match parse_dns(data) {
            Ok(p) => p,
            Err(e) => {
                self.logger.warn(0, &format!("mDNS parse failed: {e}"));
                return;
            }
        };
        if parsed.answers.is_empty() {
            return;
        }
        let handlers = self.handlers.read().unwrap();
        let trigger = parsed
            .answers
            .iter()
            .find(|a| handlers.contains_key(&a.name));
        if let Some(t) = trigger {
            if let Some(h) = handlers.get(&t.name) {
                h(t.name.as_str(), &parsed.answers);
            }
        }
    }

    /// C# mDNS.listen：listenMulticast(224.0.0.251, 5353) + listenUdpInterfaces()（**无 global listener**）。
    /// 网卡 socket 绑 <ip>:PortProvider.free_port()（C# listenUdpInterfaces），存入 send_sockets 供 scan 复用。
    /// 接收任务需持有 broker 的 Arc，故 receiver 为 &Arc<Self>（调用方 Arc<MdnsBroker> 自动适配）。
    pub fn listen(
        self: &Arc<Self>,
        iface_ips: &[Ipv4Addr],
        ports: &Arc<Mutex<PortProvider>>,
        task_id: u32,
    ) -> crate::Result<Vec<JoinHandle<()>>> {
        let mut handles = Vec::new();
        // 组播 socket
        let (msock, _msync) = crate::net::udp_bind_multicast(
            MDNS_GROUP,
            MDNS_PORT,
            iface_ips,
            &self.logger,
            task_id,
        )?;
        let msock = Arc::new(msock);
        let ctx_self = Arc::clone(self);
        let mctx = msock.clone();
        handles.push(tokio::spawn(async move {
            let mut buf = vec![0u8; 65535];
            loop {
                tokio::select! {
                    _ = ctx_self.cancel.cancelled() => break,
                    res = mctx.recv_from(&mut buf) => {
                        if let Ok((n, _from)) = res {
                            ctx_self.on_packet(&buf[..n]);
                        }
                    }
                }
            }
        }));
        // 各网卡 socket（C# listenUdpInterfaces；接收同样喂 on_packet）
        let mut socks = self.send_sockets.lock().unwrap();
        for ip in iface_ips {
            let port = match ports.lock().unwrap().free_port() {
                Some(p) => p,
                None => {
                    self.logger
                        .warn(task_id, &format!("mDNS listen: no free port for {ip}"));
                    continue;
                }
            };
            match crate::net::udp_bind_interface(*ip, port) {
                Ok((_, sock, _sync)) => {
                    let s2 = Arc::new(sock);
                    socks.push(s2.clone());
                    let c2 = Arc::clone(self);
                    handles.push(tokio::spawn(async move {
                        let mut buf = vec![0u8; 65535];
                        loop {
                            tokio::select! {
                                _ = c2.cancel.cancelled() => break,
                                res = s2.recv_from(&mut buf) => {
                                    if let Ok((n, _from)) = res {
                                        c2.on_packet(&buf[..n]);
                                    }
                                }
                            }
                        }
                    }));
                }
                Err(e) => {
                    self.logger.warn(
                        task_id,
                        &format!("mDNS listen: bind {ip}:{port} failed: {e}"),
                    );
                }
            }
        }
        Ok(handles)
    }

    /// C# mDNS.scan：PTR 查询仅从 listen 保存的网卡 socket 发出（无 global、不经组播 socket）。
    /// `_iface_ips` 仅保持与 C# scan(queryString) 调用方签名兼容。
    pub fn scan(&self, domain: &str, _iface_ips: &[Ipv4Addr]) -> crate::Result<()> {
        // C# scan 原样发送 buildQuery 输出（完整查询包：12 字节头 + question），不得再套头。
        let pkt = build_query(domain, 0x000C)?;
        let dest: socket2::SockAddr = std::net::SocketAddr::from((MDNS_GROUP, MDNS_PORT)).into();
        let sends = self.send_sockets.lock().unwrap();
        for s in sends.as_slice() {
            // tokio socket 为 non-blocking：经 fd 同步发送（socket2）
            // SAFETY: s 由 Arc 保活，锁持有期间 fd 有效。
            let dup = unsafe { BorrowedFd::borrow_raw(s.as_raw_fd()) }.try_clone_to_owned();
            match dup {
                Ok(dup) => {
                    let sock = socket2::Socket::from(dup);
                    if let Err(e) = sock.send_to(&pkt, &dest) {
                        self.logger.warn(0, &format!("mDNS scan: send failed: {e}"));
                    }
                }
                Err(e) => self
                    .logger
                    .warn(0, &format!("mDNS scan: fd dup failed: {e}")),
            }
        }
        Ok(())
    }
}

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

/// C# mDNS.buildQuery：12 字节头（id=0, flags=0, qd=1）+ 名字（IDN→ASCII）+ type + class 1。
pub fn build_query(domain: &str, qtype: u16) -> crate::Result<Vec<u8>> {
    let name = encode_name(&idn_ascii(domain));
    let mut out = vec![0u8; 12];
    out[4..6].copy_from_slice(&1u16.to_be_bytes());
    out.extend_from_slice(&name);
    out.extend_from_slice(&qtype.to_be_bytes());
    out.extend_from_slice(&1u16.to_be_bytes()); // IN
    Ok(out)
}

// ---------- DNS 应答解析（T15；C# readAnswers/readString/readAnswer_* 逐字节对齐） ----------

/// 一条应答的数据（对应 C# mDNSAnswerData 联合体）。
#[derive(Debug, Clone)]
pub enum MdnsData {
    A(IpAddr),
    AAAA(IpAddr),
    Ptr(String),
    Txt(Vec<String>),
    Srv {
        priority: u16,
        weight: u16,
        port: u16,
        target: String,
    },
}

#[derive(Debug, Clone)]
pub struct MdnsAnswer {
    pub rrtype: u16,
    pub name: String,
    pub data: MdnsData,
}

pub struct DnsParse {
    pub answers: Vec<MdnsAnswer>,
}

fn rd16(d: &[u8], pos: &mut usize) -> crate::Result<u16> {
    if *pos + 2 > d.len() {
        return Err(Error::Dns("u16 overflow".into()));
    }
    let v = u16::from_be_bytes([d[*pos], d[*pos + 1]]);
    *pos += 2;
    Ok(v)
}

fn rd32(d: &[u8], pos: &mut usize) -> crate::Result<u32> {
    if *pos + 4 > d.len() {
        return Err(Error::Dns("u32 overflow".into()));
    }
    let v = u32::from_be_bytes([d[*pos], d[*pos + 1], d[*pos + 2], d[*pos + 3]]);
    *pos += 4;
    Ok(v)
}

/// DNS 名字（压缩指针，budget=16 重定向，C# maxCallBack 语义）。
/// 返回 (name, name 字段之后的 position)。
fn read_name(data: &[u8], pos: usize, budget: &mut u32) -> crate::Result<(String, usize)> {
    let mut name = String::new();
    let mut p = pos;
    loop {
        if p >= data.len() {
            return Err(Error::Dns("name overflow".into()));
        }
        let len = data[p];
        p += 1;
        if len == 0 {
            return Ok((name, p));
        }
        if !name.is_empty() {
            name.push('.');
        }
        if len & 0xC0 == 0xC0 {
            if p >= data.len() {
                return Err(Error::Dns("ptr overflow".into()));
            }
            let target = (((len & 0x3F) as usize) << 8) | data[p] as usize;
            p += 1;
            if target >= data.len() {
                return Err(Error::Dns("ptr out of bounds".into()));
            }
            *budget = budget.saturating_sub(1);
            if *budget == 0 {
                return Err(Error::Dns("max redirects (16) exceeded".into()));
            }
            let (rest, _) = read_name(data, target, budget)?;
            name.push_str(&rest);
            return Ok((name, p)); // p = 指针 2 字节之后
        }
        let end = p
            .checked_add(len as usize)
            .filter(|e| *e <= data.len())
            .ok_or_else(|| Error::Dns("label overflow".into()))?;
        name.push_str(&String::from_utf8_lossy(&data[p..end]));
        p = end;
    }
}

/// C# readAnswer_TXT 逐行对齐（含 `dataLen > 1` 外层条件 quirk）。
fn parse_txt(data: &[u8], pos: &mut usize, rdlen: u16) -> Vec<String> {
    let mut out = Vec::new();
    let mut remaining = rdlen as usize;
    while remaining > 1 && *pos + 1 < data.len() {
        let mut len = data[*pos] as usize;
        *pos += 1;
        remaining -= 1;
        let mut s = String::new();
        while len > 0 && remaining > 0 && *pos < data.len() {
            s.push(data[*pos] as char);
            *pos += 1;
            remaining -= 1;
            len -= 1;
        }
        out.push(s);
    }
    out
}

fn parse_srv(data: &[u8], pos: usize, rdlen: u16) -> MdnsData {
    if rdlen < 6 {
        return MdnsData::Srv {
            priority: 0,
            weight: 0,
            port: 0,
            target: String::new(),
        };
    }
    let priority = u16::from_be_bytes([data[pos], data[pos + 1]]);
    let weight = u16::from_be_bytes([data[pos + 2], data[pos + 3]]);
    let port = u16::from_be_bytes([data[pos + 4], data[pos + 5]]);
    let target = read_name(data, pos + 6, &mut 16)
        .map(|(n, _)| n)
        .unwrap_or_default();
    MdnsData::Srv {
        priority,
        weight,
        port,
        target,
    }
}

/// C# mDNS.reciever + readAnswers 语义：
/// - questions 段跳过；answer+authority+additional 三节合并解析；
/// - 未知 RRTYPE → 截断并返回已解析部分；rdata 越界 → Err（不分发）；
/// - A/AAAA rdlen 不符 → 0.0.0.0/::（Rust 前进 rdlen，C# 不前进——spec §8.2 注记）。
pub fn parse_dns(data: &[u8]) -> crate::Result<DnsParse> {
    if data.len() <= 12 {
        return Err(Error::Dns("packet too short".into()));
    }
    // 头：id(0..2) flags(2..4) qd(4) an(6) ns(8) ar(10)；RR 段自 12 起（C# mDNSHeader 布局）
    let mut h = 4usize;
    let qd = rd16(data, &mut h)?;
    let an = rd16(data, &mut h)?;
    let ns = rd16(data, &mut h)?;
    let ar = rd16(data, &mut h)?;
    let mut pos = 12usize;
    for _ in 0..qd {
        if pos >= data.len() {
            return Err(Error::Dns("question overflow".into()));
        }
        let (_, np) = read_name(data, pos, &mut 16)?;
        pos = np;
        rd16(data, &mut pos)?;
        rd16(data, &mut pos)?;
    }
    // usize 求和防 u16 溢出（构造包 an/ns/ar 全大时 debug 构建不得 panic，release 不得回绕）。
    let total = an as usize + ns as usize + ar as usize;
    let mut answers = Vec::new();
    let mut budget = 16u32;
    for _ in 0..total {
        if pos >= data.len() {
            break;
        }
        let (name, np) = read_name(data, pos, &mut budget)?;
        pos = np;
        let rrtype = rd16(data, &mut pos)?;
        let _class = rd16(data, &mut pos)?;
        let _ttl = rd32(data, &mut pos)?;
        let rdlen = rd16(data, &mut pos)? as usize;
        if pos + rdlen > data.len() {
            return Err(Error::Dns("rdata out of bounds".into()));
        }
        let data_end = pos + rdlen;
        let rdata = match rrtype {
            4 => {
                let ip = if rdlen != 4 {
                    std::net::Ipv4Addr::UNSPECIFIED
                } else {
                    ipv4_from(data, pos)
                };
                MdnsData::A(ip.into())
            }
            28 => {
                let ip = if rdlen != 16 {
                    std::net::Ipv6Addr::UNSPECIFIED
                } else {
                    let b: [u8; 16] = data[pos..pos + 16].try_into().unwrap();
                    std::net::Ipv6Addr::from(b)
                };
                MdnsData::AAAA(ip.into())
            }
            12 => {
                let (n, _) = read_name(data, pos, &mut budget)?;
                MdnsData::Ptr(n)
            }
            16 => MdnsData::Txt(parse_txt(data, &mut pos, rdlen as u16)),
            33 => parse_srv(data, pos, rdlen as u16),
            _ => {
                // 未知类型：截断 + 部分分发（C# Array.Resize 语义）
                return Ok(DnsParse { answers });
            }
        };
        pos = data_end;
        answers.push(MdnsAnswer {
            rrtype,
            name,
            data: rdata,
        });
    }
    Ok(DnsParse { answers })
}

fn ipv4_from(data: &[u8], pos: usize) -> std::net::Ipv4Addr {
    std::net::Ipv4Addr::from([data[pos], data[pos + 1], data[pos + 2], data[pos + 3]])
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
    fn build_query_bytes() {
        let q = build_query("_axis-video._tcp.local", 0x000C).unwrap();
        // 12 字节头：id=0 flags=0 qd=1 an=0 ns=0 ar=0
        assert_eq!(&q[0..12], &[0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0]);
        let name = encode_name("_axis-video._tcp.local");
        assert_eq!(&q[12..12 + name.len()], &name);
        // 结尾：type PTR + class IN
        let (t, c) = (
            q[q.len() - 4..q.len() - 2].try_into().unwrap(),
            q[q.len() - 2..].try_into().unwrap(),
        );
        assert_eq!(u16::from_be_bytes(t), 0x000C);
        assert_eq!(u16::from_be_bytes(c), 0x0001);
    }

    #[test]
    fn rfc3492_cjk_examples() {
        // RFC 3492 §7.1/§7.3 官方样例（CJK 防回归）。
        assert_eq!(punycode("他们为什么不说中文"), "ihqwcrb4cv8a8dqg056pqjye");
        assert_eq!(punycode("3年B組金八先生"), "3B-ww4c5e180e575a65lsy2b");
    }

    // ---------- DNS 应答解析（T15） ----------

    /// 构造：12 字节头 + questions 段 + 指定 RR 段。
    fn pkt(qd: u16, rrs: &[u8], an: u16, ns: u16, ar: u16) -> Vec<u8> {
        let mut p = vec![0u8; 12];
        p[4..6].copy_from_slice(&qd.to_be_bytes());
        p[6..8].copy_from_slice(&an.to_be_bytes());
        p[8..10].copy_from_slice(&ns.to_be_bytes());
        p[10..12].copy_from_slice(&ar.to_be_bytes());
        if qd > 0 {
            p.extend_from_slice(&[1, b'a', 0, 0, 0, 12, 0, 1]); // 问题占位（name 'a'）
        }
        p.extend_from_slice(rrs);
        p
    }

    fn rr(name: &[u8], rrtype: u16, rdata: &[u8]) -> Vec<u8> {
        let mut v = name.to_vec();
        v.extend_from_slice(&rrtype.to_be_bytes());
        v.extend_from_slice(&1u16.to_be_bytes()); // class IN (flush bit 视情况)
        v.extend_from_slice(&0u32.to_be_bytes()); // ttl
        v.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
        v.extend_from_slice(rdata);
        v
    }

    #[test]
    fn parses_a_in_all_three_sections() {
        let a1 = rr(&encode_name("cam.local"), 4, &[192, 168, 1, 50]);
        let a2 = rr(&encode_name("cam.local"), 4, &[192, 168, 1, 51]);
        let a3 = rr(
            &encode_name("cam.local"),
            28,
            &[0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
        );
        let p = pkt(0, &[a1, a2, a3].concat(), 1, 1, 1);
        let r = parse_dns(&p).unwrap();
        assert_eq!(r.answers.len(), 3);
        let a50: IpAddr = "192.168.1.50".parse().unwrap();
        let a51: IpAddr = "192.168.1.51".parse().unwrap();
        let fe80: IpAddr = "fe80::1".parse().unwrap();
        assert!(matches!(r.answers[0].data, MdnsData::A(ip) if ip == a50));
        assert!(matches!(r.answers[1].data, MdnsData::A(ip) if ip == a51));
        assert!(matches!(r.answers[2].data, MdnsData::AAAA(ip) if ip == fe80));
    }

    #[test]
    fn compression_pointer_resolved() {
        // 'cam.local' 全名在 offset 12（questions=0 时）
        let name = encode_name("cam.local");
        let full = rr(&name, 4, &[10, 0, 0, 1]);
        let ptr_offset = 12u16; // rr 起始处
                                // 追加一条用 0xC0 指针引用 cam.local 的 PTR；rdata 也是同一压缩指针
        let ptr2: Vec<u8> = vec![0xC0u8, (ptr_offset & 0x3F) as u8]; // 指针 0xC00C → [0xC0, 0x0C]
        let ptr_rr = rr(&ptr2, 12, &[0xC0, 0x0C]);
        let p2 = pkt(0, &[full, ptr_rr].concat(), 2, 0, 0);
        let r = parse_dns(&p2).unwrap();
        assert_eq!(r.answers[1].name, "cam.local");
        assert!(matches!(&r.answers[1].data, MdnsData::Ptr(n) if n == "cam.local"));
    }

    #[test]
    fn unknown_rrtype_truncates_and_returns_partial() {
        let good = rr(&encode_name("cam.local"), 4, &[10, 0, 0, 1]);
        let unknown = rr(&encode_name("x.local"), 0x42, b"zz");
        let more = rr(&encode_name("cam.local"), 4, &[10, 0, 0, 2]);
        let p = pkt(0, &[good, unknown, more].concat(), 3, 0, 0);
        let r = parse_dns(&p).unwrap();
        assert_eq!(r.answers.len(), 1); // 未知类型截断，后续不解析（C# Array.Resize 语义）
    }

    #[test]
    fn oob_rdata_no_dispatch() {
        // rdlen 声称 4 但 rdata 只有 3 字节（rr 辅助函数 rdlen=实际长度，故手工构造）
        let mut bad = encode_name("cam.local");
        bad.extend_from_slice(&4u16.to_be_bytes()); // rrtype A
        bad.extend_from_slice(&1u16.to_be_bytes()); // class IN
        bad.extend_from_slice(&0u32.to_be_bytes()); // ttl
        bad.extend_from_slice(&4u16.to_be_bytes()); // rdlen 声称 4
        bad.extend_from_slice(&[10, 0, 0]); // 但只有 3 字节
        let p = pkt(0, &bad, 1, 0, 0);
        assert!(parse_dns(&p).is_err());
    }

    #[test]
    fn txt_loop_uses_datalen_gt_1() {
        // C# quirk：外层 while (dataLen > 1)——首长度字节为 1 时读完 1 字符后停止，["a"]
        let t = rr(&encode_name("cam.local"), 16, &[1, b'a', b'b']);
        let p = pkt(0, &t, 1, 0, 0);
        let r = parse_dns(&p).unwrap();
        match &r.answers[0].data {
            MdnsData::Txt(v) => assert_eq!(v.as_slice(), &["a"]),
            _ => panic!("expected TXT"),
        }
        // 正常 2 项：len-prefixed
        let t2 = rr(
            &encode_name("cam.local"),
            16,
            &[2, b'a', b'b', 3, b'c', b'd', b'e'],
        );
        let p2 = pkt(0, &t2, 1, 0, 0);
        let r2 = parse_dns(&p2).unwrap();
        match &r2.answers[0].data {
            MdnsData::Txt(v) => assert_eq!(v.as_slice(), &["ab", "cde"]),
            _ => panic!("expected TXT"),
        }
    }

    #[test]
    fn a_wrong_rdlen_warns_and_advances() {
        // C# 不前进 position（quirk）；Rust 前进 rdlen（spec §8.2 注记）——后续 RR 仍可解析
        let bad = rr(&encode_name("cam.local"), 4, &[1, 2, 3, 4, 5]); // rdlen 5
        let good = rr(&encode_name("cam.local"), 4, &[10, 0, 0, 1]);
        let p = pkt(0, &[bad, good].concat(), 2, 0, 0);
        let r = parse_dns(&p).unwrap();
        assert_eq!(r.answers.len(), 2);
        let any: IpAddr = std::net::Ipv4Addr::UNSPECIFIED.into();
        assert!(matches!(r.answers[0].data, MdnsData::A(ip) if ip == any));
    }

    #[test]
    fn max_redirects_16th_fails() {
        // 16 层指针链 → Err（C# maxCallBack=16：第 16 次重定向 throw）
        // 构造：questions=0；offset 12（A RR 的 name 位置）放 16 个指针，
        // 前 15 个依次指向下一个，第 16 个指回链首（环）
        let mut full = vec![0u8; 12];
        full[6..8].copy_from_slice(&1u16.to_be_bytes()); // an=1
        let chain_start = 12usize;
        let offs: Vec<usize> = (0..16).map(|i| chain_start + i * 2).collect();
        for i in 0..15 {
            let target = offs[i + 1] as u16;
            full.extend_from_slice(&[0xC0 | (target >> 8) as u8, (target & 0xFF) as u8]);
        }
        let target = chain_start as u16;
        full.extend_from_slice(&[0xC0 | (target >> 8) as u8, (target & 0xFF) as u8]);
        // 链后接 A RR 的 type/class/ttl/rdlen/rdata
        full.extend_from_slice(&4u16.to_be_bytes());
        full.extend_from_slice(&1u16.to_be_bytes());
        full.extend_from_slice(&0u32.to_be_bytes());
        full.extend_from_slice(&4u16.to_be_bytes());
        full.extend_from_slice(&[10, 0, 0, 1]);
        assert!(parse_dns(&full).is_err());
    }

    #[test]
    fn header_counts_lying_no_overflow() {
        // an+ns+ar 按 u16 相加会溢出（0xFFFE+0x0002）：必须不 panic（debug）不回绕（release）。
        let mut p = vec![0u8; 13];
        p[6..8].copy_from_slice(&0xFFFE_u16.to_be_bytes());
        p[8..10].copy_from_slice(&0x0002_u16.to_be_bytes());
        p[12] = 0x00;
        // 越界/截断均可，唯一要求：不 panic
        let _ = parse_dns(&p);
    }
}

#[cfg(test)]
mod broker_tests {
    use super::*;
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    };

    fn a_answer_pkt(name: &str) -> Vec<u8> {
        // 1 条 A 应答，name = 给定域名（an=1）
        let mut p = vec![0u8; 12];
        p[6..8].copy_from_slice(&1u16.to_be_bytes());
        let mut r = encode_name(name);
        r.extend_from_slice(&4u16.to_be_bytes());
        r.extend_from_slice(&1u16.to_be_bytes());
        r.extend_from_slice(&0u32.to_be_bytes());
        r.extend_from_slice(&4u16.to_be_bytes());
        r.extend_from_slice(&[10, 0, 0, 1]);
        p.extend_from_slice(&r);
        p
    }

    #[tokio::test]
    async fn dispatches_to_first_matching_domain() {
        let b = MdnsBroker::new_for_test();
        let hits: Arc<AtomicUsize> = Arc::new(AtomicUsize::new(0));
        let h = hits.clone();
        b.register_domain(
            "cam.local",
            Arc::new(move |_dom, answers| {
                h.fetch_add(answers.len(), Ordering::SeqCst);
            }),
        );
        b.on_packet(&a_answer_pkt("cam.local"));
        assert_eq!(hits.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn no_match_no_dispatch() {
        let b = MdnsBroker::new_for_test();
        let hits = Arc::new(AtomicUsize::new(0));
        let h = hits.clone();
        b.register_domain(
            "other.local",
            Arc::new(move |_d, a| {
                h.fetch_add(a.len(), Ordering::SeqCst);
            }),
        );
        b.on_packet(&a_answer_pkt("cam.local"));
        assert_eq!(hits.load(Ordering::SeqCst), 0);
    }

    /// 回归：scan 的线上包 = buildQuery 输出原样（单 12 字节头 + question）。
    /// 曾因 scan 再套一层头发出 52 字节双头查询，真实 mDNS 应答端不会响应。
    #[test]
    fn scan_packet_single_header() {
        let pkt = build_query("_axis-video._tcp.local", 0x000C).unwrap();
        // 12 头 + 24 名字（0x0b+_axis-video, 0x04+_tcp, 0x05+local, 0）+ 4 type/class
        assert_eq!(pkt.len(), 40);
        assert_eq!(&pkt[0..12], &[0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0]);
        assert_eq!(&pkt[12..36], &encode_name("_axis-video._tcp.local"));
        assert_eq!(&pkt[36..38], &0x000C_u16.to_be_bytes());
        assert_eq!(&pkt[38..40], &1u16.to_be_bytes());
    }
}
