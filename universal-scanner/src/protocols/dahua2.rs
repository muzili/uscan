//! Dahua2 引擎（T22）：parse 对齐 C# Dahua2.reciever（手工 JSON 提取），probe 照 C# 结构体逐字节。

use crate::devices::Device;
use crate::engine::{EngineContext, ScanEngine};
use crate::net::SocketSet;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Mutex;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

const GROUP: Ipv4Addr = Ipv4Addr::new(239, 255, 255, 251);
const PORT: u16 = 37810;
const HEADER_SIZE: usize = 0x20;

/// C# sender 的 JSON 体（逐字，含结尾 \n）。
const BODY: &str = "{\"method\":\"DHDiscover.search\",\"params\":{\"mac\":\"\",\"uni\":0}}\n";

/// C# Dahua2Header 序列化（x86 LE 结构体）：headerSize=32 LE、magic 线上为 ASCII 'DHIP'
///（C# bigEndian32(0x44484950) 再 LE 落盘，大小端混用照抄）、packetSize1/2 = 体长 LE。
fn header(body_len: u32) -> [u8; HEADER_SIZE] {
    let mut h = [0u8; HEADER_SIZE];
    h[0x00..0x04].copy_from_slice(&(HEADER_SIZE as u32).to_le_bytes());
    h[0x04..0x08].copy_from_slice(b"DHIP");
    h[0x10..0x14].copy_from_slice(&body_len.to_le_bytes());
    h[0x18..0x1C].copy_from_slice(&body_len.to_le_bytes());
    h
}

/// C# sender()：32B 头 + JSON 体。
fn build_probe() -> Vec<u8> {
    let mut probe = header(BODY.len() as u32).to_vec();
    probe.extend_from_slice(BODY.as_bytes());
    probe
}

pub struct Dahua2 {
    socks: SocketSet,
    /// 当前 netscan sweep 的取消令牌；新一轮 scan 先取消上一轮（C# Thread.Abort 语义，同 Arecont）。
    sweep: Mutex<Option<CancellationToken>>,
}

impl Default for Dahua2 {
    fn default() -> Self {
        Self {
            socks: SocketSet::new(),
            sweep: Mutex::new(None),
        }
    }
}

impl Dahua2 {
    /// C# `Dahua2.scan` → `if (Config.DahuaNetScan) sendNetScan(port)`：
    /// 新一轮先取消上一轮 sweep（C# `scannerThread.Abort` 语义），再 spawn 可取消的子网扫描。
    fn start_netscan(&self, ctx: &EngineContext, probe: &[u8]) {
        let sweep = CancellationToken::new();
        {
            let mut cur = self.sweep.lock().unwrap();
            if let Some(old) = cur.replace(sweep.clone()) {
                old.cancel();
            }
        }
        let socks = self.socks.clone();
        let logger = ctx.logger.clone();
        let cancel = ctx.cancel.clone();
        let task_id = ctx.task_id;
        let handle = tokio::spawn(crate::netscan::netscan(
            socks,
            logger,
            cancel,
            sweep,
            task_id,
            probe.to_vec(),
            PORT,
        ));
        // 句柄登记进 ctx.sweeps：Scanner::stop() 取消后 join，避免悬空任务
        ctx.sweeps.lock().unwrap().push(handle);
    }

    /// 测试用：当前 sweep 的取消令牌（验证 scan 接线与"取消上一轮"语义）。
    #[cfg(test)]
    fn sweep_token(&self) -> Option<CancellationToken> {
        self.sweep.lock().unwrap().clone()
    }
}

impl ScanEngine for Dahua2 {
    fn name(&self) -> &str {
        "Dahua"
    }
    fn used_ports(&self) -> &[u16] {
        &[PORT]
    }
    fn color(&self) -> u32 {
        0x8b0000 // Color.DarkRed
    }

    fn listen(&self, ctx: std::sync::Arc<EngineContext>) -> crate::Result<Vec<JoinHandle<()>>> {
        let ifaces = crate::iface::active_interfaces();
        let nic_ips: Vec<Ipv4Addr> = ifaces.iter().flat_map(|i| i.ipv4_addrs()).collect();
        // recv_loop 只调用 parse()（纯函数），用新实例即可，无需自引用。
        let e: std::sync::Arc<dyn ScanEngine> = std::sync::Arc::new(Self::default());
        let mut handles = Vec::new();
        // 组播（本引擎无 global）
        let (msock, msync) =
            crate::net::udp_bind_multicast(GROUP, PORT, &nic_ips, &ctx.logger, ctx.task_id)?;
        self.socks.add(msync);
        handles.push(tokio::spawn(crate::net::recv_loop(
            ctx.clone(),
            std::sync::Arc::clone(&e),
            msock,
        )));
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
                std::sync::Arc::clone(&e),
                isock,
            )));
        }
        Ok(handles)
    }

    fn scan(&self, ctx: &EngineContext) -> crate::Result<()> {
        // C# Dahua2.scan：sendMulticast(239.255.255.251, 37810) + sendBroadcast(37810)
        let probe = build_probe();
        let mut failed = self.socks.send_multicast(GROUP, PORT, &probe);
        failed += self.socks.send_broadcast(PORT, &probe);
        // C# if (Config.DahuaNetScan) sendNetScan(port)：spawn 可取消的 sweep（T49）
        if ctx.config.dahua_net_scan {
            self.start_netscan(ctx, &probe);
        }
        if failed > 0 {
            ctx.logger
                .warn(ctx.task_id, &format!("{} Dahua sends failed", failed));
        }
        Ok(())
    }

    fn parse(&self, from: SocketAddr, data: &[u8]) -> Vec<Device> {
        // C# GetStruct：短包时结构体全零 → headerSize 校验必失败
        if data.len() < HEADER_SIZE {
            return Vec::new();
        }
        // C# littleEndian32 在 LE 平台上是恒等：头字段按 LE 原样读
        let header_size = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
        if header_size != HEADER_SIZE as u32 {
            return Vec::new();
        }
        let packet_size = data.len() - HEADER_SIZE;
        let packet_size1 = u32::from_le_bytes([data[0x10], data[0x11], data[0x12], data[0x13]]);
        if packet_size1 != packet_size as u32 {
            return Vec::new();
        }
        let body = String::from_utf8_lossy(&data[HEADER_SIZE..]);
        // C# reciever：method 必须为 client.notifyDevInfo，否则整包不上报
        let method = extract_json_string("method", &body).unwrap_or_default();
        if method != "client.notifyDevInfo" {
            return Vec::new();
        }
        let device_model =
            extract_json_string("DeviceType", &body).unwrap_or_else(|| "Dahua".into());
        let ipv4_str = extract_json_section("IPv4Address", &body)
            .and_then(|sec| extract_json_string("IPAddress", &sec))
            .unwrap_or_else(|| from.ip().to_string());
        let mut device_ipv6: Option<String> = None;
        if let Some(sec) = extract_json_section("IPv6Address", &body) {
            if let Some(mut v6) = extract_json_string("IPAddress", &sec) {
                // C# quirk：首个 '/' 或 '\\' 处 Substring(0, sub-1)——分隔符前一字符也丢
                if let Some((sub, _)) = v6.char_indices().find(|(_, c)| *c == '/' || *c == '\\') {
                    if sub > 0 {
                        v6 = v6[..sub - 1].to_string();
                    }
                }
                device_ipv6 = Some(v6);
            }
        }
        let device_serial = extract_json_string("SerialNo", &body)
            .or_else(|| extract_json_string("mac", &body))
            .unwrap_or_else(|| "Dahua device".to_string());
        // C# IPAddress.TryParse 接受 v4/v6；失败 → from（warn 由 T48 侧记）
        let mut ip: std::net::IpAddr = ipv4_str.parse().unwrap_or_else(|_| from.ip());
        // C# quirk：0.0.0.0 → 回退 from
        if ip == std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED) {
            ip = from.ip();
        }
        let mut devs = vec![Device {
            protocol: "Dahua".into(),
            version: 2,
            ip,
            device_type: device_model.clone(),
            serial: device_serial.clone(),
        }];
        // IPv6 解析成功 → 另报一条（version 2）
        if let Some(v6) = device_ipv6 {
            if let Ok(ip6) = v6.parse::<std::net::IpAddr>() {
                devs.push(Device {
                    protocol: "Dahua".into(),
                    version: 2,
                    ip: ip6,
                    device_type: device_model,
                    serial: device_serial,
                });
            }
        }
        devs
    }
}

/// C# extractJsonString：正则 `"key" *: *"([^"]*)"` 的手工等价
///（首个字面量 "key" 后：空格* ':' 空格* 引号串，首个命中即返回）。
fn extract_json_string(key: &str, json: &str) -> Option<String> {
    let pat = format!("\"{key}\"");
    let mut cursor = 0usize;
    while let Some(off) = json[cursor..].find(&pat) {
        let i = skip_spaces(json, cursor + off + pat.len());
        if i < json.len() && json.as_bytes()[i] == b':' {
            let j = skip_spaces(json, i + 1);
            if j < json.len() && json.as_bytes()[j] == b'"' {
                if let Some(end) = json[j + 1..].find('"') {
                    return Some(json[j + 1..j + 1 + end].to_string());
                }
            }
        }
        cursor = cursor + off + 1;
    }
    None
}

/// C# extractJsonSection：正则 `"key" *: *(\{[^}]*\})` 的手工等价
///（"key" 后第一个对象，取到首个 '}'，含花括号）。
fn extract_json_section(key: &str, json: &str) -> Option<String> {
    let pat = format!("\"{key}\"");
    let mut cursor = 0usize;
    while let Some(off) = json[cursor..].find(&pat) {
        let i = skip_spaces(json, cursor + off + pat.len());
        if i < json.len() && json.as_bytes()[i] == b':' {
            let j = skip_spaces(json, i + 1);
            if j < json.len() && json.as_bytes()[j] == b'{' {
                if let Some(end) = json[j..].find('}') {
                    return Some(json[j..j + end + 1].to_string());
                }
            }
        }
        cursor = cursor + off + 1;
    }
    None
}

fn skip_spaces(s: &str, i: usize) -> usize {
    let b = s.as_bytes();
    let mut j = i;
    while j < b.len() && b[j] == b' ' {
        j += 1;
    }
    j
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    /// 按 C# Dahua2Header 布局构造 32B 头 + body（packetSize1/2 = body 长，LE）。
    fn frame(body: &str) -> Vec<u8> {
        let mut f = header(body.len() as u32).to_vec();
        f.extend_from_slice(body.as_bytes());
        f
    }

    /// 构造 dahua_net_scan 可控的 EngineContext（空 socks，无需网络/特权）。
    fn scan_ctx(dahua_net_scan: bool) -> EngineContext {
        let (tx, _rx) = tokio::sync::mpsc::unbounded_channel();
        EngineContext {
            config: Arc::new(crate::Config {
                dahua_net_scan,
                ..Default::default()
            }),
            ports: Arc::new(Mutex::new(crate::ports::PortProvider::new())),
            reporter: tx,
            mdns: crate::mdns::MdnsBroker::new_for_test(),
            logger: Arc::new(crate::log::Logger::new(crate::log::Level::Debug)),
            pcap: None,
            cancel: CancellationToken::new(),
            task_id: 4,
            sweeps: std::sync::Arc::new(std::sync::Mutex::new(Vec::new())),
        }
    }

    #[tokio::test]
    async fn scan_netscan_enabled_spawns_and_cancels_previous() {
        // C# if (Config.DahuaNetScan) sendNetScan(port)：dahua_net_scan=true → scan 触发 spawn
        let e = Dahua2::default();
        let ctx = scan_ctx(true);
        e.scan(&ctx).unwrap();
        let t1 = e
            .sweep_token()
            .expect("sweep should be active when dahua_net_scan=true");
        assert!(!t1.is_cancelled());
        // 新一轮 scan：先取消上一轮 sweep（C# scannerThread.Abort 语义）
        e.scan(&ctx).unwrap();
        let t2 = e
            .sweep_token()
            .expect("new sweep should be active after second scan");
        assert!(!t2.is_cancelled());
        assert!(
            t1.is_cancelled(),
            "previous sweep must be cancelled by the new scan"
        );
    }

    #[tokio::test]
    async fn scan_netscan_disabled_no_sweep() {
        // dahua_net_scan=false（默认）→ 仅广播/组播，不 spawn netscan（sweep 保持 None）
        let e = Dahua2::default();
        let ctx = scan_ctx(false);
        e.scan(&ctx).unwrap();
        assert!(e.sweep_token().is_none());
    }

    #[test]
    fn wrong_method_discarded() {
        let body = "{\"method\":\"client.otherThing\",\"params\":{}}";
        let from: SocketAddr = "240.0.4.0:1024".parse().unwrap();
        assert!(Dahua2::default().parse(from, &frame(body)).is_empty());
    }

    #[test]
    fn ipv6_slash_truncation_quirk() {
        // "fe80::abcd/16"：首个 '/' 在 char 10 → Substring(0, 9) = "fe80::abc"（分隔符前一字符也丢）
        let body = "{\"method\":\"client.notifyDevInfo\",\"IPv6Address\":{\"IPAddress\":\"fe80::abcd/16\"}}";
        let from: SocketAddr = "240.0.4.0:1024".parse().unwrap();
        let devs = Dahua2::default().parse(from, &frame(body));
        assert_eq!(devs.len(), 2); // v4(=from 缺省) + v6
        assert_eq!(devs[1].ip, "fe80::abc".parse::<std::net::IpAddr>().unwrap());
        assert_eq!(devs[1].version, 2);
    }

    #[test]
    fn normal_notify_reports_full_tuple() {
        let body = "{\"mac\":\"aa:bb:cc:dd:ee:ff\",\"method\":\"client.notifyDevInfo\",\"params\":{\"deviceInfo\":{\"DeviceType\":\"Virtual (JSON)\",\"IPv4Address\":{\"DefaultGateway\":\"240.0.0.1\",\"IPAddress\":\"240.0.4.0\",\"SubnetMask\":\"255.0.0.0\"},\"SerialNo\":\"123456789\"}}}";
        let from: SocketAddr = "240.0.4.0:1024".parse().unwrap();
        let devs = Dahua2::default().parse(from, &frame(body));
        assert_eq!(devs.len(), 1);
        assert_eq!(devs[0].protocol, "Dahua");
        assert_eq!(devs[0].version, 2);
        assert_eq!(devs[0].ip, "240.0.4.0".parse::<std::net::IpAddr>().unwrap());
        assert_eq!(devs[0].device_type, "Virtual (JSON)");
        assert_eq!(devs[0].serial, "123456789");
    }

    #[tokio::test]
    async fn fixture_replay() {
        let data = tokio::fs::read(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/Dahua2.selftest"
        ))
        .await
        .unwrap();
        let from: SocketAddr = "240.0.4.0:1024".parse().unwrap();
        let devs = Dahua2::default().parse(from, &data);
        // 期望值：对照 C# Dahua2.reciever 规则手工核定后填入（注释出处：Dahua2.cs reciever/extractJsonString/extractJsonSection）
        assert!(!devs.is_empty(), "Dahua2 fixture should yield >=1 device");
        // TODO(T50): 填入完整 (protocol, version, ip, type, serial) 断言
    }
}
