//! SSDP 引擎（T18 完整示例）：parse 逐行对齐 C# SSDP.reciever。

use crate::devices::Device;
use crate::engine::{EngineContext, ScanEngine};
use std::net::{Ipv4Addr, SocketAddr};
use tokio::task::JoinHandle;

pub struct Ssdp;

impl ScanEngine for Ssdp {
    fn name(&self) -> &str {
        "SSDP"
    }
    fn used_ports(&self) -> &[u16] {
        &[1900]
    }
    fn color(&self) -> u32 {
        0x006400 // Color.DarkGreen
    }

    fn listen(&self, ctx: std::sync::Arc<EngineContext>) -> crate::Result<Vec<JoinHandle<()>>> {
        let ifaces = crate::iface::active_interfaces();
        let ips: Vec<Ipv4Addr> = ifaces.iter().flat_map(|i| i.ipv4_addrs()).collect();
        let sock = crate::net::udp_bind_multicast(
            "239.255.255.250".parse().unwrap(),
            1900,
            &ips,
            &ctx.logger,
            ctx.task_id,
        )?;
        let c = ctx.clone();
        let e: std::sync::Arc<dyn ScanEngine> = std::sync::Arc::new(Ssdp);
        let mut handles = vec![tokio::spawn(crate::net::recv_loop(
            c,
            std::sync::Arc::clone(&e),
            sock,
        ))];
        // C# listenUdpInterfaces()：各网卡随机端口 socket 同样喂 recv_loop。
        for ip in &ips {
            let port = match ctx.ports.lock().unwrap().free_port() {
                Some(p) => p,
                None => {
                    ctx.logger
                        .warn(ctx.task_id, "no free port; skipping interface socket");
                    continue;
                }
            };
            let (_, isock) = crate::net::udp_bind_interface(*ip, port)?;
            let c2 = ctx.clone();
            let e2 = std::sync::Arc::clone(&e);
            handles.push(tokio::spawn(crate::net::recv_loop(c2, e2, isock)));
        }
        Ok(handles)
    }

    fn scan(&self, ctx: &EngineContext) -> crate::Result<()> {
        // 探测从 multicast+global+interfaces 全部 socket 发；本引擎无 global。
        // 实现：把 listen 保存的 socket 句柄存进引擎内部（Mutex<Vec<UdpSocket>>），
        // scan 时对每个 socket 以 send() 构造目标地址（multicast 239.255.255.250:1900 与 255.255.255.255:1900）发送。
        // probe 文本（C# SSDP.sender 逐字对齐）：
        //   "M-SEARCH * HTTP/1.1\r\nHost: {ip}:{port}\r\nST:upnp:rootdevice\r\nMan:\"ssdp:discover\"\r\nMX:2\r\n\r\n"
        // 详见 T51（socket 持有模式统一化）；本任务先实现 parse + 常量，scan 在 T51 接线后补全。
        let _ = ctx;
        Ok(())
    }

    fn parse(&self, from: SocketAddr, data: &[u8]) -> Vec<Device> {
        let body = String::from_utf8_lossy(data).into_owned();
        let usn = extract_http_var(&body, "USN");
        if usn.is_empty() {
            return Vec::new();
        }
        let server = extract_http_var(&body, "SERVER");
        let type_ = split_server_details(&server)
            .pop()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| "anonymous".into());
        let serial = extract_uuid(&usn);
        vec![Device {
            protocol: "SSDP".into(),
            version: 0,
            ip: from.ip(),
            device_type: type_,
            serial,
        }]
    }
}

/// C# extractHttpVar：按 \r\n 或 \n 分行（去空行），跳过首行，key 不区分大小写。
fn extract_http_var(data: &str, variable: &str) -> String {
    let lines: Vec<&str> = data
        .split(&['\r', '\n'][..])
        .collect::<Vec<_>>()
        .into_iter()
        .map(|l| l.trim_end_matches(['\r', '\n']))
        .filter(|l| !l.is_empty())
        .collect();
    // C# Split(["\r\n","\n"], RemoveEmptyEntries)：先按 \r\n 再按 \n，等价于上面的逐字符切分后去空。
    for line in lines.iter().skip(1) {
        if let Some(s) = line.find(':') {
            let a = &line[..s];
            let b = &line[s + 1..];
            if a.trim().eq_ignore_ascii_case(variable) {
                return b.trim().to_string();
            }
        }
    }
    String::new()
}

/// C# splitServerDetails：正则 [^,/]+(/[^ ,]+)? 全部匹配、trim。
fn split_server_details(device: &str) -> Vec<String> {
    // 手工实现该正则（避免引入 regex 依赖）：
    // 匹配 = 最长 [^,/]+ 后可选 (/[^ ,]+)
    let mut out = Vec::new();
    let b = device.as_bytes();
    let mut i = 0usize;
    while i < b.len() {
        // 跳过非匹配起始字符（/, 空格等）
        while i < b.len() && (b[i] == b',' || b[i] == b'/' || b[i] == b' ' || b[i] == b'\t') {
            i += 1;
        }
        let start = i;
        while i < b.len() && b[i] != b',' && b[i] != b'/' {
            i += 1;
        }
        if i == start {
            continue;
        }
        let mut token = String::from_utf8_lossy(&b[start..i]).to_string();
        // 可选 (/[^ ,]+)
        if i < b.len() && b[i] == b'/' {
            let mut j = i + 1;
            while j < b.len() && b[j] != b' ' && b[j] != b',' {
                j += 1;
            }
            token.push_str(&String::from_utf8_lossy(&b[i..j]));
            i = j;
        }
        let t = token.trim().to_string();
        if !t.is_empty() {
            out.push(t);
        }
    }
    out
}

/// C# extractUUID：截 :: 前 → 去 uuid: 前缀。
fn extract_uuid(usn: &str) -> String {
    let s = usn.split("::").next().unwrap_or(usn).to_string();
    s.strip_prefix("uuid:").unwrap_or(&s).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    const RESP: &str = "HTTP/1.1 200 OK\r\nCACHE-CONTROL: max-age=10000\r\nDATE: Sun, 09 Nov 2014 22:42:41 GMT\r\nEXT:\r\nLOCATION: http://192.168.1.10:80/\r\nSERVER: UPnP/1.0 Realtek/4.0.20 IP/1.00\r\nST: upnp:rootdevice\r\nUSN: uuid:34206042-404E-C54A-9244-9D405C306700::upnp:rootdevice\r\n\r\n";

    #[test]
    fn parse_response() {
        let from: std::net::SocketAddr = "240.0.1.0:1900".parse().unwrap();
        let devs = Ssdp.parse(from, RESP.as_bytes());
        assert_eq!(devs.len(), 1);
        let d = &devs[0];
        assert_eq!(d.protocol, "SSDP");
        assert_eq!(d.version, 0);
        assert_eq!(d.ip, from.ip());
        assert_eq!(d.device_type, "IP/1.00"); // 正则最后 token
        assert_eq!(d.serial, "34206042-404E-C54A-9244-9D405C306700");
    }

    #[test]
    fn empty_usn_not_reported() {
        let from: std::net::SocketAddr = "240.0.1.0:1900".parse().unwrap();
        let body = "HTTP/1.1 200 OK\r\nSERVER: X/1.0\r\n\r\n";
        assert!(Ssdp.parse(from, body.as_bytes()).is_empty());
    }

    #[test]
    fn no_server_is_anonymous() {
        let from: std::net::SocketAddr = "240.0.1.0:1900".parse().unwrap();
        let body = "HTTP/1.1 200 OK\r\nUSN: uuid:abc-123::upnp:rootdevice\r\n\r\n";
        let devs = Ssdp.parse(from, body.as_bytes());
        assert_eq!(devs.len(), 1);
        assert_eq!(devs[0].device_type, "anonymous");
        assert_eq!(devs[0].serial, "abc-123");
    }

    #[tokio::test]
    async fn fixture_replay() {
        let data = tokio::fs::read(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/SSDP.selftest"
        ))
        .await
        .unwrap();
        let from: std::net::SocketAddr = "240.0.1.0:1024".parse().unwrap();
        let devs = Ssdp.parse(from, &data);
        // 期望值：对照 C# SSDP.reciever 规则手工核定后填入（注释出处：SSDP.cs reciever/extractHttpVar/extractUUID）
        assert!(!devs.is_empty(), "SSDP fixture should yield >=1 device");
        // TODO(T50): 填入完整 (protocol, version, ip, type, serial) 断言
    }
}
