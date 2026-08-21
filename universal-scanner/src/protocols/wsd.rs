//! WSDiscovery 引擎（T19）：parse 对齐 C# Wsdiscovery.reciever，probe 逐字对齐 sender()。

use crate::devices::Device;
use crate::engine::{EngineContext, ScanEngine};
use crate::net::SocketSet;
use std::net::{Ipv4Addr, SocketAddr};
use tokio::task::JoinHandle;

const GROUP: Ipv4Addr = Ipv4Addr::new(239, 255, 255, 250);
const PORT: u16 = 3702;

/// C# announce 探测模板（Wsdiscovery.cs 逐字；`{0}` 由每次发送新生成的 GUID 替换）。
/// 纯 ASCII：C# Encoding.ASCII 编码与字节等价。
const ANNOUNCE: &str = "<s:Envelope xmlns:s=\"http://www.w3.org/2003/05/soap-envelope\" xmlns:a=\"http://schemas.xmlsoap.org/ws/2004/08/addressing\" xmlns:d=\"http://schemas.xmlsoap.org/ws/2005/04/discovery\" xmlns:w=\"http://schemas.xmlsoap.org/ws/2006/02/devprof\" xmlns:o=\"http://www.onvif.org/ver10/device/wsdl\"><s:Header><a:Action s:mustUnderstand=\"1\">http://schemas.xmlsoap.org/ws/2005/04/discovery/Probe</a:Action><a:MessageID>urn:uuid:{0}</a:MessageID><a:To s:mustUnderstand=\"1\">urn:schemas-xmlsoap-org:ws:2005:04:discovery</a:To><a:ReplyTo><a:Address>http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous</a:Address></a:ReplyTo></s:Header><s:Body><d:Probe><d:Types>w:Device o:Device</d:Types></d:Probe></s:Body></s:Envelope>";

/// C# verbatim 备用 payload（Config.OnvifVerbatim；固定 MessageID）。
const VERBATIM: &str = "<s:Envelope xmlns:s=\"http://www.w3.org/2003/05/soap-envelope\" xmlns:a=\"http://schemas.xmlsoap.org/ws/2004/08/addressing\"><s:Header><a:Action s:mustUnderstand=\"1\">http://schemas.xmlsoap.org/ws/2005/04/discovery/Probe</a:Action><a:MessageID>uuid:f686768c-3e60-4f9c-a344-0769929d665c</a:MessageID><a:ReplyTo><a:Address>http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous</a:Address></a:ReplyTo><a:To s:mustUnderstand=\"1\">urn:schemas-xmlsoap-org:ws:2005:04:discovery</a:To></s:Header><s:Body><Probe xmlns=\"http://schemas.xmlsoap.org/ws/2005/04/discovery\"><d:Types xmlns:d=\"http://schemas.xmlsoap.org/ws/2005/04/discovery\" xmlns:dp0=\"http://www.onvif.org/ver10/network/wsdl\">dp0:NetworkVideoTransmitter</d:Types></Probe></s:Body></s:Envelope>";

pub struct Wsd {
    socks: SocketSet,
}

impl Default for Wsd {
    fn default() -> Self {
        Self {
            socks: SocketSet::new(),
        }
    }
}

impl ScanEngine for Wsd {
    fn name(&self) -> &str {
        "WSDiscovery"
    }
    fn used_ports(&self) -> &[u16] {
        &[PORT]
    }
    fn color(&self) -> u32 {
        0x404040
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
        // C# Wsdiscovery.scan：仅 sendMulticast(239.255.255.250, 3702)（无广播）。
        let probe: Vec<u8> = if ctx.config.onvif_verbatim {
            // C# ctor：OnvifVerbatim → announce = verbatim + warn
            ctx.logger
                .warn(ctx.task_id, "Using WSDiscovery ONVIF verbatim payload");
            VERBATIM.as_bytes().to_vec()
        } else {
            // C# sender：每次发送新生成 GUID 替换 {0}（String.Format 语义）
            ANNOUNCE
                .replace("{0}", &uuid::Uuid::new_v4().to_string())
                .into_bytes()
        };
        let failed = self.socks.send_multicast(GROUP, PORT, &probe);
        if failed > 0 {
            ctx.logger
                .warn(ctx.task_id, &format!("{} WSDiscovery sends failed", failed));
        }
        Ok(())
    }

    fn parse(&self, from: SocketAddr, data: &[u8]) -> Vec<Device> {
        let xml = String::from_utf8_lossy(data).into_owned();
        // C# reciever：Address → serial、Types → model；两者均非空才上报。
        let Some(serial_raw) = extract_tag(&xml, "Address") else {
            return Vec::new();
        };
        let serial = extract_uuid(&serial_raw);
        let Some(model) = extract_tag(&xml, "Types") else {
            return Vec::new();
        };
        let model = remove_namespace(&model);
        if model.is_empty() || serial.is_empty() {
            return Vec::new();
        }
        vec![Device {
            mac: String::new(),
            protocol: "WSDiscovery".into(),
            version: 0,
            ip: from.ip(),
            device_type: model,
            serial,
        }]
    }
}

/// C# extractUUID：去 urn: 前缀再去 uuid: 前缀。
fn extract_uuid(usn: &str) -> String {
    let s = usn.strip_prefix("urn:").unwrap_or(usn);
    s.strip_prefix("uuid:").unwrap_or(s).to_string()
}

/// C# removeNameSpace：正则 [a-zA-Z_][a-zA-Z_0-9-]*: 全部删除（手工实现，无 regex 依赖）。
fn remove_namespace(value: &str) -> String {
    let chars: Vec<char> = value.chars().collect();
    let mut out = String::with_capacity(value.len());
    let mut i = 0usize;
    while i < chars.len() {
        if chars[i].is_ascii_alphabetic() || chars[i] == '_' {
            let start = i;
            let mut j = i;
            while j < chars.len()
                && (chars[j].is_ascii_alphanumeric() || chars[j] == '_' || chars[j] == '-')
            {
                j += 1;
            }
            if j < chars.len() && chars[j] == ':' {
                i = j + 1; // 整段（含冒号）删除
                continue;
            }
            let kept: String = chars[start..j].iter().collect();
            out.push_str(&kept);
            i = j;
        } else {
            out.push(chars[i]);
            i += 1;
        }
    }
    out
}

/// C# 正则 `[<:]Tag>([^<>]+)</` 的手工等价：从左到右扫描所有候选开标签
///（`<Tag>` 或 `<prefix:Tag>`），返回首个"内容非空、不含 < 或 >、且后紧跟 </"的匹配。
fn extract_tag(xml: &str, tag: &str) -> Option<String> {
    let plain = format!("<{tag}>");
    let prefixed = format!(":{tag}>");
    let mut cursor = 0usize;
    loop {
        let rest = &xml[cursor..];
        let p_plain = rest.find(&plain);
        let p_pref = rest.find(&prefixed);
        let (off, len) = match (p_plain, p_pref) {
            (Some(a), Some(b)) if b < a => (b, prefixed.len()),
            (Some(a), Some(_)) => (a, plain.len()),
            (None, Some(b)) => (b, prefixed.len()),
            _ => break,
        };
        let start = cursor + off + len; // 内容起点（开标签 '>' 之后）
        if let Some(content) = tag_content(xml, start) {
            return Some(content);
        }
        cursor = cursor + off + 1; // 推进找下一候选
    }
    None
}

fn tag_content(xml: &str, start: usize) -> Option<String> {
    let b = xml.as_bytes();
    let mut end = start;
    while end < b.len() && b[end] != b'<' && b[end] != b'>' {
        end += 1;
    }
    // C# 正则尾部 `</`：内容后必须紧跟 `</`
    if end > start && end + 1 < b.len() && b[end] == b'<' && b[end + 1] == b'/' {
        Some(xml[start..end].to_string())
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_address_and_types() {
        let from: SocketAddr = "240.0.2.0:1024".parse().unwrap();
        // 用真实 fixture 同款字段（Address/Types）构造；断言 serial=去前缀 GUID、model=去命名空间类型串
        let xml = b"<?xml version=\"1.0\" encoding=\"UTF-8\"?><e:Envelope xmlns:a=\"http://schemas.xmlsoap.org/ws/2004/08/addressing\" xmlns:d=\"http://schemas.xmlsoap.org/ws/2005/04/discovery\"><e:Body><d:ProbeMatches><d:ProbeMatch><a:EndpointReference><a:Address>urn:uuid:11223344-5566-7788-9900-000000000002</a:Address></a:EndpointReference><d:Types>Virtual tds:Device</d:Types></d:ProbeMatch></d:ProbeMatches></e:Body></e:Envelope>";
        let devs = Wsd::default().parse(from, xml);
        assert_eq!(devs.len(), 1);
        assert_eq!(devs[0].protocol, "WSDiscovery");
        assert_eq!(devs[0].version, 0);
        assert_eq!(devs[0].device_type, "Virtual Device");
        assert_eq!(devs[0].serial, "11223344-5566-7788-9900-000000000002");
    }

    #[test]
    fn missing_types_not_reported() {
        // 无 Types → 空（model 与 serial 均非空才上报）
        let from: SocketAddr = "240.0.2.0:1024".parse().unwrap();
        let xml = b"<e:Body><d:ProbeMatches><d:ProbeMatch><a:EndpointReference><a:Address>urn:uuid:11223344-5566-7788-9900-000000000002</a:Address></a:EndpointReference></d:ProbeMatch></d:ProbeMatches></e:Body>";
        assert!(Wsd::default().parse(from, xml).is_empty());
    }

    #[tokio::test]
    async fn fixture_replay() {
        // 注意小写 d！
        let data = tokio::fs::read(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/Wsdiscovery.selftest"
        ))
        .await
        .unwrap();
        let from: SocketAddr = "240.0.2.0:1024".parse().unwrap();
        let devs = Wsd::default().parse(from, &data);
        // C# Wsdiscovery.reciever：name="WSDiscovery"，version 0
        assert_eq!(devs.len(), 1);
        assert_eq!(devs[0].protocol, "WSDiscovery");
        assert_eq!(devs[0].version, 0);
        assert_eq!(devs[0].ip.to_string(), "240.0.2.0");
        assert_eq!(devs[0].device_type, "Virtual Device");
        assert_eq!(devs[0].serial, "11223344-5566-7788-9900-000000000002");
    }
}
