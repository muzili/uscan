//! Eaton 引擎（T26）：`<OBJECT name="...">` 块手工提取，逐行对齐 C# Eaton.reciever。

use crate::devices::Device;
use crate::engine::{EngineContext, ScanEngine};
use crate::net::SocketSet;
use std::net::{Ipv4Addr, SocketAddr};
use tokio::task::JoinHandle;

const PORT: u16 = 4679; // C# port（监听 + 探测同端口）
                        // C# request 串（逐字）
const PROBE: &[u8] = b"<SCAN_REQUEST/>";

pub struct Eaton {
    socks: SocketSet,
}

impl Default for Eaton {
    fn default() -> Self {
        Self {
            socks: SocketSet::new(),
        }
    }
}

impl ScanEngine for Eaton {
    fn name(&self) -> &str {
        "Eaton"
    }
    fn used_ports(&self) -> &[u16] {
        &[PORT]
    }
    fn color(&self) -> u32 {
        0x0000ff // Color.Blue
    }

    fn listen(&self, ctx: std::sync::Arc<EngineContext>) -> crate::Result<Vec<JoinHandle<()>>> {
        let ifaces = crate::iface::active_interfaces();
        let nic_ips: Vec<Ipv4Addr> = ifaces.iter().flat_map(|i| i.ipv4_addrs()).collect();
        // recv_loop 只调用 parse()（纯函数），用新实例即可，无需自引用。
        let e: std::sync::Arc<dyn ScanEngine> = std::sync::Arc::new(Self::default());
        let mut handles = Vec::new();
        // C# listenUdpGlobal(port)：被占且 port_sharing 关闭时放弃（Ok(None)）
        if let Some((gsock, gsync)) =
            crate::net::udp_bind_global(PORT, ctx.config.port_sharing, &ctx.logger, ctx.task_id)?
        {
            self.socks.add(gsync);
            handles.push(tokio::spawn(crate::net::recv_loop(
                ctx.clone(),
                std::sync::Arc::clone(&e),
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
                std::sync::Arc::clone(&e),
                isock,
            )));
        }
        Ok(handles)
    }

    fn scan(&self, ctx: &EngineContext) -> crate::Result<()> {
        // C# Eaton.scan：sendBroadcast(4679)
        let failed = self.socks.send_broadcast(PORT, PROBE);
        if failed > 0 {
            ctx.logger
                .warn(ctx.task_id, &format!("{} Eaton sends failed", failed));
        }
        Ok(())
    }

    fn parse(&self, from: SocketAddr, data: &[u8]) -> Vec<Device> {
        let xml = String::from_utf8_lossy(data).into_owned();
        // C#：System.Description → model，缺则回退 UPS.PowerSummary.iProduct，都没有 → 丢弃
        let device_model = extract_object_entry(&xml, "System.Description")
            .or_else(|| extract_object_entry(&xml, "UPS.PowerSummary.iProduct"));
        let Some(device_model) = device_model else {
            return Vec::new();
        };
        // C#：UPS.PowerSummary.iSerialNumber → serial（缺省 "Unknown"）
        let device_serial = extract_object_entry(&xml, "UPS.PowerSummary.iSerialNumber")
            .unwrap_or_else(|| "Unknown".into());
        // C#：ip 恒为 from
        vec![Device {
            protocol: "Eaton".into(),
            version: 1,
            ip: from.ip(),
            device_type: device_model,
            serial: device_serial,
        }]
    }
}
/// C# 正则 `<OBJECT +name *= *"{name}">([^<]*)</OBJECT>` 的手工等价（首个匹配）。
/// `+`/`*` 为字面空格（.NET 语义）；内容不含 '<'，开标签后直接跟 `</OBJECT>`。
fn extract_object_entry(xml: &str, name: &str) -> Option<String> {
    let mut cursor = 0usize;
    while let Some(off) = xml[cursor..].find("<OBJECT") {
        let start = cursor + off;
        if let Some(captured) = match_object(xml, start, name) {
            return Some(captured);
        }
        cursor = start + 1;
    }
    None
}

/// 自 `start`（`<OBJECT` 起点）匹配：1+ 空格、`name`、0+ 空格、`=`、0+ 空格、`"{name}">`，
/// 随后捕获 `[^<]*` 且紧跟 `</OBJECT>`。
fn match_object(xml: &str, start: usize, name: &str) -> Option<String> {
    let bytes = xml.as_bytes();
    let mut i = start + "<OBJECT".len();
    let ws0 = i;
    while i < bytes.len() && bytes[i] == b' ' {
        i += 1;
    }
    if i == ws0 || !xml[i..].starts_with("name") {
        return None; // ' +'：至少一个空格，后跟字面 name
    }
    i += "name".len();
    while i < bytes.len() && bytes[i] == b' ' {
        i += 1;
    }
    if !xml[i..].starts_with('=') {
        return None;
    }
    i += 1;
    while i < bytes.len() && bytes[i] == b' ' {
        i += 1;
    }
    if !xml[i..].starts_with('"') {
        return None;
    }
    i += 1;
    let name_end = i + name.len();
    if name_end > xml.len() || &xml[i..name_end] != name {
        return None;
    }
    i = name_end;
    if !xml[i..].starts_with("\">") {
        return None;
    }
    i += 2;
    // ([^<]*)：捕获到下一个 '<'（可为空）
    let rel = xml[i..].find('<').unwrap_or(xml.len() - i);
    let end = i + rel;
    if !xml[end..].starts_with("</OBJECT>") {
        return None;
    }
    Some(xml[i..end].to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_description_no_product_discarded() {
        // C#：System.Description 与 iProduct 都取不到 → return（不上报）
        let xml = b"<FILE><OBJECT name=\"System.Location\">somewhere</OBJECT><OBJECT name=\"UPS.PowerSummary.iModel\">m</OBJECT></FILE>";
        let from: SocketAddr = "240.0.19.0:1024".parse().unwrap();
        assert!(Eaton::default().parse(from, xml).is_empty());
    }

    #[test]
    fn iproduct_fallback_used() {
        // 无 System.Description → model = iProduct；无 iSerialNumber → "Unknown"
        let xml = b"<FILE><OBJECT name=\"UPS.PowerSummary.iProduct\">Eaton 5P</OBJECT></FILE>";
        let from: SocketAddr = "240.0.19.0:1024".parse().unwrap();
        let devs = Eaton::default().parse(from, xml);
        assert_eq!(devs.len(), 1);
        assert_eq!(devs[0].protocol, "Eaton");
        assert_eq!(devs[0].version, 1);
        assert_eq!(devs[0].ip, from.ip());
        assert_eq!(devs[0].device_type, "Eaton 5P");
        assert_eq!(devs[0].serial, "Unknown");
    }

    #[test]
    fn description_takes_precedence() {
        let xml = b"<FILE><OBJECT name=\"System.Description\">Eaton Virtual</OBJECT><OBJECT name=\"UPS.PowerSummary.iProduct\">Eaton</OBJECT><OBJECT name=\"UPS.PowerSummary.iSerialNumber\">123456789</OBJECT></FILE>";
        let from: SocketAddr = "240.0.19.0:1024".parse().unwrap();
        let devs = Eaton::default().parse(from, xml);
        assert_eq!(devs.len(), 1);
        assert_eq!(devs[0].device_type, "Eaton Virtual");
        assert_eq!(devs[0].serial, "123456789");
    }

    #[tokio::test]
    async fn fixture_replay() {
        let data = tokio::fs::read(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/Eaton.selftest"
        ))
        .await
        .unwrap();
        let from: SocketAddr = "240.0.19.0:1024".parse().unwrap();
        let devs = Eaton::default().parse(from, &data);
        // 期望值：对照 C# Eaton.reciever 规则手工核定后填入（注释出处：Eaton.cs reciever/extractObjectEntry）
        // C# Eaton.reciever：extractObjectEntry 提取 model/serial
        assert_eq!(devs.len(), 1);
        assert_eq!(devs[0].protocol, "Eaton");
        assert_eq!(devs[0].version, 1);
        assert_eq!(devs[0].ip.to_string(), "240.0.19.0");
        assert_eq!(devs[0].device_type, "Eaton Virtual");
        assert_eq!(devs[0].serial, "123456789");
    }
}
