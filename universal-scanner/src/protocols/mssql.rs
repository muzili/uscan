//! MSSQL 引擎（T32）：1 字节 0x02 探测，parse 逐行对齐 C# MSSQL.reciever。
//!
//! 注意：C# 载荷为交替 Key;Value 对（`ServerName;SRV1;InstanceName;X`，无 '=' 字符），
//! 与计划的"每项按首个 = 拆分"不符；以 C# + MSSQL.selftest fixture 为准（记录为偏差）。

use crate::devices::Device;
use crate::engine::{EngineContext, ScanEngine};
use crate::net::SocketSet;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::task::JoinHandle;

const PORT: u16 = 1434;
const PROBE: [u8; 1] = [0x02]; // C# datagramType.request
const RESP: u8 = 0x05; // C# datagramType.response

pub struct Mssql {
    socks: SocketSet,
}

impl Default for Mssql {
    fn default() -> Self {
        Self {
            socks: SocketSet::new(),
        }
    }
}

impl ScanEngine for Mssql {
    fn name(&self) -> &str {
        "MSSQL"
    }
    fn used_ports(&self) -> &[u16] {
        &[PORT]
    }
    fn color(&self) -> u32 {
        0x000000 // Color.Black
    }

    fn listen(&self, ctx: Arc<EngineContext>) -> crate::Result<Vec<JoinHandle<()>>> {
        let ifaces = crate::iface::active_interfaces();
        let nic_ips: Vec<std::net::Ipv4Addr> = ifaces.iter().flat_map(|i| i.ipv4_addrs()).collect();
        // recv_loop 只调用 parse()（纯函数），用新实例即可，无需自引用。
        let e: Arc<dyn ScanEngine> = Arc::new(Self::default());
        let mut handles = Vec::new();
        // C# listenUdpGlobal(port)：G 绑监听端口 1434
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
        // C# MSSQL.scan：sendBroadcast(port)
        let failed = self.socks.send_broadcast(PORT, &PROBE);
        if failed > 0 {
            ctx.logger
                .warn(ctx.task_id, &format!("{} MSSQL sends failed", failed));
        }
        Ok(())
    }

    fn parse(&self, from: SocketAddr, data: &[u8]) -> Vec<Device> {
        // C# reciever：data.Length < 3 → 静默 return
        if data.len() < 3 {
            return Vec::new();
        }
        // C#：首字节须 0x05（response），不符静默丢弃
        if data[0] != RESP {
            return Vec::new();
        }
        // C#：len = data[1] 须等于 data.Length - 3（第 3 字节被跳过、不计长度）；
        // 不匹配 → warn + 丢弃（parse 纯函数，warn 由调用侧记）
        if data[1] as usize != data.len() - 3 {
            return Vec::new();
        }
        // C#：textPayload = UTF8(data[3..]) 按 ';' 分割，交替 Key;Value 对（i += 2）
        let body = String::from_utf8_lossy(&data[3..]).into_owned();
        let parts: Vec<&str> = body.split(';').collect();
        // C#：遇空 key 停止收集（只取第一实例）；重复 key 在 C# 会因
        // Dictionary.Add 抛异常被外层 catch 吞掉（不报告），此处取末次出现（fixture 无此情况）
        let mut server_name = None;
        let mut instance_name = None;
        let mut i = 0usize;
        while i + 1 < parts.len() {
            if parts[i].is_empty() {
                break;
            }
            match parts[i] {
                "ServerName" => server_name = Some(parts[i + 1].to_string()),
                "InstanceName" => instance_name = Some(parts[i + 1].to_string()),
                _ => {}
            }
            i += 2;
        }
        vec![Device {
            protocol: "MSSQL".into(),
            version: 1,
            ip: from.ip(),
            device_type: instance_name.unwrap_or_else(|| String::from("Unknown")),
            serial: server_name.unwrap_or_else(|| String::from("Unknown")),
        }]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn packet(first: u8, body: &[u8]) -> Vec<u8> {
        let mut d = vec![first, 0u8, 0x00];
        d.extend_from_slice(body);
        d[1] = (d.len() - 3) as u8; // C#：len == data.Length - 3（第 3 字节跳过、不计长度）
        d
    }

    #[test]
    fn mssql_basic() {
        let body = b"ServerName;SRV1;InstanceName;SQLEXPRESS";
        let d = packet(0x05, body);
        let from: SocketAddr = "240.0.29.0:1024".parse().unwrap();
        let devs = Mssql::default().parse(from, &d);
        assert_eq!(devs.len(), 1);
        assert_eq!(devs[0].protocol, "MSSQL");
        assert_eq!(devs[0].version, 1);
        assert_eq!(devs[0].serial, "SRV1");
        assert_eq!(devs[0].device_type, "SQLEXPRESS");
        assert_eq!(devs[0].ip.to_string(), "240.0.29.0");
    }

    #[test]
    fn mssql_request_byte_silent_drop() {
        // 首字节 0x02（request 回显）→ 静默丢弃
        let d = packet(0x02, b"ServerName;SRV1");
        let from: SocketAddr = "240.0.29.0:1024".parse().unwrap();
        assert!(Mssql::default().parse(from, &d).is_empty());
    }

    #[test]
    fn mssql_len_mismatch_warn_drop() {
        // d[1] 比 data.len()-3 大 1 → C# warn 后丢弃
        let mut d = packet(0x05, b"ServerName;SRV1;InstanceName;X");
        d[1] = (d.len() - 3 + 1) as u8;
        let from: SocketAddr = "240.0.29.0:1024".parse().unwrap();
        assert!(Mssql::default().parse(from, &d).is_empty());
    }

    #[test]
    fn mssql_empty_key_stops_at_first_instance() {
        // "ServerName;SRV1;;InstanceName;OTHER" → 空 key 中止收集 → serial=SRV1, model=Unknown
        let d = packet(0x05, b"ServerName;SRV1;;InstanceName;OTHER");
        let from: SocketAddr = "240.0.29.0:1024".parse().unwrap();
        let devs = Mssql::default().parse(from, &d);
        assert_eq!(devs.len(), 1);
        assert_eq!(devs[0].serial, "SRV1");
        assert_eq!(devs[0].device_type, "Unknown");
    }

    #[test]
    fn mssql_short_packet_dropped() {
        // C#：data.Length < 3 → 静默丢弃
        let from: SocketAddr = "240.0.29.0:1024".parse().unwrap();
        assert!(Mssql::default().parse(from, &[0x05, 0x00]).is_empty());
    }

    #[tokio::test]
    async fn fixture_replay() {
        let data = tokio::fs::read(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/MSSQL.selftest"
        ))
        .await
        .unwrap();
        let from: SocketAddr = "240.0.29.0:1024".parse().unwrap();
        let devs = Mssql::default().parse(from, &data);
        // 期望值：对照 C# MSSQL.reciever 规则手工核定后填入（注释出处：MSSQL.cs reciever）
        assert!(!devs.is_empty(), "MSSQL fixture should yield >=1 device");
        // TODO(T50): 填入完整 (protocol, version, ip, type, serial) 断言
    }
}
