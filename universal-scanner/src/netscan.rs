//! Dahua2 子网扫描（spec §3.5 / C# `ScanEngine.sendNetScannerInterfaces`）。
//!
//! 纯函数 `plan_hosts` 枚举单个接口地址的子网主机（供单元测试）；
//! 异步 `netscan` 遍历活跃接口、对私有地址逐 host 发单播探测（可取消）。

use crate::iface::{active_interfaces, is_private, mask_of, subnet_hosts};
use crate::log::Logger;
use crate::net::SocketSet;
use std::net::Ipv4Addr;
use std::sync::Arc;
use tokio_util::sync::CancellationToken;

/// C# `subNetListIPv4Addresses(net, mask, 254)` 的 host 上限。
const HOST_CAP: u32 = 254;

/// 纯函数：枚举 `if_ip/mask` 子网主机（先按 `HOST_CAP` 截断，C# 语义）再去掉接口自身地址
///（C# `sendNetScannerInterfaces` 的 `if (local.Equals(net.endPoint.Address)) continue;`）。
pub fn plan_hosts(if_ip: Ipv4Addr, mask: Ipv4Addr) -> Vec<Ipv4Addr> {
    subnet_hosts(if_ip, mask, HOST_CAP)
        .into_iter()
        .filter(|h| *h != if_ip)
        .collect()
}

/// C# `sendNetScannerInterfaces`（可取消）：对每个活跃接口的每个 IPv4，
/// 私有地址（含 169.254/16）才继续；从 `plan_hosts` 的每个 host 发单播探测（`port`）；
/// 每轮（每个接口地址）之间检查 cancel。尽力发、失败汇总一次 warn（C# 逐包 try/catch 静默）。
pub async fn netscan(
    socks: SocketSet,
    logger: Arc<Logger>,
    cancel: CancellationToken,
    sweep: CancellationToken,
    task_id: u32,
    probe: Vec<u8>,
    port: u16,
) {
    let mut total_failed = 0usize;
    for iface in active_interfaces() {
        for ip in iface.ipv4_addrs() {
            // 每轮之间检查 cancel（引擎级 stop 或新一轮 scan 的 sweep 取消）
            if cancel.is_cancelled() || sweep.is_cancelled() {
                logger.info(task_id, "Dahua2 netscan: cancelled");
                return;
            }
            if !is_private(ip.into()) {
                continue;
            }
            let mask = mask_of(ip);
            for host in plan_hosts(ip, mask) {
                total_failed += socks.send_unicast(host, port, &probe);
            }
        }
    }
    if total_failed > 0 {
        logger.warn(
            task_id,
            &format!("Dahua2 netscan: {total_failed} sends failed"),
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn ip(a: u8, b: u8, c: u8, d: u8) -> Ipv4Addr {
        Ipv4Addr::new(a, b, c, d)
    }

    #[test]
    fn plan_hosts_skips_self_and_respects_cap() {
        // 192.168.1.5/24 → 253 个，不含 192.168.1.5（254 上限先 cap，再去掉自身）
        let h = plan_hosts(ip(192, 168, 1, 5), ip(255, 255, 255, 0));
        assert_eq!(h.len(), 253);
        assert!(!h.contains(&ip(192, 168, 1, 5)));
        // 10.0.0.1/8 → C# subNetListIPv4Addresses 先 cap 254、再 skip self → 253
        // FLAG: plan T49 测试注释写"恰 254 个（上限）"，与 C# ground truth 不符——
        // self 10.0.0.1 是 cap 254 窗口首个元素、被移除后剩 253；此处从 C# = 253
        let h8 = plan_hosts(ip(10, 0, 0, 1), ip(255, 0, 0, 0));
        assert_eq!(h8.len(), 253);
        // 192.168.1.5/32 → 空
        assert!(plan_hosts(ip(192, 168, 1, 5), ip(255, 255, 255, 255)).is_empty());
        // 192.168.1.0/31 → 空（C# 下溢 wrap 的有意偏离，spec §8.2）
        assert!(plan_hosts(ip(192, 168, 1, 0), ip(255, 255, 255, 254)).is_empty());
    }
}
