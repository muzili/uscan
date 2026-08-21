//! 全链路 loopback 集成测试（T51）：独立 socket 发 SSDP 响应，
//! SSDP 引擎经组播接收并解析出设备事件。
//!
//! 组播在 CI/loopback 环境可能不可用，故先做一次 join+send+recv 自检：
//! 自检失败 → 整测 skip（环境无组播）；自检成功 → 后续任何接收超时都算真 bug（测试失败）。

use std::net::{Ipv4Addr, UdpSocket};
use std::time::Duration;
use universal_scanner::{Config, Scanner};

/// 自检：能否向 239.255.255.250:1900 发组播并本地收到。
/// 需绑定 1900 并加入组（否则返回 false）。
fn multicast_supported() -> bool {
    let group: Ipv4Addr = "239.255.255.250".parse().unwrap();
    let ifaces = universal_scanner::iface::active_interfaces();
    let ips: Vec<Ipv4Addr> = ifaces.iter().flat_map(|i| i.ipv4_addrs()).collect();
    if ips.is_empty() {
        return false;
    }
    // 接收端：绑 0.0.0.0:1900 并加入组（每条有 IPv4 的网卡）。
    let recv = match UdpSocket::bind("0.0.0.0:1900") {
        Ok(s) => s,
        Err(_) => return false,
    };
    let mut joined = false;
    for ip in &ips {
        if recv.join_multicast_v4(&group, ip).is_ok() {
            joined = true;
        }
    }
    if !joined {
        return false;
    }
    let _ = recv.set_read_timeout(Some(Duration::from_millis(1000)));
    // 发送端：向组播地址发一条探测。
    let sender = match UdpSocket::bind("0.0.0.0:0") {
        Ok(s) => s,
        Err(_) => return false,
    };
    if sender.send_to(b"probe", (group, 1900)).is_err() {
        return false;
    }
    let mut buf = [0u8; 64];
    recv.recv_from(&mut buf).map(|_| true).unwrap_or(false)
}

#[tokio::test]
async fn ssdp_full_chain_via_multicast() {
    if !multicast_supported() {
        eprintln!("SKIP: multicast unavailable in this environment (CI loopback 限制)");
        return;
    }
    // 1. 仅 SSDP 的 Scanner
    let (mut scanner, mut rx) =
        Scanner::new(Config::default(), Some(&["SSDP".into()]), None).unwrap();
    scanner.start().await.unwrap();
    // 2. 立即第一轮 scan（广播探测；此处主要验证响应接收链路）
    scanner.scan().unwrap();

    // 3. 从独立 socket 向 239.255.255.250:1900 发一条 C# 风格 SSDP 响应
    let resp =
        "HTTP/1.1 200 OK\r\nUSN: uuid:chain-test::upnp:rootdevice\r\nSERVER: TestCam/1.0\r\n\r\n";
    let sock = UdpSocket::bind("0.0.0.0:0").unwrap();
    sock.send_to(resp.as_bytes(), "239.255.255.250:1900")
        .expect("send SSDP response");

    // 4. 等待设备事件（3s 超时）
    let got = tokio::time::timeout(Duration::from_secs(3), rx.recv())
        .await
        .ok()
        .flatten();
    match got {
        Some(dev) => {
            // 5a. 断言
            assert_eq!(dev.protocol, "SSDP");
            assert_eq!(dev.serial, "chain-test");
            // 6. stop 必须 1s 内完成（select! 取消路径）
            let t = std::time::Instant::now();
            scanner.stop().await.unwrap();
            assert!(t.elapsed() < std::time::Duration::from_secs(1));
        }
        None => panic!("SSDP full-chain: no device event received within 3s"),
    }
}
