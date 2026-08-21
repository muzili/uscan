//! ARP 被动捕获与 sendpacket 注入（libpcap）。
//!
//! 所有 pcap 调用都在专用 `std::thread` 内完成（在 tokio worker 上阻塞会饿死运行时，spec §3.6）。
use crate::log::Logger;
use std::sync::mpsc;
use std::sync::Arc;
use std::thread::JoinHandle;
use tokio::sync::mpsc::UnboundedSender;
use tokio_util::sync::CancellationToken;

/// 一个网卡的 ARP 捕获 + 注入通道。所有 pcap 操作都在专用 std::thread 内完成
/// （tokio worker 上阻塞会饿死运行时，spec §3.6）。
#[derive(Clone)]
pub struct ArpNic {
    pub name: String,
    /// 主动发帧通道（scan sweep 用）
    pub tx: mpsc::Sender<Vec<u8>>,
}

/// ARP 被动捕获 + 帧注入（libpcap）。
pub struct ArpCapture;

impl ArpCapture {
    /// 打开单个网卡：非混杂、BPF "ether proto 0x0806"、100ms 超时。
    /// 权限不足或设备不存在时返回 None（优雅降级，不 panic）。
    pub fn open(name: &str, logger: &Logger, task_id: u32) -> Option<pcap::Capture<pcap::Active>> {
        match pcap::Capture::from_device(name)
            .ok()
            .and_then(|c| c.timeout(100).promisc(false).snaplen(65535).open().ok())
            .and_then(|mut cap| cap.filter("ether proto 0x0806", true).map(|_| cap).ok())
        {
            Some(c) => Some(c),
            None => {
                logger.warn(task_id, "ARP discovery disabled (no capture permission)");
                None
            }
        }
    }

    /// 启动全部可打开网卡；返回 (每网卡发帧通道, 线程句柄)。
    /// 无法打开的网卡降级跳过，其余照常。
    pub fn start(
        names: &[String],
        frames: UnboundedSender<Vec<u8>>,
        cancel: CancellationToken,
        logger: &Arc<Logger>,
        task_id: u32,
    ) -> (Vec<ArpNic>, Vec<JoinHandle<()>>) {
        let mut nics = Vec::new();
        let mut handles = Vec::new();
        for name in names {
            let mut cap = match Self::open(name, logger, task_id) {
                Some(c) => c,
                None => continue, // 该网卡降级，其余照常
            };
            let (tx, rx) = mpsc::channel::<Vec<u8>>();
            nics.push(ArpNic {
                name: name.clone(),
                tx,
            });
            let frames = frames.clone();
            let cancel = cancel.clone();
            let logger = Arc::clone(logger);
            let nic_name = name.clone();
            handles.push(std::thread::spawn(move || {
                loop {
                    if cancel.is_cancelled() {
                        break;
                    }
                    while let Ok(frame) = rx.try_recv() {
                        if cap.sendpacket(&frame[..]).is_err() {
                            logger.warn(task_id, &format!("ARP inject failed on {nic_name}"));
                        }
                    }
                    match cap.next_packet() {
                        Ok(pkt) if !pkt.data.is_empty() => {
                            let _ = frames.send(pkt.data.to_vec());
                        }
                        Ok(_) => { /* 超时/空包 tick */ }
                        // 100ms 超时：pcap 返回 TimeoutExpired，继续循环而非退出。
                        Err(pcap::Error::TimeoutExpired) => {}
                        Err(e) => {
                            logger.warn(task_id, &format!("ARP capture stopped: {e}"));
                            break;
                        }
                    }
                }
            }));
        }
        (nics, handles)
    }
}

#[cfg(test)]
mod tests {
    use crate::arp::capture::ArpCapture;
    use crate::log::Level;
    use crate::log::Logger;

    #[test]
    fn open_missing_device_degrades_to_none() {
        let logger = Logger::new(Level::Debug);
        let cap = ArpCapture::open("definitely-not-a-nic-xyz99", &logger, 1);
        assert!(cap.is_none()); // 优雅降级，不 panic
    }
}
