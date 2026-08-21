//! `ScanEngine` trait 与 `EngineContext`（同步方法，listen/scan 返回 `Vec<JoinHandle>`）。

use crate::devices::Device;
use crate::mdns::MdnsBroker;
use crate::pcap::PcapWriter;
use crate::ports::PortProvider;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::mpsc::UnboundedSender;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

/// 协议引擎（对应 C# ScanEngine 抽象类）。
/// 同步方法、无 async fn → Box<dyn ScanEngine> 原生可用。
pub trait ScanEngine: Send + Sync {
    fn name(&self) -> &str;
    fn used_ports(&self) -> &[u16]; // ARP/Vivotek/NiceVision/Advantech 等可为空
    fn color(&self) -> u32; // RGB（CLI table 着色）
    /// 建立本引擎 socket（global/interface/multicast 按需组合）并 spawn 接收任务。
    /// ctx 按值传入（调用方持 Arc）：spawn 的 recv_loop 需要 `Arc<EngineContext>`，`ctx.clone()` 即共享。
    fn listen(&self, ctx: Arc<EngineContext>) -> crate::Result<Vec<JoinHandle<()>>>;
    /// 发送一轮探测，**立即返回**（C# scan() 语义）；长任务内部 spawn 可取消。
    fn scan(&self, ctx: &EngineContext) -> crate::Result<()>;
    /// 纯解析函数：无 I/O 无副作用，fixture 测试直接调用。
    fn parse(&self, from: SocketAddr, data: &[u8]) -> Vec<Device>;
}

pub struct EngineContext {
    pub config: Arc<crate::Config>,
    pub ports: Arc<std::sync::Mutex<PortProvider>>,
    pub reporter: UnboundedSender<Device>,
    pub mdns: Arc<MdnsBroker>,
    pub logger: Arc<crate::log::Logger>,
    pub pcap: Option<Arc<PcapWriter>>,
    pub cancel: CancellationToken,
    pub task_id: u32, // 本引擎日志任务号（C# 线程号语义）
    /// scan() 内部 spawn 的长任务（netscan/Arecont 多轮 sweep）句柄；
    /// Scanner::stop() 取消后 join，避免悬空任务。
    pub sweeps: Arc<std::sync::Mutex<Vec<JoinHandle<()>>>>,
}

impl EngineContext {
    /// 发送路径：pcap tap + debug 日志 + 从所有活动 socket 各发一份（C# send()）。
    pub async fn send_all(&self, sockets: &[&tokio::net::UdpSocket], to: SocketAddr, data: &[u8]) {
        for s in sockets {
            let local = s.local_addr().unwrap_or(to);
            if let Some(p) = &self.pcap {
                let _ = p.append_udp(std::time::SystemTime::now(), local, to, data);
            }
            self.logger
                .debug(self.task_id, &format!("-> {to} ({}B)", data.len()));
            if s.send_to(data, to).await.is_err() {
                self.logger
                    .warn(self.task_id, &format!("send to {to} failed"));
            }
        }
    }
}
