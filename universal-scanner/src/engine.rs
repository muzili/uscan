//! `ScanEngine` trait 与 `EngineContext`（同步方法，listen/scan 返回 `Vec<JoinHandle>`）。

use crate::devices::Device;
use crate::log::Logger;
use crate::pcap::PcapWriter;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::mpsc::UnboundedSender;
use tokio_util::sync::CancellationToken;

/// 协议引擎（对应 C# ScanEngine 抽象类）。
/// 前向声明：T11 的 recv_loop 需要 `parse()`；T12 补齐 name/used_ports/color/listen/scan。
pub trait ScanEngine: Send + Sync {
    /// 纯解析函数：无 I/O 无副作用，fixture 测试直接调用。
    fn parse(&self, from: SocketAddr, data: &[u8]) -> Vec<Device>;
}

/// 引擎共享上下文。
/// 前向声明：T11 的 recv_loop 使用以下字段；T12 补齐 config/ports/mdns 与 send_all。
pub struct EngineContext {
    pub reporter: UnboundedSender<Device>,
    pub logger: Arc<Logger>,
    pub pcap: Option<Arc<PcapWriter>>,
    pub cancel: CancellationToken,
    pub task_id: u32, // 本引擎日志任务号（C# 线程号语义）
}
