//! `Scanner`：顶层扫描编排（协议注册、接口分配、结果汇聚，对应 C# `Program.Main` 运行时流程）。

use crate::config::Config;
use crate::devices::Device;
use crate::engine::{EngineContext, ScanEngine};
use crate::errors::Error;
use crate::iface;
use crate::log::{Level, Logger};
use crate::mdns::MdnsBroker;
use crate::pcap::PcapWriter;
use crate::ports::PortProvider;
use crate::protocols;
use std::net::Ipv4Addr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use tokio::sync::mpsc::{unbounded_channel, UnboundedReceiver, UnboundedSender};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

pub struct Scanner {
    config: Arc<Config>,
    entries: Vec<(u16, Arc<dyn ScanEngine>)>, // (registry id, engine)
    broker: Arc<MdnsBroker>,
    logger: Arc<Logger>,
    ports: Arc<Mutex<PortProvider>>,
    pcap: Option<Arc<PcapWriter>>,
    cancel: CancellationToken,
    /// 构造时保留的 `UnboundedSender<Device>` 克隆；start() 时克隆进各 EngineContext。
    reporter_tx: UnboundedSender<Device>,
    ctxs: Vec<Arc<EngineContext>>, // start() 后与 entries 一一对应，scan() 复用
    handles: Vec<JoinHandle<()>>,
}

impl Scanner {
    /// `protocols` 为 None = 全部引擎；Some = 按 name 大小写不敏感过滤（拼错 → Err 列可选值）。
    /// 返回 (Scanner, 设备接收端)；接收端交调用方 drain（见 T51 集成测试）。
    pub fn new(
        config: Config,
        protocols: Option<&[String]>,
        pcap_out: Option<PathBuf>,
    ) -> crate::Result<(Self, UnboundedReceiver<Device>)> {
        let (tx, rx) = unbounded_channel();
        let cancel = CancellationToken::new();
        let logger = Arc::new(Logger::new(if config.debug_mode {
            Level::Debug
        } else {
            Level::Info
        }));
        let broker = MdnsBroker::new(Arc::clone(&logger), cancel.clone());
        let pcap = match pcap_out {
            Some(p) => Some(Arc::new(PcapWriter::new(&p)?)),
            None => None,
        };
        // T17 增量表；T43 后恰 27 项；id 作 task_id 时转 u32
        let all: Vec<(u16, Arc<dyn ScanEngine>)> = protocols::registry();
        let entries = match protocols {
            None => all,
            Some(names) => {
                let wanted: Vec<String> = names.iter().map(|s| s.to_ascii_lowercase()).collect();
                let known: Vec<String> = all
                    .iter()
                    .map(|(_, e)| e.name().to_ascii_lowercase())
                    .collect();
                for w in &wanted {
                    if !known.contains(w) {
                        return Err(Error::Config(format!(
                            "unknown protocol: {}; available: {}",
                            w,
                            known.to_vec().join(", ")
                        )));
                    }
                }
                all.into_iter()
                    .filter(|(_, e)| wanted.contains(&e.name().to_ascii_lowercase()))
                    .collect()
            }
        };
        let ports = Arc::new(Mutex::new(PortProvider::new()));
        let config = Arc::new(config);
        Ok((
            Self {
                config,
                entries,
                broker,
                logger,
                ports,
                pcap,
                cancel,
                reporter_tx: tx,
                ctxs: Vec::new(),
                handles: Vec::new(),
            },
            rx,
        ))
    }

    /// 已选中引擎数量（测试/CLI 用）。
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// 各引擎 name，按 entries 顺序（测试断言 Dahua 双引擎等）。
    pub fn protocol_names(&self) -> Vec<String> {
        self.entries
            .iter()
            .map(|(_, e)| e.name().to_string())
            .collect()
    }

    /// 绑定接口 socket 并 spawn 接收任务；立即返回（long task 在引擎内部 spawn，可取消）。
    pub async fn start(&mut self) -> crate::Result<()> {
        let ifaces = iface::active_interfaces();
        if ifaces.is_empty() {
            return Err(Error::NoInterface);
        }
        let nic_ips: Vec<Ipv4Addr> = ifaces.iter().flat_map(|i| i.ipv4_addrs()).collect();
        // C# reserveUDP(getUsedPort())：引擎启动前预占固定端口
        for (_, e) in &self.entries {
            if !e.used_ports().is_empty() {
                self.ports.lock().unwrap().reserve(e.used_ports());
            }
        }
        let has_mdns_consumer = self
            .entries
            .iter()
            .any(|(_, e)| matches!(e.name(), "Axis" | "Google" | "Arecont"));
        let mut handles = Vec::new();
        if has_mdns_consumer {
            // broker 无注册表 ID → task_id 0（与 selftest 源地址 240.0.0.0 一致）
            handles.extend(self.broker.listen(&nic_ips, &self.ports, 0)?);
        }
        self.ctxs.clear();
        for (id, e) in &self.entries {
            let ctx = Arc::new(EngineContext {
                config: Arc::clone(&self.config),
                ports: Arc::clone(&self.ports),
                reporter: self.reporter_tx.clone(),
                mdns: self.broker.clone(),
                logger: Arc::clone(&self.logger),
                pcap: self.pcap.clone(),
                cancel: self.cancel.clone(),
                task_id: *id as u32, // 注册表 ID 作任务号（broker=0）
            });
            handles.extend(e.listen(Arc::clone(&ctx))?);
            self.ctxs.push(ctx);
        }
        self.handles = handles;
        Ok(())
    }

    /// 立即返回（C# scan() 语义）；长任务（netscan/Arecont 多轮）在引擎内部 spawn 可取消。
    pub fn scan(&self) -> crate::Result<()> {
        // ctx 与 engine 一一对应（同序）
        for ((_, e), ctx) in self.entries.iter().zip(self.ctxs.iter()) {
            e.scan(ctx)?;
        }
        Ok(())
    }

    /// 取消所有任务并 join 接收线程（recv_loop 经 select! 响应 cancel）。
    pub async fn stop(&mut self) -> crate::Result<()> {
        self.cancel.cancel();
        for h in self.handles.drain(..) {
            let _ = h.await;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Config;

    #[test]
    fn filter_case_insensitive_and_dahua_dual() {
        // protocols=["dahua"]（大小写不敏感）→ 恰好 2 个引擎（Dahua1+Dahua2，name 同为 "Dahua"）
        let (s, _rx) = Scanner::new(Config::default(), Some(&["Dahua".into()]), None).unwrap();
        assert_eq!(s.len(), 2);
        assert_eq!(
            s.protocol_names(),
            vec!["Dahua".to_string(), "Dahua".to_string()]
        );
        // protocols=["ssdp","Lantronix"]（混合大小写）→ 2 个
        let (s, _rx) = Scanner::new(
            Config::default(),
            Some(&["ssdp".into(), "LANTRONIX".into()]),
            None,
        )
        .unwrap();
        assert_eq!(s.len(), 2);
        // protocols=["nope"] → Err，错误信息含可选值列表
        let r = Scanner::new(Config::default(), Some(&["nope".into()]), None);
        let err = r
            .err()
            .expect("expected Config error for unknown protocol")
            .to_string();
        assert!(err.contains("unknown protocol: nope"), "msg: {err}");
        assert!(err.contains("ssdp"), "available list missing ssdp: {err}");
        assert!(err.contains("dahua"), "available list missing dahua: {err}");
    }

    #[test]
    fn no_filter_gives_all_27() {
        // protocols=None → 27 个引擎（26 C# + ARP）
        let (s, _rx) = Scanner::new(Config::default(), None, None).unwrap();
        assert_eq!(s.len(), 27);
    }
}
