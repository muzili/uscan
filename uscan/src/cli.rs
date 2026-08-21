//! CLI 定义（clap derive）：命令骨架 + 扫描参数 + 输出格式。T52。

use clap::{Args, Parser, Subcommand, ValueEnum};

/// Universal network device scanner (Rust port)
#[derive(Parser, Debug)]
#[command(
    name = "uscan",
    about = "Universal network device scanner (Rust port)",
    version
)]
pub struct Cli {
    #[command(subcommand)]
    pub cmd: Option<Cmd>,
}

/// 子命令；省略 → 默认 Scan。
#[derive(Subcommand, Debug)]
pub enum Cmd {
    /// 扫描（默认命令）
    Scan(ScanArgs),
    /// 重放 .selftest fixture（默认全部）
    Selftest {
        /// 仅重放该协议引擎（不区分大小写）
        protocol: Option<String>,
    },
    /// 把 fixture 包装成单个 UDP loopback pcap 包
    Selftest2pcap {
        /// 输入 fixture（.selftest）
        in_file: std::path::PathBuf,
        /// 输出 pcap 文件
        out_file: std::path::PathBuf,
        /// 目的端口（默认 1024）
        #[arg(long, default_value_t = 1024)]
        dest_port: u16,
    },
    /// 列出全部协议引擎
    ListProtocols,
    /// 下载 IEEE OUI 厂家数据库到用户缓存（ARP 输出的厂家标注数据源）
    UpdateOui,
}

/// 扫描参数（含 10 对对称 flag，CLI > TOML > 默认值，见 config.rs）。
#[derive(Args, Debug, Default)]
pub struct ScanArgs {
    /// 协议过滤（逗号分隔；缺省 = 全部）
    #[arg(long, value_delimiter = ',')]
    pub protocols: Option<Vec<String>>,
    /// 输出格式
    #[arg(long, value_enum, default_value = "table")]
    pub format: OutputFormat,
    /// 批量：结束时按发现顺序一次性输出
    #[arg(long)]
    pub batch: bool,
    /// 重扫间隔（秒）
    #[arg(long, value_name = "SECS")]
    pub rescan: Option<u64>,
    /// 超时（秒）后优雅退出
    #[arg(long, value_name = "SECS")]
    pub timeout: Option<u64>,
    /// 显示 Version 列
    #[arg(long)]
    pub show_version: bool,
    /// 禁用着色
    #[arg(long)]
    pub no_color: bool,
    /// 输出 pcap
    #[arg(long, value_name = "PATH")]
    pub pcap_out: Option<std::path::PathBuf>,
    /// 配置文件
    #[arg(long, value_name = "PATH")]
    pub config: Option<std::path::PathBuf>,
    #[arg(long)]
    pub enable_ipv4: bool,
    #[arg(long)]
    pub disable_ipv4: bool,
    #[arg(long)]
    pub enable_ipv6: bool,
    #[arg(long)]
    pub disable_ipv6: bool,
    #[arg(long)]
    pub force_link_local: bool,
    #[arg(long)]
    pub no_force_link_local: bool,
    #[arg(long)]
    pub force_zeroconf: bool,
    #[arg(long)]
    pub no_force_zeroconf: bool,
    #[arg(long)]
    pub force_generic_protocols: bool,
    #[arg(long)]
    pub no_force_generic_protocols: bool,
    #[arg(long)]
    pub debug: bool,
    #[arg(long)]
    pub no_debug: bool,
    #[arg(long)]
    pub port_sharing: bool,
    #[arg(long)]
    pub no_port_sharing: bool,
    #[arg(long)]
    pub onvif_verbatim: bool,
    #[arg(long)]
    pub no_onvif_verbatim: bool,
    #[arg(long)]
    pub dahua_net_scan: bool,
    #[arg(long)]
    pub no_dahua_net_scan: bool,
    /// 启用 ARP 捕获（默认启用）
    #[arg(long)]
    pub arp: bool,
    #[arg(long)]
    pub no_arp: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum, Default)]
pub enum OutputFormat {
    #[default]
    Table,
    Csv,
    Json,
    Tsv,
}
