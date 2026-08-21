//! scan 运行循环（T54）：流式/批量渲染、重扫、超时、Ctrl+C、退出码。
//!
//! 约定（spec §5.3）：
//! 1. 合并配置 → Scanner::new（protocols 过滤）→ start() → 立即第一轮 scan()。
//! 2. stdout 只出数据（渲染器），日志走 stderr。
//! 3. 流式：rx.recv() → DeviceTable::add → Some 时输出一行；--rescan N 周期重扫；
//!    --timeout N 到期 → 优雅退出（exit 0）。
//! 4. Ctrl+C：第一次 → 优雅 stop + exit 130；停止中第二次 → 立即 exit 130。
//! 5. 退出码：0 正常（含 timeout 到期）/ 1 致命错误（消息到 stderr）/ 130 Ctrl+C。

use crate::cli::ScanArgs;
use crate::config::load_config;
use crate::output;
use anyhow::Result;
use std::time::Duration;
use universal_scanner::{DeviceTable, Scanner};

/// 执行一次扫描；返回退出码（0/1/130）。致命错误 → stderr + 1。
pub async fn run_scan(args: &ScanArgs) -> i32 {
    match run_scan_inner(args).await {
        Ok(code) => code,
        Err(e) => {
            eprintln!("error: {e:#}");
            1
        }
    }
}

async fn run_scan_inner(args: &ScanArgs) -> Result<i32> {
    let config = load_config(args.config.as_deref(), args)?;
    let color = !args.no_color && std::env::var_os("NO_COLOR").is_none();
    let force_generic = config.force_generic_protocols;
    let enable_ipv4 = config.enable_ipv4;
    let enable_ipv6 = config.enable_ipv6;

    let protocols: Option<Vec<String>> = args.protocols.as_ref().filter(|v| !v.is_empty()).cloned();
    let (mut scanner, mut rx) = Scanner::new(config, protocols.as_deref(), args.pcap_out.clone())?;
    scanner.start().await?;
    scanner.scan()?;

    let mut table = DeviceTable::new(force_generic);
    // 表头（CSV/TSV）先行；stdout 只出数据。
    if let Some(h) = output::header(args.format) {
        println!("{h}");
    }

    let mut rescan = args
        .rescan
        .map(|s| tokio::time::interval(Duration::from_secs(s)));
    // 消费 interval 的第一次即刻 tick（首轮 scan 已在上面发出）。
    if let Some(i) = rescan.as_mut() {
        i.tick().await;
    }
    let timeout = args
        .timeout
        .map(|s| tokio::time::Instant::now() + Duration::from_secs(s));

    loop {
        tokio::select! {
            maybe_dev = rx.recv() => match maybe_dev {
                Some(dev) => {
                    if let Some(d) = table.add(dev, enable_ipv4, enable_ipv6) {
                        if !args.batch {
                            println!(
                                "{}",
                                output::render_row(&d, args.format, args.show_version, color)
                            );
                        }
                    }
                }
                None => break, // 发送端全部关闭
            },
            _ = wait_rescan(rescan.as_mut()) => {
                let _ = scanner.scan();
            }
            _ = wait_timeout(timeout) => {
                break; // timeout 到期 → 优雅退出 0
            }
            _ = ctrl_c() => {
                // 第一次 Ctrl+C：优雅停止 + 130；停止期间第二次 → 立即退出。
                let guard = tokio::spawn(async {
                    let _ = tokio::signal::ctrl_c().await;
                    std::process::exit(130);
                });
                let _ = scanner.stop().await;
                guard.abort();
                return Ok(130);
            }
        }
    }
    let _ = scanner.stop().await;
    // 批量：结束时按发现顺序一次性输出全部行。
    if args.batch {
        for line in output::batch_lines(&table, args.format, args.show_version, color) {
            println!("{line}");
        }
    }
    Ok(0)
}

/// rescan 周期；None → 永不触发。
async fn wait_rescan(interval: Option<&mut tokio::time::Interval>) {
    match interval {
        Some(i) => {
            i.tick().await;
        }
        None => {
            std::future::pending::<()>().await;
        }
    }
}

/// timeout（绝对截止时间）；None → 永不触发。
async fn wait_timeout(deadline: Option<tokio::time::Instant>) {
    match deadline {
        Some(d) => tokio::time::sleep_until(d).await,
        None => std::future::pending::<()>().await,
    }
}

async fn ctrl_c() {
    let _ = tokio::signal::ctrl_c().await;
}
