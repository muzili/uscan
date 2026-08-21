mod cli;
mod config;

use clap::Parser;

fn main() {
    let cli = cli::Cli::parse();
    // T52 骨架：解析命令。scan 运行循环见 T54；selftest/selftest2pcap/list-protocols 见 T55。
    if let Some(cli::Cmd::Scan(args)) = &cli.cmd {
        let _ = config::load_config(args.config.as_deref(), args);
    }
}
