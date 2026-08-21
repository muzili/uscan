mod cli;
mod config;
mod output;

use clap::Parser;
use universal_scanner::DeviceTable;

fn main() {
    let cli = cli::Cli::parse();
    // T53 过渡：验证渲染器（真实运行循环见 T54）。
    if let Some(cli::Cmd::Scan(args)) = &cli.cmd {
        let _ = config::load_config(args.config.as_deref(), args);
        for line in output::batch_lines(
            &DeviceTable::new(false),
            args.format,
            args.show_version,
            false,
        ) {
            println!("{line}");
        }
    }
}
