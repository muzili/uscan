mod cli;
mod config;
mod output;
mod run;

use clap::Parser;

#[tokio::main]
async fn main() {
    let cli = cli::Cli::parse();
    let code: i32 = match cli.cmd {
        None => run::run_scan(&cli::ScanArgs::default()).await,
        Some(cli::Cmd::Scan(args)) => run::run_scan(&args).await,
        Some(cli::Cmd::Selftest { .. })
        | Some(cli::Cmd::Selftest2pcap { .. })
        | Some(cli::Cmd::ListProtocols) => {
            eprintln!("command not implemented yet (T55)");
            2
        }
    };
    std::process::exit(code);
}
