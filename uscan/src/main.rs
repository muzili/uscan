mod cli;
mod commands;
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
        Some(cli::Cmd::Selftest { protocol }) => commands::run_selftest(protocol.as_deref()),
        Some(cli::Cmd::Selftest2pcap {
            in_file,
            out_file,
            dest_port,
        }) => commands::run_selftest2pcap(&in_file, &out_file, dest_port),
        Some(cli::Cmd::ListProtocols) => commands::run_list_protocols(),
        Some(cli::Cmd::UpdateOui) => commands::run_update_oui(),
        Some(cli::Cmd::TvtSet(args)) => commands::run_tvt_set(&args),
    };
    std::process::exit(code);
}
