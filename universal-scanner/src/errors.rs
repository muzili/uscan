use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("pcap: {0}")]
    Pcap(#[from] pcap::Error),
    #[error("dns: {0}")]
    Dns(String),
    #[error("config: {0}")]
    Config(String),
    #[error("no active interface with an IPv4 address")]
    NoInterface,
    #[error("no free UDP port available")]
    NoFreePort,
}

pub type Result<T> = std::result::Result<T, Error>;
