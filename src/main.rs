mod message;
mod networking;
use crate::message::{NetworkAddress};
use crate::networking::Peer;
use std::net::{IpAddr, Ipv4Addr};

#[derive(Debug)]
pub enum Error {
    IOError(std::io::Error),
    SystemTime(std::time::SystemTimeError),
    ArrayError(std::array::TryFromSliceError),
    TcpError(&'static str),
    DeserializeError(&'static str),
    InvalidInputLength,
    InvalidChecksum,
}

#[tokio::main]
async fn main() -> Result<(), Error> {
    let mut peer = Peer::connect(NetworkAddress {
        services: 0,
        ip: IpAddr::V4(Ipv4Addr::new(168, 119, 68, 66)),
        port: 8333,
    })
    .await
    .unwrap();

    let _res = peer.init_handshake::<Config>().await?;

    Ok(())
}

pub trait NodeConfig {
    /// protocol version number
    const VERSION: u32;
    /// services supported by this node
    const SERVICES: u64;
    /// User-agent
    const USER_AGENT: &'static str;
    /// relay node IP to other peers?
    const RELAY: bool;
    /// magic bytes to identify network
    const MAGIC: [u8; 4];
}

struct Config;
impl NodeConfig for Config {
    const VERSION: u32 = 70001;
    const SERVICES: u64 = 0;
    const USER_AGENT: &'static str = "/Satoshi:23.0.0/";
    const RELAY: bool = false;
    const MAGIC: [u8; 4] = [0xf9, 0xbe, 0xb4, 0xd9];
}

// Error wrapping impls
impl From<std::io::Error> for Error {
    fn from(err: std::io::Error) -> Error {
        Error::IOError(err)
    }
}

impl From<std::time::SystemTimeError> for Error {
    fn from(err: std::time::SystemTimeError) -> Error {
        Error::SystemTime(err)
    }
}

impl From<std::array::TryFromSliceError> for Error {
    fn from(err: std::array::TryFromSliceError) -> Error {
        Error::ArrayError(err)
    }
}
