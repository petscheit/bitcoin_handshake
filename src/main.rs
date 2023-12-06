mod message;
mod networking;
use crate::message::{NetworkAddress, VersionMessage};
use crate::networking::Peer;
use std::io::{BufRead, BufReader, Read};
use std::net::{IpAddr, Ipv4Addr};

#[derive(Debug)]
pub enum Error {
    IOError(std::io::Error),
    SystemTime(std::time::SystemTimeError),
    ArrayError(std::array::TryFromSliceError),
    TcpError(&'static str),
    DeserializeError(&'static str),
}

#[tokio::main]
async fn main() {
    let mut peer = Peer::connect(NetworkAddress {
        services: 0,
        ip: IpAddr::V4(Ipv4Addr::new(168, 119, 68, 66)),
        port: 8333,
    })
    .await
    .unwrap();

    println!("{:?}", peer);
    let res = peer.init_handshake::<Config>().await;
    //
    // let assembeled_message = version_msg.assemble_message();
    // peer.send_message(&assembeled_message).unwrap();
    //
    // let read_stream = peer.connection.try_clone().unwrap();
    // let mut stream_reader = BufReader::new(read_stream);
    //
    // let mut buffer = Vec::new();
    //
    // loop {
    //     match stream_reader.read_to_end(&mut buffer) {
    //         Ok(0) => {
    //             // No more data to read; you might want to break or handle this case.
    //             continue;
    //         },
    //         Ok(_) => {
    //             // Process and print the buffer content.
    //             // The actual implementation will depend on the specifics of the Bitcoin protocol.
    //             // For demonstration, let's just print the raw bytes.
    //             println!("Received data: {:?}", buffer);
    //
    //             // Clear the buffer for the next read.
    //             buffer.clear();
    //         },
    //         Err(e) => {
    //             eprintln!("Failed to read from stream: {}", e);
    //             break;
    //         }
    //     }
    // }

    // println!("{:?}", assembeled_message);
    // match peer {
    //     Ok(stream) => println!("Connected to peer: {:?}", stream),
    //     Err(e) => println!("Error connecting to peer: {:?}", e),
    // }
    // println!("{:?}", peer);
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
