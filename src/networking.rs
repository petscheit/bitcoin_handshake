use crate::message::{MessageEnvelope, NetworkAddress, VersionMessage};
use crate::{Error, NodeConfig};
use std::net::{IpAddr, Ipv4Addr};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

#[derive(Debug)]
pub(crate) struct Peer {
    pub addr_recv: NetworkAddress,
    pub connection: TcpStream,
}

impl Peer {
    /// Connect to a peer via TcpStream
    pub(crate) async fn connect(address: NetworkAddress) -> Result<Self, Error> {
        let connection = TcpStream::connect(&format!("{}:{}", &address.ip, &address.port)).await?;

        Ok(Peer {
            addr_recv: address,
            connection,
        })
    }

    /// Initialize the handshake with a peer
    pub async fn init_handshake<T: NodeConfig>(&mut self) -> Result<(), Error> {
        let version_msg = VersionMessage::new::<T>(self.addr_recv.clone(), self.to_addr_from()?);

        let packed_version_msg = MessageEnvelope::pack_version::<T>(version_msg?.serialize());
        self.connection
            .write_all(&packed_version_msg.serialize())
            .await
            .unwrap();

        // Buffer to store the data
        let mut buffer = [0; 1024];

        // Read data into the buffer in a non-blocking way
        match self.connection.read(&mut buffer).await {
            Ok(n) => {
                if n == 0 {
                    println!("Connection was closed");
                    // Connection was closed
                    return Ok(());
                }
                let mut received_data = &buffer[..n];
                let mut messages = vec![];

                while received_data.len() > 0 {
                    let (msg, rest) = MessageEnvelope::deserialize(received_data)?;
                    messages.push(msg);
                    received_data = rest;
                }

                println!("Received messages: {:?}", messages);

            }
            Err(e) => {
                eprintln!("Failed to read from stream: {}", e);
            }
        }

        Ok(())
    }

    pub fn to_addr_from(&self) -> Result<NetworkAddress, Error> {
        let ip = self.connection.local_addr()?.ip();
        let port = self.connection.local_addr()?.port();

        Ok(NetworkAddress {
            services: 0, // we hardcode the services to 0 for now
            ip,
            port,
        })
    }

    // pub fn send_message(&mut self, message: &[u8]) -> Result<(), Error> {
    //     self.connection.write_all(message).unwrap();
    //     println!("Sent message: {:?}", message);
    //     Ok(())
    // }
}

// F9 BE B4 D9 // magic
// 76 65 72 73 69 6F 6E 00 00 00 00 00 // command
// 66 00 00 00 // payload_size
// 46 3D D0 8B // checksum
// 80 11 01 00 // version
// 09 04 00 00 00 00 00 00 // services
// 86 99 70 65 00 00 00 00 // timestamp
// 00 00 00 00 00 00 00 00 // services
// 00 00 00 00 00 00 00 00 00 00 FF FF 59 F7 AE 78 // ip
// 8F 5D // port
// 09 04 00 00 00 00 00 00 //services
// 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 // ip
// 00 00 //port
// 8D B7 3F A6 DE 87 4F AB // nonce
// 10 // user_agent_size
// 2F 53 61 74 6F 73 68 69 3A 32 35 2E 30 2E 30 2F
// 38 83 0C 00
// 01
//
// F9 BE B4 D9
// 76 65 72 61 63 6B 00 00 00 00 00 00 00 00 00 00 5D F6 E0 E2 F9 BE B4 D9 61 6C 65 72 74 00 00 00 00 00 00 00 A8 00 00 00 1B F9 AA EA 60 01 00 00 00 00 00 00 00 00 00 00 00 FF FF FF 7F 00 00 00 00 FF FF FF 7F FE FF FF 7F 01 FF FF FF 7F 00 00 00 00 FF FF FF 7F 00 FF FF FF 7F 00 2F 55 52 47 45 4E 54 3A 20 41 6C 65 72 74 20 6B 65 79 20 63 6F 6D 70 72 6F 6D 69 73 65 64 2C 20 75 70 67 72 61 64 65 20 72 65 71 75 69 72 65 64 00 46 30 44 02 20 65 3F EB D6 41 0F 47 0F 6B AE 11 CA D1 9C 48 41 3B EC B1 AC 2C 17 F9 08 FD 0F D5 3B DC 3A BD 52 02 20 6D 0E 9C 96 FE 88 D4 A0 F0 1E D9 DE DA E2 B6 F9 E0 0D A9 4C AD 0F EC AA E6 6E CF 68 9B F7 1B 50

// #[derive(Debug)]
// pub struct VersionMessage {
//     version: u32,
//     services: u64,
//     timestamp: i64,
//     addr_recv: NetworkAddress,
//     addr_from: NetworkAddress,
//     nonce: u64,
//     user_agent: String,
//     start_height: i32,
//     relay: bool,
// }
