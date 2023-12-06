use crate::message::{MessageEnvelope, NetworkAddress, NetworkMessage, VersionMessage};
use crate::{Error, NodeConfig};
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
        let version_msg = VersionMessage::new::<T>(self.addr_recv.clone(), self.to_addr_from()?)?;
        let envelope = MessageEnvelope::new::<T>(NetworkMessage::Version(version_msg));
        println!("Sending version message: {:#?}", envelope);
        self.connection
            .write_all(&envelope.serialize())
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

                println!("Received messages: {:#?}", messages);

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
}
