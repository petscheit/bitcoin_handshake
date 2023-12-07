use crate::message::{MessageEnvelope, NetworkAddress, NetworkMessage, VersionMessage};
use crate::{Error, NodeConfig};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

#[derive(Debug)]
pub(crate) struct Peer {
    pub addr_recv: NetworkAddress,
    pub connection: TcpStream,
    pub version: Option<VersionMessage>,
    pub received_verack: bool,
    pub sent_verack: bool,
}

impl Peer {
    /// Connect to a peer via TcpStream
    pub(crate) async fn connect(address: NetworkAddress) -> Result<Self, Error> {
        let connection = TcpStream::connect(&format!("{}:{}", &address.ip, &address.port)).await?;

        Ok(Peer {
            addr_recv: address,
            connection,
            version: None,
            received_verack: false,
            sent_verack: false,
        })
    }

    /// Initialize the handshake with a peer
    pub async fn init_handshake<T: NodeConfig>(&mut self) -> Result<(), Error> {
        let version_msg = VersionMessage::new::<T>(self.addr_recv.clone(), self.to_addr_from()?)?;
        let envelope = MessageEnvelope::new::<T>(NetworkMessage::Version(version_msg))?;
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

                while !received_data.is_empty() {
                    let (msg, rest) = MessageEnvelope::deserialize(received_data)?;
                    match msg.message {
                        NetworkMessage::Version(version) => {
                            self.version = Some(version);
                            // respond with verack when receiving valid version
                            let verack_envelope = MessageEnvelope::new::<T>(NetworkMessage::Verack)?;
                            self.connection
                                .write_all(&verack_envelope.serialize())
                                .await?;
                            self.sent_verack = true;
                        }
                        NetworkMessage::Verack => {
                            self.received_verack = true;
                        }
                        NetworkMessage::Unimplemented => ()
                    }
                    received_data = rest;
                }
            }
            Err(e) => {
                return Err(e.into())
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
