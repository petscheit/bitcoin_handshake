use crate::message::{MessageEnvelope, NetworkAddress, NetworkMessage};
use crate::{Error, Event, NodeConfig};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::mpsc;

#[derive(Debug)]
pub struct TcpConnection {
    pub(crate) stream: TcpStream,
}

impl TcpConnection {
    /// Connect to a peer via TcpStream
    pub(crate) async fn new(address: &NetworkAddress) -> Result<Self, Error> {
        let stream = TcpStream::connect(&format!("{}:{}", &address.ip, &address.port)).await?;
        Ok(TcpConnection { stream })
    }

    ///
    /// This function continuously reads data from the connection, deserializes incoming messages,
    /// and performs appropriate actions based on the message type. It handles version and verack
    /// messages, sets the peer's version, and updates the active status of the peer once the
    /// handshake is completed. The function runs in a loop and only returns in case of an error.
    ///
    /// # Type Parameters
    /// - `T`: A type that implements the `NodeConfig` trait, used for message creation.
    ///
    /// # Errors
    /// Returns an `Error` if there are issues with reading from the connection or deserializing messages.
    pub async fn handle_network_communication<T: NodeConfig>(
        &mut self,
        version_message: MessageEnvelope,
        peer_id: [u8; 32],
        tx: mpsc::Sender<Event>,
    ) -> Result<(), Error> {
        // Send the initial version message to the peer
        self.stream.write_all(&version_message.serialize()).await?;

        let mut received_verack = false;
        let mut sent_verack = false;
        let mut peer_ready = false;

        loop {
            // Buffer to store incoming data
            let mut buffer = [0; 1024];
            // Read data from the stream
            match self.stream.read(&mut buffer).await {
                Ok(n) => {
                    let mut received_data = &buffer[..n];

                    // Process each received message
                    while !received_data.is_empty() {
                        let (msg, rest) = MessageEnvelope::deserialize(received_data)?;
                        match msg.message {
                            NetworkMessage::Version(version) => {
                                // send received version to main thread
                                tx.send(Event::SetVersion(peer_id, version))
                                    .await
                                    .expect("Thread messaging failed!");

                                // Respond with verack upon receiving a valid version message
                                let verack_envelope =
                                    MessageEnvelope::new::<T>(NetworkMessage::Verack)?;
                                self.stream.write_all(&verack_envelope.serialize()).await?;

                                sent_verack = true;
                            }
                            NetworkMessage::Verack => {
                                received_verack = true;
                            }
                            NetworkMessage::Unimplemented => (), // Handle unimplemented messages
                        }
                        received_data = rest;
                    }
                }
                Err(e) => {
                    return Err(e.into()); // Return error if reading fails
                }
            }

            // Update peer status and notify once handshake is completed
            if received_verack && sent_verack && !peer_ready {
                peer_ready = true;
                tx.send(Event::PeerReady(peer_id))
                    .await
                    .expect("Thread messaging failed!");
            }
        }

        Ok(())
    }
}
