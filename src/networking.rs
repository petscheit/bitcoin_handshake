use crate::message::{MessageEnvelope, NetworkAddress, NetworkMessage};
use crate::{Error, Event, NodeConfig};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::mpsc;

/// Represents a TCP connection to a peer in the network.
#[derive(Debug)]
pub struct TcpConnection {
    // TcpStream for communication with the peer.
    pub(crate) stream: TcpStream,
}

impl TcpConnection {
    /// Establishes a new TCP connection to a specified network address.
    ///
    /// # Arguments
    /// * `address` - The network address of the peer to connect to.
    ///
    /// # Returns
    /// A result containing the new `TcpConnection` or an `Error`.
    pub(crate) async fn new(address: &NetworkAddress) -> Result<Self, Error> {
        let stream = TcpStream::connect(&format!("{}:{}", &address.ip, &address.port)).await?;
        Ok(TcpConnection { stream })
    }

    /// Handles the network communication over the TCP connection.
    ///
    /// This function manages the sending of the initial version message,
    /// and the processing of incoming messages.
    ///
    /// # Arguments
    /// * `version_message` - The initial version message to send.
    /// * `peer_id` - The identifier for the peer.
    /// * `tx` - A sender for sending events to the main thread.
    pub async fn handle_network_communication<T: NodeConfig>(
        &mut self,
        version_message: MessageEnvelope,
        peer_id: [u8; 32],
        tx: mpsc::Sender<Event>,
    ) -> Result<(), Error> {
        // Send the initial version message to the peer
        self.stream.write_all(&version_message.serialize()).await?;

        // Flags to track the status of version acknowledgement
        let mut received_verack = false;
        let mut sent_verack = false;
        let mut peer_ready = false;

        loop {
            // Buffer for storing incoming data from the peer
            let mut buffer = [0; 1024];
            // Read data from the stream
            match self.stream.read(&mut buffer).await {
                Ok(n) => {
                    let mut received_data = &buffer[..n];

                    // Process each received message
                    while !received_data.is_empty() {
                        let (msg, rest) = MessageEnvelope::deserialize(received_data)?;
                        match msg.message {
                            // Handle specific network messages
                            NetworkMessage::Version(version) => {
                                // Send received version to main thread
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
                    // Return an error if reading from the stream fails
                    return Err(e.into());
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
