// Import necessary modules and structs from the crate and external libraries.
use crate::message::{MessageEnvelope, NetworkAddress, NetworkMessage, Serialize, VersionMessage};
use crate::{Error, NodeConfig};
use sha2::{Digest, Sha256};
use std::net::{IpAddr, Ipv4Addr};

/// Represents a peer in the network.
///
/// A `Peer` holds information about a network node, including its address,
/// version information, and status of readiness in the network communication.
#[derive(Debug)]
pub(crate) struct Peer {
    /// The network address at which the peer is receiving messages.
    pub receiver_address: NetworkAddress,
    /// The version message of the peer, representing its version information.
    /// This is optional and is set during the peer-to-peer handshake process.
    pub version: Option<VersionMessage>,
    /// A boolean flag indicating whether the peer is ready for network communication.
    pub ready: bool,
}

impl Peer {
    /// Constructs a new `Peer` with the given network address.
    ///
    /// # Arguments
    /// * `address` - The network address of the peer.
    ///
    /// # Returns
    /// A new `Peer` instance.
    pub fn new(address: NetworkAddress) -> Self {
        Peer {
            receiver_address: address,
            version: None,
            ready: false,
        }
    }

    /// Generates a unique identifier for the peer based on its network address.
    ///
    /// This method uses SHA-256 hashing to create a unique ID.
    ///
    /// # Returns
    /// A 32-byte array representing the peer's unique ID.
    pub fn id(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(&self.receiver_address.serialize());
        hasher.finalize().into()
    }

    /// Constructs the version message for the peer to be used during the P2P handshake.
    ///
    /// # Type Parameters
    /// * `T` - The implementation of `NodeConfig` providing configuration details.
    ///
    /// # Returns
    /// A result containing the `MessageEnvelope` for the version message or an `Error`.
    pub fn construct_version_message<T: NodeConfig>(&self) -> Result<MessageEnvelope, Error> {
        MessageEnvelope::new::<T>(NetworkMessage::Version(VersionMessage::new::<T>(
            self.receiver_address.clone(),
            self.sender_address()?,
        )?))
    }

    /// Generates a network address representing the sender. Currently, this method
    /// returns a dummy address, as sender information is not required.
    ///
    /// # Returns
    /// A result containing a `NetworkAddress` or an `Error`.
    pub fn sender_address(&self) -> Result<NetworkAddress, Error> {
        Ok(NetworkAddress {
            services: 0,
            ip: IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)),
            port: 0,
        })
    }
}
