use crate::message::{MessageEnvelope, NetworkAddress, NetworkMessage, Serialize, VersionMessage};
use crate::{Error, NodeConfig};
use sha2::{Digest, Sha256};
use std::net::{IpAddr, Ipv4Addr};

/// Representation of the a network peer
#[derive(Debug)]
pub(crate) struct Peer {
    pub addr_recv: NetworkAddress,
    pub version: Option<VersionMessage>,
    pub ready: bool,
}

impl Peer {
    pub fn new(address: NetworkAddress) -> Self {
        Peer {
            addr_recv: address,
            version: None,
            ready: false,
        }
    }

    /// Generate id for peer, based on constant value addr_recv
    pub fn id(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(&self.addr_recv.serialize());
        hasher.finalize().into()
    }

    /// Constructs the version message sent during P2P handshake
    pub fn construct_version_message<T: NodeConfig>(&self) -> Result<MessageEnvelope, Error> {
        MessageEnvelope::new::<T>(NetworkMessage::Version(VersionMessage::new::<T>(
            self.addr_recv.clone(),
            self.to_addr_from()?,
        )?))
    }

    /// Generate sender address params. It is not required to set these.
    pub fn to_addr_from(&self) -> Result<NetworkAddress, Error> {
        Ok(NetworkAddress {
            services: 0,
            ip: IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)),
            port: 0,
        })
    }
}
