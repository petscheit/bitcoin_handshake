mod message;
mod networking;
mod peer;

use crate::message::VersionMessage;
use crate::networking::TcpConnection;
use crate::peer::Peer;
use message::NetworkAddress;
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use tokio::sync::mpsc;

#[derive(Debug)]
pub enum Error {
    IOError(std::io::Error),
    SystemTime(std::time::SystemTimeError),
    ArrayError(std::array::TryFromSliceError),
    InvalidInputLength,
    InvalidChecksum,
    CantInitUnimplementedMessage,
    PeerDuplicate,
    PeerNotFound,
}

#[derive(Debug)]
pub enum Event {
    PeerReady([u8; 32]),
    SetVersion([u8; 32], VersionMessage),
}

/// The entry point of the application. Initializes and manages network communications.
#[tokio::main]
async fn main() -> Result<(), Error> {
    // Initialize the structure for tracking peers.
    let mut peer_tracker = PeerTracker::new();
    // Create a message-passing channel for handling events.
    let (tx, mut rx) = mpsc::channel(32);

    // Create dummy peers for initial testing and setup.
    let peers = get_dummy_peers();

    // Iterate through each peer to set up TCP connections and message handling.
    for peer in peers {
        let tx_clone = tx.clone();
        let mut peer_tcp = TcpConnection::new(&peer.receiver_address).await?;
        let msg = peer.construct_version_message::<Config>()?;
        let peer_id = peer.id();

        // Spawn a new asynchronous task for each peer to handle network communication.
        tokio::spawn(async move {
            peer_tcp
                .handle_network_communication::<Config>(msg, peer_id, tx_clone)
                .await?;
            Ok::<(), Error>(())
        });

        // Add the peer to the peer tracker.
        peer_tracker.add(peer)?;
    }

    // Continuously listen for and handle messages from the peer TCP streams.
    loop {
        tokio::select! {
            message = rx.recv() => {
                match message {
                    Some(event) => {
                        match event {
                            Event::PeerReady(peer_id) => {
                                peer_tracker.set_ready(peer_id)?;
                                println!("Handshake Successful: {:?}", peer_id)
                            }
                            Event::SetVersion(peer_id, version) => {
                                peer_tracker.add_version(peer_id, version)?;
                            }
                        }
                    }
                    None => break, // Exit if the channel has closed
                }
            }
            // Additional asynchronous events can be handled here.
        }
    }

    Ok(())
}

/// Generates a list of dummy peers for testing and initial setup.
fn get_dummy_peers() -> Vec<Peer> {
    vec![
        Peer::new(NetworkAddress {
            services: 0,
            ip: IpAddr::V4(Ipv4Addr::new(168, 119, 68, 66)),
            port: 8333,
        }),
        Peer::new(NetworkAddress {
            services: 0,
            ip: IpAddr::V4(Ipv4Addr::new(149, 102, 139, 50)),
            port: 8333,
        }),
        Peer::new(NetworkAddress {
            services: 0,
            ip: IpAddr::V4(Ipv4Addr::new(116, 203, 99, 217)),
            port: 8333,
        }),
    ]
}

/// Defines the configuration parameters for a node in the network.
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

/// Default (mainnet) configuration for the node.
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

/// `PeerTrackerTrait` defines the operations that can be performed on a `PeerTracker`.
trait PeerTrackerTrait {
    /// Creates a new `PeerTracker` instance.
    fn new() -> Self;
    /// Adds a new peer to the tracker.
    fn add(&mut self, peer: Peer) -> Result<(), Error>;
    /// Add the `VersionMessage` to a stored peer
    fn add_version(&mut self, peer_id: [u8; 32], version: VersionMessage) -> Result<(), Error>;
    /// Sets a peer to ready
    fn set_ready(&mut self, peer_id: [u8; 32]) -> Result<(), Error>;
}

/// `PeerTracker` manages the state and information of all connected peers in the network.
pub struct PeerTracker {
    peers: HashMap<[u8; 32], Peer>,
}

impl PeerTrackerTrait for PeerTracker {
    fn new() -> Self {
        PeerTracker {
            peers: HashMap::new(),
        }
    }

    fn add(&mut self, peer: Peer) -> Result<(), Error> {
        if !&self.peers.contains_key(&peer.id()) {
            self.peers.insert(peer.id(), peer);
            Ok(())
        } else {
            Err(Error::PeerDuplicate)
        }
    }

    fn add_version(&mut self, peer_id: [u8; 32], version: VersionMessage) -> Result<(), Error> {
        let peer = self.peers.get_mut(&peer_id).ok_or(Error::PeerNotFound)?;
        peer.version = Some(version);
        Ok(())
    }

    fn set_ready(&mut self, peer_id: [u8; 32]) -> Result<(), Error> {
        let peer = self.peers.get_mut(&peer_id).ok_or(Error::PeerNotFound)?;
        peer.ready = true;
        Ok(())
    }
}
