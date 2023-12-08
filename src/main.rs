mod message;
mod networking;
mod peer;

use crate::message::VersionMessage;
use message::NetworkAddress;
use std::net::{IpAddr, Ipv4Addr};
use tokio::sync::mpsc;
use std::collections::HashMap;
use crate::networking::TcpConnection;
use crate::peer::Peer;

#[derive(Debug)]
pub enum Error {
    IOError(std::io::Error),
    SystemTime(std::time::SystemTimeError),
    ArrayError(std::array::TryFromSliceError),
    TcpError(&'static str),
    DeserializeError(&'static str),
    InvalidInputLength,
    InvalidChecksum,
    CantInitUnimplementedMessage,
    PeerDuplicate,
    PeerNotFound
}

#[derive(Debug)]
pub enum Event {
    PeerReady([u8; 32]),
    SetVersion([u8; 32], VersionMessage),
}

#[tokio::main]
async fn main() -> Result<(), Error> {
    // init memory for peer list
    let mut peer_tracker = PeerTracker::new();
    let (tx, mut rx) = mpsc::channel(32);

    // init peer
    let mut peers = get_dummy_peers();

    for peer in peers {
        // run tcp stream processing in seperate thread
        let tx_clone = tx.clone();
        let mut peer_tcp = TcpConnection::new(&peer.addr_recv).await?;
        let msg = peer.construct_version_message::<Config>()?;
        let peer_id = peer.id();
        tokio::spawn(async move {
            // Handle the network communication and send events back to main loop
            peer_tcp
                .handle_network_communication::<Config>(msg, peer_id, tx_clone)
                .await?;
            Ok::<(), Error>(())
        });

        // add peer instance
        peer_tracker.add(peer)?;
    }

    // handle paar messages
    loop {
        tokio::select! {
            message = rx.recv() => {
                match message {
                    Some(event) => {
                        match event {
                            Event::PeerReady(peer_id) => {
                                peer_tracker.set_ready(peer_id)?;
                                println!("Handshake Successful: {:?}", peer_id)
                                //  => Init other protocol operations, e.g req_blocks
                            }
                            Event::SetVersion(peer_id, version) => {
                                peer_tracker.add_version(peer_id, version)?;
                            }
                        }
                    }
                    None => break, // Channel has closed
                }
            }
            // other async events...
        }
    }

    Ok(())
}

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

trait PeerTrackerTrait {
    fn add(&mut self, peer: Peer) -> Result<(), Error>;
    fn add_version(&mut self, peer_id: [u8;32], version:VersionMessage) ->  Result<(), Error>;
    fn set_ready(&mut self, peer_id: [u8; 32]) -> Result<(), Error>;
    fn new() -> Self;
}

pub struct PeerTracker {
    peers: HashMap<[u8; 32], Peer>
}

impl PeerTrackerTrait for PeerTracker {
    fn new() -> Self {
        PeerTracker {
            peers: HashMap::new()
        }
    }

    fn add(&mut self, peer: Peer) -> Result<(), Error> {
        if !&self.peers.contains_key(&peer.id()) {
            &self.peers.insert(peer.id(), peer);
            Ok(())
        } else {
            Err(Error::PeerDuplicate)
        }
    }

    fn set_ready(&mut self, peer_id: [u8; 32]) -> Result<(), Error> {
        if let Some(peer) = self.peers.get_mut(&peer_id) {
            peer.ready = true;
            Ok(())
        } else {
            Err(Error::PeerNotFound)
        }
    }

    fn add_version(&mut self, peer_id: [u8;32], version: VersionMessage) -> Result<(), Error> {
         if let Some(peer) = self.peers.get_mut(&peer_id) {
            peer.version = Some(version);
            Ok(())
        } else {
            Err(Error::PeerNotFound)
        }
    }
}
