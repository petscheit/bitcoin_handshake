mod networking;
mod message;
use std::net::{IpAddr, Ipv4Addr};
use crate::message::{Address, VersionMessage};
use crate::networking::Peer;


#[derive(Debug)]
pub enum Error{
    TcpStreamError(std::io::Error),

}

fn main() {
    let peer = Peer::new(IpAddr::V4(Ipv4Addr::new(168, 119, 68, 66)), 8333).unwrap();
    let address_recv = peer.to_address();
    let version_msg = VersionMessage::new(
        address_recv,
        Address::new(),
    );

    println!("{:?}", version_msg);

    let assembeled_message = version_msg.assemble_message();


    println!("{:?}", assembeled_message);
    // match peer {
    //     Ok(stream) => println!("Connected to peer: {:?}", stream),
    //     Err(e) => println!("Error connecting to peer: {:?}", e),
    // }
    // println!("{:?}", peer);
}


