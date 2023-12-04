mod networking;
mod message;
version
use std::io::{BufRead, BufReader, Read};
use std::net::{IpAddr, Ipv4Addr};
use crate::message::{Address, VersionMessage};
use crate::networking::Peer;


#[derive(Debug)]
pub enum Error{
    TcpStreamError(std::io::Error),

}

fn main() {
    let mut peer = Peer::new(IpAddr::V4(Ipv4Addr::new(168, 119, 68, 66)), 8333).unwrap();
    println!("{:?}", peer);
    let version_msg = VersionMessage::new(
        peer.to_recv_address(),
        peer.to_sender_address().unwrap(),
    );

    let assembeled_message = version_msg.assemble_message();
    peer.send_message(&assembeled_message).unwrap();

    let read_stream = peer.connection.try_clone().unwrap();
    let mut stream_reader = BufReader::new(read_stream);

    let mut buffer = Vec::new();

    loop {
        match stream_reader.read_to_end(&mut buffer) {
            Ok(0) => {
                // No more data to read; you might want to break or handle this case.
                continue;
            },
            Ok(_) => {
                // Process and print the buffer content.
                // The actual implementation will depend on the specifics of the Bitcoin protocol.
                // For demonstration, let's just print the raw bytes.
                println!("Received data: {:?}", buffer);

                // Clear the buffer for the next read.
                buffer.clear();
            },
            Err(e) => {
                eprintln!("Failed to read from stream: {}", e);
                break;
            }
        }
    }



    // println!("{:?}", assembeled_message);
    // match peer {
    //     Ok(stream) => println!("Connected to peer: {:?}", stream),
    //     Err(e) => println!("Error connecting to peer: {:?}", e),
    // }
    // println!("{:?}", peer);
}


