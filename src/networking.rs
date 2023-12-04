use std::io::{BufReader, Read, Write};
use std::net::{IpAddr, Ipv4Addr, Shutdown, SocketAddr, TcpStream};
use crate::Error;
use crate::message::{Address};

#[derive(Debug)]
pub(crate) struct Peer {
    ip: IpAddr,
    port: u16,
    pub(crate) connection: TcpStream,
}

impl Peer {
    pub(crate) fn new(ip: IpAddr, port: u16) -> Result<Self, Error> {
        let connection = init_peer_connection(&format!("{}:{}", ip, port))?;

        Ok(Peer {
            ip,
            port,
            connection,
        })
    }

    pub fn to_recv_address(&self) -> Address {
        let ip: [u8; 16] = match self.ip {
            IpAddr::V4(ipv4) => {
                // Convert IPv4 addresses to IPv4-mapped IPv6 addresses
                let ipv4_bytes = ipv4.octets();
                let mut ipv6_bytes = [0u8; 16];
                ipv6_bytes[10] = 0xff;
                ipv6_bytes[11] = 0xff;
                ipv6_bytes[12..].copy_from_slice(&ipv4_bytes);
                ipv6_bytes
            },
            IpAddr::V6(ipv6) => ipv6.octets(),
        };
        Address {
            services: 0,
            ip,
            port: self.port,
        }
    }

    pub fn to_sender_address(&self) -> Result<Address, Error> {
        let address = IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0));

        let ip: [u8; 16] = match address {
            IpAddr::V4(ipv4) => {
                // Convert IPv4 addresses to IPv4-mapped IPv6 addresses
                let ipv4_bytes = ipv4.octets();
                let mut ipv6_bytes = [0u8; 16];
                ipv6_bytes[10] = 0xff;
                ipv6_bytes[11] = 0xff;
                ipv6_bytes[12..].copy_from_slice(&ipv4_bytes);
                ipv6_bytes
            },
            IpAddr::V6(ipv6) => ipv6.octets(),
        };
        Ok(Address {
            services: 0,
            ip,
            port: 0
        })
    }

    pub fn send_message(&mut self, message: &[u8]) -> Result<(), Error> {
        self.connection.write_all(message).unwrap();
        println!("Sent message: {:?}", message);
        Ok(())
    }
}
pub fn init_peer_connection(peer_address: &str) -> Result<TcpStream, Error> {
    match TcpStream::connect(peer_address) {
        Ok(stream) => Ok(stream),
        Err(e) => Err(Error::TcpStreamError(e)),
    }
}




