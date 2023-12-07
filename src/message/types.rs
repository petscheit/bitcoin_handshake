use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use crate::message::{Deserialize, Error, Serialize, Size};

#[derive(Debug, Clone)]
pub struct NetworkAddress {
    pub(crate) services: u64,
    pub(crate) ip: IpAddr,
    pub(crate) port: u16,
}

impl Serialize for NetworkAddress {
    fn serialize(&self) -> Vec<u8> {
         let mut payload = Vec::new();
        // services is LE
        payload.extend(&self.services.to_le_bytes());
        payload.extend(&self.serialize_ip_address());
        payload.extend(&self.port.to_be_bytes());
        payload
    }
}

impl Deserialize for NetworkAddress {
    fn deserialize(data: &[u8]) -> Result<NetworkAddress, Error> {
        if data.len() < Self::min_size() {
            return Err(Error::DeserializeError("Invalid Data Length"));
        }

        let (services_bytes, rest) = data.split_at(8);
        let (ip_bytes, port_bytes) = rest.split_at(16);

        let services = u64::from_le_bytes(services_bytes.try_into()?);
        let ip = NetworkAddress::deserialize_ip_address(ip_bytes)?;
        let port = u16::from_be_bytes(port_bytes.try_into()?);

        Ok(NetworkAddress { services, ip, port })
    }
}

impl NetworkAddress {

    /// The Bitcoin protocol uses IPv4-mapped IPv6 addresses for IPv4 connections
    fn serialize_ip_address(&self) -> [u8; 16] {
        match self.ip {
            IpAddr::V4(ipv4) => {
                // Convert IPv4 addresses to IPv4-mapped IPv6 addresses
                let ipv4_bytes = ipv4.octets();
                let mut ipv6_bytes = [0u8; 16];
                ipv6_bytes[10] = 0xff;
                ipv6_bytes[11] = 0xff;
                ipv6_bytes[12..].copy_from_slice(&ipv4_bytes);
                ipv6_bytes
            }
            IpAddr::V6(ipv6) => ipv6.octets(),
        }
    }

    fn deserialize_ip_address(ip_bytes: &[u8]) -> Result<IpAddr, Error> {
        if ip_bytes.len() != 16 {
            return Err(Error::DeserializeError("Invalid IP Address Length"));
        }

        return match (ip_bytes[10], ip_bytes[11]) {
            (0xff, 0xff) => {
                // If bytes 10 and 11 are both 0xff, it's an IPv4-mapped IPv6 address
                let ipv4_bytes = [ip_bytes[12], ip_bytes[13], ip_bytes[14], ip_bytes[15]];
                Ok(IpAddr::V4(Ipv4Addr::from(ipv4_bytes)))
            }
            _ => {
                let ip_v6_bytes: [u8; 16] = ip_bytes[..].try_into()?;
                Ok(IpAddr::V6(Ipv6Addr::from(ip_v6_bytes)))
            }
        };
    }
}

impl Size for NetworkAddress {
    fn min_size() -> usize {
        std::mem::size_of::<u64>() + std::mem::size_of::<[u8; 16]>() + std::mem::size_of::<u16>()
    }
}
