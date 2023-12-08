use crate::message::{Deserialize, Error, Serialize, Size};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Represents a network address in the context of the Bitcoin protocol,
/// including service flags, IP address, and port number.
#[derive(Debug, Clone)]
pub struct NetworkAddress {
    /// Service flags indicating the services supported by the node.
    pub(crate) services: u64,
    /// IP address of the node (IPv4 or IPv6).
    pub(crate) ip: IpAddr,
    /// Port number the node is listening on.
    pub(crate) port: u16,
}

impl Serialize for NetworkAddress {
    /// Serializes the `NetworkAddress` into a byte vector.
    ///
    /// # Returns
    /// A vector of bytes representing the serialized `NetworkAddress`.
    fn serialize(&self) -> Vec<u8> {
        let mut payload = Vec::new();
        // Serialize services as little-endian bytes
        payload.extend(&self.services.to_le_bytes());
        payload.extend(&self.serialize_ip_address());
        // Serialize the port as big-endian bytes. This is a special case
        payload.extend(&self.port.to_be_bytes());
        payload
    }
}

impl Deserialize for NetworkAddress {
    /// Deserializes a byte slice into a `NetworkAddress`.
    ///
    /// # Arguments
    /// * `data` - The byte slice to deserialize.
    ///
    /// # Returns
    /// A result containing the deserialized `NetworkAddress` or an `Error`.
    fn deserialize(data: &[u8]) -> Result<NetworkAddress, Error> {
        if data.len() < Self::min_size() {
            return Err(Error::InvalidInputLength);
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
    /// Serializes the IP address part of `NetworkAddress`.
    /// For IPv4 addresses, it converts them into IPv4-mapped IPv6 addresses.
    ///
    /// # Returns
    /// A 16-byte array representing the serialized IP address.
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

    /// Deserializes a 16-byte slice into an `IpAddr`.
    ///
    /// # Arguments
    /// * `ip_bytes` - The byte slice representing the IP address.
    ///
    /// # Returns
    /// A result containing the deserialized `IpAddr` or an `Error`.
    fn deserialize_ip_address(ip_bytes: &[u8]) -> Result<IpAddr, Error> {
        if ip_bytes.len() != 16 {
            return Err(Error::InvalidInputLength);
        }

        match (ip_bytes[10], ip_bytes[11]) {
            (0xff, 0xff) => {
                // If bytes 10 and 11 are both 0xff, it's an IPv4-mapped IPv6 address
                let ipv4_bytes = [ip_bytes[12], ip_bytes[13], ip_bytes[14], ip_bytes[15]];
                Ok(IpAddr::V4(Ipv4Addr::from(ipv4_bytes)))
            }
            _ => {
                let ip_v6_bytes: [u8; 16] = ip_bytes[..].try_into()?;
                Ok(IpAddr::V6(Ipv6Addr::from(ip_v6_bytes)))
            }
        }
    }
}

impl Size for NetworkAddress {
    fn min_size() -> usize {
        std::mem::size_of::<u64>() + std::mem::size_of::<[u8; 16]>() + std::mem::size_of::<u16>()
    }
}
