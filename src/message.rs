use crate::{Error, NodeConfig};
use rand;
use sha2::{Digest, Sha256};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::{SystemTime, UNIX_EPOCH};

trait Size {
    fn min_size() -> usize;
}

#[derive(Debug, Clone)]
pub struct NetworkAddress {
    pub(crate) services: u64,
    pub(crate) ip: IpAddr,
    pub(crate) port: u16,
}

impl NetworkAddress {
    pub fn serialize(&self) -> Vec<u8> {
        let mut payload = Vec::new();
        // services is LE
        payload.extend(&self.services.to_le_bytes());
        payload.extend(&self.serialize_ip_address());
        payload.extend(&self.port.to_be_bytes());
        payload
    }

    pub fn deserialize(data: &[u8]) -> Result<NetworkAddress, Error> {
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

#[derive(Debug)]
pub struct VersionMessage {
    version: u32,
    services: u64,
    timestamp: i64,
    addr_recv: NetworkAddress,
    addr_from: NetworkAddress,
    nonce: u64,
    user_agent: String,
    start_height: i32,
    relay: bool,
}

impl VersionMessage {
    pub fn new<T: NodeConfig>(
        receiver: NetworkAddress,
        sender: NetworkAddress,
    ) -> Result<VersionMessage, Error> {
        let ts = SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis() as i64;

        Ok(VersionMessage {
            version: T::VERSION,
            services: T::SERVICES,
            timestamp: ts,
            addr_recv: receiver,
            addr_from: sender,
            nonce: rand::random(),
            user_agent: T::USER_AGENT.to_string(),
            start_height: 0,
            relay: T::RELAY,
        })
    }

    pub fn serialize(&self) -> Vec<u8> {
        let mut payload = Vec::with_capacity(Self::min_size() + self.user_agent.len());
        payload.extend(&self.version.to_le_bytes());
        payload.extend(&self.services.to_le_bytes());
        payload.extend(&self.timestamp.to_le_bytes());
        payload.extend(&self.addr_recv.serialize());
        payload.extend(&self.addr_from.serialize());
        payload.extend(&self.nonce.to_le_bytes());
        payload.extend((self.user_agent.as_bytes().len() as u8).to_le_bytes());
        payload.extend(self.user_agent.as_bytes());
        payload.extend(&self.start_height.to_le_bytes());
        payload.extend(if self.relay { &[1] } else { &[0] });
        payload
    }

    pub fn deserialize(data: &[u8]) -> Result<VersionMessage, Error> {
        let input_len = data.len();

        println!("input_len: {:?}", input_len);

        let (version_bytes, rest) = data.split_at(std::mem::size_of::<u32>());
        let (services_bytes, rest) = rest.split_at(std::mem::size_of::<u64>());
        let (timestamp_bytes, rest) = rest.split_at(std::mem::size_of::<i64>());
        let addr_size = NetworkAddress::min_size();

        println!("addr_size: {:?}", addr_size);
        let (addr_recv_bytes, rest) = rest.split_at(addr_size);
        let (addr_from_bytes, rest) = rest.split_at(addr_size);
        let (nonce_bytes, rest) = rest.split_at(std::mem::size_of::<u64>());
        let (user_agent_len_bytes, rest) = rest.split_at(1);
        let user_agent_len = user_agent_len_bytes[0] as usize;

        println!("user_agent_len: {:?}", user_agent_len);
        println!("rest: {:?}", rest);

        // we now know the user agent length, so we can check the input length
        // if input_len == Self::min_size() + &user_agent_len {
        //     return Err(Error::DeserializeError("Data too short"));
        // }

        let (user_agent_bytes, rest) = rest.split_at(user_agent_len);
        let (start_height_bytes, relay_bytes) = rest.split_at(std::mem::size_of::<i32>());

        let version = u32::from_le_bytes(version_bytes.try_into()?);
        let services = u64::from_le_bytes(services_bytes.try_into()?);
        let timestamp = i64::from_le_bytes(timestamp_bytes.try_into()?);
        let addr_recv = NetworkAddress::deserialize(addr_recv_bytes)?;
        let addr_from = NetworkAddress::deserialize(addr_from_bytes)?;
        let nonce = u64::from_le_bytes(nonce_bytes.try_into()?);
        let user_agent = String::from_utf8(user_agent_bytes.to_vec()).unwrap();
        let start_height = i32::from_le_bytes(start_height_bytes.try_into()?);
        let relay = relay_bytes[0] != 0;

        Ok(VersionMessage {
            version,
            services,
            timestamp,
            addr_recv,
            addr_from,
            nonce,
            user_agent,
            start_height,
            relay,
        })
    }
}

impl Size for VersionMessage {
    fn min_size() -> usize {
        std::mem::size_of::<u32>() +
        std::mem::size_of::<u64>() +
        std::mem::size_of::<i64>() +
        NetworkAddress::min_size() * 2 +
        std::mem::size_of::<u64>() +
        std::mem::size_of::<u8>() + // user_agent length byte
        std::mem::size_of::<i32>() +
        std::mem::size_of::<bool>()
    }
}
#[derive(Debug)]
pub struct MessageEnvelope {
    /// Identifier of network
    magic: [u8; 4],
    /// Command name, null padded
    pub(crate) command: [u8; 12],
    /// Length of payload
    payload_size: u32,
    /// First 4 bytes of 2xsha256 of payload
    checksum: [u8; 4],
    /// Serialized command data
    pub payload: Vec<u8>,
}

impl MessageEnvelope {
    pub fn pack_version<T: NodeConfig>(payload: Vec<u8>) -> MessageEnvelope {
        MessageEnvelope {
            magic: T::MAGIC,
            command: MessageEnvelope::generate_command_bytes("version"),
            payload_size: payload.len() as u32,
            checksum: MessageEnvelope::generate_checksum(&payload),
            payload,
        }
    }
    pub fn serialize(&self) -> Vec<u8> {
        let mut message = Vec::with_capacity(Self::min_size() + self.payload.len());
        message.extend(&self.magic);
        message.extend(&self.command);
        message.extend(&self.payload_size.to_le_bytes());
        message.extend(&self.checksum);
        message.extend(&self.payload);
        message
    }

    pub fn deserialize(data: &[u8]) -> Result<(MessageEnvelope, &[u8]), Error> {
        let input_len = data.len();

        if &input_len < &Self::min_size() {
            return Err(Error::DeserializeError("Invalid bytes input length"));
        }

        let (header, payload_and_rest) = data.split_at(24);
        let (magic_bytes, rest) = header.split_at(4);
        let (command_bytes, rest) = rest.split_at(12);
        let (payload_size_bytes, checksum_bytes) = rest.split_at(4);

        let magic = magic_bytes.try_into()?;
        let command = command_bytes.try_into()?;
        let payload_size = u32::from_le_bytes(payload_size_bytes.try_into()?);

        let (payload, rest) = payload_and_rest.split_at(payload_size as usize);

        // ensure the msg has the correct length
        if input_len - rest.len() != Self::min_size() + payload_size as usize {
            return Err(Error::DeserializeError("Invalid bytes input length"));
        }

        let checksum = checksum_bytes.try_into()?;

        // ensure the checksum matches the payload
        if &MessageEnvelope::generate_checksum(payload) != &checksum {
            return Err(Error::DeserializeError("Checksum mismatch"));
        }

        Ok((
            MessageEnvelope {
                magic,
                command,
                payload_size,
                checksum,
                payload: payload.to_vec(),
            },
            rest,
        ))
    }

    fn generate_command_bytes(name: &str) -> [u8; 12] {
        // fixed length, with RHS passing -> LE
        let mut command = [0; 12];
        let bytes = name.as_bytes();
        for (i, byte) in bytes.iter().enumerate() {
            command[i] = *byte;
        }
        command
    }

    fn generate_checksum(msg: &[u8]) -> [u8; 4] {
        const CHECKSUM_SIZE: usize = 4;

        let mut hasher = Sha256::new();
        hasher.update(msg);
        let first_hash = hasher.finalize();

        let mut hasher = Sha256::new();
        hasher.update(first_hash);
        let final_hash = hasher.finalize();

        // Create an array from the first 4 bytes of the final hash
        let mut checksum = [0u8; CHECKSUM_SIZE];
        checksum.copy_from_slice(&final_hash[..CHECKSUM_SIZE]);

        checksum
    }
}

impl Size for MessageEnvelope {
    fn min_size() -> usize {
        4 + 12 + 4 + 4
    }
}
