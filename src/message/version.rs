use crate::message::types::NetworkAddress;
use crate::message::{Deserialize, Serialize, Size};
use crate::{Error, NodeConfig};
use std::time::{SystemTime, UNIX_EPOCH};

/// Represents the `version` message in the Bitcoin protocol.
/// It is used to relay information about the node when connecting to a peer.
#[derive(Debug, Clone, PartialEq)]
pub struct VersionMessage {
    /// The protocol version of the sender.
    pub(crate) version: u32,
    /// The services supported by the sender.
    pub(crate) services: u64,
    /// The current timestamp of the sender.
    pub(crate) timestamp: i64,
    /// The network address of the receiver.
    pub(crate) receiver_address: NetworkAddress,
    /// The network address of the sender.
    pub(crate) sender_address: NetworkAddress,
    /// A random nonce
    pub(crate) nonce: u64,
    /// The user agent of the sender.
    pub(crate) user_agent: String,
    /// The current block height of the sender.
    pub(crate) start_height: i32,
    /// Whether the sender wants to be relayed to other nodes by the receiver.
    pub(crate) relay: bool,
}

impl Serialize for VersionMessage {
    /// Serializes the `VersionMessage` into a byte vector.
    ///
    /// # Returns
    /// A vector of bytes representing the serialized `VersionMessage`.
    fn serialize(&self) -> Vec<u8> {
        let mut payload = Vec::with_capacity(Self::min_size() + self.user_agent.len());
        payload.extend(&self.version.to_le_bytes());
        payload.extend(&self.services.to_le_bytes());
        payload.extend(&self.timestamp.to_le_bytes());
        payload.extend(&self.receiver_address.serialize());
        payload.extend(&self.sender_address.serialize());
        payload.extend(&self.nonce.to_le_bytes());
        payload.extend((self.user_agent.as_bytes().len() as u8).to_le_bytes());
        payload.extend(self.user_agent.as_bytes());
        payload.extend(&self.start_height.to_le_bytes());
        payload.extend(if self.relay { &[1] } else { &[0] });
        payload
    }
}

impl Deserialize for VersionMessage {
    /// Deserializes a byte slice into a `VersionMessage`.
    ///
    /// # Arguments
    /// * `data` - The byte slice to deserialize.
    ///
    /// # Returns
    /// A result containing the deserialized `VersionMessage` or an `Error`.
    fn deserialize(data: &[u8]) -> Result<VersionMessage, Error> {
        let input_len = data.len();

        let (version_bytes, rest) = data.split_at(std::mem::size_of::<u32>());
        let (services_bytes, rest) = rest.split_at(std::mem::size_of::<u64>());
        let (timestamp_bytes, rest) = rest.split_at(std::mem::size_of::<i64>());
        let addr_size = NetworkAddress::min_size();

        let (receiver_address_bytes, rest) = rest.split_at(addr_size);
        let (sender_address_bytes, rest) = rest.split_at(addr_size);
        let (nonce_bytes, rest) = rest.split_at(std::mem::size_of::<u64>());
        let (user_agent_len_bytes, rest) = rest.split_at(1);
        let user_agent_len = user_agent_len_bytes[0] as usize;

        // we now know the user agent length, so we can check the input length
        if input_len != Self::min_size() + user_agent_len {
            return Err(Error::InvalidInputLength);
        }

        let (user_agent_bytes, rest) = rest.split_at(user_agent_len);
        let (start_height_bytes, relay_bytes) = rest.split_at(std::mem::size_of::<i32>());

        let version = u32::from_le_bytes(version_bytes.try_into()?);
        let services = u64::from_le_bytes(services_bytes.try_into()?);
        let timestamp = i64::from_le_bytes(timestamp_bytes.try_into()?);
        let receiver_address = NetworkAddress::deserialize(receiver_address_bytes)?;
        let sender_address = NetworkAddress::deserialize(sender_address_bytes)?;
        let nonce = u64::from_le_bytes(nonce_bytes.try_into()?);
        let user_agent = String::from_utf8(user_agent_bytes.to_vec()).unwrap();
        let start_height = i32::from_le_bytes(start_height_bytes.try_into()?);
        let relay = relay_bytes[0] != 0;

        Ok(VersionMessage {
            version,
            services,
            timestamp,
            receiver_address,
            sender_address,
            nonce,
            user_agent,
            start_height,
            relay,
        })
    }
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
            receiver_address: receiver,
            sender_address: sender,
            nonce: rand::random(),
            user_agent: T::USER_AGENT.to_string(),
            start_height: 0,
            relay: T::RELAY,
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;
    use std::net::{IpAddr, Ipv4Addr};

    #[test]
    fn test_serialize_deserialize_version_message_ipv4() {
        let receiver_address = NetworkAddress {
            services: 1,
            ip: IpAddr::V4(Ipv4Addr::from_str("192.168.1.1").unwrap()),
            port: 8080,
        };

        let sender_address = NetworkAddress {
            services: 2,
            ip: IpAddr::V4(Ipv4Addr::from_str("192.168.1.2").unwrap()),
            port: 8081,
        };

        let original_message = VersionMessage {
            version: 70015,
            services: 0x01020304,
            timestamp: 1234567890,
            receiver_address,
            sender_address,
            nonce: 9876543210,
            user_agent: "/Satoshi:0.7.2/".to_string(),
            start_height: 654321,
            relay: true,
        };

        let serialized_data = original_message.serialize();
        let deserialized_message = VersionMessage::deserialize(&serialized_data).unwrap();

        assert_eq!(deserialized_message.version, original_message.version);
        assert_eq!(deserialized_message.services, original_message.services);
        assert_eq!(deserialized_message.timestamp, original_message.timestamp);
        assert_eq!(deserialized_message.receiver_address, original_message.receiver_address);
        assert_eq!(deserialized_message.sender_address, original_message.sender_address);
        assert_eq!(deserialized_message.nonce, original_message.nonce);
        assert_eq!(deserialized_message.user_agent, original_message.user_agent);
        assert_eq!(deserialized_message.start_height, original_message.start_height);
        assert_eq!(deserialized_message.relay, original_message.relay);
    }
}

