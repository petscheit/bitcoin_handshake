use crate::message::types::NetworkAddress;
use crate::message::{Deserialize, Serialize, Size};
use crate::{Error, NodeConfig};
use std::time::{SystemTime, UNIX_EPOCH};

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

impl Serialize for VersionMessage {
    fn serialize(&self) -> Vec<u8> {
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
}

impl Deserialize for VersionMessage {
    fn deserialize(data: &[u8]) -> Result<VersionMessage, Error> {
        let input_len = data.len();

        let (version_bytes, rest) = data.split_at(std::mem::size_of::<u32>());
        let (services_bytes, rest) = rest.split_at(std::mem::size_of::<u64>());
        let (timestamp_bytes, rest) = rest.split_at(std::mem::size_of::<i64>());
        let addr_size = NetworkAddress::min_size();

        let (addr_recv_bytes, rest) = rest.split_at(addr_size);
        let (addr_from_bytes, rest) = rest.split_at(addr_size);
        let (nonce_bytes, rest) = rest.split_at(std::mem::size_of::<u64>());
        let (user_agent_len_bytes, rest) = rest.split_at(1);
        let user_agent_len = user_agent_len_bytes[0] as usize;

        // we now know the user agent length, so we can check the input length
        if input_len != Self::min_size() + user_agent_len {
            return Err(Error::DeserializeError("Invalid byte input length"));
        }

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
