use chrono::Utc;
use rand;
type ServiceFlag = u64;
use sha2::{Sha256, Digest};

#[derive(Debug)]
pub struct Address {
    pub(crate) services: ServiceFlag,
    pub(crate) ip: [u8; 16],
    pub(crate) port: u16,
}

impl Address {
    pub fn new() -> Address {
        Address {
            services: 0,
            ip: [0; 16],
            port: 0,
        }
    }

    pub fn serialize(&self) -> Vec<u8> {
        let mut payload = Vec::new();
        // services is LE
        payload.extend(&self.services.to_le_bytes());
        // IP and port are the exception, and encoded in BE
        payload.extend(&self.ip);
        payload.extend(&self.port.to_be_bytes());
        payload
    }
}

#[derive(Debug)]
pub struct VersionMessage {
    version: u32,
    services: ServiceFlag,
    timestamp: i64,
    addr_recv: Address,
    addr_from: Address,
    nonce: u64,
    user_agent: String,
    start_height: i32,
    relay: bool,
}

impl VersionMessage {
    pub fn new(
        receiver: Address,
        sender: Address,
    ) -> VersionMessage {
        VersionMessage {
            version: 70001,
            services: 0,
            timestamp: 1701707143,
            addr_recv: receiver,
            addr_from: sender,
            nonce: rand::random(),
            user_agent: String::from("/Satoshi:23.0.0/"),
            start_height: 0,
            relay: false,
        }
    }

    pub fn serialize(&self) -> Vec<u8> {
        let mut payload = Vec::new();
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


    // All messages are wrapped in a network envelope that contains the following fields:
    // | Field Size | Description | Data type |
    // |------------|-------------|-----------|
    // | 4 bytes    | magic       | uint32_t  |
    // | 12 bytes   | command     | char[12]  |
    // | 4 bytes    | length      | uint32_t  |
    // | 4 bytes    | checksum    | uint32_t  |
    // | ? bytes    | payload     | uchar[]   |
    // These are then LE encoded and sent to the peer
    pub fn assemble_message(&self) -> Vec<u8> {
        let mut payload = Vec::new();
        // magic -> in this case it's the mainnet magic
        payload.extend(vec![0xf9, 0xbe, 0xb4, 0xd9]);
        // command char[12] -> in this case it's version
        payload.extend(VersionMessage::generate_command_bytes("version"));

        let msg= self.serialize();
        // payload size (u32) -> in this case it's the size of the version message
        payload.extend((msg.len() as u32).to_le_bytes());
        // checksum -> first 4 bytes of the sha256d of the version message
        payload.extend(VersionMessage::generate_checksum(&msg));

        payload.extend(msg);
        payload
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

    fn generate_checksum(msg: &Vec<u8>) -> Vec<u8> {
        let mut hasher = Sha256::new();
        hasher.update(msg);
        let first_hash = hasher.finalize();

        // Second hash on the result of the first hash
        let mut hasher = Sha256::new();
        hasher.update(first_hash);
        // Getting the first 4 bytes of the final hash
        hasher.finalize().to_vec()[0..4].to_vec()
    }
}
