use sha2::{Digest, Sha256};
use crate::{Error, NodeConfig};
use crate::message::{Deserialize, Serialize, Size};
use crate::message::version::VersionMessage;

/// The generic wrapper used to send messages to other nodes
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
    pub message: NetworkMessage,
}

#[derive(Debug)]
pub enum NetworkMessage {
    Version(VersionMessage),
    Unimplemented
}

impl MessageEnvelope {
    pub fn new<T: NodeConfig>(message: NetworkMessage) -> MessageEnvelope {
        let (command, payload) = match &message {
            NetworkMessage::Version(payload) => ("version", payload.serialize()),
            NetworkMessage::Unimplemented => ("verack", vec![])
        };

        MessageEnvelope {
            magic: T::MAGIC,
            command: MessageEnvelope::generate_command_bytes(command),
            payload_size: payload.len() as u32,
            checksum: MessageEnvelope::generate_checksum(&payload),
            message,
        }
    }
    pub fn serialize(&self) -> Vec<u8> {
        let payload = match &self.message {
            NetworkMessage::Version(payload) => payload.serialize(),
            NetworkMessage::Unimplemented => vec![]
        };

        let mut envelope = Vec::with_capacity(Self::min_size() + self.payload_size as usize);
        envelope.extend(&self.magic);
        envelope.extend(&self.command);
        envelope.extend(&self.payload_size.to_le_bytes());
        envelope.extend(&self.checksum);
        envelope.extend(payload);
        envelope
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
        let checksum = checksum_bytes.try_into()?;
        let payload_size = u32::from_le_bytes(payload_size_bytes.try_into()?);

        let (payload_bytes, rest) = payload_and_rest.split_at(payload_size as usize);

        // ensure the checksum matches the payload
        if &MessageEnvelope::generate_checksum(payload_bytes) != &checksum {
            return Err(Error::DeserializeError("Checksum mismatch"));
        }

        // ensure the msg has the correct length
        if input_len - rest.len() != Self::min_size() + payload_size as usize {
            return Err(Error::DeserializeError("Invalid bytes input length"));
        }

        let message = match &command {
            b"version\0\0\0\0\0" => {
                NetworkMessage::Version(VersionMessage::deserialize(payload_bytes)?)
            },
            b"verack\0\0\0\0\0\0" => NetworkMessage::Unimplemented,
            _ => NetworkMessage::Unimplemented,
        };

        Ok((
            MessageEnvelope {
                magic,
                command,
                payload_size,
                checksum,
                message,
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
