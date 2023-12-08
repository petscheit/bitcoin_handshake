use crate::message::version::VersionMessage;
use crate::message::{Deserialize, Serialize, Size};
use crate::{Error, NodeConfig};
use sha2::{Digest, Sha256};

/// Represents a generic message envelope used for network communication.
/// This envelope wraps network messages with additional metadata for transmission.
#[derive(Debug)]
pub struct MessageEnvelope {
    /// Magic bytes to identify the network.
    magic: [u8; 4],
    /// Command name, right-padded with null bytes.
    pub(crate) command: [u8; 12],
    /// Size of the payload in bytes.
    payload_size: u32,
    /// Checksum for integrity verification, derived from the payload.
    checksum: [u8; 4],
    /// The actual network message payload.
    pub message: NetworkMessage,
}

/// Enum representing different types of network messages.
#[derive(Debug)]
pub enum NetworkMessage {
    Version(VersionMessage),
    Verack,
    Unimplemented,
}

impl MessageEnvelope {
    /// Creates a new message envelope for a given network message.
    ///
    /// # Arguments
    /// * `message` - The network message to be wrapped in the envelope.
    ///
    /// # Returns
    /// A result containing the new `MessageEnvelope` or an `Error`.
    pub fn new<T: NodeConfig>(message: NetworkMessage) -> Result<MessageEnvelope, Error> {
        let (command, payload) = match &message {
            NetworkMessage::Version(payload) => ("version", payload.serialize()),
            NetworkMessage::Verack => ("verack", vec![]),
            NetworkMessage::Unimplemented => return Err(Error::CantInitUnimplementedMessage),
        };

        Ok(MessageEnvelope {
            magic: T::MAGIC,
            command: MessageEnvelope::generate_command_bytes(command),
            payload_size: payload.len() as u32,
            checksum: MessageEnvelope::generate_checksum(&payload),
            message,
        })
    }

    /// Serializes the message envelope into a byte vector for transmission.
    ///
    /// # Returns
    /// A vector of bytes representing the serialized message envelope.
    pub fn serialize(&self) -> Vec<u8> {
        let payload = match &self.message {
            NetworkMessage::Version(payload) => payload.serialize(),
            NetworkMessage::Verack => vec![], // Verack has an empty payload
            NetworkMessage::Unimplemented => vec![],
        };

        let mut envelope = Vec::with_capacity(Self::min_size() + self.payload_size as usize);
        envelope.extend(&self.magic);
        envelope.extend(&self.command);
        envelope.extend(&self.payload_size.to_le_bytes());
        envelope.extend(&self.checksum);
        envelope.extend(payload);
        envelope
    }

    /// Deserializes a byte array into a `MessageEnvelope`, returning the envelope
    /// and any remaining bytes.
    ///
    /// # Arguments
    /// * `data` - The byte array to deserialize.
    ///
    /// # Returns
    /// A result containing the deserialized `MessageEnvelope` and any remaining bytes,
    /// or an `Error` if deserialization fails.
    pub fn deserialize(data: &[u8]) -> Result<(MessageEnvelope, &[u8]), Error> {
        let input_len = data.len();

        if input_len < Self::min_size() {
            return Err(Error::InvalidInputLength);
        }

        let (header, payload_and_rest) = data.split_at(24);
        let (magic_bytes, rest) = header.split_at(4);
        let (command_bytes, rest) = rest.split_at(12);
        let (payload_size_bytes, checksum_bytes) = rest.split_at(4);

        let magic = magic_bytes.try_into()?;
        let command = command_bytes.try_into()?;
        let checksum = checksum_bytes.try_into()?;
        let payload_size = u32::from_le_bytes(payload_size_bytes.try_into()?);

        // the rest can either be empty or contain the bytes to the next envelope.
        let (payload_bytes, rest) = payload_and_rest.split_at(payload_size as usize);

        // ensure the checksum matches the payload
        if MessageEnvelope::generate_checksum(payload_bytes) != checksum {
            return Err(Error::InvalidChecksum);
        }

        // ensure the msg has the correct length
        if input_len - rest.len() != Self::min_size() + payload_size as usize {
            return Err(Error::InvalidInputLength);
        }

        let message = match &command {
            b"version\0\0\0\0\0" => {
                NetworkMessage::Version(VersionMessage::deserialize(payload_bytes)?)
            }
            b"verack\0\0\0\0\0\0" => NetworkMessage::Verack,
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

    /// Generates a fixed-length command byte array from a string command.
    ///
    /// # Arguments
    /// * `name` - The command name to convert into bytes.
    ///
    /// # Returns
    /// A 12-byte array representing the command.
    fn generate_command_bytes(name: &str) -> [u8; 12] {
        // fixed length, with RHS passing -> LE
        let mut command = [0; 12];
        let bytes = name.as_bytes();
        for (i, byte) in bytes.iter().enumerate() {
            command[i] = *byte;
        }
        command
    }

    /// Generates a checksum for a given message payload.
    ///
    /// # Arguments
    /// * `msg` - The message payload to checksum.
    ///
    /// # Returns
    /// A 4-byte array representing the checksum.
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
