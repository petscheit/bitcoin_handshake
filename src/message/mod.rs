use crate::Error;
pub mod envelope;
pub mod types;
pub mod version;

pub use envelope::{MessageEnvelope, NetworkMessage};
pub use types::NetworkAddress;
pub use version::VersionMessage;

pub trait Size {
    fn min_size() -> usize;
}

pub trait Serialize {
    fn serialize(&self) -> Vec<u8>;
}

pub trait Deserialize {
    fn deserialize(data: &[u8]) -> Result<Self, Error>
    where
        Self: Sized;
}