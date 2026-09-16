//! Borrowed, complete-message transports. No fragmentation, buffering or heap.
#![cfg_attr(not(feature = "std"), no_std)]

use thiserror::Error;

pub const MAX_FRAME_MESSAGE: usize = 20;

#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum TransportError {
    #[error("empty message or invalid transport length")]
    InvalidLength,
    #[error("message exceeds the v3 transport limit")]
    TooLarge,
}

pub fn validate_message(message: &[u8]) -> Result<&[u8], TransportError> {
    if message.is_empty() {
        Err(TransportError::InvalidLength)
    } else if message.len() > MAX_FRAME_MESSAGE {
        Err(TransportError::TooLarge)
    } else {
        Ok(message)
    }
}

/// The host delivers one complete message per GATT write/notification or APDU
/// data field. Native platform framing/status words stay outside this API.
pub trait FrameCodec {
    fn encode<'a>(&self, message: &'a [u8]) -> Result<&'a [u8], TransportError>;
    fn decode<'a>(&self, frame: &'a [u8]) -> Result<&'a [u8], TransportError>;
}
