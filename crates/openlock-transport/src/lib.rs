//! Byte-oriented transport extension point. Platform I/O stays outside this crate.
#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

use alloc::vec::Vec;
use thiserror::Error;

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum TransportError {
    #[error("fragment is too short")]
    TooShort,
    #[error("fragment has invalid length")]
    InvalidLength,
    #[error("message exceeds configured limit")]
    TooLarge,
    #[error("fragment is outside message")]
    OutOfBounds,
    #[error("fragment conflicts with an existing fragment")]
    Conflict,
    #[error("another message is being reassembled")]
    Busy,
    #[error("message is incomplete")]
    Incomplete,
    #[error("invalid NFC record or APDU")]
    InvalidNfc,
}

pub trait FrameCodec {
    type Error;
    fn encode(&mut self, message: &[u8]) -> Result<Vec<Vec<u8>>, Self::Error>;
    fn push(&mut self, fragment: &[u8]) -> Result<Option<Vec<u8>>, Self::Error>;
    fn reset(&mut self);
}
