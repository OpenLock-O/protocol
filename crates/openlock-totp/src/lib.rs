//! Plaintext TOTP authentication for OpenLock. Firmware selects its mode
//! through trusted configuration; there is no automatic fallback between
//! encrypted sessions and TOTP.
//!
//! This crate is independent of the secure crates and needs no heap, public-key
//! cryptography, or runtime RNG. Firmware supplies trusted time and durable
//! storage. Use `core::LockState` to authorize; OTP comparison alone is not enough.
#![cfg_attr(not(feature = "std"), no_std)]

pub mod core;
pub mod crypto;
pub mod protocol;
pub mod provisioning;
pub mod transport;
pub mod types;

pub use crate::core::{
    ActuationError, AttemptState, Credential, LockState, PersistentState, UsageState,
};
pub use crypto::TotpSecret;
pub use types::*;
