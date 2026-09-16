//! Optional plaintext TOTP scheme in OpenLock v3. The secure v2 scheme remains
//! available in the original OpenLock crates. Selection is explicit; there is
//! no automatic fallback between schemes.
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
