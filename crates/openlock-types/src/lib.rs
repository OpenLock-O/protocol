//! Shared domain values. No transport, cryptography or platform dependencies.
#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

use alloc::{collections::BTreeSet, vec::Vec};
use thiserror::Error;

pub const PROTOCOL_VERSION: u64 = 4;
/// Signed grants and policies retain their v2 encoding and domains.
pub const CREDENTIAL_VERSION: u64 = 2;
pub const MAX_OBJECT_SIZE: usize = 4096;
pub const MAX_MESSAGE_SIZE: usize = 4096;
/// Local session events add an authenticated peer key to the wire body.
pub const MAX_EVENT_SIZE: usize = MAX_MESSAGE_SIZE + 64;
pub const RIGHTS_UNLOCK: u32 = 1;
pub const RIGHTS_STATUS: u32 = 2;
pub const RIGHTS_LOCK: u32 = 4;
pub const RIGHTS_LOG: u32 = 8;
pub const RIGHTS_CONFIG: u32 = 16;
pub const RIGHTS_CREDENTIALS: u32 = 32;
pub const RIGHTS_CLOCK: u32 = 64;
pub const RIGHTS_REBOOT: u32 = 128;
pub const RIGHTS_FIRMWARE: u32 = 256;
pub const RIGHTS_RESET: u32 = 512;
pub const RIGHTS_TRUST: u32 = 1024;
pub const KNOWN_RIGHTS: u32 = 2047;
// Capability bits identify command opcodes. They never confer authorization.
pub const CAP_UNLOCK: u64 = 1;
pub const CAP_STATUS: u64 = 2;
pub const CAP_POLICY: u64 = 4;
pub const KNOWN_CAPABILITIES: u64 = (1 << 23) - 1;
pub mod device;
pub use device::*;

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct LockId(pub [u8; 16]);
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct CredentialId(pub [u8; 16]);
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SubjectKey(pub [u8; 32]);
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Validity {
    pub not_before: u64,
    pub not_after: u64,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Grant {
    pub credential_id: CredentialId,
    pub lock_id: LockId,
    pub subject_key: SubjectKey,
    pub rights: u32,
    pub epoch: u64,
    pub validity: Option<Validity>,
    pub max_uses: Option<u32>,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PolicyUpdate {
    pub lock_id: LockId,
    pub epoch: u64,
    pub version: u64,
    pub revoked: BTreeSet<CredentialId>,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ClockSample {
    pub lower: u64,
    pub upper: u64,
}
impl ClockSample {
    pub fn validate(self) -> Result<Self, Error> {
        if self.lower > self.upper {
            Err(Error::ClockUntrusted)
        } else {
            Ok(self)
        }
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Authorization {
    LongLived,
    Timed,
    Counted { used: u32, max: u32 },
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Decision {
    Authorized(Authorization),
    AlreadyConsumed { next_use: u32 },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeviceKey {
    pub device_id: LockId,
    pub key_id: u32,
    pub key_version: u32,
    pub x25519_public_key: [u8; 32],
    /// Independent Ed25519 key; an X25519 key cannot sign rotation records.
    pub rotation_public_key: [u8; 32],
    pub capabilities: u64,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeviceKeyRecord {
    pub key: DeviceKey,
    pub issuer_key_id: u32,
    pub signature: Vec<u8>,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct KeyUpdate {
    pub old_key_id: u32,
    pub new_record: DeviceKeyRecord,
    pub not_before: u64,
    pub retire_after: u64,
    /// None means the old device's rotation key; Some identifies a trusted root.
    pub issuer_key_id: Option<u32>,
    pub signature: Vec<u8>,
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum Error {
    #[error("object is too large")]
    ObjectTooLarge,
    #[error("invalid COSE object")]
    InvalidCose,
    #[error("invalid payload")]
    InvalidPayload,
    #[error("signature verification failed")]
    BadSignature,
    #[error("wrong lock")]
    WrongLock,
    #[error("credential is revoked")]
    Revoked,
    #[error("credential epoch is stale")]
    StaleEpoch,
    #[error("credential is outside its validity window")]
    Expired,
    #[error("clock is not trusted")]
    ClockUntrusted,
    #[error("credential usage exhausted")]
    UsageExhausted,
    #[error("policy version is stale or conflicting")]
    StalePolicy,
    #[error("persistent storage failed")]
    StorageUnavailable,
    #[error("invalid consumption sequence")]
    InvalidConsumption,
    #[error("requested right is not present")]
    MissingRight,
    #[error("Noise authentication failed")]
    Noise,
    #[error("unsupported protocol version or profile")]
    UnsupportedVersion,
    #[error("invalid session state")]
    InvalidState,
    #[error("unsupported capability")]
    UnsupportedCapability,
    #[error("untrusted identity")]
    UntrustedKey,
    #[error("stale or conflicting key version")]
    StaleKey,
    #[error("actuation failed; result may be ambiguous")]
    ActuatorFailed,
    #[error("invalid NFC record")]
    InvalidNfc,
    #[error("Busy")]
    Busy,
    #[error("DoorOpen")]
    DoorOpen,
    #[error("PrivacyActive")]
    PrivacyActive,
    #[error("Jammed")]
    Jammed,
    #[error("ActionTimeout")]
    ActionTimeout,
    #[error("SensorConflict")]
    SensorConflict,
    #[error("InvalidConfig")]
    InvalidConfig,
    #[error("Conflict")]
    Conflict,
    #[error("ResultUnavailable")]
    ResultUnavailable,
    #[error("NotProvisioned")]
    NotProvisioned,
    #[error("AlreadyProvisioned")]
    AlreadyProvisioned,
    #[error("PairingClosed")]
    PairingClosed,
    #[error("InvalidSetupKey")]
    InvalidSetupKey,
    #[error("PhysicalConfirmationRequired")]
    PhysicalConfirmationRequired,
    #[error("ClockRollback")]
    ClockRollback,
    #[error("FirmwareInvalid")]
    FirmwareInvalid,
    #[error("FirmwareTargetMismatch")]
    FirmwareTargetMismatch,
    #[error("FirmwareRollback")]
    FirmwareRollback,
    #[error("FirmwareConflict")]
    FirmwareConflict,
    #[error("FirmwareIncomplete")]
    FirmwareIncomplete,
    #[error("PowerInsufficient")]
    PowerInsufficient,
    #[error("BootFailed")]
    BootFailed,
    #[error("ResourceExhausted")]
    ResourceExhausted,
}
impl Error {
    /// Stable, positive v2 wire/FFI error codes.
    pub fn code(&self) -> u32 {
        match self {
            Self::ObjectTooLarge => 1,
            Self::InvalidCose => 2,
            Self::InvalidPayload => 3,
            Self::BadSignature => 4,
            Self::WrongLock => 5,
            Self::Revoked => 6,
            Self::StaleEpoch => 7,
            Self::Expired => 8,
            Self::ClockUntrusted => 9,
            Self::UsageExhausted => 10,
            Self::StalePolicy => 11,
            Self::StorageUnavailable => 12,
            Self::InvalidConsumption => 13,
            Self::MissingRight => 14,
            Self::Noise => 15,
            Self::UnsupportedVersion => 16,
            Self::InvalidState => 17,
            Self::UnsupportedCapability => 18,
            Self::UntrustedKey => 19,
            Self::StaleKey => 20,
            Self::ActuatorFailed => 21,
            Self::InvalidNfc => 22,
            Self::Busy => 32,
            Self::DoorOpen => 33,
            Self::PrivacyActive => 34,
            Self::Jammed => 35,
            Self::ActionTimeout => 36,
            Self::SensorConflict => 37,
            Self::InvalidConfig => 38,
            Self::Conflict => 39,
            Self::ResultUnavailable => 40,
            Self::NotProvisioned => 41,
            Self::AlreadyProvisioned => 42,
            Self::PairingClosed => 43,
            Self::InvalidSetupKey => 44,
            Self::PhysicalConfirmationRequired => 45,
            Self::ClockRollback => 46,
            Self::FirmwareInvalid => 47,
            Self::FirmwareTargetMismatch => 48,
            Self::FirmwareRollback => 49,
            Self::FirmwareConflict => 50,
            Self::FirmwareIncomplete => 51,
            Self::PowerInsufficient => 52,
            Self::BootFailed => 53,
            Self::ResourceExhausted => 54,
        }
    }
}
