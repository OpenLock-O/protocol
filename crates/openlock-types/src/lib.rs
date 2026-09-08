//! Shared domain values. No transport, cryptography or platform dependencies.
use std::collections::BTreeSet;
use thiserror::Error;

pub const PROTOCOL_VERSION: u64 = 2;
pub const MAX_OBJECT_SIZE: usize = 4096;
pub const MAX_MESSAGE_SIZE: usize = 4096;
pub const RIGHTS_UNLOCK: u32 = 1;
pub const RIGHTS_STATUS: u32 = 2;
pub const CAP_UNLOCK: u64 = 1;
pub const CAP_STATUS: u64 = 2;
pub const CAP_POLICY: u64 = 4;
pub const KNOWN_CAPABILITIES: u64 = CAP_UNLOCK | CAP_STATUS | CAP_POLICY;

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
pub struct AccessRequest {
    pub credential: Vec<u8>,
    pub requested_use: Option<u32>,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Command {
    Unlock(AccessRequest),
    Status(AccessRequest),
    ApplyPolicy(Vec<u8>),
}
impl Command {
    pub fn capability(&self) -> u64 {
        match self {
            Self::Unlock(_) => CAP_UNLOCK,
            Self::Status(_) => CAP_STATUS,
            Self::ApplyPolicy(_) => CAP_POLICY,
        }
    }
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Response {
    Unlocked,
    Status { epoch: u64, policy_version: u64 },
    PolicyApplied,
    AlreadyConsumed { next_use: u32 },
    Rejected { code: u32 },
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
        }
    }
}
