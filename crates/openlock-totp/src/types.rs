//! Fixed-size values for OpenLock plaintext TOTP authentication.

use thiserror::Error;

pub const PROTOCOL_VERSION: u8 = 3;
pub const PROFILE: u8 = 1;
pub const MAX_MESSAGE_SIZE: usize = 20;
pub const TOTP_PERIOD: u64 = 30;
pub const TOTP_DIGITS: u32 = 8;
pub const TOTP_MODULUS: u32 = 100_000_000;
pub const TOTP_SECRET_SIZE: usize = 32;
pub const ALLOWED_CLOCK_SKEW_STEPS: u64 = 1;
/// Lock-wide, including unknown credential IDs; never reset on reconnect.
pub const MAX_ATTEMPTS_PER_STEP: u8 = 5;

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct LockId(pub [u8; 16]);
/// A nonzero, locally provisioned identifier, unique within a lock.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct CredentialId(pub u32);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Validity {
    pub not_before: u64,
    /// Exclusive end, in Unix seconds.
    pub not_after: u64,
}
impl Validity {
    pub fn validate(self) -> Result<(), Error> {
        if self.not_before >= self.not_after {
            Err(Error::InvalidPayload)
        } else {
            Ok(())
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UnlockRequest {
    pub credential_id: CredentialId,
    pub time_step: u64,
    /// Numeric encoding of an eight-digit OTP, including leading zeroes.
    pub code: u32,
}
impl UnlockRequest {
    pub fn validate(self) -> Result<(), Error> {
        if self.credential_id.0 == 0 || self.code >= TOTP_MODULUS {
            Err(Error::InvalidPayload)
        } else {
            Ok(())
        }
    }
}

/// Informational only: plaintext responses do not authenticate the lock.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UnlockResponse {
    pub credential_id: CredentialId,
    pub time_step: u64,
    pub result: Result<(), Error>,
}
impl UnlockResponse {
    pub fn for_request(request: &UnlockRequest, result: Result<(), Error>) -> Self {
        Self {
            credential_id: request.credential_id,
            time_step: request.time_step,
            result,
        }
    }
}

#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum Error {
    #[error("object is too large")]
    ObjectTooLarge,
    #[error("invalid payload")]
    InvalidPayload,
    #[error("wrong lock")]
    WrongLock,
    #[error("credential is disabled")]
    Revoked,
    #[error("credential is outside its validity window")]
    Expired,
    #[error("clock is missing, untrusted or has moved backwards")]
    ClockUntrusted,
    #[error("credential usage exhausted")]
    UsageExhausted,
    #[error("persistent storage failed or contains invalid state")]
    StorageUnavailable,
    #[error("unsupported protocol version or profile")]
    UnsupportedVersion,
    #[error("actuation failed; the OTP remains consumed")]
    ActuatorFailed,
    #[error("invalid NFC record")]
    InvalidNfc,
    #[error("invalid TOTP or time step outside the allowed window")]
    InvalidTotp,
    #[error("TOTP time step has already been consumed or superseded")]
    Replayed,
    #[error("too many attempts in this time step")]
    RateLimited,
    #[error("unknown credential")]
    UnknownCredential,
}
impl Error {
    /// Stable, positive TOTP wire/FFI error codes; unassigned codes are reserved.
    pub const fn code(self) -> u32 {
        match self {
            Self::ObjectTooLarge => 1,
            Self::InvalidPayload => 3,
            Self::WrongLock => 5,
            Self::Revoked => 6,
            Self::Expired => 8,
            Self::ClockUntrusted => 9,
            Self::UsageExhausted => 10,
            Self::StorageUnavailable => 12,
            Self::UnsupportedVersion => 16,
            Self::ActuatorFailed => 21,
            Self::InvalidNfc => 22,
            Self::InvalidTotp => 23,
            Self::Replayed => 24,
            Self::RateLimited => 25,
            Self::UnknownCredential => 26,
        }
    }
    pub const fn from_code(code: u32) -> Option<Self> {
        Some(match code {
            1 => Self::ObjectTooLarge,
            3 => Self::InvalidPayload,
            5 => Self::WrongLock,
            6 => Self::Revoked,
            8 => Self::Expired,
            9 => Self::ClockUntrusted,
            10 => Self::UsageExhausted,
            12 => Self::StorageUnavailable,
            16 => Self::UnsupportedVersion,
            21 => Self::ActuatorFailed,
            22 => Self::InvalidNfc,
            23 => Self::InvalidTotp,
            24 => Self::Replayed,
            25 => Self::RateLimited,
            26 => Self::UnknownCredential,
            _ => return None,
        })
    }
}
