//! RFC 6238 TOTP: HMAC-SHA-256, 30 seconds, eight digits, no heap or RNG.

use crate::types::{
    CredentialId, Error, UnlockRequest, TOTP_MODULUS, TOTP_PERIOD, TOTP_SECRET_SIZE,
};
use core::fmt;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

/// Provision a unique random key for each (lock, credential). Never transmit it
/// on the plaintext access channel. Debug output deliberately redacts the key.
#[derive(Clone)]
pub struct TotpSecret([u8; TOTP_SECRET_SIZE]);
impl TotpSecret {
    pub const fn new(bytes: [u8; TOTP_SECRET_SIZE]) -> Self {
        Self(bytes)
    }
    pub fn as_bytes(&self) -> &[u8; TOTP_SECRET_SIZE] {
        &self.0
    }
}
impl fmt::Debug for TotpSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("TotpSecret([REDACTED])")
    }
}
impl Drop for TotpSecret {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

pub const fn time_step(unix_seconds: u64) -> u64 {
    unix_seconds / TOTP_PERIOD
}

/// RFC 4226 dynamic truncation with the SHA-256 option from RFC 6238.
/// This primitive alone does not enforce freshness, one-time use or throttling.
pub fn totp_at_step(secret: &TotpSecret, step: u64) -> u32 {
    let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes()).expect("HMAC accepts this key");
    mac.update(&step.to_be_bytes());
    let digest = mac.finalize().into_bytes();
    let offset = (digest[digest.len() - 1] & 0x0f) as usize;
    let binary = u32::from_be_bytes(digest[offset..offset + 4].try_into().expect("four bytes"));
    (binary & 0x7fff_ffff) % TOTP_MODULUS
}

pub fn totp(secret: &TotpSecret, unix_seconds: u64) -> u32 {
    totp_at_step(secret, time_step(unix_seconds))
}

/// Constant-time comparison of a numeric OTP. Use `crate::core::LockState`
/// for access authorization; this function is only a cryptographic primitive.
pub fn verify_totp_at_step(secret: &TotpSecret, step: u64, code: u32) -> bool {
    code < TOTP_MODULUS && bool::from(totp_at_step(secret, step).ct_eq(&code))
}

pub fn unlock_request(
    secret: &TotpSecret,
    credential_id: CredentialId,
    unix_seconds: u64,
) -> Result<UnlockRequest, Error> {
    let request = UnlockRequest {
        credential_id,
        time_step: time_step(unix_seconds),
        code: totp(secret, unix_seconds),
    };
    request.validate()?;
    Ok(request)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc6238_sha256_vectors() {
        // RFC 6238 Appendix B, including dates beyond 2038.
        let key = TotpSecret::new(*b"12345678901234567890123456789012");
        for (timestamp, expected) in [
            (59, 46_119_246),
            (1_111_111_109, 68_084_774),
            (1_111_111_111, 67_062_674),
            (1_234_567_890, 91_819_424),
            (2_000_000_000, 90_698_825),
            (20_000_000_000, 77_737_706),
        ] {
            assert_eq!(totp(&key, timestamp), expected);
            assert!(verify_totp_at_step(&key, time_step(timestamp), expected));
            assert!(!verify_totp_at_step(
                &key,
                time_step(timestamp),
                expected ^ 1
            ));
        }
    }

    #[test]
    fn same_step_has_the_same_code_and_boundaries_change_step() {
        let key = TotpSecret::new([7; 32]);
        assert_eq!(totp(&key, 30), totp(&key, 59));
        assert_eq!(time_step(29), 0);
        assert_eq!(time_step(30), 1);
        assert_eq!(time_step(u64::MAX), u64::MAX / 30);
        assert!(!verify_totp_at_step(&key, 0, TOTP_MODULUS));
        assert!(unlock_request(&key, CredentialId(0), 30).is_err());
    }
}
