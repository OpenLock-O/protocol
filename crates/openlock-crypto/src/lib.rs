//! Cryptographic operations and explicit trust lifecycle, independent of I/O.
pub mod cbor;
pub mod cose;
pub mod noise;
pub mod trust;
pub use cose::*;
pub use ed25519_dalek::{SigningKey, VerifyingKey};
pub use noise::*;
use openlock_types::CredentialId;
use sha2::{Digest, Sha256};
pub use trust::*;

pub fn credential_id(bytes: &[u8]) -> CredentialId {
    let hash = Sha256::digest(bytes);
    CredentialId(hash[..16].try_into().expect("fixed hash length"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use openlock_types::{Grant, LockId, SubjectKey, RIGHTS_UNLOCK};

    #[test]
    fn grant_round_trip_rejects_tampering() {
        let issuer = SigningKey::from_bytes(&[9; 32]);
        let grant = Grant {
            credential_id: credential_id(b"phone"),
            lock_id: LockId([2; 16]),
            subject_key: SubjectKey([3; 32]),
            rights: RIGHTS_UNLOCK,
            epoch: 4,
            validity: None,
            max_uses: Some(1),
        };
        let mut encoded = sign_grant(&issuer, &grant).unwrap();
        assert_eq!(
            read_grant(&issuer.verifying_key(), &encoded).unwrap(),
            grant
        );
        *encoded.last_mut().unwrap() ^= 1;
        assert_eq!(
            read_grant(&issuer.verifying_key(), &encoded),
            Err(openlock_types::Error::BadSignature)
        );
    }
}
