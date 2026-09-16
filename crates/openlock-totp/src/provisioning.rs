//! Host-side preparation of credentials for a trusted LOCAL provisioning path.
//! This crate does not send secrets or management commands over BLE/NFC.

use crate::core::{Credential, UsageState};
use crate::crypto::TotpSecret;
use crate::types::{CredentialId, Error, LockId, Validity};

pub struct IssueRequest {
    pub credential_id: CredentialId,
    /// Fresh 32-byte CSPRNG output, unique per lock and credential. Callers own
    /// key generation and secure delivery to the lock and authorized client.
    pub secret: TotpSecret,
    pub validity: Option<Validity>,
    pub max_uses: Option<u32>,
}

pub struct Issuer {
    lock_id: LockId,
}
impl Issuer {
    pub fn new(lock_id: LockId) -> Self {
        Self { lock_id }
    }
    /// Only install as a new credential. Replacing an existing key with the
    /// same secret and default usage would re-enable already consumed OTPs.
    pub fn issue(&self, request: IssueRequest) -> Result<Credential, Error> {
        let credential = Credential {
            lock_id: self.lock_id,
            id: request.credential_id,
            secret: request.secret,
            enabled: true,
            validity: request.validity,
            max_uses: request.max_uses,
            usage: UsageState::default(),
        };
        credential.validate()?;
        Ok(credential)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn provisioning_rejects_invalid_constraints() {
        let issuer = Issuer::new(LockId([1; 16]));
        for (id, max, validity, valid) in [
            (1, None, None, true),
            (0, None, None, false),
            (1, Some(0), None, false),
            (
                1,
                Some(2),
                Some(Validity {
                    not_before: 10,
                    not_after: 10,
                }),
                false,
            ),
            (
                1,
                Some(2),
                Some(Validity {
                    not_before: 10,
                    not_after: 20,
                }),
                true,
            ),
        ] {
            assert_eq!(
                issuer
                    .issue(IssueRequest {
                        credential_id: CredentialId(id),
                        secret: TotpSecret::new([1; 32]),
                        validity,
                        max_uses: max,
                    })
                    .is_ok(),
                valid
            );
        }
    }
}
