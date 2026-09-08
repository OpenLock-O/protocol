//! Offline administrator-side credential issuing helpers.

use ed25519_dalek::SigningKey;
use openlock_core::{
    sign_grant, sign_policy, CredentialId, Grant, LockId, PolicyUpdate, SubjectKey,
};
use openlock_crypto::{sign_device_key, sign_key_update};
use openlock_types::{DeviceKey, DeviceKeyRecord, KeyUpdate};
use std::collections::BTreeSet;

pub struct Issuer {
    key: SigningKey,
}

pub struct IssueRequest {
    pub credential_id: CredentialId,
    pub lock_id: LockId,
    pub subject_key: SubjectKey,
    pub rights: u32,
    pub epoch: u64,
    pub validity: Option<(u64, u64)>,
    pub max_uses: Option<u32>,
}

impl Issuer {
    pub fn from_signing_key(key: SigningKey) -> Self {
        Self { key }
    }

    pub fn verifying_key(&self) -> [u8; 32] {
        self.key.verifying_key().to_bytes()
    }

    pub fn issue(&self, request: &IssueRequest) -> Result<(Grant, Vec<u8>), openlock_core::Error> {
        let grant = Grant {
            credential_id: request.credential_id,
            lock_id: request.lock_id,
            subject_key: request.subject_key,
            rights: request.rights,
            epoch: request.epoch,
            validity: request
                .validity
                .map(|(not_before, not_after)| openlock_core::Validity {
                    not_before,
                    not_after,
                }),
            max_uses: request.max_uses,
        };
        Ok((grant.clone(), sign_grant(&self.key, &grant)?))
    }

    pub fn revoke(
        &self,
        lock_id: LockId,
        epoch: u64,
        version: u64,
        revoked: BTreeSet<CredentialId>,
    ) -> Result<(PolicyUpdate, Vec<u8>), openlock_core::Error> {
        let update = PolicyUpdate {
            lock_id,
            epoch,
            version,
            revoked,
        };
        Ok((update.clone(), sign_policy(&self.key, &update)?))
    }

    pub fn issue_device_key(
        &self,
        key: DeviceKey,
        issuer_key_id: u32,
    ) -> Result<DeviceKeyRecord, openlock_core::Error> {
        sign_device_key(&self.key, &key, issuer_key_id)
    }

    pub fn rotate_device_key(&self, update: KeyUpdate) -> Result<KeyUpdate, openlock_core::Error> {
        sign_key_update(&self.key, update)
    }
}
