//! v2 authorization domain. Transport and cryptographic primitives live in
//! `openlock-protocol`, `openlock-transport-*`, and `openlock-crypto`.
use ed25519_dalek::VerifyingKey;
use openlock_crypto::{read_grant, read_policy};
use std::collections::{BTreeMap, BTreeSet};
use thiserror::Error;

pub use openlock_crypto::{verify_grant, verify_policy};
pub use openlock_types::{
    AccessRequest, Authorization, ClockSample, Command, CredentialId, Decision, DeviceKey,
    DeviceKeyRecord, Error, Grant, KeyUpdate, LockId, PolicyUpdate, Response, SubjectKey, Validity,
    PROTOCOL_VERSION, RIGHTS_STATUS, RIGHTS_UNLOCK,
};

pub trait PersistentState {
    fn commit(&mut self, state: &LockSnapshot) -> Result<(), Error>;
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LockSnapshot {
    pub epoch: u64,
    pub policy_version: u64,
    pub revoked: BTreeSet<CredentialId>,
    pub usage: BTreeMap<CredentialId, u32>,
}
pub struct LockState<S> {
    pub lock_id: LockId,
    pub issuer: VerifyingKey,
    pub snapshot: LockSnapshot,
    storage: S,
}
impl<S: PersistentState> LockState<S> {
    pub fn new(lock_id: LockId, issuer: VerifyingKey, storage: S) -> Self {
        Self {
            lock_id,
            issuer,
            snapshot: LockSnapshot {
                epoch: 0,
                policy_version: 0,
                revoked: BTreeSet::new(),
                usage: BTreeMap::new(),
            },
            storage,
        }
    }
    pub fn apply_policy(&mut self, update: &PolicyUpdate, signature: &[u8]) -> Result<(), Error> {
        if update.lock_id != self.lock_id
            || update.epoch < self.snapshot.epoch
            || (update.epoch == self.snapshot.epoch
                && update.version <= self.snapshot.policy_version)
        {
            return Err(Error::StalePolicy);
        }
        verify_policy(&self.issuer, update, signature)?;
        let mut next = self.snapshot.clone();
        if update.epoch > next.epoch {
            next.epoch = update.epoch;
            next.policy_version = 0;
            next.revoked.clear();
            next.usage.clear();
        }
        next.policy_version = update.version;
        next.revoked.extend(update.revoked.iter().copied());
        self.storage.commit(&next)?;
        self.snapshot = next;
        Ok(())
    }
    pub fn authorize(
        &self,
        grant: &Grant,
        signature: &[u8],
        subject_key: SubjectKey,
        now: Option<ClockSample>,
        requested_use: Option<u32>,
    ) -> Result<Decision, Error> {
        self.authorize_with_rights(
            grant,
            signature,
            subject_key,
            now,
            requested_use,
            RIGHTS_UNLOCK,
        )
    }
    pub fn authorize_with_rights(
        &self,
        grant: &Grant,
        signature: &[u8],
        subject_key: SubjectKey,
        now: Option<ClockSample>,
        requested_use: Option<u32>,
        required_rights: u32,
    ) -> Result<Decision, Error> {
        if grant.lock_id != self.lock_id {
            return Err(Error::WrongLock);
        }
        if grant.epoch != self.snapshot.epoch {
            return Err(Error::StaleEpoch);
        }
        verify_grant(&self.issuer, grant, signature)?;
        if grant.subject_key != subject_key {
            return Err(Error::BadSignature);
        }
        if grant.rights & required_rights != required_rights {
            return Err(Error::MissingRight);
        }
        if self.snapshot.revoked.contains(&grant.credential_id) {
            return Err(Error::Revoked);
        }
        if let Some(validity) = grant.validity {
            let clock = now.ok_or(Error::ClockUntrusted)?.validate()?;
            if clock.lower < validity.not_before || clock.upper >= validity.not_after {
                return Err(Error::Expired);
            }
        }
        let used = self
            .snapshot
            .usage
            .get(&grant.credential_id)
            .copied()
            .unwrap_or(0);
        if let Some(max) = grant.max_uses {
            if used >= max {
                return Err(Error::UsageExhausted);
            }
            let sequence = requested_use.ok_or(Error::InvalidConsumption)?;
            if sequence < used {
                return Ok(Decision::AlreadyConsumed { next_use: used });
            }
            if sequence != used {
                return Err(Error::InvalidConsumption);
            }
            return Ok(Decision::Authorized(Authorization::Counted { used, max }));
        }
        Ok(Decision::Authorized(if grant.validity.is_some() {
            Authorization::Timed
        } else {
            Authorization::LongLived
        }))
    }
    pub fn consume(&mut self, grant: &Grant, decision: Decision) -> Result<(), Error> {
        if let Decision::Authorized(Authorization::Counted { used, max }) = decision {
            let mut next = self.snapshot.clone();
            if next.usage.get(&grant.credential_id).copied().unwrap_or(0) != used {
                return Err(Error::InvalidConsumption);
            }
            if used >= max {
                return Err(Error::UsageExhausted);
            }
            next.usage.insert(grant.credential_id, used + 1);
            self.storage.commit(&next)?;
            self.snapshot = next;
        }
        Ok(())
    }
    pub fn storage(&self) -> &S {
        &self.storage
    }
}
pub fn sign_grant(key: &ed25519_dalek::SigningKey, grant: &Grant) -> Result<Vec<u8>, Error> {
    openlock_crypto::sign_grant(key, grant)
}
pub fn sign_policy(
    key: &ed25519_dalek::SigningKey,
    policy: &PolicyUpdate,
) -> Result<Vec<u8>, Error> {
    openlock_crypto::sign_policy(key, policy)
}
pub fn credential_id(bytes: &[u8]) -> CredentialId {
    openlock_crypto::credential_id(bytes)
}
pub fn parse_grant(key: &VerifyingKey, bytes: &[u8]) -> Result<Grant, Error> {
    read_grant(key, bytes)
}
pub fn parse_policy(key: &VerifyingKey, bytes: &[u8]) -> Result<PolicyUpdate, Error> {
    read_policy(key, bytes)
}

#[derive(Debug, Error)]
pub enum ActuationError {
    #[error("actuator callback failed")]
    Failed,
}
pub fn authorize_and_consume<S: PersistentState>(
    lock: &mut LockState<S>,
    grant: &Grant,
    signature: &[u8],
    peer: SubjectKey,
    now: Option<ClockSample>,
    use_number: Option<u32>,
    actuator: impl FnOnce() -> Result<(), ActuationError>,
) -> Result<(), Error> {
    let decision = lock.authorize(grant, signature, peer, now, use_number)?;
    lock.consume(grant, decision)?;
    actuator().map_err(|_| Error::ActuatorFailed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    #[derive(Default)]
    struct Store {
        commits: Vec<LockSnapshot>,
    }
    impl PersistentState for Store {
        fn commit(&mut self, s: &LockSnapshot) -> Result<(), Error> {
            self.commits.push(s.clone());
            Ok(())
        }
    }
    fn fixture() -> (SigningKey, Grant) {
        (
            SigningKey::from_bytes(&[7; 32]),
            Grant {
                credential_id: CredentialId([1; 16]),
                lock_id: LockId([2; 16]),
                subject_key: SubjectKey([3; 32]),
                rights: RIGHTS_UNLOCK,
                epoch: 0,
                validity: None,
                max_uses: Some(2),
            },
        )
    }
    #[test]
    fn signed_counted_grant_is_consumed_once() {
        let (key, grant) = fixture();
        let sig = sign_grant(&key, &grant).unwrap();
        let mut lock = LockState::new(grant.lock_id, key.verifying_key(), Store::default());
        let d = lock
            .authorize(&grant, &sig, grant.subject_key, None, Some(0))
            .unwrap();
        lock.consume(&grant, d).unwrap();
        assert_eq!(
            lock.authorize(&grant, &sig, grant.subject_key, None, Some(0))
                .unwrap(),
            Decision::AlreadyConsumed { next_use: 1 }
        );
    }
    #[test]
    fn tampering_fails() {
        let (key, grant) = fixture();
        let mut sig = sign_grant(&key, &grant).unwrap();
        *sig.last_mut().unwrap() ^= 1;
        let lock = LockState::new(grant.lock_id, key.verifying_key(), Store::default());
        assert_eq!(
            lock.authorize(&grant, &sig, grant.subject_key, None, Some(0)),
            Err(Error::BadSignature)
        );
    }
}
