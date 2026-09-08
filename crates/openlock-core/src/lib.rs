//! OpenLock's transport-independent authorization core.
//!
//! The wire objects use a deliberately small COSE_Sign1 profile.  The signed
//! payload is a canonical CBOR array and the protected header contains EdDSA.

use ciborium::value::{Integer, Value};
use ciborium::{de::from_reader, ser::into_writer};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::io::Cursor;
use thiserror::Error;

pub const PROTOCOL_VERSION: u64 = 1;
pub const MAX_OBJECT_SIZE: usize = 4096;
pub const RIGHTS_UNLOCK: u32 = 1;
pub const RIGHTS_STATUS: u32 = 2;

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

#[derive(Debug, Error, Eq, PartialEq)]
pub enum Error {
    #[error("object is too large")]
    ObjectTooLarge,
    #[error("invalid COSE object")]
    InvalidCose,
    #[error("invalid signed payload")]
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
    #[error("Noise handshake failed")]
    Noise,
}

/// Perform the two-message Noise IK handshake used after GATT connection.
/// The returned transport states must be kept by their respective endpoints.
pub fn noise_ik_handshake(
    initiator_static: &[u8; 32],
    responder_static: &[u8; 32],
) -> Result<(snow::TransportState, snow::TransportState), Error> {
    if *initiator_static == [0; 32] || *responder_static == [0; 32] {
        return Err(Error::Noise);
    }
    let params: snow::params::NoiseParams = "Noise_IK_25519_ChaChaPoly_SHA256"
        .parse()
        .map_err(|_| Error::Noise)?;
    let responder_public_key = responder_public(responder_static);
    let initiator_builder = snow::Builder::new(params.clone());
    let initiator_builder = initiator_builder
        .local_private_key(initiator_static)
        .map_err(|_| Error::Noise)?;
    let mut initiator = initiator_builder
        .remote_public_key(&responder_public_key)
        .map_err(|_| Error::Noise)?
        .build_initiator()
        .map_err(|_| Error::Noise)?;
    let responder_builder = snow::Builder::new(params);
    let responder_builder = responder_builder
        .local_private_key(responder_static)
        .map_err(|_| Error::Noise)?;
    let mut responder = responder_builder
        .build_responder()
        .map_err(|_| Error::Noise)?;
    let mut first = [0u8; 256];
    let mut second = [0u8; 256];
    let first_len = initiator
        .write_message(&[], &mut first)
        .map_err(|_| Error::Noise)?;
    responder
        .read_message(&first[..first_len], &mut second)
        .map_err(|_| Error::Noise)?;
    let second_len = responder
        .write_message(&[], &mut second)
        .map_err(|_| Error::Noise)?;
    initiator
        .read_message(&second[..second_len], &mut first)
        .map_err(|_| Error::Noise)?;
    Ok((
        initiator.into_transport_mode().map_err(|_| Error::Noise)?,
        responder.into_transport_mode().map_err(|_| Error::Noise)?,
    ))
}

/// Return the authenticated static public key learned during the handshake.
/// The lock compares this value with `Grant::subject_key` before authorization.
pub fn noise_peer_static(state: &snow::TransportState) -> Option<SubjectKey> {
    let key = state.get_remote_static()?;
    let key: [u8; 32] = key.try_into().ok()?;
    Some(SubjectKey(key))
}

fn responder_public(private_key: &[u8; 32]) -> [u8; 32] {
    use x25519_dalek::{PublicKey, StaticSecret};
    PublicKey::from(&StaticSecret::from(*private_key)).to_bytes()
}

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
            let clock = now.ok_or(Error::ClockUntrusted)?;
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

    /// Persist a counted authorization immediately before invoking the actuator.
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

pub fn credential_id(bytes: &[u8]) -> CredentialId {
    let digest = Sha256::digest(bytes);
    let mut id = [0u8; 16];
    id.copy_from_slice(&digest[..16]);
    CredentialId(id)
}

pub fn sign_grant(key: &SigningKey, grant: &Grant) -> Result<Vec<u8>, Error> {
    sign_object(key, b"grant", &grant_value(grant))
}

pub fn verify_grant(key: &VerifyingKey, grant: &Grant, cose: &[u8]) -> Result<(), Error> {
    verify_object(key, b"grant", &grant_value(grant), cose)
}

pub fn sign_policy(key: &SigningKey, policy: &PolicyUpdate) -> Result<Vec<u8>, Error> {
    sign_object(key, b"policy", &policy_value(policy))
}

pub fn verify_policy(key: &VerifyingKey, policy: &PolicyUpdate, cose: &[u8]) -> Result<(), Error> {
    verify_object(key, b"policy", &policy_value(policy), cose)
}

fn sign_object(key: &SigningKey, kind: &[u8], payload: &Value) -> Result<Vec<u8>, Error> {
    let payload_bytes = encode(payload)?;
    let protected = protected_header()?;
    let sig_structure = sig_structure(kind, &protected, &payload_bytes)?;
    let signature = key.sign(&sig_structure);
    encode(&Value::Array(vec![
        Value::Bytes(protected),
        Value::Map(Vec::new()),
        Value::Bytes(payload_bytes),
        Value::Bytes(signature.to_bytes().to_vec()),
    ]))
}

fn protected_header() -> Result<Vec<u8>, Error> {
    encode(&Value::Map(vec![(
        Value::Integer(Integer::from(1)),
        Value::Integer(Integer::from(-8)),
    )]))
}

fn verify_object(
    key: &VerifyingKey,
    kind: &[u8],
    payload: &Value,
    cose: &[u8],
) -> Result<(), Error> {
    if cose.len() > MAX_OBJECT_SIZE {
        return Err(Error::ObjectTooLarge);
    }
    let Value::Array(items) = from_reader(Cursor::new(cose)).map_err(|_| Error::InvalidCose)?
    else {
        return Err(Error::InvalidCose);
    };
    if items.len() != 4 {
        return Err(Error::InvalidCose);
    }
    let (
        Value::Bytes(protected),
        Value::Map(unprotected),
        Value::Bytes(encoded_payload),
        Value::Bytes(raw_sig),
    ) = (&items[0], &items[1], &items[2], &items[3])
    else {
        return Err(Error::InvalidCose);
    };
    if !unprotected.is_empty() || raw_sig.len() != 64 || protected != &protected_header()? {
        return Err(Error::InvalidCose);
    }
    let decoded: Value =
        from_reader(Cursor::new(encoded_payload)).map_err(|_| Error::InvalidPayload)?;
    if &decoded != payload {
        return Err(Error::InvalidPayload);
    }
    let sig_structure = sig_structure(kind, protected, encoded_payload)?;
    key.verify(
        &sig_structure,
        &Signature::from_slice(raw_sig).map_err(|_| Error::InvalidCose)?,
    )
    .map_err(|_| Error::BadSignature)
}

fn sig_structure(kind: &[u8], protected: &[u8], payload: &[u8]) -> Result<Vec<u8>, Error> {
    encode(&Value::Array(vec![
        Value::Text("Signature1".into()),
        Value::Bytes(protected.to_vec()),
        Value::Bytes(kind.to_vec()),
        Value::Bytes(payload.to_vec()),
    ]))
}

fn encode(value: &Value) -> Result<Vec<u8>, Error> {
    let mut out = Vec::new();
    into_writer(value, &mut out).map_err(|_| Error::InvalidPayload)?;
    if out.len() > MAX_OBJECT_SIZE {
        return Err(Error::ObjectTooLarge);
    }
    Ok(out)
}

fn bytes(bytes: &[u8]) -> Value {
    Value::Bytes(bytes.to_vec())
}

fn uint(value: u64) -> Value {
    Value::Integer(Integer::from(value))
}

fn grant_value(grant: &Grant) -> Value {
    Value::Array(vec![
        uint(PROTOCOL_VERSION),
        Value::Text("grant".into()),
        bytes(&grant.credential_id.0),
        bytes(&grant.lock_id.0),
        bytes(&grant.subject_key.0),
        uint(grant.rights as u64),
        uint(grant.epoch),
        match grant.validity {
            Some(v) => Value::Array(vec![uint(v.not_before), uint(v.not_after)]),
            None => Value::Null,
        },
        grant.max_uses.map_or(Value::Null, |uses| uint(uses as u64)),
    ])
}

fn policy_value(policy: &PolicyUpdate) -> Value {
    Value::Array(vec![
        uint(PROTOCOL_VERSION),
        Value::Text("policy".into()),
        bytes(&policy.lock_id.0),
        uint(policy.epoch),
        uint(policy.version),
        Value::Array(policy.revoked.iter().map(|id| bytes(&id.0)).collect()),
    ])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Default)]
    struct MemoryStore {
        commits: Vec<LockSnapshot>,
    }

    impl PersistentState for MemoryStore {
        fn commit(&mut self, state: &LockSnapshot) -> Result<(), Error> {
            self.commits.push(state.clone());
            Ok(())
        }
    }

    fn fixture() -> (SigningKey, Grant) {
        let key = SigningKey::from_bytes(&[7u8; 32]);
        let grant = Grant {
            credential_id: CredentialId([1; 16]),
            lock_id: LockId([2; 16]),
            subject_key: SubjectKey([3; 32]),
            rights: RIGHTS_UNLOCK,
            epoch: 0,
            validity: None,
            max_uses: Some(2),
        };
        (key, grant)
    }

    #[test]
    fn cose_round_trip_and_counted_consumption() {
        let (key, grant) = fixture();
        let cose = sign_grant(&key, &grant).unwrap();
        let mut lock = LockState::new(grant.lock_id, key.verifying_key(), MemoryStore::default());
        let decision = lock
            .authorize(&grant, &cose, grant.subject_key, None, Some(0))
            .unwrap();
        assert_eq!(
            decision,
            Decision::Authorized(Authorization::Counted { used: 0, max: 2 })
        );
        lock.consume(&grant, decision).unwrap();
        assert_eq!(lock.snapshot.usage[&grant.credential_id], 1);
        assert_eq!(
            lock.authorize(&grant, &cose, grant.subject_key, None, Some(0))
                .unwrap(),
            Decision::AlreadyConsumed { next_use: 1 }
        );
    }

    #[test]
    fn tampering_and_wrong_subject_fail() {
        let (key, grant) = fixture();
        let mut cose = sign_grant(&key, &grant).unwrap();
        *cose.last_mut().unwrap() ^= 1;
        let lock = LockState::new(grant.lock_id, key.verifying_key(), MemoryStore::default());
        assert_eq!(
            lock.authorize(&grant, &cose, grant.subject_key, None, Some(0)),
            Err(Error::BadSignature)
        );
        let cose = sign_grant(&key, &grant).unwrap();
        assert_eq!(
            lock.authorize(&grant, &cose, SubjectKey([4; 32]), None, Some(0)),
            Err(Error::BadSignature)
        );
    }

    #[test]
    fn noise_ik_establishes_transport() {
        let (mut initiator, mut responder) = noise_ik_handshake(&[3; 32], &[4; 32]).unwrap();
        assert_eq!(
            noise_peer_static(&responder),
            Some(SubjectKey(responder_public(&[3; 32])))
        );
        let mut encrypted = [0u8; 64];
        let len = initiator.write_message(b"unlock", &mut encrypted).unwrap();
        let mut plaintext = [0u8; 64];
        let decoded = responder
            .read_message(&encrypted[..len], &mut plaintext)
            .unwrap();
        assert_eq!(&plaintext[..decoded], b"unlock");
    }
}
