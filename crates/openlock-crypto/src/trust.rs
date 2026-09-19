use crate::cbor::*;
use crate::cose::{sign_object, verify_object};
use crate::validate_public;
use crate::VerifyingKey;
use alloc::{collections::BTreeMap, vec, vec::Vec};
use ed25519_dalek::SigningKey;
use openlock_types::{
    ClockSample, DeviceKey, DeviceKeyRecord, Error, KeyUpdate, LockId, KNOWN_CAPABILITIES,
};

const DEVICE: &[u8] = b"openlock:v2:device-key";
const UPDATE: &[u8] = b"openlock:v2:key-update";

pub fn device_key_value(key: &DeviceKey, issuer_key_id: u32) -> Value {
    array(vec![
        uint(2),
        bytes(&key.device_id.0),
        uint(key.key_id as u64),
        uint(key.key_version as u64),
        bytes(&key.x25519_public_key),
        bytes(&key.rotation_public_key),
        uint(key.capabilities),
        uint(issuer_key_id as u64),
    ])
}
pub fn sign_device_key(
    issuer: &SigningKey,
    key: &DeviceKey,
    issuer_key_id: u32,
) -> Result<DeviceKeyRecord, Error> {
    validate_device_key(key)?;
    Ok(DeviceKeyRecord {
        key: key.clone(),
        issuer_key_id,
        signature: sign_object(issuer, DEVICE, &device_key_value(key, issuer_key_id))?,
    })
}
pub fn verify_device_key(issuer: &VerifyingKey, record: &DeviceKeyRecord) -> Result<(), Error> {
    validate_device_key(&record.key)?;
    let value = verify_object(issuer, DEVICE, &record.signature)?;
    let f = fields(&value, 8)?;
    if number(&f[0])? != 2
        || fixed::<16>(&f[1])? != record.key.device_id.0
        || u32_value(&f[2])? != record.key.key_id
        || u32_value(&f[3])? != record.key.key_version
        || fixed::<32>(&f[4])? != record.key.x25519_public_key
        || fixed::<32>(&f[5])? != record.key.rotation_public_key
        || number(&f[6])? != record.key.capabilities
        || u32_value(&f[7])? != record.issuer_key_id
    {
        return Err(Error::InvalidPayload);
    }
    Ok(())
}

/// Validate device-key invariants independent of the issuer signature.
pub fn validate_device_key(key: &DeviceKey) -> Result<(), Error> {
    if key.key_version == 0
        || key.x25519_public_key == [0; 32]
        || key.rotation_public_key == [0; 32]
        || key.capabilities == 0
        || key.capabilities & !KNOWN_CAPABILITIES != 0
    {
        return Err(Error::InvalidPayload);
    }
    validate_public(&key.x25519_public_key).map_err(|_| Error::UntrustedKey)?;
    VerifyingKey::from_bytes(&key.rotation_public_key).map_err(|_| Error::UntrustedKey)?;
    Ok(())
}
pub fn key_update_value(update: &KeyUpdate) -> Value {
    array(vec![
        uint(2),
        uint(update.old_key_id as u64),
        device_key_value(&update.new_record.key, update.new_record.issuer_key_id),
        uint(update.not_before),
        uint(update.retire_after),
        update
            .issuer_key_id
            .map_or(Value::Null, |id| uint(id as u64)),
    ])
}
pub fn sign_key_update(issuer: &SigningKey, mut update: KeyUpdate) -> Result<KeyUpdate, Error> {
    validate_key_update(&update)?;
    update.signature = sign_object(issuer, UPDATE, &key_update_value(&update))?;
    Ok(update)
}
pub fn sign_key_update_with_key(
    key: &SigningKey,
    mut update: KeyUpdate,
) -> Result<KeyUpdate, Error> {
    validate_key_update(&update)?;
    update.signature = sign_object(key, UPDATE, &key_update_value(&update))?;
    Ok(update)
}

fn validate_key_update(update: &KeyUpdate) -> Result<(), Error> {
    validate_device_key(&update.new_record.key)?;
    if update.not_before >= update.retire_after {
        return Err(Error::InvalidPayload);
    }
    Ok(())
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TrustSnapshot {
    pub devices: BTreeMap<LockId, DeviceKeyRecord>,
}
pub trait TrustStorage {
    /// Persist atomically. An error may still have written the snapshot and
    /// makes the TrustStore unusable until restored from authoritative storage.
    fn commit(&mut self, snapshot: &TrustSnapshot) -> Result<(), Error>;
}
impl TrustStorage for () {
    fn commit(&mut self, _: &TrustSnapshot) -> Result<(), Error> {
        Ok(())
    }
}

pub struct TrustStore<S> {
    issuer: VerifyingKey,
    snapshot: TrustSnapshot,
    storage: S,
    poisoned: bool,
}
impl<S: TrustStorage> TrustStore<S> {
    pub fn new(issuer: VerifyingKey, storage: S) -> Self {
        Self {
            issuer,
            snapshot: TrustSnapshot {
                devices: BTreeMap::new(),
            },
            storage,
            poisoned: false,
        }
    }
    /// Restore the complete integrity-checked durable snapshot without replacing
    /// it with an empty store. Unsigned pinned records rely on storage integrity.
    pub fn from_snapshot(
        issuer: VerifyingKey,
        storage: S,
        snapshot: TrustSnapshot,
    ) -> Result<Self, Error> {
        for (id, record) in &snapshot.devices {
            if *id != record.key.device_id {
                return Err(Error::StorageUnavailable);
            }
            validate_device_key(&record.key)?;
            if !record.signature.is_empty() {
                verify_device_key(&issuer, record)?;
            }
        }
        Ok(Self {
            issuer,
            snapshot,
            storage,
            poisoned: false,
        })
    }
    pub fn import(&mut self, record: DeviceKeyRecord) -> Result<(), Error> {
        self.ensure_healthy()?;
        verify_device_key(&self.issuer, &record)?;
        if let Some(old) = self.snapshot.devices.get(&record.key.device_id) {
            if old.key.key_id != record.key.key_id || record.key.key_version <= old.key.key_version
            {
                return Err(Error::StaleKey);
            }
        }
        let mut next = self.snapshot.clone();
        next.devices.insert(record.key.device_id, record);
        self.commit(next)
    }
    pub fn pin(&mut self, key: DeviceKey) -> Result<(), Error> {
        self.ensure_healthy()?;
        validate_device_key(&key)?;
        if let Some(old) = self.snapshot.devices.get(&key.device_id) {
            if old.key.key_id != key.key_id || key.key_version <= old.key.key_version {
                return Err(Error::StaleKey);
            }
        }
        let record = DeviceKeyRecord {
            key,
            issuer_key_id: 0,
            signature: Vec::new(),
        };
        let mut next = self.snapshot.clone();
        next.devices.insert(record.key.device_id, record);
        self.commit(next)
    }
    pub fn apply_update(&mut self, update: &KeyUpdate, now: ClockSample) -> Result<(), Error> {
        self.ensure_healthy()?;
        now.validate()?;
        let old = self
            .snapshot
            .devices
            .get(&update.new_record.key.device_id)
            .ok_or(Error::UntrustedKey)?;
        if old.key.key_id != update.old_key_id
            || update.new_record.key.key_version <= old.key.key_version
            || now.lower < update.not_before
            || now.upper >= update.retire_after
            || update.not_before >= update.retire_after
        {
            return Err(Error::StaleKey);
        }
        verify_device_key(&self.issuer, &update.new_record)?;
        let signer = if update.issuer_key_id.is_some() {
            self.issuer
        } else {
            VerifyingKey::from_bytes(&old.key.rotation_public_key)
                .map_err(|_| Error::UntrustedKey)?
        };
        if verify_object(&signer, UPDATE, &update.signature)? != key_update_value(update) {
            return Err(Error::InvalidPayload);
        }
        let mut next = self.snapshot.clone();
        next.devices
            .insert(update.new_record.key.device_id, update.new_record.clone());
        self.commit(next)
    }
    pub fn get(&self, device: &LockId) -> Option<&DeviceKeyRecord> {
        if self.poisoned {
            return None;
        }
        self.snapshot.devices.get(device)
    }
    pub fn snapshot(&self) -> Result<&TrustSnapshot, Error> {
        self.ensure_healthy()?;
        Ok(&self.snapshot)
    }
    fn ensure_healthy(&self) -> Result<(), Error> {
        if self.poisoned {
            Err(Error::StorageUnavailable)
        } else {
            Ok(())
        }
    }
    fn commit(&mut self, next: TrustSnapshot) -> Result<(), Error> {
        if self.storage.commit(&next).is_err() {
            self.poisoned = true;
            return Err(Error::StorageUnavailable);
        }
        self.snapshot = next;
        Ok(())
    }
}

/// Full transport object: the signed update and the independently signed new record.
pub fn encode_key_update(update: &KeyUpdate) -> Result<Vec<u8>, Error> {
    encode(&array(vec![
        bytes(&update.signature),
        bytes(&update.new_record.signature),
    ]))
}
/// Validate a ready-to-activate device rotation against the current device key.
pub fn read_key_update(
    issuer: &VerifyingKey,
    old: &DeviceKey,
    input: &[u8],
    now: openlock_types::ClockSample,
) -> Result<KeyUpdate, Error> {
    now.validate()?;
    let outer = decode(input)?;
    let parts = fields(&outer, 2)?;
    let signature = data(&parts[0])?.to_vec();
    // Try only the two explicitly configured trust anchors, never a packet-supplied key.
    let rotation =
        VerifyingKey::from_bytes(&old.rotation_public_key).map_err(|_| Error::UntrustedKey)?;
    let (v, root_signed) = match verify_object(issuer, UPDATE, &signature) {
        Ok(v) => (v, true),
        Err(_) => (verify_object(&rotation, UPDATE, &signature)?, false),
    };
    let f = fields(&v, 6)?;
    if number(&f[0])? != 2 {
        return Err(Error::UnsupportedVersion);
    }
    let k = fields(&f[2], 8)?;
    if number(&k[0])? != 2 {
        return Err(Error::UnsupportedVersion);
    }
    let record = DeviceKeyRecord {
        key: DeviceKey {
            device_id: LockId(fixed(&k[1])?),
            key_id: u32_value(&k[2])?,
            key_version: u32_value(&k[3])?,
            x25519_public_key: fixed(&k[4])?,
            rotation_public_key: fixed(&k[5])?,
            capabilities: number(&k[6])?,
        },
        issuer_key_id: u32_value(&k[7])?,
        signature: data(&parts[1])?.to_vec(),
    };
    let update = KeyUpdate {
        old_key_id: u32_value(&f[1])?,
        new_record: record,
        not_before: number(&f[3])?,
        retire_after: number(&f[4])?,
        issuer_key_id: optional_u32(&f[5])?,
        signature,
    };
    if root_signed != update.issuer_key_id.is_some() || key_update_value(&update) != v {
        return Err(Error::InvalidPayload);
    }
    validate_key_update(&update)?;
    verify_device_key(issuer, &update.new_record)?;
    if update.old_key_id != old.key_id
        || update.new_record.key.device_id != old.device_id
        || update.new_record.key.key_version <= old.key_version
        || now.lower < update.not_before
        || now.upper >= update.retire_after
    {
        return Err(Error::StaleKey);
    }
    Ok(update)
}

/// Parse the signed device-key payload, whose version remains 2.
pub fn parse_device_key_value(value: &Value) -> Result<(DeviceKey, u32), Error> {
    let f = fields(value, 8)?;
    if number(&f[0])? != 2 {
        return Err(Error::UnsupportedVersion);
    }
    let key = DeviceKey {
        device_id: LockId(fixed(&f[1])?),
        key_id: u32_value(&f[2])?,
        key_version: u32_value(&f[3])?,
        x25519_public_key: fixed(&f[4])?,
        rotation_public_key: fixed(&f[5])?,
        capabilities: number(&f[6])?,
    };
    validate_device_key(&key)?;
    Ok((key, u32_value(&f[7])?))
}
/// Sign the independently versioned device and key-update payloads for SDKs.
pub fn sign_trust_payload(key: &SigningKey, kind: u32, value: &Value) -> Result<Vec<u8>, Error> {
    match kind {
        3 => {
            let (device, issuer_id) = parse_device_key_value(value)?;
            Ok(sign_device_key(key, &device, issuer_id)?.signature)
        }
        4 => {
            let f = fields(value, 6)?;
            if number(&f[0])? != 2 {
                return Err(Error::UnsupportedVersion);
            }
            u32_value(&f[1])?;
            parse_device_key_value(&f[2])?;
            optional_u32(&f[5])?;
            if number(&f[3])? >= number(&f[4])? {
                return Err(Error::InvalidPayload);
            }
            sign_object(key, UPDATE, value)
        }
        _ => Err(Error::InvalidPayload),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use openlock_types::{DeviceKey, LockId};

    #[test]
    fn signed_record_and_monotonic_rotation() {
        let issuer = SigningKey::from_bytes(&[5; 32]);
        let first = DeviceKey {
            device_id: LockId([1; 16]),
            key_id: 1,
            key_version: 1,
            x25519_public_key: [2; 32],
            rotation_public_key: [3; 32],
            capabilities: 3,
        };
        let second = DeviceKey {
            key_version: 2,
            key_id: 2,
            x25519_public_key: [4; 32],
            rotation_public_key: [6; 32],
            ..first.clone()
        };
        let first_record = sign_device_key(&issuer, &first, 9).unwrap();
        let second_record = sign_device_key(&issuer, &second, 9).unwrap();
        let update = sign_key_update(
            &issuer,
            KeyUpdate {
                old_key_id: 1,
                new_record: second_record,
                not_before: 10,
                retire_after: 20,
                issuer_key_id: Some(9),
                signature: Vec::new(),
            },
        )
        .unwrap();
        let mut store = TrustStore::new(issuer.verifying_key(), ());
        store.import(first_record).unwrap();
        store
            .apply_update(
                &update,
                ClockSample {
                    lower: 10,
                    upper: 10,
                },
            )
            .unwrap();
        assert_eq!(store.get(&LockId([1; 16])).unwrap().key.key_version, 2);
        assert_eq!(store.pin(first), Err(Error::StaleKey));
    }
    #[test]
    fn ambiguous_commits_disable_all_trust_paths_until_durable_restore() {
        use alloc::rc::Rc;
        use core::cell::{Cell, RefCell};
        #[derive(Clone, Default)]
        struct Store {
            state: Rc<RefCell<Option<TrustSnapshot>>>,
            fail: Rc<Cell<bool>>,
            after_write: Rc<Cell<bool>>,
        }
        impl TrustStorage for Store {
            fn commit(&mut self, next: &TrustSnapshot) -> Result<(), Error> {
                if !self.fail.get() || self.after_write.get() {
                    *self.state.borrow_mut() = Some(next.clone());
                }
                if self.fail.get() {
                    Err(Error::StorageUnavailable)
                } else {
                    Ok(())
                }
            }
        }
        let issuer = SigningKey::from_bytes(&[5; 32]);
        let id = LockId([1; 16]);
        let record = |version| {
            sign_device_key(
                &issuer,
                &DeviceKey {
                    device_id: id,
                    key_id: 1,
                    key_version: version,
                    x25519_public_key: crate::static_public(&[version as u8; 32]),
                    rotation_public_key: issuer.verifying_key().to_bytes(),
                    capabilities: 3,
                },
                9,
            )
            .unwrap()
        };
        for after_write in [false, true] {
            for method in 0..3 {
                let access = Store::default();
                let mut trust = TrustStore::new(issuer.verifying_key(), access.clone());
                trust.import(record(1)).unwrap();
                let update = sign_key_update(
                    &issuer,
                    KeyUpdate {
                        old_key_id: 1,
                        new_record: record(3),
                        not_before: 10,
                        retire_after: 20,
                        issuer_key_id: Some(9),
                        signature: Vec::new(),
                    },
                )
                .unwrap();
                let now = ClockSample {
                    lower: 10,
                    upper: 10,
                };
                access.fail.set(true);
                access.after_write.set(after_write);
                let result = match method {
                    0 => trust.import(record(3)),
                    1 => trust.pin(record(3).key),
                    _ => trust.apply_update(&update, now),
                };
                assert_eq!(result, Err(Error::StorageUnavailable));
                assert!(trust.get(&id).is_none());
                assert_eq!(trust.snapshot(), Err(Error::StorageUnavailable));
                access.fail.set(false);
                assert_eq!(trust.import(record(2)), Err(Error::StorageUnavailable));
                assert_eq!(trust.pin(record(2).key), Err(Error::StorageUnavailable));
                assert_eq!(
                    trust.apply_update(&update, now),
                    Err(Error::StorageUnavailable)
                );
                let snapshot = access.state.borrow().clone().unwrap();
                let mut restored =
                    TrustStore::from_snapshot(issuer.verifying_key(), access, snapshot).unwrap();
                assert_eq!(
                    restored.get(&id).unwrap().key.key_version,
                    if after_write { 3 } else { 1 }
                );
                if after_write {
                    assert_eq!(restored.import(record(2)), Err(Error::StaleKey));
                }
            }
        }
    }
}
