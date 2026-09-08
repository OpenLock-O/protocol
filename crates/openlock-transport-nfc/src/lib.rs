//! NFC bootstrap and ISO-DEP/APDU framing. Native reader/card I/O is platform-owned.
use ed25519_dalek::VerifyingKey;
use openlock_crypto::{cbor, verify_device_key};
use openlock_transport::{FrameCodec, TransportError};
use openlock_types::{DeviceKeyRecord, Error, MAX_OBJECT_SIZE};

pub const NDEF_MIME: &str = "application/vnd.openlock.bootstrap+cbor";
pub const MAX_NDEF_RECORD: usize = MAX_OBJECT_SIZE;
pub const MAX_APDU_PAYLOAD: usize = 240;

pub fn encode_bootstrap(record: &DeviceKeyRecord) -> Result<Vec<u8>, Error> {
    let key = &record.key;
    cbor::encode_limit(
        &cbor::array(vec![
            cbor::uint(2),
            cbor::bytes(&key.device_id.0),
            cbor::uint(key.key_id as u64),
            cbor::uint(key.key_version as u64),
            cbor::bytes(&key.x25519_public_key),
            cbor::bytes(&key.rotation_public_key),
            cbor::uint(key.capabilities),
            cbor::uint(record.issuer_key_id as u64),
            cbor::bytes(&record.signature),
        ]),
        MAX_NDEF_RECORD,
    )
}
pub fn decode_bootstrap(bytes: &[u8], issuer: &VerifyingKey) -> Result<DeviceKeyRecord, Error> {
    let value = cbor::decode_limit(bytes, MAX_NDEF_RECORD)?;
    let f = cbor::fields(&value, 9)?;
    if cbor::number(&f[0])? != 2 {
        return Err(Error::UnsupportedVersion);
    }
    let key = openlock_types::DeviceKey {
        device_id: openlock_types::LockId(cbor::fixed(&f[1])?),
        key_id: cbor::u32_value(&f[2])?,
        key_version: cbor::u32_value(&f[3])?,
        x25519_public_key: cbor::fixed(&f[4])?,
        rotation_public_key: cbor::fixed(&f[5])?,
        capabilities: cbor::number(&f[6])?,
    };
    let record = DeviceKeyRecord {
        key,
        issuer_key_id: cbor::u32_value(&f[7])?,
        signature: cbor::data(&f[8])?.to_vec(),
    };
    verify_device_key(issuer, &record)?;
    Ok(record)
}

/// Encode a single MIME NDEF record. Its payload is the signed bootstrap CBOR.
pub fn encode_ndef(record: &DeviceKeyRecord) -> Result<Vec<u8>, Error> {
    let payload = encode_bootstrap(record)?;
    let mime = NDEF_MIME.as_bytes();
    if mime.len() > u8::MAX as usize || payload.len() > u32::MAX as usize {
        return Err(Error::ObjectTooLarge);
    }
    let mut out = Vec::with_capacity(6 + mime.len() + payload.len());
    out.push(0xc2); // MB|ME|TNF=MIME, long payload length
    out.push(mime.len() as u8);
    out.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    out.extend_from_slice(mime);
    out.extend_from_slice(&payload);
    Ok(out)
}

pub fn decode_ndef(bytes: &[u8], issuer: &VerifyingKey) -> Result<DeviceKeyRecord, Error> {
    if bytes.len() < 6 || bytes[0] != 0xc2 {
        return Err(Error::InvalidNfc);
    }
    let type_len = bytes[1] as usize;
    let payload_len = u32::from_be_bytes([bytes[2], bytes[3], bytes[4], bytes[5]]) as usize;
    let payload_start = 6usize.checked_add(type_len).ok_or(Error::InvalidNfc)?;
    let payload_end = payload_start
        .checked_add(payload_len)
        .ok_or(Error::InvalidNfc)?;
    if bytes.len() != payload_end || &bytes[6..payload_start] != NDEF_MIME.as_bytes() {
        return Err(Error::InvalidNfc);
    }
    decode_bootstrap(&bytes[payload_start..], issuer)
}

#[derive(Default)]
pub struct IsoDepCodec {
    sequence: u8,
    expected_sequence: Option<u8>,
    inner: Vec<u8>,
    expected: Option<usize>,
}
impl FrameCodec for IsoDepCodec {
    type Error = TransportError;
    fn encode(&mut self, message: &[u8]) -> Result<Vec<Vec<u8>>, Self::Error> {
        if message.is_empty() || message.len() > MAX_NDEF_RECORD {
            return Err(TransportError::TooLarge);
        }
        let total = message.len() as u16;
        let mut result = Vec::new();
        for chunk in message.chunks(MAX_APDU_PAYLOAD) {
            let mut apdu = Vec::with_capacity(3 + chunk.len());
            apdu.push(self.sequence);
            apdu.extend_from_slice(&total.to_be_bytes());
            apdu.extend_from_slice(chunk);
            self.sequence = self.sequence.wrapping_add(1);
            result.push(apdu);
        }
        Ok(result)
    }
    fn push(&mut self, fragment: &[u8]) -> Result<Option<Vec<u8>>, Self::Error> {
        if fragment.len() < 3 {
            return Err(TransportError::TooShort);
        }
        let total = u16::from_be_bytes([fragment[1], fragment[2]]) as usize;
        if total == 0 || total > MAX_NDEF_RECORD || fragment.len() > MAX_APDU_PAYLOAD + 3 {
            return Err(TransportError::InvalidNfc);
        }
        if self.expected.is_none() {
            self.expected = Some(total);
            self.expected_sequence = Some(fragment[0]);
        } else if self.expected != Some(total) {
            return Err(TransportError::Conflict);
        }
        if self.expected_sequence != Some(fragment[0]) {
            return Err(TransportError::Conflict);
        }
        self.expected_sequence = self.expected_sequence.map(|n| n.wrapping_add(1));
        self.inner.extend_from_slice(&fragment[3..]);
        if self.inner.len() > total {
            return Err(TransportError::OutOfBounds);
        }
        if self.inner.len() == total {
            let value = std::mem::take(&mut self.inner);
            self.reset();
            Ok(Some(value))
        } else {
            Ok(None)
        }
    }
    fn reset(&mut self) {
        self.inner.clear();
        self.expected = None;
        self.expected_sequence = None;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use openlock_crypto::sign_device_key;
    use openlock_types::{DeviceKey, LockId};
    #[test]
    fn apdu_chunks_and_reassembles() {
        let mut tx = IsoDepCodec::default();
        let frames = tx.encode(&vec![7; 500]).unwrap();
        let mut rx = IsoDepCodec::default();
        let mut result = None;
        for frame in frames {
            result = rx.push(&frame).unwrap().or(result);
        }
        assert_eq!(result, Some(vec![7; 500]));
    }
    #[test]
    fn wrong_apdu_sequence_is_rejected() {
        let mut tx = IsoDepCodec::default();
        let mut frames = tx.encode(&vec![8; 500]).unwrap();
        let mut rx = IsoDepCodec::default();
        let _ = rx.push(&frames.remove(0)).unwrap();
        frames[0][0] = frames[0][0].wrapping_add(1);
        assert_eq!(rx.push(&frames[0]), Err(TransportError::Conflict));
    }
    #[test]
    fn signed_ndef_bootstrap_round_trips() {
        let issuer = SigningKey::from_bytes(&[6; 32]);
        let key = DeviceKey {
            device_id: LockId([1; 16]),
            key_id: 7,
            key_version: 1,
            x25519_public_key: [2; 32],
            rotation_public_key: [3; 32],
            capabilities: 3,
        };
        let record = sign_device_key(&issuer, &key, 11).unwrap();
        let bytes = encode_bootstrap(&record).unwrap();
        assert_eq!(
            decode_bootstrap(&bytes, &issuer.verifying_key()).unwrap(),
            record
        );
        let ndef = encode_ndef(&record).unwrap();
        assert_eq!(decode_ndef(&ndef, &issuer.verifying_key()).unwrap(), record);
    }
}
