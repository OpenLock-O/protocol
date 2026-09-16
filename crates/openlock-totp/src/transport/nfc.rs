//! Public NFC discovery and one TOTP message per ISO-DEP/APDU data field.

use crate::transport::{validate_message, FrameCodec, TransportError};
use crate::types::{Error, LockId, PROFILE, PROTOCOL_VERSION};

pub const NDEF_MIME: &str = "application/vnd.openlock.bootstrap";
pub const BOOTSTRAP_SIZE: usize = 18;
pub const NDEF_SIZE: usize = 3 + NDEF_MIME.len() + BOOTSTRAP_SIZE;

/// An unauthenticated discovery hint, never proof of lock identity. No key,
/// credential, clock-setting instruction or access code belongs in an NDEF tag.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Bootstrap {
    pub lock_id: LockId,
}

pub fn encode_bootstrap(record: &Bootstrap) -> [u8; BOOTSTRAP_SIZE] {
    let mut out = [0; BOOTSTRAP_SIZE];
    out[0] = PROTOCOL_VERSION;
    out[1] = PROFILE;
    out[2..].copy_from_slice(&record.lock_id.0);
    out
}

pub fn decode_bootstrap(bytes: &[u8]) -> Result<Bootstrap, Error> {
    if bytes.len() != BOOTSTRAP_SIZE {
        return Err(Error::InvalidNfc);
    }
    if bytes[0] != PROTOCOL_VERSION || bytes[1] != PROFILE {
        return Err(Error::UnsupportedVersion);
    }
    Ok(Bootstrap {
        lock_id: LockId(bytes[2..].try_into().unwrap()),
    })
}

/// A single short MIME record: MB | ME | SR | TNF=MIME, no ID or chunks.
pub fn encode_ndef(record: &Bootstrap) -> [u8; NDEF_SIZE] {
    let mut out = [0; NDEF_SIZE];
    out[0] = 0xd2;
    out[1] = NDEF_MIME.len() as u8;
    out[2] = BOOTSTRAP_SIZE as u8;
    out[3..3 + NDEF_MIME.len()].copy_from_slice(NDEF_MIME.as_bytes());
    out[3 + NDEF_MIME.len()..].copy_from_slice(&encode_bootstrap(record));
    out
}

pub fn decode_ndef(bytes: &[u8]) -> Result<Bootstrap, Error> {
    // Check the entire size before indexing any attacker-controlled offsets.
    if bytes.len() != NDEF_SIZE
        || bytes[0] != 0xd2
        || bytes[1] as usize != NDEF_MIME.len()
        || bytes[2] as usize != BOOTSTRAP_SIZE
        || &bytes[3..3 + NDEF_MIME.len()] != NDEF_MIME.as_bytes()
    {
        return Err(Error::InvalidNfc);
    }
    decode_bootstrap(&bytes[3 + NDEF_MIME.len()..])
}

#[derive(Default)]
pub struct IsoDepCodec;
impl FrameCodec for IsoDepCodec {
    fn encode<'a>(&self, message: &'a [u8]) -> Result<&'a [u8], TransportError> {
        validate_message(message)
    }
    fn decode<'a>(&self, frame: &'a [u8]) -> Result<&'a [u8], TransportError> {
        validate_message(frame)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn public_discovery_round_trip_and_strict_lengths() {
        let record = Bootstrap {
            lock_id: LockId([1; 16]),
        };
        let ndef = encode_ndef(&record);
        assert_eq!(decode_ndef(&ndef).unwrap(), record);
        for len in 0..NDEF_SIZE {
            assert!(decode_ndef(&ndef[..len]).is_err());
        }
        let mut malformed = ndef;
        malformed[1] = 255;
        assert_eq!(decode_ndef(&malformed), Err(Error::InvalidNfc));
        malformed = ndef;
        malformed[3 + NDEF_MIME.len()] = 2;
        assert_eq!(decode_ndef(&malformed), Err(Error::UnsupportedVersion));
        assert!(decode_ndef(&[0; NDEF_SIZE + 1]).is_err());
    }
    #[test]
    fn apdu_payload_is_one_borrowed_message() {
        let codec = IsoDepCodec;
        let request = [3; 18];
        assert_eq!(
            codec.decode(codec.encode(&request).unwrap()).unwrap(),
            request
        );
        assert_eq!(codec.decode(&[]), Err(TransportError::InvalidLength));
        assert_eq!(codec.decode(&[0; 21]), Err(TransportError::TooLarge));
    }
}
