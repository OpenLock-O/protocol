//! Stateless, fixed-size TOTP messages for OpenLock. No handshake or heap.

use crate::types::{CredentialId, Error, UnlockRequest, UnlockResponse, PROTOCOL_VERSION};

pub const KIND_UNLOCK: u8 = 1;
pub const KIND_RESPONSE: u8 = 0x81;
pub const UNLOCK_REQUEST_SIZE: usize = 18;
pub const UNLOCK_RESPONSE_SIZE: usize = 15;

pub fn encode_unlock(request: &UnlockRequest) -> Result<[u8; UNLOCK_REQUEST_SIZE], Error> {
    request.validate()?;
    let mut bytes = [0; UNLOCK_REQUEST_SIZE];
    bytes[0] = PROTOCOL_VERSION;
    bytes[1] = KIND_UNLOCK;
    bytes[2..6].copy_from_slice(&request.credential_id.0.to_be_bytes());
    bytes[6..14].copy_from_slice(&request.time_step.to_be_bytes());
    bytes[14..18].copy_from_slice(&request.code.to_be_bytes());
    Ok(bytes)
}

pub fn decode_unlock(bytes: &[u8]) -> Result<UnlockRequest, Error> {
    validate_header(bytes, UNLOCK_REQUEST_SIZE, KIND_UNLOCK)?;
    let request = UnlockRequest {
        credential_id: CredentialId(u32::from_be_bytes(bytes[2..6].try_into().unwrap())),
        time_step: u64::from_be_bytes(bytes[6..14].try_into().unwrap()),
        code: u32::from_be_bytes(bytes[14..18].try_into().unwrap()),
    };
    request.validate()?;
    Ok(request)
}

pub fn encode_response(response: &UnlockResponse) -> Result<[u8; UNLOCK_RESPONSE_SIZE], Error> {
    if response.credential_id.0 == 0 {
        return Err(Error::InvalidPayload);
    }
    let mut bytes = [0; UNLOCK_RESPONSE_SIZE];
    bytes[0] = PROTOCOL_VERSION;
    bytes[1] = KIND_RESPONSE;
    bytes[2..6].copy_from_slice(&response.credential_id.0.to_be_bytes());
    bytes[6..14].copy_from_slice(&response.time_step.to_be_bytes());
    bytes[14] = response.result.err().map_or(0, |error| error.code() as u8);
    Ok(bytes)
}

/// Decodes an *unauthenticated* result. Matching the ID and step is only
/// correlation, never proof of the lock's identity or of physical actuation.
pub fn decode_response(bytes: &[u8]) -> Result<UnlockResponse, Error> {
    validate_header(bytes, UNLOCK_RESPONSE_SIZE, KIND_RESPONSE)?;
    let credential_id = CredentialId(u32::from_be_bytes(bytes[2..6].try_into().unwrap()));
    if credential_id.0 == 0 {
        return Err(Error::InvalidPayload);
    }
    let result = match bytes[14] {
        0 => Ok(()),
        code => Err(Error::from_code(code as u32).ok_or(Error::InvalidPayload)?),
    };
    Ok(UnlockResponse {
        credential_id,
        time_step: u64::from_be_bytes(bytes[6..14].try_into().unwrap()),
        result,
    })
}

fn validate_header(bytes: &[u8], size: usize, kind: u8) -> Result<(), Error> {
    if bytes.len() != size {
        return Err(Error::InvalidPayload);
    }
    if bytes[0] != PROTOCOL_VERSION {
        return Err(Error::UnsupportedVersion);
    }
    if bytes[1] != kind {
        return Err(Error::InvalidPayload);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_wire_vector_and_response() {
        let request = UnlockRequest {
            credential_id: CredentialId(0x01020304),
            time_step: 1,
            code: 46_119_246,
        };
        let bytes = encode_unlock(&request).unwrap();
        assert_eq!(
            bytes,
            [3, 1, 1, 2, 3, 4, 0, 0, 0, 0, 0, 0, 0, 1, 2, 191, 185, 78]
        );
        assert_eq!(decode_unlock(&bytes).unwrap(), request);
        for result in [Ok(()), Err(Error::Replayed), Err(Error::ActuatorFailed)] {
            let response = UnlockResponse::for_request(&request, result);
            assert_eq!(
                decode_response(&encode_response(&response).unwrap()).unwrap(),
                response
            );
        }
    }

    #[test]
    fn malformed_and_legacy_messages_are_rejected() {
        let mut bytes = encode_unlock(&UnlockRequest {
            credential_id: CredentialId(1),
            time_step: u64::MAX,
            code: 0,
        })
        .unwrap();
        for len in 0..UNLOCK_REQUEST_SIZE {
            assert!(decode_unlock(&bytes[..len]).is_err());
        }
        assert!(decode_unlock(&[0; UNLOCK_REQUEST_SIZE + 1]).is_err());
        bytes[0] = 2;
        assert_eq!(decode_unlock(&bytes), Err(Error::UnsupportedVersion));
        bytes[0] = 3;
        bytes[1] = 2;
        assert!(decode_unlock(&bytes).is_err());
        bytes[1] = KIND_UNLOCK;
        bytes[14..].copy_from_slice(&100_000_000u32.to_be_bytes());
        assert!(decode_unlock(&bytes).is_err());
        let mut response = [0; UNLOCK_RESPONSE_SIZE];
        response[0] = 3;
        response[1] = KIND_RESPONSE;
        response[5] = 1;
        response[14] = 255;
        assert!(decode_response(&response).is_err());
    }
}
