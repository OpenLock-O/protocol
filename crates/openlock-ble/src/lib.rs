//! GATT-independent framing for the OpenLock service.

use thiserror::Error;

pub const HEADER_SIZE: usize = 8;
pub const MAX_MESSAGE: usize = 4096;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FragmentHeader {
    pub message_id: u16,
    pub offset: u16,
    pub total: u16,
}

#[derive(Debug, Error, Eq, PartialEq)]
pub enum FrameError {
    #[error("fragment is too short")]
    TooShort,
    #[error("fragment has invalid length")]
    InvalidLength,
    #[error("message exceeds configured limit")]
    TooLarge,
    #[error("fragment is outside message")]
    OutOfBounds,
    #[error("fragment conflicts with an existing fragment")]
    Conflict,
    #[error("another message is being reassembled")]
    Busy,
    #[error("message is incomplete")]
    Incomplete,
}

pub fn encode(header: FragmentHeader, payload: &[u8]) -> Result<Vec<u8>, FrameError> {
    let total = header.total as usize;
    let offset = header.offset as usize;
    if total == 0 || total > MAX_MESSAGE || offset + payload.len() > total {
        return Err(FrameError::OutOfBounds);
    }
    let mut out = Vec::with_capacity(HEADER_SIZE + payload.len());
    out.extend_from_slice(&header.message_id.to_le_bytes());
    out.extend_from_slice(&header.offset.to_le_bytes());
    out.extend_from_slice(&header.total.to_le_bytes());
    out.extend_from_slice(&(payload.len() as u16).to_le_bytes());
    out.extend_from_slice(payload);
    Ok(out)
}

pub fn decode(frame: &[u8]) -> Result<(FragmentHeader, &[u8]), FrameError> {
    if frame.len() < HEADER_SIZE {
        return Err(FrameError::TooShort);
    }
    let header = FragmentHeader {
        message_id: u16::from_le_bytes([frame[0], frame[1]]),
        offset: u16::from_le_bytes([frame[2], frame[3]]),
        total: u16::from_le_bytes([frame[4], frame[5]]),
    };
    let length = u16::from_le_bytes([frame[6], frame[7]]) as usize;
    if frame.len() != HEADER_SIZE + length {
        return Err(FrameError::InvalidLength);
    }
    let total = header.total as usize;
    if total == 0 || total > MAX_MESSAGE || header.offset as usize + length > total {
        return Err(FrameError::OutOfBounds);
    }
    Ok((header, &frame[HEADER_SIZE..]))
}

#[derive(Debug, Default)]
pub struct Reassembler {
    message_id: Option<u16>,
    total: usize,
    bytes: Vec<u8>,
    received: Vec<bool>,
}

impl Reassembler {
    pub fn push(&mut self, frame: &[u8]) -> Result<Option<Vec<u8>>, FrameError> {
        let (header, payload) = decode(frame)?;
        if self.message_id.is_none() {
            self.message_id = Some(header.message_id);
            self.total = header.total as usize;
            self.bytes = vec![0; self.total];
            self.received = vec![false; self.total];
        } else if self.message_id != Some(header.message_id) {
            return Err(FrameError::Busy);
        } else if self.total != header.total as usize {
            return Err(FrameError::Conflict);
        }
        let start = header.offset as usize;
        for (index, byte) in payload.iter().enumerate() {
            if self.received[start + index] && self.bytes[start + index] != *byte {
                return Err(FrameError::Conflict);
            }
            self.bytes[start + index] = *byte;
            self.received[start + index] = true;
        }
        if self.received.iter().all(|v| *v) {
            let message = std::mem::take(&mut self.bytes);
            self.message_id = None;
            self.received.clear();
            self.total = 0;
            return Ok(Some(message));
        }
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reassembles_out_of_order_and_duplicate_fragments() {
        let payload = b"offline lock";
        let first = encode(
            FragmentHeader {
                message_id: 9,
                offset: 0,
                total: 12,
            },
            &payload[..6],
        )
        .unwrap();
        let second = encode(
            FragmentHeader {
                message_id: 9,
                offset: 6,
                total: 12,
            },
            &payload[6..],
        )
        .unwrap();
        let mut r = Reassembler::default();
        assert_eq!(r.push(&second).unwrap(), None);
        assert_eq!(r.push(&first).unwrap(), Some(payload.to_vec()));
    }

    #[test]
    fn rejects_conflicting_duplicate() {
        let a = encode(
            FragmentHeader {
                message_id: 1,
                offset: 0,
                total: 2,
            },
            b"a",
        )
        .unwrap();
        let b = encode(
            FragmentHeader {
                message_id: 1,
                offset: 0,
                total: 2,
            },
            b"b",
        )
        .unwrap();
        let mut r = Reassembler::default();
        assert_eq!(r.push(&a).unwrap(), None);
        assert_eq!(r.push(&b), Err(FrameError::Conflict));
    }
}
