use openlock_transport::{FrameCodec, TransportError};
pub const HEADER_SIZE: usize = 8;
pub const MAX_FRAME_MESSAGE: usize = 4096;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FragmentHeader {
    pub message_id: u16,
    pub offset: u16,
    pub total: u16,
}

pub struct BleCodec {
    next_id: u16,
    message_id: Option<u16>,
    total: usize,
    bytes: Vec<u8>,
    received: Vec<bool>,
}
impl Default for BleCodec {
    fn default() -> Self {
        Self {
            next_id: 1,
            message_id: None,
            total: 0,
            bytes: Vec::new(),
            received: Vec::new(),
        }
    }
}
impl BleCodec {
    fn frame(header: FragmentHeader, payload: &[u8]) -> Result<Vec<u8>, TransportError> {
        if header.total == 0
            || header.total as usize > MAX_FRAME_MESSAGE
            || header.offset as usize + payload.len() > header.total as usize
            || payload.len() > u16::MAX as usize
        {
            return Err(TransportError::OutOfBounds);
        }
        let mut out = Vec::with_capacity(HEADER_SIZE + payload.len());
        out.extend_from_slice(&header.message_id.to_le_bytes());
        out.extend_from_slice(&header.offset.to_le_bytes());
        out.extend_from_slice(&header.total.to_le_bytes());
        out.extend_from_slice(&(payload.len() as u16).to_le_bytes());
        out.extend_from_slice(payload);
        Ok(out)
    }
    fn parse(frame: &[u8]) -> Result<(FragmentHeader, &[u8]), TransportError> {
        if frame.len() < HEADER_SIZE {
            return Err(TransportError::TooShort);
        }
        let h = FragmentHeader {
            message_id: u16::from_le_bytes([frame[0], frame[1]]),
            offset: u16::from_le_bytes([frame[2], frame[3]]),
            total: u16::from_le_bytes([frame[4], frame[5]]),
        };
        let len = u16::from_le_bytes([frame[6], frame[7]]) as usize;
        if frame.len() != HEADER_SIZE + len {
            return Err(TransportError::InvalidLength);
        }
        if h.total == 0
            || h.total as usize > MAX_FRAME_MESSAGE
            || h.offset as usize + len > h.total as usize
        {
            return Err(TransportError::OutOfBounds);
        }
        Ok((h, &frame[HEADER_SIZE..]))
    }
}
impl FrameCodec for BleCodec {
    type Error = TransportError;
    fn encode(&mut self, message: &[u8]) -> Result<Vec<Vec<u8>>, Self::Error> {
        if message.is_empty() || message.len() > MAX_FRAME_MESSAGE {
            return Err(TransportError::TooLarge);
        }
        let id = self.next_id;
        self.next_id = self.next_id.wrapping_add(1).max(1);
        let max = 180usize;
        let total = message.len() as u16;
        message
            .chunks(max)
            .enumerate()
            .map(|(i, p)| {
                Self::frame(
                    FragmentHeader {
                        message_id: id,
                        offset: (i * max) as u16,
                        total,
                    },
                    p,
                )
            })
            .collect()
    }
    fn push(&mut self, frame: &[u8]) -> Result<Option<Vec<u8>>, Self::Error> {
        let (h, payload) = Self::parse(frame)?;
        if self.message_id.is_none() {
            self.message_id = Some(h.message_id);
            self.total = h.total as usize;
            self.bytes = vec![0; self.total];
            self.received = vec![false; self.total];
        } else if self.message_id != Some(h.message_id) {
            return Err(TransportError::Busy);
        } else if self.total != h.total as usize {
            return Err(TransportError::Conflict);
        }
        for (i, byte) in payload.iter().enumerate() {
            let at = h.offset as usize + i;
            if self.received[at] && self.bytes[at] != *byte {
                return Err(TransportError::Conflict);
            }
            self.bytes[at] = *byte;
            self.received[at] = true;
        }
        if self.received.iter().all(|v| *v) {
            let result = std::mem::take(&mut self.bytes);
            self.reset();
            Ok(Some(result))
        } else {
            Ok(None)
        }
    }
    fn reset(&mut self) {
        self.message_id = None;
        self.total = 0;
        self.bytes.clear();
        self.received.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn round_trip_out_of_order_and_duplicate() {
        let mut tx = BleCodec::default();
        let frames = tx.encode(&vec![3; 400]).unwrap();
        let mut rx = BleCodec::default();
        assert_eq!(rx.push(&frames[1]).unwrap(), None);
        assert_eq!(rx.push(&frames[1]).unwrap(), None); // identical duplicate
        assert_eq!(rx.push(&frames[0]).unwrap(), None);
        assert_eq!(rx.push(&frames[2]).unwrap(), Some(vec![3; 400]));
    }
    #[test]
    fn conflicting_fragment_is_rejected() {
        let mut tx = BleCodec::default();
        let mut frames = tx.encode(&vec![4; 400]).unwrap();
        let mut rx = BleCodec::default();
        assert_eq!(rx.push(&frames[0]).unwrap(), None);
        frames[0][8] ^= 1;
        assert_eq!(rx.push(&frames[0]), Err(TransportError::Conflict));
    }
}
