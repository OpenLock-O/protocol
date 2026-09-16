//! One v3 message per GATT write/notification, including at the default MTU.

pub use crate::transport::MAX_FRAME_MESSAGE;
use crate::transport::{validate_message, FrameCodec, TransportError};
pub const DEFAULT_ATT_MTU: usize = 23;
pub const MIN_ATT_MTU: usize = DEFAULT_ATT_MTU;

pub struct BleCodec {
    att_mtu: usize,
}
impl Default for BleCodec {
    fn default() -> Self {
        Self {
            att_mtu: DEFAULT_ATT_MTU,
        }
    }
}
impl BleCodec {
    pub fn with_mtu(att_mtu: usize) -> Result<Self, TransportError> {
        if att_mtu < MIN_ATT_MTU {
            return Err(TransportError::InvalidLength);
        }
        Ok(Self { att_mtu })
    }
    pub fn set_mtu(&mut self, att_mtu: usize) -> Result<(), TransportError> {
        *self = Self::with_mtu(att_mtu)?;
        Ok(())
    }
    pub fn mtu(&self) -> usize {
        self.att_mtu
    }
}
impl FrameCodec for BleCodec {
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
    fn complete_messages_fit_the_default_mtu_without_extra_headers() {
        let codec = BleCodec::default();
        for size in [15, 18, 20] {
            let bytes = [7; 20];
            let frame = codec.encode(&bytes[..size]).unwrap();
            assert_eq!(frame.len(), size);
            assert!(frame.len() <= codec.mtu() - 3);
            assert_eq!(codec.decode(frame).unwrap(), &bytes[..size]);
        }
        assert_eq!(codec.encode(&[]), Err(TransportError::InvalidLength));
        assert_eq!(codec.encode(&[0; 21]), Err(TransportError::TooLarge));
        assert!(BleCodec::with_mtu(22).is_err());
        assert_eq!(
            BleCodec::with_mtu(517).unwrap().encode(&[0; 21]),
            Err(TransportError::TooLarge)
        );
    }
}
