//! QR payload is a secret setup artifact, never a public discovery record.
use alloc::{format, string::String};
use openlock_types::{Error, LockId};
#[derive(Clone, Eq, PartialEq)]
pub struct SetupPayload {
    pub lock_id: LockId,
    pub public_key: [u8; 32],
    pub setup_key: [u8; 32],
}
impl core::fmt::Debug for SetupPayload {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SetupPayload")
            .field("lock_id", &self.lock_id)
            .finish_non_exhaustive()
    }
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
fn unhex<const N: usize>(s: &str) -> Result<[u8; N], Error> {
    if s.len() != N * 2
        || !s
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(Error::InvalidPayload);
    }
    let mut out = [0; N];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).map_err(|_| Error::InvalidPayload)?;
    }
    Ok(out)
}
impl SetupPayload {
    pub fn encode(&self) -> Result<String, Error> {
        crate::validate_public(&self.public_key)?;
        if self.setup_key == [0; 32] {
            return Err(Error::InvalidPayload);
        }
        Ok(format!(
            "OPENLOCK4:{}:{}:{}",
            hex(&self.lock_id.0),
            hex(&self.public_key),
            hex(&self.setup_key)
        ))
    }
    pub fn decode(text: &str) -> Result<Self, Error> {
        let mut f = text.split(':');
        if f.next() != Some("OPENLOCK4") {
            return Err(Error::UnsupportedVersion);
        }
        let out = Self {
            lock_id: LockId(unhex(f.next().ok_or(Error::InvalidPayload)?)?),
            public_key: unhex(f.next().ok_or(Error::InvalidPayload)?)?,
            setup_key: unhex(f.next().ok_or(Error::InvalidPayload)?)?,
        };
        if f.next().is_some() {
            return Err(Error::InvalidPayload);
        }
        out.encode()?;
        Ok(out)
    }
}

impl Drop for SetupPayload {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.setup_key.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn setup_qr_roundtrip_is_exact_and_debug_redacts_the_secret() {
        let setup = SetupPayload {
            lock_id: LockId([1; 16]),
            public_key: crate::static_public(&[4; 32]),
            setup_key: [7; 32],
        };
        let text = setup.encode().unwrap();
        assert_eq!(SetupPayload::decode(&text).unwrap(), setup);
        assert!(!alloc::format!("{setup:?}").contains("070707"));
        assert!(SetupPayload::decode(&(text.clone() + ":extra")).is_err());
        assert!(SetupPayload::decode(&text.replace("OPENLOCK4", "OPENLOCK2")).is_err());
        assert!(SetupPayload::decode(&text[..text.len() - 1]).is_err());
    }
}
