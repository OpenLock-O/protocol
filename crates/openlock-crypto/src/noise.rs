use alloc::{boxed::Box, vec, vec::Vec};
use openlock_types::{Error, SubjectKey, MAX_MESSAGE_SIZE};

pub const NOISE_SUITE: &str = "Noise_IK_25519_ChaChaPoly_SHA256";
const PROLOGUE: &[u8] = b"OpenLock/v2/profile1";

pub fn static_public(private_key: &[u8; 32]) -> [u8; 32] {
    use x25519_dalek::{PublicKey, StaticSecret};
    PublicKey::from(&StaticSecret::from(*private_key)).to_bytes()
}
pub fn validate_public(public: &[u8; 32]) -> Result<(), Error> {
    use x25519_dalek::{PublicKey, StaticSecret};
    if *public == [0; 32]
        || !StaticSecret::from([0x42; 32])
            .diffie_hellman(&PublicKey::from(*public))
            .was_contributory()
    {
        Err(Error::UntrustedKey)
    } else {
        Ok(())
    }
}
enum State {
    Handshake(Box<snow::HandshakeState>),
    Transport(Box<snow::TransportState>),
    Closed,
}
pub struct NoiseChannel {
    state: State,
}
impl NoiseChannel {
    pub fn initiator(private: &[u8; 32], peer: &[u8; 32]) -> Result<Self, Error> {
        validate_public(peer)?;
        Self::new(private, Some(peer))
    }
    pub fn responder(private: &[u8; 32]) -> Result<Self, Error> {
        Self::new(private, None)
    }
    fn new(private: &[u8; 32], peer: Option<&[u8; 32]>) -> Result<Self, Error> {
        if *private == [0; 32] {
            return Err(Error::Noise);
        }
        let builder = snow::Builder::new(NOISE_SUITE.parse().map_err(|_| Error::Noise)?)
            .prologue(PROLOGUE)
            .map_err(|_| Error::Noise)?
            .local_private_key(private)
            .map_err(|_| Error::Noise)?;
        let state = match peer {
            Some(peer) => builder
                .remote_public_key(peer)
                .map_err(|_| Error::Noise)?
                .build_initiator(),
            None => builder.build_responder(),
        }
        .map_err(|_| Error::Noise)?;
        Ok(Self {
            state: State::Handshake(Box::new(state)),
        })
    }
    pub fn is_transport(&self) -> bool {
        matches!(self.state, State::Transport(_))
    }
    pub fn close(&mut self) {
        self.state = State::Closed;
    }
    fn finish_handshake(&mut self) -> Result<(), Error> {
        if matches!(&self.state, State::Handshake(s) if s.is_handshake_finished()) {
            let State::Handshake(s) = core::mem::replace(&mut self.state, State::Closed) else {
                unreachable!()
            };
            self.state =
                State::Transport(Box::new(s.into_transport_mode().map_err(|_| Error::Noise)?));
        }
        Ok(())
    }
    pub fn write(&mut self, payload: &[u8]) -> Result<Vec<u8>, Error> {
        if payload.len() > MAX_MESSAGE_SIZE - 128 {
            return Err(Error::ObjectTooLarge);
        }
        let mut out = vec![0; MAX_MESSAGE_SIZE];
        let result = match &mut self.state {
            State::Handshake(s) => s.write_message(payload, &mut out),
            State::Transport(s) => s.write_message(payload, &mut out),
            State::Closed => return Err(Error::InvalidState),
        };
        match result {
            Ok(n) => {
                out.truncate(n);
                self.finish_handshake()?;
                Ok(out)
            }
            Err(_) => {
                self.close();
                Err(Error::Noise)
            }
        }
    }
    pub fn read(&mut self, input: &[u8]) -> Result<Vec<u8>, Error> {
        if input.len() > MAX_MESSAGE_SIZE {
            self.close();
            return Err(Error::ObjectTooLarge);
        }
        let mut out = vec![0; MAX_MESSAGE_SIZE];
        let result = match &mut self.state {
            State::Handshake(s) => s.read_message(input, &mut out),
            State::Transport(s) => s.read_message(input, &mut out),
            State::Closed => return Err(Error::InvalidState),
        };
        match result {
            Ok(n) => {
                out.truncate(n);
                self.finish_handshake()?;
                Ok(out)
            }
            Err(_) => {
                self.close();
                Err(Error::Noise)
            }
        }
    }
    pub fn peer_static(&self) -> Result<SubjectKey, Error> {
        let peer = match &self.state {
            State::Handshake(s) => s.get_remote_static(),
            State::Transport(s) => s.get_remote_static(),
            State::Closed => None,
        }
        .ok_or(Error::InvalidState)?;
        let key = peer.try_into().map_err(|_| Error::Noise)?;
        validate_public(&key)?;
        Ok(SubjectKey(key))
    }
}
