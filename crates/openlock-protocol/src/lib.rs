//! Transport-neutral OpenLock v2 message envelope and session state machine.
use openlock_crypto::{cbor, NoiseChannel};
use openlock_types::*;

const PROFILE: u64 = 1;
const KIND_HANDSHAKE: u64 = 0;
const KIND_REQUEST: u64 = 1;
const KIND_RESPONSE: u64 = 2;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Role {
    Initiator,
    Responder,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SessionEvent {
    HandshakeComplete {
        peer: SubjectKey,
    },
    Request {
        request_id: u32,
        command: Command,
        peer: SubjectKey,
    },
    Response {
        request_id: u32,
        response: Response,
    },
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Packet {
    pub kind: u8,
    pub request_id: u32,
    pub capabilities: u64,
    pub payload: Vec<u8>,
}

fn packet_value(p: &Packet) -> openlock_crypto::cbor::Value {
    cbor::array(vec![
        cbor::uint(PROTOCOL_VERSION),
        cbor::uint(PROFILE),
        cbor::uint(p.kind as u64),
        cbor::uint(p.request_id as u64),
        cbor::uint(p.capabilities),
        cbor::bytes(&p.payload),
    ])
}
fn encode_packet(p: &Packet) -> Result<Vec<u8>, Error> {
    cbor::encode_limit(&packet_value(p), MAX_MESSAGE_SIZE)
}
fn decode_packet(bytes: &[u8]) -> Result<Packet, Error> {
    let value = cbor::decode_limit(bytes, MAX_MESSAGE_SIZE)?;
    let f = cbor::fields(&value, 6)?;
    if cbor::number(&f[0])? != PROTOCOL_VERSION || cbor::number(&f[1])? != PROFILE {
        return Err(Error::UnsupportedVersion);
    }
    let kind = cbor::u32_value(&f[2])?;
    let payload = cbor::data(&f[5])?.to_vec();
    if kind > KIND_RESPONSE as u32
        || (kind == KIND_HANDSHAKE as u32
            && (cbor::number(&f[3])? != 0 || cbor::number(&f[4])? != 0))
    {
        return Err(Error::InvalidPayload);
    }
    Ok(Packet {
        kind: kind as u8,
        request_id: cbor::u32_value(&f[3])?,
        capabilities: cbor::number(&f[4])?,
        payload,
    })
}

fn request_value(command: &Command) -> openlock_crypto::cbor::Value {
    match command {
        Command::Unlock(r) => cbor::array(vec![
            cbor::uint(0),
            cbor::bytes(&r.credential),
            r.requested_use
                .map_or(cbor::Value::Null, |n| cbor::uint(n as u64)),
        ]),
        Command::Status(r) => cbor::array(vec![
            cbor::uint(1),
            cbor::bytes(&r.credential),
            r.requested_use
                .map_or(cbor::Value::Null, |n| cbor::uint(n as u64)),
        ]),
        Command::ApplyPolicy(s) => cbor::array(vec![cbor::uint(2), cbor::bytes(s)]),
    }
}
fn parse_request(v: &openlock_crypto::cbor::Value) -> Result<Command, Error> {
    let cbor::Value::Array(values) = v else {
        return Err(Error::InvalidPayload);
    };
    if values.is_empty() {
        return Err(Error::InvalidPayload);
    }
    let kind = cbor::u32_value(&values[0])?;
    match (kind, values.len()) {
        (0, 3) => Ok(Command::Unlock(AccessRequest {
            credential: cbor::data(&values[1])?.to_vec(),
            requested_use: cbor::optional_u32(&values[2])?,
        })),
        (1, 3) => Ok(Command::Status(AccessRequest {
            credential: cbor::data(&values[1])?.to_vec(),
            requested_use: cbor::optional_u32(&values[2])?,
        })),
        (2, 2) => Ok(Command::ApplyPolicy(cbor::data(&values[1])?.to_vec())),
        _ => Err(Error::InvalidPayload),
    }
}
fn response_value(r: &Response) -> openlock_crypto::cbor::Value {
    match r {
        Response::Unlocked => cbor::array(vec![cbor::uint(0)]),
        Response::Status {
            epoch,
            policy_version,
        } => cbor::array(vec![
            cbor::uint(1),
            cbor::uint(*epoch),
            cbor::uint(*policy_version),
        ]),
        Response::PolicyApplied => cbor::array(vec![cbor::uint(2)]),
        Response::AlreadyConsumed { next_use } => {
            cbor::array(vec![cbor::uint(3), cbor::uint(*next_use as u64)])
        }
        Response::Rejected { code } => cbor::array(vec![cbor::uint(4), cbor::uint(*code as u64)]),
    }
}
fn parse_response(v: &openlock_crypto::cbor::Value) -> Result<Response, Error> {
    let cbor::Value::Array(f) = v else {
        return Err(Error::InvalidPayload);
    };
    match (
        cbor::u32_value(f.first().ok_or(Error::InvalidPayload)?)?,
        f.len(),
    ) {
        (0, 1) => Ok(Response::Unlocked),
        (1, 3) => Ok(Response::Status {
            epoch: cbor::number(&f[1])?,
            policy_version: cbor::number(&f[2])?,
        }),
        (2, 1) => Ok(Response::PolicyApplied),
        (3, 2) => Ok(Response::AlreadyConsumed {
            next_use: cbor::u32_value(&f[1])?,
        }),
        (4, 2) => Ok(Response::Rejected {
            code: cbor::u32_value(&f[1])?,
        }),
        _ => Err(Error::InvalidPayload),
    }
}

pub struct Session {
    role: Role,
    capabilities: u64,
    next_request: u32,
    started: bool,
    channel: NoiseChannel,
}
impl Session {
    pub fn initiator(
        private: &[u8; 32],
        lock_public: &[u8; 32],
        capabilities: u64,
    ) -> Result<Self, Error> {
        if capabilities & !KNOWN_CAPABILITIES != 0 {
            return Err(Error::UnsupportedCapability);
        }
        Ok(Self {
            role: Role::Initiator,
            capabilities,
            next_request: 1,
            started: false,
            channel: NoiseChannel::initiator(private, lock_public)?,
        })
    }
    pub fn responder(private: &[u8; 32], capabilities: u64) -> Result<Self, Error> {
        if capabilities & !KNOWN_CAPABILITIES != 0 {
            return Err(Error::UnsupportedCapability);
        }
        Ok(Self {
            role: Role::Responder,
            capabilities,
            next_request: 1,
            started: false,
            channel: NoiseChannel::responder(private)?,
        })
    }
    pub fn start(&mut self) -> Result<Vec<u8>, Error> {
        if self.role != Role::Initiator || self.started {
            return Err(Error::InvalidState);
        }
        self.started = true;
        encode_packet(&Packet {
            kind: KIND_HANDSHAKE as u8,
            request_id: 0,
            capabilities: 0,
            payload: self.channel.write(&[])?,
        })
    }
    pub fn receive(&mut self, input: &[u8]) -> Result<(Vec<SessionEvent>, Option<Vec<u8>>), Error> {
        let packet = decode_packet(input)?;
        let clear = if packet.kind == KIND_HANDSHAKE as u8 {
            self.channel.read(&packet.payload)?
        } else {
            if !self.channel.is_transport() {
                return Err(Error::InvalidState);
            }
            self.channel.read(&packet.payload)?
        };
        let mut events = Vec::new();
        let mut reply = None;
        if packet.kind == KIND_HANDSHAKE as u8 {
            if self.started && self.role == Role::Responder {
                return Err(Error::InvalidState);
            }
            self.started = true;
            if self.role == Role::Responder {
                reply = Some(encode_packet(&Packet {
                    kind: KIND_HANDSHAKE as u8,
                    request_id: 0,
                    capabilities: 0,
                    payload: self.channel.write(&[])?,
                })?);
            }
            if self.channel.is_transport() {
                events.push(SessionEvent::HandshakeComplete {
                    peer: self.channel.peer_static()?,
                });
            }
            return Ok((events, reply));
        }
        let value = cbor::decode(&clear)?;
        let peer = self.channel.peer_static()?;
        match packet.kind {
            1 => {
                let command = parse_request(&value)?;
                if command.capability() & packet.capabilities & self.capabilities == 0 {
                    return Err(Error::UnsupportedCapability);
                }
                events.push(SessionEvent::Request {
                    request_id: packet.request_id,
                    command,
                    peer,
                })
            }
            2 => events.push(SessionEvent::Response {
                request_id: packet.request_id,
                response: parse_response(&value)?,
            }),
            _ => return Err(Error::InvalidPayload),
        }
        Ok((events, reply))
    }
    pub fn send(&mut self, command: Command) -> Result<(u32, Vec<u8>), Error> {
        if !self.channel.is_transport() || command.capability() & self.capabilities == 0 {
            return Err(Error::InvalidState);
        }
        let request_id = self.next_request;
        self.next_request = self
            .next_request
            .checked_add(1)
            .ok_or(Error::InvalidState)?;
        let body = cbor::encode(&request_value(&command))?;
        let payload = self.channel.write(&body)?;
        Ok((
            request_id,
            encode_packet(&Packet {
                kind: KIND_REQUEST as u8,
                request_id,
                capabilities: self.capabilities,
                payload,
            })?,
        ))
    }
    pub fn respond(&mut self, request_id: u32, response: Response) -> Result<Vec<u8>, Error> {
        if !self.channel.is_transport() {
            return Err(Error::InvalidState);
        }
        let body = cbor::encode(&response_value(&response))?;
        let payload = self.channel.write(&body)?;
        encode_packet(&Packet {
            kind: KIND_RESPONSE as u8,
            request_id,
            capabilities: self.capabilities,
            payload,
        })
    }
    pub fn peer_static(&self) -> Result<SubjectKey, Error> {
        self.channel.peer_static()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn noise_session_round_trip_over_arbitrary_bytes() {
        let mut phone = Session::initiator(
            &[3; 32],
            &openlock_crypto::static_public(&[4; 32]),
            CAP_UNLOCK,
        )
        .unwrap();
        let mut lock = Session::responder(&[4; 32], CAP_UNLOCK).unwrap();
        let first = phone.start().unwrap();
        let (events, second) = lock.receive(&first).unwrap();
        assert!(matches!(
            events.first(),
            Some(SessionEvent::HandshakeComplete { .. })
        ));
        let second = second.unwrap();
        let (events, _) = phone.receive(&second).unwrap();
        assert!(matches!(
            events.first(),
            Some(SessionEvent::HandshakeComplete { .. })
        ));
        let (_, request) = phone
            .send(Command::Unlock(AccessRequest {
                credential: vec![1, 2, 3],
                requested_use: Some(0),
            }))
            .unwrap();
        let (events, _) = lock.receive(&request).unwrap();
        assert!(matches!(
            events.first(),
            Some(SessionEvent::Request {
                command: Command::Unlock(_),
                ..
            })
        ));
    }
    #[test]
    fn malformed_command_does_not_panic() {
        assert_eq!(
            parse_request(&cbor::array(vec![])),
            Err(Error::InvalidPayload)
        );
    }
}
