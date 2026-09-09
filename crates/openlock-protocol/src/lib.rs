//! Transport-neutral OpenLock v2 message envelope and session state machine.
#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

use alloc::{collections::BTreeMap, vec, vec::Vec};
use openlock_crypto::{cbor, NoiseChannel};
use openlock_types::*;

pub const PROFILE: u64 = 1;
pub const KIND_HANDSHAKE: u8 = 0;
pub const KIND_REQUEST: u8 = 1;
pub const KIND_RESPONSE: u8 = 2;
pub const MAX_PENDING_REQUESTS: usize = 1024;

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
impl Packet {
    pub fn validate(&self) -> Result<(), Error> {
        if self.kind > KIND_RESPONSE
            || self.payload.is_empty()
            || self.capabilities & !KNOWN_CAPABILITIES != 0
        {
            return Err(Error::InvalidPayload);
        }
        if self.kind == KIND_HANDSHAKE {
            if self.request_id != 0 || self.capabilities != 0 {
                return Err(Error::InvalidPayload);
            }
        } else if self.request_id == 0 || self.capabilities == 0 {
            return Err(Error::InvalidPayload);
        }
        Ok(())
    }
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
pub fn encode_packet(p: &Packet) -> Result<Vec<u8>, Error> {
    p.validate()?;
    cbor::encode_limit(&packet_value(p), MAX_MESSAGE_SIZE)
}
pub fn decode_packet(bytes: &[u8]) -> Result<Packet, Error> {
    let value = cbor::decode_limit(bytes, MAX_MESSAGE_SIZE)?;
    let f = cbor::fields(&value, 6)?;
    if cbor::number(&f[0])? != PROTOCOL_VERSION || cbor::number(&f[1])? != PROFILE {
        return Err(Error::UnsupportedVersion);
    }
    let kind = cbor::u32_value(&f[2])?;
    if kind > KIND_RESPONSE as u32 {
        return Err(Error::InvalidPayload);
    }
    let request_id = cbor::u32_value(&f[3])?;
    let capabilities = cbor::number(&f[4])?;
    let payload = cbor::data(&f[5])?.to_vec();
    let packet = Packet {
        kind: kind as u8,
        request_id,
        capabilities,
        payload,
    };
    packet.validate()?;
    Ok(packet)
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
fn authenticated_value(
    kind: u8,
    request_id: u32,
    capabilities: u64,
    body: openlock_crypto::cbor::Value,
) -> openlock_crypto::cbor::Value {
    cbor::array(vec![
        cbor::uint(kind as u64),
        cbor::uint(request_id as u64),
        cbor::uint(capabilities),
        body,
    ])
}
fn validate_command(command: &Command) -> Result<(), Error> {
    match command {
        Command::Unlock(r) | Command::Status(r) => {
            if r.credential.is_empty() || r.credential.len() > MAX_OBJECT_SIZE {
                return Err(Error::InvalidPayload);
            }
        }
        Command::ApplyPolicy(policy) => {
            if policy.is_empty() || policy.len() > MAX_OBJECT_SIZE {
                return Err(Error::InvalidPayload);
            }
        }
    }
    Ok(())
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
        (0, 3) | (1, 3) => {
            let credential = cbor::data(&values[1])?;
            if credential.is_empty() || credential.len() > MAX_OBJECT_SIZE {
                return Err(Error::InvalidPayload);
            }
            let request = AccessRequest {
                credential: credential.to_vec(),
                requested_use: cbor::optional_u32(&values[2])?,
            };
            if kind == 0 {
                Ok(Command::Unlock(request))
            } else {
                Ok(Command::Status(request))
            }
        }
        (2, 2) => {
            let policy = cbor::data(&values[1])?;
            if policy.is_empty() || policy.len() > MAX_OBJECT_SIZE {
                return Err(Error::InvalidPayload);
            }
            Ok(Command::ApplyPolicy(policy.to_vec()))
        }
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
fn response_capability(response: &Response, expected: u64) -> Option<u64> {
    match response {
        Response::Unlocked => Some(CAP_UNLOCK),
        Response::AlreadyConsumed { .. } => Some(expected),
        Response::Status { .. } => Some(CAP_STATUS),
        Response::PolicyApplied => Some(CAP_POLICY),
        Response::Rejected { .. } => None,
    }
}

pub struct Session {
    role: Role,
    capabilities: u64,
    next_request: u32,
    started: bool,
    pending_requests: BTreeMap<u32, u64>,
    last_request_id: u32,
    channel: NoiseChannel,
}
impl Session {
    pub fn initiator(
        private: &[u8; 32],
        lock_public: &[u8; 32],
        capabilities: u64,
    ) -> Result<Self, Error> {
        if capabilities == 0 || capabilities & !KNOWN_CAPABILITIES != 0 {
            return Err(Error::UnsupportedCapability);
        }
        Ok(Self {
            role: Role::Initiator,
            capabilities,
            next_request: 1,
            started: false,
            pending_requests: BTreeMap::new(),
            last_request_id: 0,
            channel: NoiseChannel::initiator(private, lock_public)?,
        })
    }
    pub fn responder(private: &[u8; 32], capabilities: u64) -> Result<Self, Error> {
        if capabilities == 0 || capabilities & !KNOWN_CAPABILITIES != 0 {
            return Err(Error::UnsupportedCapability);
        }
        Ok(Self {
            role: Role::Responder,
            capabilities,
            next_request: 1,
            started: false,
            pending_requests: BTreeMap::new(),
            last_request_id: 0,
            channel: NoiseChannel::responder(private)?,
        })
    }
    pub fn start(&mut self) -> Result<Vec<u8>, Error> {
        if self.role != Role::Initiator || self.started {
            return Err(Error::InvalidState);
        }
        self.started = true;
        encode_packet(&Packet {
            kind: KIND_HANDSHAKE,
            request_id: 0,
            capabilities: 0,
            payload: self.channel.write(&[])?,
        })
    }
    pub fn receive(&mut self, input: &[u8]) -> Result<(Vec<SessionEvent>, Option<Vec<u8>>), Error> {
        let packet = decode_packet(input)?;
        if packet.kind == KIND_HANDSHAKE {
            if self.role == Role::Initiator {
                if !self.started {
                    return Err(Error::InvalidState);
                }
            } else if self.started {
                return Err(Error::InvalidState);
            }
        } else if !self.started {
            return Err(Error::InvalidState);
        }
        if packet.kind == KIND_REQUEST
            && (self.role != Role::Responder || packet.request_id <= self.last_request_id)
        {
            return Err(Error::InvalidState);
        }
        if packet.kind == KIND_RESPONSE
            && (self.role != Role::Initiator
                || !self.pending_requests.contains_key(&packet.request_id))
        {
            return Err(Error::InvalidState);
        }
        let clear = if packet.kind == KIND_HANDSHAKE {
            self.channel.read(&packet.payload)?
        } else {
            if !self.channel.is_transport() {
                return Err(Error::InvalidState);
            }
            self.channel.read(&packet.payload)?
        };
        let mut events = Vec::new();
        let mut reply = None;
        if packet.kind == KIND_HANDSHAKE {
            if !clear.is_empty() {
                return Err(Error::InvalidPayload);
            }
            self.started = true;
            if self.role == Role::Responder {
                reply = Some(encode_packet(&Packet {
                    kind: KIND_HANDSHAKE,
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
        let envelope = cbor::decode(&clear)?;
        let fields = cbor::fields(&envelope, 4)?;
        if cbor::u32_value(&fields[0])? != packet.kind as u32
            || cbor::u32_value(&fields[1])? != packet.request_id
            || cbor::number(&fields[2])? != packet.capabilities
        {
            return Err(Error::InvalidPayload);
        }
        let value = &fields[3];
        let peer = self.channel.peer_static()?;
        match packet.kind {
            KIND_REQUEST => {
                let command = parse_request(value)?;
                if command.capability() & packet.capabilities != command.capability()
                    || command.capability() & self.capabilities != command.capability()
                {
                    return Err(Error::UnsupportedCapability);
                }
                if self.pending_requests.len() >= MAX_PENDING_REQUESTS {
                    return Err(Error::InvalidState);
                }
                self.last_request_id = packet.request_id;
                self.pending_requests
                    .insert(packet.request_id, command.capability());
                events.push(SessionEvent::Request {
                    request_id: packet.request_id,
                    command,
                    peer,
                })
            }
            KIND_RESPONSE => {
                let response = parse_response(value)?;
                let expected = self.pending_requests[&packet.request_id];
                if response_capability(&response, expected)
                    .is_some_and(|cap| cap != expected || cap & packet.capabilities != cap)
                {
                    return Err(Error::InvalidPayload);
                }
                self.pending_requests.remove(&packet.request_id);
                events.push(SessionEvent::Response {
                    request_id: packet.request_id,
                    response,
                })
            }
            _ => return Err(Error::InvalidPayload),
        }
        Ok((events, reply))
    }
    pub fn send(&mut self, command: Command) -> Result<(u32, Vec<u8>), Error> {
        validate_command(&command)?;
        if self.role != Role::Initiator
            || !self.channel.is_transport()
            || command.capability() & self.capabilities != command.capability()
            || self.pending_requests.len() >= MAX_PENDING_REQUESTS
        {
            return Err(Error::InvalidState);
        }
        let request_id = self.next_request;
        self.next_request = self
            .next_request
            .checked_add(1)
            .ok_or(Error::InvalidState)?;
        let body = cbor::encode(&authenticated_value(
            KIND_REQUEST,
            request_id,
            self.capabilities,
            request_value(&command),
        ))?;
        let payload = self.channel.write(&body)?;
        let packet = encode_packet(&Packet {
            kind: KIND_REQUEST,
            request_id,
            capabilities: self.capabilities,
            payload,
        })?;
        self.pending_requests
            .insert(request_id, command.capability());
        Ok((request_id, packet))
    }
    /// Return the encoded request size without advancing the Noise state.
    pub fn request_size(&self, command: &Command) -> Result<usize, Error> {
        validate_command(command)?;
        if self.role != Role::Initiator
            || !self.channel.is_transport()
            || command.capability() & self.capabilities != command.capability()
            || self.pending_requests.len() >= MAX_PENDING_REQUESTS
        {
            return Err(Error::InvalidState);
        }
        let request_id = self.next_request;
        let body = cbor::encode(&authenticated_value(
            KIND_REQUEST,
            request_id,
            self.capabilities,
            request_value(command),
        ))?;
        if body.len() > MAX_MESSAGE_SIZE - 128 {
            return Err(Error::ObjectTooLarge);
        }
        let payload_len = body.len().checked_add(16).ok_or(Error::ObjectTooLarge)?;
        encode_packet(&Packet {
            kind: KIND_REQUEST,
            request_id,
            capabilities: self.capabilities,
            payload: vec![0; payload_len],
        })
        .map(|packet| packet.len())
    }
    pub fn respond(&mut self, request_id: u32, response: Response) -> Result<Vec<u8>, Error> {
        if self.role != Role::Responder
            || !self.channel.is_transport()
            || !self.pending_requests.contains_key(&request_id)
        {
            return Err(Error::InvalidState);
        }
        let expected = self.pending_requests[&request_id];
        let response_capability = response_capability(&response, expected);
        if response_capability.is_some_and(|cap| cap != expected) {
            return Err(Error::InvalidPayload);
        }
        if response_capability.is_some_and(|cap| cap & self.capabilities == 0) {
            return Err(Error::UnsupportedCapability);
        }
        let body = cbor::encode(&authenticated_value(
            KIND_RESPONSE,
            request_id,
            self.capabilities,
            response_value(&response),
        ))?;
        let payload = self.channel.write(&body)?;
        let packet = encode_packet(&Packet {
            kind: KIND_RESPONSE,
            request_id,
            capabilities: self.capabilities,
            payload,
        })?;
        self.pending_requests.remove(&request_id);
        Ok(packet)
    }
    pub fn peer_static(&self) -> Result<SubjectKey, Error> {
        self.channel.peer_static()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn v2_packet_matches_fixed_wire_bytes() {
        let encoded = [
            0x86, 0x02, 0x01, 0x01, 0x18, 0x18, 0x07, 0x43, 0xaa, 0xbb, 0xcc,
        ];
        let packet = Packet {
            kind: KIND_REQUEST,
            request_id: 24,
            capabilities: CAP_UNLOCK | CAP_STATUS | CAP_POLICY,
            payload: vec![0xaa, 0xbb, 0xcc],
        };
        assert_eq!(encode_packet(&packet).unwrap(), encoded);
        assert_eq!(decode_packet(&encoded), Ok(packet));
    }

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

    #[test]
    fn roles_and_request_ids_are_enforced() {
        let mut initiator = Session::initiator(
            &[3; 32],
            &openlock_crypto::static_public(&[4; 32]),
            CAP_UNLOCK,
        )
        .unwrap();
        let mut responder = Session::responder(&[4; 32], CAP_UNLOCK).unwrap();
        let first = initiator.start().unwrap();
        let (_, second) = responder.receive(&first).unwrap();
        initiator.receive(&second.unwrap()).unwrap();
        assert_eq!(
            responder.send(Command::Unlock(AccessRequest {
                credential: vec![1],
                requested_use: None
            })),
            Err(Error::InvalidState)
        );
        let (id, request) = initiator
            .send(Command::Unlock(AccessRequest {
                credential: vec![1],
                requested_use: None,
            }))
            .unwrap();
        responder.receive(&request).unwrap();
        assert_eq!(
            responder.respond(id + 1, Response::Unlocked),
            Err(Error::InvalidState)
        );
        let response = responder.respond(id, Response::Unlocked).unwrap();
        initiator.receive(&response).unwrap();
        assert_eq!(initiator.receive(&response), Err(Error::InvalidState));
    }

    #[test]
    fn packet_invariants_are_rejected() {
        assert_eq!(
            encode_packet(&Packet {
                kind: KIND_HANDSHAKE,
                request_id: 1,
                capabilities: 0,
                payload: vec![1]
            }),
            Err(Error::InvalidPayload)
        );
        assert_eq!(
            encode_packet(&Packet {
                kind: KIND_REQUEST,
                request_id: 1,
                capabilities: 8,
                payload: vec![1]
            }),
            Err(Error::InvalidPayload)
        );
        assert_eq!(
            encode_packet(&Packet {
                kind: KIND_RESPONSE,
                request_id: 1,
                capabilities: CAP_UNLOCK,
                payload: vec![]
            }),
            Err(Error::InvalidPayload)
        );
    }

    #[test]
    fn encrypted_metadata_tampering_is_rejected() {
        let mut initiator = Session::initiator(
            &[3; 32],
            &openlock_crypto::static_public(&[4; 32]),
            CAP_UNLOCK,
        )
        .unwrap();
        let mut responder = Session::responder(&[4; 32], CAP_UNLOCK).unwrap();
        let first = initiator.start().unwrap();
        let (_, second) = responder.receive(&first).unwrap();
        initiator.receive(&second.unwrap()).unwrap();
        let (request_id, request) = initiator
            .send(Command::Unlock(AccessRequest {
                credential: vec![1, 2, 3],
                requested_use: None,
            }))
            .unwrap();
        let packet = decode_packet(&request).unwrap();
        let forged = encode_packet(&Packet {
            request_id: request_id + 1,
            ..packet
        })
        .unwrap();
        assert_eq!(responder.receive(&forged), Err(Error::InvalidPayload));
    }

    #[test]
    fn already_consumed_uses_pending_status_capability() {
        let mut initiator = Session::initiator(
            &[3; 32],
            &openlock_crypto::static_public(&[4; 32]),
            CAP_STATUS,
        )
        .unwrap();
        let mut responder = Session::responder(&[4; 32], CAP_STATUS).unwrap();
        let first = initiator.start().unwrap();
        let (_, second) = responder.receive(&first).unwrap();
        initiator.receive(&second.unwrap()).unwrap();
        let (request_id, request) = initiator
            .send(Command::Status(AccessRequest {
                credential: vec![1, 2, 3],
                requested_use: Some(0),
            }))
            .unwrap();
        responder.receive(&request).unwrap();
        let response = responder
            .respond(request_id, Response::AlreadyConsumed { next_use: 1 })
            .unwrap();
        let (events, _) = initiator.receive(&response).unwrap();
        assert!(matches!(
            events.first(),
            Some(SessionEvent::Response {
                response: Response::AlreadyConsumed { next_use: 1 },
                ..
            })
        ));
    }
}
