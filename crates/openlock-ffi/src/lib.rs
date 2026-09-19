//! C ABI for v4 sessions. Receive queues output/events; drain without reprocessing input.
#![allow(clippy::missing_safety_doc)]
use openlock_crypto::{
    cbor::{self, Value},
    wire::{decode_wire, encode_wire, Wire},
    SigningKey,
};
use openlock_protocol::{Session, SessionEvent};
use openlock_types::*;
use std::{collections::VecDeque, ptr, slice};

pub struct OpenLockSession {
    inner: Session,
    events: VecDeque<Vec<u8>>,
    output: Option<Vec<u8>>,
}
unsafe fn input<'a>(data: *const u8, len: usize) -> Result<&'a [u8], i32> {
    if len > MAX_MESSAGE_SIZE {
        return Err(Error::ObjectTooLarge.code() as i32);
    }
    if len == 0 {
        Ok(&[])
    } else if data.is_null() {
        Err(-1)
    } else {
        Ok(slice::from_raw_parts(data, len))
    }
}
unsafe fn capacity(out: *mut u8, cap: usize, len: *mut usize, required: usize) -> Result<(), i32> {
    if len.is_null() || cap > 0 && out.is_null() {
        return Err(-1);
    }
    *len = required;
    if cap < required {
        return Err(-2);
    }
    Ok(())
}
unsafe fn copy(bytes: &[u8], out: *mut u8, cap: usize, len: *mut usize) -> i32 {
    if let Err(code) = capacity(out, cap, len, bytes.len()) {
        return code;
    }
    if !bytes.is_empty() {
        ptr::copy_nonoverlapping(bytes.as_ptr(), out, bytes.len());
    }
    0
}
fn code(e: Error) -> i32 {
    e.code() as i32
}
fn event_bytes(event: &SessionEvent) -> Result<Vec<u8>, Error> {
    let (tag, id, peer, body) = match event {
        SessionEvent::HandshakeComplete { peer } => (1, 0, peer.value(), Value::Null),
        SessionEvent::Request {
            request_id,
            command,
            peer,
        } => (2, *request_id, peer.value(), command.value()),
        SessionEvent::Response {
            request_id,
            response,
        } => (3, *request_id, Value::Null, response.value()),
    };
    cbor::encode_limit(
        &cbor::array(vec![cbor::uint(tag), cbor::uint(id as u64), peer, body]),
        MAX_EVENT_SIZE,
    )
}
#[no_mangle]
pub unsafe extern "C" fn openlock_session_initiator(
    private: *const u8,
    public: *const u8,
    capabilities: u64,
    out: *mut *mut OpenLockSession,
) -> i32 {
    if private.is_null() || public.is_null() || out.is_null() {
        return -1;
    }
    *out = ptr::null_mut();
    match Session::initiator(
        &*(private as *const [u8; 32]),
        &*(public as *const [u8; 32]),
        capabilities,
    ) {
        Ok(inner) => {
            *out = Box::into_raw(Box::new(OpenLockSession {
                inner,
                events: VecDeque::new(),
                output: None,
            }));
            0
        }
        Err(e) => code(e),
    }
}
#[no_mangle]
pub unsafe extern "C" fn openlock_session_responder(
    private: *const u8,
    capabilities: u64,
    out: *mut *mut OpenLockSession,
) -> i32 {
    if private.is_null() || out.is_null() {
        return -1;
    }
    *out = ptr::null_mut();
    match Session::responder(&*(private as *const [u8; 32]), capabilities) {
        Ok(inner) => {
            *out = Box::into_raw(Box::new(OpenLockSession {
                inner,
                events: VecDeque::new(),
                output: None,
            }));
            0
        }
        Err(e) => code(e),
    }
}
#[no_mangle]
pub unsafe extern "C" fn openlock_session_start(
    session: *mut OpenLockSession,
    out: *mut u8,
    cap: usize,
    len: *mut usize,
) -> i32 {
    let Some(s) = session.as_mut() else { return -1 };
    let required = match s.inner.start_size() {
        Ok(n) => n,
        Err(e) => return code(e),
    };
    if let Err(e) = capacity(out, cap, len, required) {
        return e;
    }
    match s.inner.start() {
        Ok(bytes) => copy(&bytes, out, cap, len),
        Err(e) => code(e),
    }
}
#[no_mangle]
pub unsafe extern "C" fn openlock_session_send(
    session: *mut OpenLockSession,
    data: *const u8,
    data_len: usize,
    id: *mut u32,
    out: *mut u8,
    cap: usize,
    len: *mut usize,
) -> i32 {
    let Some(s) = session.as_mut() else { return -1 };
    if id.is_null() {
        return -1;
    }
    let bytes = match input(data, data_len) {
        Ok(b) => b,
        Err(e) => return e,
    };
    let command: Command = match decode_wire(bytes) {
        Ok(c) => c,
        Err(e) => return code(e),
    };
    let required = match s.inner.request_size(&command) {
        Ok(n) => n,
        Err(e) => return code(e),
    };
    if let Err(e) = capacity(out, cap, len, required) {
        return e;
    }
    match s.inner.send(command) {
        Ok((request_id, packet)) => {
            *id = request_id;
            copy(&packet, out, cap, len)
        }
        Err(e) => code(e),
    }
}
#[no_mangle]
pub unsafe extern "C" fn openlock_session_respond(
    session: *mut OpenLockSession,
    id: u32,
    data: *const u8,
    data_len: usize,
    out: *mut u8,
    cap: usize,
    len: *mut usize,
) -> i32 {
    let Some(s) = session.as_mut() else { return -1 };
    let bytes = match input(data, data_len) {
        Ok(b) => b,
        Err(e) => return e,
    };
    let response: Response = match decode_wire(bytes) {
        Ok(r) => r,
        Err(e) => return code(e),
    };
    let required = match s.inner.response_size(id, &response) {
        Ok(n) => n,
        Err(e) => return code(e),
    };
    if let Err(e) = capacity(out, cap, len, required) {
        return e;
    }
    match s.inner.respond(id, response) {
        Ok(packet) => copy(&packet, out, cap, len),
        Err(e) => code(e),
    }
}
#[no_mangle]
pub unsafe extern "C" fn openlock_session_receive(
    session: *mut OpenLockSession,
    data: *const u8,
    data_len: usize,
) -> i32 {
    let Some(s) = session.as_mut() else { return -1 };
    if s.output.is_some() || !s.events.is_empty() {
        return code(Error::Busy);
    }
    let bytes = match input(data, data_len) {
        Ok(b) => b,
        Err(e) => return e,
    };
    match s.inner.receive(bytes) {
        Ok((events, reply)) => {
            for event in events {
                match event_bytes(&event) {
                    Ok(bytes) => s.events.push_back(bytes),
                    Err(e) => {
                        s.inner.close();
                        return code(e);
                    }
                }
            }
            s.output = reply;
            0
        }
        Err(e) => {
            s.inner.close();
            code(e)
        }
    }
}
#[no_mangle]
pub unsafe extern "C" fn openlock_session_take_output(
    session: *mut OpenLockSession,
    out: *mut u8,
    cap: usize,
    len: *mut usize,
) -> i32 {
    let Some(s) = session.as_mut() else { return -1 };
    let bytes = s.output.as_deref().unwrap_or(&[]);
    let result = copy(bytes, out, cap, len);
    if result == 0 {
        s.output = None;
    }
    result
}
#[no_mangle]
pub unsafe extern "C" fn openlock_session_take_event(
    session: *mut OpenLockSession,
    out: *mut u8,
    cap: usize,
    len: *mut usize,
) -> i32 {
    let Some(s) = session.as_mut() else { return -1 };
    let bytes = s.events.front().map_or(&[][..], |v| v.as_slice());
    let result = copy(bytes, out, cap, len);
    if result == 0 {
        s.events.pop_front();
    }
    result
}
#[no_mangle]
pub unsafe extern "C" fn openlock_session_free(session: *mut OpenLockSession) {
    if !session.is_null() {
        drop(Box::from_raw(session));
    }
}
#[no_mangle]
pub unsafe extern "C" fn openlock_encode_command(
    credential: *const u8,
    credential_len: usize,
    sequence: u64,
    action: *const u8,
    action_len: usize,
    out: *mut u8,
    cap: usize,
    len: *mut usize,
) -> i32 {
    let credential = match input(credential, credential_len) {
        Ok(b) => b,
        Err(e) => return e,
    };
    let action = match input(action, action_len) {
        Ok(b) => b,
        Err(e) => return e,
    };
    let result = (|| {
        let action: Action = decode_wire(action)?;
        let c = Command {
            credential: credential.to_vec(),
            sequence: if sequence == 0 { None } else { Some(sequence) },
            action,
        };
        c.validate()?;
        encode_wire(&c)
    })();
    match result {
        Ok(bytes) => copy(&bytes, out, cap, len),
        Err(e) => code(e),
    }
}
#[no_mangle]
pub unsafe extern "C" fn openlock_public_key(kind: u32, private: *const u8, out: *mut u8) -> i32 {
    if private.is_null() || out.is_null() {
        return -1;
    }
    let key = &*(private as *const [u8; 32]);
    let public = match kind {
        0 => openlock_crypto::static_public(key),
        1 => SigningKey::from_bytes(key).verifying_key().to_bytes(),
        _ => return -1,
    };
    ptr::copy_nonoverlapping(public.as_ptr(), out, 32);
    0
}
/// Sign a canonical payload: 0 grant, 1 policy, 2 firmware manifest.
#[no_mangle]
pub unsafe extern "C" fn openlock_sign(
    kind: u32,
    private: *const u8,
    data: *const u8,
    data_len: usize,
    out: *mut u8,
    cap: usize,
    len: *mut usize,
) -> i32 {
    if private.is_null() {
        return -1;
    }
    let bytes = match input(data, data_len) {
        Ok(b) => b,
        Err(e) => return e,
    };
    let key = SigningKey::from_bytes(&*(private as *const [u8; 32]));
    let result = (|| {
        let value = cbor::decode(bytes)?;
        match kind {
            0 => openlock_crypto::sign_grant(&key, &openlock_crypto::cose::parse_grant(&value)?),
            1 => {
                let signed =
                    openlock_crypto::cose::sign_object(&key, b"openlock:v2:policy", &value)?;
                openlock_crypto::read_policy(&key.verifying_key(), &signed)?;
                Ok(signed)
            }
            2 => openlock_crypto::firmware::sign_manifest(&key, &FirmwareManifest::parse(&value)?),
            3 | 4 => openlock_crypto::sign_trust_payload(&key, kind, &value),
            _ => Err(Error::InvalidPayload),
        }
    })();
    match result {
        Ok(bytes) => copy(&bytes, out, cap, len),
        Err(e) => code(e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    unsafe fn drain(s: *mut OpenLockSession, event: bool) -> Vec<u8> {
        let mut n = 0;
        let call = if event {
            openlock_session_take_event
        } else {
            openlock_session_take_output
        };
        let result = call(s, ptr::null_mut(), 0, &mut n);
        assert!(result == 0 || result == -2);
        let mut data = vec![0; n];
        assert_eq!(call(s, data.as_mut_ptr(), n, &mut n), 0);
        data
    }
    #[test]
    fn near_limit_wire_request_preserves_a_larger_authenticated_event() {
        use openlock_protocol::{decode_packet, encode_packet, Packet};
        let issuer = SigningKey::from_bytes(&[9; 32]);
        let peer = openlock_crypto::static_public(&[3; 32]);
        let credential = openlock_crypto::sign_grant(
            &issuer,
            &Grant {
                credential_id: CredentialId([2; 16]),
                lock_id: LockId([1; 16]),
                subject_key: SubjectKey(peer),
                rights: RIGHTS_CREDENTIALS,
                epoch: 0,
                validity: None,
                max_uses: None,
            },
        )
        .unwrap();
        let policy = PolicyUpdate {
            lock_id: LockId([1; 16]),
            epoch: 0,
            version: 1,
            revoked: (0..223u16)
                .map(|n| {
                    let mut id = [0; 16];
                    id[..2].copy_from_slice(&n.to_le_bytes());
                    CredentialId(id)
                })
                .collect(),
        };
        let command = Command {
            credential,
            sequence: Some(1),
            action: Action::ApplyPolicy(openlock_crypto::sign_policy(&issuer, &policy).unwrap()),
        };
        let clear = cbor::encode(&cbor::array(vec![
            cbor::uint(1),
            cbor::uint(1),
            cbor::uint(4),
            command.value(),
        ]))
        .unwrap();
        let public = openlock_crypto::static_public(&[4; 32]);
        // An interoperating peer may use the full wire limit, unlike the Rust
        // sender's conservative sizing budget. Exercise an actual Noise packet.
        let mut noise = snow::Builder::new("Noise_IK_25519_ChaChaPoly_SHA256".parse().unwrap())
            .prologue(b"OpenLock/v4/profile1")
            .unwrap()
            .local_private_key(&[3; 32])
            .unwrap()
            .remote_public_key(&public)
            .unwrap()
            .build_initiator()
            .unwrap();
        let mut encrypted = [0; MAX_MESSAGE_SIZE];
        let size = noise.write_message(&[], &mut encrypted).unwrap();
        let first = encode_packet(&Packet {
            kind: 0,
            request_id: 0,
            capabilities: 0,
            payload: encrypted[..size].to_vec(),
        })
        .unwrap();
        unsafe {
            let mut native = ptr::null_mut();
            assert_eq!(
                openlock_session_responder([4; 32].as_ptr(), 4, &mut native),
                0
            );
            assert_eq!(
                openlock_session_receive(native, first.as_ptr(), first.len()),
                0
            );
            drain(native, true);
            let reply = drain(native, false);
            noise
                .read_message(&decode_packet(&reply).unwrap().payload, &mut encrypted)
                .unwrap();
            let mut transport = noise.into_transport_mode().unwrap();
            let size = transport.write_message(&clear, &mut encrypted).unwrap();
            let packet = encode_packet(&Packet {
                kind: 1,
                request_id: 1,
                capabilities: 4,
                payload: encrypted[..size].to_vec(),
            })
            .unwrap();
            assert!(packet.len() <= MAX_MESSAGE_SIZE);
            assert_eq!(
                openlock_session_receive(native, packet.as_ptr(), packet.len()),
                0
            );
            let mut small = [0xcc; MAX_MESSAGE_SIZE];
            let mut required = 0;
            assert_eq!(
                openlock_session_take_event(native, small.as_mut_ptr(), small.len(), &mut required),
                -2
            );
            assert!(required > MAX_MESSAGE_SIZE && required <= MAX_EVENT_SIZE);
            assert!(small.iter().all(|byte| *byte == 0xcc));
            let event = drain(native, true);
            assert_eq!(event.len(), required);
            let value = cbor::decode_limit(&event, MAX_EVENT_SIZE).unwrap();
            let fields = cbor::fields(&value, 4).unwrap();
            assert_eq!(cbor::number(&fields[0]).unwrap(), 2);
            assert_eq!(cbor::number(&fields[1]).unwrap(), 1);
            assert_eq!(cbor::fixed::<32>(&fields[2]).unwrap(), peer);
            assert_eq!(Command::parse(&fields[3]).unwrap(), command);
            assert!(drain(native, true).is_empty());
            openlock_session_free(native);
        }
    }
    #[test]
    fn capacity_queries_preserve_noise_and_complete_events() {
        unsafe {
            let mut a = ptr::null_mut();
            let mut b = ptr::null_mut();
            let public = openlock_crypto::static_public(&[4; 32]);
            assert_eq!(
                openlock_session_initiator(
                    [3; 32].as_ptr(),
                    public.as_ptr(),
                    KNOWN_CAPABILITIES,
                    &mut a
                ),
                0
            );
            assert_eq!(
                openlock_session_responder([4; 32].as_ptr(), KNOWN_CAPABILITIES, &mut b),
                0
            );
            let mut length = 0;
            assert_eq!(
                openlock_session_start(a, ptr::null_mut(), 0, &mut length),
                -2
            );
            let mut short = vec![0xaa; length - 1];
            assert_eq!(
                openlock_session_start(a, short.as_mut_ptr(), short.len(), &mut length),
                -2
            );
            assert!(short.iter().all(|b| *b == 0xaa));
            let mut first = vec![0; length];
            assert_eq!(
                openlock_session_start(a, first.as_mut_ptr(), first.len(), &mut length),
                0
            );
            assert_eq!(openlock_session_receive(b, first.as_ptr(), first.len()), 0);
            assert_eq!(
                openlock_session_receive(b, first.as_ptr(), first.len()),
                Error::Busy.code() as i32
            );
            let mut needed = 0;
            assert_eq!(
                openlock_session_take_event(b, ptr::null_mut(), 0, &mut needed),
                -2
            );
            let mut small = [0xcc; 1];
            assert_eq!(
                openlock_session_take_event(b, small.as_mut_ptr(), 1, &mut needed),
                -2
            );
            assert_eq!(small, [0xcc]);
            assert!(!drain(b, true).is_empty());
            let reply = drain(b, false);
            assert_eq!(openlock_session_receive(a, reply.as_ptr(), reply.len()), 0);
            assert!(!drain(a, true).is_empty());
            let c = Command {
                credential: vec![1],
                sequence: Some(1),
                action: Action::Unlock,
            };
            let bytes = encode_wire(&c).unwrap();
            let mut id = 0;
            assert_eq!(
                openlock_session_send(
                    a,
                    bytes.as_ptr(),
                    bytes.len(),
                    &mut id,
                    ptr::null_mut(),
                    0,
                    &mut length
                ),
                -2
            );
            let mut packet = vec![0; length];
            assert_eq!(
                openlock_session_send(
                    a,
                    bytes.as_ptr(),
                    bytes.len(),
                    &mut id,
                    packet.as_mut_ptr(),
                    packet.len(),
                    &mut length
                ),
                0
            );
            assert_eq!(id, 1);
            assert_eq!(
                openlock_session_receive(b, packet.as_ptr(), packet.len()),
                0
            );
            let event = drain(b, true);
            let v = cbor::decode(&event).unwrap();
            let f = cbor::fields(&v, 4).unwrap();
            assert_eq!(Command::parse(&f[3]).unwrap(), c);
            let r = encode_wire(&Response {
                opcode: 0,
                result: Err(Error::Jammed.code()),
            })
            .unwrap();
            assert_eq!(
                openlock_session_respond(
                    b,
                    id,
                    r.as_ptr(),
                    r.len(),
                    ptr::null_mut(),
                    0,
                    &mut length
                ),
                -2
            );
            let mut response = vec![0; length];
            assert_eq!(
                openlock_session_respond(
                    b,
                    id,
                    r.as_ptr(),
                    r.len(),
                    response.as_mut_ptr(),
                    response.len(),
                    &mut length
                ),
                0
            );
            assert_eq!(
                openlock_session_receive(a, response.as_ptr(), response.len()),
                0
            );
            let event = drain(a, true);
            let v = cbor::decode(&event).unwrap();
            let f = cbor::fields(&v, 4).unwrap();
            assert_eq!(
                Response::parse(&f[3]).unwrap().result,
                Err(Error::Jammed.code())
            );
            openlock_session_free(a);
            openlock_session_free(b);
        }
    }
}
