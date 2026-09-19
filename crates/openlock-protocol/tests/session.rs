use openlock_protocol::*;
use openlock_types::*;
fn pair() -> (Session, Session) {
    let mut a = Session::initiator(
        &[3; 32],
        &openlock_crypto::static_public(&[4; 32]),
        KNOWN_CAPABILITIES,
    )
    .unwrap();
    let mut b = Session::responder(&[4; 32], KNOWN_CAPABILITIES).unwrap();
    let size = a.start_size().unwrap();
    let first = a.start().unwrap();
    assert_eq!(first.len(), size);
    let (_, reply) = b.receive(&first).unwrap();
    a.receive(&reply.unwrap()).unwrap();
    (a, b)
}
fn command() -> Command {
    Command {
        credential: vec![1, 2, 3],
        sequence: Some(1),
        action: Action::Unlock,
    }
}
#[test]
fn fixed_v4_wire_and_body() {
    let p = Packet {
        kind: KIND_REQUEST,
        request_id: 24,
        capabilities: 7,
        payload: vec![0xaa, 0xbb, 0xcc],
    };
    assert_eq!(
        encode_packet(&p).unwrap(),
        [0x86, 4, 1, 1, 0x18, 0x18, 7, 0x43, 0xaa, 0xbb, 0xcc]
    );
    assert_eq!(
        encode_wire(&command()).unwrap(),
        [0x83, 0x43, 1, 2, 3, 1, 0x81, 0]
    );
}
#[test]
fn roundtrip_sizes_roles_and_replays() {
    let (mut a, mut b) = pair();
    let expected = a.request_size(&command()).unwrap();
    let (id, p) = a.send(command()).unwrap();
    assert_eq!(p.len(), expected);
    let (events, _) = b.receive(&p).unwrap();
    assert!(matches!(&events[0],SessionEvent::Request{command:c,..} if c==&command()));
    assert_eq!(b.send(command()), Err(Error::InvalidState));
    let r = Response {
        opcode: 0,
        result: Err(Error::Busy.code()),
    };
    assert_eq!(b.respond(id + 1, r.clone()), Err(Error::InvalidState));
    let n = b.response_size(id, &r).unwrap();
    let packet = b.respond(id, r.clone()).unwrap();
    assert_eq!(packet.len(), n);
    assert!(
        matches!(&a.receive(&packet).unwrap().0[0],SessionEvent::Response{response,..} if response==&r)
    );
    assert!(a.receive(&packet).is_err());
}
#[test]
fn tampering_wrong_capabilities_and_response_opcode_rejected() {
    let (mut a, mut b) = pair();
    let (id, p) = a.send(command()).unwrap();
    let mut forged = decode_packet(&p).unwrap();
    forged.request_id += 1;
    assert_eq!(
        b.receive(&encode_packet(&forged).unwrap()),
        Err(Error::InvalidPayload)
    );
    let (mut a, mut b) = pair();
    let (_, p) = a.send(command()).unwrap();
    b.receive(&p).unwrap();
    assert!(b
        .respond(
            id,
            Response {
                opcode: 3,
                result: Err(1)
            }
        )
        .is_err());
    assert_eq!(
        encode_packet(&Packet {
            kind: 1,
            request_id: 1,
            capabilities: 1 << 63,
            payload: vec![1]
        }),
        Err(Error::InvalidPayload)
    );
}
#[test]
fn malformed_and_oversize_messages_do_not_advance_sender() {
    for v in [&[][..], &[0x80], &[0x9f, 0xff], &[3, 1, 0, 0]] {
        assert!(decode_wire::<Command>(v).is_err());
    }
    let (mut a, mut b) = pair();
    let mut c = command();
    c.credential = vec![0; 4096];
    assert_eq!(a.send(c), Err(Error::ObjectTooLarge));
    let (id, p) = a.send(command()).unwrap();
    assert_eq!(id, 1);
    assert!(b.receive(&p).is_ok());
}

#[test]
fn wrong_qr_public_key_cannot_complete_the_handshake() {
    let mut client = Session::initiator(
        &[3; 32],
        &openlock_crypto::static_public(&[5; 32]),
        KNOWN_CAPABILITIES,
    )
    .unwrap();
    let mut actual_lock = Session::responder(&[4; 32], KNOWN_CAPABILITIES).unwrap();
    assert_eq!(
        actual_lock.receive(&client.start().unwrap()),
        Err(Error::Noise)
    );
}
