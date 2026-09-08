# OpenLock Protocol v2

This document is the wire contract implemented by `openlock-protocol`.
BLE GATT and NFC ISO-DEP are byte transports: a transport MUST deliver one
complete protocol message to `Session::receive`, and MUST send each returned
byte string without modification.

## Encoding

Every message is a definite, canonical CBOR array of exactly six items:

```text
[version, profile, kind, request_id, capabilities, payload]
```

| item | type | value and meaning |
| --- | --- | --- |
| `version` | unsigned integer | `2` (`PROTOCOL_VERSION`) |
| `profile` | unsigned integer | `1` (`PROFILE`) |
| `kind` | unsigned integer | `0` handshake, `1` request, `2` response |
| `request_id` | unsigned integer | `0` for handshake; non-zero for encrypted messages |
| `capabilities` | unsigned integer | bit mask of `CAP_UNLOCK=1`, `CAP_STATUS=2`, `CAP_POLICY=4` |
| `payload` | byte string | Noise message; never empty; complete packet <= 4096 bytes |

Integers MUST be non-negative and minimally encoded. Indefinite arrays, maps,
strings, tags, floating point values, trailing bytes and unknown capability bits
are rejected. Handshake messages MUST have `request_id=0` and
`capabilities=0`. Requests and responses MUST have a non-zero request ID and at
least one known capability bit.

## Noise session

The session uses `Noise_IK_25519_ChaChaPoly_SHA256` with prologue
`OpenLock/v2/profile1`. The initiator is constructed with its X25519 private key
and the responder's static public key. The responder is constructed with its
private key. The authenticated responder static key is exposed as `SubjectKey`.

The only valid sequence is:

```text
initiator.start() -> handshake 1
responder.receive(handshake 1) -> handshake 2 + HandshakeComplete
initiator.receive(handshake 2) -> HandshakeComplete
initiator.send(request) -> responder.receive(request)
responder.respond(request_id, response) -> initiator.receive(response)
```

Handshake packets are unencrypted Noise handshake messages. Requests and
responses are encrypted Noise transport messages. For an encrypted message,
the plaintext is itself a four-item CBOR array
`[kind, request_id, capabilities, body]`; the receiver MUST compare these
fields with the outer envelope before parsing `body`. This authenticated copy
binds all outer metadata to the Noise AEAD and makes header tampering fail.

A session is one-directional:
the initiator sends requests and receives responses; the responder receives
requests and sends responses. A request ID is unique within a session, and a
response is accepted only for an outstanding request. At most
`MAX_PENDING_REQUESTS` (1024) requests may be outstanding. After an
authentication or protocol error, the application should discard the session
rather than continue with it.

The capability mask in an encrypted request identifies the sender's supported
operations. The command's capability MUST be present in that mask and in the
receiver's configured mask. Responses carry the responder's configured mask.

## Request payloads

After the authenticated four-item envelope is checked, its `body` is a
canonical CBOR array:

```text
Unlock       = [0, credential_cose, requested_use]
Status       = [1, credential_cose, requested_use]
ApplyPolicy  = [2, policy_cose]
```

`credential_cose` and `policy_cose` are non-empty byte strings, each at most
4096 bytes. `requested_use` is either `null` or an unsigned 32-bit integer. A
use number is required for counted grants and MUST be omitted for grants that
do not have a maximum use count. The signed COSE objects are verified by the
authorization layer, not by the transport state machine.

## Response payloads

Responses are canonical CBOR arrays:

```text
[0]                 ; Unlocked
[1, epoch, version] ; Status
[2]                 ; PolicyApplied
[3, next_use]       ; AlreadyConsumed
[4, error_code]     ; Rejected
```

`epoch` and `version` are unsigned 64-bit values. `next_use` and
`error_code` are unsigned 32-bit values. `error_code` uses the stable values
returned by `Error::code()`.

## Authorization and persistence

The lock verifies a grant signature, lock ID, epoch, rights, revocation, time
window and Noise peer key. For a counted grant, the increment is committed via
`PersistentState::commit` before the actuator callback. A stale use number
returns `AlreadyConsumed` and cannot cause a second actuator event. An actuator
failure is reported as `ActuatorFailed`; the durable usage increment is kept.

## NFC bootstrap

The NDEF MIME type is `application/vnd.openlock.bootstrap+cbor`. Its payload is
the canonical CBOR array:

```text
[2, device_id16, key_id_u32, key_version_u32, x25519_public32,
 rotation_public32, capabilities_u64, issuer_key_id_u32, signature]
```

The record is signed with the configured Ed25519 issuer key. X25519 and Ed25519
keys are independent. `key_version` is non-zero and increases monotonically;
unknown capabilities and invalid public keys are rejected. A trust store may
also pin a device key directly after local provisioning. Key rotation enforces
the old key ID, monotonic version and activation interval before committing the
new record.

ISO-DEP fragments contain `[sequence_u8, total_length_be_u16, payload]`, with a
maximum payload of 240 bytes and total message size of 4096 bytes. Fragments
must arrive in sequence and are reassembled before protocol decoding.

BLE fragment writes are bounded by the negotiated ATT MTU. `BleCodec` defaults
to the mandatory 23-byte ATT MTU and reserves the 3-byte ATT/L2CAP overhead and
its 8-byte fragment header, leaving 12 bytes of message data per write. Hosts
MUST call `BleCodec::with_mtu` or `set_mtu` after MTU negotiation when a larger
value is available; a frame never exceeds `att_mtu - 3` bytes.
