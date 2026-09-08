# OpenLock protocol v2

OpenLock treats BLE GATT and NFC ISO-DEP as byte transports. The protocol
state machine is shared by both; only the frame codec changes. A complete
packet is a definite CBOR array:

```text
[version, profile, kind, request_id, capabilities, payload]
```

`version` is `2`, `profile` is `1`, and `kind` is handshake, request, or
response. Handshake payloads are Noise IK messages. Once the handshake is
complete, request and response payloads are encrypted Noise transport messages.
Unknown versions, profiles, kinds, malformed CBOR and packets over 4096 bytes
are rejected.

## Session

The initiator is configured with its static X25519 private key and the trusted
lock public key. The responder is configured with its static private key. Both
use `Noise_IK_25519_ChaChaPoly_SHA256` and the v2 prologue. The responder's
authenticated static key is exposed to authorization as `SubjectKey`.

```text
initiator -> responder: Noise IK message 1
responder -> initiator: Noise IK message 2
initiator -> responder: encrypted Request
responder -> initiator: encrypted Response
```

The application must keep each `Session` state for one direction's nonce
sequence and must discard it after an authentication error or timeout.

## NFC bootstrap

A passive NDEF tag may carry a signed CBOR record with the lock ID, key ID,
monotonic key version, X25519 public key, independent Ed25519 rotation key,
capabilities and issuer signature. The application verifies the record against
its configured issuer root before pinning it locally. No display or online CA
is required. A direct-pinning trust store is also supported for installations
that provision the public key through a factory or QR workflow.

Full NFC sessions use ISO-DEP/APDU chunks with a sequence byte and total length.
Platform code provides reader/card-emulation callbacks; this crate only validates
and reassembles chunks.

## Authorization

The lock verifies the signed grant before checking lock ID, epoch, rights,
revocation, time and the Noise peer key. Counted grants commit their increment
through `PersistentState::commit` before actuator invocation. A stale use
sequence returns `AlreadyConsumed` and cannot emit a second actuator event.
