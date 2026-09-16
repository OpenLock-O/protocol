# OpenLock protocol

OpenLock is an offline BLE/NFC access protocol with two authentication modes:
**encrypted sessions** and **plaintext TOTP**. A deployment selects one or both
through trusted configuration according to its access policy and hardware
requirements. This document defines their shared rules and complete wire
contracts. `MUST` denotes an implementation requirement.

| Authentication mode | Credential | Operations | Communication |
| --- | --- | --- | --- |
| [Encrypted sessions](#encrypted-sessions) | Holder-bound signed grant and Noise peer key | Unlock, Status, ApplyPolicy; device trust and key rotation | Noise handshake, authenticated/encrypted messages, bounded BLE/NFC fragments |
| [TOTP](#totp) | Unique shared key per lock and credential | Unlock; trusted local provisioning and management | One 18-byte plaintext request and one 15-byte unauthenticated result |

## Shared access rules

The host MUST associate its BLE/NFC endpoints, provisioned credentials and
local authorization policy with the configured authentication mode. Enabling
both library features does not itself enable both modes on a lock. Separate
characteristics or APDU routes can make this association explicit; an endpoint
that supports both needs trusted configuration for each accepted mode.

The access path is: parse a complete message, authenticate the requester,
validate authorization, persist any required credential consumption, and then
invoke the actuator. Packet parsing alone never authorizes an opening. Storage
errors or failure of a required clock check MUST prevent actuation. Firmware
owns the trusted time source, durable storage and physical actuator integration.

A failed handshake, signature check, authorization check or unsupported packet
MUST NOT cause automatic fallback to another authentication mode. Public
discovery records and unauthenticated responses cannot enable a mode or relax
its policy. Parsers, keys and credential types are mode-specific; a signed grant
cannot be treated as a TOTP key, and an OTP cannot authenticate a Noise session.

Signed policy updates apply to signed-grant credentials. TOTP credentials are
installed and revoked through trusted local management. If one user has both
kinds of credential, the management layer must coordinate revocation in both
stores. Grant use counters and TOTP consumption records are independent and
must survive transport changes and reconnects as required by their contracts.

Both modes use BLE GATT or NFC ISO-DEP as byte transports. Encrypted-session
messages use bounded reassembly; TOTP messages fit a single transport payload.
Each parser receives only a complete message for its configured mode. Native
APDU headers/status words and platform I/O are host responsibilities.

## Encrypted sessions

`openlock-protocol::Session` owns the Noise handshake and message state machine.
A transport MUST deliver one complete message to `Session::receive` and send
each returned byte string without modification. The session and signed grant
authenticate the holder and authorize the requested operation.

### Encoding

Each encrypted-session message is a definite, canonical CBOR array of exactly six items:

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

### Noise session

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

### Request payloads

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

### Response payloads

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

### Authorization and persistence

The lock verifies a grant signature, lock ID, epoch, rights, revocation, time
window and Noise peer key. For a counted grant, the increment is committed via
`PersistentState::commit` before the actuator callback. A stale use number
returns `AlreadyConsumed` and cannot cause a second actuator event. An actuator
failure is reported as `ActuatorFailed`; the durable usage increment is kept.

### NFC bootstrap

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

## TOTP

`openlock_totp::protocol` encodes fixed-size messages; `openlock_totp::core::LockState` enforces authorization, durable one-time use and throttling.

### TOTP parameters

| Parameter | Value |
| --- | --- |
| Algorithm | RFC 6238 TOTP using HMAC-SHA-256 |
| Secret | 32 CSPRNG-generated bytes, unique per `(lock, credential)` |
| Epoch `T0` | Unix epoch, 0 seconds |
| Time step `X` | 30 seconds |
| Digits | 8, including leading zeroes |
| Tolerance | Exactly ±1 time step relative to the lock's trusted RTC |
| Code encoding | Unsigned 32-bit integer, 0 through 99,999,999 |

```text
T = floor(unix_seconds / 30)
H = HMAC-SHA-256(secret, T encoded as eight big-endian bytes)
offset = H[31] & 0x0f
binary = BE32(H[offset .. offset + 4]) & 0x7fffffff
code = binary % 100000000
```

This is the SHA-256 option of [RFC 6238](https://www.rfc-editor.org/rfc/rfc6238).
There is no custom key derivation or transaction MAC. Do not substitute SHA-1,
six digits, a different period, or a local timezone. A numeric `1234` represents
the eight-digit code `00001234`. The OTP computation alone is not an access
verifier: all one-time-use and throttling rules below are mandatory.

### Complete wire messages

Every multibyte integer is big-endian. There is no padding, encryption, CBOR,
length prefix, handshake, nonce, session ID, or trailing data. Exact lengths,
version, kind, nonzero credential ID, code range and known response codes MUST
be checked before processing. `MAX_MESSAGE_SIZE` is 20 bytes; actual protocol
messages must have one of the exact lengths below.

#### Unlock request — 18 bytes

| Offset | Size | Field |
| --- | --- | --- |
| 0 | 1 | version = `3` |
| 1 | 1 | kind = `0x01` |
| 2 | 4 | nonzero local `credential_id` |
| 6 | 8 | `time_step` used to generate the OTP |
| 14 | 4 | `code` |

The transmitted step selects one HMAC calculation; it is never a clock-setting
instruction. The lock MUST verify that it is within ±1 of its own current step.
Request time is not trusted simply because it is included in a packet.

Lock identity is selected during connection/discovery and bound by a unique
locally provisioned key. The same key MUST NOT be reused for another lock or
credential. Request fields do not carry permissions or policy. The only valid
opcode is Unlock, so an OTP cannot be reused to authorize management commands.

Example using the RFC test secret `12345678901234567890123456789012`, Unix time
59, and credential ID `0x01020304` (test data, never a production key):

```text
03 01 01 02 03 04 00 00 00 00 00 00 00 01 02 BF B9 4E
```

This carries step 1 and code 46119246. The shared secret is never in the packet.

#### Unlock response — 15 bytes

| Offset | Size | Field |
| --- | --- | --- |
| 0 | 1 | version = `3` |
| 1 | 1 | kind = `0x81` |
| 2 | 4 | echoed `credential_id` |
| 6 | 8 | echoed `time_step` |
| 14 | 1 | result: `0` or a stable error code |

A successful response for the example above is:

```text
03 81 01 02 03 04 00 00 00 00 00 00 00 01 00
```

Responses are plaintext and unauthenticated. A client SHOULD correlate the ID
and step with its request, but MUST NOT treat that match as authentication of
the lock or proof that the door physically opened. Do not automatically retry
actuation after an ambiguous result. Malformed packets may be dropped without a
response; a syntactically valid request can receive a rejection result.

### Verification, consumption and durable state

[RFC 6238 section 5.2](https://www.rfc-editor.org/rfc/rfc6238#section-5.2) requires
the verifier to reject reuse after the first successful validation. Generating
a TOTP twice within a time step produces the same value; checking that value
against the clock is therefore insufficient.

For each credential the lock MUST persist `last_accepted_step` (initially absent)
and `uses` (initially zero), together with its locally provisioned secret and
policy. The lock also MUST retain one global `AttemptState` across all transports,
connections and credential IDs. Requests MUST be serialized through one owner
of that state. The reference verifier performs these steps:

1. Validate syntax and require trusted local Unix time. Reject a request step
   more than one step from the local step. This uses bounded integer arithmetic.
2. Load the global attempt state. Reject clock rollback relative to the last
   recorded attempt, invalid stored state, or five attempts already reserved
   in the current local step. Atomically persist the next reserved attempt
   **before looking up a credential or comparing an OTP**. A new local step
   resets the count to one. Unknown IDs and invalid codes spend the same budget.
3. Load the credential and check its ID, lock binding, enabled flag, local
   validity interval `[not_before, not_after)`, and optional maximum uses.
4. Reject `time_step <= last_accepted_step`. This applies even when the code
   still falls within the clock-tolerance window. Accepting a future step also
   invalidates all older steps, including unused ones.
5. Compute exactly one HMAC-SHA-256 for the supplied step and compare the
   numeric code in constant time. Invalid codes do not consume a credential.
6. Atomically and durably persist `last_accepted_step = time_step` and
   `uses = uses + 1` **before calling the actuator**. Integer exhaustion rejects
   access. If persistence fails, do not actuate.
7. Call the actuator once. A callback failure returns `ActuatorFailed` and
   keeps the OTP consumed. A lost reply, power loss after commitment, or reboot
   never permits a second actuation for that step.

`Replayed` is a rejection, not an instruction to actuate or a cached success.
After consumption the holder must use a strictly later step. One credential
cannot unlock twice in the same step; multiple independent credentials retain
separate consumption records and share the lock-wide attempt budget. Numeric
OTP values have a finite space and may coincide in distant steps; this is not a
global lifetime blacklist of eight-digit numbers.

Both attempt and usage commits MUST survive brownouts. Storage read failures,
corruption and uncertain commit results MUST fail closed. A commit may have
reached durable storage even if an error was returned: reload authoritative
state after recovery. Never replace missing/corrupt storage with default state.
Default state is valid only during fresh provisioning. Never reset usage while
retaining the same secret. A separate `LockState` per BLE/NFC connection is not
a substitute for serialized access to the shared durable store.

The implementation reserves up to five attempts per local 30-second step,
including valid requests. This fixed global limit prevents changing IDs or
rebooting from bypassing the budget. It can also be exhausted by an attacker,
so it does not promise resistance to denial of service. Firmware should bound
radio wakeups and parser work before invoking the verifier. NVM wear leveling,
FRAM, or another appropriate durable implementation is needed; a successful
unlock currently needs an attempt commit and a usage commit.

### Time and provisioning

The lock MUST use a trusted RTC with an explicit validity indication. On RTC
loss, unknown time, or rollback, reject access. Do not bootstrap or repair time
from a received step, phone timestamp, public NDEF record, or unauthenticated
response. Do not automatically expand the time window to compensate for drift.
Repair the clock through trusted local maintenance; preserve replay and rate
state. If correcting time backwards, wait until it reaches the stored watermark
or perform controlled reprovisioning with new secrets. Large forward clock
faults and RTC authenticity remain firmware responsibilities.

A trusted local provisioning path installs a fresh random per-credential key,
its nonzero ID, optional validity/use limits, and initial durable state in the
lock, and delivers the key securely to the authorized client. An issuer may
instead give a guest a single current OTP out of band. Raw secrets, local
policy objects and future key material MUST NOT be sent over the plaintext
access channel. Revocation disables/removes the local credential; re-enabling
an unchanged key must preserve its usage. Key replacement requires a fresh
secret and atomic replacement of the local record. There is no remote
`ApplyPolicy`, clock-setting, enrollment, key rotation or status opcode.

### BLE and NFC

BLE carries one complete message in a GATT characteristic write and one in a
notification/indication. The 18/15-byte messages fit the mandatory 23-byte ATT
MTU (20-byte attribute payload). No custom fragment header, reassembly buffer,
MTU negotiation, or application handshake is necessary. Platform connection
setup still applies. Larger MTUs do not change the 20-byte message limit.

For NFC ISO-DEP, put one message in an APDU data field; the host supplies native
APDU headers/status words and removes them before calling `IsoDepCodec`.
There is no application fragment header. A passive NDEF tag is discovery only;
it cannot implement the lock's TOTP verification or trusted clock by itself.

NDEF MIME type: `application/vnd.openlock.bootstrap`. Its 18-byte payload is:

```text
[version_u8 = 3, profile_u8 = 1, lock_id_16_bytes]
```

The encoder emits one short MIME record (`0xD2`, MB|ME|SR|TNF=MIME), with no ID,
chunks, trailing records or signature. The decoder enforces this exact form.
This record is an untrusted lookup hint. It contains no secret, issuer identity,
OTP, or trusted time; applications select already provisioned credentials.

### Stable errors

| Code | Meaning |
| --- | --- |
| 0 | Success; only after the actuator callback reports success |
| 1 | ObjectTooLarge |
| 3 | InvalidPayload |
| 5 | WrongLock |
| 6 | Revoked / locally disabled |
| 8 | Expired / outside local validity interval |
| 9 | ClockUntrusted |
| 10 | UsageExhausted |
| 12 | StorageUnavailable |
| 16 | UnsupportedVersion / profile |
| 21 | ActuatorFailed; OTP stays consumed |
| 22 | InvalidNfc |
| 23 | InvalidTotp / out-of-window step |
| 24 | Replayed / superseded time step |
| 25 | RateLimited |
| 26 | UnknownCredential |

Unassigned result codes are reserved and MUST be rejected. The C ABI
additionally returns `-1` for invalid pointers and `-2` for insufficient output
capacity. Decoding a rejection response returns ABI success with its operation
error in `openlock_response_t.error_code`.

### Security boundary

TOTP proves knowledge of a short-lived bearer code. Durable one-time use blocks
reuse **after consumption**, including after reboot. It does not prevent an
observer from using an unconsumed code first or relaying it to the real lock.
The TOTP mode provides no confidentiality, authenticated response, mutual
identity proof, proximity guarantee, or protection for arbitrary command data.
NDEF hints and responses may be spoofed. Do not add privileged commands that
reuse the same TOTP as authorization for freely editable parameters.

RFC 6238 recommends a secure channel. This profile intentionally transmits in
plaintext as a product tradeoff and therefore does not implement that channel
recommendation. Locally provisioned keys, durable storage, a trusted clock and
physical lock integration remain part of the trust boundary. Possession of a
credential's secret allows generating its future OTPs until locally revoked or
expired; sharing a key also shares that credential's one-use-per-step limit.

## Wire identifiers and compatibility

These values identify the encodings used by the authentication modes; the
workspace release number does not replace them.

| Wire identifier | Encrypted sessions | TOTP |
| --- | --- | --- |
| Message version | `2` (`openlock_types::PROTOCOL_VERSION`) | `3` (`openlock_totp::types::PROTOCOL_VERSION`) |
| Profile | `1` in the CBOR envelope | `1` in the NFC discovery payload |
| NFC MIME type | `application/vnd.openlock.bootstrap+cbor` | `application/vnd.openlock.bootstrap` |

The Noise prologue `OpenLock/v2/profile1`, signature domain strings, packet
layouts and stable error values are interoperability constants. Preserve their
exact values when implementing or updating a client. Matching a version/profile
field does not authenticate a sender, and equal profile numbers do not make
the two encodings interchangeable. Existing credentials and clients continue
to use their configured authentication mode without mandatory re-enrollment.
