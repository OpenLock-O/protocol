# OpenLock protocol 4

This is the wire and behavior contract for the reference implementation. MUST
and MUST NOT denote requirements. BLE and NFC carry the same complete messages.
All normal access and wireless management use authenticated, encrypted Noise
sessions. Authentication failure MUST NOT select another authentication scheme.

## Encoding and sessions

The canonical CBOR outer envelope is:

```text
[4, 1, kind, request_id, capabilities, noise_payload]
```

`kind` is 0 handshake, 1 request or 2 response. Handshake ID and capabilities
are zero. Encrypted IDs are nonzero u32 values, increasing within one session.
Capabilities are a u64 mask: bit `n` represents command opcode `n`. Only bits
0 through 22 are defined. They identify supported commands, never permissions.
The payload is a nonempty byte string; a complete packet is at most 4096 bytes.

The suite is `Noise_IK_25519_ChaChaPoly_SHA256`, with prologue
`OpenLock/v4/profile1`. The client supplies its X25519 private key and a trusted
lock public key. X25519 identity and Ed25519 signing keys are independent.
The first and second empty-payload handshake messages contain 96 and 48 Noise
bytes respectively. After the handshake, plaintext is:

```text
[kind, request_id, capabilities, body]
```

The inner metadata MUST equal the outer metadata. A command's bit MUST be set
in the sender and receiver capability masks. Responses MUST match the pending
request's opcode and request ID. Initiators only send requests; responders only
send responses. At most 1024 requests can be pending. Protocol/authentication
errors close the channel; there is no reuse after an error. A lost connection
requires a new handshake, but never resets credential operation sequences.

Use definite arrays, byte strings, UTF-8 strings, nonnegative minimally encoded
integers and `null` exactly as specified below. Application booleans are integers
0 and 1. Unknown opcodes, enum values, capabilities, wrong field counts,
indefinite/nonminimal encodings and trailing bytes are rejected. Strings in
device/firmware records are at most 64 UTF-8 bytes. Signed COSE structures retain
their specified protected and empty unprotected maps.

## Commands, authorization and responses

Every request body is:

```text
[credential_cose, operation_sequence_or_null, [opcode, arguments...]]
```

Queries use `null` for the sequence. Mutations use a nonzero u64 sequence,
strictly increasing per credential within the authorization epoch. The sequence
is independent of the session request ID and the credential's unlock use count.
`credential_cose` is nonempty except for Claim and PairingStatus.

| Opcode | Action and arguments | Required right | Mutation |
| --- | --- | --- | --- |
| 0 | Unlock | UNLOCK = 1 | yes |
| 1 | Status | STATUS = 2 | no |
| 2 | ApplyPolicy, signed_policy_bytes | CREDENTIALS = 32 | yes |
| 3 | Lock | LOCK = 4 | yes |
| 4 | Info | STATUS | no |
| 5 | Operation, original_sequence | STATUS | no |
| 6 | GetConfig | STATUS | no |
| 7 | SetConfig, configuration | CONFIG = 16 | yes |
| 8 | ReadLog, after_cursor_u64, limit_u32 | LOG = 8 | no |
| 9 | SetClock, unix_seconds_u64 | CLOCK = 64 | yes |
| 10 | Reboot | REBOOT = 128 | yes |
| 11 | FactoryReset | RESET = 512, plus physical confirmation | yes |
| 12 | ReplaceIssuer, new_ed25519_public32 | TRUST = 1024, plus physical confirmation | yes |
| 13 | FirmwareBegin, signed_manifest_bytes | FIRMWARE = 256 | yes |
| 14 | FirmwareChunk, offset_u64, data_bytes | FIRMWARE | yes |
| 15 | FirmwareFinish | FIRMWARE | yes |
| 16 | FirmwareActivate | FIRMWARE | yes |
| 17 | FirmwareAbort | FIRMWARE | yes |
| 18 | FirmwareStatus | FIRMWARE | no |
| 19 | Claim, setup_key32, issuer_public32, first_admin_grant | setup key and local pairing window | yes |
| 20 | CredentialStatus | STATUS | no |
| 21 | RotateDeviceKey, signed_update_container | TRUST | yes |
| 22 | PairingStatus | unbound device only, over Noise | no |

All grants bind credential ID (16 bytes), lock ID, authenticated holder public
key, rights, epoch, optional validity and optional maximum unlock uses. Check the
signature, holder, target, rights, epoch, revocation and time window for every
request. A timed grant requires a trusted clock interval fully inside its validity
window. Exhausting unlock uses does not remove separately granted query or lock
rights. Grant identifiers MUST NOT be reused for different grant contents in the
same epoch; accepted mutations bind IDs to the exact credential digest.

Each response body is:

```text
[opcode, error_code, reply_or_null]
```

A pre-acceptance rejection uses a positive error and `null`. Success uses zero
and `[reply_tag, record]`. An accepted operation that later fails is still an
Operation reply: inspect its phase and operation error, not only the outer code.

| Reply tag | Record | Returned by |
| --- | --- | --- |
| 0 | OperationStatus | mutations other than Claim; Operation query |
| 1 | LockStatus | Status |
| 2 | DeviceInfo | Info |
| 3 | DeviceConfig | GetConfig |
| 4 | AuditPage | ReadLog |
| 5 | FirmwareStatus | FirmwareStatus |
| 6 | `[epoch, generation]` | Claim |
| 7 | `[uses_u32, max_uses_u32_or_null, next_sequence_u64]` | CredentialStatus |
| 8 | `[epoch, generation, window_open_bool]` | PairingStatus |

Operation queries address only the calling credential's sequence. A holder with
LOG permission can read the device audit log. Ordinary status is not public.

## Physical lock contract

```text
OperationStatus = [credential_id16, sequence_u64, opcode_u8,
                   phase, evidence, operation_error_u32]
phase    = 0 Accepted, 1 Running, 2 Completed, 3 Failed, 4 Unknown
evidence = 0 None, 1 Driver, 2 Sensor, 3 NoChange
Reading<T> = [0] Unsupported | [1] Unknown | [2, T] Known
bolt = 0 Locked | 1 Unlocked
door = 0 Closed | 1 Open
fault = 0 None | 1 Jammed | 2 Timeout | 3 SensorConflict | 4 Driver | 5 DoorAjar

LockStatus = [bolt_reading, door_reading, privacy_reading, battery_reading,
              fault, active_operation_or_null, epoch, policy_version,
              config_version, generation, clock_trusted_bool]
```

Privacy readings contain booleans; battery readings contain u8 percentages in
0..100. Unsupported and unavailable readings are different. An automatic action
uses the reserved all-zero credential ID and sequence zero in live status and
audit operation records.

The controller has one actuator owner across every BLE/NFC connection and local
entrypoint. Conflicting physical actions return Busy and are not queued. Reads
and firmware downloading may proceed while an actuator moves. Reboot, ownership
changes, device-key rotation, configuration changes and firmware activation are
rejected while a physical action is active. Epoch-changing policies also wait.

The access path MUST be: complete decoding, authentication and grant validation,
physical preflight, atomic durable acceptance/sequence/use reservation, then one
actuator start. A reliable sensor already at the requested target returns
Completed/NoChange without driving or consuming an unlock use. Otherwise an
accepted Unlock consumes a use even if the driver subsequently fails. Lock,
queries and pre-acceptance rejections do not consume unlock uses.

Unlock means release the locking mechanism. It MUST NOT mean that the door opened.
Pulse hardware cannot advertise active Lock. Its platform MUST guarantee finite
energization independently of network traffic and polling. A driver completion
can return Completed/Driver with an unsupported/unknown bolt reading; it MUST NOT
invent sensor evidence. A contrary sensor reading produces SensorConflict.
Jammed, timeout and driver failure have separate stable errors. Ambiguous driver
start retains exclusive ownership until completion or a confirmed stop.
If the door becomes open or unknown during active locking, stop the actuator,
fail the operation and cancel automatic retry. An already sensor-confirmed locked
target can return NoChange without requiring conditions for a new movement.

Each accepted mutation durably stores its credential sequence, digest and result.
The same sequence and digest returns the saved operation; different arguments
with that sequence return Conflict. Result eviction does not erase the sequence
watermark: an evicted operation returns ResultUnavailable and MUST NOT execute.
Storage errors poison the controller until it reloads authoritative storage.
Accepted/running operations found at startup become Unknown, with no replay.
The platform stops any interrupted actuator before accepting new physical work.

Local keys, knobs, buttons and sensor transitions enter through `hardware_changed`.
They update the same physical state and audit stream. They are not represented as
wireless credentials. A known active privacy input blocks wireless Unlock; an
unknown supported privacy input also blocks it. There is no remote privacy bypass.

### Device information and configuration

```text
DeviceInfo = [lock_id16, model_text, hardware_text, firmware_text,
 capabilities_u64, actuator, bolt_sensor_bool, door_sensor_bool,
 privacy_sensor_bool, battery_sensor_bool, safe_lock_without_door_bool,
 hold_open_supported_bool, max_release_ms_u32, max_action_ms_u32,
 max_delay_ms_u32, log_capacity_u32, operation_capacity_u32,
 credential_capacity_u32, max_image_size_u64, max_chunk_size_u32]
actuator = 0 Motor | 1 Pulse

DeviceConfig = [version_u64, auto_relock, release_ms_u32,
                action_timeout_ms_u32, hold_open_bool, door_ajar_ms_u32]
auto_relock = [0] Disabled | [1, delay_ms_u32] | [2, after_close_ms_u32]
```

Every configuration update MUST be the next version and commit atomically.
Durations must fit advertised hardware limits. Release and action timeout must
be nonzero; zero door-ajar duration disables that reminder. AfterClose and door
reminders require a door sensor. Hold-open requires advertised support and cannot
coexist with auto-relock. Factory configuration disables auto-relock and reminders;
release is `min(max_release_ms,500)` and timeout is `min(max_action_ms,10000)`.

A known open door MUST block active locking. An unknown door blocks locking when
a door sensor exists. Without a door sensor, active locking and delayed relock
require `safe_lock_without_door`. AfterClose restarts its countdown on a new close
transition. Enabling auto-relock while reliably unlocked schedules a new countdown.
A local mechanical unlock can also schedule relock. No blind motor retry is made.

The relock intent survives reboot. At startup it is considered due, subject to
current door conditions; an AfterClose transition can start a fresh close delay.
Before driving the automatic lock, the intent is durably claimed so an ambiguous
motor action cannot be replayed after another reboot. Observed locking clears the
intent. A failed automatic action is reported and does not cause repeated drive.

## Commissioning and ownership

A secret setup QR is the exact lowercase-hex text:

```text
OPENLOCK4:<lock_id_32_hex_chars>:<initialization_public_64_hex_chars>:<setup_key_64_hex_chars>
```

Generate the independent 32-byte setup key with a CSPRNG and deliver the QR through
the product's controlled setup process. Store its SHA-256 digest on the device.
It MUST NOT appear in public BLE advertisements or public NDEF discovery. Scan and
pin the initialization X25519 key before the Noise handshake. A wrong device key
fails the handshake; a wrong target ID fails grant binding.

Only an unbound device accepts PairingStatus and Claim without a grant. A local
physical gesture opens a 120-second window. Five wrong setup-key attempts close
it; reopening requires another gesture. The window is not restored on reboot.
PairingStatus reports the current epoch needed to issue the initial administrator
grant, including after a reset. It never provides the setup key.

Claim carries a grant signed by the proposed administrator issuer. It MUST bind
the current lock/epoch and the Noise holder, have all rights (2047), and have no
expiry/use limit. The device atomically installs the issuer and administrator and
increments its generation. Concurrent/repeated claims cannot replace an owner.
The client reconnects after receiving the claim result.

Every transport session captures `SessionContext { peer, generation }` at the
handshake. Never reconstruct that context for each request. Claim, reset, issuer
replacement, epoch changes and device-key rotation invalidate earlier generations.
Send the final result, then close every affected session. A new Noise session must
use the current device key from durable state.

FactoryReset and ReplaceIssuer additionally require a local, one-shot physical
confirmation bound to the holder and digest of the exact command. It expires at
60 seconds and is never supplied as a trusted bit in a packet. A wrong or expired
confirmation does not execute the action.

FactoryReset atomically clears the owner, credentials, operation records, user
configuration and audit history. It increments epoch and generation, retains the
clock watermark and firmware security version, and restores the factory identity
and unbound state. Hardware parameters, initialization key and firmware root are
trusted provisioning inputs and are not erased. The pairing window remains closed
until a new gesture. Old grants cannot regain access even if the same issuer key
is installed later. ReplaceIssuer increments epoch/generation, clears the old
credential domain, retains configuration/history and invalidates all old grants.

## Clock, policies, rotation and audit

SetClock requires CLOCK permission. Wall-clock time is distinct from monotonic
milliseconds used for physical windows, action timeouts and relock. Persist the
observed trusted lower-bound watermark; never accept a clock below it. Missing,
invalid or rolled-back time becomes untrusted. A non-expiring administrative grant
can set time to at least the watermark and repair it. If setting the hardware
clock fails, trust is not restored. Neither a packet timestamp nor a discovery
record is a time source.

Grants and policies retain version 2 and signature domains
`openlock:v2:grant` and `openlock:v2:policy`. Extend the defined rights mask to
2047; preserve existing rights 1 and 2. Revocation is additive within an epoch;
policy versions increase. A larger epoch invalidates the preceding grant domain.
`migrate_legacy` imports old epochs, policy versions, revocations and consumed uses
without reinitializing them. An ordinary open/load error MUST NOT trigger migration
or factory provisioning.

Device records retain `openlock:v2:device-key` and key updates retain
`openlock:v2:key-update`. The transport update container is
`[signed_update_cose_bytes, signed_new_device_record_cose_bytes]`.
Verify the new record with the configured issuer, and the update with its explicit
issuer or the current rotation key. Require matching device/old key ID, increasing
key version, and the trusted time interval within `[not_before, retire_after)`.
The new private key MUST already be securely installed locally; this command does
not carry private key material. A successful update persists the public identity
and invalidates old sessions. It does not reset grant usage or grant epoch.

```text
HardwareState = [bolt_reading, door_reading, privacy_reading, battery_reading]
AuditEvent = [cursor_u64, unix_seconds_or_null, kind, credential_id_or_null,
              operation_sequence_or_null, code_u32,
              hardware_state_or_null, operation_status_or_null]
AuditPage = [[events...], next_cursor_u64, gap_bool]
kind = 0 Operation | 1 Hardware | 2 Configuration | 3 Ownership | 4 Clock
     | 5 Policy | 6 Firmware | 7 Reboot | 8 Rejected
```

ReadLog returns entries strictly after the cursor, at most 16 per page. A gap
means older requested entries have been overwritten. Capacity is finite and
advertised. Operation events include phase/result evidence; physical changes
include sensor observations. Errors use stable codes. Logs MUST NOT contain keys,
setup secrets, credential payloads or image contents. Logging is local, with
explicit queries; the protocol has no unsolicited push messages.

## Signed firmware lifecycle

```text
FirmwareManifest = [model_text, hardware_text, version_text,
                    image_size_u64, sha256_bytes32, security_version_u64]
FirmwareStatus = [phase, durably_received_u64, manifest_or_null, confirmed_security_version_u64]
phase = 0 Empty | 1 Receiving | 2 Verified | 3 Trial | 4 Confirmed | 5 Failed
```

The manifest is COSE/Ed25519 signed under the independent factory-provisioned
firmware root with domain `openlock:v4:firmware`. Access administrator signatures
cannot substitute for that root. Match hardware/model, enforce image size limits,
and require a security version greater than the last confirmed version.

Begin reserves one transfer and durably initializes staging. Chunks are nonempty,
no more than the advertised size (maximum 1024 bytes), and fit the 4096-byte
complete-message limit including the grant. Write at the confirmed offset; a fully
confirmed duplicate range is accepted only when bytes match exactly. Gaps, overlap
beyond the watermark and conflicting confirmed bytes are rejected.

A chunk is acknowledged only after flash durability and the received watermark
commit. On reconnect/reboot query FirmwareStatus and resume from that watermark.
An unacknowledged write can have reached flash: the backend must support safely
rewriting that range or return an error requiring abort/restart. Operation-sequence
replay protection still applies; Unknown operation results do not authorize a
second callback with the old sequence.

Finish requires the full size and verifies the actual staged image hash. Activate
requires Verified, no active physical action, and acceptable platform power/boot
conditions. Durably record Trial before scheduling activation. The bootloader
independently verifies the signed target/hash and stages a recoverable trial boot.
It reports Pending, Confirmed or RolledBack. Only a confirmed boot advances the
security version. Rollback marks Failed and retains the old security floor.
Network clients cannot report boot success. Abort is not permitted during Trial.
Normal unlock authorization remains active during download; trial activation
blocks new physical actions while boot outcome is unresolved.

## BLE and NFC

BLE framing retains the bounded fragment codec. The default ATT MTU is 23; frames
fit `att_mtu - 3`, with an eight-byte fragment header. The host supplies negotiated
MTU changes. Reassembly rejects conflicting fragments and oversized messages.
NFC ISO-DEP fragments remain `[sequence_u8, total_length_be_u16, payload]`, with at
most 240 payload bytes. Native APDU headers/status words remain platform-owned.

Public NDEF uses MIME `application/vnd.openlock.bootstrap+cbor`. The discovery
payload is `[4, device_id16, key_id_u32, key_version_u32, x25519_public32,
rotation_public32, capabilities_u64, issuer_key_id_u32, signature_bytes]`.
The signature is the independently versioned v2 device-key COSE object. Public
NDEF never replaces the secret setup QR. Identity records and capabilities must
be verified through configured trust before use.

## Errors and fixed vectors

Existing error codes 1..22 retain their meanings: ObjectTooLarge, InvalidCose,
InvalidPayload, BadSignature, WrongLock, Revoked, StaleEpoch, Expired,
ClockUntrusted, UsageExhausted, StalePolicy, StorageUnavailable,
InvalidConsumption, MissingRight, Noise, UnsupportedVersion, InvalidState,
UnsupportedCapability, UntrustedKey, StaleKey, ActuatorFailed, InvalidNfc.

| Code | Error | Code | Error |
| --- | --- | --- | --- |
| 32 | Busy | 33 | DoorOpen |
| 34 | PrivacyActive | 35 | Jammed |
| 36 | ActionTimeout | 37 | SensorConflict |
| 38 | InvalidConfig | 39 | Conflict |
| 40 | ResultUnavailable | 41 | NotProvisioned |
| 42 | AlreadyProvisioned | 43 | PairingClosed |
| 44 | InvalidSetupKey | 45 | PhysicalConfirmationRequired |
| 46 | ClockRollback | 47 | FirmwareInvalid |
| 48 | FirmwareTargetMismatch | 49 | FirmwareRollback |
| 50 | FirmwareConflict | 51 | FirmwareIncomplete |
| 52 | PowerInsufficient | 53 | BootFailed |
| 54 | ResourceExhausted | | |

The C ABI additionally returns -1 for invalid pointers and -2 for output capacity.
An operation error inside a received event is distinct from ABI decoding success.

Fixed structural examples (dummy payloads, not valid authorization):

```text
[4,1,1,24,7,h'aabbcc']       = 86 04 01 01 18 18 07 43 aa bb cc
[h'010203',1,[0]]           = 83 43 01 02 03 01 81 00
[0,32,null]                = 83 00 18 20 f6
[h'',null,[22]]            = 83 40 f6 81 16
```

Tests fix these layouts and exercise Noise exchanges over the same bounded
transports. Message version is independent of Cargo package version; v2 session
packets are rejected by the v4 implementation. There is no automatic downgrade.
