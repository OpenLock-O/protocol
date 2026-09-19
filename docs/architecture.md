# OpenLock implementation and integration

OpenLock has one encrypted access protocol. `Session` handles Noise and message
correlation; `DeviceController` interprets authenticated requests and owns all
physical and persistent device behavior. BLE and NFC only carry complete bytes.

```text
BLE/NFC framing -> Session -> authenticated peer + Command
                                  |
                         DeviceController
                         /       |        \
             DeviceStorage   DevicePlatform   Bootloader
             atomic state    clock/sensors    signed staging
             uses/results    physical I/O     trial/recovery
                                  |
                             typed Response
                                  |
                         Session -> BLE/NFC
```

## Runtime and state ownership

Use one controller for a physical device across every connection and local
management path. Serialize calls. Do not make a controller per connection or
share storage between independent controllers without serialization.

The runtime crates support `no_std + alloc`. Disable default features on every
runtime dependency; Cargo feature unification can otherwise restore `std`.
Firmware supplies the allocator, panic handler, entropy source, storage and I/O.
The issuer and FFI are host libraries. The simulator uses `std` and deterministic
test identities; it is not board firmware.

A minimal application flow is:

1. Call `DeviceController::open` with trusted factory inputs and the durable store.
2. Construct each responder session using the current device key and capabilities.
3. At `HandshakeComplete`, capture `controller.context(peer)` once for that session.
4. At `Request`, call `controller.handle(captured_context, &command)`.
5. Encrypt the response with `Session::respond` and transmit it.
6. If the controller generation changed, close all sessions with an older generation.
7. Forward actual hardware events to `hardware_changed` and `actuator_finished`;
   call `poll` for deadlines and boot outcomes even when no client is connected.

The example `crates/openlock-core/examples/simulator.rs` executes this flow.
`SessionContext` is a trusted host value, never parsed from a packet. Recreating
it per request would defeat generation invalidation. Local management uses the
same authorization/controller path through `handle_local`; it still supplies a
valid administrator grant. Factory provisioning, pairing-button events and
physical confirmations are separate trusted local methods.

### Platform interfaces

| Interface | Required behavior |
| --- | --- |
| `DeviceStorage::load` | Return the latest integrity-checked record; distinguish absent storage from read failure or corruption. |
| `DeviceStorage::commit` | Atomically persist the complete snapshot before success. Failure may be ambiguous; the controller then refuses further work until reopened. |
| `DevicePlatform::monotonic_ms` | Monotonic duration source for this boot; rollback poisons the instance. |
| `wall_clock` / `set_wall_clock` | Trusted Unix-second interval and privileged clock adjustment. Missing RTC validity is `None`. |
| `sensors` | Actual readings matching the advertised hardware, including unknown/unavailable values. |
| `start_action` | Start once without waiting for radio progress. Enforce pulse maximum time in hardware. |
| `stop_action` | Stop an in-progress drive, or report failure so the controller cannot accept another drive. |
| `request_reboot` | Schedule reboot after response delivery or a bounded transmission deadline. |
| `has_device_private_key` | Confirm securely installed private material for the proposed rotation public key. |
| `bootloader` | Return a backend only when signed staging, boot verification and recoverable trials are implemented. |

Successful `start_action` means started, not physically unlocked. Complete through
`actuator_finished`, with a fresh sensor sample. Mechanical/manual transitions
use `hardware_changed` even when no wireless action is active. Door state and
bolt state are never inferred from each other. Periodic calls must meet configured
timeout/reminder resolution; firmware must make pulse safety independent of this
scheduler. Board policy owns local emergency egress and electrical fail behavior.

### Durable records and migration

`DeviceSnapshot` contains owner/epoch/generation, policy/revocations, unlock uses,
credential digests, sequence watermarks, bounded operation results, versioned
configuration, bounded audit history, clock watermark, relock intent, firmware
transfer/security state, and active device public identity.

Use explicit field serialization with integrity checking and an atomic journal,
transactional NVM or equivalent. Rust struct layouts, `Option` layouts and raw
memory dumps are not storage formats. Preserve configured capacity bounds when
reading. The controller validates loaded fields and retained firmware signatures.
A commit error poisons the in-memory instance because either the previous or new
record may be durable. Reopen from authoritative state; never restore defaults.

`provision` only accepts an absent store. `open` only accepts an existing valid
store. `migrate_legacy` explicitly copies a v2 `LockSnapshot` into a new v4 store,
including epoch, policy version, revocations and consumed uses. Supply issuer,
current device keys and first-admin identity from trusted provisioning. Retain
the old store until the new record commits. Insufficient capacity fails migration
rather than dropping data. Wire upgrades do not reset authorization state.

Persist sequence watermarks even after operation results are evicted. A result
cache is not a sufficient replay barrier. Reusing a credential ID for changed
grant contents in one epoch is rejected after its first mutation. Issue a new ID
for a changed grant. Revocation/policy epochs provide explicit domain changes.

The actuator owner remains exclusive after an ambiguous start error. On reboot,
accepted/running operations become Unknown and are not driven again. A pending
automatic relock is evaluated from fresh door readings, with its intent treated
as due. Once a relock attempt has durably claimed the intent, another reboot does
not replay that drive. Recovery may consume a use without opening the lock.

### Commissioning and physical confirmation

Generate independent factory X25519/rotation keys, a firmware-signing trust root
and a 32-byte random setup key. Encode the setup artifact with
`openlock_crypto::commissioning::SetupPayload`; retain the setup-key hash in
`FactoryIdentity`. Factory inputs are outside erasable user state. Keep their
private material in the platform's secure storage. Secret wrapper/debug behavior
does not erase copies made by application code, QR scanners or platform buffers.

A local gesture calls `open_pairing_window`. The phone scans/pins the QR identity,
starts Noise, queries PairingStatus, issues a full-rights initial grant for that
epoch, and sends Claim. Reconnect after ownership is committed. Setup-key
comparison uses `subtle` constant-time equality. Claim action and QR wrappers
redact secrets in Debug and zero their owned setup bytes on drop.

For reset or issuer replacement, display/identify the exact proposed operation
locally, obtain a physical gesture and call `confirm_physical(context, command)`.
This stores a one-shot digest for 60 seconds. Do not expose that method as an
untrusted transport callback. The same command then follows ordinary `handle`.

### Firmware backend

`Bootloader` must durably begin staging and write bounded ranges, read existing
ranges for duplicate verification, hash the actual staged image and report power
readiness. Writes below the acknowledged offset are only duplicate reads; writes
at the acknowledged offset can repeat after a lost acknowledgment. Make that
retry safe for the selected flash technology, or require abort/restart.

`activate` receives both the manifest and its signed COSE bytes. The bootloader
independently validates them under its provisioned firmware root, checks the
hardware target/security policy and uses A/B partitions or an equivalent recovery
scheme. It must report Pending while a trial is unresolved, Confirmed only after
successful boot confirmation, and RolledBack after restoring the previous image.
An activation error may still have scheduled a boot; keep the outcome truthful
and resolve it through the same interface, including across resets. The network
cannot assert boot success. The protocol commits a new security floor only after
Confirmed. Do not advertise firmware commands with a nonrecoverable backend.

### Bare-metal RNG

Noise uses `getrandom` 0.3. Configure the firmware target:

```toml
[target.thumbv7em-none-eabihf]
rustflags = ['--cfg', 'getrandom_backend="custom"']
```

Link exactly one Rust-ABI `__getrandom_v03_custom` symbol using the matching
`getrandom` version and `#[unsafe(no_mangle)]`:

```text
unsafe fn __getrandom_v03_custom(dest: *mut u8, len: usize) -> Result<(), getrandom::Error>
```

Initialize every requested byte from a CSPRNG before success. Do not read
uninitialized destination memory or return predictable data on entropy failure.
The library maps Noise RNG failures to `Error::Noise`. The embedded library
compile check does not supply the final allocator, panic handler or RNG symbol.

## C and mobile clients

C is declared in `include/openlock.h`; the Swift header copy must match. C handles
are opaque and must be serialized. `start`, `send` and `respond` preflight output
size. A null/zero output or an undersized buffer returns -2 and the required size
without advancing the send state. The caller retries with sufficient capacity.

`receive` accepts input once and stores its complete event and optional handshake
reply. Drain `take_event` and `take_output`; small buffers retain queued values.
A second `receive` while either is pending returns Busy without consuming input.
Event CBOR is `[kind, request_id, peer_or_null, body_or_null]`, with kind 1
handshake, 2 request and 3 response. Body is the full canonical Command/Response.
A rejected lock action is an event result, not a C buffer/decoding error.

Swift exposes `OpenLockSession`, `LockAction`, `SessionEvent`, `LockReply` and
structured physical/configuration/audit/firmware values. Kotlin exposes the same
concepts, with JNI loaded as `openlock_jni`; Kotlin uses `ULong` for u64 fields.
Both issuers sign grants, revocation policies, firmware manifests, device records
and key updates. The administrator must use a separate firmware signing key.
Mobile apps own keychain/keystore storage, camera UI, user interaction and BLE/NFC.

```swift
let sent = try session.send(.unlock, credential: grant, sequence: nextSequence)
// Send sent.packet over the configured transport.
let received = try session.receive(packetFromLock)
if case .response(_, let response) = received.event,
   case .operation(let operation) = response.reply {
    // Running means accepted; query operation.sequence for the final result.
    print(operation.phase, operation.evidence)
}
```

```kotlin
val sent = session.send(LockAction.Unlock, credential = grant, sequence = nextSequence)
val received = session.receive(packetFromLock)
val response = (received.event as SessionEvent.Response).value
val operation = (response.reply as LockReply.Operation).value
// Persist nextSequence independently of the session; inspect operation.phase.
```

A disconnect does not authorize a new operation sequence. First query the old
operation or resend the identical request with the identical sequence. Unknown
and ResultUnavailable do not prove either opening or non-opening. Present that
uncertainty to the caller; do not automatically drive again.

Build the Rust FFI for each target ABI. Swift links `openlock_ffi` through its
module/linker declaration; supply its library search path or platform package.
Android packages both the JNI library and matching Rust library. The JNI CMake
project supports Android NDK and desktop JNI for integration tests.

## Verification and hardware acceptance

`devenv shell -- scripts/check-bindings.sh` builds Rust, the native C client, the
JNI library, Kotlin and the Swift executable runner. Each drives the Rust device
through real encrypted packets. The runner intentionally avoids XCTest so it can
run in the pinned Swift environment. CI runs this complete workflow on macOS.

Rust tests cover wire vectors, Noise metadata/roles/replay rejection, grants and
trust, BLE/NFC bounds, pulse and motor profiles, unavailable sensors, physical
faults, auto-relock, sequence eviction, cross-session/reboot replay, before/after
commit failures, migration, clock rollback, pairing, physical confirmation,
reset/trust replacement and signed firmware resume/boot outcomes. Native ABI tests
exercise small buffers and retained events. These are simulated platform tests.

Before deployment, additionally validate on the chosen board:

- Actual pulse cutoff, motor stop, limit sensing, privacy/door wiring, jam and timeout behavior.
- Atomic NVM persistence under power cuts at every commit/drive boundary, including write wear.
- Monotonic timer behavior, RTC validity and recovery, and boot-time sensor uncertainty.
- Firmware staging under flash-write interruption, independent boot verification, bad trial recovery and security-floor persistence.
- Real BLE/NFC MTUs, disconnection timing, key storage, image capacity and power/latency budgets.

The `thumbv7em-none-eabihf` job compiles libraries with `no_std + alloc`; it does
not link, flash or run a board image. Successful simulator tests do not replace
these platform acceptance checks.
