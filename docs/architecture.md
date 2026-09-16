# OpenLock v3 architecture

The access path is one request and one response:

```text
Client                                  Lock
secret + local time                     trusted RTC + local credential store
  |                                       |
  +-- 18-byte plaintext Unlock ---------->+ syntax/time window
                                          + reserve durable attempt budget
                                          + load local key/policy
                                          + reject consumed time step
                                          + one HMAC-SHA-256 comparison
                                          + durable consumption commit
                                          + actuator callback
  <--- 15-byte plaintext result ----------+
```

There are no sessions or public-key identities. `openlock-protocol` encodes
fixed arrays and parses borrowed slices. BLE and ISO-DEP adapters carry a
complete message directly. `openlock-core::LockState` owns authorization;
transport parsers and TOTP primitives cannot authorize an actuation by
themselves. The [protocol](protocol.md) defines exact bytes and security rules.

## Embedded integration

All seven runtime crates support `no_std` without `alloc`. Firmware disables
default features on each OpenLock dependency. No runtime RNG, allocator, Noise
backend, certificate store, dynamically allocated map, or fragment buffer is
needed. The host still supplies its panic handler and board integration.
`openlock-issuer` and `openlock-ffi` are host-side crates.

The cryptographic dependencies are HMAC, SHA-256, constant-time comparison and
secret zeroization. The runtime uses fixed-size values and stack buffers.
There is no measured MCU stack/flash or battery guarantee: choose a board,
measure its radio/RTC/NVM/actuator costs, and account for durable writes. Removing
handshakes and fragmentation reduces protocol communication; actuator energy
and standby current may still dominate total consumption.

Implement `PersistentState` over a journal, FRAM or other atomic durable store:

| Method | Contract |
| --- | --- |
| `load_attempts` | Return the latest lock-wide attempt record; fail on read errors/corruption |
| `commit_attempts` | Atomically persist the entire attempt record before success |
| `load_credential` | Look up the local credential, key, policy and latest usage by ID |
| `commit_usage` | Atomically persist both consumed step and use count before success |

Storage capacity is chosen by firmware; the core holds one credential at a time
and has no collection of credentials. Each credential includes a 32-byte key,
ID and lock binding, an enabled flag, optional validity/use limits, and
`UsageState { last_accepted_step: Option<u64>, uses: u32 }`. Global
`AttemptState { last_attempt_at: Option<u64>, attempts: u8 }` persists the rate
budget and clock watermark. Encode fields explicitly; Rust layout and
`Option<u64>` memory representation are not a storage format. Add whatever
integrity, recovery and wear-leveling scheme the hardware needs.

One owner MUST serialize requests across transports/connections and local
management. `&mut LockState` prevents concurrent calls on that instance, but
multiple instances over the same store still require external serialization.
A reboot loads the authoritative durable state. Do not implement these methods
with an in-memory-only store in production, clear state on reconnect, or turn
storage errors into default values. Preserve consumption through local
revocation/re-enablement; replacing/resetting a credential requires a new key.

The host reads trusted Unix seconds from its RTC. Pass `None` when that clock
is invalid. The core rejects rollback below the last committed attempt time;
the host must also detect RTC faults before that watermark and large forward
jumps. The wire exposes no clock-setting operation. Trusted local maintenance
is required for provisioning, revocation, policy edits and clock recovery.

A firmware handler can use the following structure:

```rust
use openlock_core::{ActuationError, LockState, PersistentState};
use openlock_protocol::{decode_unlock, encode_response, UNLOCK_RESPONSE_SIZE};
use openlock_types::{Error, UnlockResponse};

fn handle<S: PersistentState>(
    lock: &mut LockState<S>,
    message: &[u8],
    trusted_unix_seconds: Option<u64>,
    actuator: impl FnOnce() -> Result<(), ActuationError>,
) -> Result<[u8; UNLOCK_RESPONSE_SIZE], Error> {
    let request = decode_unlock(message)?;
    let result = lock.unlock(&request, trusted_unix_seconds, actuator);
    encode_response(&UnlockResponse::for_request(&request, result))
}
```

The callback is called at most once for an accepted step, after durable
consumption. If it fails, the step stays consumed. Loss of power after the
commit but before actuation sacrifices availability to avoid a duplicate
opening; the next attempt must use a later step. Send the response only after
the handler returns. A plaintext response still cannot prove physical opening.

## Client and binding integration

Rust clients use `openlock_crypto::unlock_request` then
`openlock_protocol::encode_unlock`. C clients use `openlock_make_unlock` or
`openlock_encode_unlock`, send the resulting bytes, and parse results with
`openlock_decode_response`. `openlock_totp` is also available for displaying an
eight-digit code. Decoders do not perform authorization.

Swift:

```swift
let packet = try OpenLock.makeUnlock(secret: provisionedSecret,
                                    credentialID: 7, unixSeconds: trustedNow)
// Send packet with the platform BLE/NFC APIs.
let result = try OpenLock.decodeResponse(receivedBytes)
```

Kotlin:

```kotlin
val packet = OpenLock.makeUnlock(provisionedSecret, credentialId = 7L, unixSeconds = trustedNow)
// Send packet with the platform BLE/NFC APIs.
val result = OpenLock.decodeResponse(receivedBytes)
```

Check response correlation against the submitted ID and step. Do not silently
retry on lost/ambiguous replies or interpret `Replayed` as a fresh opening. The
same credential must wait for a strictly later step after use. Neither wrapper
retains a native session handle. Applications own secure key storage and the
lifetimes/copies of secret buffers; Rust key wrappers redact Debug output and
zeroize their own key bytes on drop, not every copy in a platform or crypto
library. Kotlin uses signed nonnegative `Long` values for timestamps/steps and
IDs in `1..0xffffffff`; response steps beyond `Long.MAX_VALUE` are rejected.

Build Swift with `swift build` in `bindings/swift`. Consumers link the Rust
`openlock_ffi` library for the target architecture. Kotlin loads `openlock_jni`,
which links `openlock_ffi`; package both target-ABI libraries. Both header copies
must remain identical. C ABI structs are native layouts, never wire layouts.

## v2 migration and compatibility

| v2 | v3 |
| --- | --- |
| Noise IK session and `Session::start/receive/send` | Stateless `encode_unlock/decode_unlock` and response functions |
| X25519/Ed25519 keys and COSE grants | Unique shared key and local credential policy |
| Remote signed policy/key updates | Trusted local maintenance |
| Subject-key proof and grant rights | One operation, Unlock, authenticated by its credential TOTP |
| Optional grant consumption counter | Mandatory durable TOTP step consumption plus optional usage cap |
| Signed CBOR NDEF device record | Unauthenticated fixed-size discovery hint |
| Up to 4096-byte packets and fragments | 18-byte request, 15-byte result, maximum transport payload 20 |
| `no_std + alloc` and custom RNG | `no_std`, no heap and no runtime RNG |
| Stateful C `openlock_session_*` ABI | Stateless `openlock_make_unlock` / `openlock_decode_response` ABI |

Protocol version 3, crate version 0.3, new NDEF MIME, C headers and mobile
bindings move together. V2 messages and key material do not automatically
migrate. Provision new unique symmetric keys through a trusted path. No v2
fallback or mixed-session compatibility code is included. Timed and counted
access remain local credential constraints; remote status/policy operations
and mutual authentication are deliberately absent from this minimal profile.

## Verification

`cargo test --workspace` checks all RFC SHA-256 vectors, strict packet parsing,
ABI buffers, one-time use across reboot and time-window boundaries, persistent
attempt limits, clock rollback, policy constraints, storage failure, and
actuator failure. An integration test sends a BLE request through the lock and
replays it over NFC after restarting the runtime.

`devenv shell -- no-std-check` runs runtime tests with default features disabled
and checks the runtime libraries for `thumbv7em-none-eabihf` without a custom RNG
configuration. This is a library compile check, not a linked/running firmware
image; brownout durability, radio wakeups, physical actuation and RTC drift need
verification on the selected hardware.
