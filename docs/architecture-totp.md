# Optional TOTP scheme integration

The TOTP scheme is implemented entirely in `openlock-totp`, independent of the
retained secure v2 crates. Select it through trusted deployment configuration;
there is no automatic downgrade from a secure session. See the
[v3 architecture](architecture.md) for both schemes and [the TOTP wire
contract](protocol-totp.md) for exact bytes and verification rules.

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

## Firmware integration

Disable the crate's default features for `no_std`; no allocator or runtime RNG
is required. All messages are fixed arrays or borrowed slices. The firmware
still supplies its panic handler, trusted RTC, durable storage, BLE/NFC stack
and physical actuation. Measure actual radio, standby, NVM and motor costs on
the chosen hardware; library structure alone does not establish battery life.

Implement `openlock_totp::core::PersistentState` with these contracts:

| Method | Contract |
| --- | --- |
| `load_attempts` | Read the latest lock-wide attempt record; fail on corruption/read errors |
| `commit_attempts` | Atomically and durably persist the complete reserved attempt record |
| `load_credential` | Read the local key, policy and latest usage for a credential ID |
| `commit_usage` | Atomically and durably persist the consumed step and use count |

A credential has a 32-byte unique secret, local ID, lock binding, enabled flag,
optional validity/use limits, and
`UsageState { last_accepted_step: Option<u64>, uses: u32 }`. The global
`AttemptState { last_attempt_at: Option<u64>, attempts: u8 }` survives reconnects
and reboot. Storage capacity is chosen by firmware; the core holds one loaded
credential at a time. Serialize fields explicitly; Rust structs and `Option`
layouts are not persistent storage formats.

One owner must serialize requests across BLE/NFC connections and local
management. Multiple instances over one store require external serialization.
Never reset state on reconnect, replace corrupted storage with defaults, or
reset usage while retaining the same key. Preserve usage through disable and
re-enable; replacement/reset requires a fresh secret. A journal, FRAM or another
suitable durable implementation must tolerate brownouts and write wear.

Pass trusted Unix seconds from the local RTC, or `None` if time is invalid.
The core rejects rollback below its committed attempt watermark. RTC validity,
large forward jumps, provisioning and clock repair are host responsibilities.
A received OTP step, public NFC tag or plaintext response cannot set the clock.

```rust
use openlock_totp::core::{ActuationError, LockState, PersistentState};
use openlock_totp::protocol::{decode_unlock, encode_response, UNLOCK_RESPONSE_SIZE};
use openlock_totp::types::{Error, UnlockResponse};

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

Consumption precedes the callback. A failed callback, lost response or power
loss after commitment cannot restore the OTP; retrying it cannot open again.
Power loss between commit and actuation may consume a code without opening.
The holder must use a later step. Responses are unauthenticated and cannot
prove physical opening. TOTP cannot authorize secure v2 operations or policies.

## Client integration

Rust uses `openlock_totp::crypto::unlock_request` and
`openlock_totp::protocol::encode_unlock`. C uses `openlock_make_unlock` /
`openlock_encode_unlock` and `openlock_decode_response`. These helpers do not
perform lock authorization. The combined default FFI also contains secure v2
session symbols; calling a TOTP helper explicitly selects only this scheme.

Swift:

```swift
let packet = try OpenLock.makeUnlock(secret: provisionedSecret,
                                    credentialID: 7, unixSeconds: trustedNow)
let result = try OpenLock.decodeResponse(receivedBytes)
```

Kotlin:

```kotlin
val packet = OpenLock.makeUnlock(provisionedSecret, credentialId = 7L, unixSeconds = trustedNow)
val result = OpenLock.decodeResponse(receivedBytes)
```

The platform supplies BLE/NFC I/O and correlates ID/step with its request.
Neither a match nor `Replayed` proves a new opening. Do not automatically issue
another actuation after an ambiguous result. Kotlin requires nonnegative signed
`Long` timestamps/steps and IDs in `1..0xffffffff`; larger response steps are
rejected. Rust secret wrappers redact Debug and erase their own key bytes on
drop. Applications own all platform copies, secret storage and lifetimes.

`openlock_totp::transport::ble::BleCodec` sends one complete message at the
default ATT MTU. `transport::nfc::IsoDepCodec` accepts APDU data fields without
native headers/status words. Its unsigned NDEF bootstrap is a public discovery
hint, separate from the secure scheme's signed NDEF record and trust store.
