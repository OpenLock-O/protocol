# OpenLock Kotlin binding

The Kotlin binding provides encrypted-session and TOTP authentication through
the same native library. Choose the mode through trusted application/device
configuration; a failed session must not trigger automatic fallback to TOTP.

Use `OpenLockSession` to own an encrypted-session handle:

```kotlin
OpenLockSession.initiator(privateKey, lockPublicKey, capabilities).use { session ->
    // Platform BLE/NFC I/O remains application-owned.
}
```

Use `OpenLock` to generate and parse complete TOTP messages:

```kotlin
val request = OpenLock.makeUnlock(secret, credentialId = 7L, unixSeconds = now)
// Send the 18 bytes through the configured TOTP BLE/NFC endpoint.
val result = OpenLock.decodeResponse(receivedBytes)
```

For TOTP, provision a unique 32-byte key per lock/credential through a trusted
local path. `encodeUnlock(credentialId, timeStep, code)` also encodes a code
received out of band. IDs are `1..0xffffffff`, timestamps/steps are nonnegative,
and codes are `0..99_999_999`. A result is unauthenticated; correlate its ID/step
but do not treat it as proof of physical opening. Code 24 rejects a consumed or
superseded step. Consumption survives failed actuation, reconnection and reboot.

Run `gradle --no-daemon --console=plain build` to build the JVM package. Build
Rust `openlock-ffi` with its default `secure,totp` features for each Android ABI,
make the library available to the Android linker, and build the JNI shim in
`src/main/cpp`. Package both `libopenlock_jni.so` and `libopenlock_ffi.so`.
Both entry points load `openlock_jni`, which exports the two method sets and
links Rust. The header path points to the canonical `include/openlock.h`.

BLE/NFC callbacks, key storage and authentication mode selection belong to the
application. Lock firmware must enforce the mode's authorization and persistence
contract; packet decoding is not authorization. See the
[protocol specification](../../docs/protocol.md),
[TOTP contract](../../docs/protocol.md#totp) and
[architecture guide](../../docs/architecture.md).
