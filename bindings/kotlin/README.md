# Kotlin binding (OpenLock v3)

V3 contains both the fully supported secure v2 scheme and optional plaintext
TOTP. Choose the scheme explicitly through trusted application/device policy.
Do not fall back to TOTP when a secure session fails.

`OpenLockSession` retains the v2 API:

```kotlin
OpenLockSession.initiator(privateKey, lockPublicKey, capabilities).use { session ->
    // Existing v2 session handle ownership; platform I/O remains host-owned.
}
```

`OpenLock` is the separate stateless TOTP API:

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

BLE/NFC callbacks, secure key storage and explicit scheme selection belong to
the application. Lock firmware must enforce each scheme's authorization and
persistence contract; packet decoding is not authorization. See the
[v3 protocol overview](../../docs/protocol.md) and
[TOTP contract](../../docs/protocol-totp.md).
