# Kotlin binding (v3)

`OpenLock` is a stateless JVM/Android wrapper around the plaintext TOTP C ABI.
There are no session handles, handshakes, public-key parameters or native close
operations. Provision a unique 32-byte secret per lock/credential through a
trusted local path; never transmit the secret over the access channel.

```kotlin
val request = OpenLock.makeUnlock(secret, credentialId = 7L, unixSeconds = now)
// Send the 18 bytes over BLE or NFC using platform APIs.
val result = OpenLock.decodeResponse(receivedBytes)
// Correlate result.credentialId and result.timeStep with the submitted request.
```

`encodeUnlock(credentialId, timeStep, code)` also encodes an eight-digit code
received out of band. IDs must be in `1..0xffffffff`; timestamps/steps must be
nonnegative. The numeric code is in `0..99_999_999`.

A decoded response is unauthenticated. `errorCode == 0` is a reported success,
not cryptographic evidence of physical actuation. Code 24 means the step was
consumed/superseded and cannot actuate again. After an ambiguous result, do not
automatically issue another opening. After consumption, use a later step.

Run `gradle --no-daemon --console=plain build` to build the JVM package. Build
Rust `openlock-ffi` for each Android ABI, make `openlock_ffi` available to the
Android native linker, and build the JNI shim in `src/main/cpp`. Package both
`libopenlock_jni.so` and `libopenlock_ffi.so`. The Kotlin class loads
`openlock_jni`, which links the Rust ABI. The CMake include path points to the
repository's canonical `include/openlock.h`.

Android BLE/NFC callbacks, trusted client time, key storage and credential
lifetimes are application responsibilities. Native code clears its temporary
key buffer; the application owns copies in Java/Kotlin. Lock firmware must
implement the mandatory durable replay and rate-limit rules in
[the protocol](../../docs/protocol.md); decoding a packet alone is insufficient.
