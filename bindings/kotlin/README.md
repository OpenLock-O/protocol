# OpenLock Kotlin/JNI

`OpenLockSession` implements the v4 encrypted protocol. Use `LockAction` for all
physical and management commands, and inspect typed `SessionEvent.Response` and
`LockReply` values. `Reading.Unsupported` and `Reading.Unknown` are distinct;
`OperationPhase.RUNNING` is not proof of physical unlocking.

```kotlin
OpenLockSession.initiator(holderPrivateKey, trustedLockPublicKey).use { session ->
    // Exchange session.start() and session.receive(...) handshake packets.
    val request = session.send(LockAction.Unlock, grant, nextSequence)
    // Platform BLE/NFC transports request.packet; receive returns the full result.
}
```

Use `SetupPayload(qrText)` to read secret factory initialization credentials.
After a physical pairing gesture, query `LockAction.PairingStatus`, issue the
initial grant with `OpenLockIssuer.issue`, then send `LockAction.claim`. Reconnect
following successful claim or any ownership/device identity change. Keep the
operation sequence in persistent application state, independent of the session.

`OpenLockIssuer` provides Ed25519 public keys, grant issuance, revocation policies
and firmware manifests. `signDeviceKey` and `signRotation` prepare device trust
updates. Hardware keys and firmware verification roots are provisioned separately.
Application code owns Android Keystore integration and copies of secret arrays.

Build under the repository Devenv shell. Its `JDK17_HOME` is registered in
`gradle.properties`, so Gradle selects JDK 17 even when another JDK starts Gradle.

```sh
devenv shell -- scripts/check-bindings.sh
```

This builds and runs desktop JNI integration against the Rust device simulator.
For Android, compile `openlock-ffi` for each Android ABI and pass the directory
containing that library to CMake as `OPENLOCK_LIBRARY_DIR`. Package both
`libopenlock_jni.so` and `libopenlock_ffi.so`. The JAR includes consumer rules in `META-INF/proguard/openlock.pro` to retain
JNI entry points and the native exception constructor in R8/ProGuard release
builds. Keep these rules when repackaging the library; manually configured
shrinker pipelines must include them.

Desktop CMake locates JNI headers
with `find_package(JNI)`; Android uses NDK headers.

See [protocol](../../docs/protocol.md) and [integration](../../docs/architecture.md)
for permissions, wire formats, durable storage and physical confirmation contracts.
