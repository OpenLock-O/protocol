# OpenLock

OpenLock is an offline, encrypted BLE/NFC lock protocol and reference implementation.
It defines physical lock behavior, phone commissioning, authorization, device management
and signed firmware delivery. Platform firmware supplies durable storage, clocks,
sensors, actuators and a verifying bootloader; no cloud or vendor SDK is required.

The workspace is based on the `b564e0e` encrypted-protocol implementation. There is one
Noise-encrypted authentication path. The current release is **0.4.0**, using
**wire version 4 / profile 1**. Signed grants, policies and device trust objects
retain their independent v2 formats and signature domains.

| Component | Responsibility |
| --- | --- |
| `openlock-types` | Commands, physical state, capabilities, permissions, results and stable errors |
| `openlock-crypto` | Noise IK, COSE/Ed25519, signed firmware, device rotation, canonical CBOR and secret QR payloads |
| `openlock-protocol` | Encrypted session, request correlation and bounded message encoding |
| `openlock-core::device` | Serialized device controller, commissioning, durable operation deduplication, lock behavior, management and firmware state machines |
| `openlock-transport`, BLE and NFC adapters | Bounded framing and signed NFC discovery |
| `openlock-issuer` | Offline signing of access grants, revocation policies and device trust records |
| `openlock-ffi` | Buffer-safe C session, event and signing APIs |
| Swift / Kotlin | Typed commands, state, operation results, commissioning and administrator helpers |

`Unlock` releases the locking mechanism; it does not assert that a door opened.
Physical bolt state, door state, actuator progress and completion evidence are
separate. Unsupported sensors and unknown readings are explicit. Only accepted
unlock attempts consume unlock uses, durably before driving. Reconnects and
reboots never restore a consumed use or replay an ambiguous operation.

Read the [wire and behavior specification](docs/protocol.md) and the
[platform integration guide](docs/architecture.md). They include command permissions,
state transitions, storage contracts, migration and hardware validation requirements.

## Development and verification

```sh
direnv allow
# For an empty Rust dependency cache:
devenv shell -- sh -c 'CARGO_NET_OFFLINE=false cargo fetch'
devenv shell -- check
devenv shell -- cargo test --workspace --locked
devenv shell -- cargo build --workspace --all-targets --locked
devenv shell -- no-std-check
devenv shell -- scripts/check-bindings.sh
```

The last command builds a Rust simulated device and drives its complete lifecycle
from **native C, Swift, and Kotlin/JNI**, including actual Noise sessions. It checks
binding, unlock/lock, state, configuration, logs, signed upgrade, revocation,
clock maintenance and factory reset. Swift/Kotlin additionally exercise device-key
rotation and reconnection using the new key. Test keys are deterministic and must
never be used in a device.

The runtime crates support `no_std + alloc`; the embedded compile target is
`thumbv7em-none-eabihf`. Issuer, FFI and the executable simulator are host tools.
The Devenv environment includes Rust, Swift, Kotlin, Gradle, JDK 17, CMake and JNI
headers. `JDK17_HOME` explicitly selects the declared Java toolchain for Gradle.
The Swift integration runner is an executable, so it does not require XCTest.

The implementation does not include board-specific drivers, a phone UI, flash
partitioning or a production bootloader. The reference tests simulate these
interfaces; actuator safety, brownout durability and boot recovery must also be
verified on the selected hardware.
