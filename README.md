# OpenLock

OpenLock is an offline BLE/NFC access protocol with two authentication modes:
**encrypted sessions** and **plaintext TOTP**. Devices can enable either or both
through trusted configuration according to their access policy and hardware
requirements. The host supplies platform I/O, storage, clocks and actuation;
OpenLock does not require a cloud service or vendor SDK.

| | Encrypted sessions | TOTP |
| --- | --- | --- |
| Authentication | Noise IK, X25519, Ed25519/COSE grants | RFC 6238 HMAC-SHA-256, 30 seconds, eight digits |
| Transport security | Authenticated, encrypted sessions | Plaintext bearer OTP; responses unauthenticated |
| Operations | Unlock, Status, ApplyPolicy, device trust/rotation | Unlock; trusted local provisioning/management |
| Authorization | Holder-bound grants, epochs, revocation, time/use limits | Per-lock/per-credential key, local validity/use limits |
| Communication | Handshake, up to 4096-byte messages, bounded fragments | 18-byte request, 15-byte result, no application handshake/fragments |
| Firmware runtime | `no_std + alloc`, RNG for ephemeral keys | `no_std`, no heap or runtime RNG |

The [protocol specification](docs/protocol.md) defines shared access rules and
the wire contract for each mode. The [architecture guide](docs/architecture.md)
covers firmware integration, Rust modules, C ABI and mobile bindings.

Authentication mode selection is explicit. A failed handshake or authorization
check never permits automatic fallback to another mode. Credentials, revocation
and use counters are scoped to their mode; management coordinates them when a
user has both kinds of credential.

TOTP verification consumes a step durably **before** actuation and rejects reuse
across reconnects, transports and reboot. It also persists a lock-wide attempt
budget. Provision its shared key through a trusted path. TOTP does not provide
confidentiality, authenticated lock responses or protection against first-use
interception/real-time relay. Battery life and brownout durability require
measurements on the selected hardware.

## Workspace and bindings

| Component | Responsibility |
| --- | --- |
| `openlock-types` | Encrypted-session domain types and stable errors |
| `openlock-crypto` | Noise IK, COSE/Ed25519 and device trust/rotation |
| `openlock-protocol` | Encrypted-session envelope and `Session` state machine |
| `openlock-core` | Signed-grant authorization, policy versions and durable use counters |
| `openlock-transport`, `openlock-transport-ble`, `openlock-transport-nfc` | Encrypted-session framing, reassembly and signed NFC bootstrap |
| `openlock-totp` | TOTP types, crypto, authorization, wire encoding, transports and local provisioning |
| `openlock-issuer` | Signed grants, policies and device records; TOTP provisioning through its `totp` module |
| `openlock-ffi` | C ABI for both authentication modes |

Firmware can depend only on the components it needs. A TOTP-only device uses
`openlock-totp` with `default-features = false`, without introducing the
session cryptography, CBOR, allocator or RNG dependencies.

FFI enables `secure` and `totp` by default. A smaller host library can use
`--no-default-features --features secure` or `--features totp`. Swift/Kotlin
expose `OpenLockSession` for encrypted sessions and the stateless `OpenLock`
helpers for TOTP. Consumers using both link the default combined FFI library.

Wire identifiers and cryptographic domain strings are defined in the
[compatibility section](docs/protocol.md#wire-identifiers-and-compatibility).
They are fixed encoding values, independent of the Cargo workspace release.
Existing clients and credentials continue to use their configured mode.

## Development

The project uses [Devenv](https://devenv.sh/) and Direnv:

```sh
direnv allow
devenv shell
# Once for an empty dependency cache:
CARGO_NET_OFFLINE=false cargo fetch
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace --locked
cargo build --workspace --all-targets --locked
devenv shell -- no-std-check
```

The shell pins tools through `devenv.lock`, defaults Cargo to offline mode, and
provides Rust, Kotlin, Gradle, JDK 17, Swift, CMake, Ninja and Android SDK/NDK
support. `local.properties` is generated and machine-local.

`no-std-check` tests both modes without default features, then compiles the
session libraries for `thumbv7em-none-eabihf` with the custom RNG backend setting
and compiles TOTP independently without that setting. These are library checks,
not linked/running firmware images. See [integration](docs/architecture.md).
