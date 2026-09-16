# OpenLock

**OpenLock v3 fully includes the v2 secure scheme and adds plaintext TOTP as an
optional scheme.** The v2 protocol, functionality and public APIs remain
supported. TOTP is a separate choice for constrained, battery-powered hardware;
there is no automatic downgrade from a secure session to plaintext.

The Cargo workspace is version 0.3. The secure scheme retains **wire version 2**
and its original Noise prologue, CBOR/COSE formats and error codes so existing
v2 clients remain compatible. The TOTP scheme uses its own **wire version 3**
fixed-size messages. See the [v3 protocol overview](docs/protocol.md).

| | Secure scheme, fully compatible with v2 | Optional TOTP scheme |
| --- | --- | --- |
| Rust entry point | Existing `openlock-*` runtime crates | Independent `openlock-totp` crate |
| Authentication | Noise IK, X25519, Ed25519/COSE grants | RFC 6238 HMAC-SHA-256, 30 seconds, eight digits |
| Transport security | Encrypted, authenticated sessions | Plaintext bearer OTP; responses unauthenticated |
| Operations | Unlock, Status, ApplyPolicy, device trust/rotation | Unlock; trusted local provisioning/management |
| Authorization | Holder-bound grants, epochs, revocation, time/use limits | Per-lock/per-credential secret, local validity/use limits |
| Communication | Handshake, up to 4096-byte packets, bounded fragments | 18-byte request, 15-byte result, no application handshake/fragments |
| Firmware runtime | `no_std + alloc`, RNG for Noise ephemeral keys | `no_std`, no heap or runtime RNG |

A deployment explicitly enables its scheme(s) through trusted configuration.
Enabling both library features does not authorize a device to accept both kinds
of credential. BLE/NFC endpoints and credentials must be associated with the
configured scheme. Failure to authenticate in one scheme never permits trying
the other automatically. Revocation and counters are scoped to each scheme;
management must coordinate them if one user has credentials in both.

TOTP verification consumes a step durably **before** actuation and rejects
reuse across reconnects, transports and reboot. It also persists a lock-wide
attempt budget. The shared key never belongs on the plaintext access channel.
TOTP does not provide confidentiality, authenticated lock responses or
protection against first-use interception/real-time relay. See the
[TOTP contract](docs/protocol-totp.md). Both schemes depend on host integration
for BLE/NFC I/O, storage, clocks and physical actuation; battery life and
brownout durability need measurements on the selected hardware.

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

`no-std-check` tests both runtimes without default features, then compiles the
secure libraries for `thumbv7em-none-eabihf` with the custom RNG backend setting
and compiles TOTP independently without that setting. These are library checks,
not linked/running firmware images. See [integration](docs/architecture.md).

## Workspace and bindings

The original v2 crates retain their responsibilities and APIs:

- `openlock-types`: secure domain types and stable errors.
- `openlock-crypto`: Noise IK, COSE/Ed25519 and device trust/rotation.
- `openlock-protocol`: secure envelope and `Session` state machine.
- `openlock-core`: grant authorization, policy versions and durable use counters.
- `openlock-transport`, `openlock-transport-ble`, `openlock-transport-nfc`:
  secure message fragmentation and signed NDEF bootstrap.
- `openlock-issuer`: signed grants, policies and device records; the additional
  `totp` module exposes local TOTP provisioning helpers.
- `openlock-ffi`: all original C `openlock_session_*` and credential-ID symbols,
  plus the stateless TOTP symbols.

`openlock-totp` contains independent `types`, `crypto`, `core`, `protocol`,
`transport::{ble,nfc}` and `provisioning` modules. TOTP-only firmware depends on
this crate with `default-features = false`; it does not need the secure crates.

FFI defaults to both `secure` and `totp`. A smaller host library can be built with
`--no-default-features --features secure` or `--features totp`. The combined
Swift/Kotlin packages expose the original `OpenLockSession` and the TOTP
`OpenLock` helpers. Consumers using both link the default combined FFI library.

## Compatibility

Existing v2 wire messages, credentials, signed bootstrap records and public
Rust/C/Swift/Kotlin APIs remain supported in v3. No forced key migration or
TOTP enrollment is required for a secure-only deployment. The previous
replacement-only TOTP proposal has been reorganized: its Rust implementation
now lives under `openlock_totp::*`; its stateless C/mobile APIs remain available.

Read the [secure v2 wire contract](docs/protocol-v2.md),
[TOTP wire contract](docs/protocol-totp.md), and
[scheme selection and integration](docs/architecture.md) for the two paths.
