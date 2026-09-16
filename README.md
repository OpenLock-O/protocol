# OpenLock

OpenLock v3 is an offline BLE/NFC access protocol for small, battery-powered
locks. It uses **plaintext requests authenticated by a one-time TOTP**. There is
no handshake, asymmetric cryptography, encrypted session, certificate, CBOR
parser, or application fragmentation. No cloud service or vendor SDK is needed.

- RFC 6238 HMAC-SHA-256, 32-byte per-credential secret, 30-second period,
  eight-digit OTP, fixed ±1-step clock tolerance.
- One 18-byte unlock request and one 15-byte result. Both fit the default BLE
  ATT MTU of 23 without negotiation, or one NFC APDU data field each.
- A successful OTP is consumed **durably before actuation**. Repetition,
  reconnection, another transport, and reboot cannot authorize it again.
- Five attempts per lock per local time step, including unknown credential IDs;
  the budget also survives reboot. Local validity intervals and usage limits
  are optional.
- All seven runtime crates support **`no_std` without an allocator**. Runtime
  cryptography needs no RNG. Provisioning needs securely generated keys.

The host supplies a trusted RTC, atomic durable storage, BLE/NFC I/O, and an
actuator callback. Missing/untrusted time or storage failure prevents opening.
This implementation reduces protocol work; it does not establish a measured
battery-life or board memory budget.

Plaintext TOTP does not provide confidentiality, mutual authentication, or
protection against an unused OTP being intercepted and used first or relayed in
real time. Responses and NFC discovery are unauthenticated. Provision a unique
random secret per `(lock, credential)` through a trusted local path, never over
the plaintext access channel. See the [wire and security contract](docs/protocol.md)
and [firmware integration](docs/architecture.md).

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
provides Rust, Kotlin, Gradle, JDK 17, Swift, CMake, Ninja, and the Android SDK
(API 35) with NDK support. `local.properties` is generated and machine-local.
The embedded check targets `thumbv7em-none-eabihf`; no custom `getrandom`
backend or global allocator is required. It compiles libraries, not firmware.

## Workspace

| Crate | Responsibility |
| --- | --- |
| `openlock-types` | Fixed-size identifiers, requests, results and errors |
| `openlock-crypto` | Standard TOTP generation and constant-time code comparison |
| `openlock-protocol` | Stateless fixed-size plaintext wire encoding |
| `openlock-core` | Durable one-time use, attempt budget and local credential policy |
| `openlock-transport` | Borrowed complete-message transport interface |
| `openlock-transport-ble` | One complete message per GATT write/notification |
| `openlock-transport-nfc` | Public NDEF discovery and APDU data fields |
| `openlock-issuer` | Host-side preparation for local credential provisioning |
| `openlock-ffi` | Stateless C ABI for Swift and Kotlin clients |

Runtime crates default to `std`; firmware must set `default-features = false`
on every runtime dependency. Issuer and FFI are host-side crates. Rust APIs
return fixed arrays or borrowed slices, with no session handles or message heap.

## Migration from v2

Version 3 and crate version 0.3 are intentionally incompatible with v2. Upgrade
the lock and clients together and provision fresh symmetric credentials. There
is no automatic fallback. The previous Noise sessions, signed grants, remote
policy updates, device-key rotation records, and signed NFC bootstrap are
removed. Local provisioning owns credential installation, revocation, key
replacement and clock repair. Existing timed/count-limited access becomes
local credential configuration.

C/Swift/Kotlin clients now generate an unlock packet directly and decode a
response; they do not create, start or free a session. Details and migration
examples are in [architecture.md](docs/architecture.md) and the
[Kotlin binding README](bindings/kotlin/README.md).
