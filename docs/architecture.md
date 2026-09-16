# OpenLock v3 architecture

V3 fully includes the secure v2 implementation and offers a separate TOTP
implementation. The original secure runtime crates retain their source APIs and
wire behavior; `openlock-totp` is an independent crate for constrained devices.
Both are members of the same version 0.3 Cargo workspace.

```text
Trusted deployment configuration
  |
  +-- Secure scheme --> original openlock-* crates
  |                    Noise / COSE / policy / trust / fragmentation
  |                    v2 wire and APIs remain compatible
  |
  +-- TOTP scheme ----> openlock-totp
                       HMAC / durable one-time use / local policy
                       small plaintext packets, no heap or RNG

Host-side openlock-ffi (default: both)
  +-- original openlock_session_* and credential-ID ABI
  +-- stateless TOTP generation/encoding/decoding ABI
```

There is no authentication downgrade or automatic fallback between paths. Both
library features being present does not enable TOTP access on a device: the
host must explicitly provision and enable that scheme. The
[protocol overview](protocol.md) defines selection and authorization isolation.

## Secure v2 integration

The seven existing runtime crates (`openlock-types`, `openlock-crypto`,
`openlock-protocol`, `openlock-core`, `openlock-transport`,
`openlock-transport-ble`, `openlock-transport-nfc`) retain the complete v2
implementation and API. This includes Noise sessions, signed grants, policy
updates, trust/rotation, signed NFC bootstrap and bounded fragmentation.

They support `no_std + alloc` with default features disabled. Firmware supplies
a global allocator, panic handler, secure RNG backend for Noise ephemeral keys,
and its BLE/NFC, clock, storage and actuator integration. The existing
[secure embedded integration contract](architecture-v2.md#embedded-integration)
is retained in full. Secure `PROTOCOL_VERSION` and Noise prologue remain at v2,
so old clients and credential material remain usable.

## Independent TOTP integration

TOTP-only firmware needs one dependency:

```toml
[dependencies]
openlock-totp = { version = "0.3", default-features = false }
```

For a checkout-based build, use `path = ".../crates/openlock-totp"` instead of
a registry version. The crate is not dependent on any secure runtime crate and
has no Noise, Ed25519, X25519, CBOR, allocator or getrandom dependency. Its
modules are `types`, `crypto`, `core`, `protocol`, `transport::{ble,nfc}` and
`provisioning`. See [TOTP firmware integration](architecture-totp.md).

`openlock_totp::core::LockState` enforces the durable replay and attempt budget
rules. TOTP primitives and wire parsers alone do not authorize opening. Keys,
usage and policy types belong to the TOTP namespace; v2 `Grant`, `Issuer`,
`LockState`, `CredentialId` and error types retain their original meanings.
`openlock_issuer::totp` re-exports the TOTP local provisioning helpers for host
applications alongside the original signing issuer.

## C and mobile bindings

The default `openlock-ffi` exports both schemes. The original `openlock_session_*`
and `openlock_credential_id` symbols and layouts are retained. The added
`openlock_totp`, `openlock_make_unlock`, `openlock_encode_unlock`,
`openlock_decode_unlock`, `openlock_encode_response` and
`openlock_decode_response` symbols are TOTP-only helpers. Both header copies
contain the same declarations; C ABI structs are native layouts, not packets.

Feature selection can limit the exported implementation:

```sh
# Combined (backward-compatible default):
cargo build -p openlock-ffi
# Secure only:
cargo build -p openlock-ffi --no-default-features --features secure
# TOTP only, excluding secure crypto/session dependencies:
cargo build -p openlock-ffi --no-default-features --features totp
```

Headers declare both schemes. Consumers of a restricted build must use only its
selected symbols. FFI remains host-side; embedded TOTP firmware uses
`openlock-totp` directly. FFI feature selection is a build choice, not a device
security negotiation mechanism.

Swift and Kotlin expose the original `OpenLockSession` APIs and the added
stateless `OpenLock` TOTP helpers. The combined wrappers should link the default
combined FFI library. JNI exports both sets of methods in `openlock_jni`, linked
to `openlock_ffi`; both Kotlin entry points load the JNI shim. Applications own
platform I/O, key storage and explicit scheme selection.

## Compatibility with the TOTP proposal

The former replacement-only proposal's Rust implementation moved as follows:

| Proposal crate | Final optional scheme module |
| --- | --- |
| `openlock-types` | `openlock_totp::types` |
| `openlock-crypto` | `openlock_totp::crypto` |
| `openlock-core` | `openlock_totp::core` |
| `openlock-protocol` | `openlock_totp::protocol` |
| `openlock-transport` | `openlock_totp::transport` |
| `openlock-transport-ble` / `openlock-transport-nfc` | `openlock_totp::transport::ble` / `openlock_totp::transport::nfc` |
| local TOTP issuer | `openlock_totp::provisioning` or `openlock_issuer::totp` |

Its TOTP wire bytes and C/mobile entry points remain available. The original
crate names again denote the fully supported secure v2 scheme. New projects
should use these explicit namespaces and avoid mixing the schemes' credentials,
clocks, counters or transport codecs.

## Verification

`cargo test --workspace` covers the retained secure suite and the TOTP suite,
including secure fixed wire bytes, Noise sessions, signed grants/policies,
trust/rotation, transport framing, RFC TOTP vectors, one-time use across reboot
and BLE/NFC, persistent throttling, clock rollback and ambiguous commit/actuator
failures. A combined-ABI test exercises both paths and rejects a TOTP packet in
a secure session. Build checks cover each restricted FFI feature set.

`devenv shell -- no-std-check` runs runtime tests without default features,
checks secure libraries for `thumbv7em-none-eabihf` using the existing custom RNG
setting, and checks `openlock-totp` separately without that setting. These checks
do not link firmware or measure physical brownout recovery, RAM/flash or power.
