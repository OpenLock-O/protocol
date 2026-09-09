# OpenLock

OpenLock is an offline BLE/NFC access protocol reference implementation. It does
not require a cloud service, vendor SDK, secure element, or particular lock
hardware. The v2 core is transport independent: a host supplies its BLE/NFC
stack, trusted clock, durable storage, and actuator callbacks.

## Environment

The project uses [Devenv](https://devenv.sh/) and Direnv:

```sh
direnv allow
devenv shell
devenv shell check
devenv shell unit-tests
```

The declared shell installs Rust through `rust-overlay`, pins its inputs in
`devenv.lock`, and defaults Cargo to offline mode. Populate a new dependency
cache once with `CARGO_NET_OFFLINE=false cargo fetch`, then use the offline
commands above.

The same shell provides Kotlin, Gradle, JDK 17, Swift, CMake, Ninja and the
Android SDK (API 35) with NDK support. Android SDK licenses are enabled through
`devenv.yaml`; `local.properties` is generated automatically and remains
machine-local.

The seven runtime crates (`openlock-types`, `openlock-crypto`,
`openlock-protocol`, `openlock-core`, `openlock-transport`,
`openlock-transport-ble`, and `openlock-transport-nfc`) default to `std` and
support `no_std + alloc` with `--no-default-features`. Downstream firmware must
set `default-features = false` on every OpenLock runtime dependency. Cargo
unifies features, so enabling `std` through any dependency restores it for the
affected crates. An embedded application must provide a global allocator,
a hardware-backed `getrandom` custom backend for Noise ephemeral keys, and its
own BLE/NFC stack, clock, durable storage and actuator integration. The issuer
and FFI crates remain host-side tools.

The development shell includes `thumbv7em-none-eabihf`. Run the runtime tests
without default features and the embedded compile check with:

```sh
devenv shell -- no-std-check
```

The script selects the custom RNG backend only for the embedded check; host
tests use the host OS RNG. See [embedded integration](docs/architecture.md#embedded-integration)
for the allocator, panic handler and RNG contracts. The target check compiles
the libraries; it does not link or run board firmware.

## Workspace

- `openlock-types`: shared v2 domain types and stable errors.
- `openlock-crypto`: Noise IK, COSE/Ed25519 and device trust/rotation.
- `openlock-protocol`: transport-neutral envelope and session state machine.
- `openlock-core`: policy versions, time windows and durable usage counters.
- `openlock-transport-ble`: bounded, out-of-order GATT framing.
- `openlock-transport-nfc`: signed NDEF bootstrap and ISO-DEP/APDU framing.
- `openlock-issuer`: offline grant, policy and device-record helpers.
- `openlock-ffi`: C ABI used by Swift and Kotlin byte-oriented wrappers.

See [the v2 architecture](docs/architecture.md) and [the v2 protocol](docs/protocol.md).

A grant binds a lock, credential ID, holder public key, rights, epoch, optional
validity interval, and optional maximum uses. Counted grants are consumed
durably before an actuator callback; an ambiguous result is never retried
automatically.
