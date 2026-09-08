# OpenLock

OpenLock is an offline BLE access protocol reference implementation. It does
not require a cloud service, vendor SDK, secure element, or particular lock
hardware. The core is transport independent so a host supplies its BLE stack,
trusted clock, durable storage, and actuator callbacks.

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

## Crates

- `openlock-core`: Ed25519/COSE-Sign1 credentials, Noise IK sessions, policy
  versions, time windows, and durable usage counters.
- `openlock-ble`: bounded, out-of-order GATT fragment framing.
- `openlock-issuer`: offline administrator grant and revocation helpers.
- `openlock-ffi`: C ABI and `include/openlock.h` for embedding.

A grant binds a lock, credential ID, holder public key, rights, epoch, optional
validity interval, and optional maximum uses. Counted grants are consumed
durably before an actuator callback; an ambiguous result is never retried
automatically.
