# OpenLock v2 architecture

OpenLock v2 is a Cargo workspace with one protocol state machine and multiple
byte transports. `openlock-protocol::Session` owns Noise handshake and request
encoding. A transport codec converts complete protocol messages into fragments
for its medium.

The NFC bootstrap record is a signed CBOR device-key record. It can be stored
in a passive NDEF tag, verified using the configured issuer root, and placed in
a local trust store. Full sessions use the same Noise IK profile over BLE GATT
or NFC ISO-DEP/APDU. Rust does not access platform hardware; Swift and Kotlin
supply reader, card-emulation, BLE callbacks and persistence.

The v2 complete packet limit is 4096 bytes. BLE uses bounded out-of-order
fragments sized from the negotiated ATT MTU (default 23 bytes). ISO-DEP uses a
sequence byte and a two-byte total length. Both codecs reject conflicting
duplicates, truncation, overflow and sequence errors.

Device X25519 keys are used for Noise identity and are not used to sign key
updates. Device records and rotation records use an independent Ed25519 key or
the configured issuer key. Key versions are monotonic and old versions cannot
replace a newer record.

## Embedded integration

The runtime libraries support `no_std + alloc` with default features disabled.
This retains their existing `Vec`, `Box`, `BTreeMap` and `BTreeSet` interfaces,
packet limits, v2 wire encoding and authorization behavior. The firmware owns
the global allocator and panic handler, including allocation failure behavior;
the libraries do not install either. This configuration does not imply a fixed
RAM budget or a heap-free implementation. Issuer and FFI remain host-side crates.

Noise still uses `Noise_IK_25519_ChaChaPoly_SHA256`. Its ephemeral keys are
generated through `getrandom` 0.3. For a bare-metal build, select the custom
backend in the firmware's `.cargo/config.toml`:

```toml
[target.thumbv7em-none-eabihf]
rustflags = ['--cfg', 'getrandom_backend="custom"']
```

The final firmware must depend directly on the same `getrandom` 0.3 version
and export exactly one unmangled Rust-ABI symbol named
`__getrandom_v03_custom` using `#[unsafe(no_mangle)]`. Its signature is:

```text
unsafe fn __getrandom_v03_custom(dest: *mut u8, len: usize) -> Result<(), getrandom::Error>
```

On success, the backend must initialize all `len` bytes at `dest` with
cryptographically secure random data. The destination may initially be
uninitialized; it must not be read before being written. Report entropy source
failure as `getrandom::Error`, rather than returning predictable bytes. OpenLock
maps RNG failures to its existing `Error::Noise` and closes the channel when a
Noise read or write fails. Backend selection is an application build setting,
not an OpenLock API or a new protocol capability.

BLE/NFC I/O, trusted time, durable storage and actuator integration remain the
application's responsibility. `devenv shell -- no-std-check` runs host tests
without default features and compiles the runtime libraries for
`thumbv7em-none-eabihf` using the custom backend. The compile check does not
provide that symbol or a global allocator, and does not link or execute a
firmware image.
