# OpenLock implementation and integration

OpenLock has one encrypted access protocol. `Session` handles Noise and message
correlation; `DeviceController` interprets authenticated requests and owns all
physical and persistent device behavior. BLE and NFC only carry complete bytes.

```text
BLE/NFC framing -> Session -> authenticated peer + Command
                                  |
                         DeviceController
                         /       |        \
             DeviceStorage   DevicePlatform   Bootloader
             atomic state    clock/sensors    signed staging
             uses/results    physical I/O     trial/recovery
                                  |
                             typed Response
                                  |
                         Session -> BLE/NFC
```

## Runtime and state ownership

Use one controller for a physical device across every connection and local
management path. Serialize calls. Do not make a controller per connection or
share storage between independent controllers without serialization.

The runtime crates use `std` by default, including on ESP32 with ESP-IDF. They also
support `no_std + alloc` for bare-metal firmware: disable default features on every
runtime dependency in that case; Cargo feature unification can otherwise restore
`std`. Bare-metal firmware supplies the allocator, panic handler and entropy source.
ESP-IDF supplies these through its Rust `std` integration. Both paths require
platform storage and I/O implementations.
The issuer and FFI are host libraries. The simulator uses `std` and deterministic
test identities; it is not board firmware.

A minimal application flow is:

1. Call `DeviceController::open` with trusted factory inputs and the durable store.
2. Construct each responder session using the current device key and capabilities.
3. At `HandshakeComplete`, capture `controller.context(peer)` once for that session.
4. At `Request`, call `controller.handle(captured_context, &command)`.
5. Encrypt the response with `Session::respond` and transmit it.
6. If the controller generation changed, close all sessions with an older generation.
7. Forward actual hardware events to `hardware_changed` and `actuator_finished`;
   call `poll` for deadlines and boot outcomes even when no client is connected.

The example `crates/openlock-core/examples/simulator.rs` executes this flow.
`SessionContext` is a trusted host value, never parsed from a packet. Recreating
it per request would defeat generation invalidation. Local management uses the
same authorization/controller path through `handle_local`; it still supplies a
valid administrator grant. Factory provisioning, pairing-button events and
physical confirmations are separate trusted local methods.

### Platform interfaces

C ABI events include the authenticated peer key and can be larger than their
encrypted wire packet. Packets remain bounded by `OPENLOCK_MAX_MESSAGE_SIZE`
(4096 bytes); local event buffers use `OPENLOCK_MAX_EVENT_SIZE` (4160 bytes) or
the size returned by `openlock_session_take_event` with NULL/0. A short buffer
leaves the complete event queued for a subsequent drain.

| Interface | Required behavior |
| --- | --- |
| `DeviceStorage::load` | Return the latest integrity-checked record; distinguish absent storage from read failure or corruption. |
| `DeviceStorage::commit` | Atomically persist the complete snapshot before success. Failure may be ambiguous; the controller then refuses further work until reopened. |
| `DevicePlatform::monotonic_ms` | Monotonic duration source for this boot; rollback poisons the instance. |
| `wall_clock` / `set_wall_clock` | Trusted Unix-second interval and privileged clock adjustment. Missing RTC validity is `None`. |
| `sensors` | Actual readings matching the advertised hardware, including unknown/unavailable values. |
| `start_action` | Start once without waiting for radio progress. Enforce pulse maximum time in hardware. |
| `stop_action` | Quiesce the drive, including as the first step of every constructor before configuration validation or storage access. It must safely succeed when already idle, or report failure so initialization/movement cannot continue. |
| `request_reboot` | Schedule reboot after response delivery or a bounded transmission deadline. |
| `has_device_private_key` | Confirm securely installed private material for the proposed rotation public key. |
| `bootloader` | Return a backend only when signed staging, boot verification and recoverable trials are implemented. |

Successful `start_action` means started, not physically unlocked. Complete through
`actuator_finished(id, result)`, with a fresh sensor sample and the exact
`ActuationId` passed to `start_action`. Capture that ID in the driver operation
and its queued callback; never replace it with the latest ID on delivery. IDs
remain distinct across reboots and ownership changes. Stale callbacks return
`InvalidState` without releasing or completing the current drive. Mechanical/manual transitions
use `hardware_changed` even when no wireless action is active. Door state and
bolt state are never inferred from each other. Periodic calls must meet configured
timeout/reminder resolution; firmware must make pulse safety independent of this
scheduler. Board policy owns local emergency egress and electrical fail behavior.

### Durable records and migration

`DeviceSnapshot` contains owner/epoch/generation, policy/revocations, unlock uses,
credential digests, sequence watermarks, bounded operation results, versioned
configuration, bounded audit history, clock watermark, relock intent, firmware
transfer/security state, and active device public identity.

Use explicit field serialization with integrity checking and an atomic journal,
transactional NVM or equivalent. Rust struct layouts, `Option` layouts and raw
memory dumps are not storage formats. Preserve configured capacity bounds when
reading. The controller validates loaded fields and retained firmware signatures.
A commit error poisons the in-memory instance because either the previous or new
record may be durable. Reopen from authoritative state; never restore defaults.

The authorization clock watermark never decreases in a snapshot commit.
`SetClock` checks the latest durable watermark and trusted RTC again after
acceptance, so a tick during persistence cannot revive an expired credential.
Timed authorization and key-rotation checks use the exact clock interval whose
lower bound was persisted, including when the check rejects a credential. A
subsequent RTC read during audit cannot erase an observed expiration or restore
trust after an observed missing/rolled-back time.
Mutation preflight checks the grant again against its latest clock observation
before reserving a sequence or use.

`provision` only accepts an absent store. `open` only accepts an existing valid
store. `migrate_legacy` explicitly copies a v2 `LockSnapshot` into a new v4 store,
including epoch, policy version, revocations and consumed uses. Supply issuer,
current device keys and first-admin identity from trusted provisioning. Retain
the old store until the new record commits. Insufficient capacity fails migration
rather than dropping data. Wire upgrades do not reset authorization state.

Client-side `TrustStore` also fails closed after an ambiguous commit: `get` returns
no trusted record, and mutations and `snapshot` return `StorageUnavailable`.
Reload the complete integrity-checked durable snapshot with `from_snapshot`;
do not reconstruct an empty trust store from discovery records after an error.


Persist sequence watermarks even after operation results are evicted. A result
cache is not a sufficient replay barrier. Reusing a credential ID for changed
grant contents in one epoch is rejected after its first mutation. Issue a new ID
for a changed grant. Revocation/policy epochs provide explicit domain changes. Authorized epoch
changes, issuer replacement and physically confirmed reset atomically replace
the old domain without first allocating a credential or result slot. They remain
available at full capacity; the new epoch itself prevents old-grant replay.

The actuator owner remains exclusive after an ambiguous start error. On reboot,
accepted/running operations become Unknown and are not driven again. A pending
automatic relock is evaluated from fresh door readings, with its intent treated
as due. Once a relock attempt has durably claimed the intent, another reboot does
not replay that drive. Recovery may consume a use without opening the lock.

After durable acceptance, both manual and automatic drives re-sample physical
interlocks immediately before starting, with no intervening storage access.
If the door or privacy input changes during the acceptance write, the operation
fails without driving; its durable sequence/use reservation remains consumed.
The actuator timeout starts from this post-commit check. Platform drivers must
still enforce electrical interlocks and pulse limits at the hardware boundary.
If that sample already confirms the target bolt position, completion records
sensor evidence without starting a drive; an already reserved unlock use remains
consumed. Unrelated configuration changes preserve a pending relock and its
deadline even without a reliable bolt reading. Changes to relock/hold-open policy
explicitly reschedule or cancel the obligation according to the new policy.

### Commissioning and physical confirmation

Generate independent factory X25519/rotation keys, a firmware-signing trust root
and a 32-byte random setup key. Encode the setup artifact with
`openlock_crypto::commissioning::SetupPayload`; retain the setup-key hash in
`FactoryIdentity`. Factory inputs are outside erasable user state. Keep their
private material in the platform's secure storage. Secret wrapper/debug behavior
does not erase copies made by application code, QR scanners or platform buffers.

A local gesture calls `open_pairing_window`. The phone scans/pins the QR identity,
starts Noise, queries PairingStatus, issues a full-rights initial grant for that
epoch, and sends Claim. Reconnect after ownership is committed. Setup-key
comparison uses `subtle` constant-time equality. Claim action and QR wrappers
redact secrets in Debug and zero their owned setup bytes on drop.

For reset or issuer replacement, display/identify the exact proposed operation
locally, obtain a physical gesture and call `confirm_physical(context, command)`.
This stores a one-shot digest for 60 seconds. Do not expose that method as an
untrusted transport callback. The same command then follows ordinary `handle`.

### Firmware backend

`Bootloader` must durably begin staging and write bounded ranges, read existing
ranges for duplicate verification, hash the actual staged image and report power
readiness. Writes below the acknowledged offset are only duplicate reads; writes
at the acknowledged offset can repeat after a lost acknowledgment. Make that
retry safe for the selected flash technology, or require abort/restart.

Aborting first commits an empty transfer record, then calls `Bootloader::abort`
to erase staging. A reset or ambiguous failure therefore leaves either the old
record with its bytes untouched, or an empty record that cannot advertise erased
bytes as resumable or verified. A subsequent begin may replace orphaned staging.

`activate` receives both the manifest and its signed COSE bytes. The bootloader
independently validates them under its provisioned firmware root, checks the
hardware target/security policy and uses A/B partitions or an equivalent recovery
scheme. Its `outcome(candidate)` must use durable boot metadata for that exact manifest,
including its hash and security version. Report Pending while that candidate is
unresolved, Confirmed only after its successful boot confirmation, and RolledBack
after restoring the previous image or when the candidate was never activated.
A prior image’s confirmation must never confirm a newly staged candidate.
An activation error may still have scheduled a boot; keep the outcome truthful
and resolve it through the same interface, including across resets. The network
cannot assert boot success. The protocol commits a new security floor only after
Confirmed. Do not advertise firmware commands with a nonrecoverable backend.

### ESP32 with ESP-IDF and std

Use an ESP-IDF 5+ application and leave OpenLock's default `std` features enabled.
The runtime libraries use the same protocol and controller implementation as the
host. There is no ESP32-specific `no_std` feature or custom RNG callback to supply.

| Chip | Rust target | Rust toolchain |
| --- | --- | --- |
| ESP32 | `xtensa-esp32-espidf` | Espressif `esp` |
| ESP32-S2 | `xtensa-esp32s2-espidf` | Espressif `esp` |
| ESP32-S3 | `xtensa-esp32s3-espidf` | Espressif `esp` |
| ESP32-C2 / C3 | `riscv32imc-esp-espidf` | `nightly` with `rust-src` |
| ESP32-C6 / H2 | `riscv32imac-esp-espidf` | `nightly` with `rust-src` |

These are OS targets, separate from the `*-unknown-none-elf` bare-metal targets.
ESP32-S2 has no Bluetooth radio; use a supported external transport on that chip.
Select the ESP-IDF release and `MCU` for the actual board (C6/H2 require at least
ESP-IDF 5.1). See the [Rust ESP-IDF target guide](https://doc.rust-lang.org/rustc/platform-support/esp-idf.html).

Devenv provides `rustup` and `espup`. Install the extra toolchains once; this does
not change the workspace's normal stable Rust compiler:

```sh
devenv shell -- espup install --std --targets esp32,esp32s2,esp32s3
devenv shell -- rustup toolchain install nightly --profile minimal --component rust-src

# The first build also downloads the standard library's Cargo dependencies.
devenv shell -- sh -c '. "$HOME/export-esp.sh"; CARGO_NET_OFFLINE=false esp32-check'

# Subsequent builds can use the cached dependencies; choose one target if desired.
devenv shell -- sh -c '. "$HOME/export-esp.sh"; esp32-check xtensa-esp32-espidf'
```

Outside Devenv, install `rustup` and `espup` following the
[ESP Rust toolchain instructions](https://docs.espressif.com/projects/rust/book/getting-started/toolchain.html),
then use `bash scripts/check-esp32.sh` from the repository root. The script
accepts one or more target triples and defaults to all five targets in the table.
`ESP_XTENSA_TOOLCHAIN` and `ESP_RISCV_TOOLCHAIN` can select installed toolchain
versions instead of `esp` and `nightly`.

The check compiles release `.rlib` libraries with `-Zbuild-std=std,panic_abort`.
It verifies machine-code generation for all runtime crates, without linking a
complete firmware image or requiring the ESP-IDF SDK. Final firmware linking and
hardware behavior must be validated in the board application.

For a board application, start from the
[ESP-IDF Rust template](https://github.com/esp-rs/esp-idf-template), which provides
`esp-idf-sys`/`esp-idf-svc`, startup, SDK configuration and build-script link
integration. Add OpenLock dependencies with `std` enabled (paths below assume the
application is next to the `protocol` checkout):

```toml
[dependencies]
openlock-core = { path = "../protocol/crates/openlock-core", features = ["std"] }
openlock-protocol = { path = "../protocol/crates/openlock-protocol", features = ["std"] }
openlock-types = { path = "../protocol/crates/openlock-types", features = ["std"] }
openlock-transport-ble = { path = "../protocol/crates/openlock-transport-ble", features = ["std"] }
```

Cargo does not inherit configuration from dependencies. Keep these settings in
the application's `.cargo/config.toml`, along with the template's MCU/SDK settings:

```toml
[build]
target = "xtensa-esp32-espidf"

[target.'cfg(target_os = "espidf")']
linker = "ldproxy"
rustflags = ["--cfg", "espidf_time64"]

[unstable]
build-std = ["std", "panic_abort"]
```

`espidf_time64` matches ESP-IDF 5+'s 64-bit `time_t` ABI. Install `ldproxy` for
final linking (`cargo install ldproxy --locked`) and call the template's
`esp_idf_sys::link_patches()` (or `esp_idf_svc::sys::link_patches()`) at startup.
The repository scopes its ABI flags to ESP-IDF targets and passes `build-std`
only in the ESP32 check, so host and bare-metal builds keep their normal settings.

Noise's `getrandom` 0.3 dependency automatically uses ESP-IDF's `esp_fill_random`.
Before generating keys or starting a Noise handshake, ensure the chip's hardware
entropy source is active. On ESP32, that requires active Wi-Fi/Bluetooth or the
internal entropy source enabled under ESP-IDF's ADC/I2S/RF restrictions. This also
applies to NFC-only operation and radio sleep: `std` and `esp_fill_random` alone
do not ensure fresh entropy. See the
[ESP-IDF RNG requirements](https://docs.espressif.com/projects/esp-idf/en/stable/esp32/api-reference/system/random.html).
Do not select `getrandom_backend="custom"` for this path.

Implement `DeviceStorage` with explicit, integrity-checked serialization and atomic
durable commits, and `DevicePlatform` with board clocks, sensors and actuator
drivers. BLE/NFC framing remains transport-neutral; firmware supplies the actual
ESP-IDF radio or reader I/O. Keep controller access serialized across FreeRTOS
tasks and CPU cores, and only expose firmware-update capabilities after implementing
the verifying, recoverable `Bootloader` contract above.

### Bare-metal targets and RNG

The runtime libraries are built in release mode for `thumbv7em-none-eabihf`,
`riscv32imc-unknown-none-elf`, `riscv32imac-unknown-none-elf` and
`riscv64imac-unknown-none-elf`. The RV32IMC build checks support without the atomic
A extension; RV64IMAC also checks a 64-bit pointer ABI. Use the target matching
the chip's ISA and firmware ABI. These are bare-metal targets; an OS-based board
needs its corresponding OS target and integration.

Devenv's `embeddedTargets` list controls both installed targets and the
`embedded-check` build. Run all four builds with `devenv shell -- embedded-check`,
or build an individual runtime crate and its dependencies:

```sh
devenv shell -- cargo build --locked --release --no-default-features \
  --target riscv32imc-unknown-none-elf -p openlock-core
```

The protocol/runtime crates share the same implementation on ARM and RISC-V.
Firmware provides the allocator, panic handler, chip startup, linker script and platform
interfaces. Serialize controller access across interrupts and, where applicable,
harts; `no_std` does not make the controller concurrently callable. A firmware
runtime such as `riscv-rt` can supply RISC-V startup and linking support, with the
board's memory map. See the [Rust RISC-V target guide](https://doc.rust-lang.org/rustc/platform-support/riscv32-unknown-none-elf.html)
and [Rust platform support](https://doc.rust-lang.org/rustc/platform-support.html).

Noise uses `getrandom` 0.3. This repository's `.cargo/config.toml` selects its
custom backend only for bare-metal ARM/RISC-V, preserving OS entropy for host
tools and tests. Cargo does not inherit a dependency's workspace configuration;
when consuming OpenLock from another firmware project, add the matching entry
to that project's `.cargo/config.toml` (change the target for your chip):

```toml
[target.riscv32imc-unknown-none-elf]
rustflags = ['--cfg', 'getrandom_backend="custom"']
```

Link exactly one Rust-ABI `__getrandom_v03_custom` symbol using the matching
`getrandom` version and `#[unsafe(no_mangle)]`:

```text
unsafe fn __getrandom_v03_custom(dest: *mut u8, len: usize) -> Result<(), getrandom::Error>
```

Initialize every requested byte from a CSPRNG before success. Do not read
uninitialized destination memory or return predictable data on entropy failure.
The library maps Noise RNG failures to `Error::Noise`. The embedded library
compile check does not supply the final allocator, panic handler or RNG symbol.

## C and mobile clients

C is declared in `include/openlock.h`; the Swift header copy must match. C handles
are opaque and must be serialized. `start`, `send` and `respond` preflight output
size. A null/zero output or an undersized buffer returns -2 and the required size
without advancing the send state. The caller retries with sufficient capacity.

`receive` accepts input once and stores its complete event and optional handshake
reply. Drain `take_event` and `take_output`; small buffers retain queued values.
A second `receive` while either is pending returns Busy without consuming input.
Event CBOR is `[kind, request_id, peer_or_null, body_or_null]`, with kind 1
handshake, 2 request and 3 response. Body is the full canonical Command/Response.
A rejected lock action is an event result, not a C buffer/decoding error.

Swift exposes `OpenLockSession`, `LockAction`, `SessionEvent`, `LockReply` and
structured physical/configuration/audit/firmware values. Kotlin exposes the same
concepts, with JNI loaded as `openlock_jni`; Kotlin uses `ULong` for u64 fields.
Both issuers sign grants, revocation policies, firmware manifests, device records
and key updates. The administrator must use a separate firmware signing key.
Mobile apps own keychain/keystore storage, camera UI, user interaction and BLE/NFC.

```swift
let sent = try session.send(.unlock, credential: grant, sequence: nextSequence)
// Send sent.packet over the configured transport.
let received = try session.receive(packetFromLock)
if case .response(_, let response) = received.event,
   case .operation(let operation) = response.reply {
    // Running means accepted; query operation.sequence for the final result.
    print(operation.phase, operation.evidence)
}
```

```kotlin
val sent = session.send(LockAction.Unlock, credential = grant, sequence = nextSequence)
val received = session.receive(packetFromLock)
val response = (received.event as SessionEvent.Response).value
val operation = (response.reply as LockReply.Operation).value
// Persist nextSequence independently of the session; inspect operation.phase.
```

A disconnect does not authorize a new operation sequence. First query the old
operation or resend the identical request with the identical sequence. Unknown
and ResultUnavailable do not prove either opening or non-opening. Present that
uncertainty to the caller; do not automatically drive again.

Build the Rust FFI for each target ABI. Swift links `openlock_ffi` through its
module/linker declaration; supply its library search path or platform package.
Android packages both the JNI library and matching Rust library. The JNI CMake
project supports Android NDK and desktop JNI for integration tests.

## Verification and hardware acceptance

`devenv shell -- scripts/check-bindings.sh` builds Rust, the native C client, the
JNI library, Kotlin and the Swift executable runner. Each drives the Rust device
through real encrypted packets. The runner intentionally avoids XCTest so it can
run in the pinned Swift environment. CI runs this complete workflow on macOS.

Rust tests cover wire vectors, Noise metadata/roles/replay rejection, grants and
trust, BLE/NFC bounds, pulse and motor profiles, unavailable sensors, physical
faults, auto-relock, sequence eviction, cross-session/reboot replay, before/after
commit failures, migration, clock rollback, pairing, physical confirmation,
reset/trust replacement and signed firmware resume/boot outcomes. Native ABI tests
exercise small buffers and retained events. These are simulated platform tests.

Before deployment, additionally validate on the chosen board:

- Actual pulse cutoff, motor stop, limit sensing, privacy/door wiring, jam and timeout behavior.
- Atomic NVM persistence under power cuts at every commit/drive boundary, including write wear.
- Monotonic timer behavior, RTC validity and recovery, and boot-time sensor uncertainty.
- Firmware staging under flash-write interruption, independent boot verification, bad trial recovery and security-floor persistence.
- Real BLE/NFC MTUs, disconnection timing, key storage, image capacity and power/latency budgets.

The ARM/RISC-V build checks generate optimized runtime library artifacts with
`no_std + alloc`; they do not link a complete firmware image, execute RISC-V
instructions in an emulator, flash or run a board. Host simulator tests validate
protocol behavior, and do not replace these platform acceptance checks.
