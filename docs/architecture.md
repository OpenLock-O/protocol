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
fragments. ISO-DEP uses a sequence byte and a two-byte total length. Both codecs
reject conflicting duplicates, truncation, overflow and sequence errors.

Device X25519 keys are used for Noise identity and are not used to sign key
updates. Device records and rotation records use an independent Ed25519 key or
the configured issuer key. Key versions are monotonic and old versions cannot
replace a newer record.
