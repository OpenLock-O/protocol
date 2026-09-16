# OpenLock v3 protocol family

OpenLock v3 is a superset of v2: the complete secure v2 scheme remains available,
and plaintext TOTP is an additional optional scheme. The Cargo release version
is 0.3. Scheme selection is a trusted deployment choice, not unauthenticated
capability negotiation or fallback after a failed handshake.

## Scheme contracts and compatibility

| Scheme | Wire format | Contract | Runtime |
| --- | --- | --- | --- |
| Secure (v2 compatible) | Version 2, profile 1, canonical CBOR + Noise IK | [Complete v2 wire contract](protocol-v2.md) | Existing `openlock-protocol::Session` and companion crates |
| Plaintext TOTP (optional) | Version 3, fixed binary, 18-byte request / 15-byte response | [TOTP wire contract](protocol-totp.md) | Independent `openlock-totp` crate |

The v3 family does **not** rewrite secure packet versions from 2 to 3. Keeping
`openlock_types::PROTOCOL_VERSION = 2`, the Noise prologue
`OpenLock/v2/profile1`, the CBOR layouts, signature inputs and error values is
necessary for v2 interoperability. `openlock_totp::types::PROTOCOL_VERSION = 3`
identifies only the new TOTP wire scheme. These are separate namespaces; equal
numeric profile IDs do not make their formats or credentials interchangeable.

All v2 capabilities remain: authenticated/encrypted sessions, holder-bound
signed grants, Unlock, Status, ApplyPolicy, epochs and revocation, optional
validity/use limits, device trust and monotonic key rotation, signed NFC
bootstrap, and BLE/NFC fragmentation. The original root Rust APIs and C session
ABI remain available, as do the Swift/Kotlin session wrappers. A secure-only
installation does not need new keys or any TOTP enrollment.

## Explicit selection and isolation

A host MUST associate endpoints, provisioned credentials and authorization
policy with their intended scheme. An endpoint may support both only if trusted
local configuration explicitly enables both; the host then routes to the
appropriate parser and authorization store. Separate characteristics/APDU
routes are a straightforward way to keep this selection explicit.

A failed secure handshake, signature check, authorization check or unsupported
packet MUST NOT trigger a retry as TOTP. Neither a public discovery record nor
an unauthenticated response may enable a scheme or relax the expected one.
Applications MUST NOT infer that a TOTP code authenticates a secure session or
that a secure grant can be interpreted as a TOTP secret.

Secure and TOTP parsers reject each other's messages. The implementation has
no automatic cross-scheme dispatcher or fallback. The C ABI has distinct entry
points: `openlock_session_*` for secure sessions and `openlock_make_unlock` /
`openlock_decode_response` for TOTP. Mobile callers explicitly choose
`OpenLockSession` or the `OpenLock` TOTP helpers.

A v2 signed policy update affects secure credentials only. TOTP credentials are
installed/revoked through trusted local management. A user with credentials
in both schemes must be revoked in both stores by the management layer. Usage
counters and TOTP consumption records are independent and cannot be reset by
switching transport or scheme. Adding an authorized TOTP credential provides a
plaintext access path with its own security properties; it does not inherit
the confidentiality or peer authentication of the secure path.

## TOTP one-time use

The optional scheme uses RFC 6238 HMAC-SHA-256, a 32-byte unique key per
`(lock, credential)`, a 30-second period, eight digits and ±1-step tolerance.
The lock MUST persist consumption before actuation and reject consumed or
older steps, including across reconnects, transport changes and reboot. The
lock-wide rate limit also survives restart. Clock and storage failures reject
access. Full rules and vectors are in [the TOTP contract](protocol-totp.md).

## Discovery and transports

Secure NFC retains its signed CBOR MIME record
`application/vnd.openlock.bootstrap+cbor`, issuer trust and device keys. TOTP
uses the distinct public hint `application/vnd.openlock.bootstrap`, containing
only its version/profile and lock ID. The unsigned TOTP hint cannot replace a
secure trust record. Both records remain supported in their separate modules.

Secure BLE/ISO-DEP retains v2 framing and limits. TOTP sends one complete small
message per characteristic write/notification or APDU data field. Hosts select
the corresponding codec; a single TOTP frame is never fed through the v2
fragment parser as a recovery strategy.
