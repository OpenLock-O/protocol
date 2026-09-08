# OpenLock protocol v1

OpenLock treats BLE GATT as a byte transport. A server exposes one custom
128-bit service with three characteristics:

| Characteristic | GATT operation | Purpose |
| --- | --- | --- |
| RX | Write With Response | client-to-lock frames |
| TX | Indicate | lock-to-client frames and acknowledgements |
| Metadata | Read | protocol version and framing limits only |

RX and TX values use `openlock-ble::FragmentHeader`. A message is identified by
`message_id`, carries a total length, and may arrive out of order. A second
message cannot evict an incomplete one. The application must expire a partial
message and start a new session instead.

## Session sequence

1. The client starts `Noise_IK_25519_ChaChaPoly_SHA256` with its static
   X25519 key and the provisioned lock public key.
2. The lock completes the handshake and checks that the authenticated static
   key equals the key in the signed grant.
3. The client sends a signed grant and an `Unlock` or `Status` request inside
   the Noise transport state. The lock verifies the COSE-Sign1 object before
   evaluating policy.
4. For counted grants, the lock commits the increment through
   `PersistentState::commit` before emitting the actuator event. A repeated
   consumption sequence returns `AlreadyConsumed` and never emits a second
   event.

COSE protected headers contain EdDSA. The OpenLock object kind (`grant` or
`policy`) is used as the COSE external authenticated data, preventing a valid
signature for one object type from being interpreted as another. The payload
is a fixed CBOR array so every implementation can produce identical bytes.
