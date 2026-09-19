#ifndef OPENLOCK_H
#define OPENLOCK_H
#include <stddef.h>
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif
#define OPENLOCK_PROTOCOL_VERSION 4
#define OPENLOCK_MAX_MESSAGE_SIZE 4096
#define OPENLOCK_ALL_CAPABILITIES UINT64_C(8388607)
typedef struct OpenLockSession openlock_session_t;
/* All keys are exactly 32 bytes. Return 0, -1 invalid pointer, -2 small output,
 * or a positive protocol error. Calls on one handle must be serialized.
 * Output buffers never overlap inputs or out_len. NULL/0 queries required size;
 * a small buffer is untouched and does not advance send/start/respond state. */
int32_t openlock_session_initiator(const uint8_t*,const uint8_t*,uint64_t,openlock_session_t**);
int32_t openlock_session_responder(const uint8_t*,uint64_t,openlock_session_t**);
int32_t openlock_session_start(openlock_session_t*,uint8_t*,size_t,size_t*);
/* command/response are canonical application CBOR, never encrypted packets. */
int32_t openlock_session_send(openlock_session_t*,const uint8_t*,size_t,uint32_t*,uint8_t*,size_t,size_t*);
int32_t openlock_session_respond(openlock_session_t*,uint32_t,const uint8_t*,size_t,uint8_t*,size_t,size_t*);
/* Receive ONCE, then drain output/event. Returns Busy without consuming input
 * while an earlier output/event is pending. No output buffer can lose an event. */
int32_t openlock_session_receive(openlock_session_t*,const uint8_t*,size_t);
int32_t openlock_session_take_output(openlock_session_t*,uint8_t*,size_t,size_t*);
/* Event CBOR: [kind,request_id,peer_or_null,body_or_null]. kinds: handshake=1,
 * request=2, response=3. Empty bytes means none. Small buffers retain the event. */
int32_t openlock_session_take_event(openlock_session_t*,uint8_t*,size_t,size_t*);
void openlock_session_free(openlock_session_t*);
/* sequence=0 for queries, positive monotonically increasing per credential for
 * mutations. action CBOR is [opcode, arguments...]. Claim/Pairing use no grant. */
int32_t openlock_encode_command(const uint8_t*,size_t,uint64_t,const uint8_t*,size_t,uint8_t*,size_t,size_t*);
/* kind: 0 X25519 Noise identity, 1 Ed25519 signing key. Output exactly 32 bytes. */
int32_t openlock_public_key(uint32_t,const uint8_t*,uint8_t*);
/* kind: 0 grant, 1 policy, 2 firmware manifest, 3 device record, 4 key update;
 * data is canonical unsigned CBOR. */
int32_t openlock_sign(uint32_t,const uint8_t*,const uint8_t*,size_t,uint8_t*,size_t,size_t*);
#ifdef __cplusplus
}
#endif
#endif
