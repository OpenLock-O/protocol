#ifndef OPENLOCK_H
#define OPENLOCK_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define OPENLOCK_PROTOCOL_VERSION 3
#define OPENLOCK_SECRET_SIZE 32
#define OPENLOCK_REQUEST_SIZE 18
#define OPENLOCK_RESPONSE_SIZE 15

/* These native structs are NOT wire layouts. Use the encoder/decoder functions. */
typedef struct {
    uint32_t credential_id;
    uint64_t time_step;
    uint32_t code;
} openlock_request_t;
typedef struct {
    uint32_t credential_id;
    uint64_t time_step;
    uint32_t error_code; /* 0 success; positive protocol error code */
} openlock_response_t;

/* Return: 0 success, -1 invalid pointer, -2 output capacity too small,
 * positive protocol error (see docs/protocol.md).
 * Every secret pointer refers to exactly 32 readable bytes.
 * out_len must be writable and not overlap out. Pass NULL/0 for out/capacity
 * to query required length (-2); small buffers remain untouched.
 * No session handles, allocations, handshake or RNG are needed.
 * These helpers DO NOT authorize access. Firmware must use openlock-core or
 * implement the complete durable replay and throttling rules in the protocol.
 */
int32_t openlock_totp(const uint8_t *secret, uint64_t unix_seconds, uint32_t *out_code);
int32_t openlock_make_unlock(const uint8_t *secret, uint32_t credential_id,
                             uint64_t unix_seconds, uint8_t *out,
                             size_t capacity, size_t *out_len);
int32_t openlock_encode_unlock(uint32_t credential_id, uint64_t time_step,
                               uint32_t code, uint8_t *out,
                               size_t capacity, size_t *out_len);
int32_t openlock_decode_unlock(const uint8_t *input, size_t input_len,
                               openlock_request_t *out);
int32_t openlock_encode_response(uint32_t credential_id, uint64_t time_step,
                                 uint32_t error_code, uint8_t *out,
                                 size_t capacity, size_t *out_len);
/* Result is unauthenticated. A matching ID/step is only correlation. */
int32_t openlock_decode_response(const uint8_t *input, size_t input_len,
                                 openlock_response_t *out);

#ifdef __cplusplus
}
#endif
#endif
