#ifndef OPENLOCK_H
#define OPENLOCK_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* v3 release contains both wire protocols. The generic macro is the TOTP
 * proposal alias; secure sessions retain wire version 2. */
#define OPENLOCK_SECURE_PROTOCOL_VERSION 2
#define OPENLOCK_TOTP_PROTOCOL_VERSION 3
#define OPENLOCK_PROTOCOL_VERSION OPENLOCK_TOTP_PROTOCOL_VERSION
/* Secure v2 API: available with the secure Cargo feature (default). */
typedef struct {
    uint8_t bytes[16];
} openlock_credential_id_t;

/* Returns 0 on success, -1 for a null pointer. */
int32_t openlock_credential_id(const uint8_t *data, size_t len,
                               openlock_credential_id_t *out);

typedef struct openlock_session openlock_session_t;

/* All key pointers below refer to exactly 32 readable bytes. */
int32_t openlock_session_initiator(const uint8_t *private_key,
                                   const uint8_t *lock_public,
                                   uint64_t capabilities,
                                   openlock_session_t **out);
int32_t openlock_session_responder(const uint8_t *private_key,
                                   uint64_t capabilities,
                                   openlock_session_t **out);
int32_t openlock_session_start(openlock_session_t *session, uint8_t *out,
                               size_t capacity, size_t *out_len);
/* event: 0 none, 1 handshake complete, 2 request received, 3 response received. */
int32_t openlock_session_receive(openlock_session_t *session,
                                 const uint8_t *input, size_t input_len,
                                 uint8_t *out, size_t capacity, size_t *out_len,
                                 uint32_t *event);
/* requested_use = -1 means no use counter was supplied. */
int32_t openlock_session_send_unlock(openlock_session_t *session,
                                     const uint8_t *credential,
                                     size_t credential_len,
                                     int64_t requested_use,
                                     uint32_t *request_id, uint8_t *out,
                                     size_t capacity, size_t *out_len);
int32_t openlock_session_send_status(openlock_session_t *session,
                                     const uint8_t *credential,
                                     size_t credential_len,
                                     int64_t requested_use,
                                     uint32_t *request_id, uint8_t *out,
                                     size_t capacity, size_t *out_len);
int32_t openlock_session_send_policy(openlock_session_t *session,
                                     const uint8_t *policy, size_t policy_len,
                                     uint32_t *request_id, uint8_t *out,
                                     size_t capacity, size_t *out_len);
void openlock_session_free(openlock_session_t *session);

/* TOTP API: available with the totp Cargo feature (default). */
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
 * positive protocol error (see docs/protocol-totp.md).
 * Every secret pointer refers to exactly 32 readable bytes.
 * out_len must be writable and not overlap out. Pass NULL/0 for out/capacity
 * to query required length (-2); small buffers remain untouched.
 * No session handles, allocations, handshake or RNG are needed.
 * These helpers DO NOT authorize access. Firmware must use openlock-totp::core or
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
