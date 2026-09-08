#ifndef OPENLOCK_H
#define OPENLOCK_H

#include <stddef.h>
#include <stdint.h>

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

#endif
