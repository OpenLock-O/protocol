#ifndef OPENLOCK_SWIFT_FFI_H
#define OPENLOCK_SWIFT_FFI_H

#include <stddef.h>
#include <stdint.h>

typedef struct openlock_session openlock_session_t;
int32_t openlock_session_initiator(const uint8_t *, const uint8_t *, uint64_t, openlock_session_t **);
int32_t openlock_session_start(openlock_session_t *, uint8_t *, size_t, size_t *);
void openlock_session_free(openlock_session_t *);

#endif
