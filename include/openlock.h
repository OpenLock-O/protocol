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

#endif
