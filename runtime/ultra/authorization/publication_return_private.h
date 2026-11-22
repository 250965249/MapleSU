#ifndef MAPLESU_PUBLICATION_RETURN_PRIVATE_H
#define MAPLESU_PUBLICATION_RETURN_PRIVATE_H

#include "request_protocol.h"

/* Same-generation private tail of the read-only publication page. The public
 * schema-1 control remains exactly 64 bytes. No function address is inferred
 * from a code distance or discovered through kernel symbol names. */
#define MAPLESU_PRIVATE_RETURN_CONTROL_OFFSET 64u
#define MAPLESU_PRIVATE_RETURN_CONTROL_SCHEMA 3u

typedef struct __attribute__((aligned(8))) maplesu_publication_return_private {
    uint64_t publication_id;
    uint32_t schema;
    uint32_t length;
    uint64_t acquire_function;
    uint64_t release_function;
    uint64_t caller_x28_function;
    uint64_t caller_lr_function;
    uint64_t status_function;
    uint64_t actor_attach_function;
    uint64_t payload_function;
} maplesu_publication_return_private;

#ifdef __cplusplus
static_assert(sizeof(maplesu_publication_return_private) == 72, "private return control size");
#else
_Static_assert(sizeof(maplesu_publication_return_private) == 72, "private return control size");
#endif

#endif
