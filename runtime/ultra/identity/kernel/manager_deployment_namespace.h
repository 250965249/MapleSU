// SPDX-License-Identifier: GPL-3.0-only
#ifndef MAPLESU_MANAGER_DEPLOYMENT_NAMESPACE_H
#define MAPLESU_MANAGER_DEPLOYMENT_NAMESPACE_H
#include "manager_claim_loader.h"

#define MSU_DEPLOYMENT_NAMESPACE_MAGIC 0x4e44534dU
#define MSU_DEPLOYMENT_NAMESPACE_SCHEMA 1U
#define MSU_DEPLOYMENT_NAMESPACE_BYTES 16U

/* A public path namespace, never an installation pin, grant or Ready fact. */
struct msu_deployment_namespace_record {
    msu_loader_u32 magic;
    msu_loader_u16 schema, bytes;
    msu_loader_u8 name[MSU_DEPLOYMENT_NAMESPACE_BYTES];
};
_Static_assert(sizeof(struct msu_deployment_namespace_record) == 24, "deployment namespace record");

static inline int msu_deployment_namespace_valid(const struct msu_deployment_namespace_record *record)
{
    unsigned int i;
    if (!record || record->magic != MSU_DEPLOYMENT_NAMESPACE_MAGIC ||
        record->schema != MSU_DEPLOYMENT_NAMESPACE_SCHEMA || record->bytes != sizeof(*record)) return 0;
    for (i = 0; i < sizeof(record->name); ++i) {
        unsigned char c = record->name[i];
        if (!((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
              (c >= '0' && c <= '9'))) return 0;
    }
    return 1;
}
#endif
