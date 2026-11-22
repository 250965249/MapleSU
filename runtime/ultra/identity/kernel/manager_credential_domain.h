// SPDX-License-Identifier: GPL-3.0-only
#ifndef MAPLESU_MANAGER_CREDENTIAL_DOMAIN_H
#define MAPLESU_MANAGER_CREDENTIAL_DOMAIN_H

#include <linux/types.h>

#ifndef MSU_MANAGEMENT_PROFILE_DOMAIN_VERIFIED
#define MSU_MANAGEMENT_PROFILE_DOMAIN_VERIFIED 0
#endif

struct cred;

/* A build admission result, never proof of target qualification. The producer
 * must bind actual native headers/accessor, LSM blob layout/lifetime, resolver
 * type/import/KCFI and reference image before enabling the native branch. */
int msu_credential_domain_supported(void);

/* Mutates only the supplied uncommitted native prepare_creds result. length is
 * the domain byte count excluding its final NUL, at most 63. Zero inherits and
 * touches no LSM state. The input stays immutable for this synchronous call.
 * Failure is returned to the unique credential core, which aborts prepared.
 * No second prepare/commit, procattr write, task flag or global policy change. */
int msu_credential_domain_prepare(struct cred *prepared, const char *domain, u32 length);

/* Native declaration facts for the producer's independent target qualification.
 * Missing native fields use offset ~0U and size 0, never a guessed layout.
 * The accessor reads the actual selinux_blob_sizes.lbs_cred at runtime; these
 * words record its declaration, not an invented fixed blob offset value. */
enum msu_credential_domain_layout_word {
    MSU_CREDENTIAL_DOMAIN_SCHEMA, MSU_CREDENTIAL_DOMAIN_KERNEL_VERSION,
    MSU_CREDENTIAL_DOMAIN_BUILD_VERIFIED, MSU_CREDENTIAL_DOMAIN_SELINUX,
    MSU_CREDENTIAL_DOMAIN_CRED_SIZE, MSU_CREDENTIAL_DOMAIN_CRED_ALIGN,
    MSU_CREDENTIAL_DOMAIN_SECURITY_OFFSET, MSU_CREDENTIAL_DOMAIN_SECURITY_BYTES,
    MSU_CREDENTIAL_DOMAIN_BLOB_SIZE, MSU_CREDENTIAL_DOMAIN_BLOB_ALIGN,
    MSU_CREDENTIAL_DOMAIN_OSID_OFFSET, MSU_CREDENTIAL_DOMAIN_OSID_BYTES,
    MSU_CREDENTIAL_DOMAIN_SID_OFFSET, MSU_CREDENTIAL_DOMAIN_SID_BYTES,
    MSU_CREDENTIAL_DOMAIN_EXEC_OFFSET, MSU_CREDENTIAL_DOMAIN_EXEC_BYTES,
    MSU_CREDENTIAL_DOMAIN_CREATE_OFFSET, MSU_CREDENTIAL_DOMAIN_CREATE_BYTES,
    MSU_CREDENTIAL_DOMAIN_KEYCREATE_OFFSET, MSU_CREDENTIAL_DOMAIN_KEYCREATE_BYTES,
    MSU_CREDENTIAL_DOMAIN_SOCKCREATE_OFFSET, MSU_CREDENTIAL_DOMAIN_SOCKCREATE_BYTES,
    MSU_CREDENTIAL_DOMAIN_SIZES_SIZE, MSU_CREDENTIAL_DOMAIN_SIZES_ALIGN,
    MSU_CREDENTIAL_DOMAIN_LBS_CRED_OFFSET, MSU_CREDENTIAL_DOMAIN_LBS_CRED_BYTES,
    MSU_CREDENTIAL_DOMAIN_LAYOUT_WORDS,
};
extern const unsigned int msu_credential_domain_compiled_layout[MSU_CREDENTIAL_DOMAIN_LAYOUT_WORDS];

#endif
