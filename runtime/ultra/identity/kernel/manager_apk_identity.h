// SPDX-License-Identifier: GPL-3.0-only
#ifndef MAPLESU_MANAGER_APK_IDENTITY_H
#define MAPLESU_MANAGER_APK_IDENTITY_H

#ifdef __KERNEL__
#include <linux/types.h>
typedef u8 msu_apk_u8;
typedef u32 msu_apk_u32;
typedef u64 msu_apk_u64;
#else
#include <stddef.h>
#include <stdint.h>
typedef uint8_t msu_apk_u8;
typedef uint32_t msu_apk_u32;
typedef uint64_t msu_apk_u64;
#endif

/* Internal reader for ONE retained, protected installation file. The resolver
 * owns that file and rechecks its installation snapshot before releasing a key.
 * This parser checks the installed signer pin, not APK cryptographic signatures;
 * Android's verified installation and the protected source are prerequisites.
 * Neither a caller path nor a public certificate establishes that identity. */
struct msu_apk_source {
    void *context;
    msu_apk_u64 length;
    /* Return 0 only after reading all count bytes / writing all 32 digest bytes. */
    int (*read_at)(void *context, msu_apk_u64 offset, void *bytes, size_t count);
    int (*sha256)(void *context, const void *bytes, size_t count, msu_apk_u8 digest[32]);
};

struct msu_manager_apk_pin {
    msu_apk_u32 certificate_size;
    msu_apk_u8 certificate_sha256[32];
    msu_apk_u32 minimum_generation;
};

/* No logging, allocation, path lookup, credential change, or authorization. */
int msu_manager_apk_identity(const struct msu_apk_source *source,
                             const struct msu_manager_apk_pin *pin,
                             msu_apk_u32 *generation);

/* The pin below is the current signer obtained from the SAME protected PMS
 * snapshot after verified history reached the immutable trust pin. Never use
 * an APK-supplied certificate/lineage or a caller-selected signer here. */
int msu_manager_installed_apk_identity(const struct msu_apk_source *source,
    const struct msu_manager_apk_pin *verified_current, msu_apk_u32 *generation);

#endif
