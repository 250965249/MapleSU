// SPDX-License-Identifier: GPL-3.0-only
#ifndef MSU_INSTALL_RECORDS_H
#define MSU_INSTALL_RECORDS_H
#ifdef __KERNEL__
#include <linux/types.h>
typedef u8 msu_rec_u8;
typedef u16 msu_rec_u16;
typedef u32 msu_rec_u32;
typedef u64 msu_rec_u64;
#else
#include <stddef.h>
#include <stdint.h>
typedef uint8_t msu_rec_u8;
typedef uint16_t msu_rec_u16;
typedef uint32_t msu_rec_u32;
typedef uint64_t msu_rec_u64;
#endif
#define MSU_RECORD_LIMIT (8U * 1024U * 1024U)
#define MSU_RECORD_PATH 512U
#define MSU_RECORD_REFS 65535U
#define MSU_RECORD_SCRATCH_WORDS 1024U
struct msu_record_bytes { const msu_rec_u8 *data; size_t length; };
struct msu_record_ref { msu_rec_u32 offset; msu_rec_u16 length; };
struct msu_record_workspace {
    struct msu_record_ref refs[MSU_RECORD_REFS];
    unsigned long parser_scratch[MSU_RECORD_SCRATCH_WORDS];
};
struct msu_install_record {
    msu_rec_u32 full_uid;
    msu_rec_u32 user_id;
    msu_rec_u32 app_id;
    char apk_path[MSU_RECORD_PATH];
};
/* Documents are protected snapshots supplied by the internal resolver, NEVER
 * app-supplied. A zero-length per-user document means proven absent, not a
 * read failure; Android's default installed=true then applies. This function
 * parses disk state only; PMS asynchronous writes are not a revocation fence. */
int msu_read_install_records(struct msu_record_bytes list,
    struct msu_record_bytes global, struct msu_record_bytes per_user,
    msu_rec_u32 real_full_uid, const char *manager_package,
    struct msu_record_workspace *workspace, struct msu_install_record *out);
/* Same protected disk parser, permitting an ordinary application's sharedUID.
 * The caller must enumerate the complete same-appId member set separately. */
int msu_read_observed_install_records(struct msu_record_bytes list,
    struct msu_record_bytes global, struct msu_record_bytes per_user,
    msu_rec_u32 real_full_uid, const char *package,
    struct msu_record_workspace *workspace, struct msu_install_record *out);
#define MSU_OBSERVED_SIGNERS 32U
struct msu_observed_record_identity {
    msu_rec_u64 first_install_ms;
    msu_rec_u32 signer_count;
    msu_rec_u8 signers[MSU_OBSERVED_SIGNERS][32];
};
/* Caller allocates the scratch once on its slow path, never a kernel stack. */
struct msu_observed_identity_workspace {
    struct msu_record_workspace parser;
    struct msu_record_ref certificates[MSU_RECORD_REFS];
    msu_rec_u8 certificate_kinds[MSU_RECORD_REFS];
    msu_rec_u8 certificate[8192];
};
int msu_read_observed_record_identity(struct msu_record_bytes global,
    struct msu_record_bytes per_user,msu_rec_u32 app_id,const char *package,
    struct msu_observed_identity_workspace *workspace,
    int (*sha256)(const void *,size_t,msu_rec_u8[32]),
    struct msu_observed_record_identity *identity);
struct msu_manager_apk_pin;
/* Read only PMS-verified signing history from the SAME protected global
 * installation snapshot. No APK-supplied lineage is a trust source. */
int msu_read_install_signing(struct msu_record_bytes global, const char *package,
    struct msu_record_workspace *workspace, const struct msu_manager_apk_pin *pin,
    void *context, int (*sha256)(void *, const void *, size_t, msu_rec_u8[32]),
    struct msu_manager_apk_pin *verified_current);

#endif
