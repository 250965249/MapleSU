// SPDX-License-Identifier: GPL-3.0-only
#ifndef MSU_PROTECTED_INSTALL_KERNEL_H
#define MSU_PROTECTED_INSTALL_KERNEL_H
#include <linux/types.h>
#include "manager_apk_identity.h"
struct inode;
struct msu_install_monitor {
    void *context;
    int (*watch_directory)(void *context, struct inode *inode, const char *child);
};
struct msu_internal_manager_policy {
    const char *manager_package;
    struct msu_manager_apk_pin pin;
    /* A trusted kernel sha256 adapter, NEVER a user function pointer. */
    int (*sha256)(const void *bytes, size_t length, u8 digest[32]);
};
/* Original eight-word report is retained for legacy tooling. The target schema
 * additionally reports exact owner sizes, nested inline fields and configs. */
extern const unsigned int msu_resolver_compiled_layout[8];
extern const unsigned int msu_resolver_target_layout[];

/* Work-only synchronous, internal verification. No hook or root/key output.
 * Must run in the actual app caller thread, outside an existing cred override.
 * The image/SDK loader must independently validate ALL struct layout offsets,
 * marker hook location/ABI and these imports against the actual target kernel. */
int msu_kernel_verify_manager_installation(
    const struct msu_internal_manager_policy *policy, u32 *generation);
/* The retained host supplies this monitor; all inode/name inputs below are
 * resolved internally from the protected PID1 root before reading each input. */
int msu_kernel_verify_manager_installation_watched(
    const struct msu_internal_manager_policy *policy, u32 *generation,
    const struct msu_install_monitor *monitor);
/* Internal installation producer only; PID1 root, every ancestor protected.
 * Caller owns the successful file reference and must fput it. */
struct file *msu_kernel_open_installation_path(const char *absolute, bool directory);
ssize_t msu_kernel_read_installation_record(struct file *directory, void *buffer, size_t bytes);
int msu_kernel_installation_boot_id(char boot[40]);
int msu_kernel_write_installation_guard(struct file *directory, const void *buffer, size_t bytes);

/* Slow internal package observer only. Bytes and the held file are returned
 * together after an exact bounded read and stable native stat; caller kvfree/
 * fput owns both. No caller path from the request wire reaches this function. */
struct kstat;
int msu_kernel_read_protected_document(const char *absolute, size_t limit,
    struct file **held, void **bytes, size_t *length, struct kstat *stat);
int msu_kernel_stat_protected_path(const char *absolute, bool directory,
    struct file **held, struct kstat *stat);
int msu_kernel_stat_observed_app_directory(u32 full_uid,const char *package,
    struct file **held,struct kstat *stat);
struct dir_context;
int msu_kernel_iterate_protected_directory(const char *absolute,struct dir_context *context);

#endif
