// SPDX-License-Identifier: GPL-3.0-only
#ifndef MAPLESU_SU_SESSION_RECEIPT_H
#define MAPLESU_SU_SESSION_RECEIPT_H
#include <linux/ioctl.h>
#include <linux/types.h>

/* Private su-session receipt. This descriptor has no grant/apply operation.
 * The anon-inode name locates a descriptor; only its kernel ioctl attests it. */
#define MSU_SU_SESSION_NAME "maplesu_su_session"
#define MSU_SU_SESSION_MAGIC 0x5355534dU
#define MSU_SU_SESSION_VERSION 1U
#define MSU_SU_SESSION_APPLIED 1U
#define MSU_SU_SESSION_EXECUTED 2U
#define MSU_SU_SESSION_CONSUMED 4U
struct msu_su_session_receipt {
    __u32 magic;
    __u16 version, bytes;
    __u32 state;
    __s32 error;
    __u32 subject_uid, target_uid, target_gid, phase;
    __u32 credential_effects, task_effects;
    __u64 generation, exec_id;
    __u32 reserved[2];
};
#define MSU_SU_SESSION_CONSUME _IOR(0xb7, 0x71, struct msu_su_session_receipt)
#endif
