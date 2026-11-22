/* SPDX-License-Identifier: GPL-3.0-only */
#ifndef MAPLESU_POLICY_HOOK_ABI_H
#define MAPLESU_POLICY_HOOK_ABI_H

/* Fixed-width, pointer-width-independent control ABI. All operations require
 * live uid/euid 0. Data is copied; no userspace address is retained by a Hook. */
#define MSU_POLICY_HOOK_VERSION 2u
#define MSU_POLICY_HOOK_IOCTL 0xc0f84d51u
#define MSU_POLICY_HOOK_PATH "/proc/maplesu_policy_hook"
/* Same resident Root channel as jailbreak status hiding, with a separate op.
 * Native PR_SET_DUMPABLE rejects op=3; only a real control reply proves support. */
#define MSU_POLICY_HOOK_OP 3u
#define MSU_POLICY_HOOK_TAG_LO 0x504f4c59u
#define MSU_POLICY_HOOK_TAG_HI 0x4d535532u
#define MSU_POLICY_QUERY_HOOK_COUNT 9u
#define MSU_POLICY_HOOK_COUNT 12u
#define MSU_POLICY_HOOK_CHUNK 32768u
#define MSU_POLICY_HOOK_MAX_IMAGE (4u * 1024u * 1024u)

enum msu_policy_hook_command {
    MSU_PH_QUERY, MSU_PH_LOOKUP, MSU_PH_ALLOCATE, MSU_PH_RELEASE,
    MSU_PH_READ, MSU_PH_WRITE, MSU_PH_CALL, MSU_PH_INSTALL, MSU_PH_ACTIVATE,
    MSU_PH_CANCEL, MSU_PH_BIND, MSU_PH_POLICY_WRITE
};

struct msu_policy_hook_request {
    unsigned int version, command;
    unsigned long long address, bytes, data, args[3], result;
    int status;
    unsigned int installed, enabled, prepared, pinned, reserved;
    char name[128];
    unsigned long long predicate, handler, activation;
    unsigned int operation, flags;
};

struct msu_policy_hook_dispatch {
    unsigned long long target, predicate, handler, activation;
    unsigned int operation, installed;
};

#endif
