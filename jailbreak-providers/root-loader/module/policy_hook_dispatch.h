/* SPDX-License-Identifier: GPL-3.0-only */
#ifndef MAPLESU_POLICY_HOOK_DISPATCH_H
#define MAPLESU_POLICY_HOOK_DISPATCH_H
#include "../policy_hook_abi.h"
#ifdef MAPLESU_POLICY_HOOK_HOST_TEST
#define MSU_PH_NOCFI
#else
#define MSU_PH_NOCFI __attribute__((no_sanitize("kcfi", "cfi")))
#endif

/* The assembly helper's single return label is the only re-entry exemption.
 * It preserves x18, callee-saved registers, SP alignment, and native arguments. */
unsigned long long msu_policy_call_original(unsigned long long target,
                                          const unsigned long long args[6]);
MSU_PH_NOCFI unsigned long long msu_policy_dispatch(
    const struct msu_policy_hook_dispatch *hook, const unsigned long long args[6]);
void msu_policy_backend_note_error(int error);
void msu_policy_backend_reconcile(void);
#endif
