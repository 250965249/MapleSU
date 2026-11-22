/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _LINUX_MAPLESU_KPROBE_TEXT_OWNER_H
#define _LINUX_MAPLESU_KPROBE_TEXT_OWNER_H

#include <linux/types.h>
#include <linux/maplesu/legacy_hook_private.h>

#define KPROBE_TEXT_OWNER_RETAINED 1U
#define KPROBE_TEXT_OWNER_WRITTEN 2U
#define KPROBE_TEXT_OWNER_RELEASED 4U
#define KPROBE_TEXT_OWNER_DISABLED 8U
#define KPROBE_TEXT_OWNER_ATTEMPTED 16U

/* Trusted kernel text publishers only. These operations acquire kprobe_mutex,
 * CPU hotplug and text_mutex in that order; callers hold none of them. The
 * owner is an actual publication object, never a userspace supplied token.
 * A failed claim with RETAINED must be reconciled by disable and release.
 * Disable closes the native logical branch and waits for native
 * pre/simulate/post readers, retaining the actual target module lease. The
 * caller then drains its complete gate/original/callback lifetime before
 * release drops that lease and makes the entry available for a new claim. */
int kprobe_text_owner_claim(void *address, u32 expected, u32 branch,
                           const void *owner, u32 *effects);
int kprobe_text_owner_disable(void *address, const void *owner, u32 *effects);
int kprobe_text_owner_release(void *address, const void *owner, u32 *effects);
int kprobe_text_owner_read(void *address, u32 *logical, u32 *physical);

/* Native producer only: caller holds kprobe_mutex or has preemption disabled,
 * exactly as for get_kprobe(). A successful lookup copies immutable words. */
bool kprobe_text_owner_lookup(void *address, u32 *original, u32 *branch);
int arch_kprobe_text_owner_patch(void *address, u32 instruction);

/* Called by the resident sched_process_exit consumer before removing its exit
 * hook. It drops native provider leases for EXEC stacks abandoned by this task;
 * no provider callback or sleeping lock is used from the tracepoint. */
struct task_struct;
void maplesu_legacy_hook_provider_task_exit(struct task_struct *task);

/* Private Legacy authorization acceleration. prepare reads the unpublished,
 * immutable sorted UID list, including its terminator. forget is idempotent
 * and precedes native table release; exposed readers must already be drained
 * by the writer's existing RCU transaction. Index memory itself uses kfree_rcu.
 * lookup owns its native read section and preserves plain-list compatibility. */
int maplesu_legacy_uid_index_prepare(unsigned long table, u32 count);
int maplesu_legacy_uid_index_forget(unsigned long table);
u64 maplesu_legacy_uid_lookup(unsigned long control);

#endif
