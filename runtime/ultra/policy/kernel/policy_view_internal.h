// SPDX-License-Identifier: GPL-3.0-only
#ifndef MAPLESU_POLICY_VIEW_INTERNAL_H
#define MAPLESU_POLICY_VIEW_INTERNAL_H
#if defined(MAPLESU_POLICY_BOOT_HOST_TEST)
#include "policy_boot_fixture.h"
#elif defined(MAPLESU_POLICY_VIEW_HOST_TEST)
#include "policy_kernel_fixture.h"
#else
#ifdef MAPLESU_POLICY_PIC
#include <linux/jump_label.h>
#undef static_branch_likely
#undef static_branch_unlikely
#define static_branch_likely(x) __builtin_expect(!!static_key_enabled(&(x)->key), 1)
#define static_branch_unlikely(x) __builtin_expect(!!static_key_enabled(&(x)->key), 0)
#endif
#include <linux/cred.h>
#include <linux/fs.h>
#include <linux/gfp.h>
#include <linux/irqflags.h>
#include <linux/mm.h>
#include <linux/mutex.h>
#include <linux/overflow.h>
#include <linux/rcupdate.h>
#include <linux/rwsem.h>
#include <linux/sched.h>
#include <linux/sched/signal.h>
#include <linux/sched/task.h>
#include <linux/ptrace.h>
#include <linux/preempt.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/version.h>
#include <linux/vmalloc.h>
#include "security.h"
#include "objsec.h"
#include "avc.h"
#include "ss/context.h"
#include "ss/conditional.h"
#include "ss/mls.h"
#include "ss/policydb.h"
#include "ss/services.h"
#include "ss/sidtab.h"
#include "ss/symtab.h"
#endif

#include "policy_view.h"
#ifndef MAPLESU_POLICY_VIEW_HOST_TEST
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 6, 0)
#define maplesu_avc_has_perm(...) avc_has_perm(__VA_ARGS__)
#define maplesu_bounded_transition(...) security_bounded_transition(__VA_ARGS__)
#else
#define maplesu_avc_has_perm(...) avc_has_perm(&selinux_state, __VA_ARGS__)
#define maplesu_bounded_transition(...) security_bounded_transition(&selinux_state, __VA_ARGS__)
#endif
#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 18, 0)
#define maplesu_cred_security task_security_struct
#else
#define maplesu_cred_security cred_security_struct
#endif
#include "policy_dynamic_layout.h"
struct hidden_policy_epoch {
    struct hidden_policy_epoch *next;
    u32 sequence;
};
struct maplesu_policy_view {
    struct selinux_policy *policy;
    struct page *status;
    const struct policydb *original_live_db;
    u32 original_live_generation;
    u32 original_type_limit;
    struct hidden_policy_epoch *hidden_epochs;
    unsigned hidden_epoch_count;
    struct task_struct *module_writer;
};
extern struct maplesu_policy_view maplesu_view;
int maplesu_context_to_sid(const char *text, u32 length, u32 *sid,
                          u32 *live_sid, int *live_rc);
int maplesu_context_to_sid_live(const char *text, u32 length, u32 *sid);
int maplesu_sid_to_context(u32 sid, char **text, u32 *length);
void maplesu_compute_policy_av(struct policydb *, struct context *,
    struct context *, u16, struct av_decision *, struct extended_perms *);
extern void (*maplesu_policy_dump_masked_av)(struct policydb *, struct context *,
    struct context *, u16, u32, const char *);
#endif
#if defined(MAPLESU_POLICY_VIEW_HOST_TEST)
#include "policy_dynamic_layout.h"
#endif

void maplesu_policy_query_begin(void);
void maplesu_policy_query_end(void);
int maplesu_policy_refresh_snapshot(void);
int maplesu_policy_hidden_sequence(u32 sequence);
extern bool maplesu_policy_hot_bound, maplesu_policy_hot_hidden;

int maplesu_type_is_original(struct policydb *live, u32 generation, u32 type);
int maplesu_context_parse(struct policydb *pol, struct policydb *live_pol,
                         struct sidtab *sidtab, struct sidtab *live_sidtab,
                         char *context, const char *source, u32 source_len,
                         struct context *ctx, struct context *live_ctx,
                         u32 generation, u32 def_sid, int *live_rc);
int maplesu_context_parse_live(struct policydb *pol, struct policydb *live_pol,
                               struct sidtab *sidtab, char *text,
                               struct context *ctx, u32 generation);
#endif
