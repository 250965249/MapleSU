// SPDX-License-Identifier: GPL-3.0-only
#ifndef MAPLESU_POLICY_DYNAMIC_LAYOUT_H
#define MAPLESU_POLICY_DYNAMIC_LAYOUT_H
#if defined(MAPLESU_POLICY_BOOT_HOST_TEST) || defined(MAPLESU_POLICY_VIEW_HOST_TEST)
#define PV_FIELD(object, type, member) ((object)->member)
#define PV_SIZE(type) sizeof(struct type)
#define PV_BITS(object, type, member) ((object)->member)
#define pv_current_uid current_uid
#define pv_current_sid current_sid
#define pv_selinux_cred selinux_cred
#define pv_task_cred __task_cred
#define pv_ptrace_parent ptrace_parent
#define pv_sidtab_search sidtab_search
#define pv_sym_name sym_name
#define PV_SYMTAB(object, member, symbol) ((object)->member)
#define pv_sock_family(sk) ((sk)->sk_family)
#define pv_netlink_cb(skb, member) (NETLINK_CB(skb).member)
#else
#include "policy_layout_slots.h"
extern struct maplesu_policy_layout_table maplesu_policy_layout;
#define PV_FIELD(object, type, member) \
    (*(__typeof__(((struct type *)0)->member) *)((char *)(object) + \
        maplesu_policy_layout.offsets[MP_FIELD_##type##_##member]))
#define PV_SIZE(type) (maplesu_policy_layout.sizes[MP_TYPE_##type])
static inline u32 pv_policy_bits(const void *object, unsigned int slot)
{
    const u32 offset = maplesu_policy_layout.bit_offsets[slot];
    const u32 width = maplesu_policy_layout.bit_widths[slot];
    const unsigned char *bytes = (const unsigned char *)object + offset / 8;
    u64 value = 0;
    unsigned int i;

    /* Read only the containing bytes, never a speculative word beyond the
     * target object. Widths (1..32) are proved before ready is published. */
    for (i = 0; i < ((offset & 7) + width + 7) / 8; ++i)
        value |= (u64)bytes[i] << (i * 8);
    return (value >> (offset & 7)) & ((1ULL << width) - 1);
}
#define PV_BITS(object, type, member) pv_policy_bits(object, MP_BIT_##type##_##member)
static inline kuid_t pv_current_uid(void)
{
    const struct cred *cred = rcu_dereference_protected(PV_FIELD(current, task_struct, cred), 1);
    return PV_FIELD(cred, cred, uid);
}
static inline struct maplesu_cred_security *pv_selinux_cred(const struct cred *cred)
{
    return (void *)((char *)PV_FIELD(cred, cred, security) +
                   PV_FIELD(&selinux_blob_sizes, lsm_blob_sizes, lbs_cred));
}
static inline u32 pv_current_sid(void)
{
    const struct cred *cred = rcu_dereference_protected(PV_FIELD(current, task_struct, cred), 1);
    return PV_FIELD(pv_selinux_cred(cred), maplesu_cred_security, sid);
}
#define pv_task_cred(task) rcu_dereference(PV_FIELD(task, task_struct, real_cred))
static inline struct task_struct *pv_ptrace_parent(struct task_struct *task)
{
    return READ_ONCE(PV_FIELD(task, task_struct, ptrace)) ?
        rcu_dereference(PV_FIELD(task, task_struct, parent)) : NULL;
}
static inline struct context *pv_sidtab_search(struct sidtab *sidtab, u32 sid)
{
    struct sidtab_entry *entry = sidtab_search_entry(sidtab, sid);
    return entry ? &PV_FIELD(entry, sidtab_entry, context) : NULL;
}
#define PV_SYMTAB(object, member, symbol) (PV_FIELD(object, policydb, symtab)[symbol])
#define pv_sock_family(sk) PV_FIELD(&PV_FIELD(sk, sock, __sk_common), sock_common, skc_family)
#define pv_netlink_cb(skb, member) PV_FIELD((struct netlink_skb_parms *)PV_FIELD(skb, sk_buff, cb), netlink_skb_parms, member)
#define pv_sym_name(policy, symbol, index) (PV_FIELD(policy, policydb, sym_val_to_name)[symbol][index])
#endif
#endif
