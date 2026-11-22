// SPDX-License-Identifier: GPL-3.0-only
#ifndef MAPLESU_POLICY_LAYOUT_SLOTS_H
#define MAPLESU_POLICY_LAYOUT_SLOTS_H
/* Shared wire schema, not kernel pointers. Resolve once before publication;
 * hot paths consume offsets only. Embedded sizes may grow; scalar ABIs do not. */
#define MAPLESU_POLICY_LAYOUT_FIELDS(F) \
    F(selinux_state, policy, 0) \
    F(selinux_state, policy_mutex, 1) \
    F(selinux_state, status_lock, 1) \
    F(selinux_policy, policydb, 1) \
    F(selinux_policy, sidtab, 0) \
    F(selinux_policy, latest_granting, 0) \
    F(policy_file, data, 0) \
    F(policy_file, len, 0) \
    F(policydb, symtab, 1) \
    F(policydb, sym_val_to_name, 0) \
    F(policydb, len, 0) \
    F(policydb, class_val_to_struct, 0) \
    F(policydb, type_val_to_struct, 0) \
    F(policydb, role_val_to_struct, 0) \
    F(policydb, type_attr_map_array, 0) \
    F(policydb, permissive_map, 1) \
    F(policydb, te_avtab, 1) \
    F(policydb, te_cond_avtab, 1) \
    F(policydb, process_class, 0) \
    F(policydb, process_trans_perms, 0) \
    F(policydb, role_allow, 0) \
    F(sidtab_entry, context, 1) \
    F(task_struct, mm, 0) \
    F(task_struct, signal, 0) \
    F(task_struct, thread_node, 1) \
    F(signal_struct, thread_head, 1) \
    F(task_struct, ptrace, 0) \
    F(task_struct, parent, 0) \
    F(task_struct, real_cred, 0) \
    F(task_struct, cred, 0) \
    F(cred, uid, 0) \
    F(cred, security, 0) \
    F(lsm_blob_sizes, lbs_cred, 0) \
    F(maplesu_cred_security, sid, 0) \
    F(file, private_data, 0) \
    F(file, f_op, 0) \
    F(vm_area_struct, vm_start, 0) \
    F(vm_area_struct, vm_end, 0) \
    F(vm_area_struct, vm_pgoff, 0) \
    F(vm_area_struct, vm_flags, 0) \
    F(vm_area_struct, vm_page_prot, 0) \
    F(vm_area_struct, vm_file, 0) \
    F(mm_struct, mmap_lock, 1) \
    F(sock, __sk_common, 1) \
    F(sock, sk_protocol, 0) \
    F(sock, sk_uid, 0) \
    F(sock_common, skc_family, 0) \
    F(sk_buff, data, 0) \
    F(sk_buff, len, 0) \
    F(sk_buff, cb, 1) \
    F(sk_buff, data_len, 0) \
    F(netlink_skb_parms, portid, 0) \
    F(netlink_skb_parms, dst_group, 0)
/* Optional in old kernels and present with two Android-backported protocols. */
#define MAPLESU_POLICY_OPTIONAL_LAYOUT_FIELDS(F) \
    F(mm_struct, mm_lock_seq, 1)
#define MAPLESU_POLICY_LAYOUT_TYPES(T) \
    T(selinux_policy) \
    T(policy_file) \
    T(policydb) \
    T(sidtab)
#define MAPLESU_POLICY_LAYOUT_BITS(B) \
    B(policydb, allow_unknown) \
    B(policydb, android_netlink_route) \
    B(policydb, android_netlink_getneigh)
enum maplesu_policy_bit_slot {
#define MP_BIT(type, member) MP_BIT_##type##_##member,
    MAPLESU_POLICY_LAYOUT_BITS(MP_BIT)
#undef MP_BIT
    MP_BIT_COUNT
};
enum maplesu_policy_field_slot {
#define MP_FIELD(type, member, embedded) MP_FIELD_##type##_##member,
    MAPLESU_POLICY_LAYOUT_FIELDS(MP_FIELD)
    MAPLESU_POLICY_OPTIONAL_LAYOUT_FIELDS(MP_FIELD)
#undef MP_FIELD
    MP_FIELD_COUNT
};
enum maplesu_policy_type_slot {
#define MP_TYPE(type) MP_TYPE_##type,
    MAPLESU_POLICY_LAYOUT_TYPES(MP_TYPE)
#undef MP_TYPE
    MP_TYPE_COUNT
};
#define MAPLESU_POLICY_LAYOUT_MAGIC 0x4d504c31U
#define MAPLESU_POLICY_LAYOUT_VERSION 3U
/* uint32_t/u32 supplied by the including userspace/kernel translation unit. */
struct maplesu_policy_layout_table {
    unsigned int magic, version, bytes, fields, types, ready;
    unsigned int offsets[MP_FIELD_COUNT], alignments[MP_FIELD_COUNT];
    unsigned int sizes[MP_TYPE_COUNT];
    unsigned int bit_offsets[MP_BIT_COUNT], bit_widths[MP_BIT_COUNT];
};
#endif
