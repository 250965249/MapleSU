// SPDX-License-Identifier: GPL-3.0-only
#include "policy_view_internal.h"
#include <linux/netlink.h>
#include <net/netlink.h>
#include <net/sock.h>
/* The loader verifies these compiled values against DWARF before replacing
 * them with target BTF values. Not const: constant-folding offsets is invalid. */
struct maplesu_policy_layout_table maplesu_policy_layout = {
    .magic = MAPLESU_POLICY_LAYOUT_MAGIC,
    .version = MAPLESU_POLICY_LAYOUT_VERSION,
    .bytes = sizeof(struct maplesu_policy_layout_table),
    .fields = MP_FIELD_COUNT,
    .types = MP_TYPE_COUNT,
    .ready = 0,
    .offsets = {
#define MP_OFFSET(type, member, embedded) [MP_FIELD_##type##_##member] = offsetof(struct type, member),
        MAPLESU_POLICY_LAYOUT_FIELDS(MP_OFFSET)
#ifdef CONFIG_PER_VMA_LOCK
        MAPLESU_POLICY_OPTIONAL_LAYOUT_FIELDS(MP_OFFSET)
#endif
#undef MP_OFFSET
    },
    .alignments = {
#define MP_ALIGN(type, member, embedded) [MP_FIELD_##type##_##member] = __alignof__(((struct type *)0)->member),
        MAPLESU_POLICY_LAYOUT_FIELDS(MP_ALIGN)
#ifdef CONFIG_PER_VMA_LOCK
        MAPLESU_POLICY_OPTIONAL_LAYOUT_FIELDS(MP_ALIGN)
#endif
#undef MP_ALIGN
    },
    .bit_widths = {
        [MP_BIT_policydb_allow_unknown] = 1,
#if defined(POLICYDB_CONFIG_ANDROID_NETLINK_ROUTE) && defined(POLICYDB_CONFIG_ANDROID_NETLINK_GETNEIGH)
        [MP_BIT_policydb_android_netlink_route] = 1,
        [MP_BIT_policydb_android_netlink_getneigh] = 1,
#endif
    },
    .sizes = {
#define MP_SIZE(type) [MP_TYPE_##type] = sizeof(struct type),
        MAPLESU_POLICY_LAYOUT_TYPES(MP_SIZE)
#undef MP_SIZE
    },
};
