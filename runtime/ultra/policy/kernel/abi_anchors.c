// SPDX-License-Identifier: GPL-3.0-only
/* Compile-only DWARF anchors. This object is never linked into the payload. */
#include "policy_view_internal.h"
#include <net/netlink.h>
#include <net/sock.h>
#define ANCHOR(type) __attribute__((used)) const struct type *maplesu_layout_##type
ANCHOR(selinux_state);
ANCHOR(selinux_policy);
ANCHOR(policy_file);
ANCHOR(policydb);
ANCHOR(sidtab);
ANCHOR(sidtab_entry);
ANCHOR(hashtab);
ANCHOR(context);
ANCHOR(mls_range);
ANCHOR(mls_level);
ANCHOR(ebitmap);
ANCHOR(ebitmap_node);
ANCHOR(symtab);
ANCHOR(role_datum);
ANCHOR(user_datum);
ANCHOR(type_datum);
ANCHOR(class_datum);
ANCHOR(constraint_node);
ANCHOR(constraint_expr);
ANCHOR(role_allow);
ANCHOR(avtab);
ANCHOR(avtab_key);
ANCHOR(avtab_node);
ANCHOR(avtab_datum);
ANCHOR(avtab_extended_perms);
ANCHOR(extended_perms);
ANCHOR(extended_perms_data);
ANCHOR(av_decision);
ANCHOR(mutex);
ANCHOR(ratelimit_state);
ANCHOR(lsm_blob_sizes);
ANCHOR(selinux_kernel_status);
ANCHOR(page);
ANCHOR(task_struct);
ANCHOR(signal_struct);
ANCHOR(thread_info);
ANCHOR(cred);
ANCHOR(file);
ANCHOR(vm_area_struct);
ANCHOR(mm_struct);
ANCHOR(callback_head);
ANCHOR(sock);
ANCHOR(sock_common);
ANCHOR(sk_buff);
ANCHOR(netlink_skb_parms);
ANCHOR(nlmsghdr);
ANCHOR(maplesu_cred_security);
