// SPDX-License-Identifier: GPL-3.0-only
/* Retain native multicast construction, socket ownership, wakeups and filters.
 * SDK before-dispatch selects only policyload deliveries to app-owned sockets;
 * never pass an unregistered payload callback to a CFI-protected kernel. */
#include "policy_view_internal.h"
#ifndef MAPLESU_POLICY_BOOT_HOST_TEST
#include <linux/selinux_netlink.h>
#include <net/netlink.h>
#include <net/sock.h>
#endif

static int policyload_message(const struct sock *sk, const struct sk_buff *skb)
{
    const struct nlmsghdr *header;

    if (pv_sock_family(sk) != AF_NETLINK || PV_FIELD(sk, sock, sk_protocol) != NETLINK_SELINUX ||
        pv_netlink_cb(skb, portid) || pv_netlink_cb(skb, dst_group) != SELNLGRP_AVC ||
        PV_FIELD(skb, sk_buff, data_len) > PV_FIELD(skb, sk_buff, len) ||
        (PV_FIELD(skb, sk_buff, len) - PV_FIELD(skb, sk_buff, data_len)) < NLMSG_LENGTH(sizeof(struct selnl_msg_policyload)))
        return 0;
    header = ((struct nlmsghdr *)PV_FIELD(skb, sk_buff, data));
    if (!(header->nlmsg_type == SELNL_MSG_POLICYLOAD &&
           header->nlmsg_len >= NLMSG_LENGTH(sizeof(struct selnl_msg_policyload)) &&
           header->nlmsg_len <= (PV_FIELD(skb, sk_buff, len) - PV_FIELD(skb, sk_buff, data_len))))
        return 0;
    return maplesu_policy_hidden_sequence(((const struct selnl_msg_policyload *)
        ((const char *)header + NLMSG_HDRLEN))->seqno);
}

int maplesu_policy_filter_selected(const struct sock *sk,
                                       const struct sk_buff *skb)
{
    return READ_ONCE(PV_FIELD(sk, sock, sk_uid).val) >= 10000 && policyload_message(sk, skb);
}

int maplesu_policy_view_filter(struct sock *sk, struct sk_buff *skb, unsigned int cap)
{
    (void)sk;
    (void)skb;
    (void)cap;
    return -EPERM;
}

struct sk_buff *maplesu_policy_view_receive(struct sock *sk, struct sk_buff *skb,
                                          unsigned int flags)
{
    if (!policyload_message(sk, skb))
        return skb;
    /* The receiver's UID selects this path, including root-created FDs passed
     * with SCM_RIGHTS. Native kill_datagram also handles MSG_PEEK queue refs. */
    skb_kill_datagram(sk, skb, flags);
    return NULL;
}
