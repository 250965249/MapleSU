/* Drive the real snapshot/notification implementation. Only native kernel
 * allocation, locking and policy serialization are supplied by the fixture. */
#define main snapshot_fixture_main
#include "policy_view_boot_test.c"
#undef main

static void native_load(u32 generation)
{
    struct selinux_kernel_status *status = (void *)original_status.data;
    live.latest_granting = generation;
    status->sequence += 2;
    status->policyload = generation;
}

static struct sk_buff message(u32 sequence, void *buffer)
{
    struct nlmsghdr *header = buffer;
    *header = (struct nlmsghdr){.nlmsg_len=NLMSG_LENGTH(sizeof(struct selnl_msg_policyload)),
        .nlmsg_type=SELNL_MSG_POLICYLOAD};
    ((struct selnl_msg_policyload *)((char *)buffer+NLMSG_HDRLEN))->seqno=sequence;
    return (struct sk_buff){.data=buffer,.len=header->nlmsg_len,.cb={.dst_group=SELNLGRP_AVC}};
}

int main(void)
{
    unsigned char packet[NLMSG_LENGTH(sizeof(struct selnl_msg_policyload))];
    struct sock receiver={{10123},AF_NETLINK,NETLINK_SELINUX};
    struct task_struct another = {0};
    reset();
    assert(!maplesu_policy_view_prepare());
    maplesu_policy_hot_bound=maplesu_policy_hot_hidden=true;
    struct page *page=maplesu_view.status;
    struct selinux_policy *baseline=maplesu_view.policy;
    struct selinux_kernel_status captured=*(struct selinux_kernel_status *)page->data;
    assert(!maplesu_policy_view_module_write(0));
    assert(maplesu_policy_view_module_write(0)==-EBUSY);
    assert(!maplesu_policy_view_reload(0,0));
    assert(!maplesu_policy_view_policyload(6));
    struct sk_buff hidden=message(6,packet);
    assert(maplesu_policy_view_handles(MAPLESU_POLICY_NOTIFY_FILTER,&receiver,&hidden));
    native_load(6);
    assert(!maplesu_policy_view_reload(1,24));
    assert(!maplesu_policy_view_module_write(1));
    assert(maplesu_view.policy==baseline && maplesu_view.status==page &&
        !memcmp(page->data,&captured,sizeof(captured)));
    /* The origin classification survives the originating process and also
     * covers root-created sockets handed to an application later. */
    fixture_uid=10123; receiver.sk_uid.val=0;
    assert(!maplesu_policy_view_receive(&receiver,&hidden,2) && killed_datagrams==1);
    puts("PASS module write retains the view; handed-off socket drops the recorded epoch");
    fixture_uid=0; receiver.sk_uid.val=10123;
    assert(!maplesu_policy_view_reload(0,0));
    assert(!maplesu_policy_view_policyload(7));
    struct sk_buff platform=message(7,packet);
    assert(!maplesu_policy_view_handles(MAPLESU_POLICY_NOTIFY_FILTER,&receiver,&platform));
    native_load(7);
    assert(!maplesu_policy_view_reload(1,24));
    assert(maplesu_view.policy!=baseline && maplesu_view.status==page &&
        maplesu_view.policy->latest_granting==7 && db_destroyed==1 && sid_destroyed==1);
    assert(!memcmp(page->data,&captured,sizeof(captured)));
    assert(((struct selinux_kernel_status *)original_status.data)->policyload==7);
    assert(maplesu_policy_view_receive(&receiver,&platform,0)==&platform && killed_datagrams==1);
    puts("PASS platform reload preserves delivery, refreshes policy and retains app status/page");
    baseline=maplesu_view.policy;
    unsigned previous=allocations;
    assert(!maplesu_policy_view_reload(0,0));
    assert(!maplesu_policy_view_reload(1,-EINVAL));
    assert(maplesu_view.policy==baseline && allocations==previous);
    assert(!maplesu_policy_view_reload(0,0));
    native_load(8); fail_alloc=allocations+1;
    assert(maplesu_policy_view_reload(1,24)==-ENOMEM);
    assert(maplesu_view.policy==baseline && maplesu_view.policy->latest_granting==7 &&
        !memcmp(page->data,&captured,sizeof(captured)));
    maplesu_policy_query_begin(); maplesu_policy_query_end();
    puts("PASS native failure skips refresh; allocation failure retains a live snapshot and releases locks");
    fail_alloc=0;
    assert(!maplesu_policy_view_module_write(0));
    current=&another;
    assert(maplesu_policy_view_module_write(1)==-EPERM);
    current=&fixture_task;
    assert(!maplesu_policy_view_module_write(1) && !maplesu_view.module_writer);
    assert(maplesu_policy_view_module_write(2)==-EINVAL);
    fixture_uid=10123;
    assert(maplesu_policy_view_module_write(0)==-EINVAL);
    fixture_uid=0;
    assert(!maplesu_policy_view_reload(0,0));
    native_load(0);
    assert(!maplesu_policy_view_reload(1,24));
    assert(maplesu_view.policy->latest_granting==0 && !memcmp(page->data,&captured,sizeof(captured)));
    assert(((struct selinux_kernel_status *)original_status.data)->policyload==0);
    puts("PASS writer identity cannot be transferred; native wraparound preserves the app view");
    reset();
    return 0;
}
