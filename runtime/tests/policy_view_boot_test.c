#include "policy_view_internal.h"
#include <stdio.h>

__typeof__(selinux_state) selinux_state;
u32 fixture_uid;
bool fixture_interrupt, fixture_irqs_disabled, fixture_atomic;
unsigned fixture_rcu_depth;
static struct mm_struct fixture_mm;
static struct task_struct fixture_task;
struct task_struct *current = &fixture_task;
bool maplesu_policy_hot_bound, maplesu_policy_hot_hidden;
static unsigned killed_datagrams, killed_flags;
static struct page original_status;
static struct selinux_policy live;
static unsigned fail_alloc,allocations,db_destroyed,sid_destroyed,tests;
static int write_error,read_error,sid_error;
static bool no_status;
static void *owned[64];
static unsigned owned_count;
static u32 encoded_flags;
static int mmap_error;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 10, 0)
static const u32 expected_sequence=4, expected_policyload=1;
#else
static const u32 expected_sequence=0, expected_policyload=0;
#endif
void skb_kill_datagram(struct sock *sk, struct sk_buff *skb, unsigned int flags) {
    assert(sk->sk_family == AF_NETLINK && skb);
    ++killed_datagrams; killed_flags = flags;
}

ssize_t simple_read_from_buffer(void *to,size_t count,loff_t *position,const void *from,size_t available) {
    if (*position<0) return -EINVAL;
    if ((size_t)*position>=available || !count) return 0;
    if (!to) return -EFAULT;
    if (count>available-(size_t)*position) count=available-(size_t)*position;
    memcpy(to,(const char *)from+*position,count);*position+=count;return count;
}
int remap_pfn_range(struct vm_area_struct *vma,unsigned long start,unsigned long pfn,
                    unsigned long size,unsigned long protection) {
    assert(start==vma->vm_start && size==PAGE_SIZE && protection==vma->vm_page_prot);
    assert(!(vma->vm_flags&VM_MAYWRITE));
    if (!mmap_error) vma->mapped_pfn=pfn;
    return mmap_error;
}
void mutex_lock(struct mutex *m) {
    assert(in_task() && !irqs_disabled() && !in_atomic() && !rcu_preempt_depth());
    assert(!m->held);m->held=1;
}
void mutex_unlock(struct mutex *m) {assert(m->held);m->held=0;}
static void *allocate(size_t n) {
    if (++allocations==fail_alloc) return NULL;
    void *p=calloc(1,n);assert(p && owned_count<64);owned[owned_count++]=p;return p;
}
static void release(void *p) {
    if (!p) return;
    for (unsigned i=0;i<owned_count;i++) if (owned[i]==p) {owned[i]=NULL;free(p);return;}
    assert(!"unknown allocation/double free");
}
void *vmalloc(size_t n) {assert(selinux_state.policy_mutex.held);return allocate(n);}
void *kzalloc(size_t n,int flags) {(void)flags;return allocate(n);}
void vfree(void *p) {release(p);}
void kfree(void *p) {release(p);}
struct page *fixture_alloc_page(int flags) {(void)flags;return allocate(sizeof(struct page));}
struct page *selinux_kernel_status_page(void) {return no_status?NULL:&original_status;}
int policydb_write(struct policydb *p,struct policy_file *f) {
    assert(p==&live.policydb && selinux_state.policy_mutex.held);
    if (write_error) return write_error;
    assert(f->len>=24);memset(f->data,0,24);f->data=(char *)f->data+24;f->len-=24;return 0;
}
int policydb_read(struct policydb *p,void *file) {
    struct policy_file *f=file;
    assert(selinux_state.policy_mutex.held);
    if (read_error) return read_error;
    encoded_flags=((__le32 *)f->data)[5];
    p->initialized=true;p->p_types.nprim=17;return 0;
}
int policydb_load_isids(struct policydb *p,struct sidtab *s) {
    assert(p->initialized && selinux_state.policy_mutex.held);
    if (sid_error) return sid_error;
    s->initialized=true;return 0;
}
void policydb_destroy(struct policydb *p) {assert(p->initialized);p->initialized=false;++db_destroyed;}
void sidtab_destroy(struct sidtab *s) {assert(s->initialized);s->initialized=false;++sid_destroyed;}
static void reset(void) {
    for (unsigned i=0;i<owned_count;i++) free(owned[i]);
    owned_count=0;allocations=db_destroyed=sid_destroyed=fail_alloc=0;
    write_error=read_error=sid_error=0;no_status=false;encoded_flags=0;fixture_uid=0;
    fixture_interrupt=fixture_irqs_disabled=fixture_atomic=false;fixture_rcu_depth=0;
    mmap_error=0;
    maplesu_policy_hot_bound=maplesu_policy_hot_hidden=false;
    fixture_task.mm=&fixture_mm;killed_datagrams=killed_flags=0;
    memset(&maplesu_view,0,sizeof(maplesu_view));memset(&selinux_state,0,sizeof(selinux_state));
    memset(&live,0,sizeof(live));live.policydb.len=64;live.policydb.p_types.nprim=17;live.latest_granting=5;
    selinux_state.policy=&live;
    *(struct selinux_kernel_status *)original_status.data=(struct selinux_kernel_status){1,16,1,5,1};
}
static void fails(int error) {
    assert(maplesu_policy_view_prepare()==error);
    assert(!maplesu_view.policy && !maplesu_view.status);
    assert(!selinux_state.policy_mutex.held && !selinux_state.status_lock.held);
    for (unsigned i=0;i<owned_count;i++) assert(!owned[i]);
    ++tests;
}
int main(void) {
    reset();fixture_uid=2000;fails(-EPERM);assert(!allocations);
    reset();fixture_interrupt=true;fails(-EWOULDBLOCK);assert(!allocations);
    reset();fixture_irqs_disabled=true;fails(-EWOULDBLOCK);assert(!allocations);
    reset();fixture_atomic=true;fails(-EWOULDBLOCK);assert(!allocations);
    reset();fixture_rcu_depth=1;fails(-EWOULDBLOCK);assert(!allocations);
    reset();fixture_rcu_depth=2;fails(-EWOULDBLOCK);assert(!allocations);
    reset();selinux_state.policy=NULL;fails(-EAGAIN);assert(!allocations);
    reset();live.policydb.len=SIZE_MAX;fails(-EOVERFLOW);assert(!allocations);
    for (unsigned i=1;i<=5;i++) {reset();fail_alloc=i;fails(-ENOMEM);}
    reset();write_error=-EINVAL;fails(-EINVAL);assert(!db_destroyed);
    reset();read_error=-EINVAL;fails(-EINVAL);assert(!db_destroyed);
    reset();sid_error=-ENOMEM;fails(-ENOMEM);assert(db_destroyed==1 && !sid_destroyed);
    reset();no_status=true;fails(-ENOMEM);assert(db_destroyed==1 && sid_destroyed==1);
    /* A retry may follow SKP's suppressed notification. Copy the policy without
     * requiring its generation to equal the status notification counter. */
    reset();((struct selinux_kernel_status *)original_status.data)->policyload=3;
    assert(!maplesu_policy_view_prepare());
    assert(maplesu_view.policy->latest_granting==5);
    assert(((struct selinux_kernel_status *)maplesu_view.status->data)->policyload==expected_policyload);++tests;
    reset();((struct selinux_kernel_status *)original_status.data)->sequence|=1;
    fails(-EAGAIN);
    reset();((struct selinux_kernel_status *)original_status.data)->version=2;
    fails(-EAGAIN);
    reset();
    ((struct selinux_kernel_status *)original_status.data)->sequence=0;
    ((struct selinux_kernel_status *)original_status.data)->policyload=0;
    assert(maplesu_policy_view_prepare()==0);
    assert(((struct selinux_kernel_status *)maplesu_view.status->data)->policyload==expected_policyload);
    assert(maplesu_view.policy->latest_granting==5);++tests;
    reset();live.policydb.android_netlink_route=live.policydb.android_netlink_getneigh=1;
    assert(maplesu_policy_view_prepare()==0);
    assert(encoded_flags==((1U<<31)|(1U<<30)));
    assert(maplesu_view.policy!=&live && maplesu_view.policy->sidtab && maplesu_view.policy->sidtab!=live.sidtab);
    assert(maplesu_view.policy->latest_granting==5 && maplesu_view.policy->policydb.len==24);
    struct selinux_kernel_status expected_status={1,expected_sequence,1,expected_policyload,1};
    assert(!memcmp(maplesu_view.status->data,&expected_status,sizeof(expected_status)));
    assert(((struct selinux_kernel_status *)original_status.data)->sequence==16 &&
           ((struct selinux_kernel_status *)original_status.data)->policyload==5);++tests;
    {
        unsigned n=allocations;struct selinux_policy *p=maplesu_view.policy;
        assert(maplesu_policy_view_prepare()==-EALREADY && allocations==n && maplesu_view.policy==p);++tests;
    }
    assert(maplesu_type_is_original(&live.policydb,5,17)==1);
    assert(maplesu_type_is_original(&live.policydb,5,0)==0);
    live.policydb.p_types.nprim=20;
    assert(maplesu_type_is_original(&live.policydb,5,18)==0);
    assert(maplesu_type_is_original(&live.policydb,6,17)==-1);
    assert(maplesu_type_is_original(&live.policydb,0,17)==-1);
    {struct policydb replaced=live.policydb;assert(maplesu_type_is_original(&replaced,5,17)==-1);}++tests;
    fixture_uid=9999;assert(!maplesu_policy_view_handles(MAPLESU_POLICY_ACCESS,NULL,NULL));
    fixture_uid=10000;assert(maplesu_policy_view_handles(MAPLESU_POLICY_ACCESS,NULL,NULL));
    assert(maplesu_policy_view_handles(MAPLESU_POLICY_SETPROCATTR,"current",NULL));
    assert(!maplesu_policy_view_handles(MAPLESU_POLICY_SETPROCATTR,"exec",NULL));
    assert(!maplesu_policy_view_handles(MAPLESU_POLICY_SETPROCATTR,NULL,NULL));
    assert(!maplesu_policy_view_handles(99,NULL,NULL));++tests;
    fixture_uid=0;
    assert(!maplesu_policy_view_handles(MAPLESU_POLICY_STATUS_READ,NULL,NULL));
    assert(!maplesu_policy_view_handles(MAPLESU_POLICY_STATUS_MMAP,NULL,NULL));++tests;
    fixture_uid=10123;
    assert(maplesu_policy_view_handles(MAPLESU_POLICY_STATUS_READ,NULL,NULL));
    assert(maplesu_policy_view_handles(MAPLESU_POLICY_STATUS_MMAP,NULL,NULL));++tests;
    {
        struct cred next={{0}};
        assert(maplesu_policy_view_handles(MAPLESU_POLICY_CRED_COMMIT,&next,NULL));
        next.uid.val=10000;
        assert(!maplesu_policy_view_handles(MAPLESU_POLICY_CRED_COMMIT,&next,NULL));
        fixture_uid=0;
        assert(maplesu_policy_view_handles(MAPLESU_POLICY_CRED_COMMIT,&next,NULL));
        current->mm=NULL;
        assert(!maplesu_policy_view_handles(MAPLESU_POLICY_CRED_COMMIT,&next,NULL));
        current->mm=&fixture_mm;fixture_uid=10123;++tests;
    }
    {
        struct file before={0},after={0};
        assert(!maplesu_policy_view_status_open(NULL,&before));
        ((struct selinux_kernel_status *)original_status.data)->policyload=99;
        live.latest_granting=99;
        assert(!maplesu_policy_view_status_open(NULL,&after));
        assert(before.private_data==after.private_data && before.private_data==&original_status);
        loff_t position=0;struct selinux_kernel_status view={0};
        assert(maplesu_policy_view_status_read(&after,(char *)&view,sizeof(view),&position)==sizeof(view));
        assert(view.policyload==expected_policyload);++tests;
    }
    {
        /* Root-opened FD is shared; choosing an app view must not change its
         * page pointer or the native page still used by platform services. */
        struct file inherited={&original_status};
        struct selinux_kernel_status readback={0};
        loff_t position=0;
        assert(maplesu_policy_view_status_read(&inherited,(char *)&readback,sizeof(readback),&position)==sizeof(readback));
        assert(readback.sequence==expected_sequence && readback.policyload==expected_policyload && position==sizeof(readback));
        assert(inherited.private_data==&original_status);
        assert(((struct selinux_kernel_status *)original_status.data)->policyload==99);++tests;
        assert(!maplesu_policy_view_status_read(&inherited,(char *)&readback,sizeof(readback),&position));++tests;
        position=4;
        assert(maplesu_policy_view_status_read(&inherited,(char *)&readback,4,&position)==4);
        assert(*(u32 *)&readback==expected_sequence && position==8);++tests;
        position=-1;
        assert(maplesu_policy_view_status_read(&inherited,(char *)&readback,sizeof(readback),&position)==-EINVAL);++tests;
        position=0;
        assert(maplesu_policy_view_status_read(&inherited,NULL,sizeof(readback),&position)==-EFAULT && !position);++tests;
        struct vm_area_struct vma={.vm_start=0x10000,.vm_end=0x10000+PAGE_SIZE,.vm_flags=VM_MAYWRITE};
        assert(!maplesu_policy_view_status_mmap(&inherited,&vma));
        assert(vma.mapped_pfn==page_to_pfn(maplesu_view.status) && inherited.private_data==&original_status);++tests;
        vma.vm_pgoff=1;assert(maplesu_policy_view_status_mmap(&inherited,&vma)==-EIO);++tests;
        vma.vm_pgoff=0;vma.vm_end++;
        assert(maplesu_policy_view_status_mmap(&inherited,&vma)==-EIO);++tests;
        vma.vm_end--;vma.vm_flags=VM_WRITE|VM_MAYWRITE;
        assert(maplesu_policy_view_status_mmap(&inherited,&vma)==-EPERM && (vma.vm_flags&VM_MAYWRITE));++tests;
        vma.vm_flags=VM_MAYWRITE;mmap_error=-ENOMEM;
        assert(maplesu_policy_view_status_mmap(&inherited,&vma)==-ENOMEM && !(vma.vm_flags&VM_MAYWRITE));++tests;
    }
    {
        struct {struct nlmsghdr header;struct selnl_msg_policyload payload;} packet={
            .header={.nlmsg_len=NLMSG_LENGTH(sizeof(struct selnl_msg_policyload)),.nlmsg_type=SELNL_MSG_POLICYLOAD},
            .payload={99}};
        struct sk_buff skb={.data=(unsigned char *)&packet,.len=sizeof(packet),.cb={.dst_group=SELNLGRP_AVC}};
        struct sock platform_receiver={{10123},AF_NETLINK,NETLINK_SELINUX};
        maplesu_policy_hot_bound=true;
        assert(!maplesu_policy_view_handles(MAPLESU_POLICY_NOTIFY_FILTER,&platform_receiver,&skb));
        assert(maplesu_policy_view_receive(&platform_receiver,&skb,0)==&skb && !killed_datagrams);
        maplesu_policy_hot_bound=false;
        unsigned before_allocations=allocations;
        for (fixture_uid=0;fixture_uid<=10000;fixture_uid+=10000)
            for (u32 uid=0;uid<=110000;uid+=1000) {
                struct sock receiver={{uid},AF_NETLINK,NETLINK_SELINUX};
                assert(maplesu_policy_view_handles(MAPLESU_POLICY_NOTIFY_FILTER,&receiver,&skb)==(uid>=10000));
                if (uid>=10000) assert(maplesu_policy_view_filter(&receiver,&skb,1)==-EPERM);
                ++tests;
            }
        struct sock receiver={{10123},AF_NETLINK,NETLINK_SELINUX};
        fixture_uid=10123;
        assert(maplesu_policy_view_handles(MAPLESU_POLICY_NOTIFY_RECEIVE,&receiver,NULL));
        assert(!maplesu_policy_view_receive(&receiver,&skb,2));
        assert(killed_datagrams==1 && killed_flags==2);
        receiver.sk_uid.val=0;
        assert(maplesu_policy_view_handles(MAPLESU_POLICY_NOTIFY_RECEIVE,&receiver,NULL));
        assert(!maplesu_policy_view_receive(&receiver,&skb,0));
        assert(killed_datagrams==2 && !killed_flags);
        fixture_uid=0;
        assert(!maplesu_policy_view_handles(MAPLESU_POLICY_NOTIFY_RECEIVE,&receiver,NULL));
        packet.header.nlmsg_type=16;
        assert(maplesu_policy_view_receive(&receiver,&skb,2)==&skb && killed_datagrams==2);
        packet.header.nlmsg_type=SELNL_MSG_POLICYLOAD;
        receiver.sk_uid.val=10123;++tests;
#define PASSTHROUGH() do {assert(!maplesu_policy_view_handles(MAPLESU_POLICY_NOTIFY_FILTER,&receiver,&skb));++tests;} while(0)
        receiver.sk_family=2;PASSTHROUGH();receiver.sk_family=AF_NETLINK;
        receiver.sk_protocol=0;PASSTHROUGH();receiver.sk_protocol=NETLINK_SELINUX;
        skb.cb.portid=123;PASSTHROUGH();skb.cb.portid=0;
        skb.cb.dst_group=2;PASSTHROUGH();skb.cb.dst_group=SELNLGRP_AVC;
        packet.header.nlmsg_type=16;PASSTHROUGH();packet.header.nlmsg_type=SELNL_MSG_POLICYLOAD;
        packet.header.nlmsg_len=15;PASSTHROUGH();packet.header.nlmsg_len=sizeof(packet)+1;PASSTHROUGH();
        packet.header.nlmsg_len=sizeof(packet);skb.len--;PASSTHROUGH();skb.len++;
        skb.data_len=1;PASSTHROUGH();skb.data_len=0;
        skb.data_len=skb.len+1;PASSTHROUGH();skb.data_len=0;
        struct selinux_policy *prepared=maplesu_view.policy;
        maplesu_view.policy=NULL;PASSTHROUGH();maplesu_view.policy=prepared;
#undef PASSTHROUGH
        assert(allocations==before_allocations && packet.payload.seqno==99);++tests;
    }
    reset();
    printf("PASS %u snapshot preparation/lifetime cases (atomic publication, allocation failures, config, counters and FD page ownership)\n",tests);
    return 0;
}
