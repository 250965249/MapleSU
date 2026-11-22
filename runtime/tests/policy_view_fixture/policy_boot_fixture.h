#ifndef MAPLESU_POLICY_BOOT_FIXTURE_H
#define MAPLESU_POLICY_BOOT_FIXTURE_H
#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
typedef uint32_t u32;
typedef uint64_t u64;
typedef uint16_t u16;
typedef uint32_t __le32;
struct context;struct extended_perms;struct av_decision;
#ifndef LINUX_VERSION_CODE
#define LINUX_VERSION_CODE 0x060600
#endif
#define KERNEL_VERSION(a,b,c) (((a)<<16)|((b)<<8)|(c))
#define GFP_KERNEL 0
#define GFP_USER 1
#define __GFP_ZERO 0
#define __user
#define PAGE_SIZE 4096
#define VM_WRITE 2
#define VM_MAYWRITE 32
#define MAPLESU_POLICY_HAS_VM_FLAGS_CLEAR
#define SELNL_MSG_POLICYLOAD 17
#define SELNLGRP_AVC 1
#define AF_NETLINK 16
#define NETLINK_SELINUX 7
#define POLICYDB_CONFIG_ANDROID_NETLINK_ROUTE (1U<<31)
#define POLICYDB_CONFIG_ANDROID_NETLINK_GETNEIGH (1U<<30)
#define SELINUX_KERNEL_STATUS_VERSION 1
struct mutex { unsigned held; };
#define DEFINE_MUTEX(name) struct mutex name
struct rw_semaphore { unsigned readers, writer; };
#define DECLARE_RWSEM(name) struct rw_semaphore name
static inline void down_read(struct rw_semaphore *lock) { assert(!lock->writer); ++lock->readers; }
static inline void up_read(struct rw_semaphore *lock) { assert(lock->readers); --lock->readers; }
static inline void down_write(struct rw_semaphore *lock) { assert(!lock->readers && !lock->writer); lock->writer=1; }
static inline void up_write(struct rw_semaphore *lock) { assert(lock->writer); lock->writer=0; }
struct policydb { struct { u32 nprim; } p_types; size_t len; int android_netlink_route,android_netlink_getneigh; bool initialized; };
struct sidtab { bool initialized; };
struct selinux_policy { struct sidtab *sidtab; struct policydb policydb; u32 latest_granting; };
struct page { unsigned char data[4096]; };
struct selinux_kernel_status {u32 version,sequence,enforcing,policyload,deny_unknown;};
struct policy_file {void *data;size_t len;};
struct inode { unsigned ignored; };
struct file {void *private_data;};
struct mm_struct {unsigned unused;};
struct task_struct {struct mm_struct *mm;};
struct cred {struct {u32 val;} uid;};
extern struct task_struct *current;
struct vm_area_struct {unsigned long vm_start,vm_end,vm_pgoff,vm_flags,vm_page_prot,mapped_pfn;};
struct sock {struct {u32 val;} sk_uid;unsigned sk_family,sk_protocol;};
struct nlmsghdr {u32 nlmsg_len;unsigned short nlmsg_type,nlmsg_flags;u32 nlmsg_seq,nlmsg_pid;};
struct selnl_msg_policyload {u32 seqno;};
struct sk_buff {unsigned char *data;u32 len,data_len;struct {unsigned portid,dst_group;} cb;};
#define READ_ONCE(value) __atomic_load_n(&(value),__ATOMIC_RELAXED)
#define WRITE_ONCE(value, v) __atomic_store_n(&(value),v,__ATOMIC_RELAXED)
#define smp_wmb() __atomic_thread_fence(__ATOMIC_RELEASE)
#define NETLINK_CB(skb) ((skb)->cb)
#define NLMSG_LENGTH(size) (sizeof(struct nlmsghdr)+(size))
#define NLMSG_HDRLEN sizeof(struct nlmsghdr)
#define nlmsg_hdr(skb) ((struct nlmsghdr *)((skb)->data))
#define skb_headlen(skb) ((skb)->len-(skb)->data_len)
void skb_kill_datagram(struct sock *, struct sk_buff *, unsigned int);
ssize_t simple_read_from_buffer(void *,size_t,loff_t *,const void *,size_t);
int remap_pfn_range(struct vm_area_struct *,unsigned long,unsigned long,unsigned long,unsigned long);
#define page_to_pfn(page) ((unsigned long)(page))
#define vm_flags_clear(vma,flags) ((vma)->vm_flags &= ~(flags))
extern struct {struct mutex policy_mutex,status_lock;struct selinux_policy *policy;} selinux_state;
extern u32 fixture_uid;
extern bool fixture_interrupt, fixture_irqs_disabled, fixture_atomic;
extern unsigned fixture_rcu_depth;
#define in_task() (!fixture_interrupt)
#define irqs_disabled() (fixture_irqs_disabled)
#define in_atomic() (fixture_atomic)
#define rcu_preempt_depth() (fixture_rcu_depth)
static inline struct {u32 val;} current_uid(void) {return (__typeof__(current_uid())){fixture_uid};}
void mutex_lock(struct mutex *);
void mutex_unlock(struct mutex *);
#define lockdep_is_held(p) ((p)->held)
#define rcu_dereference_protected(p,c) ((void)assert(c),(p))
#define check_mul_overflow(a,b,p) __builtin_mul_overflow(a,b,p)
#define check_add_overflow(a,b,p) __builtin_add_overflow(a,b,p)
#define ERR_PTR(rc) ((void *)(intptr_t)(rc))
#define PTR_ERR(p) ((intptr_t)(p))
#define IS_ERR(p) ((uintptr_t)(p)>(uintptr_t)-4096)
#define le32_to_cpu(x) (x)
#define cpu_to_le32(x) (x)
#define smp_store_release(p,v) __atomic_store_n(p,v,__ATOMIC_RELEASE)
#define smp_load_acquire(p) __atomic_load_n(p,__ATOMIC_ACQUIRE)
void *vmalloc(size_t);
void vfree(void *);
void *kzalloc(size_t,int);
void kfree(void *);
int policydb_write(struct policydb *,struct policy_file *);
int policydb_read(struct policydb *,void *);
int policydb_load_isids(struct policydb *,struct sidtab *);
void policydb_destroy(struct policydb *);
void sidtab_destroy(struct sidtab *);
struct page *selinux_kernel_status_page(void);
struct page *fixture_alloc_page(int);
#define alloc_page(x) fixture_alloc_page(x)
#define page_address(p) ((p)->data)
#endif
