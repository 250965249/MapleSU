/* Native MM/task primitives are the test boundary; payload functions are real. */
#ifndef MAPLESU_POLICY_MAPPING_FIXTURE_H
#define MAPLESU_POLICY_MAPPING_FIXTURE_H
#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#define CONFIG_PER_VMA_LOCK 1
#define MAPLESU_POLICY_MMAP_SEQCOUNT 1
#define PAGE_SIZE 4096UL
#define VM_PFNMAP 1024UL
#define VM_WRITE 2UL
#define GFP_ATOMIC 0
#define TWA_RESUME 1
#define __user
#define READ_ONCE(x) __atomic_load_n(&(x),__ATOMIC_RELAXED)
#define smp_load_acquire(x) __atomic_load_n(x,__ATOMIC_ACQUIRE)
#define smp_store_release(x,v) __atomic_store_n(x,v,__ATOMIC_RELEASE)
#define container_of(p,t,m) ((t *)((char *)(p)-offsetof(t,m)))
#define PV_FIELD(p,t,m) ((p)->m)
#define DEFINE_MUTEX(n) struct mutex n
struct mutex { unsigned held; };
struct rw_semaphore { unsigned held; };
#define DECLARE_RWSEM(n) struct rw_semaphore n
typedef struct {unsigned sequence;} seqcount_t;
struct list_head {struct list_head *next,*prev;};
#define LIST_HEAD(n) struct list_head n={&(n),&(n)}
#define INIT_LIST_HEAD(p) ((p)->next=(p)->prev=(p))
static inline void list_add_tail(struct list_head *p,struct list_head *h) {
    p->prev=h->prev;p->next=h;h->prev->next=p;h->prev=p;
}
static inline void list_del(struct list_head *p) {p->prev->next=p->next;p->next->prev=p->prev;}
static inline bool list_empty(const struct list_head *h) {return h->next==h;}
#define list_first_entry(h,t,m) container_of((h)->next,t,m)
#define list_for_each_entry(p,h,m) for(p=list_first_entry(h,__typeof__(*p),m);&(p)->m!=(h);p=list_first_entry(&(p)->m,__typeof__(*p),m))
struct file_operations {unsigned unused;};
struct page {unsigned long pfn;};
struct file {const struct file_operations *f_op;void *private_data;};
struct vm_area_struct {
    unsigned long vm_start,vm_end,vm_flags,vm_page_prot,mapped_pfn;
    struct file *vm_file;
};
struct mm_struct {struct rw_semaphore mmap_lock;seqcount_t mm_lock_seq;struct vm_area_struct *vmas;unsigned count,refs;};
struct cred {struct {unsigned val;} uid;};
struct callback_head {struct callback_head *next;void (*func)(struct callback_head *);};
struct signal_struct {struct list_head thread_head;};
struct task_struct {struct mm_struct *mm;struct cred *real_cred;struct signal_struct *signal;struct list_head thread_node;struct callback_head *work;};
struct maplesu_policy_view {void *policy;struct page *status;};
extern struct maplesu_policy_view maplesu_view;
extern struct task_struct *current;
extern struct task_struct init_task;
extern bool maplesu_policy_hot_bound, maplesu_policy_hot_hidden;
static inline struct {unsigned val;} pv_current_uid(void) {return (__typeof__(pv_current_uid())){current->real_cred->uid.val};}
#define pv_task_cred(t) ((t)->real_cred)
#define in_task() true
#define irqs_disabled() false
#define in_atomic() false
#define rcu_preempt_depth() 0
#define page_to_pfn(p) ((p)->pfn)
#define init_task_work(w,f) ((w)->func=(f))
#define rcu_read_lock() ((void)0)
#define rcu_read_unlock() ((void)0)
void mutex_lock(struct mutex *);
void mutex_unlock(struct mutex *);
int down_write_killable(struct rw_semaphore *);
void down_write(struct rw_semaphore *);
void up_write(struct rw_semaphore *);
void down_read(struct rw_semaphore *);
void up_read(struct rw_semaphore *);
void do_raw_write_seqcount_begin(seqcount_t *);
void do_raw_write_seqcount_end(seqcount_t *);
void vma_end_write_all(struct mm_struct *);
void *kmalloc(size_t,int);
void kfree(void *);
int task_work_add(struct task_struct *,struct callback_head *,int);
struct mm_struct *get_task_mm(struct task_struct *);
void mmput(struct mm_struct *);
void walk_process_tree(struct task_struct *,int (*)(struct task_struct *,void *),void *);
struct vm_area_struct *find_vma(struct mm_struct *,unsigned long);
void zap_vma_ptes(struct vm_area_struct *,unsigned long,unsigned long);
int remap_pfn_range(struct vm_area_struct *,unsigned long,unsigned long,unsigned long,unsigned long);
void maplesu_policy_view_creds_changed(void);
void maplesu_policy_view_fork_guard(unsigned);
int maplesu_policy_view_transition(unsigned);
#endif
