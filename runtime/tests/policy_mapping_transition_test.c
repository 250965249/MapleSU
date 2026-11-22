#include "policy_mapping_fixture.h"
#include <stdio.h>
#include <string.h>
const struct file_operations sel_handle_status_ops={0}, unrelated_ops={1};
struct maplesu_policy_view maplesu_view;
struct task_struct init_task;
struct task_struct *current;
static struct task_struct tasks[4];
static struct signal_struct signals[4];
static struct cred creds[4];
static struct mm_struct mms[4];
static struct vm_area_struct vmas[4][2];
static struct page native={11},snapshot={29};
static struct file status_file={&sel_handle_status_ops,&native},other_file={&unrelated_ops,&native};
static unsigned in_walk,allocations,fail_allocate,fail_remap,lock_begins,lock_ends,work_count;
void mutex_lock(struct mutex *m) {assert(!m->held&&!in_walk);m->held=1;}
void mutex_unlock(struct mutex *m) {assert(m->held);m->held=0;}
int down_write_killable(struct rw_semaphore *m) {assert(!in_walk&&!m->held);m->held=1;return 0;}
void down_write(struct rw_semaphore *m) {assert(!down_write_killable(m));}
void up_write(struct rw_semaphore *m) {assert(m->held);m->held=0;}
void down_read(struct rw_semaphore *m) {assert(!m->held);m->held=1;}
void up_read(struct rw_semaphore *m) {assert(m->held);m->held=0;}
void do_raw_write_seqcount_begin(seqcount_t *s) {assert(!(s->sequence&1));++s->sequence;++lock_begins;}
void do_raw_write_seqcount_end(seqcount_t *s) {assert(s->sequence&1);++s->sequence;++lock_ends;}
void vma_end_write_all(struct mm_struct *m) {do_raw_write_seqcount_end(&m->mm_lock_seq);}
void *kmalloc(size_t size,int flags) {(void)flags;return ++allocations==fail_allocate?NULL:calloc(1,size);}
void kfree(void *p) {free(p);}
int task_work_add(struct task_struct *t,struct callback_head *w,int flags) {
    assert(flags==TWA_RESUME);w->next=t->work;t->work=w;++work_count;return 0;
}
struct mm_struct *get_task_mm(struct task_struct *t) {if(t->mm)++t->mm->refs;return t->mm;}
void mmput(struct mm_struct *m) {assert(!in_walk&&m->refs);--m->refs;}
void walk_process_tree(struct task_struct *root,int (*visitor)(struct task_struct *,void *),void *data) {
    assert(root==&init_task);in_walk=1;
    for(unsigned i=0;i<3;++i)if(visitor(&tasks[i],data)<0)break;
    in_walk=0;
}
struct vm_area_struct *find_vma(struct mm_struct *mm,unsigned long address) {
    assert(mm->mmap_lock.held&&(mm->mm_lock_seq.sequence&1));
    for(unsigned i=0;i<mm->count;++i)if(mm->vmas[i].vm_end>address)return &mm->vmas[i];
    return NULL;
}
void zap_vma_ptes(struct vm_area_struct *v,unsigned long at,unsigned long bytes) {
    assert(at==v->vm_start&&bytes==PAGE_SIZE);v->mapped_pfn=0;
}
int remap_pfn_range(struct vm_area_struct *v,unsigned long at,unsigned long pfn,unsigned long bytes,unsigned long protection) {
    assert(at==v->vm_start&&bytes==PAGE_SIZE&&protection==v->vm_page_prot);
    if(fail_remap){--fail_remap;return -ENOMEM;}v->mapped_pfn=pfn;return 0;
}
static void run_work(struct task_struct *t) {
    current=t;
    while(t->work){struct callback_head *w=t->work;t->work=w->next;w->func(w);--work_count;}
}
static void reset(void) {
    memset(tasks,0,sizeof tasks);memset(signals,0,sizeof signals);memset(mms,0,sizeof mms);
    for(unsigned i=0;i<4;++i){
        creds[i].uid.val=i?10123:0;tasks[i].real_cred=&creds[i];tasks[i].mm=&mms[i];tasks[i].signal=&signals[i];
        INIT_LIST_HEAD(&signals[i].thread_head);list_add_tail(&tasks[i].thread_node,&signals[i].thread_head);
        mms[i].vmas=vmas[i];mms[i].count=2;
        vmas[i][0]=(struct vm_area_struct){.vm_start=0x10000,.vm_end=0x11000,.vm_flags=VM_PFNMAP,.vm_file=&status_file,.mapped_pfn=native.pfn};
        vmas[i][1]=(struct vm_area_struct){.vm_start=0x20000,.vm_end=0x21000,.vm_flags=VM_PFNMAP,.vm_file=&other_file,.mapped_pfn=77};
    }
    current=&tasks[0];maplesu_view.policy=(void *)1;maplesu_view.status=&snapshot;
    allocations=fail_allocate=fail_remap=lock_begins=lock_ends=0;
}
int main(void) {
#ifdef MAPLESU_POLICY_MAPPING_CREDS_ONLY
    reset();current=&tasks[1];maplesu_policy_view_creds_changed();run_work(current);
    assert(vmas[1][0].mapped_pfn==snapshot.pfn&&lock_begins==lock_ends);
    puts("PASS: native mmap seqcount remains balanced across the credential callback");
#else
    reset();
    assert(!maplesu_policy_view_transition(1));
    assert(vmas[0][0].mapped_pfn==native.pfn&&vmas[1][0].mapped_pfn==snapshot.pfn&&vmas[2][0].mapped_pfn==snapshot.pfn);
    for(unsigned i=0;i<3;++i)assert(vmas[i][1].mapped_pfn==77&&!mms[i].refs&&!(mms[i].mm_lock_seq.sequence&1));
    assert(lock_begins==3&&lock_ends==3);
    puts("PASS: enable retargets existing app status VMAs, preserves root/unrelated mappings and native seqcount locks");
    assert(!maplesu_policy_view_transition(0));
    for(unsigned i=0;i<3;++i)assert(vmas[i][0].mapped_pfn==native.pfn&&!mms[i].refs);
    puts("PASS: disable restores all existing mapped pages before reporting success");
    assert(!maplesu_policy_view_transition(1));
    creds[1].uid.val=0;current=&tasks[1];maplesu_policy_view_creds_changed();assert(work_count==1);run_work(current);
    assert(vmas[1][0].mapped_pfn==native.pfn&&lock_begins==lock_ends);
    puts("PASS: inherited mapping follows a credential boundary with a balanced native write sequence");
    current=&tasks[0];maplesu_policy_view_fork_guard(0);
    vmas[3][0].mapped_pfn=vmas[2][0].mapped_pfn;maplesu_policy_view_fork_guard(1);
    assert(vmas[3][0].mapped_pfn==snapshot.pfn);
    assert(!maplesu_policy_view_transition(0));maplesu_policy_view_fork_guard(0);
    vmas[3][0].mapped_pfn=vmas[2][0].mapped_pfn;maplesu_policy_view_fork_guard(1);
    assert(vmas[3][0].mapped_pfn==native.pfn);
    puts("PASS: the native fork guard preserves the selected mapping across a hot transition");
    current=&tasks[0];fail_remap=1;assert(maplesu_policy_view_transition(1)==-ENOMEM);
    assert(vmas[0][0].mapped_pfn==native.pfn);for(unsigned i=0;i<3;++i)assert(!mms[i].refs);
    fail_remap=0;assert(!maplesu_policy_view_transition(0));
    puts("PASS: failed remap retains readable native mapping and returns a recoverable failure");
    fail_allocate=allocations+2;assert(maplesu_policy_view_transition(1)==-ENOMEM);
    for(unsigned i=0;i<3;++i)assert(!mms[i].refs);
    fail_allocate=0;assert(!maplesu_policy_view_transition(0));
    puts("PASS: task-list allocation failure releases MM references outside the native task-list lock");
    reset();tasks[2].mm=&mms[1];
    assert(!maplesu_policy_view_transition(1));
    assert(lock_begins==2&&lock_ends==2&&!mms[1].refs);
    assert(!maplesu_policy_view_transition(0));
    puts("PASS: threads sharing one MM reconcile that address space only once");
    reset();tasks[1].mm=&mms[0];
    assert(maplesu_policy_view_transition(1)==-EOPNOTSUPP);
    assert(!lock_begins&&!lock_ends);
    for(unsigned i=0;i<3;++i)assert(!mms[i].refs&&vmas[i][0].mapped_pfn==native.pfn);
    assert(!maplesu_policy_view_transition(0));
    puts("PASS: a mixed root/app address space preserves native mappings and supports immediate rollback");
#endif
    return 0;
}
