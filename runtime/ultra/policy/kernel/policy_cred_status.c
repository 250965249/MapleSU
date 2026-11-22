// SPDX-License-Identifier: GPL-3.0-only
/* A status VMA can outlive the credentials that created it. Retarget only
 * selinuxfs status mappings when that address space crosses the app boundary. */
#ifdef MAPLESU_POLICY_MAPPINGS_HOST_TEST
#include "policy_mapping_fixture.h"
#else
#include "policy_view_internal.h"
#include <linux/mmap_lock.h>
#include <linux/task_work.h>
#endif

extern const struct file_operations sel_handle_status_ops;

struct status_mapping_work {
    struct callback_head work;
};

bool maplesu_policy_hot_bound, maplesu_policy_hot_hidden;
static DEFINE_MUTEX(mapping_transition_lock);
static DECLARE_RWSEM(mapping_fork_lock);

/* Match native mmap_write_lock/unlock, including Android's backported VMA
 * sequence protocol. The mm field is target-bound, never a compiled offset. */
static void mapping_write_begin(struct mm_struct *mm)
{
#ifdef CONFIG_PER_VMA_LOCK
#ifdef MAPLESU_POLICY_MMAP_SEQCOUNT
    do_raw_write_seqcount_begin(&PV_FIELD(mm, mm_struct, mm_lock_seq));
#endif
#endif
}

static void mapping_write_end(struct mm_struct *mm)
{
#ifdef CONFIG_PER_VMA_LOCK
#ifdef MAPLESU_POLICY_MMAP_SEQCOUNT
    do_raw_write_seqcount_end(&PV_FIELD(mm, mm_struct, mm_lock_seq));
#else
    smp_store_release(&PV_FIELD(mm, mm_struct, mm_lock_seq),
                     PV_FIELD(mm, mm_struct, mm_lock_seq) + 1);
#endif
#endif
    up_write(&PV_FIELD(mm, mm_struct, mmap_lock));
}

static int retarget_status_mappings(struct mm_struct *mm, bool app)
{
    struct vm_area_struct *vma;
    unsigned long address = 0;
    int result = 0;
    bool hidden = !smp_load_acquire(&maplesu_policy_hot_bound) ||
                  smp_load_acquire(&maplesu_policy_hot_hidden);

    while ((vma = find_vma(mm, address))) {
        struct page *original, *selected;

        address = PV_FIELD(vma, vm_area_struct, vm_end);
        if (!PV_FIELD(vma, vm_area_struct, vm_file) || PV_FIELD(PV_FIELD(vma, vm_area_struct, vm_file), file, f_op) != &sel_handle_status_ops ||
            !(PV_FIELD(vma, vm_area_struct, vm_flags) & VM_PFNMAP) || (PV_FIELD(vma, vm_area_struct, vm_flags) & VM_WRITE) ||
            PV_FIELD(vma, vm_area_struct, vm_end) - PV_FIELD(vma, vm_area_struct, vm_start) != PAGE_SIZE)
            continue;
        original = PV_FIELD(PV_FIELD(vma, vm_area_struct, vm_file), file, private_data);
        if (!original)
            continue;
        selected = app && hidden ? maplesu_view.status : original;
        zap_vma_ptes(vma, PV_FIELD(vma, vm_area_struct, vm_start), PAGE_SIZE);
        /* A failed remap must retain the native mapping rather than leave a
         * previously readable status address as an unexpected SIGBUS. */
        result = remap_pfn_range(vma, PV_FIELD(vma, vm_area_struct, vm_start), page_to_pfn(selected),
                                PAGE_SIZE, PV_FIELD(vma, vm_area_struct, vm_page_prot));
        if (result) {
            int restore = remap_pfn_range(vma, PV_FIELD(vma, vm_area_struct, vm_start), page_to_pfn(original),
                                         PAGE_SIZE, PV_FIELD(vma, vm_area_struct, vm_page_prot));
            return restore ? restore : result;
        }
    }
    return result;
}

/* Native task_work is an indirect call. Keep its KCFI type prefix and a real
 * BTI landing pad when the target's dynamic SCS rewrites PAC instructions. */
#ifdef __aarch64__
__attribute__((target("branch-protection=bti")))
#endif
static
void status_mappings_on_return(struct callback_head *work)
{
    struct mm_struct *mm = PV_FIELD(current, task_struct, mm);

    if (mm) {
        mutex_lock(&mapping_transition_lock);
        /* Match mmap_write_lock/unlock without unregistered tracepoint sites
         * in the private PIC image. Native rwsem/VMA write ownership remains. */
        down_write(&PV_FIELD(mm, mm_struct, mmap_lock));
        mapping_write_begin(mm);
        retarget_status_mappings(mm, pv_current_uid().val >= 10000);
        mapping_write_end(mm);
        mutex_unlock(&mapping_transition_lock);
    }
    kfree(container_of(work, struct status_mapping_work, work));
}

static void queue_status_mapping_work(struct task_struct *task)
{
    struct status_mapping_work *work;

    if (!PV_FIELD(task, task_struct, mm))
        return;
    /* commit_creds has callers outside setuid. Defer until return to userspace
     * so the caller has released its mmap/RCU/atomic locks. */
    work = kmalloc(sizeof(*work), GFP_ATOMIC);
    if (!work)
        return;
    init_task_work(&work->work, status_mappings_on_return);
    if (task_work_add(task, &work->work, TWA_RESUME))
        kfree(work);
}

void maplesu_policy_view_creds_changed(void)
{
    queue_status_mapping_work(current);
}

void maplesu_policy_view_fork_guard(unsigned phase)
{
    /* The sidecar brackets native copy_process exactly once. Transition owns
     * the write side through MM enumeration and remap, so no half-copied child
     * can escape the task list and retain the previous page after a toggle. */
    if (!phase) down_read(&mapping_fork_lock);
    else up_read(&mapping_fork_lock);
}

struct mapping_reference {
    struct list_head next;
    struct mm_struct *mm;
    struct mapping_reference *index_next;
    bool app;
    bool duplicate;
};
struct mapping_collection {
    struct list_head references;
    unsigned count;
    int error;
};

#ifdef __aarch64__
__attribute__((target("branch-protection=bti")))
#endif
static int collect_status_mappings(struct task_struct *leader, void *data)
{
    struct mapping_collection *collection = data;
    struct signal_struct *signal = PV_FIELD(leader, task_struct, signal);
    struct list_head *head = &PV_FIELD(signal, signal_struct, thread_head), *link;

    /* walk_process_tree holds native tasklist_lock, including thread links.
     * Only atomic allocations/MM references here; no mmap locks or mmput. */
    for (link = head->next; link != head; link = link->next) {
#ifdef MAPLESU_POLICY_MAPPINGS_HOST_TEST
        struct task_struct *task = container_of(link, struct task_struct, thread_node);
#else
        struct task_struct *task = (void *)((char *)link -
            maplesu_policy_layout.offsets[MP_FIELD_task_struct_thread_node]);
#endif
        struct mapping_reference *reference;
        if (++collection->count > 65536) {
            collection->error = -E2BIG;
            return -1;
        }
        reference = kmalloc(sizeof(*reference), GFP_ATOMIC);
        if (!reference) {
            collection->error = -ENOMEM;
            return -1;
        }
        reference->mm = get_task_mm(task);
        if (!reference->mm) { kfree(reference); continue; }
        reference->duplicate = false;
        reference->index_next = NULL;
        rcu_read_lock();
        reference->app = PV_FIELD(pv_task_cred(task), cred, uid).val >= 10000;
        rcu_read_unlock();
        list_add_tail(&reference->next, &collection->references);
    }
    return 1;
}

int maplesu_policy_view_transition(unsigned enabled)
{
    struct mapping_collection collection;
    struct mapping_reference *index[128] = {0}, *reference;
    int result = 0;

    if (enabled > 1 || !maplesu_view.policy || !maplesu_view.status) return -EINVAL;
    if (pv_current_uid().val) return -EPERM;
    if (!in_task() || irqs_disabled() || in_atomic() || rcu_preempt_depth()) return -EWOULDBLOCK;
    INIT_LIST_HEAD(&collection.references);
    collection.count = 0; collection.error = 0;
    mutex_lock(&mapping_transition_lock);
    down_write(&mapping_fork_lock);
    smp_store_release(&maplesu_policy_hot_hidden, !!enabled);
    smp_store_release(&maplesu_policy_hot_bound, true);
    walk_process_tree(&init_task, collect_status_mappings, &collection);
    result = collection.error;
    /* A shared MM has one set of PTEs. Validate all owners before changing any
     * mapping, and take its mmap lock only once. Mixed root/app owners cannot
     * receive different pages; ordinary mode still restores that MM normally. */
    if (!result) list_for_each_entry(reference, &collection.references, next) {
        unsigned bucket = ((unsigned long)reference->mm >> 6) & 127;
        struct mapping_reference *seen = index[bucket];
        while (seen && seen->mm != reference->mm) seen = seen->index_next;
        if (seen) {
            reference->duplicate = true;
            if (enabled && seen->app != reference->app) result = -EOPNOTSUPP;
        } else {
            reference->index_next = index[bucket];
            index[bucket] = reference;
        }
    }
    while (!list_empty(&collection.references)) {
        struct mapping_reference *reference = list_first_entry(&collection.references, struct mapping_reference, next);
        int rc = 0;
        list_del(&reference->next);
        if (!result && !reference->duplicate) {
            rc = down_write_killable(&PV_FIELD(reference->mm, mm_struct, mmap_lock));
            if (!rc) {
                mapping_write_begin(reference->mm);
                rc = retarget_status_mappings(reference->mm, reference->app);
                mapping_write_end(reference->mm);
            }
            if (rc) result = rc;
        }
        mmput(reference->mm);
        kfree(reference);
    }
    up_write(&mapping_fork_lock);
    mutex_unlock(&mapping_transition_lock);
    return result;
}
