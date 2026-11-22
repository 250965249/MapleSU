// SPDX-License-Identifier: GPL-3.0-only
/* The runner includes exact production function bodies. Kernel APIs and object
 * layouts below are fixtures; this does not establish a real target ABI. */
#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

typedef uint64_t u64;
#define TASK_COMM_LEN 16
#define EOPNOTSUPP 95
#define rcu_access_pointer(value) (value)
struct cred { unsigned int fixture; };
struct task_struct {
    const struct cred *cred;
    unsigned char gap[29];
    char comm[TASK_COMM_LEN];
    const struct cred *real_cred;
};
struct inode { unsigned int fixture; };
struct file { struct inode *f_inode; };
struct vm_area_struct {
    unsigned long vm_start, vm_end;
    struct file *vm_file;
};
struct mm_struct {
    struct vm_area_struct *areas;
    unsigned int count;
};

static struct task_struct caller;
static struct task_struct *current = &caller;
static struct cred caller_cred, init_cred, other_cred;
static struct mm_struct mm;
static struct mm_struct *available_mm;
static int task_locks, task_lock_calls, overrides, reverts;
static int mm_locks, mm_refs, mm_puts, mm_gets, vma_calls;
static unsigned long vma_addresses[8];
static bool stuck_vma;
static char original_comm[TASK_COMM_LEN];

static const struct cred *current_cred(void) { return current->cred; }
static void task_lock(struct task_struct *task)
{ assert(task == current && task_locks++ == 0); ++task_lock_calls; }
static void task_unlock(struct task_struct *task)
{ assert(task == current && --task_locks == 0); }
static const struct cred *override_creds(const struct cred *next)
{
    const struct cred *old = current->cred;
    const u64 marker = 0xf000f000f000f000ULL;
    assert(next == &init_cred && task_locks == 0);
    assert(!memcmp(current->comm, &marker, sizeof(marker)));
    ++overrides; current->cred = next;
    return old;
}
static void revert_creds(const struct cred *old)
{
    assert(old == &caller_cred && task_locks == 0);
    assert(!memcmp(current->comm, original_comm, TASK_COMM_LEN));
    ++reverts; current->cred = old;
}
static struct mm_struct *get_task_mm(struct task_struct *task)
{
    assert(task == current); ++mm_gets;
    if (available_mm) ++mm_refs;
    return available_mm;
}
static void mmap_read_lock(struct mm_struct *value)
{ assert(value == &mm && mm_refs == 1 && mm_locks++ == 0); }
static void mmap_read_unlock(struct mm_struct *value)
{ assert(value == &mm && --mm_locks == 0); }
static void mmput(struct mm_struct *value)
{ assert(value == &mm && mm_locks == 0 && --mm_refs == 0); ++mm_puts; }
static struct inode *file_inode(struct file *file) { return file->f_inode; }
static struct vm_area_struct *find_vma(struct mm_struct *value, unsigned long address)
{
    unsigned int i;
    assert(value == &mm && mm_refs == 1 && mm_locks == 1 && vma_calls < 8);
    vma_addresses[vma_calls++] = address;
    if (stuck_vma) return mm.areas;
    for (i = 0; i < value->count; ++i)
        if (value->areas[i].vm_end > address) return &value->areas[i];
    return NULL;
}

#include "claim-kernel-scope.inc"

static void reset(void)
{
    unsigned int i;
    memset(&caller, 0, sizeof(caller));
    caller.cred = caller.real_cred = &caller_cred;
    for (i = 0; i < TASK_COMM_LEN; ++i) caller.comm[i] = (char)('A' + i);
    memcpy(original_comm, caller.comm, TASK_COMM_LEN);
    task_locks = task_lock_calls = overrides = reverts = 0;
    mm_locks = mm_refs = mm_puts = mm_gets = vma_calls = 0;
    memset(vma_addresses, 0, sizeof(vma_addresses));
    memset(&mm, 0, sizeof(mm)); available_mm = &mm; stuck_vma = false;
}
static void released(void)
{ assert(mm_gets == 1 && mm_puts == 1 && mm_refs == 0 && mm_locks == 0); }

int main(void)
{
    struct msu_io_scope scope;
    struct inode wanted = {1}, different = {2};
    struct file apk = {&wanted}, alias = {&wanted}, unrelated = {&different};
    struct vm_area_struct areas[] = {
        {0x1000, 0x2000, NULL}, {0x9000, 0xa000, &unrelated},
        {0xf000, 0x11000, &alias},
    };
    const u64 marker = 0xf000f000f000f000ULL;
    reset();
    assert(offsetof(struct task_struct, comm) != offsetof(struct task_struct, cred) + 16);
    assert(msu_io_enter(&scope) == 0 && scope.active && overrides == 1);
    assert(scope.old_cred == &caller_cred && caller.cred == &init_cred);
    assert(!memcmp(caller.comm, &marker, sizeof(marker)));
    assert(!memcmp(caller.comm + sizeof(marker), original_comm + sizeof(marker), TASK_COMM_LEN - sizeof(marker)));
    msu_io_leave(&scope);
    assert(!scope.active && caller.cred == &caller_cred && reverts == 1 && task_lock_calls == 2);
    assert(!memcmp(caller.comm, original_comm, TASK_COMM_LEN));
    puts("io-marker: passed");

    reset(); caller.cred = &other_cred;
    assert(msu_io_enter(&scope) == -EOPNOTSUPP && !scope.active);
    assert(!overrides && !task_lock_calls && caller.cred == &other_cred);
    assert(!memcmp(caller.comm, original_comm, TASK_COMM_LEN));
    msu_io_leave(&scope); assert(!reverts);
    puts("io-overridden: passed");

    reset(); memset(&scope, 0, sizeof(scope)); msu_io_leave(&scope);
    assert(!overrides && !reverts && !task_lock_calls);
    puts("io-inactive: passed");

    reset(); available_mm = NULL;
    assert(!msu_caller_maps_apk(&apk));
    assert(mm_gets == 1 && !mm_puts && !mm_locks && !vma_calls);
    puts("map-no-mm: passed");

    reset(); assert(!msu_caller_maps_apk(&apk)); released(); assert(vma_calls == 1);
    puts("map-empty: passed");

    reset(); mm.areas = areas; mm.count = 3;
    assert(msu_caller_maps_apk(&apk)); released();
    assert(vma_calls == 3 && vma_addresses[0] == 0 && vma_addresses[1] == 0x2000 && vma_addresses[2] == 0xa000);
    puts("map-gap-and-inode-alias: passed");

    reset(); mm.areas = &areas[2]; mm.count = 1;
    assert(msu_caller_maps_apk(&apk)); released(); assert(vma_calls == 1);
    puts("map-first: passed");

    reset(); mm.areas = areas; mm.count = 2;
    assert(!msu_caller_maps_apk(&apk)); released();
    assert(vma_calls == 3 && vma_addresses[2] == 0xa000);
    puts("map-unmapped: passed");

    reset(); mm.areas = areas; mm.count = 1;
    assert(!msu_caller_maps_apk(&apk)); released();
    assert(vma_calls == 2 && vma_addresses[1] == 0x2000);
    puts("map-anonymous: passed");

    reset(); mm.areas = areas; mm.count = 1; stuck_vma = true;
    assert(!msu_caller_maps_apk(&apk)); released(); assert(vma_calls == 2);
    puts("map-nonprogress: passed");
    return 0;
}
