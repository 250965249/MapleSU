// SPDX-License-Identifier: GPL-3.0-only
#include <linux/errno.h>
#include <linux/fs.h>
#include <linux/fsnotify_backend.h>
#include <linux/mutex.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/version.h>
#include "manager_owner.h"
#include "manager_owner_watch.h"
#include "protected_install_kernel.h"
#include "manager_dynamic_layout.h"

#define MSU_WATCH_TYPE(type) sizeof(type), __alignof__(type)
#define MSU_WATCH_FIELD(type, member) offsetof(type, member), sizeof(((type *)0)->member)
const unsigned int msu_manager_owner_watch_compiled_layout[MSU_WATCH_LAYOUT_WORDS] __attribute__((section(".msu.layout"))) = {
    1, LINUX_VERSION_CODE,
    MSU_WATCH_TYPE(struct fsnotify_mark),
    MSU_WATCH_FIELD(struct fsnotify_mark, mask),
    MSU_WATCH_TYPE(struct fsnotify_ops),
    MSU_WATCH_FIELD(struct fsnotify_ops, handle_inode_event),
    MSU_WATCH_FIELD(struct fsnotify_ops, freeing_mark),
    MSU_WATCH_FIELD(struct fsnotify_ops, free_mark),
    MSU_WATCH_TYPE(struct qstr),
    MSU_WATCH_FIELD(struct qstr, len),
    MSU_WATCH_FIELD(struct qstr, name),
    MSU_WATCH_TYPE(struct inode),
    MSU_WATCH_FIELD(struct inode, i_mode),
    MSU_WATCH_TYPE(struct mutex),
#ifdef CONFIG_PREEMPT_RT
    MSU_WATCH_FIELD(struct mutex, rtmutex),
    ~0U, 0, ~0U, 0, ~0U, 0, ~0U, 0, ~0U, 0,
#else
    ~0U, 0,
    MSU_WATCH_FIELD(struct mutex, owner),
    MSU_WATCH_FIELD(struct mutex, wait_lock),
    MSU_WATCH_FIELD(struct mutex, wait_list),
#ifdef CONFIG_MUTEX_SPIN_ON_OWNER
    MSU_WATCH_FIELD(struct mutex, osq),
#else
    ~0U, 0,
#endif
#ifdef CONFIG_DEBUG_MUTEXES
    MSU_WATCH_FIELD(struct mutex, magic),
#else
    ~0U, 0,
#endif
#endif
#ifdef CONFIG_DEBUG_LOCK_ALLOC
    MSU_WATCH_FIELD(struct mutex, dep_map),
#else
    ~0U, 0,
#endif
    MSU_WATCH_TYPE(struct lock_class_key),
    MSU_WATCH_TYPE(raw_spinlock_t),
    MSU_WATCH_TYPE(struct list_head),
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 0, 0)
    2,
#else
    1,
#endif
};
#undef MSU_WATCH_FIELD
#undef MSU_WATCH_TYPE

struct msu_owner_watch_name {
    struct msu_owner_watch_name *next;
    size_t length;
    char name[];
};
struct msu_owner_watch_mark {
    struct fsnotify_mark mark;
    struct msu_owner_watch_mark *next;
    struct msu_manager_owner_watch *watch;
    struct msu_owner_watch_name *names;
    struct inode *inode;
    bool active;
};
struct msu_manager_owner_watch {
    struct msu_manager_owner *owner;
    struct fsnotify_group *group;
    struct msu_owner_watch_mark *marks;
    struct mutex registration;
};

/* External linkage emits the compiler's KCFI type symbols. The payload link
 * version script keeps these callbacks private to the resident ELF. */
int msu_owner_inode_event(struct fsnotify_mark *mark, u32 mask,
    struct inode *inode, struct inode *dir, const struct qstr *name, u32 cookie);
void msu_owner_freeing_mark(struct fsnotify_mark *mark, struct fsnotify_group *group);
void msu_owner_free_mark(struct fsnotify_mark *mark);

int msu_owner_inode_event(struct fsnotify_mark *mark, u32 mask,
    struct inode *inode, struct inode *dir, const struct qstr *name, u32 cookie)
{
    struct msu_owner_watch_mark *entry = container_of(mark,
        struct msu_owner_watch_mark, mark);
    struct msu_owner_watch_name *target;
    (void)inode; (void)dir; (void)cookie;
    if ((mask & (FS_DELETE_SELF | FS_MOVE_SELF | FS_UNMOUNT)) ||
        ((mask & FS_ATTRIB) && !name)) {
        msu_manager_owner_invalidate(entry->watch->owner);
        fsnotify_destroy_mark(mark, entry->watch->group);
        return 0;
    }
    if (!name) return 0;
    target = __atomic_load_n(&entry->names, __ATOMIC_ACQUIRE);
    for (; target; target = target->next) {
        if (MSU_DYN_FIELD(name, qstr, len) == target->length &&
            !memcmp(MSU_DYN_FIELD(name, qstr, name), target->name, target->length)) {
            /* Once invalidated, no cached owner may rely on this mark. Retire
             * its old path names; the next protected verification re-arms the
             * current paths. fsnotify drains event readers before free_mark. */
            msu_manager_owner_invalidate(entry->watch->owner);
            fsnotify_destroy_mark(mark, entry->watch->group);
            break;
        }
    }
    return 0;
}

void msu_owner_freeing_mark(struct fsnotify_mark *mark,
    struct fsnotify_group *group)
{
    struct msu_owner_watch_mark *entry = container_of(mark,
        struct msu_owner_watch_mark, mark);
    struct msu_manager_owner_watch *watch = entry->watch;
    struct msu_owner_watch_mark **link;
    (void)group;
    __atomic_store_n(&entry->active, false, __ATOMIC_RELEASE);
    /* fsnotify invokes freeing_mark after detach, outside the group lock.
     * Registration owns the initial mark reference and every list traversal
     * holds this mutex. Unlink before dropping that reference. */
    mutex_lock(&watch->registration);
    for (link = &watch->marks; *link; link = &(*link)->next) {
        if (*link != entry) continue;
        *link = entry->next;
        break;
    }
    mutex_unlock(&watch->registration);
    msu_manager_owner_invalidate(watch->owner);
    fsnotify_put_mark(mark);
}

void msu_owner_free_mark(struct fsnotify_mark *mark)
{
    struct msu_owner_watch_mark *entry = container_of(mark,
        struct msu_owner_watch_mark, mark);
    struct msu_owner_watch_name *name, *next;
    for (name = entry->names; name; name = next) {
        next = name->next;
        kfree(name);
    }
    kfree(entry);
}

static const struct fsnotify_ops msu_owner_watch_ops = {
    .handle_inode_event = msu_owner_inode_event,
    .freeing_mark = msu_owner_freeing_mark,
    .free_mark = msu_owner_free_mark,
};

int msu_manager_owner_watch_init(struct msu_manager_owner *owner)
{
    struct msu_manager_owner_watch *watch;
    if (!owner || owner->watch) return -EINVAL;
    watch = kzalloc(sizeof(*watch), GFP_KERNEL);
    if (!watch) return -ENOMEM;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 0, 0)
    watch->group = fsnotify_alloc_group(&msu_owner_watch_ops, 0);
#else
    watch->group = fsnotify_alloc_group(&msu_owner_watch_ops);
#endif
    if (IS_ERR(watch->group)) {
        const int error = PTR_ERR(watch->group);
        kfree(watch);
        return error;
    }
    watch->owner = owner;
    mutex_init(&watch->registration);
    owner->watch = watch;
    return 0;
}

int msu_manager_owner_discard_unpublished(struct msu_manager_owner *owner)
{
    struct msu_manager_owner_watch *watch;
    if (!owner) return -EINVAL;
    watch = owner->watch;
    if (owner->bindings || (watch && watch->marks)) return -EBUSY;
    __atomic_store_n(&owner->initialized, 3, __ATOMIC_RELEASE);
    __atomic_store_n(&owner->epoch, 0, __ATOMIC_RELEASE);
    owner->watch = NULL;
    if (watch) {
        fsnotify_put_group(watch->group);
        kfree(watch);
    }
    return 0;
}

static int msu_owner_watch_name(struct msu_owner_watch_mark *entry,
    const char *name)
{
    struct msu_owner_watch_name *value;
    size_t length;
    if (!name) return 0;
    length = strnlen(name, 256);
    if (!length || length == 256) return -EINVAL;
    for (value = entry->names; value; value = value->next)
        if (value->length == length && !memcmp(value->name, name, length))
            return 0;
    value = kzalloc(sizeof(*value) + length + 1, GFP_KERNEL);
    if (!value) return -ENOMEM;
    value->length = length;
    memcpy(value->name, name, length);
    value->next = entry->names;
    __atomic_store_n(&entry->names, value, __ATOMIC_RELEASE);
    return 0;
}

static int msu_owner_watch_inode(void *context, struct inode *inode,
    const char *name)
{
    struct msu_manager_owner_watch *watch = context;
    struct msu_owner_watch_mark *entry;
    int error;
    if (!watch || !inode || !S_ISDIR(MSU_DYN_FIELD(inode, inode, i_mode))) return -EINVAL;
    mutex_lock(&watch->registration);
    for (entry = watch->marks; entry; entry = entry->next) {
        if (!__atomic_load_n(&entry->active, __ATOMIC_ACQUIRE) ||
            entry->inode != inode) continue;
        error = msu_owner_watch_name(entry, name);
        if (!error && !__atomic_load_n(&entry->active, __ATOMIC_ACQUIRE))
            error = -EAGAIN;
        mutex_unlock(&watch->registration);
        return error;
    }
    entry = kzalloc(sizeof(*entry), GFP_KERNEL);
    if (!entry) { error = -ENOMEM; goto out; }
    entry->watch = watch;
    entry->inode = inode;
    error = msu_owner_watch_name(entry, name);
    if (error) { kfree(entry); goto out; }
    fsnotify_init_mark(&entry->mark, watch->group);
    entry->mark.mask = FS_CREATE | FS_DELETE | FS_MOVE | FS_CLOSE_WRITE |
        FS_MODIFY | FS_ATTRIB | FS_DELETE_SELF | FS_MOVE_SELF |
        FS_UNMOUNT | FS_EVENT_ON_CHILD;
    entry->active = true;
    entry->next = watch->marks;
    watch->marks = entry;
    error = fsnotify_add_inode_mark(&entry->mark, inode, 0);
    if (error) {
        watch->marks = entry->next;
        entry->active = false;
        fsnotify_put_mark(&entry->mark);
    } else if (!__atomic_load_n(&entry->active, __ATOMIC_ACQUIRE)) {
        error = -EAGAIN;
    }
out:
    mutex_unlock(&watch->registration);
    return error;
}

int msu_manager_owner_watch_monitor(struct msu_manager_owner *owner,
    struct msu_install_monitor *monitor)
{
    if (!owner || !owner->watch || !monitor) return -EINVAL;
    monitor->context = owner->watch;
    monitor->watch_directory = msu_owner_watch_inode;
    return 0;
}
