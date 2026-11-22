// SPDX-License-Identifier: GPL-3.0-only
#include <linux/capability.h>
#include <linux/cred.h>
#include <linux/err.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/fs_struct.h>
#include <linux/fsnotify_backend.h>
#include <linux/irqflags.h>
#include <linux/mount.h>
#include <linux/mutex.h>
#include <linux/namei.h>
#include <linux/nsproxy.h>
#include <linux/pid_namespace.h>
#include <linux/preempt.h>
#include <linux/refcount.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/stat.h>
#include <linux/string.h>
#include <linux/user_namespace.h>
#include <linux/version.h>
#include <linux/workqueue.h>
#include "su_nonroot_mount_source.h"
#include "su_install_registry.h"
#include "manager_installation_state.h"

/* Native mount types provide field widths; input BTF supplies every offset.
 * namespace_sem protects this read-only walk; no copied layout or clone IDs. */
#include <fs/mount.h>
#include "manager_dynamic_layout.h"
extern struct rw_semaphore namespace_sem;
#define SOURCE_MAX_NATIVE_MOUNTS 16384U

#define SOURCE_DIRECTORY "/data/adb/maplesu/module-mounts"
#define SOURCE_WATCHES 7
struct source_record {
    char *name;
    u64 mount_id, device, inode;
    u64 parent_id;
    u32 inode_generation;
};
struct source_snapshot {
    refcount_t refs;
    u64 generation;
    maplesu_installation_state_v3 installation;
    u32 count;
    char *bytes;
    struct source_record records[MSU_SU_NONROOT_MOUNT_MAX_ENTRIES];
};
struct source_watch {
    struct fsnotify_mark mark;
    struct msu_su_nonroot_mount_source *source;
    struct file *file;
    unsigned int slot;
    bool active;
};
struct msu_su_nonroot_mount_source {
    raw_spinlock_t lock;
    struct mutex scan;
    const struct cred *boot_cred;
    maplesu_host_instance host;
    struct path root;
    struct nsproxy *global;
    struct source_snapshot *snapshot;
    atomic64_t generation;
    struct work_struct work;
    struct fsnotify_group *group;
    struct source_watch *watches[SOURCE_WATCHES];
    u32 users;
    int error;
    bool closed, dirty;
};
struct source_view {
    struct msu_su_nonroot_mounts mounts;
    struct msu_su_nonroot_mount_source *source;
    struct source_snapshot *snapshot;
    struct nsproxy *child, *parent;
    struct msu_su_nonroot_mount entries[];
};
static bool source_sleepable(void)
{ return in_task() && !in_atomic() && !irqs_disabled(); }
static void snapshot_put(struct source_snapshot *snapshot)
{
    if (snapshot && refcount_dec_and_test(&snapshot->refs)) {
        kvfree(snapshot->bytes); kvfree(snapshot);
    }
}
/* lock held. Saturation closes admission rather than reusing a generation. */
static void invalidate(struct msu_su_nonroot_mount_source *source, int error)
{
    if ((u64)atomic64_read(&source->generation) == ~0ULL) source->closed = true;
    else atomic64_inc(&source->generation);
    source->error = source->closed ? -ESHUTDOWN : error;
}
static bool installation_equal(const maplesu_installation_state_v3 *a,
    const maplesu_installation_state_v3 *b)
{
    return a->record.active && b->record.active && !a->flags && !b->flags &&
        a->host.low == b->host.low && a->host.high == b->host.high &&
        a->device == b->device && a->inode == b->inode && a->revision == b->revision &&
        !memcmp(a->name,b->name,sizeof(a->name)) &&
        !memcmp(a->record.generation,b->record.generation,16);
}
static bool protected_inode(const struct inode *inode, bool directory, bool state)
{
    u32 uid = __kuid_val(MSU_DYN_FIELD(inode, inode, i_uid)), gid = __kgid_val(MSU_DYN_FIELD(inode, inode, i_gid));
    umode_t mode = MSU_DYN_FIELD(inode, inode, i_mode);
    if (!(directory ? S_ISDIR(mode) : S_ISREG(mode))) return false;
    if (state) return uid == 0 && !(mode & (S_IWGRP | S_IWOTH));
    /* Same protected Android ancestor ownership as the existing native reader. */
    return (uid == 0 || uid == 1000) && !(mode & S_IWOTH) &&
        (!(mode & S_IWGRP) || gid == 0 || gid == 1000);
}
/* Each component has a retained path and O_NOFOLLOW, including the final one.
 * O_NONBLOCK prevents opening a substituted FIFO from waiting before type check.
 * Called only on the producer, under the actual factory boot credential. */
static struct file *open_protected(struct msu_su_nonroot_mount_source *source,
    const char *absolute, bool directory, bool state)
{
    struct path walk = source->root;
    struct file *file = NULL;
    const char *start;
    char part[256];
    size_t length;
    bool last;
    int flags;
    if (!absolute || absolute[0] != '/') return ERR_PTR(-EINVAL);
    start = absolute + 1;
    if (!protected_inode(msu_dynamic_d_inode(walk.dentry),true,false)) return ERR_PTR(-EPERM);
    path_get(&walk);
    do {
        length = strcspn(start,"/"); last = !start[length];
        if (!length && start != absolute + 1) { file = ERR_PTR(-EINVAL); break; }
        if (length >= sizeof(part)) { file = ERR_PTR(-ENAMETOOLONG); break; }
        memcpy(part,start,length); part[length] = 0;
        if (!length) strcpy(part,".");
        flags = last && !directory ? O_RDONLY | O_NONBLOCK : O_PATH | O_DIRECTORY;
#if LINUX_VERSION_CODE < KERNEL_VERSION(5,15,0)
        file = file_open_root(walk.dentry,walk.mnt,part,flags | O_NOFOLLOW,0);
#else
        file = file_open_root(&walk,part,flags | O_NOFOLLOW,0);
#endif
        if (IS_ERR(file)) break;
        if (!protected_inode(msu_dynamic_file_inode(file),last ? directory : true,last && state)) {
            fput(file); file = ERR_PTR(-EPERM); break;
        }
        if (last) break;
        path_put(&walk); walk = MSU_DYN_FIELD(file, file, f_path); path_get(&walk); fput(file); file = NULL;
        start += length + 1;
    } while (true);
    path_put(&walk);
    return file;
}
static bool stat_equal(const struct kstat *a, const struct kstat *b)
{
    return a->dev == b->dev && a->ino == b->ino && a->size == b->size &&
        a->mode == b->mode && __kuid_val(a->uid) == __kuid_val(b->uid) &&
        __kgid_val(a->gid) == __kgid_val(b->gid) &&
        a->mtime.tv_sec == b->mtime.tv_sec && a->mtime.tv_nsec == b->mtime.tv_nsec &&
        a->ctime.tv_sec == b->ctime.tv_sec && a->ctime.tv_nsec == b->ctime.tv_nsec;
}
static int read_document(struct file *file, char *bytes, size_t limit, size_t *length)
{
    struct kstat before, after;
    loff_t offset = 0;
    ssize_t got;
    int error = vfs_getattr(&MSU_DYN_FIELD(file, file, f_path),&before,STATX_BASIC_STATS,AT_STATX_SYNC_AS_STAT);
    if (error) return error;
    *length = 0;
    while (*length < limit) {
        got = kernel_read(file,bytes + *length,limit - *length,&offset);
        if (got < 0) return (int)got;
        if (!got) break;
        *length += got;
    }
    if (*length == limit) return -E2BIG;
    error = vfs_getattr(&MSU_DYN_FIELD(file, file, f_path),&after,STATX_BASIC_STATS,AT_STATX_SYNC_AS_STAT);
    if (error) return error;
    if (!stat_equal(&before,&after)) return -EAGAIN;
    bytes[*length] = 0;
    return memchr(bytes,0,*length) ? -EINVAL : 0;
}
static void source_event(struct msu_su_nonroot_mount_source *source)
{
    unsigned long irq;
    raw_spin_lock_irqsave(&source->lock,irq);
    if (!source->closed) {
        invalidate(source,-EAGAIN); source->dirty = true;
        schedule_work(&source->work);
    }
    raw_spin_unlock_irqrestore(&source->lock,irq);
}
static int source_inode_event(struct fsnotify_mark *mark,u32 mask,struct inode *inode,
    struct inode *dir,const struct qstr *name,u32 cookie)
{
    static const char *const children[] = {"data","adb","maplesu","module-mounts"};
    struct source_watch *watch = container_of(mark,struct source_watch,mark);
    const char *child;
    (void)inode; (void)dir; (void)cookie;
    if (!(mask & (FS_MODIFY | FS_CLOSE_WRITE | FS_ATTRIB | FS_CREATE | FS_DELETE |
        FS_MOVE | FS_DELETE_SELF | FS_MOVE_SELF | FS_UNMOUNT))) return 0;
    if (name && !(mask & (FS_DELETE_SELF | FS_MOVE_SELF | FS_UNMOUNT))) {
        if (watch->slot < 4) {
            child = children[watch->slot];
            if (MSU_DYN_FIELD(name, qstr, len) != strlen(child) || memcmp(MSU_DYN_FIELD(name, qstr, name),child,MSU_DYN_FIELD(name, qstr, len))) return 0;
        } else if (watch->slot == 4 &&
            !((MSU_DYN_FIELD(name, qstr, len) == 4 && !memcmp(MSU_DYN_FIELD(name, qstr, name),"boot",4)) ||
              (MSU_DYN_FIELD(name, qstr, len) == 6 && !memcmp(MSU_DYN_FIELD(name, qstr, name),"ledger",6)))) return 0;
    }
    source_event(watch->source);
    return 0;
}
static void source_freeing_mark(struct fsnotify_mark *mark,struct fsnotify_group *group)
{
    struct source_watch *watch = container_of(mark,struct source_watch,mark);
    (void)group;
    WRITE_ONCE(watch->active,false);
    source_event(watch->source);
    fsnotify_put_mark(mark); /* group-owned reference; source holds another */
}
static void source_free_mark(struct fsnotify_mark *mark)
{
    struct source_watch *watch = container_of(mark,struct source_watch,mark);
    fput(watch->file); kfree(watch);
}
static const struct fsnotify_ops source_ops = {
    .handle_inode_event = source_inode_event,
    .freeing_mark = source_freeing_mark,
    .free_mark = source_free_mark,
};
static void drop_watch(struct msu_su_nonroot_mount_source *source,unsigned int slot)
{
    struct source_watch *watch = source->watches[slot];
    if (!watch) return;
    source->watches[slot] = NULL;
    fsnotify_destroy_mark(&watch->mark,source->group);
    fsnotify_put_mark(&watch->mark);
}
static int watch_file(struct msu_su_nonroot_mount_source *source,struct file *file,unsigned int slot)
{
    struct source_watch *watch = source->watches[slot];
    int error;
    if (watch && READ_ONCE(watch->active) && msu_dynamic_file_inode(watch->file) == msu_dynamic_file_inode(file)) return 0;
    drop_watch(source,slot);
    watch = kzalloc(sizeof(*watch),GFP_KERNEL);
    if (!watch) return -ENOMEM;
    watch->source = source; watch->slot = slot; watch->file = msu_dynamic_get_file(file);
    fsnotify_init_mark(&watch->mark,source->group); /* group-owned initial ref */
    watch->mark.mask = FS_MODIFY | FS_CLOSE_WRITE | FS_ATTRIB | FS_CREATE | FS_DELETE |
        FS_MOVE | FS_DELETE_SELF | FS_MOVE_SELF | FS_UNMOUNT | FS_EVENT_ON_CHILD;
    WRITE_ONCE(watch->active,true);
    error = fsnotify_add_inode_mark(&watch->mark,msu_dynamic_file_inode(file),0);
    if (error) { fsnotify_put_mark(&watch->mark); return error; }
    fsnotify_get_mark(&watch->mark); /* independent source slot */
    source->watches[slot] = watch;
    return 0;
}
static int watch_directories(struct msu_su_nonroot_mount_source *source)
{
    static const char *const dirs[] = {"/","/data","/data/adb","/data/adb/maplesu",SOURCE_DIRECTORY};
    struct file *file;
    unsigned int i, j;
    int error;
    for (i = 0; i < ARRAY_SIZE(dirs); ++i) {
        file = open_protected(source,dirs[i],true,i == 4);
        if (IS_ERR(file)) {
            error = PTR_ERR(file);
            for (j = i; j < SOURCE_WATCHES; ++j) drop_watch(source,j);
            return error;
        }
        error = watch_file(source,file,i); fput(file);
        if (error) return error;
    }
    return 0;
}
static bool canonical_name(const char *name)
{
    const char *p;
    size_t length = strlen(name);
    if (length < 2 || length >= PATH_MAX || name[0] != '/' || name[length-1] == '/') return false;
    for (p = name; *p; ++p) {
        if ((unsigned char)*p <= ' ' || *p == '\\') return false;
        if (*p == '/' && (p[1] == '/' || (p[1] == '.' &&
            (!p[2] || p[2] == '/' || (p[2] == '.' && (!p[3] || p[3] == '/')))))) return false;
    }
    return true;
}
static int parse_ledger(struct source_snapshot *snapshot,size_t length)
{
    struct source_record swap;
    char *line = snapshot->bytes, *end = line + length, *p, *name;
    u64 id;
    u32 i;
    while (line < end) {
        id = 0; p = line;
        if (*p < '1' || *p > '9') return -EINVAL;
        while (p < end && *p >= '0' && *p <= '9') {
            if (id > (0x7fffffffU - (u32)(*p-'0')) / 10U) return -EOVERFLOW;
            id = id * 10 + (u32)(*p++-'0');
        }
        if (p == end || *p++ != ' ') return -EINVAL;
        name = p;
        while (p < end && *p != '\n') ++p;
        if (p == end) return -EAGAIN;
        *p++ = 0; line = p;
        if (!canonical_name(name)) return -EINVAL;
        /* A mount ID identifies one same-boot receipt. Collapse only that
         * identical ID/name at its last position; distinct IDs preserve layers. */
        for (i = 0; i < snapshot->count; ++i) if (snapshot->records[i].mount_id == id) break;
        if (i < snapshot->count) {
            if (strcmp(snapshot->records[i].name,name)) return -EINVAL;
            memmove(&snapshot->records[i],&snapshot->records[i+1],
                (snapshot->count-i-1)*sizeof(snapshot->records[0]));
            --snapshot->count;
        }
        if (snapshot->count == MSU_SU_NONROOT_MOUNT_MAX_ENTRIES) return -E2BIG;
        snapshot->records[snapshot->count++] = (struct source_record){.name=name,.mount_id=id};
    }
    for (i = 0; i < snapshot->count/2; ++i) {
        swap = snapshot->records[i];
        snapshot->records[i] = snapshot->records[snapshot->count-i-1];
        snapshot->records[snapshot->count-i-1] = swap;
    }
    /* Exact reverse creation order supports an overmounted parent followed
     * by a formerly hidden descendant. The actual native mount graph below
     * checks that every recorded child precedes its recorded parent. */
    return 0;
}
/* Same native depth-first step as fs/namespace.c next_mnt (6.6/6.18).
 * iterate_mounts walks a collected tree's mnt_list, not an arbitrary live root.
 * Retain real paths under namespace_sem, then stat outside the lock. */
static struct mount *source_next_mount(struct mount *mount,struct mount *root)
{
    struct list_head *next = MSU_DYN_FIELD(mount, mount, mnt_mounts).next;
    if (next == &MSU_DYN_FIELD(mount, mount, mnt_mounts)) {
        for (;;) {
            struct mount *parent;
            if (mount == root) return NULL;
            next = MSU_DYN_FIELD(mount, mount, mnt_child).next;
            parent = MSU_DYN_FIELD(mount, mount, mnt_parent);
            if (next != &MSU_DYN_FIELD(parent, mount, mnt_mounts)) break;
            mount = parent;
        }
    }
    return MSU_DYN_CONTAINER(next, mount, mnt_child);
}
static void source_drop_paths(struct path *paths)
{
    struct path *path;
    for (path = paths; path->mnt; ++path) path_put(path);
    kvfree(paths);
}
static struct path *source_collect_paths(struct msu_su_nonroot_mount_source *source)
{
    struct mount *root = MSU_DYN_CONTAINER(source->root.mnt, mount, mnt), *child, *mount;
    struct list_head *node, *head;
    struct path *paths;
    u32 count = 0;
    int error = 0;
    paths = kvcalloc(SOURCE_MAX_NATIVE_MOUNTS+1U,sizeof(*paths),GFP_KERNEL);
    if (!paths) return ERR_PTR(-ENOMEM);
    down_read(&namespace_sem);
    if (MSU_DYN_FIELD(root, mount, mnt_ns) != MSU_DYN_FIELD(source->global, nsproxy, mnt_ns)) { error = -EXDEV; goto unlock; }
    paths[count] = source->root; path_get(&paths[count++]);
    head = &MSU_DYN_FIELD(root, mount, mnt_mounts);
    list_for_each(node, head) {
        child = MSU_DYN_CONTAINER(node, mount, mnt_child);
        if (!is_subdir(MSU_DYN_FIELD(child, mount, mnt_mountpoint),source->root.dentry)) continue;
        for (mount = child; mount; mount = source_next_mount(mount,child)) {
            if (count == SOURCE_MAX_NATIVE_MOUNTS) { error = -E2BIG; goto unlock; }
            paths[count] = (struct path){.mnt=&MSU_DYN_FIELD(mount, mount, mnt),
                .dentry=MSU_DYN_FIELD(&MSU_DYN_FIELD(mount, mount, mnt), vfsmount, mnt_root)};
            path_get(&paths[count++]);
        }
    }
unlock:
    up_read(&namespace_sem);
    if (error) { source_drop_paths(paths); return ERR_PTR(error); }
    return paths;
}
/* All covered ledger layers have independent real refs on this slow path.
 * None survive publication: the child resolves each layer only when exposed. */
static int capture_targets(struct msu_su_nonroot_mount_source *source,struct source_snapshot *snapshot)
{
    struct path *paths, *path;
    struct kstat stat;
    char *buffer, *name;
    bool *found;
    u32 i;
    u64 mount_id;
    int error = 0;
    buffer = kvmalloc(PATH_MAX,GFP_KERNEL);
    found = kvcalloc(snapshot->count,sizeof(*found),GFP_KERNEL);
    if (!buffer || !found) { error = -ENOMEM; goto free; }
    paths = source_collect_paths(source);
    if (IS_ERR(paths)) { error = PTR_ERR(paths); goto free; }
    for (path = paths; path->mnt; ++path) {
        mount_id = (u64)MSU_DYN_FIELD(MSU_DYN_CONTAINER(path->mnt, mount, mnt), mount, mnt_id);
        for (i = 0; i < snapshot->count; ++i)
            if (mount_id == snapshot->records[i].mount_id) break;
        if (i == snapshot->count) continue;
        if (found[i] || path->dentry != MSU_DYN_FIELD(path->mnt, vfsmount, mnt_root)) {
            error = -ESTALE; break;
        }
        name = __d_path(path,&source->root,buffer,PATH_MAX);
        if (IS_ERR(name)) { error = PTR_ERR(name); break; }
        if (!name || strcmp(name,snapshot->records[i].name)) { error = -ESTALE; break; }
        error = vfs_getattr(path,&stat,STATX_BASIC_STATS,AT_STATX_SYNC_AS_STAT);
        if (error) break;
        snapshot->records[i].device = stat.dev;
        snapshot->records[i].inode = stat.ino;
        snapshot->records[i].inode_generation = MSU_DYN_FIELD(msu_dynamic_d_inode(path->dentry), inode, i_generation);
        found[i] = true;
    }
    if (!error) for (i = 0; i < snapshot->count; ++i)
        if (!found[i]) { error = -ESTALE; break; }
    source_drop_paths(paths);
free:
    kvfree(buffer); kvfree(found);
    return error;
}
/* Match EVERY real ID/name, including lower overmounted layers. /proc retains
 * native parent IDs so reverse action order can be checked without clone IDs. */
static int check_mountinfo(struct msu_su_nonroot_mount_source *source,
    struct source_snapshot *snapshot)
{
    struct file *file;
    char *bytes, *line, *end, *p, *field = NULL, *newline;
    bool *found;
    u64 id, parent;
    size_t length;
    u32 column, i, j;
    int error;
    file = open_protected(source,"/proc/1/mountinfo",false,true);
    if (IS_ERR(file)) return PTR_ERR(file);
    bytes = kvmalloc(1024U*1024U+1U,GFP_KERNEL);
    found = kvcalloc(snapshot->count,sizeof(*found),GFP_KERNEL);
    if (!bytes || !found) { error = -ENOMEM; goto out; }
    error = read_document(file,bytes,1024U*1024U,&length);
    if (error) goto out;
    line = bytes; end = bytes+length;
    while (line < end) {
        newline = memchr(line,'\n',end-line);
        if (!newline) { error = -EAGAIN; goto out; }
        *newline = 0; p = line; id = 0; parent = 0;
        for (column = 0; column < 2; ++column) {
            u64 value = 0;
            if (*p < '1' || *p > '9') { error = -EINVAL; goto out; }
            while (*p >= '0' && *p <= '9') {
                if (value > (0x7fffffffU-(u32)(*p-'0'))/10U) { error = -EOVERFLOW; goto out; }
                value = value*10+(u32)(*p++-'0');
            }
            if (*p++ != ' ') { error = -EINVAL; goto out; }
            if (!column) id = value; else parent = value;
        }
        for (column = 2; column < 5; ++column) {
            field = p; while (*p && *p != ' ') ++p;
            if (*p != ' ') { error = -EINVAL; goto out; }
            *p++ = 0;
        }
        for (i = 0; i < snapshot->count; ++i) if (snapshot->records[i].mount_id == id) {
            if (found[i] || strcmp(snapshot->records[i].name,field) ||
                (snapshot->records[i].parent_id && snapshot->records[i].parent_id != parent)) {
                error = -ESTALE; goto out;
            }
            snapshot->records[i].parent_id = parent; found[i] = true; break;
        }
        line = newline+1;
    }
    for (i = 0; i < snapshot->count; ++i) {
        if (!found[i]) { error = -ESTALE; goto out; }
        for (j = 0; j < i; ++j)
            if (snapshot->records[i].parent_id == snapshot->records[j].mount_id) {
                error = -EINVAL; goto out;
            }
    }
out:
    kvfree(bytes); kvfree(found); fput(file);
    return error;
}
/* The constructor may precede Android's switch_root. Resolve the real PID1
 * root again on each slow refresh; take never reads it or performs file I/O. */
static int refresh_root(struct msu_su_nonroot_mount_source *source)
{
    struct task_struct *init;
    struct path root = {0};
    int error = -ENOENT;
    rcu_read_lock(); init = find_task_by_pid_ns(1,&init_pid_ns);
    if (init) msu_dynamic_get_task_struct(init);
    rcu_read_unlock();
    if (!init) return error;
    msu_dynamic_task_lock(init);
    if (MSU_DYN_FIELD(init, task_struct, fs) && MSU_DYN_FIELD(init, task_struct, nsproxy) && MSU_DYN_FIELD(MSU_DYN_FIELD(init, task_struct, nsproxy), nsproxy, mnt_ns) == MSU_DYN_FIELD(source->global, nsproxy, mnt_ns)) {
        msu_dynamic_get_fs_root(MSU_DYN_FIELD(init, task_struct, fs),&root); error = 0;
    }
    msu_dynamic_task_unlock(init); msu_dynamic_put_task_struct(init);
    if (error) return error;
    if (!protected_inode(msu_dynamic_d_inode(root.dentry),true,false)) { path_put(&root); return -EPERM; }
    path_put(&source->root); source->root = root;
    return 0;
}
static int capture(struct msu_su_nonroot_mount_source *source,struct source_snapshot *snapshot)
{
    struct file *boot = NULL, *ledger = NULL, *actual = NULL, *check;
    maplesu_installation_state_v3 after;
    struct kstat before, final;
    char stored[39], running[39];
    size_t a, b, length;
    int error = refresh_root(source);
    if (error) return error;
    error = watch_directories(source);
    if (error == -ENOENT) return 0; /* nearest existing ancestor is watched */
    if (error) return error;
    ledger = open_protected(source,SOURCE_DIRECTORY "/ledger",false,true);
    if (IS_ERR(ledger)) {
        error = PTR_ERR(ledger); ledger = NULL;
        if (error == -ENOENT) { drop_watch(source,6); return 0; }
        return error;
    }
    error = watch_file(source,ledger,6);
    if (error) goto out;
    snapshot->bytes = kvmalloc(MSU_SU_NONROOT_MOUNT_MAX_BYTES+1U,GFP_KERNEL);
    if (!snapshot->bytes) { error = -ENOMEM; goto out; }
    error = vfs_getattr(&MSU_DYN_FIELD(ledger, file, f_path),&before,STATX_BASIC_STATS,AT_STATX_SYNC_AS_STAT);
    if (!error) error = read_document(ledger,snapshot->bytes,MSU_SU_NONROOT_MOUNT_MAX_BYTES+1U,&length);
    if (!error) error = parse_ledger(snapshot,length);
    if (!error && atomic_read(&MSU_DYN_FIELD(msu_dynamic_file_inode(ledger), inode, i_writecount)) > 0) error = -EAGAIN;
    if (error || !snapshot->count) goto out; /* no boot/installation prerequisite for empty table */
    boot = open_protected(source,SOURCE_DIRECTORY "/boot",false,true);
    if (IS_ERR(boot)) { error = PTR_ERR(boot); boot = NULL; goto out; }
    error = watch_file(source,boot,5);
    if (error) goto out;
    actual = open_protected(source,"/proc/sys/kernel/random/boot_id",false,true);
    if (IS_ERR(actual)) { error = PTR_ERR(actual); actual = NULL; goto out; }
    error = read_document(boot,stored,sizeof(stored)-1,&a);
    if (!error) error = read_document(actual,running,sizeof(running)-1,&b);
    if (error) goto out;
    if (a != 37 || b != a || stored[36] != '\n' || memcmp(stored,running,a)) {
        error = -ESTALE; goto out;
    }
    error = msu_installation_read(&snapshot->installation);
    if (error) goto out;
    if (!snapshot->installation.record.active || snapshot->installation.flags ||
        snapshot->installation.host.low != source->host.low ||
        snapshot->installation.host.high != source->host.high) {
        error = snapshot->installation.flags & MAPLESU_INSTALLATION_PENDING ? -EINPROGRESS : -ESTALE;
        goto out;
    }
    error = check_mountinfo(source,snapshot);
    if (!error) error = capture_targets(source,snapshot);
    if (!error) error = check_mountinfo(source,snapshot);
    if (!error) error = msu_installation_read(&after);
    if (!error && !installation_equal(&snapshot->installation,&after))
        error = after.flags & MAPLESU_INSTALLATION_PENDING ? -EINPROGRESS : -ESTALE;
    if (error) goto out;
    check = open_protected(source,SOURCE_DIRECTORY "/ledger",false,true);
    if (IS_ERR(check)) { error = PTR_ERR(check); goto out; }
    error = vfs_getattr(&MSU_DYN_FIELD(check, file, f_path),&final,STATX_BASIC_STATS,AT_STATX_SYNC_AS_STAT);
    if (!error && (MSU_DYN_FIELD(check, file, f_path).mnt != MSU_DYN_FIELD(ledger, file, f_path).mnt ||
        MSU_DYN_FIELD(check, file, f_path).dentry != MSU_DYN_FIELD(ledger, file, f_path).dentry || !stat_equal(&before,&final) ||
        atomic_read(&MSU_DYN_FIELD(msu_dynamic_file_inode(ledger), inode, i_writecount)) > 0)) error = -EAGAIN;
    fput(check);
out:
    if (actual) fput(actual);
    if (boot) fput(boot);
    if (ledger) fput(ledger);
    return error;
}
int msu_su_nonroot_mount_source_refresh(struct msu_su_nonroot_mount_source *source)
{
    struct source_snapshot *fresh, *old = NULL;
    const struct cred *saved;
    unsigned long irq;
    u64 generation;
    int error;
    if (!source) return -EINVAL;
    if (!source_sleepable()) return -EWOULDBLOCK;
    if (!mutex_trylock(&source->scan)) return -EINPROGRESS;
    raw_spin_lock_irqsave(&source->lock,irq);
    if (source->closed) { raw_spin_unlock_irqrestore(&source->lock,irq); error = -ESHUTDOWN; goto unlock; }
    invalidate(source,-EINPROGRESS); source->dirty = false;
    generation = (u64)atomic64_read(&source->generation);
    raw_spin_unlock_irqrestore(&source->lock,irq);
    fresh = kvzalloc(sizeof(*fresh),GFP_KERNEL);
    if (!fresh) { error = -ENOMEM; goto publish_error; }
    refcount_set(&fresh->refs,1); fresh->generation = generation;
    saved = override_creds(source->boot_cred);
    error = capture(source,fresh);
    revert_creds(saved);
    raw_spin_lock_irqsave(&source->lock,irq);
    if (source->closed) { if (!error) error = -ESHUTDOWN; }
    else if ((u64)atomic64_read(&source->generation) != generation) { if (!error) error = -EAGAIN; }
    else {
        source->error = error;
        if (!error) { old = source->snapshot; source->snapshot = fresh; fresh = NULL; }
    }
    raw_spin_unlock_irqrestore(&source->lock,irq);
    snapshot_put(old); snapshot_put(fresh);
    goto unlock;
publish_error:
    raw_spin_lock_irqsave(&source->lock,irq);
    if (!source->closed && (u64)atomic64_read(&source->generation) == generation) source->error = error;
    raw_spin_unlock_irqrestore(&source->lock,irq);
unlock:
    mutex_unlock(&source->scan);
    /* Only an actual event missed by a contending worker requests another run. */
    raw_spin_lock_irqsave(&source->lock,irq);
    if (!source->closed && source->dirty) schedule_work(&source->work);
    raw_spin_unlock_irqrestore(&source->lock,irq);
    return error;
}
static void source_work(struct work_struct *work)
{
    struct msu_su_nonroot_mount_source *source = container_of(work,struct msu_su_nonroot_mount_source,work);
    msu_su_nonroot_mount_source_refresh(source);
}
int msu_su_nonroot_mount_source_create(const maplesu_host_instance *host,
    const struct cred *boot_cred,struct msu_su_nonroot_mount_source **output)
{
    struct msu_su_nonroot_mount_source *source;
    struct source_snapshot *snapshot;
    struct task_struct *init;
    int error = -ENOENT;
    if (!output) return -EINVAL;
    *output = NULL;
    if (!msu_runtime_layout_ready()) return -EAGAIN;
    if (!source_sleepable()) return -EWOULDBLOCK;
    if (!host || !(host->low | host->high) || !boot_cred ||
        MSU_DYN_FIELD(boot_cred, cred, user_ns) != &init_user_ns || __kuid_val(MSU_DYN_FIELD(boot_cred, cred, uid)) ||
        __kuid_val(MSU_DYN_FIELD(boot_cred, cred, euid)) || __kuid_val(MSU_DYN_FIELD(boot_cred, cred, fsuid)) ||
        !cap_raised(MSU_DYN_FIELD(boot_cred, cred, cap_effective),CAP_SYS_ADMIN)) return -EPERM;
#if defined(MSU_INIT_BRIDGE_HOST_IMPORTS) && defined(MSU_SU_NONROOT_NATIVE)
    /* Optional MODULE imports may be absent without blocking ordinary SU. */
    if (!msu_native_namespace_sem || !msu_native___d_path) return -EOPNOTSUPP;
#endif
    source = kzalloc(sizeof(*source),GFP_KERNEL);
    snapshot = kvzalloc(sizeof(*snapshot),GFP_KERNEL);
    if (!source || !snapshot) { kfree(source); kvfree(snapshot); return -ENOMEM; }
    raw_spin_lock_init(&source->lock); mutex_init(&source->scan);
    INIT_WORK(&source->work,source_work); atomic64_set(&source->generation,1);
    source->host = *host; source->boot_cred = msu_dynamic_get_cred(boot_cred);
    refcount_set(&snapshot->refs,1); snapshot->generation = 1; source->snapshot = snapshot;
    rcu_read_lock(); init = find_task_by_pid_ns(1,&init_pid_ns);
    if (init) msu_dynamic_get_task_struct(init);
    rcu_read_unlock();
    if (!init) goto fail;
    msu_dynamic_task_lock(init);
    if (MSU_DYN_FIELD(init, task_struct, fs) && MSU_DYN_FIELD(init, task_struct, nsproxy) && MSU_DYN_FIELD(MSU_DYN_FIELD(init, task_struct, nsproxy), nsproxy, mnt_ns)) {
        msu_dynamic_get_fs_root(MSU_DYN_FIELD(init, task_struct, fs),&source->root);
        source->global = MSU_DYN_FIELD(init, task_struct, nsproxy); msu_dynamic_get_nsproxy(source->global); error = 0;
    }
    msu_dynamic_task_unlock(init); msu_dynamic_put_task_struct(init);
    if (error) goto fail;
    if (!protected_inode(msu_dynamic_d_inode(source->root.dentry),true,false)) { error = -EPERM; goto fail; }
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6,0,0)
    source->group = fsnotify_alloc_group(&source_ops,0);
#else
    source->group = fsnotify_alloc_group(&source_ops);
#endif
    if (IS_ERR(source->group)) { error = PTR_ERR(source->group); source->group = NULL; goto fail; }
    *output = source;
    return 0;
fail:
    if (source->root.mnt) path_put(&source->root);
    if (source->global) msu_dynamic_put_nsproxy(source->global);
    msu_dynamic_put_cred(source->boot_cred); snapshot_put(snapshot); kfree(source);
    return error;
}
void msu_su_nonroot_mount_source_put(struct msu_su_nonroot_mount_source *source,
    struct msu_su_nonroot_mounts *mounts)
{
    struct source_view *view;
    unsigned long irq;
    u32 i;
    if (!mounts) return;
    view = container_of(mounts,struct source_view,mounts);
    /* A successful take is paired with the same retained factory owner. */
    if (source != view->source) return;
    for (i = 0; i < mounts->count; ++i) if (view->entries[i].path.mnt) path_put(&view->entries[i].path);
    if (view->child) msu_dynamic_put_nsproxy(view->child);
    if (view->parent) msu_dynamic_put_nsproxy(view->parent);
    snapshot_put(view->snapshot);
    kvfree(view);
    raw_spin_lock_irqsave(&source->lock,irq); --source->users;
    raw_spin_unlock_irqrestore(&source->lock,irq);
}
int msu_su_nonroot_mount_source_take(struct msu_su_nonroot_mount_source *source,
    struct msu_su_registry *registry,struct msu_su_nonroot_mounts **output)
{
    struct source_snapshot *snapshot;
    struct source_view *view;
    struct task_struct *parent;
    const struct cred *cred;
    maplesu_installation_state_v3 installation;
    enum msu_su_non_root_umount_policy policy;
    unsigned long irq;
    u32 uid, i;
    bool skip;
    int error;
    if (!output || !registry) return -EINVAL;
    *output = NULL;
    if (!msu_runtime_layout_ready()) return -EAGAIN;
    if (!source_sleepable()) return -EWOULDBLOCK;
    cred = msu_dynamic_current_real_cred();
    if (!cred || msu_dynamic_current_cred() != cred || MSU_DYN_FIELD(cred, cred, user_ns) != &init_user_ns ||
        __kuid_val(MSU_DYN_FIELD(cred, cred, uid)) != __kuid_val(MSU_DYN_FIELD(cred, cred, euid))) return -EPERM;
    uid = __kuid_val(MSU_DYN_FIELD(cred, cred, uid));
    error = msu_su_registry_non_root_policy(registry,uid,&policy);
    if (error || policy != MSU_SU_NON_ROOT_UMOUNT_ENABLED) return error;
    error = msu_su_registry_non_root_skip_manager(registry,&skip);
    if (error || skip) return error;
    if (!source) return -ENODATA;
    raw_spin_lock_irqsave(&source->lock,irq);
    error = source->closed ? -ESHUTDOWN : source->error;
    snapshot = source->snapshot;
    if (!error && snapshot->generation != (u64)atomic64_read(&source->generation)) error = -ESTALE;
    if (!error && !snapshot->count) { raw_spin_unlock_irqrestore(&source->lock,irq); return 0; }
    if (!error && source->users == ~0U) error = -EOVERFLOW;
    if (!error) { ++source->users; refcount_inc(&snapshot->refs); }
    raw_spin_unlock_irqrestore(&source->lock,irq);
    if (error) return error;
    view = kvzalloc(struct_size(view,entries,snapshot->count),GFP_KERNEL);
    if (!view) {
        snapshot_put(snapshot);
        raw_spin_lock_irqsave(&source->lock,irq); --source->users;
        raw_spin_unlock_irqrestore(&source->lock,irq); return -ENOMEM;
    }
    view->source = source; view->snapshot = snapshot;
    view->mounts = (struct msu_su_nonroot_mounts){.registry=registry,.installation=snapshot->installation,
        .live_generation=&source->generation,.generation=snapshot->generation,.full_uid=uid,
        .classification=MSU_SU_NONROOT_APP,.cred=source->boot_cred,.entries=view->entries,.count=snapshot->count};
    msu_dynamic_task_lock(current);
    view->child = MSU_DYN_FIELD(current, task_struct, nsproxy);
    if (view->child) msu_dynamic_get_nsproxy(view->child);
    msu_dynamic_task_unlock(current);
    rcu_read_lock(); parent = rcu_dereference(MSU_DYN_FIELD(current, task_struct, real_parent)); msu_dynamic_get_task_struct(parent); rcu_read_unlock();
    msu_dynamic_task_lock(parent); view->parent = MSU_DYN_FIELD(parent, task_struct, nsproxy);
    if (view->parent) msu_dynamic_get_nsproxy(view->parent);
    msu_dynamic_task_unlock(parent); msu_dynamic_put_task_struct(parent);
    if (!view->child || !view->parent || !MSU_DYN_FIELD(view->child, nsproxy, mnt_ns) || !MSU_DYN_FIELD(view->parent, nsproxy, mnt_ns) ||
        MSU_DYN_FIELD(view->child, nsproxy, mnt_ns) == MSU_DYN_FIELD(view->parent, nsproxy, mnt_ns) ||
        MSU_DYN_FIELD(view->child, nsproxy, mnt_ns) == MSU_DYN_FIELD(source->global, nsproxy, mnt_ns) ||
        MSU_DYN_FIELD(view->child, nsproxy, mnt_ns) == MSU_DYN_FIELD(&init_nsproxy, nsproxy, mnt_ns)) { error = -EXDEV; goto fail; }
    view->mounts.mnt_ns = MSU_DYN_FIELD(view->child, nsproxy, mnt_ns);
    view->mounts.zygote_ns = MSU_DYN_FIELD(view->parent, nsproxy, mnt_ns); view->mounts.global_ns = MSU_DYN_FIELD(source->global, nsproxy, mnt_ns);
    error = msu_installation_read(&installation);
    if (!error && !installation_equal(&snapshot->installation,&installation))
        error = installation.flags & MAPLESU_INSTALLATION_PENDING ? -EINPROGRESS : -ESTALE;
    if (error) goto fail;
    /* Publish immutable layer metadata only. Action resolves exactly one
     * current child layer after its predecessor was consumed. No top-ref copies. */
    for (i = 0; i < snapshot->count; ++i) {
        const struct source_record *record = &snapshot->records[i];
        view->entries[i] = (struct msu_su_nonroot_mount){.name=record->name,.flags=MNT_DETACH,
            .device=record->device,.inode=record->inode,.inode_generation=record->inode_generation};
    }
    if (!error && (msu_dynamic_current_real_cred() != cred || msu_dynamic_current_cred() != cred ||
        MSU_DYN_FIELD(current, task_struct, nsproxy) != view->child || (MSU_DYN_FIELD(current, task_struct, flags) & PF_EXITING) ||
        (u64)atomic64_read(&source->generation) != snapshot->generation)) error = -ESTALE;
    if (error) goto fail;
    *output = &view->mounts;
    return 0;
fail:
    msu_su_nonroot_mount_source_put(source,&view->mounts);
    return error;
}
void msu_su_nonroot_mount_source_close(struct msu_su_nonroot_mount_source *source)
{
    unsigned long irq;
    if (!source) return;
    raw_spin_lock_irqsave(&source->lock,irq);
    if (!source->closed) { source->closed = true; invalidate(source,-ESHUTDOWN); }
    raw_spin_unlock_irqrestore(&source->lock,irq);
}
int msu_su_nonroot_mount_source_quiesce(struct msu_su_nonroot_mount_source *source)
{
    unsigned long irq;
    u32 users;
    unsigned int i;
    if (!source) return 0;
    if (!source_sleepable()) return -EWOULDBLOCK;
    msu_su_nonroot_mount_source_close(source);
    if (!mutex_trylock(&source->scan)) return -EINPROGRESS;
    if (source->group) {
        for (i = 0; i < SOURCE_WATCHES; ++i) drop_watch(source,i);
        fsnotify_destroy_group(source->group); source->group = NULL;
        fsnotify_wait_marks_destroyed();
    }
    cancel_work(&source->work);
    raw_spin_lock_irqsave(&source->lock,irq); users = source->users;
    raw_spin_unlock_irqrestore(&source->lock,irq);
    mutex_unlock(&source->scan);
    return users || work_busy(&source->work) ? -EINPROGRESS : 0;
}
int msu_su_nonroot_mount_source_destroy(struct msu_su_nonroot_mount_source **owner)
{
    struct msu_su_nonroot_mount_source *source;
    int error;
    if (!owner) return -EINVAL;
    source = *owner;
    if (!source) return 0;
    error = msu_su_nonroot_mount_source_quiesce(source);
    if (error) return error;
    snapshot_put(source->snapshot); msu_dynamic_put_cred(source->boot_cred);
    path_put(&source->root); msu_dynamic_put_nsproxy(source->global);
    kfree(source); *owner = NULL;
    return 0;
}
