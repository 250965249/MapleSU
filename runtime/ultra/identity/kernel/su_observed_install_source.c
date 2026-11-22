// SPDX-License-Identifier: GPL-3.0-only
#if __has_include(<crypto/sha2.h>)
#include <crypto/sha2.h>
#else
#include <crypto/sha.h>
#endif
#include <linux/err.h>
#include <linux/errno.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/fsnotify_backend.h>
#include <linux/kernel.h>
#include <linux/kref.h>
#include <linux/mm.h>
#include <linux/mutex.h>
#include <linux/random.h>
#include <linux/slab.h>
#include <linux/sort.h>
#include <linux/string.h>
#include <linux/version.h>
#include <linux/workqueue.h>
#include "install_records.h"
#include "protected_install_kernel.h"
#include "su_observed_install_source.h"
#include "su_profile_execution.h"
#include "manager_dynamic_layout.h"

struct msu_observed_document { struct file *file; void *bytes; size_t length; struct kstat stat; const char *path; };
struct msu_observed_member {
    struct msu_su_install_member name;
    char apk_path[MSU_RECORD_PATH];
    struct file *apk;
    struct kstat stat;
    struct msu_observed_record_identity identity;
    int identity_error;
};
struct msu_observed_pin {
    struct kref refs;
    u32 full_uid, count;
    u8 id[MSU_SU_INSTALL_ID_BYTES];
    struct msu_su_install_member names[MSU_SU_INSTALL_MAX_MEMBERS];
    struct msu_observed_member members[];
};
struct msu_observed_uid { u32 uid; struct msu_observed_pin *pin;
    struct msu_su_saved_grant *grant; int error; bool dirty; };
struct msu_observed_mark {
    struct fsnotify_mark mark;
    struct msu_observed_mark *next;
    struct msu_su_observed_provider *provider;
    struct file *directory;
    u32 user;
    u32 kind;
    bool active;
    char path[128], child[32];
};
struct msu_su_observed_provider {
    struct mutex operation, scan;
    struct msu_su_observed_authority authority;
    struct msu_su_registry *registry;
    struct fsnotify_group *group;
    struct msu_observed_mark *marks;
    struct delayed_work work;
    struct msu_observed_uid uids[MSU_SU_REGISTRY_MAX_UIDS];
    u32 count;
    u64 candidate;
    struct msu_su_observed_publication_receipt publication;
    int last_error;
    bool closed, started, uncertain, marks_detached;
    atomic_t authority_dirty;
};
static void msu_observed_scan_work(struct work_struct *work);
int msu_observed_inode_event(struct fsnotify_mark *mark,u32 mask,struct inode *inode,
    struct inode *dir,const struct qstr *name,u32 cookie);
void msu_observed_free_mark(struct fsnotify_mark *mark);
void msu_observed_freeing_mark(struct fsnotify_mark *mark,struct fsnotify_group *group);
static void msu_observed_pin_free(struct kref *ref)
{
    struct msu_observed_pin *pin = container_of(ref, struct msu_observed_pin, refs);
    u32 i;
    for (i = 0; i < MSU_SU_INSTALL_MAX_MEMBERS; ++i)
        if (pin->members[i].apk) fput(pin->members[i].apk);
    kvfree(pin);
}
static void msu_observed_put(struct msu_observed_pin *pin)
{ if (pin) kref_put(&pin->refs, msu_observed_pin_free); }
static bool msu_observed_stat_equal(const struct kstat *a, const struct kstat *b)
{
    return a->ino == b->ino && a->dev == b->dev && a->size == b->size &&
        a->nlink == b->nlink && a->mode == b->mode && uid_eq(a->uid,b->uid) &&
        gid_eq(a->gid,b->gid) && timespec64_equal(&a->mtime,&b->mtime) &&
        timespec64_equal(&a->ctime,&b->ctime);
}
static void msu_observed_drop_document(struct msu_observed_document *document)
{
    if (document->file) fput(document->file);
    kvfree(document->bytes);
    memset(document, 0, sizeof(*document));
}
static int msu_observed_document(const char *const *paths, u32 count, bool optional,
    struct msu_observed_document *document)
{
    u32 i;
    int error = -ENOENT;
    memset(document,0,sizeof(*document));
    for (i = 0; i < count; ++i) {
        error = msu_kernel_read_protected_document(paths[i],MSU_RECORD_LIMIT,
            &document->file,&document->bytes,&document->length,&document->stat);
        if (error != -ENOENT) { if (!error) document->path = paths[i]; return error; }
    }
    return optional && error == -ENOENT ? 0 : error;
}
static int msu_observed_member_compare(const void *a, const void *b)
{ return strcmp(((const struct msu_observed_member *)a)->name.package,
    ((const struct msu_observed_member *)b)->name.package); }
/* Parse exactly the protected packages.list columns KSU uses, with bounded
 * names/UIDs and the complete same-appId member set instead of one package. */
static int msu_observed_members(struct msu_observed_document *document, u32 uid,
    struct msu_observed_pin *pin)
{
    const u8 *bytes = document->bytes;
    size_t position = 0, begin, end, split, number;
    u32 id, digit;
    while (position < document->length) {
        begin = position;
        while (position < document->length && bytes[position] != '\n') {
            if (!bytes[position] || bytes[position] == '\r') return -EBADMSG;
            ++position;
        }
        end = position;
        if (position < document->length) ++position;
        split = begin;
        while (split < end && bytes[split] != ' ') ++split;
        if (split == begin || split - begin >= 256 || split == end) return -EBADMSG;
        number = split + 1; id = 0;
        if (number == end || bytes[number] == ' ') return -EBADMSG;
        while (number < end && bytes[number] != ' ') {
            digit = bytes[number++] - '0';
            if (digit > 9 || id > (0x7fffffffU - digit) / 10) return -EBADMSG;
            id = id * 10 + digit;
        }
        if (number == end) return -EBADMSG;
        if (id != uid % 100000U) continue;
        if (pin->count == MSU_SU_INSTALL_MAX_MEMBERS) return -E2BIG;
        memcpy(pin->members[pin->count].name.package,bytes + begin,split - begin);
        ++pin->count;
    }
    sort(pin->members,pin->count,sizeof(pin->members[0]),msu_observed_member_compare,NULL);
    for (id = 1; id < pin->count; ++id)
        if (!strcmp(pin->members[id-1].name.package,pin->members[id].name.package)) return -EBADMSG;
    return 0;
}
static int msu_observed_sha256(const void *bytes,size_t length,u8 digest[32])
{
    if (length > 0xffffffffU) return -EOVERFLOW;
    sha256(bytes,(unsigned int)length,digest); return 0;
}
static int msu_observed_capture(u32 uid, struct msu_observed_pin **output)
{
    static const char *const list_paths[] = {"/data/system/packages.list"};
    static const char *const global_paths[] = {"/data/system/packages-backup.xml",
        "/data/system/packages.xml","/data/system/packages.xml.reservecopy"};
    struct msu_observed_document docs[3] = {0};
    struct msu_record_workspace *workspace = NULL;
    struct msu_observed_identity_workspace *identity_workspace = NULL;
    struct msu_observed_pin *pin = NULL;
    struct msu_install_record *record = NULL;
    struct msu_record_bytes data[3];
    char userdir[80],backup[128],main[128],reserve[128];
    const char *user_paths[] = {backup,main,reserve};
    struct kstat after;
    struct file *check = NULL;
    u32 i, kept = 0;
    int error;
    *output = NULL;
    pin = kvzalloc(sizeof(*pin) + sizeof(pin->members[0]) * MSU_SU_INSTALL_MAX_MEMBERS,GFP_KERNEL);
    workspace = kvzalloc(sizeof(*workspace),GFP_KERNEL);
    record = kzalloc(sizeof(*record),GFP_KERNEL);
    identity_workspace = kvzalloc(sizeof(*identity_workspace),GFP_KERNEL);
    if (pin) kref_init(&pin->refs);
    if (!pin || !workspace || !record || !identity_workspace) { error = -ENOMEM; goto out; }
    pin->full_uid = uid;
    error = msu_observed_document(list_paths,1,false,&docs[0]);
    if (error) goto out;
    error = msu_observed_document(global_paths,3,false,&docs[1]);
    if (error) goto out;
    snprintf(userdir,sizeof(userdir),"/data/system/users/%u",uid / 100000U);
    error = msu_kernel_stat_protected_path(userdir,true,&check,&after);
    if (error) goto out;
    fput(check); check = NULL;
    snprintf(backup,sizeof(backup),"%s/package-restrictions-backup.xml",userdir);
    snprintf(main,sizeof(main),"%s/package-restrictions.xml",userdir);
    snprintf(reserve,sizeof(reserve),"%s/package-restrictions.xml.reservecopy",userdir);
    error = msu_observed_document(user_paths,3,true,&docs[2]);
    if (error) goto out;
    error = msu_observed_members(&docs[0],uid,pin);
    if (error) goto out;
    for (i = 0; i < 3; ++i) { data[i].data = docs[i].bytes; data[i].length = docs[i].length; }
    for (i = 0; i < pin->count; ++i) {
        error = msu_read_observed_install_records(data[0],data[1],data[2],uid,
            pin->members[i].name.package,workspace,record);
        if (error == -3) continue; /* Explicitly uninstalled for this user. */
        if (error) { error = -EBADMSG; goto out; }
        if (kept != i) pin->members[kept].name = pin->members[i].name;
        memcpy(pin->members[kept].apk_path,record->apk_path,sizeof(record->apk_path));
        error = msu_kernel_stat_protected_path(record->apk_path,false,
            &pin->members[kept].apk,&pin->members[kept].stat);
        if (error) goto out;
        pin->members[kept].identity_error = msu_read_observed_record_identity(data[1],data[2],
            uid % 100000U,pin->members[kept].name.package,identity_workspace,
            msu_observed_sha256,&pin->members[kept].identity);
        pin->names[kept] = pin->members[kept].name;
        ++kept;
    }
    pin->count = kept;
    for (i = 0; i < kept; ++i) {
        error = msu_kernel_stat_protected_path(pin->members[i].apk_path,false,&check,&after);
        if (error || msu_dynamic_file_inode(check) != msu_dynamic_file_inode(pin->members[i].apk) ||
            !msu_observed_stat_equal(&pin->members[i].stat,&after)) {
            if (!error) error = -EAGAIN;
            goto out;
        }
        fput(check); check = NULL;
    }
    /* Re-resolve each selected document to detect replacement/partial scans.
     * Unrelated package changes never become part of an app's identity. */
    for (i = 0; i < 3; ++i) {
        if (!docs[i].file) continue;
        error = msu_kernel_stat_protected_path(docs[i].path,false,&check,&after);
        if (error || msu_dynamic_file_inode(check) != msu_dynamic_file_inode(docs[i].file) ||
            !msu_observed_stat_equal(&docs[i].stat,&after)) {
            if (!error) error = -EAGAIN;
            goto out;
        }
        fput(check); check = NULL;
    }
    get_random_bytes(pin->id,sizeof(pin->id));
    if (!memchr_inv(pin->id,0,sizeof(pin->id))) { error = -EIO; goto out; }
    *output = pin; pin = NULL; error = 0;
out:
    if (check) fput(check);
    if (pin) msu_observed_put(pin);
    for (i = 0; i < 3; ++i) msu_observed_drop_document(&docs[i]);
    kvfree(workspace); kvfree(identity_workspace); kfree(record);
    return error;
}
static bool msu_observed_same(const struct msu_observed_pin *a,const struct msu_observed_pin *b)
{
    u32 i;
    if (!a || !b || a->full_uid != b->full_uid || a->count != b->count) return false;
    for (i = 0; i < a->count; ++i)
        if (strcmp(a->members[i].name.package,b->members[i].name.package) ||
            strcmp(a->members[i].apk_path,b->members[i].apk_path) ||
            msu_dynamic_file_inode(a->members[i].apk) != msu_dynamic_file_inode(b->members[i].apk) ||
            !msu_observed_stat_equal(&a->members[i].stat,&b->members[i].stat) ||
            a->members[i].identity_error != b->members[i].identity_error ||
            memcmp(&a->members[i].identity,&b->members[i].identity,sizeof(a->members[i].identity))) return false;
    return true;
}
int msu_su_observed_match_saved_member(const struct msu_su_verified_install *installation,
    const char *package,u64 first_install_ms,const u8 (*signers)[32],u32 signer_count)
{
    const struct msu_observed_pin *pin;
    const struct msu_observed_member *member = NULL;
    u32 i,j;
    if (!installation || !installation->pin || !package || !first_install_ms ||
        !signers || !signer_count || signer_count > MSU_OBSERVED_SIGNERS) return -EINVAL;
    pin = installation->pin;
    if (pin->full_uid != installation->full_uid ||
        memcmp(pin->id,installation->installation_id,sizeof(pin->id))) return -ESTALE;
    for (i = 0; i < pin->count; ++i)
        if (!strcmp(pin->members[i].name.package,package)) { member = &pin->members[i]; break; }
    if (!member) return -ENOENT;
    if (member->identity_error) return -EOPNOTSUPP;
    if (first_install_ms != member->identity.first_install_ms ||
        signer_count != member->identity.signer_count) return -ESTALE;
    for (i = 0; i < signer_count; ++i) {
        for (j = 0; j < i; ++j) if (!memcmp(signers[i],signers[j],32)) return -EINVAL;
        for (j = 0; j < member->identity.signer_count; ++j)
            if (!memcmp(signers[i],member->identity.signers[j],32)) break;
        if (j == member->identity.signer_count) return -ESTALE;
    }
    return 0;
}
static int msu_observed_pin_current(const void *owner,u32 uid,struct msu_su_verified_install *output)
{
    struct msu_su_observed_provider *provider = (void *)owner;
    struct msu_observed_pin *pin = NULL;
    u32 i;
    int error = -ENOENT;
    memset(output,0,sizeof(*output));
    mutex_lock(&provider->operation);
    if (provider->closed) error = -ESHUTDOWN;
    else for (i = 0; i < provider->count; ++i) if (provider->uids[i].uid == uid) {
        pin = provider->uids[i].pin;
        error = provider->uids[i].error;
        if (!error && (!pin || !pin->count)) error = -ENOENT;
        if (!error) kref_get(&pin->refs);
        break;
    }
    mutex_unlock(&provider->operation);
    if (!error) {
        output->full_uid = uid; memcpy(output->installation_id,pin->id,sizeof(pin->id));
        output->pin = pin; output->members = pin->names; output->member_count = pin->count;
    }
    return error;
}
static void msu_observed_put_install(const void *owner,const void *pin)
{ (void)owner; msu_observed_put((void *)pin); }
static int msu_observed_read_grant(const void *owner,const struct msu_su_verified_install *install,
    struct msu_su_saved_grant *grant)
{
    struct msu_su_observed_provider *provider = (void *)owner;
    struct msu_su_saved_grant *copy;
    u32 i;
    int error;
    if (READ_ONCE(provider->closed)) return -ESHUTDOWN;
    error = provider->authority.read_grant(provider->authority.owner,install,grant);
    if (error == -ENOENT) {
        memset(grant,0,sizeof(*grant)); grant->full_uid = install->full_uid;
        memcpy(grant->installation_id,install->installation_id,sizeof(grant->installation_id));
    } else if (error) return error;
    copy = kmemdup(grant,sizeof(*copy),GFP_KERNEL);
    if (!copy) return -ENOMEM;
    mutex_lock(&provider->operation);
    for (i = 0; i < provider->count; ++i) if (provider->uids[i].uid == install->full_uid) {
        kfree(provider->uids[i].grant); provider->uids[i].grant = copy; copy = NULL; break;
    }
    mutex_unlock(&provider->operation); kfree(copy);
    return error;
}
static int msu_observed_validate_producer(const void *owner)
{ return READ_ONCE(((struct msu_su_observed_provider *)owner)->closed) ? -ESHUTDOWN : 0; }
static int msu_observed_check_closed(const void *owner)
{
    struct msu_su_observed_provider *provider = (void *)owner;
    return READ_ONCE(provider->closed) ? -ESHUTDOWN :
        READ_ONCE(provider->started) ? -EBUSY : 0;
}
void msu_su_observed_close(struct msu_su_observed_provider *provider)
{ if (provider) WRITE_ONCE(provider->closed,true); }
static int msu_observed_quiesce(const void *owner)
{
    struct msu_su_observed_provider *provider = (void *)owner;
    struct msu_observed_mark *mark,*next;
    msu_su_observed_close(provider);
    if (!mutex_trylock(&provider->scan)) return -EINPROGRESS;
    if (!mutex_trylock(&provider->operation)) { mutex_unlock(&provider->scan); return -EINPROGRESS; }
    if (!provider->marks_detached) {
        for (mark = provider->marks; mark; mark = mark->next)
            fsnotify_destroy_mark(&mark->mark,provider->group);
        /* destroy_group waits for in-flight event dispatch before cancellation;
         * keep one group reference for the held mark list's final cleanup. */
        fsnotify_get_group(provider->group);
        fsnotify_destroy_group(provider->group);
        for (mark = provider->marks; mark; mark = next) {
            next = mark->next;
            fsnotify_put_mark(&mark->mark);
        }
        provider->marks = NULL;
        fsnotify_wait_marks_destroyed();
        provider->marks_detached = true;
    }
    cancel_delayed_work(&provider->work);
    mutex_unlock(&provider->scan);
    mutex_unlock(&provider->operation);
    return work_busy(&provider->work.work) ? -EINPROGRESS : 0;
}
static void msu_observed_put_owner(const void *owner)
{
    struct msu_su_observed_provider *provider = (void *)owner;
    struct msu_observed_mark *mark,*next;
    u32 i;
    /* Registry calls only after quiesce and after all installation pins drop. */
    for (mark = provider->marks; mark; mark = next) {
        next = mark->next;
        fsnotify_put_mark(&mark->mark);
    }
    fsnotify_put_group(provider->group);
    for (i = 0; i < provider->count; ++i) {
        msu_observed_put(provider->uids[i].pin); kfree(provider->uids[i].grant);
    }
    provider->authority.put_owner(provider->authority.owner);
    kvfree(provider);
}
int msu_observed_inode_event(struct fsnotify_mark *mark,u32 mask,struct inode *inode,
    struct inode *dir,const struct qstr *name,u32 cookie)
{
    struct msu_observed_mark *watch = container_of(mark,struct msu_observed_mark,mark);
    (void)inode; (void)dir; (void)cookie;
    if (READ_ONCE(watch->provider->closed)) return 0;
    if (name && watch->child[0] && !(mask & (FS_DELETE_SELF | FS_MOVE_SELF | FS_UNMOUNT)) &&
        (MSU_DYN_FIELD(name, qstr, len) != strlen(watch->child) || memcmp(MSU_DYN_FIELD(name, qstr, name),watch->child,MSU_DYN_FIELD(name, qstr, len)))) return 0;
    if (mask & (FS_DELETE_SELF | FS_MOVE_SELF | FS_UNMOUNT)) WRITE_ONCE(watch->active,false);
    if (watch->kind >= 2 && (!name || !watch->child[0] ||
        (MSU_DYN_FIELD(name, qstr, len) == strlen(watch->child) && !memcmp(MSU_DYN_FIELD(name, qstr, name),watch->child,MSU_DYN_FIELD(name, qstr, len)))))
        atomic_set(&watch->provider->authority_dirty,1);
    if (!name || !(mask & FS_ISDIR) || watch->kind >= 2)
        schedule_delayed_work(&watch->provider->work,0);
    return 0;
}
void msu_observed_freeing_mark(struct fsnotify_mark *mark,struct fsnotify_group *group)
{
    struct msu_observed_mark *watch = container_of(mark,struct msu_observed_mark,mark);
    (void)group; WRITE_ONCE(watch->active,false);
    if (!READ_ONCE(watch->provider->closed)) schedule_delayed_work(&watch->provider->work,0);
}
void msu_observed_free_mark(struct fsnotify_mark *mark)
{
    struct msu_observed_mark *watch = container_of(mark,struct msu_observed_mark,mark);
    fput(watch->directory); kfree(watch);
}
static const struct fsnotify_ops msu_observed_ops = {
    .handle_inode_event = msu_observed_inode_event,
    .free_mark = msu_observed_free_mark,
    .freeing_mark = msu_observed_freeing_mark,
};
static int msu_observed_watch_path(struct msu_su_observed_provider *provider,
    const char *path,const char *child,u32 kind,u32 user)
{
    struct msu_observed_mark *watch;
    struct kstat stat;
    int error;
    if (strlen(path) >= sizeof(watch->path) || strlen(child) >= sizeof(watch->child)) return -ENAMETOOLONG;
    for (watch = provider->marks; watch; watch = watch->next)
        if (!strcmp(watch->path,path) && READ_ONCE(watch->active)) return 0;
    watch = kzalloc(sizeof(*watch),GFP_KERNEL);
    if (!watch) return -ENOMEM;
    error = msu_kernel_stat_protected_path(path,true,&watch->directory,&stat);
    if (error) { kfree(watch); return error; }
    watch->provider = provider; watch->user = user; watch->kind = kind; watch->active = true;
    memcpy(watch->path,path,strlen(path)+1); memcpy(watch->child,child,strlen(child)+1);
    fsnotify_init_mark(&watch->mark,provider->group);
    watch->mark.mask = FS_CREATE | FS_DELETE | FS_MOVE | FS_CLOSE_WRITE |
        FS_ATTRIB | FS_DELETE_SELF | FS_MOVE_SELF | FS_UNMOUNT | FS_EVENT_ON_CHILD;
    error = fsnotify_add_inode_mark(&watch->mark,msu_dynamic_file_inode(watch->directory),0);
    if (error) { fsnotify_put_mark(&watch->mark); return error; }
    watch->next = provider->marks; provider->marks = watch;
    return 0;
}
static int msu_observed_watch(struct msu_su_observed_provider *provider,u32 user,u32 kind)
{
    char path[80];
    if (kind == 2) return msu_observed_watch_path(provider,provider->authority.directory,
        provider->authority.filename,kind,user);
    if (kind == 1) return msu_observed_watch_path(provider,"/data/system","",kind,user);
    snprintf(path,sizeof(path),"/data/system/users/%u",user);
    return msu_observed_watch_path(provider,path,"",kind,user);
}
struct msu_observed_directory_list {
    struct dir_context context;
    u32 count,ids[MSU_SU_REGISTRY_MAX_UIDS];
    int error;
};
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6,1,0)
#define MSU_OBSERVED_ACTOR bool
#define MSU_OBSERVED_MORE true
#define MSU_OBSERVED_STOP false
#else
#define MSU_OBSERVED_ACTOR int
#define MSU_OBSERVED_MORE 0
#define MSU_OBSERVED_STOP -ENOSPC
#endif
MSU_OBSERVED_ACTOR msu_observed_authority_directory(struct dir_context *context,
    const char *name,int length,loff_t offset,u64 inode,unsigned int type);
MSU_OBSERVED_ACTOR msu_observed_authority_directory(struct dir_context *context,
    const char *name,int length,loff_t offset,u64 inode,unsigned int type)
{
    struct msu_observed_directory_list *list = container_of(context,struct msu_observed_directory_list,context);
    u32 i,id = 0,digit;
    (void)offset; (void)inode; (void)type;
    if (!length || length > 10) return MSU_OBSERVED_MORE;
    for (i = 0; i < length; ++i) {
        digit = name[i] - '0';
        if (digit > 9 || id > (0x7fffffffU-digit)/10) return MSU_OBSERVED_MORE;
        id = id*10+digit;
    }
    if (list->count == MSU_SU_REGISTRY_MAX_UIDS) { list->error = -EOVERFLOW; return MSU_OBSERVED_STOP; }
    list->ids[list->count++] = id;
    return MSU_OBSERVED_MORE;
}
static int msu_observed_watch_authorities(struct msu_su_observed_provider *provider)
{
    static const char *const paths[] = {"/data","/data/adb","/data/adb/maplesu",
        "/data/adb/maplesu/authorization"};
    static const char *const children[] = {"adb","maplesu","authorization",""};
    struct msu_observed_directory_list *list;
    char path[128];
    u32 i;
    int error = 0;
    for (i = 0; i < ARRAY_SIZE(paths); ++i) {
        error = msu_observed_watch_path(provider,paths[i],children[i],3,0);
        if (error == -ENOENT) return 0;
        if (error) return error;
    }
    list = kvzalloc(sizeof(*list),GFP_KERNEL);
    if (!list) return -ENOMEM;
    list->context.actor = msu_observed_authority_directory;
    error = msu_kernel_iterate_protected_directory(paths[3],&list->context);
    if (!error) error = list->error;
    for (i = 0; !error && i < list->count; ++i) {
        snprintf(path,sizeof(path),"%s/%u",paths[3],list->ids[i]);
        error = msu_observed_watch_path(provider,path,"",3,0);
        if (error == -ENOENT) error = 0;
    }
    kvfree(list); return error;
}
static int msu_observed_validate(int (*validate)(void *),void *context)
{
    int error = validate ? validate(context) : 0;
    return error > 0 ? -EIO : error;
}
/* scan serializes the candidate and its exact responses across requests. A
 * pending commit keeps its known staged ref; only a new explicit sync cancels
 * that ref before reading the current authority. Never infer consumption from
 * a return code or replay a commit whose completion is unknown. */
static int msu_observed_cancel(struct msu_su_observed_provider *provider,
    struct msu_su_observed_publication_receipt *receipt)
{
    int error;
    receipt->cancel_attempted = true;
    error = msu_su_registry_cancel_kernel(provider->registry,provider->candidate,&receipt->cancel);
    receipt->cancel.status = error;
    if (receipt->cancel.metadata_length & MAPLESU_EFFECT_REFERENCE_DROPPED)
        provider->candidate = 0;
    else if (!(receipt->cancel.metadata_length & MAPLESU_EFFECT_PENDING)) {
        provider->uncertain = true;
        if (!error) error = -EUCLEAN;
    } else if (!error) error = -EINPROGRESS;
    receipt->cleanup_error = error;
    receipt->candidate_after = provider->candidate;
    receipt->uncertain = provider->uncertain;
    return error;
}
static int msu_observed_publish(struct msu_su_observed_provider *provider,
    int (*validate)(void *),void *context,
    struct msu_su_observed_publication_receipt *detail)
{
    struct msu_su_observed_publication_receipt receipt = {0};
    int error;
    receipt.candidate_before = provider->candidate;
    if (provider->uncertain || provider->candidate) {
        if (detail) *detail = provider->publication;
        return provider->uncertain ? -EUCLEAN : -EINPROGRESS;
    }
    error = msu_observed_validate(validate,context);
    if (error) goto out;
    receipt.prepare_attempted = true;
    error = msu_su_registry_prepare_kernel(provider->registry,&receipt.prepare);
    receipt.prepare.status = error;
    if (receipt.prepare.metadata_length & MAPLESU_EFFECT_ALLOCATED) {
        provider->candidate = receipt.prepare.result;
        if (!provider->candidate) {
            provider->uncertain = true;
            if (!error) error = -EUCLEAN;
        }
    } else if (!error) { provider->uncertain = true; error = -EUCLEAN; }
    if (error) goto cleanup;
    error = msu_observed_validate(validate,context);
    if (error) goto cleanup;
    receipt.commit_attempted = true;
    error = msu_su_registry_commit_kernel(provider->registry,provider->candidate,&receipt.commit);
    receipt.commit.status = error;
    if (receipt.commit.metadata_length & (MAPLESU_EFFECT_COMMITTED | MAPLESU_EFFECT_REFERENCE_DROPPED))
        provider->candidate = 0;
    else if (!error) { provider->uncertain = true; error = -EUCLEAN; }
    if (!error) error = msu_observed_validate(validate,context);
cleanup:
    if (error && provider->candidate && !provider->uncertain &&
        !(receipt.prepare.metadata_length & MAPLESU_EFFECT_PENDING) &&
        !(receipt.commit.metadata_length & MAPLESU_EFFECT_PENDING))
        msu_observed_cancel(provider,&receipt);
out:
    receipt.status = error;
    receipt.candidate_after = provider->candidate;
    receipt.uncertain = provider->uncertain;
    provider->publication = receipt;
    if (detail) *detail = receipt;
    return error;
}
/* operation serializes observation/cache only; never hold it while entering
 * registry/gateway because their source callbacks acquire this same mutex. */
static int msu_observed_scan(struct msu_su_observed_provider *provider,u32 uid,bool force,
    int (*validate)(void *),void *context,struct msu_su_observed_sync_receipt *detail)
{
    struct msu_observed_pin *fresh = NULL,*old = NULL;
    struct msu_su_revoke_receipt receipt = {0};
    maplesu_uid_record_v3 record = {0};
    u32 i;
    int error,read_error,publication_error;
    /* A retained publication must not block an installation revocation. */
    publication_error = provider->uncertain ? -EUCLEAN :
        provider->candidate ? -EINPROGRESS : 0;
    read_error = msu_observed_capture(uid,&fresh);
    error = msu_observed_validate(validate,context);
    if (error) { msu_observed_put(fresh); return error; }
    mutex_lock(&provider->operation);
    if (provider->closed) { error = -ESHUTDOWN; goto unlock; }
    for (i = 0; i < provider->count; ++i) if (provider->uids[i].uid == uid) break;
    if (i == provider->count) { error = -ENOENT; goto unlock; }
    if (!read_error && !provider->uids[i].error && msu_observed_same(provider->uids[i].pin,fresh)) {
        struct msu_su_saved_grant *previous;
        struct msu_su_saved_grant *observed_grant;
        struct msu_su_verified_install install = {0};
        if (!force && !provider->uids[i].dirty) {
            if (detail) detail->unchanged = true;
            error = publication_error; goto unlock;
        }
        observed_grant = kzalloc(sizeof(*observed_grant),GFP_KERNEL);
        if (!observed_grant) { error = -ENOMEM; goto unlock; }
        previous = provider->uids[i].grant ? kmemdup(provider->uids[i].grant,
            sizeof(*previous),GFP_KERNEL) : NULL;
        if (provider->uids[i].grant && !previous) { kfree(observed_grant); error = -ENOMEM; goto unlock; }
        install.full_uid = uid; install.pin = provider->uids[i].pin;
        memcpy(install.installation_id,provider->uids[i].pin->id,sizeof(install.installation_id));
        install.members = provider->uids[i].pin->names; install.member_count = provider->uids[i].pin->count;
        mutex_unlock(&provider->operation);
        error = provider->authority.read_grant(provider->authority.owner,&install,observed_grant);
        if (error == -ENOENT) {
            memset(observed_grant,0,sizeof(*observed_grant)); observed_grant->full_uid = uid;
            memcpy(observed_grant->installation_id,install.installation_id,sizeof(observed_grant->installation_id)); error = 0;
        }
        mutex_lock(&provider->operation);
        if (provider->closed) {
            kfree(previous); kfree(observed_grant); error = -ESHUTDOWN; goto unlock;
        }
        if (!error && !provider->uids[i].dirty && previous && !memcmp(previous,observed_grant,sizeof(*observed_grant))) {
            if (detail) detail->unchanged = true;
            kfree(previous); kfree(observed_grant); error = publication_error; goto unlock;
        }
        kfree(previous); kfree(observed_grant);
        if (error) read_error = error;
        /* Keep the same installation object for a policy-only change. */
        msu_observed_put(fresh); fresh = provider->uids[i].pin; kref_get(&fresh->refs);
    }
    mutex_unlock(&provider->operation);
    error = msu_observed_validate(validate,context);
    if (error) { msu_observed_put(fresh); return error; }
    error = msu_su_registry_revoke(provider->registry,uid,&receipt);
    if (detail) {
        detail->revoke_attempted = true; detail->revoke_status = error;
        detail->revoke = receipt;
    }
    if (error) {
        mutex_lock(&provider->operation); provider->uids[i].dirty = true;
        mutex_unlock(&provider->operation); msu_observed_put(fresh); return error;
    }
    mutex_lock(&provider->operation);
    if (provider->closed) { error = -ESHUTDOWN; goto unlock; }
    old = provider->uids[i].pin;
    provider->uids[i].pin = fresh; fresh = NULL;
    provider->uids[i].error = read_error;
    mutex_unlock(&provider->operation);
    msu_observed_put(old);
    if (read_error) return read_error;
    if (publication_error) { error = publication_error; goto dirty; }
    mutex_lock(&provider->operation); provider->uids[i].dirty = false;
    mutex_unlock(&provider->operation);
    error = msu_observed_validate(validate,context);
    if (error) goto dirty;
    error = msu_su_registry_refresh(provider->registry,uid,&record);
    if (detail) {
        detail->refresh_attempted = true; detail->refresh_status = error;
        detail->refreshed = record;
    }
    if (!error) error = msu_observed_publish(provider,validate,context,
        detail ? &detail->publication : NULL);
dirty:
    if (error) {
        mutex_lock(&provider->operation); provider->uids[i].dirty = true;
        mutex_unlock(&provider->operation);
    }
    return error;
unlock:
    mutex_unlock(&provider->operation); msu_observed_put(fresh); return error;
}
static int msu_observed_track(struct msu_su_observed_provider *provider,u32 uid)
{
    u32 i;
    int error = 0;
    if (uid > 0x7fffffffU || (uid != 1000U && uid < 2000U)) return -EINVAL;
    mutex_lock(&provider->operation);
    if (provider->closed) { error = -ESHUTDOWN; goto out; }
    for (i = 0; i < provider->count; ++i) if (provider->uids[i].uid == uid) break;
    if (i == provider->count) {
        if (i == MSU_SU_REGISTRY_MAX_UIDS) { error = -ENOSPC; goto out; }
        provider->uids[i].uid = uid; provider->uids[i].error = -EAGAIN; ++provider->count;
    }
    error = msu_observed_watch(provider,uid / 100000U,0);
out:
    mutex_unlock(&provider->operation); return error;
}
static int msu_observed_reload(struct msu_su_observed_provider *provider)
{
    u32 *uids,count = 0,i;
    int error;
    uids = kvcalloc(MSU_SU_REGISTRY_MAX_UIDS,sizeof(*uids),GFP_KERNEL);
    if (!uids) return -ENOMEM;
    error = provider->authority.list_uids(provider->authority.owner,uids,MSU_SU_REGISTRY_MAX_UIDS,&count);
    if (error == -ENOENT) { count = 0; error = 0; }
    if (!error && count > MSU_SU_REGISTRY_MAX_UIDS) error = -EOVERFLOW;
    for (i = 0; !error && i < count; ++i) error = msu_observed_track(provider,uids[i]);
    kvfree(uids); return error;
}
static void msu_observed_scan_work(struct work_struct *work)
{
    struct msu_su_observed_provider *provider = container_of(work,struct msu_su_observed_provider,work.work);
    u32 i,count;
    bool force;
    int error = 0;
    if (READ_ONCE(provider->closed)) return;
    if (!mutex_trylock(&provider->scan)) { schedule_delayed_work(&provider->work,msecs_to_jiffies(100)); return; }
    force = atomic_xchg(&provider->authority_dirty,0) != 0;
    mutex_lock(&provider->operation);
    if (!provider->closed) {
        error = msu_observed_watch(provider,0,1);
        if (!error) error = msu_observed_watch(provider,0,2);
        if (!error) error = msu_observed_watch_authorities(provider);
    }
    mutex_unlock(&provider->operation);
    if (force) { int reload = msu_observed_reload(provider); if (reload && !error) error = reload; }
    mutex_lock(&provider->operation); count = provider->count; mutex_unlock(&provider->operation);
    for (i = 0; i < count && !READ_ONCE(provider->closed); ++i) {
        int next;
        mutex_lock(&provider->operation);
        next = msu_observed_watch(provider,provider->uids[i].uid / 100000U,0);
        mutex_unlock(&provider->operation);
        { int scan = msu_observed_scan(provider,provider->uids[i].uid,force,NULL,NULL,NULL); if (scan) next = scan; }
        if (next && !error) error = next;
    }
    WRITE_ONCE(provider->last_error,error);
    mutex_unlock(&provider->scan);
    if (!READ_ONCE(provider->closed) && (error == -EINPROGRESS || error == -EAGAIN))
        schedule_delayed_work(&provider->work,msecs_to_jiffies(100));
}
int msu_su_observed_refresh(struct msu_su_observed_provider *provider,u32 uid)
{
    int error;
    if (!provider) return -EINVAL;
    if (!mutex_trylock(&provider->scan)) return -EINPROGRESS;
    error = msu_observed_track(provider,uid);
    if (!error) error = msu_observed_scan(provider,uid,true,NULL,NULL,NULL);
    mutex_unlock(&provider->scan); return error;
}
static u32 msu_observed_publication_effects(const struct msu_su_observed_publication_receipt *receipt)
{
    u32 effects = receipt->prepare.metadata_length | receipt->commit.metadata_length |
        receipt->cancel.metadata_length;
    /* The raw previous responses retain their historical PENDING. A completed
     * explicit cancel ends that staged lifetime; it is not still pending now. */
    if (!receipt->candidate_after && !receipt->uncertain &&
        (receipt->cancel.metadata_length & MAPLESU_EFFECT_REFERENCE_DROPPED))
        effects &= ~MAPLESU_EFFECT_PENDING;
    if (receipt->candidate_after || receipt->uncertain) effects |= MAPLESU_EFFECT_PENDING;
    if (receipt->uncertain) effects |= MAPLESU_EFFECT_QUARANTINED;
    return effects;
}
/* Called under scan, never under operation. Reload the complete protected
 * authority first, so newly saved fullUIDs are included. Retained tombstones
 * are also scanned to close removed grants. An individual failure does not
 * skip later revocations; an unknown publication still prevents all replay. */
static int msu_observed_sync_all(struct msu_su_observed_provider *provider,
    int (*validate)(void *),void *context,struct msu_su_observed_sync_receipt *receipt)
{
    struct msu_su_observed_sync_receipt *item;
    u32 i;
    int error,first_error = 0;
    item = kzalloc(sizeof(*item),GFP_KERNEL);
    if (!item) return -ENOMEM;
    error = msu_observed_reload(provider);
    if (error) goto out;
    receipt->unchanged = true;
    for (i = 0; i < provider->count; ++i) {
        error = msu_observed_validate(validate,context);
        if (error) { if (!first_error) first_error = error; break; }
        memset(item,0,sizeof(*item));
        item->full_uid = provider->uids[i].uid;
        error = msu_observed_scan(provider,item->full_uid,true,validate,context,item);
        ++receipt->scanned_uids;
        receipt->unchanged &= item->unchanged;
        receipt->effects |= msu_observed_publication_effects(&item->publication);
        if (item->revoke.inflight || error == -EINPROGRESS)
            receipt->effects |= MAPLESU_EFFECT_PENDING;
        if (item->publication.commit.metadata_length & MAPLESU_EFFECT_COMMITTED)
            receipt->committed_revision = item->publication.commit.result;
        if (!first_error) {
            receipt->revoke_attempted = item->revoke_attempted;
            receipt->revoke_status = item->revoke_status;
            receipt->revoke = item->revoke;
            receipt->refresh_attempted = item->refresh_attempted;
            receipt->refresh_status = item->refresh_status;
            receipt->refreshed = item->refreshed;
            if (item->publication.prepare_attempted || item->publication.commit_attempted)
                receipt->publication = item->publication;
            if (error) { first_error = error; receipt->failed_uid = item->full_uid; }
        }
    }
    error = first_error;
out:
    kfree(item);
    return error;
}
int msu_su_observed_sync(struct msu_su_observed_provider *provider,u32 uid,
    int (*validate)(void *),void *context,struct msu_su_observed_sync_receipt *receipt)
{
    int error,post_error;
    bool canceled = false;
    if (!receipt) return -EINVAL;
    memset(receipt,0,sizeof(*receipt)); receipt->full_uid = uid;
    if (!provider || !validate || uid > 0x7fffffffU || (uid && uid != 1000U && uid < 2000U)) {
        error = -EINVAL; goto out;
    }
    error = msu_observed_validate(validate,context);
    if (error) goto out;
    if (!mutex_trylock(&provider->scan)) { error = -EINPROGRESS; goto out; }
    mutex_lock(&provider->operation);
    error = provider->closed ? -ESHUTDOWN : provider->started ? 0 : -EAGAIN;
    mutex_unlock(&provider->operation);
    if (error) goto unlock;
    if (provider->uncertain) {
        receipt->previous = provider->publication;
        receipt->previous.uncertain = true;
        error = -EUCLEAN; goto unlock;
    }
    if (provider->candidate) {
        receipt->previous = provider->publication;
        error = msu_observed_validate(validate,context);
        if (error) goto unlock;
        canceled = true;
        error = msu_observed_cancel(provider,&receipt->previous);
        provider->publication = receipt->previous;
        if (error) goto unlock;
    }
    error = msu_observed_validate(validate,context);
    if (error) goto unlock;
    if (!uid) {
        error = msu_observed_sync_all(provider,validate,context,receipt);
    } else {
        error = msu_observed_track(provider,uid);
        if (!error) {
            receipt->scanned_uids = 1;
            error = msu_observed_scan(provider,uid,true,validate,context,receipt);
        }
    }
    post_error = msu_observed_validate(validate,context);
    if (!error) error = post_error;
unlock:
    if (provider->candidate || provider->uncertain)
        receipt->effects |= MAPLESU_EFFECT_PENDING;
    if (provider->uncertain) receipt->effects |= MAPLESU_EFFECT_QUARANTINED;
    WRITE_ONCE(provider->last_error,error);
    mutex_unlock(&provider->scan);
out:
    /* previous.prepare/commit are exact historical responses, not mutations
     * performed by this request. Only its explicit cancellation is new. */
    receipt->effects |= (canceled ? receipt->previous.cancel.metadata_length : 0) |
        msu_observed_publication_effects(&receipt->publication);
    if (receipt->publication.commit.metadata_length & MAPLESU_EFFECT_COMMITTED)
        receipt->committed_revision = receipt->committed_revision ? receipt->committed_revision :
            receipt->publication.commit.result;
    if (receipt->previous.candidate_after || receipt->previous.uncertain)
        receipt->effects |= MAPLESU_EFFECT_PENDING;
    if (receipt->previous.uncertain) receipt->effects |= MAPLESU_EFFECT_QUARANTINED;
    if (error == -EINPROGRESS || receipt->revoke.inflight)
        receipt->effects |= MAPLESU_EFFECT_PENDING;
    receipt->status = error;
    return error;
}
int msu_su_observed_start(struct msu_su_observed_provider *provider,const u32 *uids,u32 count)
{
    u32 i;
    int error;
    if (!provider || (!uids && count) || count > MSU_SU_REGISTRY_MAX_UIDS) return -EINVAL;
    if (!mutex_trylock(&provider->scan)) return -EINPROGRESS;
    mutex_lock(&provider->operation);
    if (provider->closed) { error = -ESHUTDOWN; goto out; }
    error = msu_observed_watch(provider,0,1);
    if (!error) error = msu_observed_watch(provider,0,2);
    if (!error) error = msu_observed_watch_authorities(provider);
    if (error) goto out;
    provider->started = true;
    mutex_unlock(&provider->operation);
    error = msu_observed_reload(provider);
    for (i = 0; !error && i < count; ++i) error = msu_observed_track(provider,uids[i]);
    for (i = 0; !error && i < provider->count; ++i)
        error = msu_observed_scan(provider,provider->uids[i].uid,true,NULL,NULL,NULL);
    mutex_unlock(&provider->scan); return error;
out:
    mutex_unlock(&provider->operation); mutex_unlock(&provider->scan); return error;
}
int msu_su_observed_create(const maplesu_host_instance *host,u64 controller,
    const struct msu_su_observed_authority *authority,
    struct msu_su_observed_provider **output,struct msu_su_registry **registry)
{
    struct msu_su_observed_provider *provider;
    struct msu_su_registry_source source = {0};
    int error;
    if (!output || !registry || !authority || !authority->owner ||
        !authority->read_grant || !authority->put_owner || !authority->list_uids ||
        !memchr(authority->directory,0,sizeof(authority->directory)) ||
        !memchr(authority->filename,0,sizeof(authority->filename)) ||
        strncmp(authority->directory,"/data/",6) || !authority->directory[6] ||
        !authority->filename[0] || strchr(authority->filename,'/')) return -EINVAL;
    *output = NULL; *registry = NULL;
    if (!msu_runtime_layout_ready()) return -EAGAIN;
    provider = kvzalloc(sizeof(*provider),GFP_KERNEL);
    if (!provider) return -ENOMEM;
    mutex_init(&provider->operation); mutex_init(&provider->scan);
    atomic_set(&provider->authority_dirty,0); INIT_DELAYED_WORK(&provider->work,msu_observed_scan_work);
    provider->authority = *authority;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6,0,0)
    provider->group = fsnotify_alloc_group(&msu_observed_ops,0);
#else
    provider->group = fsnotify_alloc_group(&msu_observed_ops);
#endif
    if (IS_ERR(provider->group)) { error = PTR_ERR(provider->group); kvfree(provider); return error; }
    source.owner = provider; source.pin_current = msu_observed_pin_current;
    source.put_install = msu_observed_put_install; source.read_grant = msu_observed_read_grant;
    source.validate_profile = msu_su_profile_check_execution;
    source.check_closed = msu_observed_check_closed; source.quiesce = msu_observed_quiesce;
    source.put_owner = msu_observed_put_owner; source.validate_producer = msu_observed_validate_producer;
    error = msu_su_registry_create(host,controller,&source,&provider->registry);
    if (error) { fsnotify_put_group(provider->group); kvfree(provider); return error; }
    *output = provider; *registry = provider->registry;
    return 0;
}
