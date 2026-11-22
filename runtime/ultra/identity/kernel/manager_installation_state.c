// SPDX-License-Identifier: GPL-3.0-only
#include <linux/cred.h>
#include <linux/err.h>
#include <linux/errno.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/irqflags.h>
#include <linux/kdev_t.h>
#include <linux/mm.h>
#include <linux/mutex.h>
#include <linux/preempt.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/user_namespace.h>
#include "manager_installation_state.h"
#include "manager_management.h"
#include "manager_su_runtime_factory.h"
#include "manager_early_fixed.h"
#include "protected_install_kernel.h"
#include "manager_dynamic_layout.h"

static DEFINE_MUTEX(msu_installation_lock);
/* Not cleared by an unpublished-state discard: no epoch is reused this boot. */
static u32 msu_installation_helper_next_epoch;
struct msu_installation_helper_lease {
    maplesu_host_instance host;
    unsigned char generation[16];
    struct file *directory, *helper, *executable;
    u64 service;
    u32 epoch;
};
static struct {
    maplesu_installation_state_v3 value;
    struct file *directory, *helper;
    const void *owner;
    msu_installation_revoke_fn revoke;
    void *context;
    u64 helper_service;
    u32 helper_epoch, helper_leases;
    bool helper_admission, helper_closed;
    bool ready;
} installation;

/* Called with installation mutex held. CORE closes/detaches matching sessions
 * under its table lock and queues cleanup; it never waits on operation here. */
static int msu_installation_helper_retire(u32 *effects)
{
    u32 service_effects = 0;
    int error = 0;
    installation.helper_admission = false;
    if (installation.helper_service)
        error = msu_runtime_service_revoke(&installation.value.host,
            installation.helper_service, &service_effects);
    *effects |= service_effects;
    if (installation.helper_leases && !error) error = -EINPROGRESS;
    if (error) *effects |= MAPLESU_EFFECT_PENDING;
    else { installation.helper_service = 0; installation.helper_epoch = 0; }
    return error;
}
static int msu_installation_revoke_consumers(u32 *effects)
{
    int error = msu_installation_helper_retire(effects);
    /* Fixed OEM/root-env/SELinux providers share this authenticated installation
     * generation. Revoke closes their admission and drains each provider before
     * the legacy SU factory callback; a pending provider keeps the installation
     * refs and preserves the first native error. */
    {
        u32 fixed_effects = 0;
        int fixed_error = msu_early_fixed_provider_revoke(&installation.value.host,
            installation.value.record.generation, &fixed_effects);
        *effects |= fixed_effects;
        if (!error) error = fixed_error;
    }
    if (installation.revoke) {
        u32 runtime_effects = 0;
        int runtime_error = installation.revoke(installation.context,
            &installation.value.host, installation.value.record.generation, &runtime_effects);
        *effects |= runtime_effects;
        if (!error) error = runtime_error;
    }
    return error;
}

static bool msu_installation_host(maplesu_host_instance host)
{
    return host.low == installation.value.host.low &&
        host.high == installation.value.host.high;
}
static bool msu_installation_nonzero(const unsigned char bytes[16])
{
    unsigned int i;
    unsigned char value = 0;
    for (i = 0; i < 16; ++i) value |= bytes[i];
    return value != 0;
}
static bool msu_installation_record(const maplesu_installation_record_v3 *value)
{
    unsigned int i;
    if (value->magic != 0x5349534dU || value->schema != 1 ||
        value->bytes != sizeof(*value) || value->active > 1 || value->reserved ||
        value->publication_reserved || value->publication_source > 2 ||
        value->publication_phase > 16 || value->version_published > 1 ||
        (value->active && (!msu_installation_nonzero(value->generation) ||
        value->publication_source || value->publication_phase != 16 ||
        !value->version_published || value->publication_code))) return false;
    for (i = 0; i < 3; ++i)
        if (value->stages[i].reserved || value->stages[i].flags & ~15U ||
            ((value->stages[i].flags & 2) && !(value->stages[i].flags & 1))) return false;
    return true;
}
static bool msu_installation_expected(const maplesu_installation_state_v3 *value)
{
    return value->magic == MAPLESU_INSTALLATION_STATE_MAGIC &&
        value->schema == MAPLESU_INSTALLATION_STATE_SCHEMA &&
        value->bytes == sizeof(*value) && !value->reserved &&
        value->flags == installation.value.flags &&
        msu_installation_host(value->host) &&
        !memcmp(value->name, installation.value.name, 16) &&
        value->revision == installation.value.revision;
}
static int msu_installation_guard(struct file *directory,
    const unsigned char generation[16], u32 active)
{
    struct {
        u32 magic;
        u16 schema, bytes;
        maplesu_host_instance host;
        unsigned char generation[16];
        u32 active, reserved;
        char boot[40];
    } guard = {0};
    int error;
    _Static_assert(sizeof(guard) == 88, "installation guard layout");
    error = msu_kernel_installation_boot_id(guard.boot);
    if (error) return error;
    guard.magic = 0x4749534dU;
    guard.schema = 2;
    guard.bytes = sizeof(guard);
    guard.host = installation.value.host;
    memcpy(guard.generation, generation, 16);
    guard.active = active;
    return msu_kernel_write_installation_guard(directory, &guard, sizeof(guard));
}
static void msu_installation_drop_files(void)
{
    if (installation.helper) {
        allow_write_access(installation.helper);
        fput(installation.helper);
        installation.helper = NULL;
    }
    if (installation.directory) {
        fput(installation.directory);
        installation.directory = NULL;
    }
}
int msu_installation_init(const maplesu_host_instance *host, const unsigned char name[16])
{
    unsigned int i;
    int error = 0;
    if (!host || !(host->low | host->high) || !name) return -EINVAL;
    if (!msu_runtime_layout_ready()) return -EAGAIN;
    for (i = 0; i < 16; ++i)
        if (!((name[i] >= 'A' && name[i] <= 'Z') || (name[i] >= 'a' && name[i] <= 'z') ||
            (name[i] >= '0' && name[i] <= '9'))) return -EINVAL;
    mutex_lock(&msu_installation_lock);
    if (installation.ready) error = -EALREADY;
    else {
        installation.value.magic = MAPLESU_INSTALLATION_STATE_MAGIC;
        installation.value.schema = MAPLESU_INSTALLATION_STATE_SCHEMA;
        installation.value.bytes = sizeof(installation.value);
        installation.value.host = *host;
        memcpy(installation.value.name, name, 16);
        installation.value.revision = 1;
        installation.value.record.magic = 0x5349534dU;
        installation.value.record.schema = 1;
        installation.value.record.bytes = sizeof(installation.value.record);
        installation.ready = true;
    }
    mutex_unlock(&msu_installation_lock);
    return error;
}
int msu_installation_bind_lifecycle(const maplesu_host_instance *host,
    const void *owner, msu_installation_revoke_fn revoke, void *context)
{
    int error = 0;
    if (!host || !owner || !revoke || !context) return -EINVAL;
    mutex_lock(&msu_installation_lock);
    if (!installation.ready || !msu_installation_host(*host)) error = -ESTALE;
    else if (installation.owner) error = -EALREADY;
    else {
        installation.owner = owner;
        installation.revoke = revoke;
        installation.context = context;
    }
    mutex_unlock(&msu_installation_lock);
    return error;
}
int msu_installation_unbind_lifecycle(const maplesu_host_instance *host, const void *owner)
{
    int error = 0;
    if (!host || !owner) return -EINVAL;
    mutex_lock(&msu_installation_lock);
    if (!installation.ready || !msu_installation_host(*host) || installation.owner != owner) error = -ESTALE;
    else if (installation.value.record.active || installation.value.flags ||
        installation.helper_service || installation.helper_leases) error = -EBUSY;
    else { installation.owner = NULL; installation.revoke = NULL; installation.context = NULL; }
    mutex_unlock(&msu_installation_lock);
    return error;
}
int msu_installation_discard_unpublished(void)
{
    int error = 0;
    mutex_lock(&msu_installation_lock);
    if (installation.owner || installation.value.record.active || installation.value.flags ||
        installation.helper_service || installation.helper_leases) error = -EBUSY;
    else {
        msu_installation_drop_files();
        memset(&installation, 0, sizeof(installation));
    }
    mutex_unlock(&msu_installation_lock);
    return error;
}
int msu_installation_read(maplesu_installation_state_v3 *output)
{
    int error = 0;
    if (!output) return -EINVAL;
    mutex_lock(&msu_installation_lock);
    if (!installation.ready) error = -EOPNOTSUPP;
    else *output = installation.value;
    mutex_unlock(&msu_installation_lock);
    return error;
}
static int msu_installation_commit(const maplesu_installation_state_v3 *value, struct file *executing, u32 *effects)
{
    struct file *directory, *helper;
    struct kstat stat;
    maplesu_installation_record_v3 disk;
    ssize_t count;
    char path[6 + 16 + 6];
    int error;
    if (installation.value.record.active || installation.value.flags ||
        installation.helper_service || installation.helper_leases) return -EBUSY;
    if (installation.value.revision == ~0ULL) return -EOVERFLOW;
    if (!msu_installation_record(&value->record) || !value->record.active ||
        !memcmp(value->record.generation, installation.value.record.generation, 16)) return -EINVAL;
    memcpy(path, "/data/", 6);
    memcpy(path + 6, installation.value.name, 16);
    path[22] = 0;
    directory = msu_kernel_open_installation_path(path, true);
    if (IS_ERR(directory)) return PTR_ERR(directory);
    error = vfs_getattr(&MSU_DYN_FIELD(directory, file, f_path), &stat, STATX_BASIC_STATS, AT_STATX_SYNC_AS_STAT);
    if (error) goto drop_directory;
    if (__kuid_val(stat.uid) || !S_ISDIR(stat.mode) || stat.mode & 0077 ||
        stat.ino != value->inode || huge_encode_dev(stat.dev) != value->device) {
        error = -ESTALE;
        goto drop_directory;
    }
    count = msu_kernel_read_installation_record(directory, &disk, sizeof(disk));
    if (count < 0) { error = count; goto drop_directory; }
    if (count != sizeof(disk) || memcmp(&disk, &value->record, sizeof(disk))) {
        error = -ESTALE; goto drop_directory;
    }
    memcpy(path + 22, "/init", 6);
    helper = msu_kernel_open_installation_path(path, false);
    if (IS_ERR(helper)) { error = PTR_ERR(helper); goto drop_directory; }
    if (__kuid_val(MSU_DYN_FIELD(msu_dynamic_file_inode(helper), inode, i_uid)) || !S_ISREG(MSU_DYN_FIELD(msu_dynamic_file_inode(helper), inode, i_mode)) ||
        MSU_DYN_FIELD(msu_dynamic_file_inode(helper), inode, i_mode) & 0077 || MSU_DYN_FIELD(msu_dynamic_file_inode(helper), inode, i_nlink) != 1) {
        error = -EPERM;
        goto drop_helper;
    }
    if (executing && msu_dynamic_file_inode(executing) != msu_dynamic_file_inode(helper)) {
        error = -EPERM;
        goto drop_helper;
    }
    error = deny_write_access(helper);
    if (error) goto drop_helper;
    error = msu_installation_guard(directory, value->record.generation, 1);
    if (error) { allow_write_access(helper); goto drop_helper; }
    msu_installation_drop_files();
    installation.directory = directory;
    installation.helper = helper;
    installation.value.record = value->record;
    installation.value.device = value->device;
    installation.value.inode = value->inode;
    ++installation.value.revision;
    *effects |= MAPLESU_EFFECT_COMMITTED;
    return 0;
drop_helper:
    fput(helper);
drop_directory:
    fput(directory);
    return error;
}
int msu_installation_management(u64 action, maplesu_installation_state_v3 *value, u32 *effects)
{
    int error = 0;
    if (!value || !effects) return -EINVAL;
    if (action == MAPLESU_INSTALLATION_READ) return msu_installation_read(value);
    mutex_lock(&msu_installation_lock);
    if (!installation.ready) { error = -EOPNOTSUPP; goto out; }
    if (!msu_installation_expected(value)) { error = -ESTALE; goto out; }
    if (installation.value.revision == ~0ULL) { error = -EOVERFLOW; goto out; }
    if (action == MAPLESU_INSTALLATION_COMMIT) error = msu_installation_commit(value, NULL, effects);
    else if (action == MAPLESU_INSTALLATION_REVOKE) {
        if (memcmp(value->record.generation, installation.value.record.generation, 16)) {
            error = -ESTALE;
            goto out;
        }
        /* The mutex closes new vendor observations before any factory drain.
         * No bound consumer means this domain has exposed no execution refs. */
        if (installation.value.record.active) {
            installation.value.record.active = 0;
            ++installation.value.revision;
            *effects |= MAPLESU_EFFECT_COMMITTED;
        }
        error = msu_installation_revoke_consumers(effects);
        if (!error && installation.directory) error = msu_installation_guard(installation.directory,
            installation.value.record.generation, 0);
        if (error) {
            installation.value.flags |= MAPLESU_INSTALLATION_PENDING;
            *effects |= MAPLESU_EFFECT_PENDING;
        } else {
            installation.value.flags = 0;
            msu_installation_drop_files();
        }
    } else error = -EINVAL;
out:
    mutex_unlock(&msu_installation_lock);
    return error;
}
/* Held executable storage alone does not prove its current fixed path. */
static int msu_installation_revalidate(void)
{
    struct file *directory, *helper;
    maplesu_installation_record_v3 disk;
    struct kstat stat;
    char path[28];
    ssize_t count;
    int error;
    memcpy(path, "/data/", 6);
    memcpy(path + 6, installation.value.name, 16);
    path[22] = 0;
    directory = msu_kernel_open_installation_path(path, true);
    if (IS_ERR(directory)) return PTR_ERR(directory);
    error = vfs_getattr(&MSU_DYN_FIELD(directory, file, f_path), &stat, STATX_BASIC_STATS, AT_STATX_SYNC_AS_STAT);
    if (error) goto drop_directory;
    if (!installation.directory || msu_dynamic_file_inode(directory) != msu_dynamic_file_inode(installation.directory) ||
        __kuid_val(stat.uid) || !S_ISDIR(stat.mode) || stat.mode & 0077 || !stat.nlink ||
        stat.ino != installation.value.inode || huge_encode_dev(stat.dev) != installation.value.device) {
        error = -ESTALE;
        goto drop_directory;
    }
    count = msu_kernel_read_installation_record(directory, &disk, sizeof(disk));
    if (count < 0) { error = count; goto drop_directory; }
    if (count != sizeof(disk) || !msu_installation_record(&disk) || !disk.active ||
        memcmp(disk.generation, installation.value.record.generation, 16)) {
        error = -ESTALE;
        goto drop_directory;
    }
    memcpy(path + 22, "/init", 6);
    helper = msu_kernel_open_installation_path(path, false);
    if (IS_ERR(helper)) { error = PTR_ERR(helper); goto drop_directory; }
    error = !installation.helper || msu_dynamic_file_inode(helper) != msu_dynamic_file_inode(installation.helper) ||
        __kuid_val(MSU_DYN_FIELD(msu_dynamic_file_inode(helper), inode, i_uid)) || !S_ISREG(MSU_DYN_FIELD(msu_dynamic_file_inode(helper), inode, i_mode)) ||
        MSU_DYN_FIELD(msu_dynamic_file_inode(helper), inode, i_mode) & 0077 || MSU_DYN_FIELD(msu_dynamic_file_inode(helper), inode, i_nlink) != 1 ? -ESTALE : 0;
    fput(helper);
drop_directory:
    fput(directory);
    return error;
}

static void msu_installation_observed_stale(u32 *effects)
{
    installation.value.record.active = 0;
    if (installation.value.revision != ~0ULL) ++installation.value.revision;
    installation.value.flags |= MAPLESU_INSTALLATION_PENDING;
    *effects |= MAPLESU_EFFECT_COMMITTED | MAPLESU_EFFECT_PENDING;
    /* The first error remains the source error. All real consumers still close
     * admission now, and keep their independent in-flight refs for follow-up. */
    msu_installation_revoke_consumers(effects);
}
int msu_installation_helper_acquire(const maplesu_host_instance *host,
    struct msu_installation_helper_lease **output, u32 *epoch, u64 *service, u32 *effects)
{
    struct msu_runtime_service_descriptor descriptor = {0};
    struct msu_installation_helper_lease *lease;
    struct file *executable;
    int error;
    if (!output || !epoch || !service || !effects) return -EINVAL;
    *output = NULL;
    *epoch = 0;
    *service = 0;
    *effects = 0;
    if (!host || !(host->low | host->high)) return -EINVAL;
    if (!in_task() || in_atomic() || irqs_disabled()) return -EWOULDBLOCK;
    if (!msu_runtime_layout_ready()) return -EAGAIN;
    if (msu_dynamic_current_user_ns() != &init_user_ns || __kuid_val(msu_dynamic_current_uid()) ||
        __kuid_val(msu_dynamic_current_euid())) return -EPERM;
    executable = get_task_exe_file(current);
    if (!executable) return -EPERM;
    lease = kzalloc(sizeof(*lease), GFP_KERNEL);
    if (!lease) { fput(executable); return -ENOMEM; }
    mutex_lock(&msu_installation_lock);
    if (!installation.ready || !msu_installation_host(*host) ||
        !installation.value.record.active || installation.value.flags || installation.helper_closed ||
        !installation.directory || !installation.helper ||
        msu_dynamic_file_inode(executable) != msu_dynamic_file_inode(installation.helper)) { error = -ESTALE; goto out; }
    error = msu_installation_revalidate();
    if (error) { msu_installation_observed_stale(effects); goto out; }
    if (installation.helper_leases == ~0U) { error = -EOVERFLOW; goto out; }
    if (installation.helper_service && !installation.helper_admission) { error = -ESTALE; goto out; }
    error = deny_write_access(installation.helper);
    if (error) goto out;
    if (!installation.helper_service) {
        if (msu_installation_helper_next_epoch == ~0U) {
            error = -EOVERFLOW;
            goto allow_write;
        }
        ++msu_installation_helper_next_epoch;
        descriptor.host = *host;
        descriptor.kind = MSU_RUNTIME_SERVICE_EARLY_HELPER;
        descriptor.lifecycle_owner = &installation;
        /* A lifecycle-only task service has no fabricated text entry. CORE
         * admits zero entries only for EARLY_HELPER and forbids its code use. */
        error = msu_runtime_service_register(&descriptor, &installation.helper_service);
        if (error) goto allow_write;
        installation.helper_epoch = msu_installation_helper_next_epoch;
        installation.helper_admission = true;
    }
    lease->host = *host;
    memcpy(lease->generation, installation.value.record.generation, 16);
    msu_dynamic_get_file(installation.directory);
    lease->directory = installation.directory;
    msu_dynamic_get_file(installation.helper);
    lease->helper = installation.helper;
    lease->executable = executable;
    lease->epoch = installation.helper_epoch;
    lease->service = installation.helper_service;
    ++installation.helper_leases;
    *output = lease;
    *epoch = lease->epoch;
    *service = lease->service;
    mutex_unlock(&msu_installation_lock);
    return 0;
allow_write:
    allow_write_access(installation.helper);
out:
    mutex_unlock(&msu_installation_lock);
    fput(executable);
    kfree(lease);
    return error;
}
int msu_installation_helper_validate(struct msu_installation_helper_lease *lease)
{
    int error = 0;
    if (!lease) return -EINVAL;
    if (!in_task() || in_atomic() || irqs_disabled()) return -EWOULDBLOCK;
    mutex_lock(&msu_installation_lock);
    if (!installation.ready || !msu_installation_host(lease->host) ||
        !installation.value.record.active || installation.value.flags || installation.helper_closed ||
        !installation.helper_admission || !installation.helper_leases || !lease->epoch ||
        installation.helper_epoch != lease->epoch || !lease->service ||
        installation.helper_service != lease->service ||
        installation.directory != lease->directory || installation.helper != lease->helper ||
        memcmp(lease->generation, installation.value.record.generation, 16)) error = -ESTALE;
    mutex_unlock(&msu_installation_lock);
    return error;
}
void msu_installation_helper_put(struct msu_installation_helper_lease *lease)
{
    if (!lease) return;
    allow_write_access(lease->helper);
    fput(lease->helper);
    fput(lease->executable);
    fput(lease->directory);
    /* File refs really drop before installation can finish its drain. No new
     * generation is admitted while any lease still contributes to this count. */
    mutex_lock(&msu_installation_lock);
    if (installation.helper_leases) --installation.helper_leases;
    mutex_unlock(&msu_installation_lock);
    kfree(lease);
}
int msu_installation_helper_close(const maplesu_host_instance *host, u32 *effects)
{
    int error;
    if (!host || !effects) return -EINVAL;
    if (!in_task() || in_atomic() || irqs_disabled()) return -EWOULDBLOCK;
    mutex_lock(&msu_installation_lock);
    if (!installation.ready || !msu_installation_host(*host)) error = -ESTALE;
    else {
        installation.helper_closed = true;
        error = msu_installation_helper_retire(effects);
    }
    mutex_unlock(&msu_installation_lock);
    return error;
}

static int msu_installation_enroll(struct file *executable, u32 *effects)
{
    maplesu_installation_state_v3 value = installation.value;
    struct file *directory;
    struct kstat stat;
    char path[23];
    ssize_t count;
    int error;
    memcpy(path, "/data/", 6);
    memcpy(path + 6, installation.value.name, 16);
    path[22] = 0;
    directory = msu_kernel_open_installation_path(path, true);
    if (IS_ERR(directory)) return PTR_ERR(directory);
    error = vfs_getattr(&MSU_DYN_FIELD(directory, file, f_path), &stat, STATX_BASIC_STATS, AT_STATX_SYNC_AS_STAT);
    if (error) goto out;
    count = msu_kernel_read_installation_record(directory, &value.record, sizeof(value.record));
    if (count < 0) { error = count; goto out; }
    if (count != sizeof(value.record)) { error = -EBADMSG; goto out; }
    value.device = huge_encode_dev(stat.dev);
    value.inode = stat.ino;
    error = msu_installation_commit(&value, executable, effects);
out:
    fput(directory);
    return error;
}

static bool msu_installation_boot(const char boot[40])
{
    unsigned int i;
    for (i = 0; i < 36; ++i) {
        char c = boot[i];
        if (i == 8 || i == 13 || i == 18 || i == 23) { if (c != '-') return false; }
        else if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') ||
            (c >= 'A' && c <= 'F'))) return false;
    }
    return !boot[36] && !boot[37] && !boot[38] && !boot[39];
}
int msu_installation_vendor(u64 action, u64 index,
    maplesu_installation_state_v3 *value, u32 *effects)
{
    struct file *executable;
    maplesu_installation_record_v3 next;
    int error = 0;
    if (!value || !effects) return -EINVAL;
    if (!msu_runtime_layout_ready()) return -EAGAIN;
    if (msu_dynamic_current_user_ns() != &init_user_ns || __kuid_val(msu_dynamic_current_uid()) ||
        __kuid_val(msu_dynamic_current_euid())) return -EPERM;
    executable = get_task_exe_file(current);
    if (!executable) return -EPERM;
    mutex_lock(&msu_installation_lock);
    if (!installation.ready) { error = -EOPNOTSUPP; goto out; }
    if (action == MAPLESU_INSTALLATION_READ && !installation.helper &&
        !installation.value.record.active && !installation.value.flags) {
        /* The existing boot helper can enroll only its exact protected inode.
         * Namespace comes from Image; generation comes from the held root-only
         * directory xattr. No caller-supplied path or package is trusted. */
        error = msu_installation_enroll(executable, effects);
        if (error) goto out;
    }
    if (!installation.value.record.active || installation.value.flags || !installation.helper ||
        msu_dynamic_file_inode(executable) != msu_dynamic_file_inode(installation.helper)) { error = -ESTALE; goto out; }
    error = msu_installation_revalidate();
    if (error) {
        /* A broken observed path is sticky. Keep references for explicit drain. */
        msu_installation_observed_stale(effects);
        goto out;
    }
    if (action == MAPLESU_INSTALLATION_READ) {
        *value = installation.value;
        goto out;
    }
    if (!msu_installation_expected(value) || value->device != installation.value.device ||
        value->inode != installation.value.inode ||
        !msu_installation_record(&value->record)) { error = -ESTALE; goto out; }
    if (installation.value.revision == ~0ULL) { error = -EOVERFLOW; goto out; }
    next = installation.value.record;
    if (action == MAPLESU_VENDOR_BEGIN) {
        if (index || !msu_installation_nonzero(value->record.attempt) ||
            !memcmp(next.attempt, value->record.attempt, 16) ||
            !msu_installation_boot(value->record.boot)) { error = -EINVAL; goto out; }
        memcpy(next.attempt, value->record.attempt, 16);
        memcpy(next.boot, value->record.boot, 40);
        memset(next.stages, 0, sizeof(next.stages));
    } else {
        if (index >= 3 || !msu_installation_nonzero(next.attempt)) { error = -EINVAL; goto out; }
        if (action == MAPLESU_VENDOR_BEFORE) {
            if (next.stages[index].flags || (index &&
                (next.stages[index - 1].flags != 11 || next.stages[index - 1].code))) {
                error = -EINVAL; goto out;
            }
            next.stages[index].flags = index < 2 ? 9 : 5;
            next.stages[index].code = 0;
        } else if (action == MAPLESU_VENDOR_COMPLETE) {
            if (next.stages[index].flags != (index < 2 ? 9U : 5U)) { error = -EINVAL; goto out; }
            next.stages[index].flags |= 2;
            next.stages[index].code = value->record.stages[index].code;
        } else { error = -EINVAL; goto out; }
    }
    if (memcmp(&next, &value->record, sizeof(next))) { error = -EINVAL; goto out; }
    installation.value.record = next;
    ++installation.value.revision;
    value->revision = installation.value.revision;
    *effects |= MAPLESU_EFFECT_COMMITTED;
out:
    mutex_unlock(&msu_installation_lock);
    fput(executable);
    /* The authenticated boot initializer needs the real producer result before
     * it consumes native SU. Installation mutex/executable refs are released;
     * preserve COMMITTED and the original failure instead of reporting queued
     * work as initialized. This grants no helper ALLOC/WRITE/EXEC authority. */
    if (!error && action == MAPLESU_VENDOR_BEGIN)
        error = msu_su_runtime_post_fs_data();
    return error;
}
