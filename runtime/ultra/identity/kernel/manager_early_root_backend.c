// SPDX-License-Identifier: GPL-3.0-only
#include <linux/capability.h>
#include <linux/compiler.h>
#include <linux/cred.h>
#include <linux/errno.h>
#include <linux/kallsyms.h>
#include <linux/mutex.h>
#include <linux/sched.h>
#include <linux/seccomp.h>
#include <linux/string.h>
#include <linux/uaccess.h>
#include <linux/user_namespace.h>
#include <linux/version.h>
#include "manager_early_root_backend.h"
#include "manager_management.h"
#include "manager_su_gate.h"
#include "manager_dynamic_layout.h"

#define ROOT_TARGETS 6U
#define ROOT_HIDE_NAMES 64U
#define ROOT_NAME_BYTES 256U
struct root_native_entry {
    u64 symbol, address, service, gate, gate_handle, payload, payload_handle;
    u64 publication;
    u32 target, original, prefix;
    int error;
    bool publish_attempted, published;
};
static struct {
    maplesu_host_instance host;
    unsigned long (*lookup)(const char *);
    int (*resolve_cfi)(const char *, const void *, unsigned long *);
    struct root_native_entry entries[ROOT_TARGETS];
    char hide_names[ROOT_HIDE_NAMES][ROOT_NAME_BYTES];
    u32 hide_lengths[ROOT_HIDE_NAMES], hide_count;
    unsigned char generation[16];
    bool bound, initialized, closed, hide_ready, quarantined;
} root_native;
static DEFINE_MUTEX(root_native_lock);
struct module;
typedef int (*root_each_callback_core)(void *, const char *, unsigned long);
typedef int (*root_each_callback_module)(void *, const char *, struct module *, unsigned long);
typedef int (*root_each_core_type)(root_each_callback_core, void *);
typedef int (*root_each_module_type)(root_each_callback_module, void *);
enum {
    ROOT_EACH_HAS_MODULE = __builtin_types_compatible_p(
        typeof(&kallsyms_on_each_symbol), root_each_module_type),
};
_Static_assert(ROOT_EACH_HAS_MODULE || __builtin_types_compatible_p(
    typeof(&kallsyms_on_each_symbol), root_each_core_type),
    "ROOT supported symbol enumeration prototype");
static union {
    typeof(&kallsyms_on_each_symbol) exact;
    root_each_core_type core;
    root_each_module_type module;
} root_each_symbol;
static noinline int root_each_reference_core(root_each_callback_core callback,
    void *context)
{
    return root_each_symbol.core(callback, context);
}
static noinline int root_each_reference_module(root_each_callback_module callback,
    void *context)
{
    return root_each_symbol.module(callback, context);
}
#define root_each_reference __builtin_choose_expr(ROOT_EACH_HAS_MODULE, \
    &root_each_reference_module, &root_each_reference_core)
_Static_assert(__builtin_types_compatible_p(typeof(root_each_reference),
    typeof(&kallsyms_on_each_symbol)), "ROOT symbol enumeration prototype");
struct root_symbol_search { const char *prefix; size_t length; u64 address; };
static int root_find_prefix_core(void *context, const char *name, unsigned long address)
{
    struct root_symbol_search *search = context;
    if (!strncmp(name, search->prefix, search->length)) {
        search->address = address;
        return 1; /* Same first-prefix match as m070. */
    }
    return 0;
}
static int root_find_prefix_module(void *context, const char *name,
    struct module *module, unsigned long address)
{
    (void)module;
    return root_find_prefix_core(context, name, address);
}
#define root_find_prefix __builtin_choose_expr(ROOT_EACH_HAS_MODULE, \
    &root_find_prefix_module, &root_find_prefix_core)
static u32 root_symbol_target(const char *name)
{
    if (!strcmp(name, "avc_denied")) return MSU_EARLY_ROOT_TARGET_AVC;
    if (!strcmp(name, "filldir64")) return MSU_EARLY_ROOT_TARGET_FILLDIR;
    if (!strcmp(name, "compat_filldir")) return MSU_EARLY_ROOT_TARGET_COMPAT;
    if (!strcmp(name, "hbt:filldir64")) return MSU_EARLY_ROOT_TARGET_HBT;
    if (!strcmp(name, "iterate_dir")) return MSU_EARLY_ROOT_TARGET_ITERATE;
    if (!strcmp(name, "audit_log_start")) return MSU_EARLY_ROOT_TARGET_AUDIT;
    return 0;
}
static bool root_caps_full(kernel_cap_t caps)
{
    kernel_cap_t full = CAP_FULL_SET;
    return cap_issubset(full, caps) && cap_issubset(caps, full);
}
/* Same m070/m071 qualification, using the target's real declarations rather
 * than offsets. It reads current state and leaves ordinary callers untouched. */
static bool root_eligible(void)
{
    const struct cred *cred;
    if (!msu_runtime_layout_ready()) return false;
    cred = msu_dynamic_current_cred();
    return MSU_DYN_FIELD(cred, cred, user_ns) == &init_user_ns && uid_eq(MSU_DYN_FIELD(cred, cred, uid), GLOBAL_ROOT_UID) &&
        uid_eq(MSU_DYN_FIELD(cred, cred, euid), GLOBAL_ROOT_UID) && !MSU_DYN_FIELD(cred, cred, securebits) &&
        root_caps_full(MSU_DYN_FIELD(cred, cred, cap_inheritable)) && root_caps_full(MSU_DYN_FIELD(cred, cred, cap_permitted)) &&
        root_caps_full(MSU_DYN_FIELD(cred, cred, cap_effective)) && root_caps_full(MSU_DYN_FIELD(cred, cred, cap_bset)) &&
        root_caps_full(MSU_DYN_FIELD(cred, cred, cap_ambient));
}
static int root_precheck(void *context, u32 mode, u32 exploit)
{
    if (context != &root_native || !READ_ONCE(root_native.initialized) ||
        READ_ONCE(root_native.closed)) return -ESTALE;
    if (mode > MSU_EARLY_ROOT_MODE_MAX || exploit > 31U) return -EINVAL;
    if (!root_eligible()) return -EPERM;
#ifdef CONFIG_SECCOMP
    if (READ_ONCE(MSU_DYN_FIELD(&MSU_DYN_FIELD(current, task_struct, seccomp), seccomp, mode))) return -EPERM;
#endif
    return 0;
}
static u64 root_before(struct msu_su_gate_frame *frame, const void *context)
{
    const struct root_native_entry *entry = context;
    u32 i, length;
    char name[ROOT_NAME_BYTES];
    if (!frame || entry < root_native.entries ||
        entry >= root_native.entries + ROOT_TARGETS ||
        !READ_ONCE(root_native.initialized) || READ_ONCE(root_native.closed)) return 0;
    if (entry->target == MSU_EARLY_ROOT_TARGET_AVC ||
        entry->target == MSU_EARLY_ROOT_TARGET_AUDIT) {
        if (!root_eligible()) return 0;
        frame->x[0] = 0;
        return 1;
    }
    if (entry->target != MSU_EARLY_ROOT_TARGET_FILLDIR &&
        entry->target != MSU_EARLY_ROOT_TARGET_COMPAT &&
        entry->target != MSU_EARLY_ROOT_TARGET_HBT) return 0;
    length = (u32)frame->x[2];
    if (!length || length >= sizeof(name)) return 0;
    for (i = 0; i < root_native.hide_count; ++i) {
        if (length != root_native.hide_lengths[i]) continue;
        if (copy_from_kernel_nofault(name, (void *)(unsigned long)frame->x[1], length)) return 0;
        if (memcmp(name, root_native.hide_names[i], length)) continue;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 1, 0)
        frame->x[0] = 1;
#else
        frame->x[0] = 0;
#endif
        return 1;
    }
    return 0;
}
static int root_resolve(void *context, const char *name, u32 match_mode, u64 *address)
{
    struct root_symbol_search search;
    unsigned long resolved = 0;
    u32 target;
    int error = 0;
    if (!address) return -EINVAL;
    *address = 0;
    if (context != &root_native || !name || match_mode > 2U) return -EINVAL;
    target = root_symbol_target(name);
    if (!target || (match_mode == 1U && target != MSU_EARLY_ROOT_TARGET_COMPAT)) return -EPERM;
    mutex_lock(&root_native_lock);
    if (!root_native.initialized || root_native.closed) { error = -ESTALE; goto out; }
    resolved = root_native.lookup(name);
    if (!resolved && match_mode == 1U) {
        if (!root_each_symbol.exact) {
            error = root_native.resolve_cfi("kallsyms_on_each_symbol",
                (const void *)root_each_reference, &resolved);
            if (error || !resolved) { error = error ? error : -ENOENT; goto out; }
            root_each_symbol.exact = (typeof(root_each_symbol.exact))resolved;
        }
        memset(&search, 0, sizeof(search)); search.prefix = name; search.length = strlen(name);
        error = root_each_symbol.exact(root_find_prefix, &search);
        if (error && (error != 1 || !search.address)) goto out;
        error = 0;
        resolved = search.address;
    }
    if (!resolved) { error = -ENOENT; goto out; }
    if ((resolved & 3U) || resolved > ~0ULL - 8U) { error = -EFAULT; goto out; }
    root_native.entries[target - 1U].symbol = resolved;
    root_native.entries[target - 1U].target = target;
    *address = resolved;
out:
    mutex_unlock(&root_native_lock);
    return error;
}
static int root_read_word(void *context, u64 address, u32 *word)
{
    u32 i;
    if (context != &root_native || !word) return -EINVAL;
    for (i = 0; i < ROOT_TARGETS; ++i)
        if (root_native.entries[i].symbol == address && address)
            return copy_from_kernel_nofault(word, (void *)(unsigned long)address,
                sizeof(*word)) ? -EFAULT : 0;
    return -EPERM;
}
static bool root_prefix(u32 word)
{
    return word == 0xd503231fU || word == 0xd503233fU ||
        word == 0xd503235fU || word == 0xd503237fU ||
        (word & 0xffffff3fU) == 0xd503241fU;
}
static int root_names(const char *const *names, u32 count)
{
    u32 i, length;
    if (count > ROOT_HIDE_NAMES || (count && !names)) return -EINVAL;
    if (root_native.hide_ready && count != root_native.hide_count) return -ESTALE;
    for (i = 0; i < count; ++i) {
        if (!names[i]) return -EINVAL;
        length = strnlen(names[i], ROOT_NAME_BYTES);
        if (!length || length == ROOT_NAME_BYTES) return -EINVAL;
        if (root_native.hide_ready) {
            if (root_native.hide_lengths[i] != length ||
                memcmp(root_native.hide_names[i], names[i], length + 1)) return -ESTALE;
        } else {
            memcpy(root_native.hide_names[i], names[i], length + 1);
            root_native.hide_lengths[i] = length;
        }
    }
    if (!root_native.hide_ready) { root_native.hide_count = count; root_native.hide_ready = true; }
    return 0;
}
static int root_publish(struct root_native_entry *entry)
{
    struct msu_runtime_service_descriptor descriptor = {0};
    maplesu_publication_member_v3 members[2] = {0};
    maplesu_publication_prepare_v3 prepare = {0};
    maplesu_publication_control_v3 control;
    maplesu_response_owner_v3 response = {0};
    u32 gate[MSU_SU_GATE_BYTES / 4], payload[MSU_SU_PAYLOAD_BYTES / 4], written;
    int error;
    entry->address = entry->symbol;
    if (copy_from_kernel_nofault(&entry->original, (void *)(unsigned long)entry->address, 4)) return -EFAULT;
    if (root_prefix(entry->original)) {
        entry->prefix = entry->original; entry->address += 4;
        if (copy_from_kernel_nofault(&entry->original, (void *)(unsigned long)entry->address, 4)) return -EFAULT;
    }
    if (!msu_su_gate_instruction(entry->original)) return -EOPNOTSUPP;
    descriptor.host = root_native.host; descriptor.kind = MSU_RUNTIME_SERVICE_EARLY_FIXED;
    descriptor.lifecycle_owner = &root_native; descriptor.entries = &entry->address; descriptor.entry_count = 1;
    error = msu_runtime_service_register(&descriptor, &entry->service);
    if (error) return error;
    error = msu_runtime_service_alloc(&root_native.host, entry->service, &root_native,
        MSU_SU_GATE_BYTES, true, entry->address, &response);
    if (error) return error;
    entry->gate_handle = response.metadata_address; entry->gate = response.result;
    error = msu_runtime_service_alloc(&root_native.host, entry->service, &root_native,
        MSU_SU_PAYLOAD_BYTES, true, 0, &response);
    if (error) return error;
    entry->payload_handle = response.metadata_address; entry->payload = response.result;
    members[0].handle = entry->gate_handle; members[0].role = MAPLESU_PUBLICATION_GATE_CODE;
    members[1].handle = entry->payload_handle; members[1].role = MAPLESU_PUBLICATION_PAYLOAD_CODE;
    prepare.member_count = 2; prepare.gate_index = 0; prepare.entry_address = entry->address;
    prepare.expected_instruction = entry->original; prepare.payload_entry = entry->payload;
    error = msu_runtime_service_prepare(&root_native.host, entry->service, &root_native,
        &prepare, members, &response);
    if (error) return error;
    entry->publication = response.result;
    if (!response.metadata_address || copy_from_kernel_nofault(&control,
            (void *)(unsigned long)response.metadata_address, sizeof(control))) return -EFAULT;
    error = msu_su_gate_build(gate, sizeof(gate), entry->gate, &control,
        entry->original, entry->prefix, &written);
    if (error) return error;
    error = msu_su_payload_build(payload, sizeof(payload),
        (u64)(unsigned long)root_before, (u64)(unsigned long)entry);
    if (error) return error;
    error = msu_runtime_service_write(&root_native.host, entry->service, &root_native,
        entry->payload_handle, 0, payload, sizeof(payload), &response);
    if (error) return error;
    error = msu_runtime_service_write(&root_native.host, entry->service, &root_native,
        entry->gate_handle, 0, gate, sizeof(gate), &response);
    if (error) return error;
    entry->publish_attempted = true;
    error = msu_runtime_service_publish(&root_native.host, entry->service, &root_native,
        entry->publication, &response);
    if (!error) entry->published = true;
    return error;
}
static int root_patch(void *context, u32 target, const u64 *addresses,
    u32 count, const char *const *names, u32 hide_count, u64 *value)
{
    struct root_native_entry *entry;
    u32 effects = 0;
    int error, cleanup;
    if (value) *value = 0;
    if (context != &root_native || !addresses || !value || !target || target > ROOT_TARGETS ||
        target == MSU_EARLY_ROOT_TARGET_ITERATE || count != 1U) return -EINVAL;
    mutex_lock(&root_native_lock);
    entry = &root_native.entries[target - 1U];
    if (!root_native.initialized || root_native.closed) { error = -ESTALE; goto out; }
    if (root_native.quarantined) { error = -EIO; goto out; }
    if (!entry->symbol || addresses[0] != entry->symbol) { error = -EPERM; goto out; }
    if (entry->error) { error = entry->error; goto out; }
    error = root_names(names, hide_count);
    if (error) goto out;
    if (entry->published) { *value = entry->publication; error = 0; goto out; }
    error = root_publish(entry);
    if (error) {
        entry->error = error;
        if (entry->service) {
            cleanup = entry->publish_attempted ?
                msu_runtime_service_revoke(&root_native.host, entry->service, &effects) :
                msu_runtime_service_abort_unexposed(&root_native.host, entry->service, &root_native, &effects);
            if (!cleanup) entry->service = 0;
            else root_native.quarantined = cleanup != -EINPROGRESS;
        }
    } else *value = entry->publication;
out:
    mutex_unlock(&root_native_lock);
    return error;
}
static int root_revoke(void *context, u32 *effects)
{
    u32 i, local;
    int error = 0, result;
    if (effects) *effects = 0;
    if (context != &root_native) return -EINVAL;
    mutex_lock(&root_native_lock);
    WRITE_ONCE(root_native.closed, true);
    for (i = 0; i < ROOT_TARGETS; ++i) {
        struct root_native_entry *entry = &root_native.entries[i];
        if (!entry->service) continue;
        local = 0;
        result = entry->publish_attempted ?
            msu_runtime_service_revoke(&root_native.host, entry->service, &local) :
            msu_runtime_service_abort_unexposed(&root_native.host, entry->service, &root_native, &local);
        if (effects) *effects |= local;
        if (!result) entry->service = 0;
        else if (!error || error == -EINPROGRESS) error = result;
        if (result && result != -EINPROGRESS) root_native.quarantined = true;
    }
    if (root_native.quarantined) {
        if (!error) error = -EIO;
        if (effects) *effects |= MAPLESU_EFFECT_QUARANTINED;
    }
    if (effects) *effects |= error ? MAPLESU_EFFECT_PENDING : MAPLESU_EFFECT_RELEASED;
    mutex_unlock(&root_native_lock);
    return error;
}
static int root_discarded(void *context)
{
    u32 i;
    int error = 0;
    if (context != &root_native) return -EINVAL;
    mutex_lock(&root_native_lock);
    if (!root_native.closed || root_native.quarantined) error = -EINPROGRESS;
    for (i = 0; i < ROOT_TARGETS; ++i)
        if (root_native.entries[i].service) error = -EINPROGRESS;
    if (!error) {
        root_native.initialized = false;
        memset(root_native.entries, 0, sizeof(root_native.entries));
        memset(root_native.hide_names, 0, sizeof(root_native.hide_names));
        memset(root_native.hide_lengths, 0, sizeof(root_native.hide_lengths));
        memset(root_native.generation, 0, sizeof(root_native.generation));
        root_native.hide_ready = false; root_native.hide_count = 0;
    }
    mutex_unlock(&root_native_lock);
    return error;
}
int msu_early_root_backend_target_bind(unsigned long (*lookup)(const char *),
    int (*resolve_cfi)(const char *, const void *, unsigned long *))
{
    int error = 0;
    if (!lookup || !resolve_cfi) return -EINVAL;
    mutex_lock(&root_native_lock);
    if (root_native.bound) error = -EALREADY;
    else { root_native.lookup = lookup; root_native.resolve_cfi = resolve_cfi; root_native.bound = true; }
    mutex_unlock(&root_native_lock);
    return error;
}
int msu_early_root_backend_create(const maplesu_host_instance *host,
    const struct msu_deployment_namespace_record *deployment,
    const unsigned char generation[16], struct msu_early_root_ops *ops)
{
    unsigned int i;
    bool nonzero = false;
    int error = 0;
    if (!ops) return -EINVAL;
    memset(ops, 0, sizeof(*ops));
    if (!msu_runtime_layout_ready()) return -EAGAIN;
    if (!host || !(host->low | host->high) || !generation ||
        !msu_deployment_namespace_valid(deployment)) return -EINVAL;
    for (i = 0; i < 16; ++i) nonzero |= generation[i] != 0;
    if (!nonzero) return -ESTALE;
    mutex_lock(&root_native_lock);
    if (!root_native.bound) error = -EAGAIN;
    else if (root_native.initialized) error = -EBUSY;
    else {
        root_native.host = *host; memcpy(root_native.generation, generation, 16);
        root_native.closed = false; root_native.initialized = true;
        ops->context = &root_native; ops->resolve = root_resolve; ops->read_word = root_read_word;
        ops->credential_precheck = root_precheck; ops->patch = root_patch;
        ops->revoke = root_revoke; ops->discarded = root_discarded;
    }
    mutex_unlock(&root_native_lock);
    return error;
}
