// SPDX-License-Identifier: GPL-2.0-only
#include <linux/errno.h>
#include <linux/mutex.h>
#include <linux/string.h>
#include <linux/types.h>
#include <linux/uaccess.h>
#include <linux/compiler.h>
#include <asm/ptrace.h>

#include "manager_early_oem.h"
#include "manager_management.h"
#include "manager_su_gate.h"
#include "manager_deployment_namespace.h"

/* KModErr values are part of the existing SDK result ABI.  This provider does
 * not include the C++ module header, but preserves its numeric contract. */
#define OEM_OK 0
#define OEM_ERR_NOT_KADDR (-20013)
#define OEM_ERR_SYMBOL_PARAM (-20021)
#define OEM_ERR_SYMBOL_NOT_EXIST (-20022)
#define OEM_ERR_HOOK_INSN_NOT_SUPPORT (-20029)
#define OEM_ERR_DUPLICATE (-20020)
#define OEM_ERR_STORAGE_WRITE (-20037)

#define OEM_MAX_TARGETS 24U
#define OEM_MAX_BYTES 8U

struct oem_entry {
    u64 address;
    u32 original;
    u32 prefix;
    u64 gate;
    u64 gate_handle;
    u64 payload;
    u64 payload_handle;
    u64 publication;
    bool publish_attempted, published;
};

struct oem_byte_backup {
    u64 address;
    u8 original;
    u8 replacement;
    bool changed;
};

static struct {
    maplesu_host_instance host;
    struct msu_deployment_namespace_record deployment;
    unsigned long (*lookup)(const char *);
    int (*resolve_cfi)(const char *, const void *, unsigned long *);
    struct oem_entry entries[OEM_MAX_TARGETS];
    struct oem_byte_backup bytes[OEM_MAX_BYTES];
    u32 count, byte_count;
    u64 service;
    u32 operation;
    u32 inflight;
    unsigned char generation[16];
    bool bound, initialized, active, closed, quarantined;
} oem;
static DEFINE_MUTEX(oem_lock);

/* Fixed callback: all supported OEM bypass handlers return zero and skip the
 * original body.  It owns no borrowed pointer and runs without provider locks. */
static u64 oem_return_zero(struct msu_su_gate_frame *frame, const void *context)
{
    (void)context;
    if (!frame) return 0;
    frame->x[0] = 0;
    return 1;
}

static long oem_cfi_reference(const struct pt_regs *regs)
{
    return regs ? -EOPNOTSUPP : -EINVAL;
}

static bool pac_or_bti(u32 word)
{
    return word == 0xd503231fU || word == 0xd503233fU ||
        word == 0xd503235fU || word == 0xd503237fU ||
        (word & 0xffffff3fU) == 0xd503241fU;
}

static int result_error(struct msu_early_fixed_result *result, int native,
    s64 code, u32 effects)
{
    if (result) {
        memset(result, 0, sizeof(*result));
        result->native_errno = native;
        result->code = code;
        result->effects = effects;
    }
    return native;
}

static void result_ok(struct msu_early_fixed_result *result, u32 effects,
    u64 value)
{
    memset(result, 0, sizeof(*result));
    result->effects = effects;
    result->values[0] = value;
}

static int lookup_optional(const char *name, u64 *address)
{
    unsigned long value;
    if (!name || !address || !oem.lookup) return -EINVAL;
    value = oem.lookup(name);
    if (!value) {
        *address = 0;
        return 0;
    }
    *address = (u64)value;
    if ((*address & 3U) || *address > ~0ULL - 4)
        return -EFAULT;
    return 0;
}

static int qualify_native_bind(unsigned long (*lookup)(const char *),
    int (*resolve_cfi)(const char *, const void *, unsigned long *))
{
    unsigned long anchor = 0;
    unsigned long cfi = 0;
    /* Both calls are real resolver qualifications; no result is retained as a
     * target until the operation-specific symbol set is selected. */
    anchor = lookup("schedule_work");
    if (!anchor) anchor = lookup("wake_up_process");
    if (!anchor) return -ENOENT;
    if (resolve_cfi("__arm64_sys_setresuid", (const void *)oem_cfi_reference, &cfi) || !cfi)
        return -ENOENT;
    return 0;
}

static int add_target(u64 address)
{
    u32 i;
    if (!address) return 0;
    for (i = 0; i < oem.count; ++i)
        if (oem.entries[i].address == address) return 0;
    if (oem.count == OEM_MAX_TARGETS) return -EOVERFLOW;
    oem.entries[oem.count++].address = address;
    return 0;
}

static int read_targets(void)
{
    u32 i;
    int error;
    for (i = 0; i < oem.count; ++i) {
        u32 word;
        struct oem_entry *entry = &oem.entries[i];
        if (copy_from_kernel_nofault(&word, (void *)(unsigned long)entry->address,
                sizeof(word))) return -EFAULT;
        entry->prefix = 0;
        if (pac_or_bti(word)) {
            entry->prefix = word;
            entry->address += 4;
            if (copy_from_kernel_nofault(&word,
                    (void *)(unsigned long)entry->address, sizeof(word))) return -EFAULT;
        }
        if (!msu_su_gate_instruction(word)) return -EOPNOTSUPP;
        entry->original = word;
        error = 0;
        if (entry->address & 3U) error = -EINVAL;
        if (error) return error;
    }
    return 0;
}

static int collect_symbols(u32 operation)
{
    static const char *const mtk[] = {
        "pkvm_mkp:handle_mkp_err_action", "mkp:handle_mkp_err_action",
        "handle_mkp_err_action",
    };
    static const char *const guard[] = {
        "oplus_exe_block_ret_handler", "oplus_harden_pre_handler",
        "oplus_root_check_post_handler", "oplus_root_check_succ_upload",
        "oplus_root_check_succ", "oplus_report_execveat_new",
        "do_execveat_common_entry_handler", "report_security_event",
        "oplus_secure_harden_kevent", "oplus_check_execveat_perm",
        "oplus_exec_block", "oplus_root_reboot", "oplus_secure_guard:handler_pre",
        "oplus_secure_guard_new:handler_pre", "oplus_security_guard:handler_pre",
        "oplus_secure_guard:uid_ret_handler", "oplus_secure_guard_new:uid_ret_handler",
        "oplus_security_guard:uid_ret_handler",
    };
    static const char *const inte[] = {
        "inte:add_ko_event", "inte:add_systbl_event", "inte:ko_proc_show",
        "inte:systbl_proc_show",
    };
    const char *const *names = NULL;
    u32 count = 0, i;
    if (operation == MSU_EARLY_FIXED_OEM_MTK) { names = mtk; count = ARRAY_SIZE(mtk); }
    else if (operation == MSU_EARLY_FIXED_OEM_OPLUS_GUARD) { names = guard; count = ARRAY_SIZE(guard); }
    else if (operation == MSU_EARLY_FIXED_OEM_OPLUS_INTE) { names = inte; count = ARRAY_SIZE(inte); }
    else return -EINVAL;
    oem.count = 0;
    for (i = 0; i < count; ++i) {
        u64 address = 0;
        int error = lookup_optional(names[i], &address);
        if (error) return error;
        error = add_target(address);
        if (error) return error;
    }
    if (operation == MSU_EARLY_FIXED_OEM_OPLUS_GUARD) {
        static const char *const state_names[] = {
            "oplus_secure_guard:g_boot_state", "oplus_secure_guard_new:g_boot_state",
            "oplus_security_guard:g_boot_state",
        };
        oem.byte_count = 0;
        for (i = 0; i < ARRAY_SIZE(state_names); ++i) {
            u64 address = 0;
            u8 value;
            int state_error = lookup_optional(state_names[i], &address);
            if (state_error) return state_error;
            if (!address) continue;
            if (oem.byte_count == OEM_MAX_BYTES) return -EOVERFLOW;
            if (copy_from_kernel_nofault(&value, (void *)(unsigned long)address,
                    sizeof(value))) return -EFAULT;
            oem.bytes[oem.byte_count].address = address;
            oem.bytes[oem.byte_count].original = value;
            ++oem.byte_count;
        }
    } else {
        oem.byte_count = 0;
    }
    return read_targets();
}

static int apply_state_bytes(void)
{
    u32 i;
    for (i = 0; i < oem.byte_count; ++i) {
        struct oem_byte_backup *backup = &oem.bytes[i];
        u8 zero = 0, observed;
        if (backup->original == 0) continue;
        if (copy_to_kernel_nofault((void *)(unsigned long)backup->address,
                &zero, sizeof(zero))) return -EFAULT;
        backup->replacement = zero;
        backup->changed = true;
        if (copy_from_kernel_nofault(&observed,
                (void *)(unsigned long)backup->address, sizeof(observed))) return -EFAULT;
        if (observed != zero) return -EIO;
    }
    return 0;
}

static int publish_entries(void)
{
    struct msu_runtime_service_descriptor descriptor = {0};
    u64 addresses[OEM_MAX_TARGETS];
    u32 i, written;
    int error;
    maplesu_response_owner_v3 response;
    if (!oem.count) return 0;
    for (i = 0; i < oem.count; ++i) addresses[i] = oem.entries[i].address;
    descriptor.host = oem.host;
    descriptor.kind = MSU_RUNTIME_SERVICE_EARLY_FIXED;
    descriptor.lifecycle_owner = &oem;
    descriptor.entries = addresses;
    descriptor.entry_count = oem.count;
    error = msu_runtime_service_register(&descriptor, &oem.service);
    if (error) return error;
    for (i = 0; i < oem.count; ++i) {
        struct oem_entry *entry = &oem.entries[i];
        maplesu_publication_member_v3 members[2] = {0};
        maplesu_publication_prepare_v3 prepare = {0};
        maplesu_publication_control_v3 control = {0};
        u32 gate[MSU_SU_GATE_BYTES / 4], payload[MSU_SU_PAYLOAD_BYTES / 4];
        error = msu_runtime_service_alloc(&oem.host, oem.service, &oem,
            MSU_SU_GATE_BYTES, true, entry->address, &response);
        entry->gate_handle = response.metadata_address;
        entry->gate = response.result;
        if (error) return error;
        error = msu_runtime_service_alloc(&oem.host, oem.service, &oem,
            MSU_SU_PAYLOAD_BYTES, true, 0, &response);
        entry->payload_handle = response.metadata_address;
        entry->payload = response.result;
        if (error) return error;
        members[0].handle = entry->gate_handle;
        members[0].role = MAPLESU_PUBLICATION_GATE_CODE;
        members[1].handle = entry->payload_handle;
        members[1].role = MAPLESU_PUBLICATION_PAYLOAD_CODE;
        prepare.member_count = 2;
        prepare.gate_index = 0;
        prepare.entry_address = entry->address;
        prepare.expected_instruction = entry->original;
        prepare.payload_entry = entry->payload;
        error = msu_runtime_service_prepare(&oem.host, oem.service, &oem,
            &prepare, members, &response);
        entry->publication = response.result;
        if (error) return error;
        if (!response.metadata_address || copy_from_kernel_nofault(&control,
                (void *)(unsigned long)response.metadata_address, sizeof(control)))
            return -EFAULT;
        error = msu_su_gate_build(gate, sizeof(gate), entry->gate, &control,
            entry->original, entry->prefix, &written);
        if (error) return error;
        error = msu_su_payload_build(payload, sizeof(payload),
            (u64)(unsigned long)oem_return_zero, (u64)(unsigned long)&oem);
        if (error) return error;
        error = msu_runtime_service_write(&oem.host, oem.service, &oem,
            entry->payload_handle, 0, payload, sizeof(payload), &response);
        if (error) return error;
        error = msu_runtime_service_write(&oem.host, oem.service, &oem,
            entry->gate_handle, 0, gate, sizeof(gate), &response);
        if (error) return error;
    }
    for (i = 0; i < oem.count; ++i) {
        struct oem_entry *entry = &oem.entries[i];
        entry->publish_attempted = true;
        error = msu_runtime_service_publish(&oem.host, oem.service, &oem,
            entry->publication, &response);
        if (error) return error;
        entry->published = true;
    }
    return 0;
}

/* Called only after admission is closed and inflight is zero.  It performs all
 * management/service callbacks without oem_lock, then returns the real drain
 * status. */
static int revoke_unlocked(u32 *effects)
{
    u32 local = 0, i;
    int error = 0;
    bool publish_attempted = false;
    for (i = 0; i < oem.count; ++i)
        publish_attempted |= oem.entries[i].publish_attempted;
    if (oem.service) {
        error = publish_attempted ?
            msu_runtime_service_revoke(&oem.host, oem.service, &local) :
            msu_runtime_service_abort_unexposed(&oem.host, oem.service, &oem, &local);
        if (error && error != -EINPROGRESS) oem.quarantined = true;
        if (!error) oem.service = 0;
    }
    if (local) *effects |= local;
    for (i = 0; i < oem.byte_count; ++i) {
        struct oem_byte_backup *backup = &oem.bytes[i];
        u8 observed;
        if (!backup->changed) continue;
        if (copy_from_kernel_nofault(&observed,
                (void *)(unsigned long)backup->address, sizeof(observed))) {
            oem.quarantined = true;
            error = error ? error : -EFAULT;
            continue;
        }
        if (observed != backup->replacement) {
            oem.quarantined = true;
            error = error ? error : -ESTALE;
            continue;
        }
        if (copy_to_kernel_nofault((void *)(unsigned long)backup->address,
                &backup->original, sizeof(backup->original))) {
            oem.quarantined = true;
            error = error ? error : -EIO;
            continue;
        }
        backup->changed = false;
        *effects |= MAPLESU_EFFECT_RELEASED;
    }
    if (!error && !oem.quarantined) *effects |= MAPLESU_EFFECT_RELEASED;
    if (oem.quarantined) *effects |= MAPLESU_EFFECT_QUARANTINED;
    if (error == -EINPROGRESS || oem.quarantined) *effects |= MAPLESU_EFFECT_PENDING;
    return error;
}

static bool oem_fixed_validate(const struct msu_early_fixed_provider *provider)
{
    return provider && provider->generation_valid && (provider->host.low | provider->host.high);
}
static int oem_fixed_operation(struct msu_early_fixed_provider *provider, u32 operation,
    u32 mode, u32 exploit, u64 value, struct msu_early_fixed_result *result)
{
    (void)provider;
    return msu_early_oem_operation(operation, mode, exploit, value, result);
}
static int oem_fixed_revoke(struct msu_early_fixed_provider *provider,
    const unsigned char generation[16], u32 *effects)
{
    return msu_early_oem_revoke((void *)&oem, &provider->host, generation, effects);
}
static int oem_fixed_close(struct msu_early_fixed_provider *provider, u32 *effects)
{
    (void)provider;
    return msu_early_oem_close(effects);
}
static struct msu_early_fixed_provider oem_fixed_provider;

int msu_early_oem_target_bind(unsigned long (*lookup)(const char *),
    int (*resolve_cfi)(const char *, const void *, unsigned long *))
{
    int error = 0;
    mutex_lock(&oem_lock);
    if (oem.bound) error = -EALREADY;
    else if (!lookup || !resolve_cfi) error = -EINVAL;
    else {
        error = qualify_native_bind(lookup, resolve_cfi);
        if (!error) {
            oem.lookup = lookup; oem.resolve_cfi = resolve_cfi; oem.bound = true;
        }
    }
    mutex_unlock(&oem_lock);
    return error;
}

int msu_early_oem_init(const maplesu_host_instance *host, const void *deployment,
    const unsigned char generation[16])
{
    int error = 0;
    mutex_lock(&oem_lock);
    if (!oem.bound || !host || !(host->low | host->high) ||
        !deployment || !msu_deployment_namespace_valid(deployment) ||
        !generation || !memchr_inv(generation, 0, 16)) error = -EINVAL;
    else if (oem.initialized && !oem.closed) error = -EALREADY;
    else {
        memset(oem.entries, 0, sizeof(oem.entries));
        memset(oem.bytes, 0, sizeof(oem.bytes));
        oem.host = *host; oem.deployment = *(const struct msu_deployment_namespace_record *)deployment;
        memcpy(oem.generation, generation, 16);
        oem.byte_count = 0; oem.service = 0; oem.operation = 0;
        oem.initialized = true; oem.active = false; oem.closed = false; oem.quarantined = false;
    }
    mutex_unlock(&oem_lock);
    if (!error) {
        memset(&oem_fixed_provider, 0, sizeof(oem_fixed_provider));
        oem_fixed_provider.host = *host;
        memcpy(oem_fixed_provider.generation, generation, 16);
        oem_fixed_provider.generation_valid = true;
        oem_fixed_provider.owner = &oem;
        oem_fixed_provider.deployment = deployment;
        oem_fixed_provider.validate = oem_fixed_validate;
        oem_fixed_provider.operation = oem_fixed_operation;
        oem_fixed_provider.revoke = oem_fixed_revoke;
        oem_fixed_provider.close = oem_fixed_close;
        error = msu_early_fixed_provider_register(MSU_EARLY_FIXED_OEM_MTK,
            MSU_EARLY_FIXED_OEM_OPLUS_INTE, &oem_fixed_provider);
    }
    return error;
}

int msu_early_oem_operation(u32 operation, u32 mode, u32 exploit, u64 value,
    struct msu_early_fixed_result *result)
{
    int error;
    u32 effects = MSU_EARLY_FIXED_EFFECT_ATTEMPTED;
    if (!result) return -EINVAL;
    memset(result, 0, sizeof(*result));
    mutex_lock(&oem_lock);
    if (!oem.initialized || oem.closed || oem.quarantined) {
        error = -ESHUTDOWN;
        goto out_error;
    }
    if (mode > MAPLESU_EARLY_FIXED_MODE_MAX || exploit > MAPLESU_EARLY_FIXED_EXPLOIT_MAX) {
        error = -EINVAL;
        goto out_error;
    }
    if (oem.active || oem.inflight) {
        error = -EBUSY;
        goto out_error;
    }
    oem.inflight = 1;
    mutex_unlock(&oem_lock);
    /* The provider admission is now held by this operation only.  No service
     * callback is made while oem_lock (or a registry lock) is held. */
    error = collect_symbols(operation);
    if (!error) error = apply_state_bytes();
    if (!error) error = publish_entries();
    if (!error) {
        bool closing;
        mutex_lock(&oem_lock);
        closing = oem.closed;
        mutex_unlock(&oem_lock);
        if (closing) {
            u32 ignored = 0;
            error = revoke_unlocked(&ignored);
        }
    }
    if (error) {
        u32 ignored = 0;
        int cleanup = revoke_unlocked(&ignored);
        mutex_lock(&oem_lock);
        oem.inflight = 0;
        oem.active = false;
        if (cleanup) oem.closed = true;
        mutex_unlock(&oem_lock);
        return result_error(result, error, error == -ENOENT ? OEM_ERR_SYMBOL_NOT_EXIST :
            (error == -EOPNOTSUPP ? OEM_ERR_HOOK_INSN_NOT_SUPPORT : OEM_ERR_NOT_KADDR), effects);
    }
    mutex_lock(&oem_lock);
    oem.operation = operation;
    oem.active = true;
    oem.inflight = 0;
    if (oem.count || oem.byte_count) effects |= MSU_EARLY_FIXED_EFFECT_READBACK;
    {
        u32 i;
        for (i = 0; i < oem.count; ++i)
            if (oem.entries[i].published) effects |= MSU_EARLY_FIXED_EFFECT_APPLIED;
        for (i = 0; i < oem.byte_count; ++i)
            if (oem.bytes[i].changed) effects |= MSU_EARLY_FIXED_EFFECT_APPLIED;
    }
    result_ok(result, effects, oem.count);
    mutex_unlock(&oem_lock);
    return 0;
out_error:
    mutex_unlock(&oem_lock);
    return result_error(result, error, error == -ENOENT ? OEM_ERR_SYMBOL_NOT_EXIST :
        (error == -EOPNOTSUPP ? OEM_ERR_HOOK_INSN_NOT_SUPPORT : OEM_ERR_NOT_KADDR), effects);
}

int msu_early_oem_revoke(void *context, const maplesu_host_instance *host,
    const unsigned char generation[16], u32 *effects)
{
    int error;
    bool busy;
    if (!effects) return -EINVAL;
    *effects = 0;
    mutex_lock(&oem_lock);
    if (context && context != &oem) { mutex_unlock(&oem_lock); return -ESTALE; }
    if (!host || host->low != oem.host.low || host->high != oem.host.high ||
        !generation || memcmp(generation, oem.generation, 16)) {
        mutex_unlock(&oem_lock); return -ESTALE;
    }
    busy = oem.inflight != 0;
    if (busy) oem.closed = true;
    mutex_unlock(&oem_lock);
    if (busy) {
        *effects |= MAPLESU_EFFECT_PENDING;
        return -EINPROGRESS;
    }
    error = revoke_unlocked(effects);
    mutex_lock(&oem_lock);
    if (!error) { oem.active = false; oem.closed = true; }
    mutex_unlock(&oem_lock);
    return error;
}

int msu_early_oem_close(u32 *effects)
{
    int error;
    if (!effects) return -EINVAL;
    *effects = 0;
    mutex_lock(&oem_lock);
    oem.closed = true;
    if (oem.inflight) {
        *effects |= MAPLESU_EFFECT_PENDING;
        mutex_unlock(&oem_lock);
        return -EINPROGRESS;
    }
    mutex_unlock(&oem_lock);
    error = revoke_unlocked(effects);
    mutex_lock(&oem_lock);
    if (!error) oem.active = false;
    mutex_unlock(&oem_lock);
    return error;
}

int msu_early_oem_discarded(void)
{
    int discarded;
    mutex_lock(&oem_lock);
    discarded = !oem.initialized || (!oem.active && !oem.service && !oem.quarantined);
    mutex_unlock(&oem_lock);
    return discarded;
}
