// SPDX-License-Identifier: GPL-3.0-only
#include <linux/errno.h>
#include <linux/compiler.h>
#include <linux/mm.h>
#include <linux/mutex.h>
#include <linux/string.h>
#include <linux/uaccess.h>
#include <linux/vmalloc.h>
#include "manager_early_selinux_backend.h"
#include "manager_deployment_namespace.h"
#include "manager_management.h"
#include "manager_su_gate.h"

struct selinux_state;
struct early_status { u32 version, sequence, enforcing, policyload, deny_unknown; };
struct early_entry {
    u64 address, gate, gate_handle, payload, payload_handle, publication;
    u32 instruction, prefix;
};
static DEFINE_MUTEX(backend_lock);
static struct {
    maplesu_host_instance host;
    struct msu_deployment_namespace_record deployment;
    unsigned char generation[16];
    unsigned long state_address, page_address, setenforce, policyload, lock_address;
    u32 lock_offset;
    bool state_argument, bound, initialized, closed, prepared;
    struct early_status *status;
    struct page *page;
    struct early_entry entries[2];
    u64 service, shared_id, shared_address;
} backend;

/* The same bounded native anchor grammar as root-loader/selinux_hide_abi.h.
 * No offset or ABI supplied by a user request is accepted. */
static int lock_anchor(const u32 *code, u64 address, u64 mutex, u64 state,
    u32 *offset, bool *argument)
{
    u64 value[31] = {0};
    u32 known[31] = {0}, i;
    known[0] = 1;
    for (i = 0; i < 16; ++i) {
        u32 word = code[i], rd = word & 31U, rn = (word >> 5) & 31U;
        if ((word & 0xfc000000U) == 0x94000000U) {
            s64 relative = word & 0x3ffffffU;
            u64 lock;
            if (relative & 0x2000000) relative -= 0x4000000;
            if (address + i * 4 + relative * 4 != mutex) return -EOPNOTSUPP;
            if (known[0] == 1) lock = value[0];
            else if (known[0] == 2 && state && value[0] >= state) lock = value[0] - state;
            else return -EOPNOTSUPP;
            if (lock < 8 || lock > 65536 || (lock & 7)) return -EOPNOTSUPP;
            *offset = lock; *argument = known[0] == 1;
            return 0;
        }
        if (((word & 0x9f000000U) == 0x90000000U ||
             (word & 0x9f000000U) == 0x10000000U) && rd < 31) {
            s64 relative = ((word >> 29) & 3U) | ((s64)((word >> 5) & 0x7ffffU) << 2);
            if (relative & 0x100000) relative -= 0x200000;
            value[rd] = (word & 0x80000000U) ?
                ((address + i * 4) & ~4095ULL) + relative * 4096 : address + i * 4 + relative;
            known[rd] = 2;
        } else if ((word & 0xff000000U) == 0x91000000U && rd < 31) {
            known[rd] = rn < 31 ? known[rn] : 0;
            value[rd] = (rn < 31 ? value[rn] : 0) +
                (((word >> 10) & 4095U) << (((word >> 22) & 1U) ? 12 : 0));
        } else if ((word & 0x7fe0ffe0U) == 0x2a0003e0U && rd < 31) {
            u32 rm = (word >> 16) & 31U;
            known[rd] = (word >> 31) && rm < 31 ? known[rm] : 0;
            value[rd] = rm < 31 ? value[rm] : 0;
        } else if (word == 0xd503233fU || word == 0xd503237fU ||
                   word == 0xd503245fU || word == 0xd503201fU || word == 0xf800865eU) {
        } else if (rn == 31 && !(word & (1U << 22)) &&
                   ((word & 0x3b000000U) == 0x29000000U ||
                    (word & 0x3b000000U) == 0x39000000U)) {
        } else if ((word & 0xff0003ffU) == 0xd10003ffU ||
                   (word & 0xff0003ffU) == 0x910003ffU) {
        } else return -EOPNOTSUPP;
    }
    return -EOPNOTSUPP;
}
static struct page *page_state_prototype(struct selinux_state *state) { (void)state; return NULL; }
static struct page *page_global_prototype(void) { return NULL; }
static void enforce_state_prototype(struct selinux_state *state, int value) { (void)state; (void)value; }
static void enforce_global_prototype(int value) { (void)value; }
static void policy_state_prototype(struct selinux_state *state, u32 value) { (void)state; (void)value; }
static void policy_global_prototype(u32 value) { (void)value; }

static int qualify(int (*resolve)(const char *, const void *, unsigned long *),
    const char *name, const void *prototype, unsigned long expected)
{
    unsigned long observed = 0;
    int error = resolve(name, prototype, &observed);
    return error ? error : (!observed || observed != expected ? -ESTALE : 0);
}
int msu_early_selinux_backend_bind(unsigned long (*lookup)(const char *),
    int (*resolve)(const char *, const void *, unsigned long *))
{
    unsigned long state, page, enforce, policy, lock;
    u32 page_code[16], enforce_code[16], page_offset, enforce_offset;
    bool page_argument, enforce_argument;
    int error;
    if (!lookup || !resolve) return -EINVAL;
    state = lookup("selinux_state"); page = lookup("selinux_kernel_status_page");
    enforce = lookup("selinux_status_update_setenforce");
    policy = lookup("selinux_status_update_policyload"); lock = lookup("mutex_lock");
    if (!state || !page || !enforce || !policy || !lock ||
        ((state | page | enforce | policy | lock) & 3U)) return -ENOENT;
    if (copy_from_kernel_nofault(page_code, (void *)page, sizeof(page_code)) ||
        copy_from_kernel_nofault(enforce_code, (void *)enforce, sizeof(enforce_code))) return -EFAULT;
    error = lock_anchor(page_code, page, lock, state, &page_offset, &page_argument);
    if (!error) error = lock_anchor(enforce_code, enforce, lock, state, &enforce_offset, &enforce_argument);
    if (error) return error;
    if (page_offset != enforce_offset || page_argument != enforce_argument ||
        state > ~0UL - page_offset) return -ESTALE;
    error = qualify(resolve, "selinux_kernel_status_page", page_argument ?
        (const void *)page_state_prototype : (const void *)page_global_prototype, page);
    if (!error) error = qualify(resolve, "selinux_status_update_setenforce", page_argument ?
        (const void *)enforce_state_prototype : (const void *)enforce_global_prototype, enforce);
    if (!error) error = qualify(resolve, "selinux_status_update_policyload", page_argument ?
        (const void *)policy_state_prototype : (const void *)policy_global_prototype, policy);
    if (error) return error;
    mutex_lock(&backend_lock);
    if (backend.initialized && !backend.closed) error = -EALREADY;
    else if (backend.bound && (backend.state_address != state || backend.page_address != page ||
        backend.setenforce != enforce || backend.policyload != policy || backend.lock_offset != page_offset)) error = -ESTALE;
    else {
        backend.state_address = state; backend.page_address = page;
        backend.setenforce = enforce; backend.policyload = policy;
        backend.lock_address = state + page_offset; backend.lock_offset = page_offset;
        backend.state_argument = page_argument; backend.bound = true;
    }
    mutex_unlock(&backend_lock);
    if (!error) {
        struct msu_early_selinux_bind bind = { .lookup = lookup, .resolve_cfi = resolve };
        error = msu_early_selinux_target_bind(&bind);
    }
    return error;
}
int msu_early_selinux_backend_init(const maplesu_host_instance *host,
    const struct msu_deployment_namespace_record *deployment, const unsigned char generation[16])
{
    int error = 0;
    if (!host || !(host->low | host->high) || !msu_deployment_namespace_valid(deployment) ||
        !generation || !memchr_inv(generation, 0, 16)) return -EINVAL;
    mutex_lock(&backend_lock);
    if (!backend.bound) error = -EAGAIN;
    else if (backend.initialized && (!backend.closed || backend.service || backend.status)) error = -EBUSY;
    else {
        backend.host = *host; backend.deployment = *deployment;
        memcpy(backend.generation, generation, 16);
        memset(backend.entries, 0, sizeof(backend.entries));
        backend.shared_id = backend.shared_address = 0;
        backend.closed = backend.prepared = false; backend.initialized = true;
    }
    mutex_unlock(&backend_lock);
    return error;
}
static void status_values(struct msu_early_selinux_result *r)
{
    r->values[0] = backend.status->version | ((u64)backend.status->sequence << 32);
    r->values[1] = backend.status->enforcing | ((u64)backend.status->policyload << 32);
    r->values[2] = backend.status->deny_unknown;
}
static int finish(struct msu_early_selinux_result *r, int error)
{
    if (error) { r->native_errno = error < 0 ? -error : error; if (!r->code) r->code = error; }
    return error;
}
static bool prefix(u32 word)
{
    return word == 0xd503231fU || word == 0xd503233fU ||
        word == 0xd503235fU || word == 0xd503237fU || (word & 0xffffff3fU) == 0xd503241fU;
}
/* These functions only notify the userspace status page. The actual enforcing
 * state and policy are changed by their native callers. Preserve that status
 * field update while retaining the sequence, as the SDK pair does. */
static u64 status_before(struct msu_su_gate_frame *frame, const void *context)
{
    const struct early_entry *entry = context;
    u32 sequence;
    if (!frame || !entry || !READ_ONCE(backend.prepared) || READ_ONCE(backend.closed) ||
        !READ_ONCE(*(u8 *)(unsigned long)backend.shared_address)) return 0;
    if (entry == &backend.entries[0]) {
        mutex_lock((struct mutex *)backend.lock_address);
        sequence = READ_ONCE(backend.status->sequence);
        WRITE_ONCE(backend.status->sequence, sequence + 1U);
        smp_wmb();
        WRITE_ONCE(backend.status->enforcing, (u32)frame->x[backend.state_argument ? 1 : 0]);
        smp_wmb();
        WRITE_ONCE(backend.status->sequence, sequence);
        mutex_unlock((struct mutex *)backend.lock_address);
    }
    return 1;
}
static int construct_entry(struct early_entry *entry, struct msu_early_selinux_result *r)
{
    maplesu_publication_member_v3 members[3] = {0};
    maplesu_publication_prepare_v3 prepare = {0};
    maplesu_publication_control_v3 control = {0};
    maplesu_response_owner_v3 response;
    u32 gate[MSU_SU_GATE_BYTES / 4], payload[MSU_SU_PAYLOAD_BYTES / 4], written;
    int error;
    error = msu_runtime_service_alloc(&backend.host, backend.service, &backend,
        sizeof(gate), true, entry->address, &response);
    r->effects |= response.metadata_length;
    if (error) return error;
    entry->gate = response.result; entry->gate_handle = response.metadata_address;
    error = msu_runtime_service_alloc(&backend.host, backend.service, &backend,
        sizeof(payload), true, 0, &response);
    r->effects |= response.metadata_length;
    if (error) return error;
    entry->payload = response.result; entry->payload_handle = response.metadata_address;
    members[0].handle = entry->gate_handle; members[0].role = MAPLESU_PUBLICATION_GATE_CODE;
    members[1].handle = entry->payload_handle; members[1].role = MAPLESU_PUBLICATION_PAYLOAD_CODE;
    members[2].handle = backend.shared_id; members[2].role = MAPLESU_PUBLICATION_SHARED_BOOL;
    members[2].address = backend.shared_address;
    prepare.member_count = 3; prepare.entry_address = entry->address;
    prepare.expected_instruction = entry->instruction; prepare.payload_entry = entry->payload;
    error = msu_runtime_service_prepare(&backend.host, backend.service, &backend, &prepare, members, &response);
    r->effects |= response.metadata_length;
    entry->publication = response.result;
    if (error) return error;
    if (!response.metadata_address || copy_from_kernel_nofault(&control,
        (void *)(unsigned long)response.metadata_address, sizeof(control))) return -EFAULT;
    error = msu_su_gate_build(gate, sizeof(gate), entry->gate, &control,
        entry->instruction, entry->prefix, &written);
    if (!error) error = msu_su_payload_build(payload, sizeof(payload),
        (unsigned long)status_before, (unsigned long)entry);
    if (error) return error;
    error = msu_runtime_service_write(&backend.host, backend.service, &backend,
        entry->payload_handle, 0, payload, sizeof(payload), &response);
    r->effects |= response.metadata_length;
    if (error) return error;
    error = msu_runtime_service_write(&backend.host, backend.service, &backend,
        entry->gate_handle, 0, gate, sizeof(gate), &response);
    r->effects |= response.metadata_length;
    return error;
}
static int retire(u32 *effects)
{
    int error = 0;
    WRITE_ONCE(backend.closed, true);
    if (backend.service) {
        error = msu_runtime_service_revoke(&backend.host, backend.service, effects);
        if (error || (*effects & (MAPLESU_EFFECT_PENDING | MAPLESU_EFFECT_QUARANTINED)))
            return error ? error : -EINPROGRESS;
        backend.service = 0;
    }
    if (backend.status) { vm_unmap_ram(backend.status, 1); backend.status = NULL; backend.page = NULL; }
    backend.prepared = false;
    backend.shared_address = backend.shared_id = 0;
    *effects |= MAPLESU_EFFECT_RELEASED;
    return 0;
}
static int native_prepare(void *context, u32 mode, u32 exploit, struct msu_early_selinux_result *r)
{
    struct msu_runtime_service_descriptor descriptor = {0};
    maplesu_response_owner_v3 response;
    u64 entries[2];
    u32 i;
    int error = 0;
    if (!r || context != &backend || mode > MAPLESU_EARLY_FIXED_MODE_MAX || exploit > MAPLESU_EARLY_FIXED_EXPLOIT_MAX)
        return r ? finish(r, -EINVAL) : -EINVAL;
    mutex_lock(&backend_lock);
    if (!backend.initialized || backend.closed) { error = -ESTALE; goto out; }
    if (backend.prepared || backend.service) { error = -EALREADY; goto out; }
    if (backend.state_argument) {
        struct page *(*page)(struct selinux_state *) = (void *)backend.page_address;
        backend.page = page((struct selinux_state *)backend.state_address);
    } else {
        struct page *(*page)(void) = (void *)backend.page_address;
        backend.page = page();
    }
    if (!backend.page) { r->code = -19909; error = -ENOMEM; goto out; }
    backend.status = vm_map_ram(&backend.page, 1, -1);
    if (!backend.status) { error = -ENOMEM; goto out; }
    r->effects |= MAPLESU_EFFECT_ALLOCATED;
    mutex_lock((struct mutex *)backend.lock_address);
    if (backend.status->version != 1) error = -EPROTO;
    if (!error) status_values(r);
    mutex_unlock((struct mutex *)backend.lock_address);
    if (error) goto failed;
    backend.entries[0].address = backend.setenforce;
    backend.entries[1].address = backend.policyload;
    for (i = 0; i < 2; ++i) {
        struct early_entry *entry = &backend.entries[i];
        if (copy_from_kernel_nofault(&entry->instruction, (void *)(unsigned long)entry->address, 4)) { error = -EFAULT; goto failed; }
        if (prefix(entry->instruction)) {
            entry->prefix = entry->instruction; entry->address += 4;
            if (copy_from_kernel_nofault(&entry->instruction, (void *)(unsigned long)entry->address, 4)) { error = -EFAULT; goto failed; }
        }
        if (!msu_su_gate_instruction(entry->instruction)) { error = -EOPNOTSUPP; goto failed; }
        entries[i] = entry->address;
    }
    descriptor.host = backend.host; descriptor.kind = MSU_RUNTIME_SERVICE_EARLY_FIXED;
    descriptor.lifecycle_owner = &backend; descriptor.entries = entries; descriptor.entry_count = 2;
    error = msu_runtime_service_register(&descriptor, &backend.service);
    if (error) goto failed;
    error = msu_runtime_service_shared_bool_create(&backend.host, backend.service, &backend, 0, &response);
    r->effects |= response.metadata_length;
    if (error) goto failed;
    backend.shared_id = response.metadata_address; backend.shared_address = response.result;
    for (i = 0; i < 2; ++i) { error = construct_entry(&backend.entries[i], r); if (error) goto failed; }
    /* PUBLISH seals the whole service. Construct and upload both entries first. */
    for (i = 0; i < 2; ++i) {
        error = msu_runtime_service_publish(&backend.host, backend.service, &backend, backend.entries[i].publication, &response);
        r->effects |= response.metadata_length;
        if (error) goto failed;
    }
    WRITE_ONCE(backend.prepared, true);
    goto out;
failed:
    {
        u32 effects = 0;
        int cleanup = retire(&effects);
        r->effects |= effects;
        if (cleanup) r->effects |= MAPLESU_EFFECT_PENDING;
    }
out:
    mutex_unlock(&backend_lock);
    return finish(r, error);
}
static int native_enable(void *context, struct msu_early_selinux_result *r)
{
    maplesu_response_owner_v3 response;
    int error;
    if (!r || context != &backend) return -EINVAL;
    mutex_lock(&backend_lock);
    if (!backend.prepared || backend.closed) error = -ESTALE;
    else {
        error = msu_runtime_service_shared_bool_store(&backend.host, backend.service, &backend, backend.shared_id, 1, &response);
        r->effects |= response.metadata_length;
    }
    mutex_unlock(&backend_lock);
    return finish(r, error);
}
static int status_operation(void *context, bool write, u32 sequence, struct msu_early_selinux_result *r)
{
    int error = 0;
    if (!r || context != &backend) return -EINVAL;
    mutex_lock(&backend_lock);
    if (!backend.prepared || backend.closed || !backend.status) error = -ESTALE;
    else {
        mutex_lock((struct mutex *)backend.lock_address);
        if (write) { WRITE_ONCE(backend.status->sequence, sequence); smp_wmb(); r->effects |= MAPLESU_EFFECT_WRITTEN; }
        status_values(r);
        if (write && backend.status->sequence != sequence) error = -EIO;
        mutex_unlock((struct mutex *)backend.lock_address);
    }
    mutex_unlock(&backend_lock);
    return finish(r, error);
}
static int native_read(void *context, struct msu_early_selinux_result *r) { return status_operation(context, false, 0, r); }
static int native_write(void *context, u32 sequence, struct msu_early_selinux_result *r) { return status_operation(context, true, sequence, r); }
static int native_revoke(void *context, u32 *effects)
{
    int error;
    if (!effects || context != &backend) return -EINVAL;
    *effects = 0;
    mutex_lock(&backend_lock); error = retire(effects); mutex_unlock(&backend_lock);
    return error;
}
static int native_close(void *context) { u32 effects; return native_revoke(context, &effects); }
int msu_early_selinux_host_backend(const maplesu_host_instance *host,
    const struct msu_deployment_namespace_record *deployment, struct msu_early_selinux_native *native)
{
    int error = 0;
    if (!host || !native || !msu_deployment_namespace_valid(deployment)) return -EINVAL;
    mutex_lock(&backend_lock);
    if (!backend.bound || !backend.initialized || backend.closed ||
        host->low != backend.host.low || host->high != backend.host.high ||
        memcmp(deployment, &backend.deployment, sizeof(*deployment))) error = -ESTALE;
    else {
        memset(native, 0, sizeof(*native));
        native->prepare = native_prepare; native->enable = native_enable;
        native->read_status = native_read; native->write_sequence = native_write;
        native->revoke = native_revoke; native->close = native_close;
        native->ctx = &backend; native->generation = backend.generation;
    }
    mutex_unlock(&backend_lock);
    return error;
}
int msu_early_selinux_backend_discarded(void)
{
    int error;
    mutex_lock(&backend_lock);
    error = backend.service || backend.status ? -EINPROGRESS : 0;
    mutex_unlock(&backend_lock);
    return error;
}
