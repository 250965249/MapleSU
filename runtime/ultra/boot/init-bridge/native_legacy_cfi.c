// SPDX-License-Identifier: GPL-3.0-only
#include <linux/cfi.h>
#include <linux/errno.h>
#include <linux/irqflags.h>
#include <linux/kallsyms.h>
#include <linux/kernel.h>
#include <linux/kprobes.h>
#include <linux/module.h>
#include <linux/preempt.h>
#include <linux/string.h>
#include <linux/uaccess.h>
#include <linux/version.h>
#include <linux/workqueue.h>
#include <asm/page.h>
#include "native_cfi.h"
#include "native_legacy_cfi.h"

#if MSU_INIT_BRIDGE_CFI_LEGACY && defined(MODULE)
/* This symbol, the canonical entries and every section relocation are emitted
 * by the real target LTO link and published by its normal module loader. */
static noinline int msu_legacy_owner_probe(struct module *owner)
{
    return owner == THIS_MODULE ? 0 : -ESTALE;
}
static int (*volatile msu_legacy_probe)(struct module *) = msu_legacy_owner_probe;

struct msu_legacy_probe_work {
    struct work_struct work;
    struct module *owner;
    int result;
};

static void msu_legacy_kernel_probe_work(struct work_struct *work)
{
    struct msu_legacy_probe_work *probe =
        container_of(work, struct msu_legacy_probe_work, work);

    WRITE_ONCE(probe->result, probe->owner == THIS_MODULE ? 0 : -ESTALE);
}
static work_func_t const msu_legacy_work_member __used = msu_legacy_kernel_probe_work;

bool msu_legacy_module_text(const void *first, unsigned long bytes)
{
    unsigned long start = (unsigned long)first;
    unsigned long base = (unsigned long)THIS_MODULE->core_layout.base;
    unsigned long text_bytes = THIS_MODULE->core_layout.text_size;

    return bytes && start >= base && start - base < text_bytes &&
        bytes <= text_bytes - (start - base);
}

int msu_legacy_module_ready(void)
{
    unsigned long check = (unsigned long)THIS_MODULE->cfi_check;
    int (*probe)(struct module *) = READ_ONCE(msu_legacy_probe);
    struct msu_legacy_probe_work kernel_probe;
    bool queued;
    int error;

    if (!in_task() || in_atomic() || irqs_disabled()) return -EWOULDBLOCK;
    if ((THIS_MODULE->state != MODULE_STATE_COMING &&
         THIS_MODULE->state != MODULE_STATE_LIVE) ||
        !check || check != (unsigned long)__cfi_check ||
        !msu_legacy_module_text((void *)check, sizeof(u32)) ||
        !msu_legacy_module_text((void *)probe, sizeof(u32))) return -ESTALE;
    /* Preserve the normal local typed membership check first. */
    error = probe(THIS_MODULE);
    if (error) return error;
    /* The real kernel workqueue makes the external typed callback call. This
     * reaches native compiler membership/owner lookup, including shadow miss,
     * rather than mistaking a local type.test for a kernel->module proof. */
    kernel_probe.owner = THIS_MODULE;
    kernel_probe.result = -EINPROGRESS;
    INIT_WORK_ONSTACK(&kernel_probe.work, msu_legacy_kernel_probe_work);
    queued = schedule_work(&kernel_probe.work);
    flush_work(&kernel_probe.work);
    destroy_work_on_stack(&kernel_probe.work);
    return queued ? READ_ONCE(kernel_probe.result) : -EBUSY;
}

static int msu_legacy_read_word(unsigned long address, u32 *word)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 8, 0)
    return copy_from_kernel_nofault(word, (const void *)address, sizeof(*word));
#else
    return probe_kernel_read(word, (const void *)address, sizeof(*word));
#endif
}

static bool msu_legacy_exact_entry(unsigned long address, const char *name)
{
    char symbol[KSYM_SYMBOL_LEN], prefix[KSYM_NAME_LEN + 1], trailing;
    unsigned long offset, size;
    int length;

    if (!address || (address & 3) || !name) return false;
    length = snprintf(prefix, sizeof(prefix), "%s+", name);
    if (length <= 0 || (size_t)length >= sizeof(prefix) ||
        sprint_symbol(symbol, address) <= 0 || strncmp(symbol, prefix, length))
        return false;
    /* A module suffix adds trailing text and is rejected for kernel imports. */
    return sscanf(symbol + length, "%lx/%lx%c", &offset, &size, &trailing) == 2 &&
        !offset && size >= sizeof(u32);
}

static int msu_legacy_jump_target(unsigned long entry, unsigned long *target)
{
    u32 word;
    long displacement;

    if (!entry || (entry & 3) || !target) return -EINVAL;
    if (msu_legacy_read_word(entry, &word)) return -EFAULT;
    if (word == 0xd503245fU || word == 0xd50324dfU) {
        if (entry > ~0UL - sizeof(word)) return -EOVERFLOW;
        entry += sizeof(word);
        if (msu_legacy_read_word(entry, &word)) return -EFAULT;
    }
    if ((word & 0xfc000000U) != 0x14000000U) return -EOPNOTSUPP;
    displacement = (s32)((word & 0x03ffffffU) << 6) >> 4;
    if ((displacement < 0 && entry < (unsigned long)-displacement) ||
        (displacement >= 0 && entry > ~0UL - displacement)) return -EOVERFLOW;
    *target = entry + displacement;
    return 0;
}

static int msu_legacy_probe_entry(unsigned long probed, const char *name,
    unsigned long *entry)
{
    char symbol[KSYM_SYMBOL_LEN], prefix[KSYM_NAME_LEN + 1], trailing;
    unsigned long offset, size;
    u32 word;
    int length = snprintf(prefix, sizeof(prefix), "%s+", name);

    if (length <= 0 || (size_t)length >= sizeof(prefix) ||
        sprint_symbol(symbol, probed) <= 0 || strncmp(symbol, prefix, length) ||
        sscanf(symbol + length, "%lx/%lx%c", &offset, &size, &trailing) != 2 ||
        (offset != 0 && offset != sizeof(word)) || offset >= size || probed < offset)
        return -ESTALE;
    *entry = probed - offset;
    if (offset && (msu_legacy_read_word(*entry, &word) ||
        (word != 0xd503245fU && word != 0xd50324dfU))) return -ESTALE;
    return msu_legacy_exact_entry(*entry, name) ? 0 : -ESTALE;
}

bool msu_legacy_probe_matches(unsigned long canonical, unsigned long probed)
{
    unsigned long body;
    u32 word;

    if (msu_legacy_jump_target(canonical, &body)) return false;
    if (probed == body) return true;
    return body <= ~0UL - sizeof(word) && probed == body + sizeof(word) &&
        !msu_legacy_read_word(body, &word) &&
        (word == 0xd503245fU || word == 0xd50324dfU);
}

int msu_legacy_bootstrap_lookup(typeof(&kallsyms_lookup_name) *result)
{
    const char *name = "kallsyms_lookup_name";
    const char *canonical = "kallsyms_lookup_name.cfi_jt";
    struct kprobe probe = { .symbol_name = canonical };
    typeof(&kallsyms_lookup_name) lookup;
    unsigned long entry, target, body;
    int error;

    if (!result) return -EINVAL;
    *result = NULL;
    error = msu_legacy_module_ready();
    if (error) return error;
    error = register_kprobe(&probe);
    if (error) return error;
    entry = (unsigned long)probe.addr;
    unregister_kprobe(&probe);
    error = msu_legacy_probe_entry(entry, canonical, &entry);
    if (error) return error;
    error = msu_legacy_jump_target(entry, &target);
    if (error) return error;
    if (!msu_legacy_exact_entry(target, name)) return -ESTALE;
    lookup = (typeof(lookup))entry;
    /* The real typed call validates canonical membership through native CFI. */
    if (lookup(canonical) != entry) return -ESTALE;
    body = lookup(name);
    if (body != target && body != entry) return -ESTALE;
    *result = lookup;
    return 0;
}

int msu_legacy_resolve_entry(typeof(&kallsyms_lookup_name) lookup,
    const char *name, unsigned long *result)
{
    char canonical[KSYM_NAME_LEN];
    unsigned long entry, target, body;
    int error, length;

    if (!result || !name || !*name) return -EINVAL;
    *result = 0;
    if (!lookup) return -EAGAIN;
    length = snprintf(canonical, sizeof(canonical), "%s.cfi_jt", name);
    if (length <= 0 || (size_t)length >= sizeof(canonical)) return -ENAMETOOLONG;
    entry = lookup(canonical);
    if (!entry) return -ENOENT;
    if (!msu_legacy_exact_entry(entry, canonical)) return -ESTALE;
    error = msu_legacy_jump_target(entry, &target);
    if (error) return error;
    body = lookup(name);
    if ((body != target && body != entry) ||
        !msu_legacy_exact_entry(target, name)) return -ESTALE;
    *result = entry;
    return 0;
}
#endif
