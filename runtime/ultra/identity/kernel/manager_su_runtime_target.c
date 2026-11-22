// SPDX-License-Identifier: GPL-3.0-only
#include <linux/binfmts.h>
#include <linux/compiler.h>
#include <linux/errno.h>
#include <linux/fs.h>
#include <linux/irqflags.h>
#include <linux/mutex.h>
#include <linux/preempt.h>
#include <linux/stddef.h>
#include <linux/string.h>
#include <linux/uaccess.h>
#include <asm/ptrace.h>
#include <asm/unistd.h>
#include "manager_su_runtime_factory.h"
#include "manager_task_state.h"
#ifndef __has_feature
#define __has_feature(name) 0
#endif
#if defined(MSU_INIT_BRIDGE_HOST_IMPORTS)
#include "native_cfi.h"
#if MSU_INIT_BRIDGE_CFI_LEGACY && defined(MODULE)
#include "native_legacy_cfi.h"
#endif
#endif

u32 msu_su_runtime_target_facts[9] __attribute__((section(".msu.su-runtime.target"))) = {
    1, sizeof(struct filename), offsetof(struct filename, name),
    sizeof(((struct filename *)0)->name), sizeof(struct pt_regs),
    offsetof(struct pt_regs, regs), sizeof(((struct pt_regs *)0)->regs[0]),
    0, 0,
};
const u32 msu_su_runtime_filename_alignment
    __attribute__((section(".msu.su-runtime.alignment"), used)) =
    __alignof__(((struct filename *)0)->name);
static DEFINE_MUTEX(msu_su_target_lock);
static struct msu_su_runtime_hook msu_su_targets[MSU_SU_RUNTIME_MAX_HOOKS];

#if defined(CONFIG_ARM64) && defined(CONFIG_ARCH_HAS_SYSCALL_WRAPPER)
#include "manager_su_runtime_target_profile.h"
#include "manager_dynamic_layout.h"

/* Same-object compiler evidence for the actual hook ABI. This variable's BTF
 * preserves the native function-pointer typedef, not a signature string. */
static msu_su_exec_source_fn msu_su_runtime_exec_abi __attribute__((used));
#define MSU_SU_EXEC_FLAGS_REGISTER (2 + 2 * sizeof(struct user_arg_ptr) / sizeof(unsigned long))
const u32 msu_su_runtime_exec_layout[2]
    __attribute__((section(".msu.su-runtime.exec-layout"), used)) = {
    sizeof(struct user_arg_ptr), MSU_SU_EXEC_FLAGS_REGISTER,
};

struct msu_su_runtime_profile_table msu_su_runtime_profiles
    __attribute__((section(".msu.su-runtime.profiles"), aligned(4))) = {
    .magic = MSU_SU_TARGET_PROFILE_MAGIC,
    .schema = MSU_SU_TARGET_PROFILE_SCHEMA,
    .bytes = sizeof(struct msu_su_runtime_profile_table),
    .count = MSU_SU_TARGET_PROFILE_COUNT,
    .ready = 0,
    .kcfi_mode = __has_feature(kcfi),
    .filename_offset = offsetof(struct filename, name),
    .reserved = 0,
    .values = {
        { .name = "do_execveat_common" },
        { .name = "__arm64_sys_newfstatat" },
        { .name = "__arm64_sys_faccessat" },
        { .name = "__arm64_sys_statx" },
        { .name = "__arm64_sys_faccessat2" },
    },
};
_Static_assert(sizeof(msu_su_runtime_profiles) == 372, "runtime profile table schema");

_Static_assert(ARRAY_SIZE(msu_su_target_profiles) + 2 <= MSU_SU_RUNTIME_MAX_HOOKS,
    "SU target capacity includes both UID transition wrappers");
_Static_assert(sizeof(struct user_arg_ptr) == sizeof(unsigned long) ||
    sizeof(struct user_arg_ptr) == 2 * sizeof(unsigned long), "exec argument registers");
/* The real resolver consumes this compiler's native syscall prototype/hash. */
static noinline long msu_su_syscall_reference(const struct pt_regs *regs)
{
    return regs ? -EOPNOTSUPP : -EINVAL;
}

#ifdef CONFIG_COMPAT
/* ARM EABI numbers and wrappers are paired by the target's actual compat table.
 * stat/lstat and stat64/lstat64 take pathname in r0 and statbuf in r1;
 * fstatat64, statx and access wrappers use their native argument positions. */
struct msu_su_compat_target {
    u32 number, kind, path, result;
    const char *name;
};
static const struct msu_su_compat_target msu_su_compat_targets[] = {
    {106, MSU_SU_STAT, 0, 1, "__arm64_compat_sys_newstat"},
    {107, MSU_SU_STAT, 0, 1, "__arm64_compat_sys_newlstat"},
    {195, MSU_SU_STAT, 0, 1, "__arm64_sys_stat64"},
    {196, MSU_SU_STAT, 0, 1, "__arm64_sys_lstat64"},
    {327, MSU_SU_STAT, 1, 2, "__arm64_sys_fstatat64"},
    {334, MSU_SU_ACCESS, 1, 0, "__arm64_sys_faccessat"},
    {397, MSU_SU_STAT, 1, 4, "__arm64_sys_statx"},
    {439, MSU_SU_ACCESS, 1, 0, "__arm64_sys_faccessat2"},
};
static int msu_su_bind_compat(unsigned long (*lookup)(const char *),
    int (*resolve_cfi)(const char *, const void *, unsigned long *),
    struct msu_su_runtime_hook *targets, u32 *count)
{
    unsigned long table = lookup("compat_sys_call_table");
    unsigned long absent = lookup("__arm64_sys_ni_syscall");
    unsigned long entry, address;
    u32 i, j;
    int error;
    if (!table || (table & (sizeof(entry) - 1)) ||
        table > ~0UL - 439 * sizeof(entry)) return -EFAULT;
    for (i = 0; i < ARRAY_SIZE(msu_su_compat_targets); ++i) {
        const struct msu_su_compat_target *source = &msu_su_compat_targets[i];
        error = copy_from_kernel_nofault(&entry,
            (const void *)(table + source->number * sizeof(entry)), sizeof(entry));
        if (error) return -EFAULT;
        if (!entry || (entry & 3)) return -EFAULT;
        if (absent && entry == absent) continue; /* actual unimplemented ABI */
        address = 0;
        error = resolve_cfi(source->name, msu_su_syscall_reference, &address);
        if (error) return error;
        if (address != entry) return -ESTALE;
        for (j = 0; j < *count; ++j) if (targets[j].entry == address) break;
        if (j < *count) {
            if (targets[j].kind != source->kind ||
                targets[j].argument_register != source->path ||
                targets[j].result_register != source->result ||
                !targets[j].syscall_frame) return -EINVAL;
            continue;
        }
        if (*count == MSU_SU_RUNTIME_MAX_HOOKS) return -EOVERFLOW;
        targets[*count].entry = address;
        targets[*count].kind = source->kind;
        targets[*count].argument_register = source->path;
        targets[*count].result_register = source->result;
        targets[*count].syscall_frame = true;
        targets[*count].optional = true;
        ++*count;
    }
    return 0;
}
#endif
#endif

int msu_su_runtime_target_bind(unsigned long (*lookup)(const char *),
    int (*resolve_cfi)(const char *, const void *, unsigned long *))
{
#if defined(CONFIG_ARM64) && defined(CONFIG_ARCH_HAS_SYSCALL_WRAPPER)
    struct msu_su_runtime_hook targets[MSU_SU_RUNTIME_MAX_HOOKS] = {0};
    unsigned long address;
    u32 words[6], prefix, i, j, count;
    int error = 0;
    if (!lookup || !resolve_cfi) return -EINVAL;
    if (!msu_runtime_layout_ready() || READ_ONCE(msu_su_runtime_profiles.ready) != 1 ||
        msu_su_runtime_profiles.magic != MSU_SU_TARGET_PROFILE_MAGIC ||
        msu_su_runtime_profiles.schema != MSU_SU_TARGET_PROFILE_SCHEMA ||
        msu_su_runtime_profiles.bytes != sizeof(msu_su_runtime_profiles) ||
        msu_su_runtime_profiles.count != MSU_SU_TARGET_PROFILE_COUNT ||
        msu_su_runtime_profiles.reserved ||
        msu_su_runtime_profiles.kcfi_mode !=
            (__has_feature(kcfi))) return -EPROTO;
    if (!in_task() || in_atomic() || irqs_disabled()) return -EWOULDBLOCK;
    mutex_lock(&msu_su_target_lock);
    if (smp_load_acquire(&msu_su_runtime_target_facts[8])) { error = -EALREADY; goto out; }
    for (i = 0; i < ARRAY_SIZE(msu_su_target_profiles); ++i) {
        const struct msu_su_target_profile *profile = &msu_su_target_profiles[i];
        address = 0;
        if (i >= 3 && !lookup(profile->name)) {
            const u32 absent[6] = {0};
            if (profile->kcfi || memcmp(profile->entry, absent, sizeof(absent))) {
                error = -ESTALE;
                goto out;
            }
            continue;
        }
        if (!i) {
            /* This native entry is a patch site, never called through this
             * pointer. The carrier binds its target BTF/source ABI and bytes. */
            address = lookup(profile->name);
        } else {
            error = resolve_cfi(profile->name, msu_su_syscall_reference, &address);
            if (error) goto out;
#if defined(MSU_INIT_BRIDGE_HOST_IMPORTS) && MSU_INIT_BRIDGE_CFI_LEGACY && defined(MODULE)
            /* A hook edits the body. The typed resolver retains the canonical
             * identity; compare both before using this target's body bytes. */
            {
                unsigned long body = lookup(profile->name);
                if (!msu_legacy_probe_matches(address, body)) { error = -ESTALE; goto out; }
                address = body;
            }
#endif
        }
        if (!address || (address & 3) || copy_from_kernel_nofault(words,
                (const void *)address, sizeof(words))) { error = -EFAULT; goto out; }
        if (memcmp(words, profile->entry, sizeof(words))) { error = -ESTALE; goto out; }
        if (i && msu_su_runtime_profiles.kcfi_mode && (address < 4 || copy_from_kernel_nofault(&prefix,
                (const void *)(address - 4), sizeof(prefix)) || prefix != profile->kcfi)) {
            error = -EOPNOTSUPP;
            goto out;
        }
        targets[i].entry = address;
        targets[i].kind = !i ? MSU_SU_EXEC : (i == 1 || i == 3 ? MSU_SU_STAT : MSU_SU_ACCESS);
        targets[i].argument_register = 1;
        targets[i].result_register = i == 1 ? 2 : i == 3 ? 4 : 0;
        targets[i].filename_member = !i ? msu_su_runtime_profiles.filename_offset : 0;
        targets[i].fd_register = 0;
        targets[i].flags_register = !i ?
            MSU_SU_EXEC_FLAGS_REGISTER : 0;
        targets[i].syscall_frame = i != 0;
        targets[i].optional = i >= 3;
    }
    count = 0;
    for (i = 0; i < ARRAY_SIZE(msu_su_target_profiles); ++i) {
        if (!targets[i].entry) continue;
        if (count != i) targets[count] = targets[i];
        ++count;
    }
    for (i = 0; i < count; ++i) for (j = 0; j < i; ++j) {
        if (targets[i].entry != targets[j].entry) continue;
        if (targets[i].kind != targets[j].kind ||
            targets[i].argument_register != targets[j].argument_register ||
            targets[i].result_register != targets[j].result_register ||
            targets[i].syscall_frame != targets[j].syscall_frame) {
            error = -EINVAL;
            goto out;
        }
        memmove(&targets[i], &targets[i + 1], (count - i - 1) * sizeof(targets[0]));
        memset(&targets[--count], 0, sizeof(targets[0]));
        --i;
        break;
    }
#ifdef CONFIG_COMPAT
    error = msu_su_bind_compat(lookup, resolve_cfi, targets, &count);
    if (error) goto out;
#endif
    /* Both native setresuid and compat setresuid32 use the same ARM64 wrapper.
     * The optional old 16-bit ABI has its own wrapper, not compat_sys_setresuid.
     * Resolve the actual native prototype; never copy another entry's bytes.
     * create_entries still validates every selected instruction for the gate. */
    for (i = 0; i < 2; ++i) {
        const char *name = i ? "__arm64_sys_setresuid16" : "__arm64_sys_setresuid";
        if (count >= ARRAY_SIZE(targets)) { error = -EOVERFLOW; goto out; }
        if (!lookup(name)) {
            if (i) continue;
            error = -ENOENT;
            goto out;
        }
        address = 0;
        error = resolve_cfi(name, msu_su_syscall_reference, &address);
        if (error) goto out;
        if (!address || (address & 3)) { error = -EFAULT; goto out; }
        targets[count].entry = address;
        targets[count].kind = i ? MSU_SU_SETRESUID16 : MSU_SU_SETRESUID;
        targets[count].syscall_frame = true;
        targets[count].optional = i != 0;
        ++count;
    }
    memcpy(msu_su_targets, targets, sizeof(targets));
    WRITE_ONCE(msu_su_runtime_target_facts[7], count);
    smp_store_release(&msu_su_runtime_target_facts[8], 1);
    /* Hook-site binding is separate from Profile target qualification. Retain
     * a missing native sys_enter object in the Profile binder; trace_open
     * reports its actual error before any SU source/publication starts. */
    (void)msu_task_profile_trace_bind(lookup);
out:
    mutex_unlock(&msu_su_target_lock);
    return error;
#else
    return -EOPNOTSUPP;
#endif
}

int msu_su_runtime_target_hooks(struct msu_su_runtime_hook *hooks, u32 *count)
{
    if (!hooks || !count) return -EINVAL;
    memset(hooks, 0, sizeof(*hooks) * MSU_SU_RUNTIME_MAX_HOOKS);
    *count = 0;
    if (!smp_load_acquire(&msu_su_runtime_target_facts[8])) return -EOPNOTSUPP;
    memcpy(hooks, msu_su_targets, sizeof(msu_su_targets));
    *count = READ_ONCE(msu_su_runtime_target_facts[7]);
    return 0;
}
