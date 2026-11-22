// SPDX-License-Identifier: GPL-3.0-only
#include <linux/cred.h>
#include <linux/compiler.h>
#include <linux/errno.h>
#include <linux/kprobes.h>
#include <linux/sched.h>
#include <linux/stddef.h>
#include <asm/page.h>
#include <asm/ptrace.h>
#include "native_layout.h"

#ifndef CONFIG_ARM64
#error "Ultra init bridge native facts require an actual ARM64 kernel target"
#endif

_Static_assert(sizeof(void *) == 8, "ARM64 kernel pointer width");
_Static_assert(sizeof(((struct task_struct *)0)->cred) == 8, "task cred pointer");
_Static_assert(sizeof(((struct cred *)0)->suid) == 4, "saved UID width");
_Static_assert(sizeof(((struct cred *)0)->securebits) == 4, "securebits width");
_Static_assert(sizeof(((struct kprobe *)0)->addr) == 8, "probe address width");
_Static_assert(sizeof(((struct kprobe *)0)->symbol_name) == 8, "probe name width");
_Static_assert(sizeof(((struct kprobe *)0)->pre_handler) == 8, "probe callback width");
_Static_assert(sizeof(((struct pt_regs *)0)->pc) == 8, "native PC width");
#ifdef CONFIG_SECCOMP
_Static_assert(sizeof(((struct task_struct *)0)->seccomp.mode) == 4, "seccomp mode width");
#endif

/* Keep the existing wire shape so the target object can be compared with BTF.
 * Allocator and release fields here are not qualified defaults: the function
 * below always replaces both with the producer's explicit variant selection. */
const struct msu_boot_sdk_layout msu_init_bridge_compiled_layout
    __attribute__((used, section(".msu.init_bridge.layout"))) = {
    .version = 1,
    .bytes = sizeof(struct msu_boot_sdk_layout),
    .page_bytes = PAGE_SIZE,
    .task_bytes = sizeof(struct task_struct),
    .cred_bytes = sizeof(struct cred),
    .task_cred = offsetof(struct task_struct, cred),
    .cred_suid = offsetof(struct cred, suid),
    .cred_securebits = offsetof(struct cred, securebits),
    .cred_usage = offsetof(struct cred, usage),
    .cred_usage_size = sizeof(((struct cred *)0)->usage),
    .kprobe_bytes = sizeof(struct kprobe),
    .kp_addr = offsetof(struct kprobe, addr),
    .kp_name = offsetof(struct kprobe, symbol_name),
    .kp_pre = offsetof(struct kprobe, pre_handler),
    .regs_pc = offsetof(struct pt_regs, pc),
    .environment = 1,
#ifdef CONFIG_SECCOMP
    .seccomp = offsetof(struct task_struct, seccomp.mode),
#endif
};

struct msu_init_bridge_runtime_layout msu_init_bridge_runtime_layout
    __attribute__((used, section(".msu.init_bridge.runtime_layout"))) = {
    .magic = MSU_INIT_BRIDGE_RUNTIME_MAGIC,
    .schema = MSU_INIT_BRIDGE_RUNTIME_SCHEMA,
    .bytes = sizeof(struct msu_init_bridge_runtime_layout),
    .ready = 0,
    .sdk = {
    .version = 1,
    .bytes = sizeof(struct msu_boot_sdk_layout),
    .page_bytes = PAGE_SIZE,
    .task_bytes = sizeof(struct task_struct),
    .cred_bytes = sizeof(struct cred),
    .task_cred = offsetof(struct task_struct, cred),
    .cred_suid = offsetof(struct cred, suid),
    .cred_securebits = offsetof(struct cred, securebits),
    .cred_usage = offsetof(struct cred, usage),
    .cred_usage_size = sizeof(((struct cred *)0)->usage),
    .kprobe_bytes = sizeof(struct kprobe),
    .kp_addr = offsetof(struct kprobe, addr),
    .kp_name = offsetof(struct kprobe, symbol_name),
    .kp_pre = offsetof(struct kprobe, pre_handler),
    .regs_pc = offsetof(struct pt_regs, pc),
    .environment = 1,
#ifdef CONFIG_SECCOMP
    .seccomp = offsetof(struct task_struct, seccomp.mode),
#endif
},
};

int msu_init_bridge_native_layout(unsigned int allocator_flags,
    unsigned int execmem_free, struct msu_boot_sdk_layout *output)
{
    struct msu_boot_sdk_layout layout = msu_init_bridge_compiled_layout;

    if (!output) return -EINVAL;
    if (READ_ONCE(msu_init_bridge_runtime_layout.ready)) {
        if (msu_init_bridge_runtime_layout.ready != 1 ||
            msu_init_bridge_runtime_layout.magic != MSU_INIT_BRIDGE_RUNTIME_MAGIC ||
            msu_init_bridge_runtime_layout.schema != MSU_INIT_BRIDGE_RUNTIME_SCHEMA ||
            msu_init_bridge_runtime_layout.bytes != sizeof(msu_init_bridge_runtime_layout))
            return -EPROTO;
        layout = msu_init_bridge_runtime_layout.sdk;
    }
    layout.allocator_noprof = allocator_flags;
    layout.execmem_free = execmem_free;
    /* The shared producer still requires its exact legacy saved-ID window.
     * An incompatible target stays unsupported; no offsets are inferred. */
    if (!msu_boot_sdk_layout_valid(&layout, PAGE_SIZE)) return -EOPNOTSUPP;
    *output = layout;
    return 0;
}
