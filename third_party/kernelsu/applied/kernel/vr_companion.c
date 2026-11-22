// SPDX-License-Identifier: GPL-2.0-only
// Ultra early-boot companion. Deliberately has no KSU root/dispatcher entry.
#include <linux/init.h>
#include <linux/module.h>
#include "hook/syscall_hook.h"
#include "hook/patch_memory.h"
#include "hook/init_module_filter.h"
#include "infra/symbol_resolver.h"

syscall_fn_t *ksu_syscall_table;
static syscall_fn_t original[2];

static int index_of(int nr)
{
    return nr == __NR_init_module ? 0 : nr == __NR_finit_module ? 1 : -1;
}

void ksu_syscall_table_hook(int nr, syscall_fn_t fn, syscall_fn_t *old)
{
    int index = index_of(nr);
    if (!ksu_syscall_table || index < 0)
        return;
    original[index] = READ_ONCE(ksu_syscall_table[nr]);
    *old = original[index];
    if (ksu_patch_text(&ksu_syscall_table[nr], &fn, sizeof(fn), KSU_PATCH_TEXT_FLUSH_DCACHE))
        pr_err("MapleSU vr: syscall %d patch failed\n", nr);
}

void ksu_syscall_table_unhook(int nr)
{
    int index = index_of(nr);
    if (index < 0 || !original[index])
        return;
    if (ksu_patch_text(&ksu_syscall_table[nr], &original[index], sizeof(original[index]), KSU_PATCH_TEXT_FLUSH_DCACHE))
        pr_err("MapleSU vr: syscall %d rollback failed\n", nr);
}

static int __init maplesu_vr_init(void)
{
    ksu_init_symbol_resolver();
    ksu_syscall_table = ksu_resolve_symbol_for_functable_hook("sys_call_table");
    if (!ksu_syscall_table)
        return -ENOENT;
    ksu_init_module_filter_init();
    if (ksu_init_module_filter_active())
        return 0;
    // Never free callback text if a protected table rejected the rollback.
    if ((original[0] && READ_ONCE(ksu_syscall_table[__NR_init_module]) != original[0]) ||
        (original[1] && READ_ONCE(ksu_syscall_table[__NR_finit_module]) != original[1])) {
        pr_err("MapleSU vr: partial installation retained until reboot\n");
        return 0;
    }
    return -EIO;
}
module_init(maplesu_vr_init);
// No module_exit: uninstall by restoring the boot chain and rebooting.
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("MapleSU Ultra early vivo vr module compatibility");
