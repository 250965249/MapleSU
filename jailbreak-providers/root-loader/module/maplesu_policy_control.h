/* SPDX-License-Identifier: GPL-3.0-only */
/* Independent optional listener; the existing ARM/SU gate remains read-only. */
#include "../policy_hook_abi.h"

#ifdef MAPLESU_L3_POLICY_BRIDGE
#ifdef MAPLESU_L3_BOOT_SDK
#include "../boot_sdk_abi.h"
extern int msu_boot_sdk_init(uptr (*lookup)(const char *), int (*subject)(void),
    int (*handover)(void));
extern long msu_boot_sdk_control(uptr);
extern void msu_boot_sdk_cleanup(void);
extern int msu_boot_sdk_pre(struct kprobe *, struct pt_regs *);
extern int msu_boot_sdk_allocator_pre(struct kprobe *, struct pt_regs *);
static u32 maplesu_sdk_available;
static int maplesu_sdk_matches(const struct maplesu_pt_regs *args)
{
    return args && (u32)args->regs[0] == 4 &&
        (u32)args->regs[1] == MSU_BOOT_SDK_OP &&
        (u32)args->regs[2] == MSU_BOOT_SDK_TAG_LO &&
        (u32)args->regs[3] == MSU_BOOT_SDK_TAG_HI;
}
#endif
extern int msu_policy_embedded_init(uptr (*lookup)(const char *), int (*subject)(void));
extern int msu_policy_embedded_retain(void);
extern void msu_policy_embedded_cleanup(void);
struct file;
extern long msu_policy_ioctl(struct file *, unsigned int, unsigned long);
extern int msu_policy_pre(struct kprobe *, struct pt_regs *);
static struct maplesu_l3_probe maplesu_policy_probe;
static u32 maplesu_policy_available;

static int maplesu_policy_subject(void)
{
    return maplesu_root_subject(maplesu_current_task());
}
static int maplesu_policy_matches(const struct maplesu_pt_regs *args)
{
    return args && (u32)args->regs[0] == 4 &&
        (u32)args->regs[1] == MSU_POLICY_HOOK_OP &&
        (u32)args->regs[2] == MSU_POLICY_HOOK_TAG_LO &&
        (u32)args->regs[3] == MSU_POLICY_HOOK_TAG_HI;
}

/* Entered only after kprobe dispatch has returned. Allocation, policy snapshot,
 * mutexes and VMA reconciliation belong to normal syscall process context. */
static MAPLESU_NOCFI __attribute__((noinline))
long maplesu_policy_control(const struct maplesu_pt_regs *args)
{
    if (!maplesu_policy_available || !maplesu_policy_subject()) return -1;
#ifdef MAPLESU_L3_BOOT_SDK
    if (maplesu_sdk_available && maplesu_sdk_matches(args))
        return msu_boot_sdk_control((uptr)args->regs[4]);
#endif
    if (!maplesu_policy_matches(args)) return -1;
    return msu_policy_ioctl(MAPLESU_NULL, MSU_POLICY_HOOK_IOCTL, (uptr)args->regs[4]);
}

__attribute__((noinline))
int maplesu_policy_control_pre(struct kprobe *probe, struct pt_regs *regs)
{
    struct maplesu_pt_regs *frame = (void *)regs;
    const struct maplesu_pt_regs *args;
    (void)probe;
    if (!frame || !maplesu_policy_available || !maplesu_policy_subject()) return 0;
    args = (const void *)(uptr)frame->regs[0];
    if ((uptr)args < MAPLESU_KERNEL_VA_MIN) return 0;
    if (!maplesu_policy_matches(args)
#ifdef MAPLESU_L3_BOOT_SDK
        && !(maplesu_sdk_available && maplesu_sdk_matches(args))
#endif
    ) return 0;
    /* Prevent unload between redirection and entry. The operation does not run
     * here and no userspace address survives the synchronous syscall. */
    if (msu_policy_embedded_retain()) return 0;
    frame->pc = (uptr)maplesu_policy_control;
    return 1;
}

static MAPLESU_NOCFI int maplesu_policy_prefix_valid(void *callback)
{
#ifdef MAPLESU_LEGACY_CFI
    extern void __cfi_check(u64 type, void *target, void *diag);
    __cfi_check((u64)MAPLESU_L3_PRE_KCFI_ID, callback, MAPLESU_NULL);
    return 1;
#else
    return *(const u32 *)((const u8 *)callback - 4) == (u32)MAPLESU_L3_PRE_KCFI_ID;
#endif
}
static MAPLESU_NOCFI void maplesu_policy_cleanup(void)
{
    if (maplesu_policy_available) unregister_kprobe(&maplesu_policy_probe);
    maplesu_policy_available = 0;
#ifdef MAPLESU_L3_BOOT_SDK
    maplesu_sdk_available = 0;
    msu_boot_sdk_cleanup();
#endif
    msu_policy_embedded_cleanup();
}
static MAPLESU_NOCFI void maplesu_policy_init(void)
{
    uptr entry = maplesu_sym("__arm64_sys_prctl");
    if (!entry || !maplesu_policy_prefix_valid((void *)maplesu_policy_control_pre) ||
        !maplesu_policy_prefix_valid((void *)msu_policy_pre) ||
        msu_policy_embedded_init(maplesu_sym, maplesu_policy_subject)) return;
    maplesu_policy_probe.symbol_name = "__arm64_sys_prctl";
    maplesu_policy_probe.pre_handler = maplesu_policy_control_pre;
    if (register_kprobe(&maplesu_policy_probe) < 0) return;
    /* Accept only the first instruction, or native arm64's skipped BTI pad.
     * A vendor probe offset after PAC/SP changes is not a redirectable entry. */
    if (maplesu_policy_probe.addr != entry &&
        !(maplesu_policy_probe.addr == entry + 4 && *(const u32 *)entry == 0xd503245f)) {
        unregister_kprobe(&maplesu_policy_probe);
        return;
    }
    maplesu_policy_available = 1;
#ifdef MAPLESU_L3_BOOT_SDK
    maplesu_prepare_creds = (void *(*)(void))maplesu_sym("prepare_creds");
    if (maplesu_prepare_creds && maplesu_policy_prefix_valid((void *)msu_boot_sdk_pre) &&
        maplesu_policy_prefix_valid((void *)msu_boot_sdk_allocator_pre) &&
        !msu_boot_sdk_init(maplesu_sym, maplesu_policy_subject,
            maplesu_sdk_root_handover)) maplesu_sdk_available = 1;
#endif
    _printk(MAPLESU_TAG "module policy resident control ready (inactive, ABI v2)\n");
}
#else
static void maplesu_policy_init(void) { }
static void maplesu_policy_cleanup(void) { }
#endif
