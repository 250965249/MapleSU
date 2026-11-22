/* SPDX-License-Identifier: GPL-3.0-only */
/* Restore only the counter history of the verified jailbreak window. The
 * original status page remains mapped everywhere, including inherited VMAs.
 * Enforcing, policyload, deny_unknown and the actual policy are never changed. */
#include "../selinux_hide_abi.h"

#ifdef MAPLESU_L3_STATUS_HIDE
enum { MSU_STATUS_IDLE, MSU_STATUS_RESERVED, MSU_STATUS_PENDING,
       MSU_STATUS_APPLYING, MSU_STATUS_READY, MSU_STATUS_FAILED };
static struct maplesu_l3_probe maplesu_status_probe;
static u32 maplesu_status_available, maplesu_status_state, maplesu_status_enabled;
static int maplesu_status_result;
static u32 maplesu_status_captured, maplesu_status_delta;
static struct msu_selinux_hide maplesu_status_request;
static struct msu_selinux_anchors maplesu_status_anchors;
static uptr maplesu_status_live_page, maplesu_status_page_function;
static struct msu_selinux_status *maplesu_status_live;
static long (*maplesu_copy_from_nofault)(void *, const void *, unsigned long);
static long (*maplesu_copy_to_nofault)(void *, const void *, unsigned long);
static long (*maplesu_simple_read)(void *, unsigned long, void *, const void *, unsigned long);
static void *(*maplesu_vm_map_ram)(void *, unsigned int, int);
static void (*maplesu_vm_unmap_ram)(void *, unsigned int);
static void (*maplesu_status_mutex_lock)(void *);
static void (*maplesu_status_mutex_unlock)(void *);
static u8 (*maplesu_status_module_get)(void *);
extern char __this_module[];

/* No layout-dependent kernel call runs until userland has resolved and
 * verified the running kernel's BTF. This path executes in read process context,
 * not the prctl/kprobe pre-handler. */
static MAPLESU_NOCFI int maplesu_status_setup(void)
{
    if (maplesu_status_request.layout.status_page_abi) {
        void *(*page)(void *) = (void *)maplesu_status_page_function;
        maplesu_status_live_page = (uptr)page(maplesu_selinux);
    } else {
        void *(*page)(void) = (void *)maplesu_status_page_function;
        maplesu_status_live_page = (uptr)page();
    }
    if (!maplesu_status_live_page) return -12;
    struct msu_selinux_status *live = maplesu_vm_map_ram(&maplesu_status_live_page, 1, -1);
    __atomic_store_n(&maplesu_status_live, live, __ATOMIC_RELEASE);
    return live ? 0 : -12;
}

/* This replacement runs after kprobe dispatch, in the native read's normal
 * process context. Never acquire a sleeping mutex inside the pre-handler. */
static MAPLESU_NOCFI long maplesu_status_read(void *file, void *buffer,
                                             unsigned long count, void *position)
{
    u32 expected = MSU_STATUS_PENDING;
    (void)file;
    if (maplesu_root_subject(maplesu_current_task()) &&
        __atomic_compare_exchange_n(&maplesu_status_state, &expected, MSU_STATUS_APPLYING,
                                    0, __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE)) {
        void *lock = (u8 *)maplesu_selinux + maplesu_status_request.layout.status_lock;
        maplesu_status_result = maplesu_status_live ? 0 : maplesu_status_setup();
        if (maplesu_status_result) {
            __atomic_store_n(&maplesu_status_state, MSU_STATUS_FAILED, __ATOMIC_RELEASE);
            return maplesu_status_result;
        }
        maplesu_status_mutex_lock(lock);
        maplesu_status_request.before = *maplesu_status_live;
        if (!maplesu_status_captured) {
            int valid = 0;
            if (maplesu_status_request.baseline_kind == MSU_STATUS_BASELINE_WINDOW) {
                valid = msu_status_window_delta(&maplesu_status_request,
                    &maplesu_status_request.before, &maplesu_status_delta);
            } else if (maplesu_status_request.baseline_kind == MSU_STATUS_BASELINE_SNAPSHOT &&
                       msu_status_baseline_valid(&maplesu_status_request.baseline,
                                                 &maplesu_status_request.before)) {
                maplesu_status_delta = maplesu_status_live->sequence -
                    maplesu_status_request.baseline.sequence;
                valid = 1;
            }
            if (!valid && (maplesu_status_request.allow_default ||
                           maplesu_status_request.baseline_kind == MSU_STATUS_BASELINE_DEFAULT) &&
                msu_status_stock_valid(&maplesu_status_request.before)) {
                /* Explicit normalized default, not a claimed pre-root capture.
                 * Derive every field from the verified live page; normalize only
                 * its event counter. The actual policy and policyload stay live. */
                maplesu_status_request.baseline = maplesu_status_request.before;
                maplesu_status_request.baseline.sequence = 0;
                maplesu_status_request.baseline_kind = MSU_STATUS_BASELINE_DEFAULT;
                maplesu_status_delta = maplesu_status_live->sequence;
                valid = 1;
            }
            if (valid) maplesu_status_captured = 1;
            else maplesu_status_result = -22;
        } else if (maplesu_status_live->version != 1 || (maplesu_status_live->sequence & 1u)) {
            maplesu_status_result = -22;
        }
        if (!maplesu_status_result &&
            maplesu_status_request.requested != maplesu_status_enabled) {
            /* Toggle only the captured jailbreak delta. Preserve all later
             * policy/enforcement events and the original mmap page, including
             * counter wrap. Never restore an old whole-page snapshot. */
            u32 sequence = maplesu_status_live->sequence +
                (maplesu_status_request.requested ? -maplesu_status_delta : maplesu_status_delta);
            if (maplesu_status_delta) {
                __atomic_fetch_add(&maplesu_status_live->sequence, 1u, __ATOMIC_RELAXED);
                __atomic_thread_fence(__ATOMIC_SEQ_CST);
                __atomic_store_n(&maplesu_status_live->sequence, sequence, __ATOMIC_RELEASE);
            }
            maplesu_status_enabled = maplesu_status_request.requested;
        }
        maplesu_status_request.after = *maplesu_status_live;
        maplesu_status_mutex_unlock(lock);
        __atomic_store_n(&maplesu_status_state,
                        maplesu_status_result ? MSU_STATUS_FAILED : MSU_STATUS_READY,
                        __ATOMIC_RELEASE);
    }
    /* Another redirected reader may arrive while the winning reader is still
     * mapping. It must retry, not dereference the unpublished page. */
    const struct msu_selinux_status *live = __atomic_load_n(&maplesu_status_live, __ATOMIC_ACQUIRE);
    if (!live) return -11;
    return maplesu_simple_read(buffer, count, position, live, sizeof(*live));
}

/* Redirect at the first instruction, before any PAC/SP prologue. After the
 * one-time request completes all reads execute the native function unchanged. */
__attribute__((noinline))
int maplesu_status_read_pre(struct kprobe *probe, struct pt_regs *regs)
{
    struct maplesu_pt_regs *frame = (void *)regs;
    (void)probe;
    if (!frame || __atomic_load_n(&maplesu_status_state, __ATOMIC_ACQUIRE) != MSU_STATUS_PENDING ||
        !maplesu_root_subject(maplesu_current_task())) return 0;
    frame->pc = (uptr)&maplesu_status_read;
    return 1;
}

static MAPLESU_NOCFI void maplesu_status_control(uptr user)
{
    struct msu_selinux_hide packet;
    u32 expected = MSU_STATUS_IDLE, state, version, held = 0;
    struct msu_selinux_layout anchored;
    if (!maplesu_root_subject(maplesu_current_task()) || !maplesu_copy_from_nofault ||
        !maplesu_copy_to_nofault ||
        maplesu_copy_from_nofault(&version, (const void *)user, sizeof(version)) ||
        version != MSU_STATUS_VERSION ||
        maplesu_copy_from_nofault(&packet, (const void *)user, sizeof(packet))) return;
    if (packet.version != MSU_STATUS_VERSION || packet.requested > 1 ||
        packet.baseline_kind > MSU_STATUS_BASELINE_DEFAULT || packet.allow_default > 1) return;
    packet.result = 0;
    if (packet.command == MSU_STATUS_INITIALIZE) {
        if (!maplesu_status_available) packet.result = -MAPLESU_ENOSYS;
        else if (!msu_status_layout_valid(&packet.layout)) packet.result = -22;
        else if (packet.layout.source == MSU_STATUS_RUNTIME_ANCHORS &&
            (!msu_status_layout_from_anchors(&maplesu_status_anchors, packet.layout.page_bytes, &anchored) ||
             anchored.status_lock != packet.layout.status_lock ||
             anchored.status_page_abi != packet.layout.status_page_abi)) packet.result = -22;
        else if (!__atomic_compare_exchange_n(&maplesu_status_state, &expected, MSU_STATUS_RESERVED,
                                             0, __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE)) packet.result = -16;
        else if (!maplesu_status_module_get(__this_module)) {
            packet.result = -MAPLESU_ENOSYS;
            __atomic_store_n(&maplesu_status_state, MSU_STATUS_IDLE, __ATOMIC_RELEASE);
        }
        else {
            /* The process-context replacement can sleep outside kprobe dispatch.
             * Pin its text until reboot before publishing a request. */
            __builtin_memcpy_inline(&maplesu_status_request, &packet, sizeof(packet));
            __atomic_store_n(&maplesu_status_state, MSU_STATUS_PENDING, __ATOMIC_RELEASE);
        }
    } else if (packet.command == MSU_STATUS_SET) {
        expected = MSU_STATUS_READY;
        if (!__atomic_compare_exchange_n(&maplesu_status_state, &expected, MSU_STATUS_RESERVED,
                                         0, __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE)) {
            packet.result = expected == MSU_STATUS_IDLE ? -11 : -16;
        } else {
            maplesu_status_request.requested = packet.requested;
            __atomic_store_n(&maplesu_status_state,
                packet.requested == maplesu_status_enabled ? MSU_STATUS_READY : MSU_STATUS_PENDING,
                __ATOMIC_RELEASE);
        }
    } else if (packet.command != MSU_STATUS_QUERY) packet.result = -22;
    state = __atomic_load_n(&maplesu_status_state, __ATOMIC_ACQUIRE);
    if (state == MSU_STATUS_READY || state == MSU_STATUS_FAILED) {
        expected = state;
        held = __atomic_compare_exchange_n(&maplesu_status_state, &expected, MSU_STATUS_RESERVED,
                                           0, __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE);
        if (!held) { state = MSU_STATUS_RESERVED; packet.result = -16; }
    }
    if (state == MSU_STATUS_FAILED) packet.result = maplesu_status_result;
    packet.available = maplesu_status_available ? MSU_STATUS_AVAILABLE | MSU_STATUS_CAN_SET : 0;
    packet.initialized = state == MSU_STATUS_READY;
    packet.effective = packet.initialized && maplesu_status_enabled;
    if (state >= MSU_STATUS_PENDING) packet.layout = maplesu_status_request.layout;
    if (state == MSU_STATUS_READY || state == MSU_STATUS_FAILED) {
        packet.baseline = maplesu_status_request.baseline;
        packet.before = maplesu_status_request.before;
        packet.after = maplesu_status_request.after;
        packet.baseline_kind = maplesu_status_request.baseline_kind;
        packet.window_end = maplesu_status_request.window_end;
    }
    if (held) __atomic_store_n(&maplesu_status_state, state, __ATOMIC_RELEASE);
    __builtin_memcpy_inline(&packet.anchors, &maplesu_status_anchors, sizeof(packet.anchors));
    packet.acknowledged = MSU_STATUS_ACK;
    (void)maplesu_copy_to_nofault((void *)user, &packet, sizeof(packet));
}

static MAPLESU_NOCFI void maplesu_status_cleanup(void)
{
    if (maplesu_status_available) unregister_kprobe(&maplesu_status_probe);
    maplesu_status_available = 0;
    if (maplesu_status_live) maplesu_vm_unmap_ram(maplesu_status_live, 1);
    maplesu_status_live = MAPLESU_NULL;
}

static MAPLESU_NOCFI void maplesu_status_init(void)
{
    uptr enforce;
    u32 index;
    maplesu_status_page_function = maplesu_sym("selinux_kernel_status_page");
    maplesu_vm_map_ram = (void *)maplesu_sym("vm_map_ram");
    maplesu_vm_unmap_ram = (void *)maplesu_sym("vm_unmap_ram");
    maplesu_simple_read = (void *)maplesu_sym("simple_read_from_buffer");
    maplesu_copy_from_nofault = (void *)maplesu_sym("copy_from_user_nofault");
    maplesu_copy_to_nofault = (void *)maplesu_sym("copy_to_user_nofault");
    maplesu_status_mutex_lock = (void *)maplesu_sym("mutex_lock");
    maplesu_status_mutex_unlock = (void *)maplesu_sym("mutex_unlock");
    maplesu_status_module_get = (void *)maplesu_sym("try_module_get");
    if (!maplesu_status_page_function || !maplesu_vm_map_ram || !maplesu_vm_unmap_ram || !maplesu_simple_read ||
        !maplesu_copy_from_nofault || !maplesu_copy_to_nofault ||
        !maplesu_status_mutex_lock || !maplesu_status_mutex_unlock || !maplesu_status_module_get) return;
    /* Copy only these two resident native functions. No user-selected kernel
     * read address is accepted, and no page/lock is touched by this snapshot. */
    enforce = maplesu_sym("selinux_status_update_setenforce");
    if (enforce) {
        maplesu_status_anchors.page_function = maplesu_status_page_function;
        maplesu_status_anchors.enforce_function = enforce;
        maplesu_status_anchors.mutex_lock = (uptr)maplesu_status_mutex_lock;
        maplesu_status_anchors.state = (uptr)maplesu_selinux;
        for (index = 0; index < MSU_STATUS_ANCHOR_WORDS; ++index) {
            maplesu_status_anchors.page_code[index] = ((const volatile u32 *)maplesu_status_page_function)[index];
            maplesu_status_anchors.enforce_code[index] = ((const volatile u32 *)enforce)[index];
        }
    }
#ifdef MAPLESU_LEGACY_CFI
    {
        extern void __cfi_check(u64 type, void *target, void *diag);
        __cfi_check((u64)MAPLESU_L3_PRE_KCFI_ID,
                    (void *)&maplesu_status_read_pre, MAPLESU_NULL);
    }
#else
    if (*(const u32 *)((const u8 *)(const void *)maplesu_status_read_pre - 4) != (u32)MAPLESU_L3_PRE_KCFI_ID)
        goto failed;
#endif
    maplesu_status_probe.symbol_name = "sel_read_handle_status";
    maplesu_status_probe.pre_handler = maplesu_status_read_pre;
    if (register_kprobe(&maplesu_status_probe) < 0) goto failed;
    maplesu_status_available = 1;
    _printk(MAPLESU_TAG "SELinux status baseline restoration ready (inactive, runtime ABI v4, root window/default, live switch)\n");
    return;
failed:
    maplesu_status_cleanup();
    _printk(MAPLESU_TAG "SELinux status baseline restoration unavailable\n");
}
#else
static void maplesu_status_control(uptr user) { (void)user; }
static void maplesu_status_init(void) { }
static void maplesu_status_cleanup(void) { }
#endif
