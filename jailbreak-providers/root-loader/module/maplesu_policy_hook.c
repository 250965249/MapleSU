/* SPDX-License-Identifier: GPL-3.0-only */
/* Optional process-context bridge for the temporary Root session. It owns its
 * allocation and policy kprobes; it has no kernel-image write operation. The Root
 * credential gate is deliberately neither replaced nor expanded by this LKM. */
#include "policy_hook_dispatch.h"
#include "policy_hook_layout.h" /* generated from the target image's BTF */

typedef unsigned long uptr;
typedef unsigned int u32;
typedef unsigned long long u64;
struct kprobe;
struct pt_regs;
struct file;
extern int register_kprobe(void *);
extern void unregister_kprobe(void *);
extern char __this_module[], msu_policy_original_return[];

static uptr (*lookup_name)(const char *);
static int (*root_subject)(void);
static long (*get_uid)(const void *), (*get_euid)(const void *);
static long (*copy_in)(void *, const void *, unsigned long);
static long (*copy_out)(void *, const void *, unsigned long);
static long (*native_write)(unsigned int, const void *, unsigned long);
static void *(*alloc_image)(unsigned long);
static void *(*alloc_execmem)(unsigned int, unsigned long);
static void (*free_image)(void *);
static int (*memory_nx)(unsigned long, int);
static unsigned char (*module_get)(void *);
#ifndef MAPLESU_POLICY_HOOK_EMBEDDED
static void *(*create_proc)(const char *, unsigned short, void *, const void *, void *);
static void (*remove_proc)(void *);
static void *proc_entry;
static unsigned char proc_ops[MSU_PH_PROC_OPS_SIZE] __attribute__((aligned(8)));
#endif
static unsigned char probes[MSU_POLICY_HOOK_COUNT][MSU_PH_KPROBE_SIZE] __attribute__((aligned(8)));
static struct msu_policy_hook_dispatch dispatches[MSU_POLICY_HOOK_COUNT];
static const char *const targets[MSU_POLICY_HOOK_COUNT] = {
    "sel_write_context", "sel_write_access", "selinux_setprocattr",
    "sel_open_handle_status", "sel_read_handle_status", "sel_mmap_handle_status",
    "sk_filter_trim_cap", "commit_creds", "__skb_try_recv_datagram", "copy_process",
    "selnl_notify_policyload", "sel_write_load"
};
static const char *const allowed_symbols[] = { MSU_PH_ALLOWED_SYMBOLS };
static uptr resolved[sizeof(allowed_symbols) / sizeof(allowed_symbols[0])];
static uptr allocation, allocation_size, prepared_entry, active_word, transition_entry;
static uptr module_write_entry;
/* One atomic receipt pairs the first runtime error with restoration progress.
 * A reader must never mistake a closed gate for completed VMA restoration. */
static u64 failure_state;
static u32 busy, installed, prepared, pinned, described, transitioning, pin_busy, module_retained;
/* Every page protection is tracked before userspace may write into it. */
static unsigned char writable[MSU_POLICY_HOOK_MAX_IMAGE / MSU_PH_PAGE_BYTES];
static unsigned char executable[MSU_POLICY_HOOK_MAX_IMAGE / MSU_PH_PAGE_BYTES];

static int same(const char *a, const char *b)
{
    unsigned int n;
    for (n = 0; n < 128; ++n) {
        if (a[n] != b[n]) return 0;
        if (!a[n]) return 1;
    }
    return 0;
}
static void clear(void *at, unsigned long size)
{
    unsigned char *p = at;
    while (size--) *p++ = 0;
}
static int owned(uptr at, uptr size)
{
    return allocation && at >= allocation && at - allocation <= allocation_size &&
        size <= allocation_size - (at - allocation);
}
static int pages_have(uptr at, uptr size, const unsigned char *protection)
{
    unsigned long first, last;
    if (!size || !owned(at, size)) return 0;
    first = (at - allocation) / MSU_PH_PAGE_BYTES;
    last = (at - allocation + size - 1) / MSU_PH_PAGE_BYTES;
    while (first <= last) if (!protection[first++]) return 0;
    return 1;
}
static MSU_PH_NOCFI int root(void)
{
    return get_uid && get_euid && !get_uid((void *)0) && !get_euid((void *)0) &&
        (!root_subject || root_subject());
}
static MSU_PH_NOCFI int retain_module(void)
{
    u32 expected=0;
    if (__atomic_load_n(&module_retained,__ATOMIC_ACQUIRE)) return 0;
    if (!__atomic_compare_exchange_n(&pin_busy,&expected,1,0,__ATOMIC_ACQUIRE,__ATOMIC_RELAXED)) return -16;
    if (!__atomic_load_n(&module_retained,__ATOMIC_ACQUIRE)) {
        if (!module_get(__this_module)) {
            __atomic_store_n(&pin_busy,0,__ATOMIC_RELEASE);
            return -19;
        }
        __atomic_store_n(&module_retained,1,__ATOMIC_RELEASE);
    }
    __atomic_store_n(&pin_busy,0,__ATOMIC_RELEASE);
    return 0;
}
static MSU_PH_NOCFI int retain(void)
{
    int rc=retain_module();
    /* Payload pinning starts only when its code or snapshot is exposed, not
     * when an authenticated controller first enters the resident listener. */
    if (!rc) __atomic_store_n(&pinned,1,__ATOMIC_RELEASE);
    return rc;
}
static MSU_PH_NOCFI uptr resolve(const char *name)
{
    unsigned int i;
    for (i = 0; i < sizeof(allowed_symbols) / sizeof(allowed_symbols[0]); ++i)
        if (same(name, allowed_symbols[i])) {
            if (!resolved[i]) resolved[i] = lookup_name(allowed_symbols[i]);
            return resolved[i];
        }
    return 0;
}
static int readable_symbol(uptr at, uptr size)
{
    unsigned int i;
    for (i = 0; i < sizeof(resolved) / sizeof(resolved[0]); ++i)
        if (resolved[i] && at >= resolved[i] && at - resolved[i] <= 64 &&
            size <= 64 - (at - resolved[i])) return 1;
    return 0;
}

#define WRAPPER(n) \
static unsigned long long wrapper_##n(u64 a, u64 b, u64 c, u64 d, u64 e, u64 f) \
{ const u64 args[] = {a,b,c,d,e,f}; return msu_policy_dispatch(&dispatches[n],args); }
WRAPPER(0) WRAPPER(1) WRAPPER(2) WRAPPER(3) WRAPPER(4)
WRAPPER(5) WRAPPER(6) WRAPPER(7) WRAPPER(8) WRAPPER(9)
WRAPPER(10) WRAPPER(11)
static void *const wrappers[MSU_POLICY_HOOK_COUNT] = {
    (void *)wrapper_0, (void *)wrapper_1, (void *)wrapper_2,
    (void *)wrapper_3, (void *)wrapper_4, (void *)wrapper_5,
    (void *)wrapper_6, (void *)wrapper_7, (void *)wrapper_8, (void *)wrapper_9,
    (void *)wrapper_10, (void *)wrapper_11
};

static int runtime_failure(void)
{
    return (int)(u32)__atomic_load_n(&failure_state,__ATOMIC_ACQUIRE);
}
static void restoration_result(int error)
{
    u64 previous=__atomic_load_n(&failure_state,__ATOMIC_ACQUIRE), next;
    do {
        next=(previous & 0xffffffffull) | ((u64)(u32)error << 32);
    } while (!__atomic_compare_exchange_n(&failure_state,&previous,next,0,__ATOMIC_ACQ_REL,__ATOMIC_ACQUIRE));
}
void msu_policy_backend_note_error(int error)
{
    u64 previous=__atomic_load_n(&failure_state,__ATOMIC_ACQUIRE), next;
    if (!error) return;
    while (!(u32)previous) {
        next=(u32)error | ((u64)(u32)-115 << 32); /* -EINPROGRESS */
        if (__atomic_compare_exchange_n(&failure_state,&previous,next,0,__ATOMIC_ACQ_REL,__ATOMIC_ACQUIRE)) break;
    }
    if (active_word) __atomic_store_n((u32 *)active_word,0,__ATOMIC_RELEASE);
}

MSU_PH_NOCFI void msu_policy_backend_reconcile(void)
{
    if (runtime_failure() && transition_entry) {
        int (*transition)(unsigned int) = (void *)transition_entry;
        restoration_result(transition(0));
    }
}

/* This callback only redirects. Sleeping, snapshot preparation, policy queries,
 * native calls and mmap locks run after the kprobe dispatch has returned. */
__attribute__((noinline))
int msu_policy_pre(struct kprobe *probe, struct pt_regs *regs)
{
    uptr *frame = (void *)regs;
    unsigned int i;
    if (!frame || frame[30] == (uptr)msu_policy_original_return) return 0;
    for (i = 0; i < MSU_POLICY_HOOK_COUNT; ++i) {
        const u32 *gate;
        if ((void *)probe != (void *)probes[i] || !dispatches[i].installed) continue;
        gate = (const void *)(uptr)dispatches[i].activation;
        if (i != 9 && !(i == 7 && __atomic_load_n(&transitioning,__ATOMIC_ACQUIRE)) &&
            !__atomic_load_n(gate, __ATOMIC_ACQUIRE)) return 0;
        frame[MSU_PH_REGS_PC / sizeof(uptr)] = (uptr)wrappers[i];
        return 1;
    }
    return 0;
}
static void detach(void)
{
    unsigned int i;
    /* Disable before synchronization; a previously redirected wrapper checks
     * the same gate again before calling the payload. */
    if (active_word) __atomic_store_n((u32 *)active_word, 0, __ATOMIC_RELEASE);
    for (i = 0; i < MSU_POLICY_HOOK_COUNT; ++i) if (dispatches[i].installed) {
        unregister_kprobe(probes[i]);
        dispatches[i].installed = 0;
    }
    installed = 0;
}

static MSU_PH_NOCFI int install(struct msu_policy_hook_request *r)
{
    unsigned int n = r->operation;
    unsigned char *p;
    uptr actual;
    int rc;
    if (n >= MSU_POLICY_HOOK_COUNT || !prepared || dispatches[n].installed ||
        !(described & (1u << n)) ||
        dispatches[n].target != r->address || dispatches[n].predicate != r->predicate ||
        dispatches[n].handler != r->handler || dispatches[n].activation != r->activation ||
        r->address != resolve(targets[n]) ||
        !pages_have((uptr)r->predicate, 8, executable) ||
        !pages_have((uptr)r->handler, 8, executable) ||
        !pages_have((uptr)r->activation, 4, writable) || (r->activation & 3) ||
        *(const u32 *)(uptr)r->activation ||
        (active_word && active_word != r->activation)) return -22;
    rc = retain();
    if (rc) return rc;
    active_word = (uptr)r->activation;
    p = probes[n]; clear(p, sizeof probes[n]);
    *(uptr *)(p + MSU_PH_KP_ADDR) = (uptr)r->address;
    *(uptr *)(p + MSU_PH_KP_PRE) = (uptr)msu_policy_pre;
    dispatches[n].target = r->address;
    dispatches[n].predicate = r->predicate;
    dispatches[n].handler = r->handler;
    dispatches[n].activation = r->activation;
    dispatches[n].operation = n;
    described |= 1u << n;
    /* Publish inactive descriptor before registration, so callback pointers
     * never refer to an incompletely initialized record. */
    dispatches[n].installed = 1;
    rc = register_kprobe(p);
    if (rc) { dispatches[n].installed = 0; detach(); return rc; }
    actual = *(uptr *)(p + MSU_PH_KP_ADDR);
    /* Native arm64 may skip a BTI landing pad, but never a PAC/SP prologue. */
    if (actual != r->address && !(actual == r->address + 4 &&
            *(const u32 *)(uptr)r->address == 0xd503245f)) {
        detach(); return -95;
    }
    ++installed;
    return 0;
}

/* Descriptors and code are resident for this boot. A replacement controller
 * re-registers the measured targets, not another payload or snapshot. */
static MSU_PH_NOCFI int reattach(void)
{
    struct msu_policy_hook_request r;
    unsigned int i;
    int rc;
    if (described != (1u << MSU_POLICY_HOOK_COUNT)-1) return -11;
    for (i=0; i<MSU_POLICY_HOOK_COUNT; ++i) {
        if (dispatches[i].installed) continue;
        clear(&r,sizeof r);
        r.operation=i; r.address=dispatches[i].target;
        r.predicate=dispatches[i].predicate; r.handler=dispatches[i].handler;
        r.activation=dispatches[i].activation;
        rc=install(&r);
        if (rc) { detach(); return rc; }
    }
    return 0;
}

static MSU_PH_NOCFI int call(struct msu_policy_hook_request *r)
{
    typedef u64 (*fn3)(u64,u64,u64);
    unsigned long i, first, count;
    const char *name = (void *)0;
    uptr address = (uptr)r->address;
    int rc, protection = 0;
    if (r->bytes > 3) return -22;
    for (i = 0; i < sizeof(resolved) / sizeof(resolved[0]); ++i)
        if (resolved[i] && resolved[i] == address) { name = allowed_symbols[i]; break; }
    if (name && (same(name,"set_memory_rw") || same(name,"set_memory_ro") ||
                 same(name,"set_memory_x") || same(name,"set_memory_nx"))) {
        if (r->bytes != 2 || (r->args[0] & (MSU_PH_PAGE_BYTES-1)) || !r->args[1] ||
            r->args[1] > MSU_POLICY_HOOK_MAX_IMAGE / MSU_PH_PAGE_BYTES ||
            !owned((uptr)r->args[0], (uptr)r->args[1] * MSU_PH_PAGE_BYTES) || installed) return -22;
        first = (r->args[0] - allocation) / MSU_PH_PAGE_BYTES;
        count = r->args[1]; protection = 1;
        if (same(name,"set_memory_x"))
            for (i = first; i < first + count; ++i) if (writable[i]) return -1;
        if (same(name,"set_memory_rw"))
            for (i = first; i < first + count; ++i) if (executable[i]) return -1;
    } else if (name && (same(name,"caches_clean_inval_pou") || same(name,"__flush_icache_range"))) {
        if (r->bytes != 2 || r->args[1] <= r->args[0] ||
            !owned(r->args[0], r->args[1]-r->args[0]) || installed) return -22;
    } else if (name && same(name,"apply_alternatives_module")) {
        if (r->bytes != 2 || !owned(r->args[0], r->args[1]) || installed) return -22;
    } else if (name && (same(name,"scs_patch") || same(name,"__pi_scs_patch"))) {
        if (r->bytes < 2 || !owned(r->args[0], r->args[1]) || r->args[2] > 1 || installed) return -22;
    } else if (name && same(name,"static_key_count")) {
        if (r->bytes != 1 || r->args[0] != resolve("dynamic_scs_enabled")) return -22;
    } else if (!name && pages_have(address, 8, executable) && !installed &&
               prepared_entry == address && !prepared && !r->bytes) {
        rc = retain(); if (rc) return rc;
    } else return -1;
    r->result = ((fn3)address)(r->args[0],r->args[1],r->args[2]);
    if (protection && !(int)r->result) {
        first = (r->args[0]-allocation) / MSU_PH_PAGE_BYTES;
        for (i=first; i<first+r->args[1]; ++i) {
            if (same(name,"set_memory_rw")) writable[i]=1;
            if (same(name,"set_memory_ro")) writable[i]=0;
            if (same(name,"set_memory_x")) executable[i]=1;
            if (same(name,"set_memory_nx")) executable[i]=0;
        }
    }
    if (prepared_entry == address && !(int)r->result) prepared=1;
    return 0;
}

static MSU_PH_NOCFI int command(struct msu_policy_hook_request *r)
{
    unsigned long i;
    switch (r->command) {
    case MSU_PH_QUERY:
        r->address=active_word; r->handler=transition_entry;
        r->predicate=prepared_entry; r->result=allocation; r->bytes=allocation_size;
        return 0;
    case MSU_PH_LOOKUP:
        if (!r->name[0] || r->name[127]) return -22;
        r->result = resolve(r->name); return r->result ? 0 : -2;
    case MSU_PH_ALLOCATE:
        if (allocation) return -114;
        if (!r->bytes || r->bytes > MSU_POLICY_HOOK_MAX_IMAGE ||
            (r->bytes & (MSU_PH_PAGE_BYTES-1))) return -22;
        allocation = (uptr)(alloc_image ? alloc_image(r->bytes) : alloc_execmem(MSU_PH_EXECMEM_MODULE_TEXT,r->bytes));
        if (!allocation) return -12;
        if (memory_nx(allocation, r->bytes / MSU_PH_PAGE_BYTES)) {
            free_image((void *)allocation); allocation=0; return -5;
        }
        allocation_size = r->bytes;
        for (i=0; i<allocation_size / MSU_PH_PAGE_BYTES; ++i) writable[i]=1;
        r->result=allocation; return 0;
    case MSU_PH_RELEASE:
        if (!allocation || r->address != allocation || pinned || installed || prepared) return -16;
        /* No callback has been exposed. Drop every pointer before freeing so
         * response/query readback never dereferences the released gate. */
        prepared_entry=active_word=transition_entry=module_write_entry=0; described=0;
        clear(dispatches,sizeof dispatches);
        free_image((void *)allocation); allocation=allocation_size=0;
        clear(writable,sizeof writable); clear(executable,sizeof executable); return 0;
    case MSU_PH_READ:
        if (!r->bytes || r->bytes > MSU_POLICY_HOOK_CHUNK ||
            (!owned(r->address,r->bytes) && !readable_symbol(r->address,r->bytes))) return -22;
        return copy_out((void *)(uptr)r->data,(const void *)(uptr)r->address,r->bytes) ? -14 : 0;
    case MSU_PH_WRITE:
        if (!r->bytes || r->bytes > MSU_POLICY_HOOK_CHUNK || installed ||
            !pages_have(r->address,r->bytes,writable)) return -22;
        return copy_in((void *)(uptr)r->address,(const void *)(uptr)r->data,r->bytes) ? -14 : 0;
    case MSU_PH_CALL: return call(r);
    case MSU_PH_BIND: {
        struct msu_policy_hook_dispatch entries[MSU_POLICY_HOOK_COUNT];
        if (prepared || installed ||
            r->bytes != sizeof entries ||
            !pages_have(r->address,8,executable) ||
            !pages_have(r->handler,8,executable) ||
            !pages_have(r->args[0],8,executable) ||
            !pages_have(r->predicate,8,executable) ||
            !pages_have(r->activation,4,writable) || (r->activation & 3) ||
            *(const u32 *)(uptr)r->activation) return -22;
        if (copy_in(entries,(const void *)(uptr)r->data,sizeof entries)) return -14;
        for (i=0;i<MSU_POLICY_HOOK_COUNT;++i) {
            if (entries[i].operation != i || entries[i].installed ||
                !entries[i].target || entries[i].target != resolve(targets[i]) ||
                entries[i].predicate != r->predicate || entries[i].activation != r->activation ||
                !pages_have(entries[i].handler,8,executable)) return -22;
        }
        /* Publish the entire immutable contract before preparing the snapshot.
         * A new controller can finish any interrupted installation without
         * knowing payload addresses or repeating policy preparation. */
        for (i=0;i<MSU_POLICY_HOOK_COUNT;++i) dispatches[i]=entries[i];
        prepared_entry=r->address; transition_entry=r->handler; active_word=r->activation;
        module_write_entry=r->args[0];
        described=(1u << MSU_POLICY_HOOK_COUNT)-1;
        return 0;
    }
    case MSU_PH_POLICY_WRITE: {
        int (*mark)(unsigned int) = (void *)module_write_entry;
        int rc;
        if (!native_write || !prepared || !module_write_entry || !r->bytes ||
            r->bytes > (64u << 20) || r->args[0] > 0x7fffffff) return -22;
        rc = mark(0);
        if (rc) return rc;
        r->result = (u64)native_write((unsigned int)r->args[0],(const void *)(uptr)r->data,r->bytes);
        rc = mark(1);
        if (rc) msu_policy_backend_note_error(rc);
        msu_policy_backend_reconcile();
        return 0;
    }
    case MSU_PH_INSTALL: return install(r);
    case MSU_PH_CANCEL:
        if (transition_entry && active_word) {
            r->command=MSU_PH_ACTIVATE; r->address=active_word;
            r->handler=transition_entry; r->result=0;
            /* Keep the public request command intact for response validation. */
            {
                int rc=command(r);
                r->command=MSU_PH_CANCEL;
                return rc;
            }
        }
        detach(); return 0;
    case MSU_PH_ACTIVATE:
        /* Hot transitions require the payload's real VMA reconciliation entry.
         * Older SDK payloads are never relabelled as a hot-capable backend. */
        if (!r->address) r->address=active_word;
        if (!r->handler) r->handler=transition_entry;
        if (r->result > 1 || !active_word || r->address != active_word ||
            !pages_have(r->handler,8,executable) ||
            (transition_entry && transition_entry != r->handler)) return -22;
        transition_entry=r->handler;
        if (r->result && runtime_failure()) return runtime_failure();
        if (r->result && installed != MSU_POLICY_HOOK_COUNT) {
            int rc=reattach();
            if (rc) return rc;
        }
        if (r->result && __atomic_load_n((u32 *)active_word,__ATOMIC_ACQUIRE)) return 0;
        if (!r->result && !installed) return 0;
        __atomic_store_n(&transitioning,1,__ATOMIC_RELEASE);
        __atomic_store_n((u32 *)active_word,(u32)r->result,__ATOMIC_RELEASE);
        {
            int (*transition)(unsigned int) = (void *)(uptr)r->handler;
            int rc = transition((unsigned int)r->result);
            if (!rc && r->result) {
                /* Publish then recheck: a fault before this store must not be
                 * overwritten, and a later fault closes the same atomic gate. */
                __atomic_store_n((u32 *)active_word,1,__ATOMIC_RELEASE);
                u64 previous=__atomic_load_n(&failure_state,__ATOMIC_ACQUIRE);
                if ((u32)previous || !__atomic_compare_exchange_n(&failure_state,&previous,0,0,__ATOMIC_ACQ_REL,__ATOMIC_ACQUIRE))
                    rc=(int)(u32)previous;
            }
            if (rc) {
                __atomic_store_n((u32 *)active_word,0,__ATOMIC_RELEASE);
                /* A partial enable may have retargeted earlier VMAs. Restore
                 * before detaching; a failed restore remains recoverable. */
                int restored = r->result ? transition(0) : rc;
                restoration_result(restored);
                if (!restored) detach();
                __atomic_store_n(&transitioning,0,__ATOMIC_RELEASE);
                return rc;
            }
        }
        /* Disable's reconciliation succeeded; ordinary mode leaves no probes. */
        if (!r->result) { restoration_result(0); detach(); }
        __atomic_store_n(&transitioning,0,__ATOMIC_RELEASE);
        return 0;
    default: return -25;
    }
}

/* proc_ioctl is already in ordinary, sleepable syscall context. proc_remove
 * provides the native rundown if an unused sidecar is removed concurrently. */
__attribute__((noinline)) MSU_PH_NOCFI
long msu_policy_ioctl(struct file *file, unsigned int request, unsigned long user)
{
    struct msu_policy_hook_request r;
    u32 expected=0;
    int rc;
    (void)file;
    if (request != MSU_POLICY_HOOK_IOCTL) return -25;
    if (!root()) return -1;
    if (!__atomic_compare_exchange_n(&busy,&expected,1,0,__ATOMIC_ACQUIRE,__ATOMIC_RELAXED)) return -16;
    rc = copy_in(&r,(const void *)user,sizeof r) ? -14 : 0;
    if (!rc && (r.version != MSU_POLICY_HOOK_VERSION || r.flags || r.reserved)) rc=-22;
    if (!rc) rc=command(&r);
    if (rc != -14) {
        r.status=rc; r.installed=installed; r.prepared=prepared; r.pinned=__atomic_load_n(&pinned,__ATOMIC_ACQUIRE);
        r.enabled=active_word ? __atomic_load_n((u32 *)active_word,__ATOMIC_ACQUIRE) : 0;
        u64 failure=__atomic_load_n(&failure_state,__ATOMIC_ACQUIRE);
        r.args[1]=(u64)(long)(int)(u32)failure;
        r.args[2]=(u64)(long)(int)(u32)(failure >> 32);
        rc=copy_out((void *)user,&r,sizeof r) ? -14 : 0;
    }
    __atomic_store_n(&busy,0,__ATOMIC_RELEASE);
    return rc;
}

#ifdef MAPLESU_POLICY_HOOK_EMBEDDED
MSU_PH_NOCFI int msu_policy_embedded_retain(void) { return root() ? retain_module() : -1; }
MSU_PH_NOCFI int msu_policy_embedded_init(uptr (*lookup)(const char *), int (*subject)(void))
{
    if (!lookup || !subject) return -22;
    lookup_name=lookup; root_subject=subject;
#else
MSU_PH_NOCFI int init_module(void)
{
    unsigned char bootstrap[MSU_PH_KPROBE_SIZE] __attribute__((aligned(8)));
    clear(bootstrap,sizeof bootstrap);
    *(const char **)(bootstrap+MSU_PH_KP_NAME)="kallsyms_lookup_name";
    if (register_kprobe(bootstrap)) return -2;
    lookup_name=(void *)*(uptr *)(bootstrap+MSU_PH_KP_ADDR);
    unregister_kprobe(bootstrap);
    if (!lookup_name) return -2;
#endif
#define RESOLVE(variable,name) variable=(void *)lookup_name(name)
    RESOLVE(get_uid,"__arm64_sys_getuid"); RESOLVE(get_euid,"__arm64_sys_geteuid");
    RESOLVE(copy_in,"copy_from_user_nofault"); RESOLVE(copy_out,"copy_to_user_nofault");
    RESOLVE(alloc_image,"module_alloc"); RESOLVE(alloc_execmem,"execmem_alloc");
    RESOLVE(free_image,"module_memfree"); if (!free_image) RESOLVE(free_image,"execmem_free");
    RESOLVE(memory_nx,"set_memory_nx"); RESOLVE(module_get,"try_module_get");
    RESOLVE(native_write,"ksys_write");
#ifndef MAPLESU_POLICY_HOOK_EMBEDDED
    RESOLVE(create_proc,"proc_create_data"); RESOLVE(remove_proc,"proc_remove");
#endif
#undef RESOLVE
    if (!get_uid || !get_euid || !copy_in || !copy_out || (!alloc_image && !alloc_execmem) ||
        !free_image || !memory_nx || !module_get || !native_write) return -2;
#ifdef MAPLESU_POLICY_HOOK_EMBEDDED
    return 0;
#else
    if (!create_proc || !remove_proc) return -2;
    *(uptr *)(proc_ops+MSU_PH_PROC_IOCTL)=(uptr)msu_policy_ioctl;
    proc_entry=create_proc("maplesu_policy_hook",0600,(void *)0,proc_ops,(void *)0);
    return proc_entry ? 0 : -12;
#endif
}
#ifdef MAPLESU_POLICY_HOOK_EMBEDDED
MSU_PH_NOCFI void msu_policy_embedded_cleanup(void)
#else
MSU_PH_NOCFI void cleanup_module(void)
#endif
{
#ifndef MAPLESU_POLICY_HOOK_EMBEDDED
    if (proc_entry) remove_proc(proc_entry);
#endif
    detach();
    /* Once code/snapshot callbacks were exposed, retain() makes unload busy. */
    if (allocation && !pinned) free_image((void *)allocation);
}
