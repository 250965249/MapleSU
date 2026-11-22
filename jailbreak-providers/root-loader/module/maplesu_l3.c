/*
 * maplesu_l3 -- the kernel-side credential gate (ABI v2), entered through kprobe.
 *
 * What this is
 * ------------
 * A resident module whose only job is to turn "a process the manager already
 * trusts" into "a process with kernel-root credentials", inside the kernel, with
 * a private root-subject SELinux gate and no userspace capability to mint root.
 *
 * The entry point is a kprobe on `__arm64_sys_prctl`'s first instruction. The
 * gate rides on the kernel's own `PR_SET_DUMPABLE` (option 4), which carries no
 * payload: in every real call `arg3 == arg4 == 0`, so it is a non-zero token that
 * makes the call this gate's --
 *
 *     prctl(4, op, token_lo, token_hi, owner_uid)               ABI v2
 *
 *     option = 4 is PR_SET_DUMPABLE; op is the syscall's arg2.
 *
 *     magic     option == 4 && (token_lo | token_hi) != 0. Anything else is a real
 *               PR_SET_DUMPABLE: observed, never touched. A zero token is never
 *               magic (the ABI's explicit rule).
 *     op = 0    (ARM) only inside the window (`selinux_state.enforcing == 0`), only
 *               by uid 0, only with owner_uid in [10000, 100000), only with a
 *               non-zero token, and only once (CAS 0 -> 1); otherwise denied with
 *               -EPERM;
 *     op = 1    (SU) requires ARMED + token match + caller uid == owner_uid;
 *               commits a reference to a pre-allocated root cred; a refusal
 *               is -EPERM, or -ENOMEM if no credential is available.
 *
 * The decision values above are the ABI's errno, and this module prints them as
 * `rc=-<errno>` on the (bounded) denial lines. They are *not* the syscall's return
 * value: a kprobe pre-handler observes the probed function, it cannot make it
 * return something else, and this module deliberately does not try to. What
 * changes is the kernel state (a cred committed, the gate armed) and the evidence
 * line. ABI v2 turns that limitation into a clean contract: the kernel's own
 * PR_SET_DUMPABLE for arg2 in {0, 1} returns 0, so a granted ARM/SU and a denied
 * one both answer `prctl() == 0` -- which is why the success criteria are the
 * kernel's "armed" line (ARM) and the caller's own `getuid()` (SU), not this
 * return value.
 *
 * Why a kprobe and not `sys_call_table[__NR_prctl]`
 * ------------------------------------------------
 * The earlier design replaced the table slot. That slot lives in the kernel
 * image's own `.rodata` (`sys_call_table` at 0x1090cb8 on 6.6.89, inside
 * `[__start_rodata, __end_rodata)`), and the two helpers that could make it
 * writable -- `set_memory_rw`/`set_memory_ro` -- tail-call
 * `change_memory_common`, whose first act is `find_vm_area`; the kernel image is
 * not a vmap area, so the range is refused with -EINVAL before a PTE is touched
 * (measured on this image, see the round's design note). Even a successful write
 * would leave the module's text in a table that outlives the module: an unload
 * race between `delete_module()` and a concurrent `prctl()`.
 *
 * A kprobe writes no kernel-image byte. It installs a breakpoint through the
 * kernel's own text-patching machinery, and `unregister_kprobe()` is the complete
 * undo. So:
 *
 *   * zero writes to any kernel image section (the L3 gates assert no
 *     `sys_call_table`/`set_memory_*`/`text_poke` name survives in the artifact);
 *   * registration is by *symbol name*, so no syscall index and no address is a
 *     build input, and a table renumbering cannot point the hook at another
 *     syscall;
 *   * `cleanup_module()` unregisters, and after that the kernel holds no pointer
 *     into this module.
 *
 * Why the arguments are one dereference away
 * ------------------------------------------
 * The probe sits at the *entry* of `__arm64_sys_prctl(const struct pt_regs *)`.
 * At that instruction x0 is the `pt_regs *` the syscall dispatcher passed in, not
 * the first syscall argument: the image's own prologue loads the option from
 * `[x0]` (0xb9400013, `ldr w19,[x0]`) and the four payload arguments from
 * `[x0, #8]`/`[x0, #24]` (0xa940d815 = `ldp x21,x22,[x0,#8]`,
 * 0xa941e418 = `ldp x24,x25,[x0,#24]`) -- i.e. the frame words ABI v2 calls
 * arg2/arg3 and arg4/arg5, which is the measured statement that the five words
 * this callback reads are the five the kernel's own wrapper reads.
 * The callback therefore reads `regs->regs[0]` to get that pointer, checks it is
 * a kernel address, and reads the five ABI arguments from the frame it names.
 *
 * Why the cred pool is built in init_module
 * -----------------------------------------
 * `prepare_kernel_cred()` allocates (`kmem_cache_alloc(GFP_KERNEL)`) and can
 * sleep; `commit_creds()` does not. So the pool is built once, in init_module
 * (process context, may sleep), and the SU path takes a reference and hands it
 * over. The pool holds `MAPLESU_L3_POOL` creds, each with usage == 1 -- exactly
 * the extra reference `commit_creds()` takes ownership of. Only the atomic usage
 * reference is updated directly. A separate AVC callback reads BTF-derived
 * uid/euid/group_info offsets to recognize only this module's root credentials.
 *
 * Two facts come from the image, never from this file
 * ---------------------------------------------------
 *   * `MAPLESU_L3_PRE_KCFI_ID` -- the KCFI type id of
 *     `int (*)(struct kprobe *, struct pt_regs *)`. The kernel's
 *     `kprobe_breakpoint_handler` calls `p->pre_handler(p, regs)` through a
 *     CONFIG_CFI_CLANG-instrumented indirect call, so the 4 bytes in front of
 *     `maplesu_l3_pre` must be the id the image compares there. build_root_module.py
 *     compiles a reference TU with this build's own flags to obtain the id, requires
 *     it to be one of the ids `kprobe_breakpoint_handler` really compares, and then
 *     requires the module's *automatically emitted* prefix to equal it -- no byte is
 *     patched. The same value is injected as the `-D` this file reads back at load
 *     time, so a module whose prefix drifted refuses to stay resident.
 *   * `MAPLESU_CRED_SOURCE` -- what `prepare_kernel_cred()` is given. `NULL` is
 *     the standard idiom, but on this image `prepare_kernel_cred` starts with
 *     `cbz x0, <WARN_ON_ONCE path>` (`kernel/cred.c:637` in the image's own
 *     `__bug_table`), i.e. a NULL argument warns and returns NULL. A WARN is a
 *     ring-buffer trace and, under panic_on_warn, a panic -- so the builder reads
 *     the image's `prepare_kernel_cred` entry and, when NULL is rejected, selects
 *     1 (`&init_task`), which yields the same init-derived root cred with no
 *     warning. Both spellings are compiled from this one source.
 *
 * KCFI
 * ----
 * The two structure names in the callback's declaration are the *kernel's*
 * (`struct kprobe`, `struct pt_regs`) and are left deliberately opaque: clang
 * hashes the spelling it sees, so `struct maplesu_kprobe *` would hash to a
 * different id (measured: 0x2b8cdf69 instead of 0xa6be5dd9) and the kernel's
 * compare would trap on the first hit. Nothing in this file dereferences either
 * one; `regs` is cast to this module's `pt_regs` layout (kernel_compat.h) before
 * it is read.
 *
 * Every function that calls through a runtime-resolved address is MAPLESU_NOCFI,
 * so no kCFI check is emitted inside this module: with CONFIG_PANIC_ON_OOPS=y a
 * surviving `brk` is a panic, not a log line. The callback itself is *not*
 * annotated -- its 4-byte prefix is mandatory and is the kernel's own id.
 *
 * The token never reaches printk
 * ------------------------------
 * The 64-bit token is generated in userspace and handed to the kernel; it is the
 * only secret in the channel. This module therefore never prints it: the ARM
 * evidence line carries `armed owner=<uid> pool=<n>`, and the SU line carries the
 * uid and the pool capacity. The helper already knows the token it sent, so
 * `suToken` in the evidence JSON comes from the helper, not from the ring buffer,
 * and this module's `.rodata` carries no `suToken=`/`%016llx`.
 */
#include "kernel_compat.h"

/*
 * The kernel's export table. `register_kprobe`/`unregister_kprobe` are
 * EXPORT_SYMBOL_GPL and `_printk` is the exported printk entry; these three are
 * the module's complete import set (L3-2).
 */
struct maplesu_l3_probe;
extern int register_kprobe(struct maplesu_l3_probe *probe);
extern void unregister_kprobe(struct maplesu_l3_probe *probe);
extern int _printk(const char *fmt, ...);

#define MAPLESU_TAG "maplesu_l3: "

/* ------------------------------------------------------------------------ */
/* ABI v2 -- fixed by the controller; not tunable per build.                 */
/* ------------------------------------------------------------------------ */

/*
 * Option 4 is PR_SET_DUMPABLE: a kernel option that carries no payload, so every
 * real call has arg3 == arg4 == 0 and this gate's magic (a non-zero token) never
 * matches one. `op` is the call's arg2, and 0/1 are exactly the two values the
 * native PR_SET_DUMPABLE accepts -- which is what makes `prctl() == 0` the same
 * answer for a granted and a denied request (see the header).
 */
#define MAPLESU_L3_OPTION	4u	/* prctl option: PR_SET_DUMPABLE */
#define MAPLESU_L3_OP_ARM	0u	/* arg2 = 0: arm the gate */
#define MAPLESU_L3_OP_SU	1u	/* arg2 = 1: take one cred */

/*
 * The magic and the token, each one statement so the gate can assert the shape
 * itself instead of a comment. `MAPLESU_L3_MAGIC` is the whole magic below the
 * option test: a call whose two token halves are both zero is a native
 * PR_SET_DUMPABLE and is never this gate's. `MAPLESU_L3_TOKEN` is the ABI's
 * `token = (arg4 << 32) | arg3`, so a zero token cannot pass the magic either.
 */
#define MAPLESU_L3_MAGIC(arg3, arg4) \
	((((u32)(arg3)) | ((u32)(arg4))) != 0u)
#define MAPLESU_L3_TOKEN(arg3, arg4) \
	((((u64)(arg4)) << 32) | (((u64)(arg3)) & 0xffffffffu))

/* Up to 64 pre-allocated immutable credentials. Checkouts acquire a reference;
 * the module retains its own reference, so this is capacity, not a request limit. */
#define MAPLESU_L3_POOL		64u

/* The ARM owner range, from the ABI: an app uid, not a system uid, not root. */
#define MAPLESU_L3_OWNER_MIN	10000u
#define MAPLESU_L3_OWNER_MAX	100000u

/*
 * The one symbol this module registers on. It is the *only* kernel function name
 * the gate depends on, it is carried as a string in .rodata, and L3-9 asserts
 * that this image really has it (a name that does not resolve is a module that
 * cannot arm, not a module that hooks the wrong syscall).
 */
#define MAPLESU_L3_SYMBOL	"__arm64_sys_prctl"

/* errno values from asm-generic (the kernel's numbering, not the host CRT's). */
#define MAPLESU_EPERM		1
#define MAPLESU_ENOENT		2
#define MAPLESU_EIO		5
#define MAPLESU_ENOMEM		12
#define MAPLESU_ENOSYS		38

/* Where the creds come from; selected by the builder from the image. */
#define MAPLESU_CRED_NULL	0
#define MAPLESU_CRED_INIT_TASK	1

/* arm64 kernel virtual addresses start here (48-bit VA, TTBR1 half). */
#define MAPLESU_KERNEL_VA_MIN	0xFFFF000000000000UL

/*
 * These three are *not* defaults. A build without them is a build whose author
 * did not read the image, and a wrong value here is a hook the kernel traps on --
 * silent at compile time, so they are compile errors.
 */
#ifndef MAPLESU_L3_PRE_KCFI_ID
#error "MAPLESU_L3_PRE_KCFI_ID must be injected from the reference TU (build_root_module.py)"
#endif
#ifndef MAPLESU_L3_KPROBE_SIZE
#define MAPLESU_L3_KPROBE_SIZE 0x80
#endif
#ifndef MAPLESU_CRED_SOURCE
#error "MAPLESU_CRED_SOURCE must be injected from the image (build_root_module.py)"
#endif

#if MAPLESU_CRED_SOURCE != MAPLESU_CRED_NULL && \
	MAPLESU_CRED_SOURCE != MAPLESU_CRED_INIT_TASK
#error "MAPLESU_CRED_SOURCE is 0 (NULL) or 1 (init_task); nothing else is defined"
#endif

/*
 * "the source lookup failed" is only a real question when the image needs
 * &init_task. With MAPLESU_CRED_SOURCE=0 the source *is* NULL by design, and the
 * obvious `source == 0` test would be constant-folded to true at -O2, deleting
 * every registration and pool statement after it (the 6.1 image is the one family
 * where prepare_kernel_cred() accepts a NULL daemon, so it is the one family where
 * this branch is compiled). The test must therefore not exist in that build.
 */
#if MAPLESU_CRED_SOURCE == MAPLESU_CRED_NULL
#define MAPLESU_CRED_SOURCE_UNRESOLVED(source)	0
#else
#define MAPLESU_CRED_SOURCE_UNRESOLVED(source)	((source) == 0)
#endif

/* ------------------------------------------------------------------------ */
/* The two kernel structures the callback names, and the probe object.       */
/* ------------------------------------------------------------------------ */

/*
 * Deliberately opaque: only the *spelling* matters, because it is what clang
 * hashes into the prefix the kernel compares (see the header comment). No member
 * of either is ever accessed through these names.
 */
struct kprobe;
struct pt_regs;

typedef int (*maplesu_l3_pre_handler_fn)(struct kprobe *p, struct pt_regs *regs);

/*
 * `struct kprobe` as the image's BTF declares it (contract `kprobe`): hlist@0x00,
 * list@0x10, nmissed@0x20, addr@0x28, symbol_name@0x30, offset@0x38,
 * pre_handler@0x40, post_handler@0x48, opcode@0x50, ainsn@0x58, flags@0x78.
 *
 * kernel_compat.h's `struct maplesu_kprobe` has the right *size* but puts
 * pre_handler at +0x00 (it was written for a build that only used addr and
 * symbol_name, and the root module must stay byte-identical, so it is frozen).
 * This module sets pre_handler, so it declares the layout it uses -- and asserts
 * every offset it depends on, because a wrong offset here is a module that loads
 * and then jumps into whatever the kernel reads at +0x40.
 */
struct maplesu_l3_probe {
	u8 hlist[0x10];           /* +0x00 struct hlist_node */
	u8 list[0x10];            /* +0x10 struct list_head */
	uptr nmissed;             /* +0x20 unsigned long nmissed */
	uptr addr;                /* +0x28 kprobe_opcode_t *addr, set by the kernel */
	const char *symbol_name;  /* +0x30 const char *symbol_name */
	u32 offset;               /* +0x38 unsigned int offset */
	u32 pad_3c;               /* +0x3c */
	maplesu_l3_pre_handler_fn pre_handler;  /* +0x40 kprobe_pre_handler_t */
	u8 post_handler[8];       /* +0x48 kprobe_post_handler_t (NULL) */
	u8 tail[MAPLESU_L3_KPROBE_SIZE - 0x50]; /* +0x50 opcode/ainsn/flags */
};

_Static_assert(sizeof(struct maplesu_l3_probe) == MAPLESU_L3_KPROBE_SIZE,
	       "struct kprobe must be MAPLESU_L3_KPROBE_SIZE bytes");
_Static_assert(__builtin_offsetof(struct maplesu_l3_probe, addr) == 0x28,
	       "kprobe.addr must be at +0x28");
_Static_assert(__builtin_offsetof(struct maplesu_l3_probe, symbol_name) == 0x30,
	       "kprobe.symbol_name must be at +0x30");
_Static_assert(__builtin_offsetof(struct maplesu_l3_probe, pre_handler) == 0x40,
	       "kprobe.pre_handler must be at +0x40 (BTF)");

/* ------------------------------------------------------------------------ */
/* Kernel function types we call through runtime-resolved addresses.         */
/* ------------------------------------------------------------------------ */

typedef unsigned long (*maplesu_kallsyms_lookup_name_fn)(const char *name);
typedef void *(*maplesu_prepare_kernel_cred_fn)(void *daemon);
typedef int (*maplesu_commit_creds_fn)(void *cred);
typedef void (*maplesu_put_cred_fn)(const void *cred);
/*
 * `__arm64_sys_getuid`: long (*)(const struct pt_regs *). The parameter type is
 * this module's spelling of the layout (kernel_compat.h); the function ignores it
 * entirely (its prologue never reads x0), which is the whole point of using it to
 * read the caller's uid without a single struct offset.
 */
typedef long (*maplesu_getuid_fn)(const struct maplesu_pt_regs *regs);

/* ------------------------------------------------------------------------ */
/* State. Everything here is .bss: nothing is per-release data.              */
/* ------------------------------------------------------------------------ */

static maplesu_kallsyms_lookup_name_fn maplesu_lookup;
static maplesu_prepare_kernel_cred_fn maplesu_prepare;
static maplesu_commit_creds_fn maplesu_commit;
static maplesu_put_cred_fn maplesu_put;
static maplesu_put_cred_fn maplesu_put_final;
static maplesu_getuid_fn maplesu_getuid;
static struct maplesu_selinux_state *maplesu_selinux;

/* The registration object; .bss, so it outlives init_module. */
static struct maplesu_l3_probe maplesu_probe;
static struct maplesu_l3_probe maplesu_avc_probe;
static u32 maplesu_avc_registered;
static uptr maplesu_groups;
static void *(*maplesu_groups_alloc)(int count);
static void (*maplesu_groups_free)(void *groups);
static void (*maplesu_set_groups)(void *cred, void *groups);
static u32 maplesu_registered;	/* register_kprobe() succeeded and not undone */

/*
 * The gate. `maplesu_armed` is the ARM *claim* (the ABI's CAS 0 -> 1); `ready`
 * is the publication of (token, owner) after the claim was won. SU requires
 * both, so a caller that arrives between the claim and the publication is denied
 * instead of being compared against a stale token.
 */
static u32 maplesu_armed;
static u32 maplesu_ready;
static u64 maplesu_token;	/* 64-bit, two 32-bit syscall arguments */
static u32 maplesu_owner_uid;
static u32 maplesu_pool_count;	/* immutable slots (atomic publication) */
static u32 maplesu_pool_cursor;
static uptr maplesu_pool[MAPLESU_L3_POOL];	/* kernel-root creds, usage == 1 */
static uptr maplesu_cred_source;	/* NULL or &init_task */

/* One bounded evidence line per denial class (no flooding from a hostile app). */
static u32 maplesu_arm_denied;
static u32 maplesu_su_denied;

/* The callback. Global so its address is taken and its prefix is emitted. */
int maplesu_l3_pre(struct kprobe *p, struct pt_regs *regs);

/* ------------------------------------------------------------------------ */
/* Runtime lookup and the guarded calls into the kernel.                     */
/* ------------------------------------------------------------------------ */

/* Indirect call through a resolved address: no KCFI check may be emitted here. */
static MAPLESU_NOCFI __attribute__((noinline)) uptr maplesu_sym(const char *name)
{
	if (maplesu_lookup == MAPLESU_NULL)
		return 0;
	return maplesu_lookup(name);
}

/*
 * The caller's real uid, read through `__arm64_sys_getuid(frame)`.
 *
 * The obvious spelling is `current->cred->uid`, which needs two per-KMI
 * structure offsets. `__arm64_sys_getuid` is `from_kuid_munged(current_user_ns(),
 * current_uid())` and never touches its argument (verified in the image: the
 * prologue loads sp_el0 and a per-cpu offset, and has no load from x0), so the
 * kernel's own function answers "what is the uid of the task in this syscall"
 * with no offsets and no way to get them wrong. It does not sleep, take a lock,
 * or fault -- which is what makes it usable from a kprobe callback.
 *
 * A lookup that failed is reported as 0xffffffff, which is neither 0 (ARM) nor
 * any legal owner_uid (SU), so a broken lookup can only deny -- never grant.
 */
static MAPLESU_NOCFI __attribute__((noinline))
u32 maplesu_caller_uid(const struct maplesu_pt_regs *frame)
{
	maplesu_getuid_fn getuid = (maplesu_getuid_fn)(void *)maplesu_getuid;

	if (getuid == MAPLESU_NULL)
		return 0xffffffffu;
	return (u32)(getuid(frame) & 0xffffffffL);
}

/*
 * The handover. One indirect call, isolated so the callback that must keep the
 * kernel's KCFI id contains none: clang lowers `commit(cred)` through a function
 * pointer to a checked indirect call, and that check's id is this module's guess
 * about `int (*)(struct cred *)` -- a guess that a NOCFI wrapper removes entirely.
 */
static MAPLESU_NOCFI __attribute__((noinline)) void maplesu_handover(uptr cred)
{
	maplesu_commit_creds_fn commit =
		(maplesu_commit_creds_fn)(void *)maplesu_commit;

	if (commit != MAPLESU_NULL && cred != 0)
		commit((void *)cred);
}

/* The pool owns one reference per immutable cred for the module lifetime.
 * Checkout takes the extra reference commit_creds consumes, just like get_cred.
 * No allocation or sleeping is needed, and successful requests never exhaust it.
 * unregister_kprobe waits for checkouts before cleanup drops the pool references. */
static uptr maplesu_pool_take(void)
{
#if MAPLESU_CRED_USAGE_SIZE == 8
	typedef u64 maplesu_cred_ref_t;
#elif MAPLESU_CRED_USAGE_SIZE == 4
	typedef u32 maplesu_cred_ref_t;
#else
#error "cred.usage must be measured as a 32-bit or 64-bit atomic"
#endif
	u32 count = __atomic_load_n(&maplesu_pool_count, __ATOMIC_ACQUIRE);
	uptr cred;
	if (count == 0)
		return 0;
	cred = maplesu_pool[__atomic_fetch_add(&maplesu_pool_cursor, 1u,
					    __ATOMIC_RELAXED) % count];
	__atomic_add_fetch((maplesu_cred_ref_t *)(cred + MAPLESU_CRED_USAGE_OFF),
			   1u, __ATOMIC_RELAXED);
	return cred;
}

/*
 * The 4 bytes in front of the callback, read back at load time.
 *
 * If this is not the id the image compares at its `kprobe_breakpoint_handler`
 * call site, the kernel's first call into us is a trap, and with
 * CONFIG_PANIC_ON_OOPS=y a trap is a panic. The builder proves the id and proves
 * the emitted prefix equals it; this is the module refusing to stay resident if
 * that proof ever stopped holding.
 */
#ifndef MAPLESU_LEGACY_CFI
static u32 maplesu_handler_prefix(void)
{
	const volatile u32 *slot =
		(const volatile u32 *)((const u8 *)(const void *)&maplesu_l3_pre - 4);

	return *slot;
}
#endif

/*
 * A denial is a *decision*, not a return value: the callback returns 0 (continue
 * the probed function) and this helper records the ABI errno once per class. The
 * line carries no token.
 */
static __attribute__((noinline)) int maplesu_deny(u32 *seen, u32 op, int err,
						  u32 uid)
{
	if (__atomic_exchange_n(seen, 1u, __ATOMIC_RELAXED) == 0u)
		_printk(MAPLESU_TAG "denied op=%u rc=-%d uid=%u owner=%u armed=%u "
			"pool=%u\n", (unsigned)op, (int)-err, (unsigned)uid,
			(unsigned)maplesu_owner_uid,
			(unsigned)__atomic_load_n(&maplesu_armed, __ATOMIC_RELAXED),
			(unsigned)__atomic_load_n(&maplesu_pool_count,
						  __ATOMIC_RELAXED));
	return 0;
}

/* A private, refcounted group_info identifies only credentials minted here.
 * fork/exec retain that object; setgroups creates another and loses the marker.
 * Holding one module reference prevents address reuse after the last child exits.
 * These offsets are measured from the image BTF, never host kernel headers. */
static uptr maplesu_current_task(void)
{
	uptr task;
	__asm__ volatile("mrs %0, sp_el0" : "=r"(task));
	return task;
}

static int maplesu_root_subject(uptr task)
{
	uptr cred;
	if (!__atomic_load_n(&maplesu_ready, __ATOMIC_ACQUIRE) ||
	    !maplesu_groups || !task)
		return 0;
	cred = *(const volatile uptr *)(task + MAPLESU_TASK_CRED_OFF);
	if (!cred)
		return 0;
	return *(const volatile u32 *)(cred + MAPLESU_CRED_UID_OFF) == 0 &&
	       *(const volatile u32 *)(cred + MAPLESU_CRED_EUID_OFF) == 0 &&
	       *(const volatile uptr *)(cred + MAPLESU_CRED_GROUPS_OFF) == maplesu_groups;
}

/* The SU caller is the forked execution child, not the manager's threads.
 * Disable its inherited syscall filter after the credential handover. Keep the
 * filter pointer/count intact: fork and exit still own and release those refs,
 * and releasing a filter here could sleep in the kprobe callback. */
static void maplesu_root_seccomp_disable(void)
{
	uptr task = maplesu_current_task();
	if (!maplesu_root_subject(task))
		return;
	__atomic_store_n((u32 *)(task + MAPLESU_TASK_SECCOMP_MODE_OFF),
			 0u, __ATOMIC_RELAXED);
	__atomic_fetch_and((u64 *)(task + MAPLESU_TASK_THREAD_FLAGS_OFF),
			   ~((u64)MAPLESU_TIF_SECCOMP_MASK), __ATOMIC_RELEASE);
}

#ifdef MAPLESU_L3_BOOT_SDK
static void *(*maplesu_prepare_creds)(void);
/* SDK authentication has already succeeded in normal syscall context. Keep its
 * SID and capabilities; attach our refcounted marker only to a fresh cred, never
 * to a published object shared with a parent, sibling or the L3 pool. */
static MAPLESU_NOCFI int maplesu_sdk_root_handover(void)
{
	uptr task = maplesu_current_task();
	uptr cred = *(const volatile uptr *)(task + MAPLESU_TASK_CRED_OFF);
	void *next;
	if (*(const volatile u32 *)(cred + MAPLESU_CRED_UID_OFF) != 0 ||
	    *(const volatile u32 *)(cred + MAPLESU_CRED_EUID_OFF) != 0)
		return 0;
	if (!__atomic_load_n(&maplesu_ready, __ATOMIC_ACQUIRE) || !maplesu_groups)
		return -MAPLESU_EPERM;
	if (!maplesu_root_subject(task)) {
		next = maplesu_prepare_creds();
		if (!next)
			return -MAPLESU_ENOMEM;
		maplesu_set_groups(next, (void *)maplesu_groups);
		maplesu_commit(next);
	}
	maplesu_root_seccomp_disable();
	return 0;
}
#endif

/* Only this separate, entry-only callback changes a return. The builder rejects
 * an entry that has already changed SP/LR. Skip before any PAC prologue executes;
 * LR is still the caller's return PC. The prctl callback remains read-only. */
#ifdef MAPLESU_L3_BOOT_SDK
extern int msu_boot_sdk_avc_redirect(struct pt_regs *);
#endif
__attribute__((noinline))
int maplesu_avc_pre(struct kprobe *p, struct pt_regs *regs)
{
	struct maplesu_pt_regs *result;
	(void)p;
	if (regs == MAPLESU_NULL)
		return 0;
	if (!maplesu_root_subject(maplesu_current_task())) {
#ifdef MAPLESU_L3_BOOT_SDK
		return msu_boot_sdk_avc_redirect(regs);
#else
		return 0;
#endif
	}
	result = (struct maplesu_pt_regs *)(void *)regs;
	result->regs[0] = 0;
	result->pc = result->regs[30];
	return 1;
}

static MAPLESU_NOCFI void maplesu_groups_release(void)
{
	uptr groups = maplesu_groups;
	if (groups && __atomic_sub_fetch((u32 *)(groups + MAPLESU_GROUP_USAGE_OFF),
					1u, __ATOMIC_ACQ_REL) == 0)
		maplesu_groups_free((void *)groups);
	maplesu_groups = 0;
}

#include "maplesu_selinux_hide.h"
#include "maplesu_policy_control.h"

/* ------------------------------------------------------------------------ */
/* The gate.                                                                 */
/* ------------------------------------------------------------------------ */

/*
 * `int (struct kprobe *, struct pt_regs *)` -- the kernel's
 * `kprobe_pre_handler_t`, spelled with the kernel's own structure names so the
 * emitted KCFI prefix is the id `kprobe_breakpoint_handler` compares. The
 * function is deliberately *not* MAPLESU_NOCFI: the prefix is mandatory here.
 *
 * The handler observes and decides; it never changes the probed frame and always
 * returns 0, which tells kprobes "carry on with the instruction and with the
 * function's own return value".
 */
__attribute__((noinline))
int maplesu_l3_pre(struct kprobe *p, struct pt_regs *regs)
{
	const struct maplesu_pt_regs *frame;
	const struct maplesu_pt_regs *argp;
	u64 token;
	u32 option;
	u32 op;
	u32 uid;
	u32 owner;
	uptr cred;

	(void)p;

	/* A trap always has a frame; fail closed rather than deref NULL. */
	if (regs == MAPLESU_NULL)
		return 0;

	/*
	 * The probe is at the entry of `__arm64_sys_prctl(const struct pt_regs *)`,
	 * so x0 holds the frame pointer `invoke_syscall()` passed, not the option
	 * (the image's own prologue loads the option from [x0]). Nothing here
	 * trusts x0 blindly: a value that is not a kernel address is not a frame.
	 */
	frame = (const struct maplesu_pt_regs *)(const void *)regs;
	argp = (const struct maplesu_pt_regs *)(uptr)frame->regs[0];
	if ((uptr)argp < MAPLESU_KERNEL_VA_MIN)
		return 0;

	option = (u32)argp->regs[0];
	if (option != MAPLESU_L3_OPTION)
		return 0;	/* not ours: observe nothing, change nothing */

	/*
	 * ABI v2's magic, in full: option 4 (PR_SET_DUMPABLE) *and* a non-zero
	 * token. A real `prctl(PR_SET_DUMPABLE, 0|1)` has arg3 == arg4 == 0 and
	 * leaves through this branch untouched -- the module's own prctl traffic
	 * must be invisible to everything that is not the manager. A zero token is
	 * never magic, which is what makes SU's token comparison meaningful.
	 */
	if (!MAPLESU_L3_MAGIC(argp->regs[2], argp->regs[3]))
		return 0;	/* a native PR_SET_DUMPABLE: observe nothing */

	op = (u32)argp->regs[1];
	if (op == MSU_POLICY_HOOK_OP && (u32)argp->regs[2] == MSU_POLICY_HOOK_TAG_LO &&
	    (u32)argp->regs[3] == MSU_POLICY_HOOK_TAG_HI)
		return 0; /* handled only by the independent process-context listener */
	if (op == MSU_STATUS_OP && (u32)argp->regs[2] == MSU_STATUS_TAG_LO &&
	    (u32)argp->regs[3] == MSU_STATUS_TAG_HI) {
		maplesu_status_control((uptr)argp->regs[4]);
		return 0;
	}
	token = MAPLESU_L3_TOKEN(argp->regs[2], argp->regs[3]);

	switch (op) {
	case MAPLESU_L3_OP_ARM:
		/*
		 * ABI: only inside the window, only uid 0, only an app uid as the
		 * owner, only a non-zero token, and only once.
		 *
		 *   * enforcing must be 0 -- the ARM is only valid while the
		 *     handover window is open, and this module *reads* that byte,
		 *     it never writes it (the restore is the helper's and
		 *     maplesu_root's job, not this module's);
		 *   * uid 0 -- the helper runs as kernel-domain root;
		 *   * owner in [10000, 100000) -- an app uid, so SU can only ever
		 *     mint root for the app that armed the gate;
		 *   * token != 0 -- the magic already excludes a zero token (a zero
		 *     token is not this gate's call at all); the check stays as the
		 *     ARM branch's own statement of the ABI, so a gate reached by
		 *     anything but the magic path still refuses a vacuous token;
		 *   * CAS 0 -> 1 -- exactly one ARM per load. A second ARM is
		 *     denied instead of overwriting the gate: "last writer wins"
		 *     would let any later uid-0 caller take it over.
		 */
		if (maplesu_selinux == MAPLESU_NULL ||
		    maplesu_selinux->enforcing != 0)
			return maplesu_deny(&maplesu_arm_denied, op, MAPLESU_EPERM,
					    0xffffffffu);
		uid = maplesu_caller_uid(frame);
		if (uid != 0)
			return maplesu_deny(&maplesu_arm_denied, op, MAPLESU_EPERM,
					    uid);
		owner = (u32)argp->regs[4];
		if (owner < MAPLESU_L3_OWNER_MIN || owner >= MAPLESU_L3_OWNER_MAX)
			return maplesu_deny(&maplesu_arm_denied, op, MAPLESU_EPERM,
					    uid);
		if (token == 0)
			return maplesu_deny(&maplesu_arm_denied, op, MAPLESU_EPERM,
					    uid);
		if (!__sync_bool_compare_and_swap(&maplesu_armed, 0u, 1u))
			return maplesu_deny(&maplesu_arm_denied, op, MAPLESU_EPERM,
					    uid);
		/* Claim won: publish the pair before SU may read it (release). */
		maplesu_owner_uid = owner;
		maplesu_token = token;
		__atomic_store_n(&maplesu_ready, 1u, __ATOMIC_RELEASE);
		/*
		 * The helper copies this line out of the ring buffer and records
		 * the armed gate. The format is the ABI's evidence contract; the
		 * token is not in it (the helper already knows the token it sent).
		 */
		_printk(MAPLESU_TAG "armed owner=%u pool=%u\n",
			(unsigned)owner,
			(unsigned)__atomic_load_n(&maplesu_pool_count,
						  __ATOMIC_RELAXED));
		return 0;

	case MAPLESU_L3_OP_SU:
		if (!__atomic_load_n(&maplesu_armed, __ATOMIC_ACQUIRE))
			return maplesu_deny(&maplesu_su_denied, op, MAPLESU_EPERM,
					    0xffffffffu);
		if (!__atomic_load_n(&maplesu_ready, __ATOMIC_ACQUIRE))
			return maplesu_deny(&maplesu_su_denied, op, MAPLESU_EPERM,
					    0xffffffffu);
		/* Token and uid are checked before anything is taken. */
		if (token != maplesu_token)
			return maplesu_deny(&maplesu_su_denied, op, MAPLESU_EPERM,
					    0xffffffffu);
		uid = maplesu_caller_uid(frame);
		if (uid != maplesu_owner_uid)
			return maplesu_deny(&maplesu_su_denied, op, MAPLESU_EPERM,
					    uid);
		cred = maplesu_pool_take();
		if (cred == 0)
			return maplesu_deny(&maplesu_su_denied, op, MAPLESU_ENOMEM,
					    uid);
		/*
		 * The handover: exactly the reference prepare_kernel_cred()
		 * returned, which is the reference commit_creds() takes over.
		 */
		maplesu_handover(cred);
		maplesu_root_seccomp_disable();
		_printk(MAPLESU_TAG "su granted uid=%u pool=%u\n", (unsigned)uid,
			(unsigned)__atomic_load_n(&maplesu_pool_count,
						  __ATOMIC_RELAXED));
		return 0;

	default:
		/* A magic option this ABI does not define: deny, never act. */
		return maplesu_deny(&maplesu_su_denied, op, MAPLESU_EPERM,
				    0xffffffffu);
	}
}

/* ------------------------------------------------------------------------ */
/* Module entry points.                                                      */
/* ------------------------------------------------------------------------ */

/*
 * Drop the pool's own references, including on failed initialization.
 * put_cred is often inline and absent from kallsyms. In that case mirror its
 * measured-width reference decrement and call __put_cred only at zero.
 * Credentials still held by a live task keep their reference and group marker.
 */
static MAPLESU_NOCFI __attribute__((noinline))
void maplesu_pool_release(const char *why, u32 held)
{
	maplesu_put_cred_fn put = (maplesu_put_cred_fn)(void *)maplesu_put;
	maplesu_put_cred_fn put_final =
		(maplesu_put_cred_fn)(void *)maplesu_put_final;
#if MAPLESU_CRED_USAGE_SIZE == 8
	typedef u64 maplesu_cred_ref_t;
#elif MAPLESU_CRED_USAGE_SIZE == 4
	typedef u32 maplesu_cred_ref_t;
#else
#error "cred.usage must be measured as a 32-bit or 64-bit atomic"
#endif
	u32 index;

	for (index = 0; index < held; ++index) {
		uptr cred = maplesu_pool[index];
		if (cred != 0) {
			if (put != MAPLESU_NULL)
				put((const void *)cred);
			else if (__atomic_sub_fetch(
				(maplesu_cred_ref_t *)(cred + MAPLESU_CRED_USAGE_OFF),
				1u, __ATOMIC_ACQ_REL) == 0)
				put_final((const void *)cred);
		}
		maplesu_pool[index] = 0;
	}
	__atomic_store_n(&maplesu_pool_count, 0u, __ATOMIC_RELEASE);
	_printk(MAPLESU_TAG "%s: released pool=%u\n", why, (unsigned)held);
	maplesu_groups_release();
}

/*
 * init_module does everything that may sleep or fail: resolve, build the pool,
 * check its own KCFI prefix, register the kprobe. On any failure it undoes what
 * it did -- the kprobe if it was registered, the creds if they can be freed --
 * and returns a negative errno, so the kernel drops a module that never hooked
 * anything.
 */
MAPLESU_NOCFI __attribute__((section(".init.text"))) __attribute__((noinline))
int init_module(void)
{
	struct maplesu_l3_probe probe;
	u8 *raw = (u8 *)&probe;
	uptr cred;
	uptr source;
	u32 got = 0;
	u32 index;
	u32 enforcing = 0xffffffffu;
	int rc;

	_printk(MAPLESU_TAG "init stage=entry\n");
	/* 1. kallsyms_lookup_name, through a kprobe on its own name. */
	for (index = 0; index < (u32)sizeof(probe); ++index)
		raw[index] = 0;
	probe.symbol_name = "kallsyms_lookup_name";
	if (register_kprobe(&probe) < 0) {
		_printk(MAPLESU_TAG "kallsyms_lookup_name not found\n");
		return -MAPLESU_ENOSYS;
	}
	maplesu_lookup = (maplesu_kallsyms_lookup_name_fn)probe.addr;
	unregister_kprobe(&probe);
	if (maplesu_lookup == MAPLESU_NULL) {
		_printk(MAPLESU_TAG "kprobe resolved no address\n");
		return -MAPLESU_ENOSYS;
	}
	_printk(MAPLESU_TAG "init stage=lookup-ready\n");

	/* 2. Every kernel object this module uses, by name (no per-KMI address). */
	maplesu_prepare =
		(maplesu_prepare_kernel_cred_fn)maplesu_sym("prepare_kernel_cred");
	maplesu_commit = (maplesu_commit_creds_fn)maplesu_sym("commit_creds");
	maplesu_put = (maplesu_put_cred_fn)maplesu_sym("put_cred");
	if (maplesu_put == MAPLESU_NULL)
		maplesu_put_final = (maplesu_put_cred_fn)maplesu_sym("__put_cred");
	maplesu_getuid = (maplesu_getuid_fn)maplesu_sym("__arm64_sys_getuid");
	maplesu_selinux =
		(struct maplesu_selinux_state *)maplesu_sym("selinux_state");
#if MAPLESU_CRED_SOURCE == MAPLESU_CRED_INIT_TASK
	source = maplesu_sym("init_task");
#else
	source = 0;
#endif
	if (maplesu_prepare == MAPLESU_NULL || maplesu_commit == MAPLESU_NULL ||
	    (maplesu_put == MAPLESU_NULL && maplesu_put_final == MAPLESU_NULL) ||
	    maplesu_getuid == MAPLESU_NULL || maplesu_selinux == MAPLESU_NULL ||
	    MAPLESU_CRED_SOURCE_UNRESOLVED(source)) {
		_printk(MAPLESU_TAG "lookup failed prepare=%px commit=%px "
			"getuid=%px selinux=%px source=%px\n",
			(void *)maplesu_prepare, (void *)maplesu_commit,
			(void *)maplesu_getuid, (void *)maplesu_selinux,
			(void *)source);
		return -MAPLESU_ENOENT;
	}
	maplesu_groups_alloc = (void *(*)(int))maplesu_sym("groups_alloc");
	maplesu_groups_free = (void (*)(void *))maplesu_sym("groups_free");
	maplesu_set_groups = (void (*)(void *, void *))maplesu_sym("set_groups");
	if (!maplesu_groups_alloc || !maplesu_groups_free || !maplesu_set_groups)
		return -MAPLESU_ENOENT;
	_printk(MAPLESU_TAG "init stage=symbols-ready\n");
	maplesu_groups = (uptr)maplesu_groups_alloc(0);
	if (!maplesu_groups)
		return -MAPLESU_ENOMEM;
	_printk(MAPLESU_TAG "init stage=groups-ready\n");
	maplesu_cred_source = source;
	/* The window state at load time: evidence, and the ARM gate's input. */
	enforcing = (u32)maplesu_selinux->enforcing;

	/*
	 * 3. The cred pool. prepare_kernel_cred() allocates and may sleep, which is
	 *    why this is here and not in the gate. A short pool is not a failure: the
	 *    gate reuses what exists; an
	 *    empty pool means the kernel cannot make a root cred at all, which is a
	 *    load failure, not a degraded channel.
	 */
	while (got < MAPLESU_L3_POOL) {
		cred = (uptr)maplesu_prepare((void *)maplesu_cred_source);
		if (cred == 0)
			break;
		maplesu_set_groups((void *)cred, (void *)maplesu_groups);
		maplesu_pool[got] = cred;
		got++;
	}
	if (got == 0) {
		_printk(MAPLESU_TAG "prepare_kernel_cred(source=%u) returned NULL; "
			"no root cred can be built\n", (unsigned)MAPLESU_CRED_SOURCE);
		maplesu_pool_release("empty pool", 0);
		return -MAPLESU_ENOMEM;
	}
	__atomic_store_n(&maplesu_pool_count, got, __ATOMIC_RELEASE);
	_printk(MAPLESU_TAG "init stage=pool-ready\n");

	/*
	 * 4. The 4-byte prefix clang emitted must be the id the image compares at
	 *    kprobe_breakpoint_handler. Checked before the probe is registered: a
	 *    wrong prefix would be a panic on the first `prctl()`, and the builder
	 *    already failed the build if the reference TU disagreed.
	 */
#ifdef MAPLESU_LEGACY_CFI
	/* 5.15 checks 64-bit types through the compiler-generated dispatcher. */
	{
		extern void __cfi_check(u64 type, void *target, void *diag);

		__cfi_check((u64)MAPLESU_L3_PRE_KCFI_ID,
			    (void *)&maplesu_l3_pre, MAPLESU_NULL);
		__cfi_check((u64)MAPLESU_L3_PRE_KCFI_ID,
			    (void *)&maplesu_avc_pre, MAPLESU_NULL);
	}
#else
	{
		u32 prefix = maplesu_handler_prefix();

		if (prefix != (u32)MAPLESU_L3_PRE_KCFI_ID ||
		    *(const volatile u32 *)((const u8 *)(const void *)&maplesu_avc_pre - 4)
			!= (u32)MAPLESU_L3_PRE_KCFI_ID) {
			_printk(MAPLESU_TAG "handler KCFI prefix 0x%08x != "
				"0x%08x; nothing registered\n", (unsigned)prefix,
				(unsigned)MAPLESU_L3_PRE_KCFI_ID);
			maplesu_pool_release("prefix mismatch", got);
			return -MAPLESU_EIO;
		}
	}

#endif
	_printk(MAPLESU_TAG "init stage=callbacks-ready\n");

	/*
	 * 5. The hook. A fresh object, the symbol name, and the callback: no address
	 *    and no syscall index is a build input, so a table renumbering cannot
	 *    point this at another syscall.
	 */
	for (index = 0; index < (u32)sizeof(maplesu_probe); ++index)
		((u8 *)&maplesu_probe)[index] = 0;
	maplesu_avc_probe.symbol_name = "avc_denied";
	maplesu_avc_probe.pre_handler = maplesu_avc_pre;
	rc = register_kprobe(&maplesu_avc_probe);
	if (rc < 0) {
		maplesu_pool_release("avc registration failed", got);
		return rc;
	}
	maplesu_avc_registered = 1;
	_printk(MAPLESU_TAG "init stage=avc-ready\n");
	maplesu_probe.symbol_name = MAPLESU_L3_SYMBOL;
	maplesu_probe.pre_handler = maplesu_l3_pre;
	rc = register_kprobe(&maplesu_probe);
	if (rc < 0) {
		_printk(MAPLESU_TAG "register_kprobe(%s) failed rc=%d\n",
			MAPLESU_L3_SYMBOL, rc);
		unregister_kprobe(&maplesu_avc_probe);
		maplesu_avc_registered = 0;
		maplesu_pool_release("probe registration failed", got);
		return rc;
	}
	if (maplesu_probe.addr == 0) {
		_printk(MAPLESU_TAG "register_kprobe(%s) returned no address\n",
			MAPLESU_L3_SYMBOL);
		unregister_kprobe(&maplesu_probe);
		unregister_kprobe(&maplesu_avc_probe);
		maplesu_avc_registered = 0;
		maplesu_pool_release("probe resolved no address", got);
		return -MAPLESU_ENOENT;
	}
	maplesu_registered = 1;
	_printk(MAPLESU_TAG "init stage=prctl-ready\n");
	maplesu_status_init();
	maplesu_policy_init();

	/* 6. Resident. This line is the module's own statement of that (no token). */
#ifdef MAPLESU_LEGACY_CFI
	_printk(MAPLESU_TAG "kprobe symbol=%s addr=%px pool=%u cfi=0x%08x%08x "
		"credSource=%u enforcing=%u\n", MAPLESU_L3_SYMBOL,
		(void *)maplesu_probe.addr, (unsigned)got,
		(unsigned)((u64)MAPLESU_L3_PRE_KCFI_ID >> 32),
		(unsigned)MAPLESU_L3_PRE_KCFI_ID,
		(unsigned)MAPLESU_CRED_SOURCE, (unsigned)enforcing);
#else
	_printk(MAPLESU_TAG "kprobe symbol=%s addr=%px pool=%u pre=0x%08x "
		"credSource=%u enforcing=%u\n", MAPLESU_L3_SYMBOL,
		(void *)maplesu_probe.addr, (unsigned)got,
		(unsigned)MAPLESU_L3_PRE_KCFI_ID, (unsigned)MAPLESU_CRED_SOURCE,
		(unsigned)enforcing);
#endif
	return 0;
}

/*
 * cleanup_module is the restore point. `unregister_kprobe()` is the complete
 * undo of the hook: the breakpoint is removed and the kernel drops its last
 * pointer into this module's text, so after `delete_module()` no `prctl()` can
 * jump into freed memory. The leftover creds are given back for the same reason
 * -- they are kernel heap objects, not module data.
 */
MAPLESU_NOCFI void cleanup_module(void)
{
	u32 held;

	if (!maplesu_registered) {
		_printk(MAPLESU_TAG "cleanup skipped (not registered)\n");
		return;
	}
	maplesu_status_cleanup();
	maplesu_policy_cleanup();
	unregister_kprobe(&maplesu_probe);
	maplesu_registered = 0;
	__atomic_store_n(&maplesu_ready, 0u, __ATOMIC_RELEASE);
	if (maplesu_avc_registered) {
		unregister_kprobe(&maplesu_avc_probe);
		maplesu_avc_registered = 0;
	}
	held = __atomic_load_n(&maplesu_pool_count, __ATOMIC_ACQUIRE);
	_printk(MAPLESU_TAG "cleanup symbol=%s unregistered=1 armed=%u pool=%u\n",
		MAPLESU_L3_SYMBOL,
		(unsigned)__atomic_load_n(&maplesu_armed, __ATOMIC_RELAXED),
		(unsigned)held);
	maplesu_pool_release("module exit", held);
}
