/*
 * maplesu_l2 -- the window-scoped L2 hook module (design rev-3, change-set C1).
 *
 * What this is
 * ------------
 * A second, separately unloadable module that lives only inside the permissive
 * window `maplesu_root.ko` opened. It provides three things and nothing else:
 *
 *   1. H1, a control channel. It is a kprobe on `__arm64_sys_ni_syscall` -- the
 *      function every *unimplemented* syscall number lands on -- so the magic
 *      number is whatever the caller put in x8 and the kernel itself keeps in
 *      `pt_regs->syscallno`. `syscall(2)` cannot reach x7, so the 64-bit cookie
 *      (which the loader injected at load time through finit_module's uargs)
 *      is a filter as well as an authenticator; see "cookies" below.
 *   2. H4, a safe read and a two-entry whitelist write: `copy_from_kernel_nofault`
 *      for reads (a bad address is -EFAULT, never an oops) and exactly two write
 *      targets -- this module's own scratch word, and the SELinux `enforcing` byte
 *      written back with the value just read (one byte, same value).
 *   3. H5, install/uninstall and *observation*: a kprobe and a kretprobe on
 *      `do_execveat_common`. The callbacks count and never touch `pt_regs`, so
 *      the exec path behaves exactly as it would without the module.
 *
 * Why kprobe/kretprobe and not the other primitives
 * -------------------------------------------------
 * `CONFIG_FUNCTION_TRACER` is not set on this image, so there is no ftrace entry
 * point to hook; `security_add_hooks` is `.init.text` (freed) and
 * `security_hook_heads` is `__ro_after_init`, so LSM registration after boot is
 * impossible; `sys_call_table` is rodata and patching it is a permanent text/
 * rodata change. kprobe/kretprobe are exported, are pure BRK sites on this image
 * (`CONFIG_KPROBES_ON_FTRACE` cannot be set without DYNAMIC_FTRACE), and vanish
 * on unregister. See design doc sections 2.2 and 3.5.
 *
 * Cookies: the loader gives, the channel only proves
 * --------------------------------------------------
 * The 64-bit cookie arrives as a module parameter from finit_module's uargs
 * ("cookie=0x<16 hex>"), which only the loading process (the window's helper) can
 * supply. The glue's `__param` row points `arg` at `l2_load_cookie`; init_module
 * copies it into the state and refuses to load when it is zero. OP_ARM never
 * writes the cookie -- it only *proves* the caller knows the loader's value, so
 * the "first process to call ARM wins" race of rev-1 is closed: a non-loader
 * cannot guess 64 bits, and `perm=0` keeps the value out of sysfs.
 *
 * One ARM per module load
 * -----------------------
 * `l2.latch` only moves IDLE -> ARMED -> DISARMED within one load. It lives in
 * this module's .bss, so `delete_module` + `finit_module` replay is *not*
 * prevented by it (design 3.7 says so explicitly); the attempt document is what
 * prevents that, not the module.
 *
 * Why ARM/DISARM are latch transitions and not (un)registrations
 * --------------------------------------------------------------
 * The control channel runs in kprobe context, with preemption disabled, and
 * `register_kprobe()`/`unregister_kprobe()` take mutexes and call
 * `synchronize_rcu()` -- they can sleep. So the probes are all registered once,
 * from init_module() (process context), the three functional ones are inert while
 * `l2.latch` is not ARMED, and `cleanup_module()` (also process context, via
 * delete_module) is the only place that unregisters them. Consequences, all
 * deliberate and all recorded in the C1 implementation doc:
 *   * OP_ARM binds the syscall number, proves the number is still unimplemented
 *     on this boot, and flips the latch -- from that instant the three callbacks
 *     observe; before it they return immediately without touching a counter;
 *   * OP_DISARM flips the latch back, so observations stop *immediately* (the
 *     negative control's `hits` freeze with no window of extra hits), while the
 *     BRK sites themselves go away at unload. No capability outlives DISARM;
 *   * the "first hit is self-triggered" discipline is therefore exact for the
 *     control probe (it is the loader's own `svc #0`) and best-effort for the
 *     exec pair: they are registered at load and an environment exec can reach
 *     `l2_pre_execve` before the helper's own `execv`. The defense against a
 *     prototype/id drift is G8's pinned equality against the image's own compare
 *     sites, not the timing of the first hit.
 *
 * kCFI rules this file obeys
 * --------------------------
 *   * every callback is declared with the *kernel's* struct names and keeps its
 *     4-byte type prefix (`int (*)(struct kprobe *, struct pt_regs *)` hashes to
 *     the id `kprobe_breakpoint_handler` compares, 0xa6be5dd9; the kretprobe
 *     handler is 0x8078be15; the post handler 0x6e21b9c7);
 *   * `no_sanitize("kcfi")` is used *only* on functions that call a
 *     runtime-resolved address (`l2_sym`, `l2_kread`, `l2_result_out`): an
 *     indirect call to a function without a type prefix would compare garbage
 *     and trap, and CONFIG_PANIC_ON_OOPS=y turns a trap into a panic.
 *     Callbacks never carry it -- they must keep the prefix the kernel checks;
 *   * no indirect call outside those functions, so the module's .text contains
 *     zero KCFI check sites (gate G13).
 *
 * Imports are exactly the seven the contract declares: the six probe/print/read
 * exports plus `param_ops_ullong` (the `__param` row's ops, referenced by the
 * glue). `__arm64_sys_ni_syscall`, `sys_call_table` and `copy_to_user_nofault`
 * are not exported on this GKI build, so they are runtime lookups -- never
 * imports, and never constants: the addresses live in this module's .bss, filled
 * from kallsyms at load. There is no per-release number in this file.
 */
#include "kernel_compat.h"

/* The seven imports. The first six are the probe/print/read exports (M4); the
 * seventh, `param_ops_ullong`, is referenced by the glue's `__param` row and is
 * therefore part of the object's undefined set without being named here. */
extern int register_kprobe(struct maplesu_l2_kprobe *probe);
extern void unregister_kprobe(struct maplesu_l2_kprobe *probe);
extern int register_kretprobe(struct maplesu_kretprobe *rp);
extern void unregister_kretprobe(struct maplesu_kretprobe *rp);
extern int _printk(const char *fmt, ...);
extern long copy_from_kernel_nofault(void *dst, const void *src, uptr size);

/* The cookie cell. Defined by the glue because the `__param` row's `arg` has to
 * name a link-visible symbol; this is the only non-static datum in the module. */
extern unsigned long long l2_load_cookie;

/* Kernel names for the callback prototypes. KCFI hashes the *spelling* of the
 * function type, so these must be the kernel's names (struct kprobe,
 * struct pt_regs, struct kretprobe_instance) and not this file's shims. The
 * shims (struct maplesu_pt_regs, ...) are used only for field access, by cast. */
struct kprobe;
struct pt_regs;
struct kretprobe_instance;

static int  l2_pre_execve(struct kprobe *p, struct pt_regs *regs);
static void l2_post_execve(struct kprobe *p, struct pt_regs *regs, unsigned long flags);
static int  l2_ret_execve(struct kretprobe_instance *ri, struct pt_regs *regs);
static int  l2_pre_ctl(struct kprobe *p, struct pt_regs *regs);

#define MAPLESU_L2_TAG "maplesu_l2: "

/* ------------------------------------------------------------------------- */
/* Control-channel ABI (design 3.1.2, frozen).                                */
/* ------------------------------------------------------------------------- */

#define L2_OP_ARM 0x01u
#define L2_OP_PROBE 0x02u
#define L2_OP_KREAD 0x03u
#define L2_OP_KWRITE 0x04u
#define L2_OP_SELFTEST 0x05u
#define L2_OP_HITS 0x06u
#define L2_OP_DISARM 0x07u
#define L2_OP_STATUS 0x08u

#define L2_RESULT_MAGIC 0x4d415032u                 /* "MAP2" */
#define L2_PROBE_MAGIC 0x4d41504c45535531ull        /* "MAPLESU1" */
#define L2_RESULT_VERSION 1ull

/* The two write tags. There is no third, and no "any address" mode. */
#define L2_WL_SCRATCH 0x80000001u
#define L2_WL_SELINUX 0x80000002u

/* errno values, spelled out because there is no kernel header here. */
#define L2_EINVAL 22
#define L2_ENOENT 2
#define L2_ENOSYS 38
#define L2_EPERM 1
#define L2_EBUSY 16
#define L2_EIO 5
#define L2_EACCES 13
#define L2_EFAULT 14

#define L2_SYSCALLNO_MAX 0x1000u      /* a bound on ptr arithmetic, not a magic number */

/* ------------------------------------------------------------------------- */
/* State. All of it is file-scope static .bss: no allocation, no kmalloc, so   */
/* unload frees everything and the latch cannot outlive the load (design 3.7). */
/* ------------------------------------------------------------------------- */

#define L2_MAX_PROBES 3
#define L2_PROBE_CTL 0
#define L2_PROBE_EXEC_ENTRY 1
#define L2_PROBE_EXEC_RET 2

#define L2_KIND_KPROBE 1
#define L2_KIND_KRETPROBE 2

#define L2_IDLE 0
#define L2_REGISTERED 1
#define L2_UNREGISTERED 2

#define L2_LATCH_IDLE 0
#define L2_LATCH_ARMED 1
#define L2_LATCH_DISARMED 2

/* The frozen result block (32 bytes, little-endian). */
struct l2_result {
	u32 magic;              /* +0x00 */
	int rc;                 /* +0x04 */
	u64 value;              /* +0x08 read value / magic / counts */
	u64 aux;                /* +0x10 readback / generation / tag */
	u32 hits;               /* +0x18 */
	u32 state;              /* +0x1c bit0 armed, bit1 disarmed, bit2 resident */
};

/* One row of the probe registry. `pre`/`post`/`ret` are the callbacks; the
 * union holds the object the kernel writes into. */
struct l2_probe {
	const char *id;                 /* "ctl.magic" / "execve.entry" / "execve.ret" */
	const char *symbol;             /* resolved by name, never an address */
	u32 kind;
	u32 state;
	u32 hits;                       /* entry-side hits (pre or kretprobe) */
	u32 post_hits;                  /* post-handler hits (execve.entry only) */
	u32 first;                      /* first-hit latch, cmpxchg'd once */
	int errno_reg;
	int (*pre)(struct kprobe *p, struct pt_regs *regs);
	void (*post)(struct kprobe *p, struct pt_regs *regs, unsigned long flags);
	int (*ret)(struct kretprobe_instance *ri, struct pt_regs *regs);
	union {
		struct maplesu_l2_kprobe kp;
		struct maplesu_kretprobe krp;
	} u;
};

struct l2_state {
	u64 lookup;                     /* kallsyms_lookup_name, via the kprobe bootstrap */
	u64 load_cookie;                /* from __param; written once, in init_module */
	u64 generation;                 /* incremented by each successful ARM */
	u32 latch;                      /* IDLE -> ARMED -> DISARMED, one load */
	u32 scno;                       /* bound at ARM from pt_regs->syscallno */
	u64 ni_addr;                    /* runtime &__arm64_sys_ni_syscall */
	u64 sys_call_table;             /* runtime &sys_call_table (read only) */
	u64 copy_to_user;               /* runtime copy_to_user_nofault */
	u64 selinux_addr;               /* runtime &selinux_state */
	u32 enforcing_now;              /* the byte the last kread saw */
	u32 hits_total;
	u32 selftest_rc;
	u32 selftest_probe;
	u32 selftest_kread;
	u32 selftest_kwrite;
	u64 selftest_value;
	u64 scratch;                    /* WL_SCRATCH target */
	struct l2_probe probes[L2_MAX_PROBES];
};

static struct l2_state l2;

typedef unsigned long (*l2_lookup_fn)(const char *name);
typedef long (*l2_copy_to_user_fn)(void *dst, const void *src, uptr size);

/* ------------------------------------------------------------------------- */
/* Small helpers.                                                             */
/* ------------------------------------------------------------------------- */

static u32 l2_state_bits(void)
{
	u32 bits = 4u;                  /* bit2: the module is resident */

	if (l2.latch == L2_LATCH_ARMED)
		bits |= 1u;
	if (l2.latch == L2_LATCH_DISARMED)
		bits |= 2u;
	return bits;
}

static void l2_count(u32 *counter)
{
	/* One relaxed RMW; the generated sequence is an LL/SC pair on this image's
	 * -march baseline, which is interrupt-safe (it retries, it never sleeps). */
	__atomic_fetch_add(counter, 1u, __ATOMIC_RELAXED);
}

/* A one-shot kernel-authored line per probe: the cmpxchg makes "first hit" a
 * fact rather than a race, and keeps printk out of the per-hit path. */
static __attribute__((noinline)) void l2_first_hit(struct l2_probe *p)
{
	u32 expected = 0;

	if (__atomic_compare_exchange_n(&p->first, &expected, 1u, 0,
					__ATOMIC_RELAXED, __ATOMIC_RELAXED))
		_printk(MAPLESU_L2_TAG "first-hit id=%s\n", p->id);
}

/* Runtime lookup. The callee has no type prefix, so this caller is the one
 * place where the KCFI check must be off (design 3.3.1 rule 5). */
static MAPLESU_NOCFI __attribute__((noinline))
u64 l2_sym(const char *name)
{
	if (l2.lookup == 0)
		return 0;
	return (u64)((l2_lookup_fn)l2.lookup)(name);
}

/* H4 read: nofault only. A wrong address is -EFAULT, never an oops, which is
 * the whole point of using this export instead of a dereference. */
static MAPLESU_NOCFI __attribute__((noinline))
int l2_kread(u64 addr, void *dst, u32 len)
{
	if (dst == MAPLESU_NULL || len == 0)
		return -L2_EINVAL;
	return (int)copy_from_kernel_nofault(dst, (const void *)addr, (uptr)len);
}

/* Result write. `copy_to_user_nofault` is a runtime lookup (unexported), so the
 * indirect call lives here and this function is the second KCFI opt-out. */
static MAPLESU_NOCFI __attribute__((noinline))
void l2_result_out(u64 user, int rc, u64 value, u64 aux)
{
	struct l2_result res;

	if (user == 0 || l2.copy_to_user == 0)
		return;
	res.magic = L2_RESULT_MAGIC;
	res.rc = rc;
	res.value = value;
	res.aux = aux;
	res.hits = l2.hits_total;
	res.state = l2_state_bits();
	(void)((l2_copy_to_user_fn)l2.copy_to_user)((void *)user,
						    (const void *)&res,
						    (uptr)sizeof(res));
}

/* ------------------------------------------------------------------------- */
/* H4: the two-entry write whitelist.                                        */
/*                                                                           */
/* WL_SCRATCH proves the write path executes (own .bss, read back).           */
/* WL_SELINUX proves it can reach a kernel object without changing anything:  */
/* the address must be the one the module resolved, the value must equal the  */
/* byte read a moment earlier, and the store is a single byte. The `policy`   */
/* pointer in the same struct is deliberately unreachable: there is no code   */
/* path here that takes an offset into selinux_state.                        */
/* ------------------------------------------------------------------------- */

static __attribute__((noinline))
int l2_kwrite(u64 addr, u64 value, u32 tag)
{
	if (tag == L2_WL_SCRATCH) {
		if (addr != (u64)(uptr)&l2.scratch)
			return -L2_EACCES;
		l2.scratch = value;
		return (l2.scratch == value) ? 0 : -L2_EIO;
	}
	if (tag == L2_WL_SELINUX) {
		u8 now = 0;

		if (addr != l2.selinux_addr)
			return -L2_EACCES;
		if (l2_kread(addr, &now, 1) != 0)
			return -L2_EACCES;
		l2.enforcing_now = (u32)now;
		if (value != (u64)now)
			return -L2_EACCES;      /* same-value only */
		*(volatile u8 *)addr = (u8)value;      /* one byte, by construction */
		return (*(volatile u8 *)addr == (u8)value) ? 0 : -L2_EIO;
	}
	return -L2_EACCES;
}

/* ------------------------------------------------------------------------- */
/* The callbacks. All four are observation-only: none of them writes `regs`.  */
/* ------------------------------------------------------------------------- */

static __attribute__((noinline)) void l2_print_arm(void)
{
	_printk(MAPLESU_L2_TAG "arm scno=%u generation=%llu\n", l2.scno,
		(unsigned long long)l2.generation);
}

static __attribute__((noinline)) void l2_print_disarm(void)
{
	_printk(MAPLESU_L2_TAG "disarm state=DISARMED armed_after=0 hits=%u\n",
		l2.hits_total);
}

static __attribute__((noinline)) void l2_print_selftest(void)
{
	_printk(MAPLESU_L2_TAG "selftest probe=%llx kread=%d kwrite=%d rc=%d\n",
		(unsigned long long)L2_PROBE_MAGIC, (int)l2.selftest_kread,
		(int)l2.selftest_kwrite, (int)l2.selftest_rc);
}

/* H5 exec entry: count only. */
static int l2_pre_execve(struct kprobe *p, struct pt_regs *regs)
{
	(void)p;
	(void)regs;
	if (l2.latch != L2_LATCH_ARMED)
		return 0;
	l2_count(&l2.probes[L2_PROBE_EXEC_ENTRY].hits);
	l2_count(&l2.hits_total);
	l2_first_hit(&l2.probes[L2_PROBE_EXEC_ENTRY]);
	return 0;
}

/* The post handler exists for the same reason: a third kernel-to-us call site
 * with its own type id, observed and never written. */
static void l2_post_execve(struct kprobe *p, struct pt_regs *regs, unsigned long flags)
{
	(void)p;
	(void)regs;
	(void)flags;
	if (l2.latch != L2_LATCH_ARMED)
		return;
	l2_count(&l2.probes[L2_PROBE_EXEC_ENTRY].post_hits);
}

/* H5 return side: count only. The kretprobe instance is the kernel's; we never
 * touch it, and `data_size` is 0 so no per-instance payload exists. */
static int l2_ret_execve(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	(void)ri;
	(void)regs;
	if (l2.latch != L2_LATCH_ARMED)
		return 0;
	l2_count(&l2.probes[L2_PROBE_EXEC_RET].hits);
	l2_count(&l2.hits_total);
	l2_first_hit(&l2.probes[L2_PROBE_EXEC_RET]);
	return 0;
}

/* ------------------------------------------------------------------------- */
/* H1: the op handlers.                                                      */
/* ------------------------------------------------------------------------- */

static int l2_op_arm(u32 scno, u64 user)
{
	u64 slot = 0;
	int rc;

	if (l2.latch == L2_LATCH_ARMED) {
		l2_result_out(user, -L2_EBUSY, 0, 0);
		return -L2_EBUSY;
	}
	if (l2.latch != L2_LATCH_IDLE) {
		l2_result_out(user, -L2_EPERM, 0, 0);
		return -L2_EPERM;
	}
	if (scno >= L2_SYSCALLNO_MAX || l2.sys_call_table == 0 || l2.ni_addr == 0) {
		l2_result_out(user, -L2_EINVAL, 0, 0);
		return -L2_EINVAL;
	}
	/* The number is unimplemented on *this* boot, proven against the table the
	 * kernel will dispatch through -- not against a per-release constant. */
	rc = l2_kread(l2.sys_call_table + (u64)scno * 8u, &slot, 8);
	if (rc != 0 || slot != l2.ni_addr) {
		l2_result_out(user, -L2_EINVAL, slot, l2.ni_addr);
		return -L2_EINVAL;
	}
	if (l2.scno != 0 && l2.scno != scno) {
		l2_result_out(user, -L2_EINVAL, (u64)l2.scno, 0);
		return -L2_EINVAL;
	}
	l2.scno = scno;
	l2.generation += 1u;
	l2.latch = L2_LATCH_ARMED;
	l2_print_arm();
	l2_result_out(user, 0, l2.generation, (u64)l2_state_bits());
	return 0;
}

static int l2_op_kread(u64 user, u64 addr, u64 len)
{
	u64 value = 0;
	int rc;

	if (len == 0 || len > (u64)sizeof(value)) {
		l2_result_out(user, -L2_EINVAL, 0, len);
		return -L2_EINVAL;
	}
	rc = l2_kread(addr, &value, (u32)len);
	l2_result_out(user, rc, value, len);
	return rc;
}

static int l2_op_kwrite(u64 user, u64 addr, u64 value, u64 tag)
{
	u64 readback = 0;
	int rc;

	rc = l2_kwrite(addr, value, (u32)tag);
	if (rc == 0) {
		if ((u32)tag == L2_WL_SCRATCH) {
			readback = l2.scratch;
		} else if (l2_kread(addr, &readback, 1) == 0) {
			readback &= 0xffu;
		}
	}
	l2_result_out(user, rc, readback, tag);
	return rc;
}

static int l2_op_selftest(u64 user)
{
	u64 now = 0;
	u64 readback = 0;
	int kread_rc;
	int kwrite_rc = -L2_EINVAL;
	int rc;

	l2.selftest_probe = (u32)(L2_PROBE_MAGIC & 0xffffffffu);
	kread_rc = l2_kread(l2.selinux_addr, &now, 1);
	if (kread_rc == 0) {
		l2.enforcing_now = (u32)(now & 0xffu);
		kwrite_rc = l2_kwrite(l2.selinux_addr, now & 0xffu, L2_WL_SELINUX);
		if (kwrite_rc == 0 && l2_kread(l2.selinux_addr, &readback, 1) == 0)
			readback &= 0xffu;
	}
	l2.selftest_kread = (u32)kread_rc;
	l2.selftest_kwrite = (u32)kwrite_rc;
	l2.selftest_value = readback;
	rc = (kread_rc == 0 && kwrite_rc == 0) ? 0 : -L2_EIO;
	l2.selftest_rc = (u32)rc;
	l2_print_selftest();
	l2_result_out(user, rc, L2_PROBE_MAGIC, readback);
	return rc;
}

static int l2_op_hits(u64 user)
{
	u64 packed = (u64)l2.probes[L2_PROBE_EXEC_ENTRY].hits
		     | ((u64)l2.probes[L2_PROBE_EXEC_RET].hits << 32);

	l2_result_out(user, 0, packed, l2.generation);
	return 0;
}

static int l2_op_status(u64 user)
{
	l2_result_out(user, 0, (u64)l2_state_bits(), l2.generation);
	return 0;
}

static int l2_op_disarm(u64 user)
{
	if (l2.latch != L2_LATCH_ARMED) {
		l2_result_out(user, -L2_EPERM, 0, 0);
		return -L2_EPERM;
	}
	l2.latch = L2_LATCH_DISARMED;
	l2_print_disarm();
	l2_result_out(user, 0, (u64)l2.hits_total, l2.generation);
	return 0;
}

/* The dispatcher. Two gates come before any op that does work:
 *   1. the cookie (checked by the caller, before this function runs);
 *   2. after ARM, `regs->syscallno` must be the number ARM bound. Mismatch is
 *      silent -- the carrier is shared by every unimplemented number, so being
 *      loud here would answer strangers.
 * The op chain is an if/else ladder on purpose: a switch would be compiled to a
 * jump table and a computed branch, which is exactly what G12 forbids.
 */
static void l2_ctl_dispatch(const struct maplesu_pt_regs *r)
{
	u32 scno = (u32)r->syscallno;
	u64 op = r->regs[1];
	u64 user = r->regs[5];

	if (op == L2_OP_ARM) {
		(void)l2_op_arm(scno, user);
		return;
	}
	if (l2.latch != L2_LATCH_ARMED) {
		l2_result_out(user, -L2_EPERM, 0, 0);
		return;
	}
	if (l2.scno == 0 || scno != l2.scno)
		return;
	if (op == L2_OP_PROBE) {
		l2_result_out(user, 0, L2_PROBE_MAGIC, L2_RESULT_VERSION);
		return;
	}
	if (op == L2_OP_KREAD) {
		(void)l2_op_kread(user, r->regs[2], r->regs[3]);
		return;
	}
	if (op == L2_OP_KWRITE) {
		(void)l2_op_kwrite(user, r->regs[2], r->regs[3], r->regs[4]);
		return;
	}
	if (op == L2_OP_SELFTEST) {
		(void)l2_op_selftest(user);
		return;
	}
	if (op == L2_OP_HITS) {
		(void)l2_op_hits(user);
		return;
	}
	if (op == L2_OP_DISARM) {
		(void)l2_op_disarm(user);
		return;
	}
	if (op == L2_OP_STATUS) {
		(void)l2_op_status(user);
		return;
	}
	l2_result_out(user, -L2_EINVAL, 0, op);
}

/* The control probe. Every unimplemented syscall on the device reaches this
 * function, so the first thing it does is prove the caller holds the loader's
 * 64-bit cookie; anything else returns without reading a parameter, writing a
 * result or changing state. x6 is reserved and must be zero (an old kernel can
 * therefore refuse a newer call). */
static int l2_pre_ctl(struct kprobe *p, struct pt_regs *regs)
{
	const struct maplesu_pt_regs *r = (const struct maplesu_pt_regs *)regs;

	(void)p;
	if (l2.load_cookie == 0 || r->regs[7] != l2.load_cookie)
		return 0;
	if (r->regs[6] != 0)
		return 0;
	l2_ctl_dispatch(r);
	return 0;
}

/* ------------------------------------------------------------------------- */
/* Registry: register once at load, unregister once at unload.               */
/* ------------------------------------------------------------------------- */

static void l2_probe_arm_handlers(struct l2_probe *p)
{
	if (p->kind == L2_KIND_KRETPROBE) {
		p->u.krp.kp.symbol_name = p->symbol;
		p->u.krp.kp.pre_handler = MAPLESU_NULL;
		p->u.krp.kp.post_handler = MAPLESU_NULL;
		p->u.krp.kp.addr = 0;
		p->u.krp.handler = (void *)p->ret;
		p->u.krp.entry_handler = MAPLESU_NULL;
		p->u.krp.maxactive = 0;
		p->u.krp.nmissed = 0;
		p->u.krp.data_size = 0;
	} else {
		p->u.kp.symbol_name = p->symbol;
		p->u.kp.addr = 0;
		p->u.kp.pre_handler = (void *)p->pre;
		p->u.kp.post_handler = (void *)p->post;
	}
}

static int l2_probe_register(struct l2_probe *p)
{
	int rc;

	l2_probe_arm_handlers(p);
	if (p->kind == L2_KIND_KRETPROBE)
		rc = register_kretprobe(&p->u.krp);
	else
		rc = register_kprobe(&p->u.kp);
	p->errno_reg = rc;
	if (rc == 0)
		p->state = L2_REGISTERED;
	return rc;
}

static void l2_probe_unregister(struct l2_probe *p)
{
	if (p->kind == L2_KIND_KRETPROBE)
		unregister_kretprobe(&p->u.krp);
	else
		unregister_kprobe(&p->u.kp);
	p->state = L2_UNREGISTERED;
}

/* Reverse order, every registered row, idempotent: the same function is the
 * rollback path (init failure) and the unload path (cleanup_module). */
static void l2_disarm_all(const char *why)
{
	int i;
	u32 left = 0;

	for (i = L2_MAX_PROBES - 1; i >= 0; --i) {
		if (l2.probes[i].state != L2_REGISTERED)
			continue;
		l2_probe_unregister(&l2.probes[i]);
	}
	for (i = 0; i < L2_MAX_PROBES; ++i) {
		if (l2.probes[i].state == L2_REGISTERED)
			left += 1u;
	}
	_printk(MAPLESU_L2_TAG "disarm by=%s registered_after=%u hits=%u\n",
		why, left, l2.hits_total);
}

static void l2_rollback(void)
{
	l2_disarm_all("rollback");
}

static int l2_register_probes(void)
{
	int rc;

	rc = l2_probe_register(&l2.probes[L2_PROBE_CTL]);
	if (rc != 0)
		return rc;
	rc = l2_probe_register(&l2.probes[L2_PROBE_EXEC_ENTRY]);
	if (rc != 0) {
		l2_rollback();
		return rc;
	}
	rc = l2_probe_register(&l2.probes[L2_PROBE_EXEC_RET]);
	if (rc != 0) {
		l2_rollback();
		return rc;
	}
	return 0;
}

static void l2_describe_probes(void)
{
	struct l2_probe *ctl = &l2.probes[L2_PROBE_CTL];
	struct l2_probe *entry = &l2.probes[L2_PROBE_EXEC_ENTRY];
	struct l2_probe *ret = &l2.probes[L2_PROBE_EXEC_RET];

	ctl->id = "ctl.magic";
	ctl->symbol = "__arm64_sys_ni_syscall";
	ctl->kind = L2_KIND_KPROBE;
	ctl->pre = l2_pre_ctl;
	entry->id = "execve.entry";
	entry->symbol = "do_execveat_common";
	entry->kind = L2_KIND_KPROBE;
	entry->pre = l2_pre_execve;
	entry->post = l2_post_execve;
	ret->id = "execve.ret";
	ret->symbol = "do_execveat_common";
	ret->kind = L2_KIND_KRETPROBE;
	ret->ret = l2_ret_execve;
}

/* ------------------------------------------------------------------------- */
/* Module entry points.                                                      */
/* ------------------------------------------------------------------------- */

/*
 * init_module does the four things that need process context -- resolve, read
 * one byte, register, print -- and nothing else. Any failure returns before the
 * module is resident, so a failed load leaves no probe behind (the kernel drops
 * the module when init returns non-zero) and the rollback path is only there for
 * the multi-probe case.
 */
__attribute__((section(".init.text"))) __attribute__((noinline))
int init_module(void)
{
	struct maplesu_l2_kprobe bootstrap;
	u64 ni_addr;
	u64 table;
	u64 to_user;
	u64 selinux_addr;
	u64 now = 0;
	u8 *raw;
	u32 index;
	int rc;

	/* 1. The loader's cookie. Zero means the uargs were missing, and a channel
	 *    that cannot authenticate must not exist at all (-EINVAL, nothing armed). */
	l2.load_cookie = l2_load_cookie;
	if (l2.load_cookie == 0) {
		_printk(MAPLESU_L2_TAG "refusing to load: no cookie in uargs\n");
		return -L2_EINVAL;
	}

	/* 2. kallsyms_lookup_name through a kprobe on its own name: the same
	 *    bootstrap maplesu_root uses, because the symbol is not exported either. */
	raw = (u8 *)&bootstrap;
	for (index = 0; index < (u32)sizeof(bootstrap); ++index)
		raw[index] = 0;
	bootstrap.symbol_name = "kallsyms_lookup_name";
	if (register_kprobe(&bootstrap) < 0) {
		_printk(MAPLESU_L2_TAG "kallsyms_lookup_name not found\n");
		return -L2_ENOSYS;
	}
	l2.lookup = (u64)bootstrap.addr;
	unregister_kprobe(&bootstrap);
	if (l2.lookup == 0)
		return -L2_ENOSYS;

	/* 3. The three runtime lookups (unexported) plus the SELinux object. A
	 *    missing one is a fail-closed load failure, not a degraded channel. */
	ni_addr = l2_sym("__arm64_sys_ni_syscall");
	table = l2_sym("sys_call_table");
	to_user = l2_sym("copy_to_user_nofault");
	selinux_addr = l2_sym("selinux_state");
	if (ni_addr == 0 || table == 0 || to_user == 0 || selinux_addr == 0) {
		_printk(MAPLESU_L2_TAG "lookup failed ni=%llx table=%llx to_user=%llx "
			"selinux=%llx\n", (unsigned long long)ni_addr,
			(unsigned long long)table, (unsigned long long)to_user,
			(unsigned long long)selinux_addr);
		return -L2_ENOENT;
	}
	l2.ni_addr = ni_addr;
	l2.sys_call_table = table;
	l2.copy_to_user = to_user;
	l2.selinux_addr = selinux_addr;
	if (l2_kread(selinux_addr, &now, 1) != 0)
		return -L2_ENOENT;
	l2.enforcing_now = (u32)(now & 0xffu);

	/* 4. Register the three probes. They are inert until OP_ARM flips the latch;
	 *    the control probe has to be live first so the helper can reach us. */
	l2_describe_probes();
	rc = l2_register_probes();
	if (rc != 0)
		return rc;

	_printk(MAPLESU_L2_TAG "ready generation=0 cookie=set selinux=%u\n",
		l2.enforcing_now);
	return 0;
}

/* cleanup_module is the final restore point for the probe registry: it is the
 * only place that can unregister (process context, may sleep), and it runs on
 * delete_module even when the helper never got to OP_DISARM. */
void cleanup_module(void)
{
	l2.latch = L2_LATCH_DISARMED;
	l2_disarm_all("cleanup");
}
