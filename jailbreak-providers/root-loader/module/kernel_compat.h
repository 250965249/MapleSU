/*
 * Kernel ABI facts for this image, without any kernel headers.
 *
 * This module is built on a host with only the Android NDK and no kernel tree, so
 * every structure the kernel writes into has to be declared here with the exact
 * layout of the *running* kernel. The numbers below are not from a header: they were
 * read out of the image's own BTF (`.analysis/ace6-20261025/gki-materials-final/boot/kernel`),
 * which is the same source that gave us `sizeof(struct module) == 0x600`, a value the
 * vendor module on the device independently confirms.
 *
 * Getting one of these wrong is not a graceful failure: register_kprobe() writes the
 * whole struct, so a layout from a different config corrupts memory silently.
 */
#ifndef MAPLESU_KERNEL_COMPAT_H
#define MAPLESU_KERNEL_COMPAT_H

typedef unsigned char u8;
typedef unsigned short u16;
typedef unsigned int u32;
typedef unsigned long long u64;
typedef unsigned long uptr;

#define MAPLESU_NULL ((void *)0)

/*
 * struct kprobe, BTF id 4887, size 0x80.
 *
 * Only two fields are ever touched by us; the rest exists so that the kernel's
 * writes land inside our object. `addr` (+0x28) is filled in by register_kprobe()
 * and is how we obtain kallsyms_lookup_name, which is not an exported symbol.
 * `symbol_name` (+0x30) is the input.
 */
struct maplesu_kprobe {
	u8 pre_handler[8];        /* +0x00 kprobe_pre_handler_t */
	u8 post_handler[8];       /* +0x08 kprobe_post_handler_t */
	u8 fault_handler[8];      /* +0x10 kprobe_fault_handler_t */
	u8 ignored_handler[8];    /* +0x18 kprobe_ignored_handler_t */
	u8 opcode[8];             /* +0x20 kprobe_opcode_t * */
	uptr addr;                /* +0x28 kprobe_opcode_t *addr, set by the kernel */
	const char *symbol_name;  /* +0x30 const char *symbol_name */
	u32 nokprobe_inline;      /* +0x38 */
	u32 offset;               /* +0x3c */
	u8 rest[0x80 - 0x40];     /* +0x40 .. +0x7f */
};

_Static_assert(sizeof(struct maplesu_kprobe) == 0x80, "struct kprobe must be 0x80");
_Static_assert(__builtin_offsetof(struct maplesu_kprobe, addr) == 0x28,
	       "kprobe.addr must be at +0x28");
_Static_assert(__builtin_offsetof(struct maplesu_kprobe, symbol_name) == 0x30,
	       "kprobe.symbol_name must be at +0x30");

/*
 * struct selinux_state, BTF id 21039, size 0x80.
 *
 * `enforcing` is a bool at +0x00 and `initialized` at +0x01; everything after is the
 * policy/status machinery we never touch. Writing +0x00 is exactly what the reference
 * implementation does (`WRITE_ONCE(*selinux_state, false)` in DirtyFragX lkm/dfroot.c).
 *
 * Note there is no separate `selinux_enforcing` symbol on this kernel - the kallsyms
 * probe in the device evidence does not find one - so that name must not be looked up.
 */
/*
 * The size differs by family (measured: 0x80 on 6.6 and 5.15, 0x88 on 6.1). The
 * builder injects the contract's value with -D; the default keeps a from-source build
 * of the primary family working.
 */
#ifndef MAPLESU_SELINUX_STATE_SIZE
#define MAPLESU_SELINUX_STATE_SIZE 0x80
#endif

#ifndef MAPLESU_SELINUX_INIT_OFF
#define MAPLESU_SELINUX_INIT_OFF 0x01
#endif

struct maplesu_selinux_state {
	u8 enforcing;             /* +0x00 */
	u8 initialized;           /* +0x01 */
	u8 rest[MAPLESU_SELINUX_STATE_SIZE - 0x02];
};

_Static_assert(sizeof(struct maplesu_selinux_state) == MAPLESU_SELINUX_STATE_SIZE,
	       "struct selinux_state must be 0x80");

/*
 * struct subprocess_info, BTF id 3405, size 0x70.
 *
 * This is the object call_usermodehelper_setup() returns and
 * call_usermodehelper_exec() consumes. Only `path` is ever touched by us, and only
 * for one reason: this kernel has CONFIG_STATIC_USERMODEHELPER=y with
 * CONFIG_STATIC_USERMODEHELPER_PATH="" (build/scratch/kconfig.txt:6952-6953), so
 * setup() *overwrites* the caller's path with a pointer to a lone NUL in rodata
 * (disassembled: `ldr x8,[x19,#0x38]` then `ldrb w8,[x8]` in exec). Writing our own
 * path back at +0x38 after setup() is what turns the silent no-op into a real exec;
 * DirtyFragX lkm/dfroot.c:185-188 is the same fix on the same device family.
 *
 * `work` is a struct work_struct (0x30 bytes on this image) and `complete` a
 * pointer; neither is read or written here, they exist so the kernel's own writes
 * land inside our declaration. `argv`/`envp`/`init`/`cleanup`/`data` are declared as
 * raw u8 slots because only their *placement* matters and the field is opaque to us.
 *
 * The member names are the kernel's own (not `init_fn`/`cleanup_fn`) so that G7 can
 * compare every asserted offset against the image's BTF by name instead of trusting
 * a hand-written mapping. The five tail offsets are asserted for a reason: setup()
 * writes `init`/`cleanup`/`data` (stp, stp, str at +0x58/+0x60/+0x68) and exec()
 * writes `complete`/`wait`/`retval` (+0x30/+0x50/+0x54), so a shim that got `path`
 * right but the tail wrong would corrupt the very struct it hands to exec().
 */
/*
 * struct subprocess_info: every offset differs by family because work_struct does
 * (measured: path at +0x38 on 6.6, +0x28 on 5.15). All of them come from the
 * contract. Only `path` is ever written by us - setup() overwrites it, which is the
 * whole point - so the tail is padding rather than a full mirror.
 */
/*
 * struct subprocess_info: every offset shifts by family because work_struct does
 * (measured: path at +0x38 on 6.6, +0x28 on 5.15). All of them come from the
 * contract; only `path` is ever written by us.
 */
struct maplesu_subprocess_info {
	u8 work[0x30];            /* +0x00 struct work_struct */
	u8 complete[8];           /* +0x30 struct completion * */
	const char *path;         /* +0x38 char *path, read by exec() */
	u8 argv[8];               /* +0x40 char **argv */
	u8 envp[8];               /* +0x48 char **envp */
	u32 wait;                 /* +0x50 int wait */
	u32 retval;               /* +0x54 int retval */
	u8 init[8];               /* +0x58 int (*init)(struct subprocess_info *,
				    *            struct cred *) */
	u8 cleanup[8];            /* +0x60 void (*cleanup)(struct subprocess_info *) */
	u8 data[8];               /* +0x68 void *data */
};

_Static_assert(sizeof(struct maplesu_subprocess_info) == 0x70,
	       "struct subprocess_info must be 0x70");
_Static_assert(__builtin_offsetof(struct maplesu_subprocess_info, complete) == 0x30,
	       "subprocess_info.complete must be at +0x30");
_Static_assert(__builtin_offsetof(struct maplesu_subprocess_info, path) == 0x38,
	       "subprocess_info.path must be at +0x38");
_Static_assert(__builtin_offsetof(struct maplesu_subprocess_info, argv) == 0x40,
	       "subprocess_info.argv must be at +0x40");
_Static_assert(__builtin_offsetof(struct maplesu_subprocess_info, envp) == 0x48,
	       "subprocess_info.envp must be at +0x48");
_Static_assert(__builtin_offsetof(struct maplesu_subprocess_info, wait) == 0x50,
	       "subprocess_info.wait must be at +0x50");
_Static_assert(__builtin_offsetof(struct maplesu_subprocess_info, retval) == 0x54,
	       "subprocess_info.retval must be at +0x54");
_Static_assert(__builtin_offsetof(struct maplesu_subprocess_info, init) == 0x58,
	       "subprocess_info.init must be at +0x58");
_Static_assert(__builtin_offsetof(struct maplesu_subprocess_info, cleanup) == 0x60,
	       "subprocess_info.cleanup must be at +0x60");
_Static_assert(__builtin_offsetof(struct maplesu_subprocess_info, data) == 0x68,
	       "subprocess_info.data must be at +0x68");

/*
 * KCFI opt-out for the functions that call runtime-resolved addresses.
 *
 * -fsanitize=kcfi turns every indirect call into "load [target-4], compare, brk on
 * mismatch". We call kallsyms_lookup_name and the usermodehelper pair through
 * addresses that only exist at runtime, so the type id is a hand-written guess about
 * a prototype we cannot see. clang 19.0.1 removes the check (and keeps the mandatory
 * 4-byte init/exit prefix) under this attribute; the reference module dfroot.ko ships
 * 0 BRK for the same reason. CONFIG_PANIC_ON_OOPS=y makes any surviving trap a panic,
 * so "probably matches" is not a posture this module takes.
 */
#ifdef MAPLESU_LEGACY_CFI
#define MAPLESU_NOCFI __attribute__((no_sanitize("cfi")))
#else
#define MAPLESU_NOCFI __attribute__((no_sanitize("kcfi")))
#endif

/* Kernel function types we call through resolved addresses. */
typedef unsigned long (*maplesu_kallsyms_lookup_name_fn)(const char *name);
typedef int (*maplesu_register_kprobe_fn)(struct maplesu_kprobe *probe);
typedef void (*maplesu_unregister_kprobe_fn)(struct maplesu_kprobe *probe);
typedef int (*maplesu_printk_fn)(const char *fmt, ...);
typedef int (*maplesu_call_usermodehelper_fn)(const char *path, char **argv,
					      char **envp, int wait);
typedef int (*maplesu_insn_patch_fn)(void *addrs[], u32 insns[], int cnt);

/*
 * struct subprocess_info *call_usermodehelper_setup(const char *path, char **argv,
 *         char **envp, gfp_t gfp_mask,
 *         int (*init)(struct subprocess_info *info, struct cred *new),
 *         void (*cleanup)(struct subprocess_info *info), void *data);
 * int call_usermodehelper_exec(struct subprocess_info *sub_info, int wait);
 *
 * Both are in this image's kallsyms table (TEXT rows at 0x850324 / 0x850776) but NOT
 * in __ksymtab, so they cannot be imported (CONFIG_TRIM_UNUSED_KSYMS); we resolve
 * them by name at runtime. The prototypes are the kernel's exact ones -- `gfp_t` is
 * `unsigned int`, and the three callbacks are opaque pointers because we pass NULL.
 */
typedef void *(*maplesu_umh_setup_fn)(const char *path, char **argv, char **envp,
				      u32 gfp_mask, void *init_fn, void *cleanup_fn,
				      void *data);
typedef int (*maplesu_umh_exec_fn)(void *sub_info, int wait);

/* GFP_KERNEL == __GFP_RECLAIM|__GFP_IO|__GFP_FS == 0xCC0 on 6.6 arm64 (gfp_types.h;
 * stable for the entire 6.x series). Spelled out because there is no kernel header. */
#define MAPLESU_GFP_KERNEL 0xCC0u

/* UMH wait modes (include/linux/umh.h, stable across 5.x and 6.x). */
#define MAPLESU_UMH_NO_WAIT 0
#define MAPLESU_UMH_WAIT_EXEC 1
/* Deliberately NOT used: WAIT_PROC waits for the helper to exit, and our helper
 * execs the long-lived consumer, so it would block init_module() forever. */

/* ======================================================================== */
/* L2 (maplesu_l2.ko): the layouts its control channel and probes need.     */
/*                                                                          */
/* Every number below is the contract's BTF-derived value                */
/* (contracts/<uname>.json, structOffsets.* and the top-level `kprobe`), */
/* asserted so that a release whose layout moved fails the build instead */
/* of corrupting memory at load. S37 in hook_contract.py compares the    */
/* same asserts against the same contract from the other side.           */
/*                                                                          */
/* Why five structs and not the root module's one: the root shim was    */
/* written when only `addr`/`symbol_name` were used, and it is frozen    */
/* (maplesu_root.ko must stay byte-identical). The L2 shim is the full    */
/* BTF layout because L2 sets pre_handler/post_handler and lets the      */
/* kernel call them; both are 0x80 so the kernel's writes land inside    */
/* either object, but only this one puts the callback pointers where     */
/* the kernel reads them (`kprobe_breakpoint_handler` loads            */
/* `[kp + 0x40]`; `aggr_pre_handler` the same).                          */
/* ======================================================================== */

/*
 * struct kprobe, BTF id 4887, size 0x80 (contract `kprobe.members`):
 *   hlist@0x00 list@0x10 nmissed@0x20 addr@0x28 symbol_name@0x30 offset@0x38
 *   pre_handler@0x40 post_handler@0x48 opcode@0x50 ainsn@0x58 flags@0x78
 * There is NO fault_handler member on this kernel (the rev-1 design copied one
 * from another release); 0x50 is `opcode`.
 */
struct maplesu_l2_kprobe {
	u8 hlist[0x10];           /* +0x00 struct hlist_node */
	u8 list[0x10];            /* +0x10 struct list_head */
	uptr nmissed;             /* +0x20 unsigned long nmissed */
	uptr addr;                /* +0x28 kprobe_opcode_t *addr, set by the kernel */
	const char *symbol_name;  /* +0x30 const char *symbol_name */
	u32 offset;               /* +0x38 unsigned int offset */
	u32 pad_3c;               /* +0x3c */
	void *pre_handler;        /* +0x40 kprobe_pre_handler_t */
	void *post_handler;       /* +0x48 kprobe_post_handler_t */
	u32 opcode;               /* +0x50 kprobe_opcode_t opcode */
	u8 ainsn[0x20];           /* +0x58 struct arch_specific_insn */
	u32 flags;                /* +0x78 u32 flags */
	u32 pad_7c;               /* +0x7c */
};

_Static_assert(sizeof(struct maplesu_l2_kprobe) == 0x80,
	       "struct kprobe must be 0x80");
_Static_assert(__builtin_offsetof(struct maplesu_l2_kprobe, addr) == 0x28,
	       "kprobe.addr must be at +0x28");
_Static_assert(__builtin_offsetof(struct maplesu_l2_kprobe, symbol_name) == 0x30,
	       "kprobe.symbol_name must be at +0x30");
_Static_assert(__builtin_offsetof(struct maplesu_l2_kprobe, pre_handler) == 0x40,
	       "kprobe.pre_handler must be at +0x40");
_Static_assert(__builtin_offsetof(struct maplesu_l2_kprobe, post_handler) == 0x48,
	       "kprobe.post_handler must be at +0x48");

/*
 * struct kretprobe, BTF id 4926, size 0xb0:
 *   kp@0x00 handler@0x80 entry_handler@0x88 maxactive@0x90 nmissed@0x94
 *   data_size@0x98 freelist@0xa0 rph@0xa8
 * register_kretprobe() writes the whole object -- including freelist and rph,
 * past data_size -- so the surrogate must be at least 0xb0 bytes; a shorter one
 * corrupts whatever follows it in .bss.
 */
struct maplesu_kretprobe {
	struct maplesu_l2_kprobe kp;  /* +0x00 struct kprobe kp */
	void *handler;                /* +0x80 kretprobe_handler_t handler */
	void *entry_handler;          /* +0x88 kretprobe_handler_t entry_handler */
	int maxactive;                /* +0x90 int maxactive */
	int nmissed;                  /* +0x94 int nmissed */
	u64 data_size;                /* +0x98 size_t data_size */
	u8 freelist[0x8];             /* +0xa0 struct freelist_head */
	u8 rph[0x8];                  /* +0xa8 struct kretprobe_holder *rph */
};

_Static_assert(sizeof(struct maplesu_kretprobe) >= 0xb0,
	       "struct kretprobe must be at least 0xb0");
_Static_assert(__builtin_offsetof(struct maplesu_kretprobe, kp) == 0x0,
	       "kretprobe.kp must be at +0x0");
_Static_assert(__builtin_offsetof(struct maplesu_kretprobe, handler) == 0x80,
	       "kretprobe.handler must be at +0x80");
_Static_assert(__builtin_offsetof(struct maplesu_kretprobe, entry_handler) == 0x88,
	       "kretprobe.entry_handler must be at +0x88");
_Static_assert(__builtin_offsetof(struct maplesu_kretprobe, data_size) == 0x98,
	       "kretprobe.data_size must be at +0x98");

/*
 * struct pt_regs, BTF id 2275, size 0x150.
 *
 * Only the syscall ABI registers are read: `regs[]` (x0..x30, so op/args/cookie
 * live at +0x08..+0x38) and `syscallno` at +0x118. The rest exists so the
 * offsets are the kernel's and a mis-sized surrogate is a compile error.
 * `user_pt_regs` is the anonymous union at +0x0; `orig_x0` occupies +0x110, which
 * is why `syscallno` is at +0x118 and not at the end of that union.
 *
 * The callbacks take the kernel's `struct pt_regs *` (never this name) because
 * kCFI hashes the *type spelling*: `struct maplesu_pt_regs *` would hash to a
 * different id (0x2b8cdf69 instead of 0xa6be5dd9), and the kernel's compare
 * would trap on the first hit. This struct is the layout, cast to only.
 */
struct maplesu_pt_regs {
	u64 regs[31];             /* +0x00 .. +0xf7 x0..x30 */
	u64 sp;                   /* +0xf8 */
	u64 pc;                   /* +0x100 */
	u64 pstate;               /* +0x108 */
	u64 orig_x0;              /* +0x110 */
	int syscallno;            /* +0x118 s32 */
	u32 unused2;              /* +0x11c */
	u64 sdei_ttbr1;           /* +0x120 */
	u64 pmr_save;             /* +0x128 */
	u64 stackframe[2];        /* +0x130 */
	u64 lockdep_hardirqs;     /* +0x140 */
	u64 exit_rcu;             /* +0x148 */
};

_Static_assert(sizeof(struct maplesu_pt_regs) == 0x150, "struct pt_regs must be 0x150");
_Static_assert(__builtin_offsetof(struct maplesu_pt_regs, regs) == 0x0,
	       "pt_regs.regs must be at +0x0");
_Static_assert(__builtin_offsetof(struct maplesu_pt_regs, sp) == 0xf8,
	       "pt_regs.sp must be at +0xf8");
_Static_assert(__builtin_offsetof(struct maplesu_pt_regs, pc) == 0x100,
	       "pt_regs.pc must be at +0x100");
_Static_assert(__builtin_offsetof(struct maplesu_pt_regs, pstate) == 0x108,
	       "pt_regs.pstate must be at +0x108");
_Static_assert(__builtin_offsetof(struct maplesu_pt_regs, syscallno) == 0x118,
	       "pt_regs.syscallno must be at +0x118");

/*
 * struct kernel_param, BTF id 2062, size 0x28:
 *   name@0x00 mod@0x08 ops@0x10 perm@0x18 level@0x1a flags@0x1b arg@0x20
 *
 * The `__param` row itself is emitted by the glue (module/root_glue_l2.S.in),
 * because it is one fixed 0x28-byte record with a relocation to
 * `param_ops_ullong` and to the module's own cookie cell; this declaration is
 * what the asserts below check, and it is the reason the glue's `.zero`s carry
 * names in their comments instead of magic offsets.
 */
struct maplesu_kernel_param {
	const char *name;         /* +0x00 */
	void *mod;                /* +0x08 struct module *mod */
	const void *ops;          /* +0x10 const struct kernel_param_ops *ops */
	u16 perm;                 /* +0x18 const u16 perm */
	signed char level;        /* +0x1a s8 level */
	u8 flags;                 /* +0x1b u8 flags */
	u32 pad_1c;               /* +0x1c */
	void *arg;                /* +0x20 union { void *arg; ... } */
};

_Static_assert(sizeof(struct maplesu_kernel_param) == 0x28,
	       "struct kernel_param must be 0x28");
_Static_assert(__builtin_offsetof(struct maplesu_kernel_param, ops) == 0x10,
	       "kernel_param.ops must be at +0x10");
_Static_assert(__builtin_offsetof(struct maplesu_kernel_param, perm) == 0x18,
	       "kernel_param.perm must be at +0x18");
_Static_assert(__builtin_offsetof(struct maplesu_kernel_param, arg) == 0x20,
	       "kernel_param.arg must be at +0x20");

/* `param_ops_ullong` is referenced by the glue (the `__param` row's `ops`), so
 * the C file does not name it: the import exists, and O6 counts exactly it.
 * The cookie cell (`l2_load_cookie`) is defined by the glue for the same
 * reason (the row's `arg` must name a link-visible symbol); maplesu_l2.c
 * carries the one `extern` declaration. */

#endif /* MAPLESU_KERNEL_COMPAT_H */
