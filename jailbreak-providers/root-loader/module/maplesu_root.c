/*
 * MapleSU kernel-side entry: resolve at runtime, patch the minimum, hand over.
 *
 * This replaces the earlier "per-kernel spec of hardcoded offsets" design. That
 * design hung the device because the offsets came from a different image than the
 * one running: the first read of `kbase + offset` landed in unmapped memory and the
 * oops took module_mutex with it. Nothing here is per-release, so there is nothing
 * to get wrong per release.
 *
 * The technique is the one DirtyFragX's dfroot LKM proved on this device
 * (lkm/dfroot.c in github.com/dugongzi/DirtyFragX):
 *
 *   1. register_kprobe("kallsyms_lookup_name") yields the address of
 *      kallsyms_lookup_name, which is not exported but is always in the kallsyms
 *      table. Every other symbol is then a lookup, so no offsets ship in the module.
 *   2. SELinux goes permissive by writing the `selinux_state.enforcing` byte.
 *   3. Vendor anti-root handlers are made to return 0 (compiled out by default).
 *   4. The real work happens in userspace as kernel-domain root, started with the
 *      two-stage usermodehelper: setup -> path restore -> exec.
 *
 * Why two-stage and not the four-argument wrapper (the defect this file used to
 * carry): this kernel is built with
 *
 *     CONFIG_STATIC_USERMODEHELPER=y
 *     CONFIG_STATIC_USERMODEHELPER_PATH=""      (build/scratch/kconfig.txt:6952-6953)
 *
 * so call_usermodehelper_setup() *overwrites* the caller's path with a lone NUL in
 * rodata (`ldr x8,[x19,#0x38]` -- subprocess_info.path -- and the store of the empty
 * string into it), and call_usermodehelper_exec() then sees an empty path and returns
 * 0 without forking anything. The four-argument wrapper is therefore a *silent
 * no-op* on this image: it prints nothing, execs nothing, returns 0 -- the module
 * used to claim "handover started; resident" while nothing ran and SELinux stayed
 * permissive. That is the false positive the canary acceptance now keys around: the
 * proof is the helper's own side effect (provider-log line + `getenforce`), never
 * this function's return value or its printk.
 *
 * The fix shape is dfroot.c:172-190: resolve both stages by name, call setup(),
 * write our path back at subprocess_info.path (BTF: +0x38), then exec() with
 * UMH_WAIT_EXEC. The four-argument wrapper stays as a *documented fallback* for a
 * kernel where setup/exec cannot be resolved (they are in kallsyms here, so the
 * fallback is dead code on this image, and it is logged distinctly when it runs).
 * That branch is fail-closed: a 0 from the wrapper is never accepted as a handover,
 * because on a static-UMH kernel it is exactly what "nothing ran" looks like.
 *
 * Five more things are done differently from the reference, each for a stated reason:
 *
 *   - UMH_WAIT_EXEC, never WAIT_PROC. Our helper execs the long-lived consumer and
 *     never exits, so WAIT_PROC would park init_module() in kernel_wait() forever,
 *     holding module_mutex: the same hang class this module exists to remove.
 *   - The resettled enforcement state is restored by the helper, which already does
 *     it at the end of its teardown; this module restores the saved value itself on
 *     every failure path so a broken handover cannot leave the device permissive.
 *   - The saved value is remembered, not assumed: a device that booted permissive
 *     must not be switched to enforcing by us.
 *   - Return 0 means "handed over and resident" -- and that is a statement about this
 *     function, not proof that the helper ran. The canary proves the helper.
 *   - Failure is *classified*, not collapsed into one errno (design D-2): -ENOSYS (38)
 *     when kallsyms_lookup_name itself cannot be resolved, -ENOENT (2) when
 *     selinux_state cannot, -EINVAL (22) when the two-stage pair cannot be resolved and
 *     the fallback therefore cannot hand over, -ENOMEM (12) when setup() returns NULL,
 *     and -ENODEV (19) when exec() fails -- "nothing ran", which is the one meaning the
 *     old single -ENOENT could not carry. The App-side errno mapping for 19/12/22 is a
 *     step-3 follow-up (docs/patching/maplesu-pre-canary-final-2026-10-29.md).
 *   - Step-3: the helper is called with `--umh --entry-enforcing <saved>` (design
 *     §2.1) and the argument block is file-scope `static` (see MAPLESU_HELPER_PATH
 *     and the maplesu_argv/maplesu_envp block above). The saved enforcement byte is
 *     handed over in argv so the helper restores what *this kernel* observed instead
 *     of assuming '1' -- and so the helper can record "the window really was open"
 *     (its own read gives 0) separately from "the target value" (argv).
 *
 * Imports are deliberate and few: exactly the four exported names below.
 * `call_usermodehelper_setup()`/`_exec()` are NOT exported on this GKI build
 * (CONFIG_TRIM_UNUSED_KSYMS), so they are runtime lookups, not imports -- which is
 * why the module still imports exactly four symbols while doing a real handover.
 *
 * Every function that makes an indirect call through a runtime-resolved address is
 * marked MAPLESU_NOCFI: the KCFI type id of a prototype we cannot see is a guess,
 * and CONFIG_PANIC_ON_OOPS=y turns a wrong guess into a panic (see kernel_compat.h).
 */
#include "kernel_compat.h"

/* Provided by the kernel's export table; the loader resolves these by name. */
extern int register_kprobe(struct maplesu_kprobe *probe);
extern void unregister_kprobe(struct maplesu_kprobe *probe);
extern int _printk(const char *fmt, ...);
/*
 * call_usermodehelper is deliberately NOT imported. Measured on the 5.15 and 6.1
 * vendor images: there is no __ksymtab_call_usermodehelper, so an import would
 * make the load fail with Unknown symbol on those families. It is resolved
 * through kallsyms like every other kernel-side dependency here; a kernel where
 * the name is absent simply cannot run the fallback, which is the truth.
 */
typedef int (*maplesu_umh_call_fn)(const char *path, char **argv, char **envp,
                                   int wait);

#define MAPLESU_TAG "maplesu_root: "

/*
 * P3b of the pre-canary safety review: the vendor neutralisation step is compiled
 * out by default, because all four handler names are absent on this image (115
 * "not found, skipping" lines across the captured klogs) and the RETAA/RETAB
 * selection that step needs is not hardware-gated yet. Keeping the code available
 * behind a switch means a vendor build that carries the handlers can re-enable it
 * without re-deriving anything. The binary consequence is that nothing here calls
 * aarch64_insn_patch_text in a default build.
 */
#ifndef MAPLESU_PATCH_VENDOR_HANDLERS
#define MAPLESU_PATCH_VENDOR_HANDLERS 0
#endif

/*
 * The helper this module dispatches. Step-3 (design D3-3): the canonical path is
 * the *credential-encrypted* (CE) app data directory the App actually stages
 * `bs` into - `DirtyfragAttempt.stageBootstrap()` writes it there on every route,
 * and the stock dfroot.ko's fixed-width array can only hold that shorter form
 * (`/data/user_de/0/...` is 5 bytes too long for it). `/data/data/<pkg>` is the
 * same inode through a symlink; kernel_execve resolves it, so the kernel-visible
 * spelling `/data/user/0/<pkg>/bs` is used here.
 *
 * CE is only mounted after user 0 is unlocked. Every attempt that reaches this
 * module is App-triggered (precondition, design §3.2): never move this handover to
 * early boot.
 *
 * This is the module's only `/data/` literal, and gate G5 requires exactly one in
 * .rodata; a second constant (for example a stage-2 path passed through argv) is a
 * contract change, not a build tweak.
 */
#ifndef MAPLESU_HELPER_PATH
#define MAPLESU_HELPER_PATH "/data/user/0/dev.maplesu.manager/bs"
#endif
static const char maplesu_helper[] = MAPLESU_HELPER_PATH;

/*
 * UMH argument block (design §2.1). File-scope `static`, never a stack array:
 * UMH_WAIT_EXEC returns when the exec succeeds, and what the kernel kept is a
 * pointer to these arrays - a stack copy would be read after init_module() is
 * gone. The reference dfroot.c uses static storage for the same reason
 * (upstream/lkm/dfroot.c:90-91).
 *
 *   argv = {helper, "--umh", "--entry-enforcing", "<0|1>", NULL}
 *
 * The trailing element carries the enforcement byte this module *observed* before
 * it wrote 0 (the value printed by `selinux permissive for handover (was %d)`), so
 * the helper's restore target comes from the kernel instead of from a userspace
 * assumption. `maplesu_entry` is written in init_module() and stays valid for the
 * lifetime of the module.
 */
static char maplesu_entry[2];
static char *maplesu_argv[5];
static char *maplesu_envp[2];

static maplesu_kallsyms_lookup_name_fn maplesu_lookup;
static u8 maplesu_saved_enforcing;
static struct maplesu_selinux_state *maplesu_selinux;

/* Indirect call through a resolved address: no KCFI check may be emitted here. */
static MAPLESU_NOCFI uptr maplesu_sym(const char *name)
{
	return maplesu_lookup ? (uptr)maplesu_lookup(name) : 0;
}

/*
 * Step-4 (D4-4, design §2.4): restoring is only honest when this module owns the value.
 *
 * `maplesu_saved_enforcing == 0` means the window was already open when this module
 * loaded - i.e. some earlier stage (dfroot) had already written 0 - so the byte this
 * module "saved" is an inherited value, not the device's entry state. Writing it back
 * is not a restore: it would overwrite the helper's correct target with 0 and turn the
 * handover's restore evidence into a false statement. Q-D1 accepts this: the module
 * declares it has nothing to write back ("own_window=0") and the helper's App-supplied
 * baseline is the authority.
 */
static void maplesu_restore_enforcing(void)
{
	if (maplesu_saved_enforcing == 0)
		return;
	if (maplesu_selinux != MAPLESU_NULL)
		maplesu_selinux->enforcing = maplesu_saved_enforcing;
}

#if MAPLESU_PATCH_VENDOR_HANDLERS
/*
 * Make a function return 0 without knowing its body.
 *
 * The prologue may begin with PACIASP/PACIBSP and/or a BTI landing pad, so the first
 * real instruction is not always at +0. RETAA/RETAB are undefined on CPUs without
 * pointer authentication, so the plain RET is used unless address auth is present.
 *
 * NOT COMPILED IN THE CANARY BUILD (MAPLESU_PATCH_VENDOR_HANDLERS = 0): this is the
 * only user of aarch64_insn_patch_text and of the authenticated-return choice, and
 * the pre-canary review flagged the missing hardware gate (§3.3). The code stays
 * here, under the switch, so enabling it is a build decision, not a rewrite.
 */
static MAPLESU_NOCFI void maplesu_patch_return_zero(void *fn)
{
	maplesu_insn_patch_fn patch = (maplesu_insn_patch_fn)maplesu_sym(
		"aarch64_insn_patch_text");
	u32 insn = *(u32 *)fn;
	int skip = 0;
	int have_pac_a = 0, have_pac_b = 0;
	void *addrs[2];
	u32 insns[2];

	if (patch == MAPLESU_NULL)
		return;

	while (skip < 2) {
		switch (insn) {
		case 0xD503233F: /* PACIASP */
			have_pac_a = 1;
			goto next_insn;
		case 0xD503237F: /* PACIBSP */
			have_pac_b = 1;
			goto next_insn;
		case 0xD503241F: /* BTI    */
		case 0xD503245F: /* BTI c  */
		case 0xD503249F: /* BTI j  */
		case 0xD50324DF: /* BTI jc */
next_insn:
			insn = *(u32 *)((u8 *)fn + ++skip * 4);
			continue;
		default:
			break;
		}
		break;
	}

	addrs[0] = (u8 *)fn + skip * 4;
	addrs[1] = (u8 *)fn + skip * 4 + 4;
	insns[0] = 0xD2800000; /* mov x0, #0 */
	insns[1] = have_pac_b ? 0xD65F0FFF : /* retab */
		   have_pac_a ? 0xD65F0BFF : /* retaa */
			0xD65F03C0;   /* ret   */
	if (patch(addrs, insns, 2))
		_printk(MAPLESU_TAG "patch failed at %px\n", fn);
}
#endif /* MAPLESU_PATCH_VENDOR_HANDLERS */

MAPLESU_NOCFI __attribute__((section(".init.text"))) __attribute__((noinline))
int init_module(void)
{
	struct maplesu_kprobe probe;
	maplesu_umh_setup_fn setup;
	maplesu_umh_exec_fn exec;
	maplesu_umh_call_fn call;
	void *info;
	int ret;
	int fallback;

	/* 1. kallsyms_lookup_name, through a kprobe on its own name. */
	{
		u8 *raw = (u8 *)&probe;

		for (u32 i = 0; i < (u32)sizeof(probe); ++i)
			raw[i] = 0;
	}
	probe.symbol_name = "kallsyms_lookup_name";
	if (register_kprobe(&probe) < 0) {
		_printk(MAPLESU_TAG "kallsyms_lookup_name not found\n");
		return -38; /* -ENOSYS */
	}
	maplesu_lookup = (maplesu_kallsyms_lookup_name_fn)probe.addr;
	unregister_kprobe(&probe);
	if (maplesu_lookup == MAPLESU_NULL) {
		_printk(MAPLESU_TAG "kprobe resolved no address\n");
		return -38;
	}
	/* Acceptance (b): positive proof that step 1 happened, not just silence. */
	_printk(MAPLESU_TAG "kallsyms_lookup_name=%px\n", (void *)maplesu_lookup);


	/* 2. SELinux permissive for the handover window, remembering the old value. */
	maplesu_selinux = (struct maplesu_selinux_state *)maplesu_sym("selinux_state");
	if (maplesu_selinux == MAPLESU_NULL) {
		_printk(MAPLESU_TAG "selinux_state not found\n");
		return -2; /* -ENOENT */
	}
	maplesu_saved_enforcing = maplesu_selinux->enforcing;
	maplesu_selinux->enforcing = 0;
	/*
	 * Step-4 (D4-4/D5): own_window is the kernel's own statement about whether it had
	 * anything to save. 1 = this module moved the byte from enforcing to permissive, so
	 * cleanup_module() must put it back. 0 = the window was already open when this module
	 * loaded, so the saved byte is an inherited value and writing it back would not be a
	 * restore. The helper copies this line out of the ring buffer inside the window, so
	 * "the kernel had no true value" is readable evidence, not an absence.
	 */
	_printk(MAPLESU_TAG "selinux permissive for handover (was %d) own_window=%d\n",
		(int)maplesu_saved_enforcing,
		(int)(maplesu_saved_enforcing != 0));

	/* 3. Vendor anti-root hooks: opt-in only (P3b; absent on this image). */
#if MAPLESU_PATCH_VENDOR_HANDLERS
	{
		void *handlers[4];
		u32 i;

		handlers[0] = (void *)maplesu_sym("oplus_exe_block_ret_handler");
		handlers[1] = (void *)maplesu_sym("oplus_root_check_post_handler");
		handlers[2] = (void *)maplesu_sym("task_defex_enforce");
		handlers[3] = (void *)maplesu_sym("task_defex_user_exec");
		for (i = 0; i < 4; ++i) {
			if (handlers[i] != MAPLESU_NULL)
				maplesu_patch_return_zero(handlers[i]);
		}
	}
#endif

	/*
	 * 4. Hand over to userspace as kernel-domain root.
	 *
	 * Primary: the two-stage call. setup() allocates and returns the subprocess_info;
	 * because CONFIG_STATIC_USERMODEHELPER_PATH is "", it also replaces the path it
	 * was given with "". Writing maplesu_helper back into subprocess_info.path
	 * (BTF: +0x38; the same field exec() reads) is what makes exec() actually fork.
	 *
	 * Fallback: the four-argument wrapper, only when the two symbols above cannot be
	 * resolved. On a static-UMH kernel that call cannot exec anything -- it returns 0
	 * silently -- so the branch is fail-closed: whatever value it returns, no handover
	 * happened, the saved enforcing value is restored and init_module fails.
	 */
	/*
	 * The argument block is filled here, once, from the byte this function observed:
	 * the helper is told which enforcement value to restore (design §2.1), and both
	 * the inner string and the arrays live in .bss for the life of the module (R1).
	 */
	maplesu_entry[0] = (char)('0' + (maplesu_saved_enforcing & 1));
	maplesu_entry[1] = '\0';
	maplesu_argv[0] = (char *)maplesu_helper;
	maplesu_argv[1] = (char *)"--umh";
	maplesu_argv[2] = (char *)"--entry-enforcing";
	maplesu_argv[3] = maplesu_entry;
	maplesu_argv[4] = MAPLESU_NULL;
	maplesu_envp[0] = (char *)"PATH=/system/bin";
	maplesu_envp[1] = MAPLESU_NULL;

	setup = (maplesu_umh_setup_fn)maplesu_sym("call_usermodehelper_setup");
	exec = (maplesu_umh_exec_fn)maplesu_sym("call_usermodehelper_exec");
	call = (maplesu_umh_call_fn)maplesu_sym("call_usermodehelper");
	fallback = (setup == MAPLESU_NULL || exec == MAPLESU_NULL);
	if (!fallback) {
		info = setup(maplesu_helper, maplesu_argv, maplesu_envp,
			     MAPLESU_GFP_KERNEL, MAPLESU_NULL, MAPLESU_NULL,
			     MAPLESU_NULL);
		if (info == MAPLESU_NULL) {
			/* The allocation failed: nothing was queued and nothing ran. */
			_printk(MAPLESU_TAG "umh setup returned NULL\n");
			maplesu_restore_enforcing();
			return -12; /* -ENOMEM */
		}
		((struct maplesu_subprocess_info *)info)->path = maplesu_helper;
		ret = exec(info, MAPLESU_UMH_WAIT_EXEC);
	} else {
		_printk(MAPLESU_TAG "umh setup/exec unresolved (setup=%px exec=%px); "
			"falling back to the four-argument wrapper\n",
			(void *)setup, (void *)exec);
		if (call == MAPLESU_NULL) {
			_printk(MAPLESU_TAG "call_usermodehelper is not in kallsyms");
			maplesu_restore_enforcing();
			return -38; /* -ENOSYS */
		}
#ifdef MAPLESU_CANARY_KPROBE
		/*
		 * Bisect build: everything runs - resolution, the SELinux write, this very
		 * call - but the target cannot exist, so no handover starts. It separates
		 * "our init kills the device" from "the handover or the helper does".
		 */
		ret = call("/nonexistent/maplesu-canary-helper",
			   maplesu_argv, maplesu_envp, MAPLESU_UMH_WAIT_EXEC);
#else
		ret = call(maplesu_helper, maplesu_argv, maplesu_envp,
			   MAPLESU_UMH_WAIT_EXEC);
#endif
		if (ret == 0)
			_printk(MAPLESU_TAG "WARNING: fallback returned 0, which on a "
				"static-UMH kernel does NOT prove the helper ran\n");
	}
	/* Acceptance (c): the resolved pair and what the handover attempt returned. */
	_printk(MAPLESU_TAG "umh setup=%px exec=%px ret=%d\n",
		(void *)setup, (void *)exec, ret);

	/*
	 * The fallback is fail-closed *by construction*, not by inspecting `ret`: on a
	 * static-UMH kernel the wrapper's 0 is the silent no-op, so there is no value it
	 * can return that would prove a handover. Reaching here means either nothing was
	 * started (this branch) or exec() said so (below); both restore and fail.
	 */
	if (fallback) {
		_printk(MAPLESU_TAG "fallback cannot hand over on a static-UMH kernel; "
			"nothing was started\n");
		maplesu_restore_enforcing();
		return -22; /* -EINVAL: the two-stage pair was not resolvable */
	}
	if (ret != 0) {
		_printk(MAPLESU_TAG "helper exec failed %d\n", ret);
		maplesu_restore_enforcing();
		return -19; /* -ENODEV: the helper was not exec'd */
	}

	/*
	 * Success: stay resident. The helper owns the enforcement restore from here -
	 * it does that at the end of its own teardown - so that a device never loses
	 * its enforcing state just because this module returned. This line is not the
	 * canary's proof; the helper's own marker and the `getenforce` readback are.
	 */
	_printk(MAPLESU_TAG "handover started; resident\n");
	return 0;
}

/*
 * cleanup_module is the restore point, not a courtesy.
 *
 * The helper execs the long-lived consumer and never exits, so this module cannot
 * observe its death (that is exactly why UMH_WAIT_PROC is forbidden here). If the
 * helper dies mid-handover, the only in-kernel place that can still put the observed
 * enforcement value back is this function, reachable through delete_module() - so the
 * module must stay resident AND stay unloadable. The App unloads a stale instance
 * before each attempt, which makes the restore part of the normal retry path too.
 *
 * Step-3 makes this the second rung of the helper's restore ladder (design §5.2 L2):
 * when the helper cannot restore the value itself it calls delete_module(), the
 * kernel runs this exit function in the caller's context, and the byte saved at
 * init time goes back. The printk is the evidence for that rung - the helper copies
 * it out of the ring buffer after the unload - so it names the value it wrote.
 */
void cleanup_module(void)
{
	/*
	 * Step-4 (D4-4, design §2.4): write back only the window this module opened.
	 * `saved == 0` means the window was already open before this module loaded (the
	 * dfroot chain), so there is no restored value to claim - and writing 0 here is
	 * exactly what made step-3's "kernel-side restore" describe 0. The helper writes the
	 * real target, last, after delete_module(); this branch must not race it.
	 */
	if (maplesu_saved_enforcing == 0) {
		_printk(MAPLESU_TAG "cleanup skipped (window inherited)\n");
		return;
	}
	maplesu_restore_enforcing();
	_printk(MAPLESU_TAG "cleanup restored enforce=%d\n",
		(int)(maplesu_selinux != MAPLESU_NULL ? maplesu_selinux->enforcing : -1));
}
