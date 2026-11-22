cmd_/output/android14-6.1/ksu_setprocattr.o := clang -Wp,-MMD,/output/android14-6.1/.ksu_setprocattr.o.d -nostdinc -I/opt/ddk/src/android14-6.1/arch/arm64/include -I./arch/arm64/include/generated -I/opt/ddk/src/android14-6.1/include -I./include -I/opt/ddk/src/android14-6.1/arch/arm64/include/uapi -I./arch/arm64/include/generated/uapi -I/opt/ddk/src/android14-6.1/include/uapi -I./include/generated/uapi -include /opt/ddk/src/android14-6.1/include/linux/compiler-version.h -include /opt/ddk/src/android14-6.1/include/linux/kconfig.h -include /opt/ddk/src/android14-6.1/include/linux/compiler_types.h -D__KERNEL__ --target=aarch64-linux-gnu -fintegrated-as -Werror=unknown-warning-option -Werror=ignored-optimization-argument -mlittle-endian -DKASAN_SHADOW_SCALE_SHIFT= -Qunused-arguments -fmacro-prefix-map=/opt/ddk/src/android14-6.1/= -Wall -Wundef -Werror=strict-prototypes -Wno-trigraphs -fno-strict-aliasing -fno-common -fshort-wchar -fno-PIE -Werror=implicit-function-declaration -Werror=implicit-int -Werror=return-type -Wno-format-security -std=gnu11 -mgeneral-regs-only -DCONFIG_CC_HAS_K_CONSTRAINT=1 -Wno-psabi -fasynchronous-unwind-tables -mbranch-protection=pac-ret -Wa,-march=armv8.5-a -DARM64_ASM_ARCH='"armv8.5-a"' -ffixed-x18 -DKASAN_SHADOW_SCALE_SHIFT= -fno-delete-null-pointer-checks -Wno-frame-address -Wno-address-of-packed-member -O2 -Wframe-larger-than=2048 -fstack-protector-strong -Wno-gnu -Wno-unused-but-set-variable -Wno-unused-const-variable -fno-omit-frame-pointer -fno-optimize-sibling-calls -ftrivial-auto-var-init=zero -fno-stack-clash-protection -fsanitize=kcfi -Wvla -Wno-pointer-sign -Wcast-function-type -Werror -Wimplicit-fallthrough -fno-strict-overflow -fno-stack-check -Werror=date-time -Werror=incompatible-pointer-types -fno-builtin-wcslen -Wno-initializer-overrides -Wno-sign-compare -Wno-pointer-to-enum-cast -Wno-tautological-constant-out-of-range-compare -Wno-unaligned-access -Wno-cast-function-type-strict -Wno-enum-compare-conditional -g -gdwarf-4 -mstack-protector-guard=sysreg -mstack-protector-guard-reg=sp_el0 -mstack-protector-guard-offset=1592 -I/output/android14-6.1 -I/output/android14-6.1/.. -I/opt/ddk/src/android14-6.1/security/selinux -I/opt/ddk/src/android14-6.1/security/selinux/include -I./security/selinux -Werror -fno-lto -fno-sanitize=cfi -DMAPLESU_POLICY_HAS_VM_FLAGS_CLEAR -fPIC -DMAPLESU_POLICY_PIC -mbranch-protection=standard  -fsanitize=array-bounds -fsanitize=local-bounds -fsanitize-undefined-trap-on-error  -DMODULE  -DKBUILD_BASENAME='"ksu_setprocattr"' -DKBUILD_MODNAME='"maplesu_policy_view"' -D__KBUILD_MODNAME=kmod_maplesu_policy_view -c -o /output/android14-6.1/ksu_setprocattr.o /output/android14-6.1/ksu_setprocattr.c  

source_/output/android14-6.1/ksu_setprocattr.o := /output/android14-6.1/ksu_setprocattr.c

deps_/output/android14-6.1/ksu_setprocattr.o := \
  /opt/ddk/src/android14-6.1/include/linux/compiler-version.h \
    $(wildcard include/config/CC_VERSION_TEXT) \
  /opt/ddk/src/android14-6.1/include/linux/kconfig.h \
    $(wildcard include/config/CPU_BIG_ENDIAN) \
    $(wildcard include/config/BOOGER) \
    $(wildcard include/config/FOO) \
  /opt/ddk/src/android14-6.1/include/linux/compiler_types.h \
    $(wildcard include/config/DEBUG_INFO_BTF) \
    $(wildcard include/config/PAHOLE_HAS_BTF_TAG) \
    $(wildcard include/config/HAVE_ARCH_COMPILER_H) \
    $(wildcard include/config/CC_HAS_ASM_INLINE) \
  /opt/ddk/src/android14-6.1/include/linux/compiler_attributes.h \
  /opt/ddk/src/android14-6.1/include/linux/compiler-clang.h \
    $(wildcard include/config/ARCH_USE_BUILTIN_BSWAP) \
    $(wildcard include/config/CLANG_VERSION) \
  /opt/ddk/src/android14-6.1/arch/arm64/include/asm/compiler.h \
  /output/android14-6.1/policy_view_internal.h \
  /opt/ddk/src/android14-6.1/include/linux/jump_label.h \
    $(wildcard include/config/JUMP_LABEL) \
    $(wildcard include/config/HAVE_ARCH_JUMP_LABEL_RELATIVE) \
  /opt/ddk/src/android14-6.1/include/linux/types.h \
    $(wildcard include/config/HAVE_UID16) \
    $(wildcard include/config/UID16) \
    $(wildcard include/config/ARCH_DMA_ADDR_T_64BIT) \
    $(wildcard include/config/PHYS_ADDR_T_64BIT) \
    $(wildcard include/config/64BIT) \
    $(wildcard include/config/ARCH_32BIT_USTAT_F_TINODE) \
  /opt/ddk/src/android14-6.1/include/uapi/linux/types.h \
  arch/arm64/include/generated/uapi/asm/types.h \
  /opt/ddk/src/android14-6.1/include/uapi/asm-generic/types.h \
  /opt/ddk/src/android14-6.1/include/asm-generic/int-ll64.h \
  /opt/ddk/src/android14-6.1/include/uapi/asm-generic/int-ll64.h \
  /opt/ddk/src/android14-6.1/arch/arm64/include/uapi/asm/bitsperlong.h \
  /opt/ddk/src/android14-6.1/include/asm-generic/bitsperlong.h \
  /opt/ddk/src/android14-6.1/include/uapi/asm-generic/bitsperlong.h \
  /opt/ddk/src/android14-6.1/include/uapi/linux/posix_types.h \
  /opt/ddk/src/android14-6.1/include/linux/stddef.h \
  /opt/ddk/src/android14-6.1/include/uapi/linux/stddef.h \
  /opt/ddk/src/android14-6.1/arch/arm64/include/uapi/asm/posix_types.h \
  /opt/ddk/src/android14-6.1/include/uapi/asm-generic/posix_types.h \
  /opt/ddk/src/android14-6.1/include/linux/compiler.h \
    $(wildcard include/config/TRACE_BRANCH_PROFILING) \
    $(wildcard include/config/PROFILE_ALL_BRANCHES) \
    $(wildcard include/config/OBJTOOL) \
  /opt/ddk/src/android14-6.1/arch/arm64/include/asm/rwonce.h \
    $(wildcard include/config/LTO) \
    $(wildcard include/config/AS_HAS_LDAPR) \
  /opt/ddk/src/android14-6.1/include/asm-generic/rwonce.h \
  /opt/ddk/src/android14-6.1/include/linux/kasan-checks.h \
    $(wildcard include/config/KASAN_GENERIC) \
    $(wildcard include/config/KASAN_SW_TAGS) \
  /opt/ddk/src/android14-6.1/include/linux/kcsan-checks.h \
    $(wildcard include/config/KCSAN) \
    $(wildcard include/config/KCSAN_WEAK_MEMORY) \
    $(wildcard include/config/KCSAN_IGNORE_ATOMICS) \
  /opt/ddk/src/android14-6.1/arch/arm64/include/asm/jump_label.h \
  /opt/ddk/src/android14-6.1/arch/arm64/include/asm/insn.h \
    $(wildcard include/config/ARM64_LSE_ATOMICS) \
  /opt/ddk/src/android14-6.1/include/linux/build_bug.h \
  /opt/ddk/src/android14-6.1/arch/arm64/include/asm/insn-def.h \
  /opt/ddk/src/android14-6.1/arch/arm64/include/asm/brk-imm.h \
  /opt/ddk/src/android14-6.1/include/linux/cred.h \
    $(wildcard include/config/MULTIUSER) \
    $(wildcard include/config/DEBUG_CREDENTIALS) \
    $(wildcard include/config/KEYS) \
    $(wildcard include/config/SECURITY) \
    $(wildcard include/config/USER_NS) \
  /opt/ddk/src/android14-6.1/include/linux/capability.h \
  /opt/ddk/src/android14-6.1/include/uapi/linux/capability.h \
  /opt/ddk/src/android14-6.1/include/linux/uidgid.h \
  /opt/ddk/src/android14-6.1/include/linux/highuid.h \
  /opt/ddk/src/android14-6.1/include/linux/init.h \
    $(wildcard include/config/HAVE_ARCH_PREL32_RELOCATIONS) \
    $(wildcard include/config/STRICT_KERNEL_RWX) \
    $(wildcard include/config/STRICT_MODULE_RWX) \
    $(wildcard include/config/LTO_CLANG) \
  /opt/ddk/src/android14-6.1/include/linux/key.h \
    $(wildcard include/config/KEY_NOTIFICATIONS) \
    $(wildcard include/config/NET) \
    $(wildcard include/config/SYSCTL) \
  /opt/ddk/src/android14-6.1/include/linux/list.h \
    $(wildcard include/config/DEBUG_LIST) \
  /opt/ddk/src/android14-6.1/include/linux/container_of.h \
  /opt/ddk/src/android14-6.1/include/linux/err.h \
  arch/arm64/include/generated/uapi/asm/errno.h \
  /opt/ddk/src/android14-6.1/include/uapi/asm-generic/errno.h \
  /opt/ddk/src/android14-6.1/include/uapi/asm-generic/errno-base.h \
  /opt/ddk/src/android14-6.1/include/linux/poison.h \
    $(wildcard include/config/ILLEGAL_POINTER_VALUE) \
  /opt/ddk/src/android14-6.1/include/linux/const.h \
  /opt/ddk/src/android14-6.1/include/vdso/const.h \
  /opt/ddk/src/android14-6.1/include/uapi/linux/const.h \
  /opt/ddk/src/android14-6.1/arch/arm64/include/asm/barrier.h \
    $(wildcard include/config/ARM64_PSEUDO_NMI) \
  /opt/ddk/src/android14-6.1/include/asm-generic/barrier.h \
    $(wildcard include/config/SMP) \
  /opt/ddk/src/android14-6.1/include/linux/rbtree.h \
  /opt/ddk/src/android14-6.1/include/linux/rbtree_types.h \
  /opt/ddk/src/android14-6.1/include/linux/rcupdate.h \
    $(wildcard include/config/PREEMPT_RCU) \
    $(wildcard include/config/TINY_RCU) \
    $(wildcard include/config/RCU_STRICT_GRACE_PERIOD) \
    $(wildcard include/config/RCU_LAZY) \
    $(wildcard include/config/TASKS_RCU_GENERIC) \
    $(wildcard include/config/RCU_STALL_COMMON) \
    $(wildcard include/config/NO_HZ_FULL) \
    $(wildcard include/config/GENERIC_ENTRY) \
    $(wildcard include/config/KVM_XFER_TO_GUEST_WORK) \
    $(wildcard include/config/RCU_NOCB_CPU) \
    $(wildcard include/config/TASKS_RCU) \
    $(wildcard include/config/TASKS_TRACE_RCU) \
    $(wildcard include/config/TASKS_RUDE_RCU) \
    $(wildcard include/config/PREEMPT_RT) \
    $(wildcard include/config/TREE_RCU) \
    $(wildcard include/config/DEBUG_OBJECTS_RCU_HEAD) \
    $(wildcard include/config/HOTPLUG_CPU) \
    $(wildcard include/config/PROVE_RCU) \
    $(wildcard include/config/DEBUG_LOCK_ALLOC) \
    $(wildcard include/config/PREEMPTION) \
    $(wildcard include/config/ARCH_WEAK_RELEASE_ACQUIRE) \
  /opt/ddk/src/android14-6.1/include/linux/atomic.h \
  /opt/ddk/src/android14-6.1/arch/arm64/include/asm/atomic.h \
  /opt/ddk/src/android14-6.1/arch/arm64/include/asm/cmpxchg.h \
  /opt/ddk/src/android14-6.1/arch/arm64/include/asm/lse.h \
  /opt/ddk/src/android14-6.1/arch/arm64/include/asm/atomic_ll_sc.h \
    $(wildcard include/config/CC_HAS_K_CONSTRAINT) \
  /opt/ddk/src/android14-6.1/include/linux/stringify.h \
  /opt/ddk/src/android14-6.1/include/linux/export.h \
    $(wildcard include/config/MODVERSIONS) \
    $(wildcard include/config/MODULES) \
    $(wildcard include/config/TRIM_UNUSED_KSYMS) \
  /opt/ddk/src/android14-6.1/arch/arm64/include/asm/alternative.h \
  /opt/ddk/src/android14-6.1/arch/arm64/include/asm/alternative-macros.h \
  /opt/ddk/src/android14-6.1/include/vdso/bits.h \
  arch/arm64/include/generated/asm/cpucaps.h \
  /opt/ddk/src/android14-6.1/arch/arm64/include/asm/atomic_lse.h \
  /opt/ddk/src/android14-6.1/include/linux/atomic/atomic-arch-fallback.h \
    $(wildcard include/config/GENERIC_ATOMIC64) \
  /opt/ddk/src/android14-6.1/include/linux/atomic/atomic-long.h \
  /opt/ddk/src/android14-6.1/include/linux/atomic/atomic-instrumented.h \
  /opt/ddk/src/android14-6.1/include/linux/instrumented.h \
  /opt/ddk/src/android14-6.1/include/linux/kmsan-checks.h \
    $(wildcard include/config/KMSAN) \
  /opt/ddk/src/android14-6.1/include/linux/irqflags.h \
    $(wildcard include/config/PROVE_LOCKING) \
    $(wildcard include/config/TRACE_IRQFLAGS) \
    $(wildcard include/config/IRQSOFF_TRACER) \
    $(wildcard include/config/PREEMPT_TRACER) \
    $(wildcard include/config/DEBUG_IRQFLAGS) \
    $(wildcard include/config/TRACE_IRQFLAGS_SUPPORT) \
  /opt/ddk/src/android14-6.1/include/linux/typecheck.h \
  /opt/ddk/src/android14-6.1/include/linux/cleanup.h \
  /opt/ddk/src/android14-6.1/arch/arm64/include/asm/irqflags.h \
  /opt/ddk/src/android14-6.1/arch/arm64/include/asm/ptrace.h \
    $(wildcard include/config/COMPAT) \
  /opt/ddk/src/android14-6.1/arch/arm64/include/asm/cpufeature.h \
    $(wildcard include/config/ARM64_PAN) \
    $(wildcard include/config/ARM64_SW_TTBR0_PAN) \
    $(wildcard include/config/ARM64_SVE) \
    $(wildcard include/config/ARM64_SME) \
    $(wildcard include/config/ARM64_CNP) \
    $(wildcard include/config/ARM64_PTR_AUTH) \
    $(wildcard include/config/ARM64_MTE) \
    $(wildcard include/config/ARM64_DEBUG_PRIORITY_MASKING) \
    $(wildcard include/config/ARM64_BTI) \
    $(wildcard include/config/ARM64_TLB_RANGE) \
    $(wildcard include/config/ARM64_PA_BITS) \
    $(wildcard include/config/ARM64_HW_AFDBM) \
    $(wildcard include/config/ARM64_AMU_EXTN) \
  /opt/ddk/src/android14-6.1/arch/arm64/include/asm/cputype.h \
  /opt/ddk/src/android14-6.1/arch/arm64/include/asm/sysreg.h \
    $(wildcard include/config/BROKEN_GAS_INST) \
    $(wildcard include/config/ARM64_PA_BITS_52) \
    $(wildcard include/config/ARM64_4K_PAGES) \
    $(wildcard include/config/ARM64_16K_PAGES) \
    $(wildcard include/config/ARM64_64K_PAGES) \
    $(wildcard include/config/KASAN_HW_TAGS) \
  /opt/ddk/src/android14-6.1/include/linux/bits.h \
  /opt/ddk/src/android14-6.1/include/linux/kasan-tags.h \
  /opt/ddk/src/android14-6.1/arch/arm64/include/asm/gpr-num.h \
  arch/arm64/include/generated/asm/sysreg-defs.h \
  /opt/ddk/src/android14-6.1/include/linux/bitfield.h \
  /opt/ddk/src/android14-6.1/arch/arm64/include/uapi/asm/byteorder.h \
  /opt/ddk/src/android14-6.1/include/linux/byteorder/little_endian.h \
  /opt/ddk/src/android14-6.1/include/uapi/linux/byteorder/little_endian.h \
  /opt/ddk/src/android14-6.1/include/linux/swab.h \
  /opt/ddk/src/android14-6.1/include/uapi/linux/swab.h \
  arch/arm64/include/generated/uapi/asm/swab.h \
  /opt/ddk/src/android14-6.1/include/uapi/asm-generic/swab.h \
  /opt/ddk/src/android14-6.1/include/linux/byteorder/generic.h \
  /opt/ddk/src/android14-6.1/arch/arm64/include/asm/hwcap.h \
  /opt/ddk/src/android14-6.1/arch/arm64/include/uapi/asm/hwcap.h \
  /opt/ddk/src/android14-6.1/include/linux/log2.h \
    $(wildcard include/config/ARCH_HAS_ILOG2_U32) \
    $(wildcard include/config/ARCH_HAS_ILOG2_U64) \
  /opt/ddk/src/android14-6.1/include/linux/bitops.h \
  /opt/ddk/src/android14-6.1/include/uapi/linux/kernel.h \
  /opt/ddk/src/android14-6.1/include/uapi/linux/sysinfo.h \
  /opt/ddk/src/android14-6.1/include/asm-generic/bitops/generic-non-atomic.h \
  /opt/ddk/src/android14-6.1/arch/arm64/include/asm/bitops.h \
  /opt/ddk/src/android14-6.1/include/asm-generic/bitops/builtin-__ffs.h \
  /opt/ddk/src/android14-6.1/include/asm-generic/bitops/builtin-ffs.h \
  /opt/ddk/src/android14-6.1/include/asm-generic/bitops/builtin-__fls.h \
  /opt/ddk/src/android14-6.1/include/asm-generic/bitops/builtin-fls.h \
  /opt/ddk/src/android14-6.1/include/asm-generic/bitops/ffz.h \
  /opt/ddk/src/android14-6.1/include/asm-generic/bitops/fls64.h \
  /opt/ddk/src/android14-6.1/include/asm-generic/bitops/sched.h \
  /opt/ddk/src/android14-6.1/include/asm-generic/bitops/hweight.h \
  /opt/ddk/src/android14-6.1/include/asm-generic/bitops/arch_hweight.h \
  /opt/ddk/src/android14-6.1/include/asm-generic/bitops/const_hweight.h \
  /opt/ddk/src/android14-6.1/include/asm-generic/bitops/atomic.h \
  /opt/ddk/src/android14-6.1/include/asm-generic/bitops/instrumented-atomic.h \
  /opt/ddk/src/android14-6.1/include/asm-generic/bitops/lock.h \
  /opt/ddk/src/android14-6.1/include/asm-generic/bitops/instrumented-lock.h \
  /opt/ddk/src/android14-6.1/include/asm-generic/bitops/non-atomic.h \
  /opt/ddk/src/android14-6.1/include/asm-generic/bitops/non-instrumented-non-atomic.h \
  /opt/ddk/src/android14-6.1/include/asm-generic/bitops/le.h \
  /opt/ddk/src/android14-6.1/include/asm-generic/bitops/ext2-atomic-setbit.h \
  /opt/ddk/src/android14-6.1/include/linux/bug.h \
    $(wildcard include/config/GENERIC_BUG) \
    $(wildcard include/config/BUG_ON_DATA_CORRUPTION) \
  /opt/ddk/src/android14-6.1/arch/arm64/include/asm/bug.h \
  /opt/ddk/src/android14-6.1/arch/arm64/include/asm/asm-bug.h \
    $(wildcard include/config/DEBUG_BUGVERBOSE) \
  /opt/ddk/src/android14-6.1/include/asm-generic/bug.h \
    $(wildcard include/config/BUG) \
    $(wildcard include/config/GENERIC_BUG_RELATIVE_POINTERS) \
  /opt/ddk/src/android14-6.1/include/linux/instrumentation.h \
    $(wildcard include/config/NOINSTR_VALIDATION) \
  /opt/ddk/src/android14-6.1/include/linux/once_lite.h \
  /opt/ddk/src/android14-6.1/include/linux/panic.h \
    $(wildcard include/config/PANIC_TIMEOUT) \
  /opt/ddk/src/android14-6.1/include/linux/printk.h \
    $(wildcard include/config/MESSAGE_LOGLEVEL_DEFAULT) \
    $(wildcard include/config/CONSOLE_LOGLEVEL_DEFAULT) \
    $(wildcard include/config/CONSOLE_LOGLEVEL_QUIET) \
    $(wildcard include/config/EARLY_PRINTK) \
    $(wildcard include/config/PRINTK) \
    $(wildcard include/config/PRINTK_INDEX) \
    $(wildcard include/config/DYNAMIC_DEBUG) \
    $(wildcard include/config/DYNAMIC_DEBUG_CORE) \
  /opt/ddk/src/android14-6.1/include/linux/stdarg.h \
  /opt/ddk/src/android14-6.1/include/linux/kern_levels.h \
  /opt/ddk/src/android14-6.1/include/linux/linkage.h \
    $(wildcard include/config/ARCH_USE_SYM_ANNOTATIONS) \
  /opt/ddk/src/android14-6.1/arch/arm64/include/asm/linkage.h \
  /opt/ddk/src/android14-6.1/include/linux/ratelimit_types.h \
  /opt/ddk/src/android14-6.1/include/uapi/linux/param.h \
  /opt/ddk/src/android14-6.1/arch/arm64/include/uapi/asm/param.h \
  /opt/ddk/src/android14-6.1/include/asm-generic/param.h \
    $(wildcard include/config/HZ) \
  /opt/ddk/src/android14-6.1/include/uapi/asm-generic/param.h \
  /opt/ddk/src/android14-6.1/include/linux/spinlock_types_raw.h \
    $(wildcard include/config/DEBUG_SPINLOCK) \
  /opt/ddk/src/android14-6.1/arch/arm64/include/asm/spinlock_types.h \
  /opt/ddk/src/android14-6.1/include/asm-generic/qspinlock_types.h \
    $(wildcard include/config/NR_CPUS) \
  /opt/ddk/src/android14-6.1/include/asm-generic/qrwlock_types.h \
  /opt/ddk/src/android14-6.1/include/linux/lockdep_types.h \
    $(wildcard include/config/PROVE_RAW_LOCK_NESTING) \
    $(wildcard include/config/LOCKDEP) \
    $(wildcard include/config/LOCK_STAT) \
  /opt/ddk/src/android14-6.1/include/linux/kernel.h \
    $(wildcard include/config/PREEMPT_VOLUNTARY_BUILD) \
    $(wildcard include/config/PREEMPT_DYNAMIC) \
    $(wildcard include/config/HAVE_PREEMPT_DYNAMIC_CALL) \
    $(wildcard include/config/HAVE_PREEMPT_DYNAMIC_KEY) \
    $(wildcard include/config/PREEMPT_) \
    $(wildcard include/config/DEBUG_ATOMIC_SLEEP) \
    $(wildcard include/config/MMU) \
    $(wildcard include/config/TRACING) \
    $(wildcard include/config/FTRACE_MCOUNT_RECORD) \
  /opt/ddk/src/android14-6.1/include/linux/align.h \
  /opt/ddk/src/android14-6.1/include/linux/array_size.h \
  /opt/ddk/src/android14-6.1/include/linux/limits.h \
  /opt/ddk/src/android14-6.1/include/uapi/linux/limits.h \
  /opt/ddk/src/android14-6.1/include/vdso/limits.h \
  /opt/ddk/src/android14-6.1/include/linux/kstrtox.h \
  /opt/ddk/src/android14-6.1/include/linux/math.h \
  arch/arm64/include/generated/asm/div64.h \
  /opt/ddk/src/android14-6.1/include/asm-generic/div64.h \
  /opt/ddk/src/android14-6.1/include/linux/minmax.h \
  /opt/ddk/src/android14-6.1/include/linux/static_call_types.h \
    $(wildcard include/config/HAVE_STATIC_CALL) \
    $(wildcard include/config/HAVE_STATIC_CALL_INLINE) \
  /opt/ddk/src/android14-6.1/include/linux/instruction_pointer.h \
  /opt/ddk/src/android14-6.1/arch/arm64/include/uapi/asm/ptrace.h \
  /opt/ddk/src/android14-6.1/arch/arm64/include/uapi/asm/sve_context.h \
  /opt/ddk/src/android14-6.1/arch/arm64/include/asm/percpu.h \
    $(wildcard include/config/DEBUG_PREEMPT) \
  /opt/ddk/src/android14-6.1/include/linux/preempt.h \
    $(wildcard include/config/PREEMPT_COUNT) \
    $(wildcard include/config/TRACE_PREEMPT_TOGGLE) \
    $(wildcard include/config/PREEMPT_NOTIFIERS) \
  /opt/ddk/src/android14-6.1/arch/arm64/include/asm/preempt.h \
  /opt/ddk/src/android14-6.1/include/linux/thread_info.h \
    $(wildcard include/config/THREAD_INFO_IN_TASK) \
    $(wildcard include/config/HAVE_ARCH_WITHIN_STACK_FRAMES) \
    $(wildcard include/config/HARDENED_USERCOPY) \
  /opt/ddk/src/android14-6.1/include/linux/restart_block.h \
  /opt/ddk/src/android14-6.1/include/linux/time64.h \
  /opt/ddk/src/android14-6.1/include/linux/math64.h \
    $(wildcard include/config/ARCH_SUPPORTS_INT128) \
  /opt/ddk/src/android14-6.1/include/vdso/math64.h \
  /opt/ddk/src/android14-6.1/include/vdso/time64.h \
  /opt/ddk/src/android14-6.1/include/uapi/linux/time.h \
  /opt/ddk/src/android14-6.1/include/uapi/linux/time_types.h \
  /opt/ddk/src/android14-6.1/include/linux/errno.h \
  /opt/ddk/src/android14-6.1/include/uapi/linux/errno.h \
  /opt/ddk/src/android14-6.1/arch/arm64/include/asm/current.h \
  /opt/ddk/src/android14-6.1/arch/arm64/include/asm/thread_info.h \
    $(wildcard include/config/SHADOW_CALL_STACK) \
  /opt/ddk/src/android14-6.1/arch/arm64/include/asm/memory.h \
    $(wildcard include/config/ARM64_VA_BITS) \
    $(wildcard include/config/KASAN_SHADOW_OFFSET) \
    $(wildcard include/config/KASAN) \
    $(wildcard include/config/VMAP_STACK) \
    $(wildcard include/config/DEBUG_VIRTUAL) \
    $(wildcard include/config/ZONE_DMA) \
    $(wildcard include/config/ZONE_DMA32) \
    $(wildcard include/config/EFI) \
    $(wildcard include/config/ARM_GIC_V3_ITS) \
  /opt/ddk/src/android14-6.1/include/linux/sizes.h \
  /opt/ddk/src/android14-6.1/arch/arm64/include/asm/page-def.h \
    $(wildcard include/config/ARM64_PAGE_SHIFT) \
  /opt/ddk/src/android14-6.1/include/linux/mmdebug.h \
    $(wildcard include/config/DEBUG_VM) \
    $(wildcard include/config/DEBUG_VM_IRQSOFF) \
    $(wildcard include/config/DEBUG_VM_PGFLAGS) \
  /opt/ddk/src/android14-6.1/include/asm-generic/memory_model.h \
    $(wildcard include/config/FLATMEM) \
    $(wildcard include/config/SPARSEMEM_VMEMMAP) \
    $(wildcard include/config/SPARSEMEM) \
  /opt/ddk/src/android14-6.1/include/linux/pfn.h \
  /opt/ddk/src/android14-6.1/arch/arm64/include/asm/stack_pointer.h \
  /opt/ddk/src/android14-6.1/include/asm-generic/percpu.h \
    $(wildcard include/config/HAVE_SETUP_PER_CPU_AREA) \
  /opt/ddk/src/android14-6.1/include/linux/threads.h \
    $(wildcard include/config/BASE_SMALL) \
  /opt/ddk/src/android14-6.1/include/linux/percpu-defs.h \
    $(wildcard include/config/DEBUG_FORCE_WEAK_PER_CPU) \
    $(wildcard include/config/AMD_MEM_ENCRYPT) \
  /opt/ddk/src/android14-6.1/include/linux/bottom_half.h \
  /opt/ddk/src/android14-6.1/include/linux/lockdep.h \
    $(wildcard include/config/DEBUG_LOCKING_API_SELFTESTS) \
  /opt/ddk/src/android14-6.1/include/linux/smp.h \
    $(wildcard include/config/UP_LATE_INIT) \
  /opt/ddk/src/android14-6.1/include/linux/cpumask.h \
    $(wildcard include/config/FORCE_NR_CPUS) \
    $(wildcard include/config/DEBUG_PER_CPU_MAPS) \
    $(wildcard include/config/CPUMASK_OFFSTACK) \
  /opt/ddk/src/android14-6.1/include/linux/bitmap.h \
  /opt/ddk/src/android14-6.1/include/linux/find.h \
  /opt/ddk/src/android14-6.1/include/linux/string.h \
    $(wildcard include/config/BINARY_PRINTF) \
    $(wildcard include/config/FORTIFY_SOURCE) \
  /opt/ddk/src/android14-6.1/include/linux/overflow.h \
  /opt/ddk/src/android14-6.1/include/uapi/linux/string.h \
  /opt/ddk/src/android14-6.1/arch/arm64/include/asm/string.h \
    $(wildcard include/config/ARCH_HAS_UACCESS_FLUSHCACHE) \
  /opt/ddk/src/android14-6.1/include/linux/fortify-string.h \
  /opt/ddk/src/android14-6.1/include/linux/gfp_types.h \
    $(wildcard include/config/CMA) \
  /opt/ddk/src/android14-6.1/include/linux/numa.h \
    $(wildcard include/config/NODES_SHIFT) \
    $(wildcard include/config/NUMA_KEEP_MEMINFO) \
    $(wildcard include/config/NUMA) \
    $(wildcard include/config/HAVE_ARCH_NODE_DEV_GROUP) \
  /opt/ddk/src/android14-6.1/include/linux/smp_types.h \
  /opt/ddk/src/android14-6.1/include/linux/llist.h \
    $(wildcard include/config/ARCH_HAVE_NMI_SAFE_CMPXCHG) \
  /opt/ddk/src/android14-6.1/arch/arm64/include/asm/smp.h \
    $(wildcard include/config/ARM64_ACPI_PARKING_PROTOCOL) \
  /opt/ddk/src/android14-6.1/arch/arm64/include/asm/processor.h \
    $(wildcard include/config/KUSER_HELPERS) \
    $(wildcard include/config/ARM64_FORCE_52BIT) \
    $(wildcard include/config/HAVE_HW_BREAKPOINT) \
    $(wildcard include/config/ARM64_PTR_AUTH_KERNEL) \
    $(wildcard include/config/ARM64_TAGGED_ADDR_ABI) \
    $(wildcard include/config/GCC_PLUGIN_STACKLEAK) \
  /opt/ddk/src/android14-6.1/include/linux/cache.h \
    $(wildcard include/config/ARCH_HAS_CACHE_LINE_SIZE) \
  /opt/ddk/src/android14-6.1/arch/arm64/include/asm/cache.h \
  /opt/ddk/src/android14-6.1/include/linux/kasan-enabled.h \
  /opt/ddk/src/android14-6.1/include/linux/static_key.h \
  /opt/ddk/src/android14-6.1/arch/arm64/include/asm/mte-def.h \
  /opt/ddk/src/android14-6.1/include/linux/android_vendor.h \
    $(wildcard include/config/ANDROID_VENDOR_OEM_DATA) \
  /opt/ddk/src/android14-6.1/include/linux/android_kabi.h \
    $(wildcard include/config/ANDROID_KABI_RESERVE) \
  /opt/ddk/src/android14-6.1/include/vdso/processor.h \
  /opt/ddk/src/android14-6.1/arch/arm64/include/asm/vdso/processor.h \
  /opt/ddk/src/android14-6.1/arch/arm64/include/asm/hw_breakpoint.h \
  /opt/ddk/src/android14-6.1/arch/arm64/include/asm/virt.h \
    $(wildcard include/config/KVM) \
  /opt/ddk/src/android14-6.1/arch/arm64/include/asm/sections.h \
  /opt/ddk/src/android14-6.1/include/asm-generic/sections.h \
    $(wildcard include/config/HAVE_FUNCTION_DESCRIPTORS) \
  /opt/ddk/src/android14-6.1/arch/arm64/include/asm/kasan.h \
  /opt/ddk/src/android14-6.1/arch/arm64/include/asm/mte-kasan.h \
  /opt/ddk/src/android14-6.1/arch/arm64/include/asm/pgtable-types.h \
    $(wildcard include/config/PGTABLE_LEVELS) \
  /opt/ddk/src/android14-6.1/include/asm-generic/pgtable-nopud.h \
  /opt/ddk/src/android14-6.1/include/asm-generic/pgtable-nop4d.h \
  /opt/ddk/src/android14-6.1/arch/arm64/include/asm/pgtable-hwdef.h \
    $(wildcard include/config/ARM64_CONT_PTE_SHIFT) \
    $(wildcard include/config/ARM64_CONT_PMD_SHIFT) \
    $(wildcard include/config/ARM64_VA_BITS_52) \
  /opt/ddk/src/android14-6.1/arch/arm64/include/asm/pointer_auth.h \
  /opt/ddk/src/android14-6.1/include/uapi/linux/prctl.h \
  /opt/ddk/src/android14-6.1/include/linux/random.h \
    $(wildcard include/config/VMGENID) \
  /opt/ddk/src/android14-6.1/include/linux/once.h \
  /opt/ddk/src/android14-6.1/include/uapi/linux/random.h \
  /opt/ddk/src/android14-6.1/include/uapi/linux/ioctl.h \
  arch/arm64/include/generated/uapi/asm/ioctl.h \
  /opt/ddk/src/android14-6.1/include/asm-generic/ioctl.h \
  /opt/ddk/src/android14-6.1/include/uapi/asm-generic/ioctl.h \
  /opt/ddk/src/android14-6.1/include/linux/irqnr.h \
  /opt/ddk/src/android14-6.1/include/uapi/linux/irqnr.h \
  /opt/ddk/src/android14-6.1/include/linux/prandom.h \
  /opt/ddk/src/android14-6.1/include/linux/percpu.h \
    $(wildcard include/config/NEED_PER_CPU_EMBED_FIRST_CHUNK) \
    $(wildcard include/config/NEED_PER_CPU_PAGE_FIRST_CHUNK) \
  /opt/ddk/src/android14-6.1/arch/arm64/include/asm/archrandom.h \
  /opt/ddk/src/android14-6.1/include/linux/arm-smccc.h \
    $(wildcard include/config/ARM64) \
    $(wildcard include/config/HAVE_ARM_SMCCC) \
    $(wildcard include/config/ARM) \
  /opt/ddk/src/android14-6.1/arch/arm64/include/asm/spectre.h \
  /opt/ddk/src/android14-6.1/arch/arm64/include/asm/fpsimd.h \
  /opt/ddk/src/android14-6.1/arch/arm64/include/uapi/asm/sigcontext.h \
  /opt/ddk/src/android14-6.1/include/linux/context_tracking_irq.h \
    $(wildcard include/config/CONTEXT_TRACKING_IDLE) \
  /opt/ddk/src/android14-6.1/include/linux/rcutree.h \
  /opt/ddk/src/android14-6.1/include/linux/sysctl.h \
  /opt/ddk/src/android14-6.1/include/linux/wait.h \
  /opt/ddk/src/android14-6.1/include/linux/spinlock.h \
  arch/arm64/include/generated/asm/mmiowb.h \
  /opt/ddk/src/android14-6.1/include/asm-generic/mmiowb.h \
    $(wildcard include/config/MMIOWB) \
  /opt/ddk/src/android14-6.1/include/linux/spinlock_types.h \
  /opt/ddk/src/android14-6.1/include/linux/rwlock_types.h \
  /opt/ddk/src/android14-6.1/arch/arm64/include/asm/spinlock.h \
  arch/arm64/include/generated/asm/qspinlock.h \
  /opt/ddk/src/android14-6.1/include/asm-generic/qspinlock.h \
  arch/arm64/include/generated/asm/qrwlock.h \
  /opt/ddk/src/android14-6.1/include/asm-generic/qrwlock.h \
  /opt/ddk/src/android14-6.1/include/linux/rwlock.h \
    $(wildcard include/config/PREEMPT) \
  /opt/ddk/src/android14-6.1/include/linux/spinlock_api_smp.h \
    $(wildcard include/config/INLINE_SPIN_LOCK) \
    $(wildcard include/config/INLINE_SPIN_LOCK_BH) \
    $(wildcard include/config/INLINE_SPIN_LOCK_IRQ) \
    $(wildcard include/config/INLINE_SPIN_LOCK_IRQSAVE) \
    $(wildcard include/config/INLINE_SPIN_TRYLOCK) \
    $(wildcard include/config/INLINE_SPIN_TRYLOCK_BH) \
    $(wildcard include/config/UNINLINE_SPIN_UNLOCK) \
    $(wildcard include/config/INLINE_SPIN_UNLOCK_BH) \
    $(wildcard include/config/INLINE_SPIN_UNLOCK_IRQ) \
    $(wildcard include/config/INLINE_SPIN_UNLOCK_IRQRESTORE) \
    $(wildcard include/config/GENERIC_LOCKBREAK) \
  /opt/ddk/src/android14-6.1/include/linux/rwlock_api_smp.h \
    $(wildcard include/config/INLINE_READ_LOCK) \
    $(wildcard include/config/INLINE_WRITE_LOCK) \
    $(wildcard include/config/INLINE_READ_LOCK_BH) \
    $(wildcard include/config/INLINE_WRITE_LOCK_BH) \
    $(wildcard include/config/INLINE_READ_LOCK_IRQ) \
    $(wildcard include/config/INLINE_WRITE_LOCK_IRQ) \
    $(wildcard include/config/INLINE_READ_LOCK_IRQSAVE) \
    $(wildcard include/config/INLINE_WRITE_LOCK_IRQSAVE) \
    $(wildcard include/config/INLINE_READ_TRYLOCK) \
    $(wildcard include/config/INLINE_WRITE_TRYLOCK) \
    $(wildcard include/config/INLINE_READ_UNLOCK) \
    $(wildcard include/config/INLINE_WRITE_UNLOCK) \
    $(wildcard include/config/INLINE_READ_UNLOCK_BH) \
    $(wildcard include/config/INLINE_WRITE_UNLOCK_BH) \
    $(wildcard include/config/INLINE_READ_UNLOCK_IRQ) \
    $(wildcard include/config/INLINE_WRITE_UNLOCK_IRQ) \
    $(wildcard include/config/INLINE_READ_UNLOCK_IRQRESTORE) \
    $(wildcard include/config/INLINE_WRITE_UNLOCK_IRQRESTORE) \
  /opt/ddk/src/android14-6.1/include/uapi/linux/wait.h \
  /opt/ddk/src/android14-6.1/include/uapi/linux/sysctl.h \
  /opt/ddk/src/android14-6.1/include/linux/rwsem.h \
    $(wildcard include/config/RWSEM_SPIN_ON_OWNER) \
    $(wildcard include/config/DEBUG_RWSEMS) \
  /opt/ddk/src/android14-6.1/include/linux/osq_lock.h \
  /opt/ddk/src/android14-6.1/include/linux/assoc_array.h \
    $(wildcard include/config/ASSOCIATIVE_ARRAY) \
  /opt/ddk/src/android14-6.1/include/linux/refcount.h \
  /opt/ddk/src/android14-6.1/include/linux/sched.h \
    $(wildcard include/config/VIRT_CPU_ACCOUNTING_NATIVE) \
    $(wildcard include/config/SCHED_INFO) \
    $(wildcard include/config/SCHEDSTATS) \
    $(wildcard include/config/SCHED_CORE) \
    $(wildcard include/config/FAIR_GROUP_SCHED) \
    $(wildcard include/config/RT_GROUP_SCHED) \
    $(wildcard include/config/RT_MUTEXES) \
    $(wildcard include/config/UCLAMP_TASK) \
    $(wildcard include/config/UCLAMP_BUCKETS_COUNT) \
    $(wildcard include/config/KMAP_LOCAL) \
    $(wildcard include/config/CGROUP_SCHED) \
    $(wildcard include/config/BLK_DEV_IO_TRACE) \
    $(wildcard include/config/PSI) \
    $(wildcard include/config/MEMCG) \
    $(wildcard include/config/LRU_GEN) \
    $(wildcard include/config/COMPAT_BRK) \
    $(wildcard include/config/CGROUPS) \
    $(wildcard include/config/BLK_CGROUP) \
    $(wildcard include/config/PAGE_OWNER) \
    $(wildcard include/config/EVENTFD) \
    $(wildcard include/config/IOMMU_SVA) \
    $(wildcard include/config/CPU_SUP_INTEL) \
    $(wildcard include/config/TASK_DELAY_ACCT) \
    $(wildcard include/config/STACKPROTECTOR) \
    $(wildcard include/config/ARCH_HAS_SCALED_CPUTIME) \
    $(wildcard include/config/CPU_FREQ_TIMES) \
    $(wildcard include/config/VIRT_CPU_ACCOUNTING_GEN) \
    $(wildcard include/config/POSIX_CPUTIMERS) \
    $(wildcard include/config/POSIX_CPU_TIMERS_TASK_WORK) \
    $(wildcard include/config/SYSVIPC) \
    $(wildcard include/config/DETECT_HUNG_TASK) \
    $(wildcard include/config/IO_URING) \
    $(wildcard include/config/AUDIT) \
    $(wildcard include/config/AUDITSYSCALL) \
    $(wildcard include/config/DEBUG_MUTEXES) \
    $(wildcard include/config/UBSAN) \
    $(wildcard include/config/UBSAN_TRAP) \
    $(wildcard include/config/COMPACTION) \
    $(wildcard include/config/TASK_XACCT) \
    $(wildcard include/config/CPUSETS) \
    $(wildcard include/config/X86_CPU_RESCTRL) \
    $(wildcard include/config/FUTEX) \
    $(wildcard include/config/PERF_EVENTS) \
    $(wildcard include/config/NUMA_BALANCING) \
    $(wildcard include/config/RSEQ) \
    $(wildcard include/config/FAULT_INJECTION) \
    $(wildcard include/config/LATENCYTOP) \
    $(wildcard include/config/KUNIT) \
    $(wildcard include/config/FUNCTION_GRAPH_TRACER) \
    $(wildcard include/config/KCOV) \
    $(wildcard include/config/UPROBES) \
    $(wildcard include/config/BCACHE) \
    $(wildcard include/config/LIVEPATCH) \
    $(wildcard include/config/BPF_SYSCALL) \
    $(wildcard include/config/X86_MCE) \
    $(wildcard include/config/KRETPROBES) \
    $(wildcard include/config/RETHOOK) \
    $(wildcard include/config/ARCH_HAS_PARANOID_L1D_FLUSH) \
    $(wildcard include/config/RV) \
    $(wildcard include/config/ARCH_TASK_STRUCT_ON_STACK) \
    $(wildcard include/config/PREEMPT_NONE) \
    $(wildcard include/config/PREEMPT_VOLUNTARY) \
    $(wildcard include/config/MEMBARRIER) \
    $(wildcard include/config/DEBUG_RSEQ) \
  /opt/ddk/src/android14-6.1/include/uapi/linux/sched.h \
  /opt/ddk/src/android14-6.1/include/linux/pid.h \
  /opt/ddk/src/android14-6.1/include/linux/rculist.h \
    $(wildcard include/config/PROVE_RCU_LIST) \
  /opt/ddk/src/android14-6.1/include/linux/sem.h \
  /opt/ddk/src/android14-6.1/include/uapi/linux/sem.h \
  /opt/ddk/src/android14-6.1/include/linux/ipc.h \
  /opt/ddk/src/android14-6.1/include/linux/rhashtable-types.h \
  /opt/ddk/src/android14-6.1/include/linux/mutex.h \
    $(wildcard include/config/MUTEX_SPIN_ON_OWNER) \
  /opt/ddk/src/android14-6.1/include/linux/debug_locks.h \
  /opt/ddk/src/android14-6.1/include/linux/workqueue.h \
    $(wildcard include/config/DEBUG_OBJECTS_WORK) \
    $(wildcard include/config/FREEZER) \
    $(wildcard include/config/SYSFS) \
    $(wildcard include/config/WQ_WATCHDOG) \
  /opt/ddk/src/android14-6.1/include/linux/timer.h \
    $(wildcard include/config/DEBUG_OBJECTS_TIMERS) \
  /opt/ddk/src/android14-6.1/include/linux/ktime.h \
  /opt/ddk/src/android14-6.1/include/linux/time.h \
    $(wildcard include/config/POSIX_TIMERS) \
  /opt/ddk/src/android14-6.1/include/linux/time32.h \
  /opt/ddk/src/android14-6.1/include/linux/timex.h \
  /opt/ddk/src/android14-6.1/include/uapi/linux/timex.h \
  /opt/ddk/src/android14-6.1/arch/arm64/include/asm/timex.h \
  /opt/ddk/src/android14-6.1/arch/arm64/include/asm/arch_timer.h \
    $(wildcard include/config/ARM_ARCH_TIMER_OOL_WORKAROUND) \
  /opt/ddk/src/android14-6.1/include/clocksource/arm_arch_timer.h \
    $(wildcard include/config/ARM_ARCH_TIMER) \
  /opt/ddk/src/android14-6.1/include/linux/timecounter.h \
  /opt/ddk/src/android14-6.1/include/asm-generic/timex.h \
  /opt/ddk/src/android14-6.1/include/vdso/time32.h \
  /opt/ddk/src/android14-6.1/include/vdso/time.h \
  /opt/ddk/src/android14-6.1/include/linux/jiffies.h \
  /opt/ddk/src/android14-6.1/include/vdso/jiffies.h \
  include/generated/timeconst.h \
  /opt/ddk/src/android14-6.1/include/vdso/ktime.h \
  /opt/ddk/src/android14-6.1/include/linux/timekeeping.h \
    $(wildcard include/config/GENERIC_CMOS_UPDATE) \
  /opt/ddk/src/android14-6.1/include/linux/clocksource_ids.h \
  /opt/ddk/src/android14-6.1/include/linux/debugobjects.h \
    $(wildcard include/config/DEBUG_OBJECTS) \
    $(wildcard include/config/DEBUG_OBJECTS_FREE) \
  /opt/ddk/src/android14-6.1/include/uapi/linux/ipc.h \
  arch/arm64/include/generated/uapi/asm/ipcbuf.h \
  /opt/ddk/src/android14-6.1/include/uapi/asm-generic/ipcbuf.h \
  arch/arm64/include/generated/uapi/asm/sembuf.h \
  /opt/ddk/src/android14-6.1/include/uapi/asm-generic/sembuf.h \
  /opt/ddk/src/android14-6.1/include/linux/shm.h \
  /opt/ddk/src/android14-6.1/arch/arm64/include/asm/page.h \
  /opt/ddk/src/android14-6.1/include/linux/personality.h \
  /opt/ddk/src/android14-6.1/include/uapi/linux/personality.h \
  /opt/ddk/src/android14-6.1/include/asm-generic/getorder.h \
  /opt/ddk/src/android14-6.1/include/uapi/linux/shm.h \
  /opt/ddk/src/android14-6.1/include/uapi/asm-generic/hugetlb_encode.h \
  arch/arm64/include/generated/uapi/asm/shmbuf.h \
  /opt/ddk/src/android14-6.1/include/uapi/asm-generic/shmbuf.h \
  /opt/ddk/src/android14-6.1/arch/arm64/include/asm/shmparam.h \
  /opt/ddk/src/android14-6.1/include/asm-generic/shmparam.h \
  /opt/ddk/src/android14-6.1/include/linux/kmsan_types.h \
  /opt/ddk/src/android14-6.1/include/linux/plist.h \
    $(wildcard include/config/DEBUG_PLIST) \
  /opt/ddk/src/android14-6.1/include/linux/hrtimer.h \
    $(wildcard include/config/HIGH_RES_TIMERS) \
    $(wildcard include/config/TIME_LOW_RES) \
    $(wildcard include/config/TIMERFD) \
  /opt/ddk/src/android14-6.1/include/linux/hrtimer_defs.h \
  /opt/ddk/src/android14-6.1/include/linux/seqlock.h \
  /opt/ddk/src/android14-6.1/include/linux/timerqueue.h \
  /opt/ddk/src/android14-6.1/include/linux/seccomp.h \
    $(wildcard include/config/SECCOMP) \
    $(wildcard include/config/HAVE_ARCH_SECCOMP_FILTER) \
    $(wildcard include/config/SECCOMP_FILTER) \
    $(wildcard include/config/CHECKPOINT_RESTORE) \
    $(wildcard include/config/SECCOMP_CACHE_DEBUG) \
  /opt/ddk/src/android14-6.1/include/uapi/linux/seccomp.h \
  /opt/ddk/src/android14-6.1/arch/arm64/include/asm/seccomp.h \
  /opt/ddk/src/android14-6.1/arch/arm64/include/asm/unistd.h \
  /opt/ddk/src/android14-6.1/arch/arm64/include/uapi/asm/unistd.h \
  /opt/ddk/src/android14-6.1/include/uapi/asm-generic/unistd.h \
  /opt/ddk/src/android14-6.1/include/asm-generic/seccomp.h \
  /opt/ddk/src/android14-6.1/include/uapi/linux/unistd.h \
  /opt/ddk/src/android14-6.1/include/linux/nodemask.h \
    $(wildcard include/config/HIGHMEM) \
  /opt/ddk/src/android14-6.1/include/linux/resource.h \
  /opt/ddk/src/android14-6.1/include/uapi/linux/resource.h \
  arch/arm64/include/generated/uapi/asm/resource.h \
  /opt/ddk/src/android14-6.1/include/asm-generic/resource.h \
  /opt/ddk/src/android14-6.1/include/uapi/asm-generic/resource.h \
  /opt/ddk/src/android14-6.1/include/linux/latencytop.h \
  /opt/ddk/src/android14-6.1/include/linux/sched/prio.h \
  /opt/ddk/src/android14-6.1/include/linux/sched/types.h \
  /opt/ddk/src/android14-6.1/include/linux/signal_types.h \
    $(wildcard include/config/OLD_SIGACTION) \
  /opt/ddk/src/android14-6.1/include/uapi/linux/signal.h \
  /opt/ddk/src/android14-6.1/arch/arm64/include/asm/signal.h \
  /opt/ddk/src/android14-6.1/arch/arm64/include/uapi/asm/signal.h \
  /opt/ddk/src/android14-6.1/include/asm-generic/signal.h \
  /opt/ddk/src/android14-6.1/include/uapi/asm-generic/signal.h \
  /opt/ddk/src/android14-6.1/include/uapi/asm-generic/signal-defs.h \
  arch/arm64/include/generated/uapi/asm/siginfo.h \
  /opt/ddk/src/android14-6.1/include/uapi/asm-generic/siginfo.h \
  /opt/ddk/src/android14-6.1/include/linux/syscall_user_dispatch.h \
  /opt/ddk/src/android14-6.1/include/linux/mm_types_task.h \
    $(wildcard include/config/ARCH_WANT_BATCHED_UNMAP_TLB_FLUSH) \
    $(wildcard include/config/SPLIT_PTLOCK_CPUS) \
    $(wildcard include/config/ARCH_ENABLE_SPLIT_PMD_PTLOCK) \
  /opt/ddk/src/android14-6.1/include/linux/task_io_accounting.h \
    $(wildcard include/config/TASK_IO_ACCOUNTING) \
  /opt/ddk/src/android14-6.1/include/linux/posix-timers.h \
  /opt/ddk/src/android14-6.1/include/linux/alarmtimer.h \
    $(wildcard include/config/RTC_CLASS) \
  /opt/ddk/src/android14-6.1/include/uapi/linux/rseq.h \
  /opt/ddk/src/android14-6.1/include/linux/kcsan.h \
  /opt/ddk/src/android14-6.1/include/linux/rv.h \
    $(wildcard include/config/RV_REACTORS) \
  arch/arm64/include/generated/asm/kmap_size.h \
  /opt/ddk/src/android14-6.1/include/asm-generic/kmap_size.h \
    $(wildcard include/config/DEBUG_KMAP_LOCAL) \
  /opt/ddk/src/android14-6.1/include/linux/sched/user.h \
    $(wildcard include/config/EPOLL) \
    $(wildcard include/config/VFIO_PCI_ZDEV_KVM) \
    $(wildcard include/config/WATCH_QUEUE) \
  /opt/ddk/src/android14-6.1/include/linux/percpu_counter.h \
  /opt/ddk/src/android14-6.1/include/linux/gfp.h \
    $(wildcard include/config/ZONE_DEVICE) \
    $(wildcard include/config/PM_SLEEP) \
    $(wildcard include/config/CONTIG_ALLOC) \
  /opt/ddk/src/android14-6.1/include/linux/mmzone.h \
    $(wildcard include/config/ARCH_FORCE_MAX_ORDER) \
    $(wildcard include/config/PAGE_BLOCK_ORDER) \
    $(wildcard include/config/MEMORY_ISOLATION) \
    $(wildcard include/config/SWAP) \
    $(wildcard include/config/TRANSPARENT_HUGEPAGE) \
    $(wildcard include/config/LRU_GEN_STATS) \
    $(wildcard include/config/MEMORY_HOTPLUG) \
    $(wildcard include/config/PAGE_EXTENSION) \
    $(wildcard include/config/DEFERRED_STRUCT_PAGE_INIT) \
    $(wildcard include/config/HAVE_MEMORYLESS_NODES) \
    $(wildcard include/config/SPARSEMEM_EXTREME) \
    $(wildcard include/config/HAVE_ARCH_PFN_VALID) \
  /opt/ddk/src/android14-6.1/include/linux/list_nulls.h \
  /opt/ddk/src/android14-6.1/include/linux/pageblock-flags.h \
    $(wildcard include/config/HUGETLB_PAGE) \
    $(wildcard include/config/HUGETLB_PAGE_SIZE_VARIABLE) \
  /opt/ddk/src/android14-6.1/include/linux/page-flags-layout.h \
  include/generated/bounds.h \
  /opt/ddk/src/android14-6.1/arch/arm64/include/asm/sparsemem.h \
  /opt/ddk/src/android14-6.1/include/linux/mm_types.h \
    $(wildcard include/config/HAVE_ALIGNED_STRUCT_PAGE) \
    $(wildcard include/config/USERFAULTFD) \
    $(wildcard include/config/PER_VMA_LOCK) \
    $(wildcard include/config/HAVE_ARCH_COMPAT_MMAP_BASES) \
    $(wildcard include/config/AIO) \
    $(wildcard include/config/MMU_NOTIFIER) \
    $(wildcard include/config/KSM) \
  /opt/ddk/src/android14-6.1/include/linux/auxvec.h \
  /opt/ddk/src/android14-6.1/include/uapi/linux/auxvec.h \
  /opt/ddk/src/android14-6.1/arch/arm64/include/uapi/asm/auxvec.h \
  /opt/ddk/src/android14-6.1/include/linux/kref.h \
  /opt/ddk/src/android14-6.1/include/linux/maple_tree.h \
    $(wildcard include/config/MAPLE_RCU_DISABLED) \
    $(wildcard include/config/DEBUG_MAPLE_TREE_VERBOSE) \
    $(wildcard include/config/DEBUG_MAPLE_TREE) \
  /opt/ddk/src/android14-6.1/include/linux/completion.h \
  /opt/ddk/src/android14-6.1/include/linux/swait.h \
  /opt/ddk/src/android14-6.1/include/linux/uprobes.h \
  /opt/ddk/src/android14-6.1/arch/arm64/include/asm/uprobes.h \
  /opt/ddk/src/android14-6.1/arch/arm64/include/asm/debug-monitors.h \
  /opt/ddk/src/android14-6.1/arch/arm64/include/asm/esr.h \
  /opt/ddk/src/android14-6.1/arch/arm64/include/asm/probes.h \
    $(wildcard include/config/KPROBES) \
  /opt/ddk/src/android14-6.1/arch/arm64/include/asm/mmu.h \
  /opt/ddk/src/android14-6.1/include/linux/page-flags.h \
    $(wildcard include/config/ARCH_USES_PG_UNCACHED) \
    $(wildcard include/config/MEMORY_FAILURE) \
    $(wildcard include/config/PAGE_IDLE_FLAG) \
    $(wildcard include/config/HUGETLB_PAGE_OPTIMIZE_VMEMMAP) \
  /opt/ddk/src/android14-6.1/include/linux/local_lock.h \
  /opt/ddk/src/android14-6.1/include/linux/local_lock_internal.h \
  /opt/ddk/src/android14-6.1/include/linux/memory_hotplug.h \
    $(wildcard include/config/HAVE_ARCH_NODEDATA_EXTENSION) \
    $(wildcard include/config/ARCH_HAS_ADD_PAGES) \
    $(wildcard include/config/MEMORY_HOTREMOVE) \
  /opt/ddk/src/android14-6.1/include/linux/notifier.h \
    $(wildcard include/config/TREE_SRCU) \
  /opt/ddk/src/android14-6.1/include/linux/srcu.h \
    $(wildcard include/config/TINY_SRCU) \
    $(wildcard include/config/SRCU) \
  /opt/ddk/src/android14-6.1/include/linux/rcu_segcblist.h \
  /opt/ddk/src/android14-6.1/include/linux/srcutree.h \
  /opt/ddk/src/android14-6.1/include/linux/rcu_node_tree.h \
    $(wildcard include/config/RCU_FANOUT) \
    $(wildcard include/config/RCU_FANOUT_LEAF) \
  /opt/ddk/src/android14-6.1/include/linux/topology.h \
    $(wildcard include/config/USE_PERCPU_NUMA_NODE_ID) \
    $(wildcard include/config/SCHED_SMT) \
  /opt/ddk/src/android14-6.1/include/linux/arch_topology.h \
    $(wildcard include/config/ACPI_CPPC_LIB) \
    $(wildcard include/config/GENERIC_ARCH_TOPOLOGY) \
  /opt/ddk/src/android14-6.1/arch/arm64/include/asm/topology.h \
  /opt/ddk/src/android14-6.1/include/asm-generic/topology.h \
  /opt/ddk/src/android14-6.1/include/linux/ratelimit.h \
  /opt/ddk/src/android14-6.1/include/linux/fs.h \
    $(wildcard include/config/READ_ONLY_THP_FOR_FS) \
    $(wildcard include/config/FS_POSIX_ACL) \
    $(wildcard include/config/CGROUP_WRITEBACK) \
    $(wildcard include/config/IMA) \
    $(wildcard include/config/FILE_LOCKING) \
    $(wildcard include/config/FSNOTIFY) \
    $(wildcard include/config/FS_ENCRYPTION) \
    $(wildcard include/config/FS_VERITY) \
    $(wildcard include/config/UNICODE) \
    $(wildcard include/config/QUOTA) \
    $(wildcard include/config/FS_DAX) \
    $(wildcard include/config/BLOCK) \
  /opt/ddk/src/android14-6.1/include/linux/wait_bit.h \
  /opt/ddk/src/android14-6.1/include/linux/kdev_t.h \
  /opt/ddk/src/android14-6.1/include/uapi/linux/kdev_t.h \
  /opt/ddk/src/android14-6.1/include/linux/dcache.h \
  /opt/ddk/src/android14-6.1/include/linux/rculist_bl.h \
  /opt/ddk/src/android14-6.1/include/linux/list_bl.h \
  /opt/ddk/src/android14-6.1/include/linux/bit_spinlock.h \
  /opt/ddk/src/android14-6.1/include/linux/lockref.h \
    $(wildcard include/config/ARCH_USE_CMPXCHG_LOCKREF) \
  /opt/ddk/src/android14-6.1/include/linux/stringhash.h \
    $(wildcard include/config/DCACHE_WORD_ACCESS) \
  /opt/ddk/src/android14-6.1/include/linux/hash.h \
    $(wildcard include/config/HAVE_ARCH_HASH) \
  /opt/ddk/src/android14-6.1/include/linux/path.h \
  /opt/ddk/src/android14-6.1/include/linux/stat.h \
  /opt/ddk/src/android14-6.1/arch/arm64/include/asm/stat.h \
  arch/arm64/include/generated/uapi/asm/stat.h \
  /opt/ddk/src/android14-6.1/include/uapi/asm-generic/stat.h \
  /opt/ddk/src/android14-6.1/arch/arm64/include/asm/compat.h \
  /opt/ddk/src/android14-6.1/include/asm-generic/compat.h \
    $(wildcard include/config/COMPAT_FOR_U64_ALIGNMENT) \
  /opt/ddk/src/android14-6.1/include/linux/sched/task_stack.h \
    $(wildcard include/config/STACK_GROWSUP) \
    $(wildcard include/config/DEBUG_STACK_USAGE) \
  /opt/ddk/src/android14-6.1/include/uapi/linux/magic.h \
  /opt/ddk/src/android14-6.1/include/linux/kasan.h \
    $(wildcard include/config/KASAN_STACK) \
    $(wildcard include/config/KASAN_VMALLOC) \
  /opt/ddk/src/android14-6.1/include/uapi/linux/stat.h \
  /opt/ddk/src/android14-6.1/include/linux/list_lru.h \
    $(wildcard include/config/MEMCG_KMEM) \
  /opt/ddk/src/android14-6.1/include/linux/shrinker.h \
    $(wildcard include/config/SHRINKER_DEBUG) \
  /opt/ddk/src/android14-6.1/include/linux/xarray.h \
    $(wildcard include/config/XARRAY_MULTI) \
  /opt/ddk/src/android14-6.1/include/linux/sched/mm.h \
    $(wildcard include/config/ARCH_HAS_MEMBARRIER_CALLBACKS) \
  /opt/ddk/src/android14-6.1/include/linux/sync_core.h \
    $(wildcard include/config/ARCH_HAS_SYNC_CORE_BEFORE_USERMODE) \
  /opt/ddk/src/android14-6.1/include/linux/ioasid.h \
    $(wildcard include/config/IOASID) \
  /opt/ddk/src/android14-6.1/include/linux/radix-tree.h \
  /opt/ddk/src/android14-6.1/include/linux/semaphore.h \
  /opt/ddk/src/android14-6.1/include/linux/fcntl.h \
    $(wildcard include/config/ARCH_32BIT_OFF_T) \
  /opt/ddk/src/android14-6.1/include/uapi/linux/fcntl.h \
  /opt/ddk/src/android14-6.1/arch/arm64/include/uapi/asm/fcntl.h \
  /opt/ddk/src/android14-6.1/include/uapi/asm-generic/fcntl.h \
  /opt/ddk/src/android14-6.1/include/uapi/linux/openat2.h \
  /opt/ddk/src/android14-6.1/include/linux/migrate_mode.h \
  /opt/ddk/src/android14-6.1/include/linux/percpu-rwsem.h \
  /opt/ddk/src/android14-6.1/include/linux/rcuwait.h \
  /opt/ddk/src/android14-6.1/include/linux/sched/signal.h \
    $(wildcard include/config/SCHED_AUTOGROUP) \
    $(wildcard include/config/BSD_PROCESS_ACCT) \
    $(wildcard include/config/TASKSTATS) \
  /opt/ddk/src/android14-6.1/include/linux/signal.h \
    $(wildcard include/config/DYNAMIC_SIGFRAME) \
    $(wildcard include/config/PROC_FS) \
  /opt/ddk/src/android14-6.1/include/linux/sched/jobctl.h \
  /opt/ddk/src/android14-6.1/include/linux/sched/task.h \
    $(wildcard include/config/HAVE_EXIT_THREAD) \
    $(wildcard include/config/ARCH_WANTS_DYNAMIC_TASK_STRUCT) \
    $(wildcard include/config/HAVE_ARCH_THREAD_STRUCT_WHITELIST) \
  /opt/ddk/src/android14-6.1/include/linux/uaccess.h \
    $(wildcard include/config/ARCH_HAS_SUBPAGE_FAULTS) \
  /opt/ddk/src/android14-6.1/include/linux/fault-inject-usercopy.h \
    $(wildcard include/config/FAULT_INJECTION_USERCOPY) \
  /opt/ddk/src/android14-6.1/arch/arm64/include/asm/uaccess.h \
  /opt/ddk/src/android14-6.1/arch/arm64/include/asm/kernel-pgtable.h \
    $(wildcard include/config/RANDOMIZE_BASE) \
  /opt/ddk/src/android14-6.1/arch/arm64/include/asm/boot.h \
  /opt/ddk/src/android14-6.1/arch/arm64/include/asm/asm-extable.h \
  /opt/ddk/src/android14-6.1/arch/arm64/include/asm/mte.h \
  /opt/ddk/src/android14-6.1/arch/arm64/include/asm/extable.h \
    $(wildcard include/config/BPF_JIT) \
  /opt/ddk/src/android14-6.1/include/asm-generic/access_ok.h \
    $(wildcard include/config/ALTERNATE_USER_ADDRESS_SPACE) \
  /opt/ddk/src/android14-6.1/include/linux/rcu_sync.h \
  /opt/ddk/src/android14-6.1/include/linux/delayed_call.h \
  /opt/ddk/src/android14-6.1/include/linux/uuid.h \
  /opt/ddk/src/android14-6.1/include/uapi/linux/uuid.h \
  /opt/ddk/src/android14-6.1/include/linux/errseq.h \
  /opt/ddk/src/android14-6.1/include/linux/ioprio.h \
  /opt/ddk/src/android14-6.1/include/linux/sched/rt.h \
  /opt/ddk/src/android14-6.1/include/linux/iocontext.h \
    $(wildcard include/config/BLK_ICQ) \
  /opt/ddk/src/android14-6.1/include/uapi/linux/ioprio.h \
  /opt/ddk/src/android14-6.1/include/linux/fs_types.h \
  /opt/ddk/src/android14-6.1/include/linux/mount.h \
  /opt/ddk/src/android14-6.1/include/linux/mnt_idmapping.h \
  /opt/ddk/src/android14-6.1/include/linux/slab.h \
    $(wildcard include/config/DEBUG_SLAB) \
    $(wildcard include/config/FAILSLAB) \
    $(wildcard include/config/KFENCE) \
    $(wildcard include/config/SLAB) \
    $(wildcard include/config/SLUB) \
    $(wildcard include/config/SLOB) \
  /opt/ddk/src/android14-6.1/include/linux/percpu-refcount.h \
  /opt/ddk/src/android14-6.1/include/uapi/linux/fs.h \
  /opt/ddk/src/android14-6.1/include/linux/quota.h \
    $(wildcard include/config/QUOTA_NETLINK_INTERFACE) \
  /opt/ddk/src/android14-6.1/include/uapi/linux/dqblk_xfs.h \
  /opt/ddk/src/android14-6.1/include/linux/dqblk_v1.h \
  /opt/ddk/src/android14-6.1/include/linux/dqblk_v2.h \
  /opt/ddk/src/android14-6.1/include/linux/dqblk_qtree.h \
  /opt/ddk/src/android14-6.1/include/linux/projid.h \
  /opt/ddk/src/android14-6.1/include/uapi/linux/quota.h \
  /opt/ddk/src/android14-6.1/include/linux/nfs_fs_i.h \
  /opt/ddk/src/android14-6.1/include/linux/mm.h \
    $(wildcard include/config/HAVE_ARCH_MMAP_RND_BITS) \
    $(wildcard include/config/HAVE_ARCH_MMAP_RND_COMPAT_BITS) \
    $(wildcard include/config/MEM_SOFT_DIRTY) \
    $(wildcard include/config/ARCH_USES_HIGH_VMA_FLAGS) \
    $(wildcard include/config/ARCH_HAS_PKEYS) \
    $(wildcard include/config/PPC) \
    $(wildcard include/config/X86) \
    $(wildcard include/config/PARISC) \
    $(wildcard include/config/IA64) \
    $(wildcard include/config/SPARC64) \
    $(wildcard include/config/HAVE_ARCH_USERFAULTFD_MINOR) \
    $(wildcard include/config/SHMEM) \
    $(wildcard include/config/MIGRATION) \
    $(wildcard include/config/ARCH_HAS_PTE_SPECIAL) \
    $(wildcard include/config/ARCH_HAS_PTE_DEVMAP) \
    $(wildcard include/config/DEBUG_VM_RB) \
    $(wildcard include/config/HAVE_FAST_GUP) \
    $(wildcard include/config/PAGE_POISONING) \
    $(wildcard include/config/INIT_ON_ALLOC_DEFAULT_ON) \
    $(wildcard include/config/INIT_ON_FREE_DEFAULT_ON) \
    $(wildcard include/config/DEBUG_PAGEALLOC) \
    $(wildcard include/config/HUGETLBFS) \
    $(wildcard include/config/MAPPING_DIRTY_HELPERS) \
    $(wildcard include/config/ANON_VMA_NAME) \
  /opt/ddk/src/android14-6.1/include/linux/mmap_lock.h \
  /opt/ddk/src/android14-6.1/include/linux/tracepoint-defs.h \
    $(wildcard include/config/TRACEPOINTS) \
  /opt/ddk/src/android14-6.1/include/linux/range.h \
  /opt/ddk/src/android14-6.1/include/linux/page_ext.h \
    $(wildcard include/config/PAGE_PINNER) \
  /opt/ddk/src/android14-6.1/include/linux/stacktrace.h \
    $(wildcard include/config/ARCH_STACKWALK) \
    $(wildcard include/config/STACKTRACE) \
    $(wildcard include/config/HAVE_RELIABLE_STACKTRACE) \
  /opt/ddk/src/android14-6.1/include/linux/stackdepot.h \
    $(wildcard include/config/STACKDEPOT) \
  /opt/ddk/src/android14-6.1/include/linux/page_ref.h \
    $(wildcard include/config/DEBUG_PAGE_REF) \
  /opt/ddk/src/android14-6.1/include/linux/pgtable.h \
    $(wildcard include/config/HIGHPTE) \
    $(wildcard include/config/ARCH_HAS_NONLEAF_PMD_YOUNG) \
    $(wildcard include/config/GUP_GET_PTE_LOW_HIGH) \
    $(wildcard include/config/HAVE_ARCH_TRANSPARENT_HUGEPAGE_PUD) \
    $(wildcard include/config/HAVE_ARCH_SOFT_DIRTY) \
    $(wildcard include/config/ARCH_ENABLE_THP_MIGRATION) \
    $(wildcard include/config/HAVE_ARCH_HUGE_VMAP) \
    $(wildcard include/config/X86_ESPFIX64) \
  /opt/ddk/src/android14-6.1/arch/arm64/include/asm/pgtable.h \
    $(wildcard include/config/PAGE_TABLE_CHECK) \
  /opt/ddk/src/android14-6.1/arch/arm64/include/asm/proc-fns.h \
  /opt/ddk/src/android14-6.1/arch/arm64/include/asm/pgtable-prot.h \
    $(wildcard include/config/ARM64_BTI_KERNEL) \
  /opt/ddk/src/android14-6.1/arch/arm64/include/asm/tlbflush.h \
    $(wildcard include/config/ARM64_WORKAROUND_REPEAT_TLBI) \
  /opt/ddk/src/android14-6.1/arch/arm64/include/asm/fixmap.h \
    $(wildcard include/config/ACPI_APEI_GHES) \
    $(wildcard include/config/ARM_SDE_INTERFACE) \
    $(wildcard include/config/UNMAP_KERNEL_AT_EL0) \
    $(wildcard include/config/RELOCATABLE) \
  /opt/ddk/src/android14-6.1/include/asm-generic/fixmap.h \
  /opt/ddk/src/android14-6.1/include/linux/page_table_check.h \
  /opt/ddk/src/android14-6.1/arch/arm64/include/asm/android_erratum_pgtable.h \
    $(wildcard include/config/ANDROID_ARM64_WORKAROUND_DMA_BEYOND_POC) \
  /opt/ddk/src/android14-6.1/include/asm-generic/pgtable_uffd.h \
    $(wildcard include/config/HAVE_ARCH_USERFAULTFD_WP) \
  /opt/ddk/src/android14-6.1/include/linux/pgsize_migration_inline.h \
  /opt/ddk/src/android14-6.1/include/linux/page_pinner.h \
  /opt/ddk/src/android14-6.1/include/linux/memremap.h \
    $(wildcard include/config/DEVICE_PRIVATE) \
    $(wildcard include/config/PCI_P2PDMA) \
  /opt/ddk/src/android14-6.1/include/linux/ioport.h \
  /opt/ddk/src/android14-6.1/include/linux/huge_mm.h \
  /opt/ddk/src/android14-6.1/include/linux/sched/coredump.h \
    $(wildcard include/config/CORE_DUMP_DEFAULT_ELF_HEADERS) \
  /opt/ddk/src/android14-6.1/include/linux/vmstat.h \
    $(wildcard include/config/VM_EVENT_COUNTERS) \
    $(wildcard include/config/DEBUG_TLBFLUSH) \
    $(wildcard include/config/PER_VMA_LOCK_STATS) \
  /opt/ddk/src/android14-6.1/include/linux/vm_event_item.h \
    $(wildcard include/config/MEMORY_BALLOON) \
    $(wildcard include/config/BALLOON_COMPACTION) \
    $(wildcard include/config/ZSWAP) \
  /opt/ddk/src/android14-6.1/include/linux/ptrace.h \
  /opt/ddk/src/android14-6.1/include/linux/pid_namespace.h \
    $(wildcard include/config/PID_NS) \
  /opt/ddk/src/android14-6.1/include/linux/nsproxy.h \
  /opt/ddk/src/android14-6.1/include/linux/ns_common.h \
  /opt/ddk/src/android14-6.1/include/linux/idr.h \
  /opt/ddk/src/android14-6.1/include/uapi/linux/ptrace.h \
  include/generated/uapi/linux/version.h \
  /opt/ddk/src/android14-6.1/include/linux/vmalloc.h \
    $(wildcard include/config/HAVE_ARCH_HUGE_VMALLOC) \
  /opt/ddk/src/android14-6.1/arch/arm64/include/asm/vmalloc.h \
    $(wildcard include/config/PTDUMP_DEBUGFS) \
  /opt/ddk/src/android14-6.1/security/selinux/include/security.h \
    $(wildcard include/config/SECURITY_SELINUX_DISABLE) \
    $(wildcard include/config/SECURITY_SELINUX_DEVELOP) \
    $(wildcard include/config/NETLABEL) \
  /opt/ddk/src/android14-6.1/include/linux/delay.h \
  arch/arm64/include/generated/asm/delay.h \
  /opt/ddk/src/android14-6.1/include/asm-generic/delay.h \
  security/selinux/flask.h \
  /opt/ddk/src/android14-6.1/security/selinux/include/policycap.h \
  /opt/ddk/src/android14-6.1/security/selinux/include/objsec.h \
  /opt/ddk/src/android14-6.1/include/linux/binfmts.h \
    $(wildcard include/config/COREDUMP) \
  /opt/ddk/src/android14-6.1/arch/arm64/include/asm/exec.h \
  /opt/ddk/src/android14-6.1/include/uapi/linux/binfmts.h \
  /opt/ddk/src/android14-6.1/include/linux/in.h \
  /opt/ddk/src/android14-6.1/include/uapi/linux/in.h \
  /opt/ddk/src/android14-6.1/include/uapi/linux/libc-compat.h \
  /opt/ddk/src/android14-6.1/include/linux/socket.h \
  arch/arm64/include/generated/uapi/asm/socket.h \
  /opt/ddk/src/android14-6.1/include/uapi/asm-generic/socket.h \
  arch/arm64/include/generated/uapi/asm/sockios.h \
  /opt/ddk/src/android14-6.1/include/uapi/asm-generic/sockios.h \
  /opt/ddk/src/android14-6.1/include/uapi/linux/sockios.h \
  /opt/ddk/src/android14-6.1/include/linux/uio.h \
    $(wildcard include/config/ARCH_HAS_COPY_MC) \
  /opt/ddk/src/android14-6.1/include/uapi/linux/uio.h \
  /opt/ddk/src/android14-6.1/include/uapi/linux/socket.h \
  /opt/ddk/src/android14-6.1/include/linux/lsm_hooks.h \
    $(wildcard include/config/LSM) \
    $(wildcard include/config/SECURITY_WRITABLE_HOOKS) \
  /opt/ddk/src/android14-6.1/include/linux/security.h \
    $(wildcard include/config/SECURITY_NETWORK) \
    $(wildcard include/config/SECURITY_INFINIBAND) \
    $(wildcard include/config/SECURITY_NETWORK_XFRM) \
    $(wildcard include/config/SECURITY_PATH) \
    $(wildcard include/config/SECURITYFS) \
  /opt/ddk/src/android14-6.1/include/linux/kernel_read_file.h \
  /opt/ddk/src/android14-6.1/include/linux/file.h \
  /opt/ddk/src/android14-6.1/include/linux/lsm_hook_defs.h \
  /opt/ddk/src/android14-6.1/include/linux/msg.h \
  /opt/ddk/src/android14-6.1/include/uapi/linux/msg.h \
  arch/arm64/include/generated/uapi/asm/msgbuf.h \
  /opt/ddk/src/android14-6.1/include/uapi/asm-generic/msgbuf.h \
  /opt/ddk/src/android14-6.1/include/net/net_namespace.h \
    $(wildcard include/config/NF_CONNTRACK) \
    $(wildcard include/config/NF_FLOW_TABLE) \
    $(wildcard include/config/UNIX) \
    $(wildcard include/config/IPV6) \
    $(wildcard include/config/IEEE802154_6LOWPAN) \
    $(wildcard include/config/IP_SCTP) \
    $(wildcard include/config/NETFILTER) \
    $(wildcard include/config/NF_TABLES) \
    $(wildcard include/config/WEXT_CORE) \
    $(wildcard include/config/XFRM) \
    $(wildcard include/config/IP_VS) \
    $(wildcard include/config/MPLS) \
    $(wildcard include/config/CAN) \
    $(wildcard include/config/XDP_SOCKETS) \
    $(wildcard include/config/MCTP) \
    $(wildcard include/config/CRYPTO_USER) \
    $(wildcard include/config/SMC) \
    $(wildcard include/config/NETFILTER_FAMILY_BRIDGE) \
    $(wildcard include/config/NET_NS) \
    $(wildcard include/config/NET_NS_REFCNT_TRACKER) \
  /opt/ddk/src/android14-6.1/include/net/flow.h \
  /opt/ddk/src/android14-6.1/include/linux/in6.h \
  /opt/ddk/src/android14-6.1/include/uapi/linux/in6.h \
  /opt/ddk/src/android14-6.1/include/net/flow_dissector.h \
  /opt/ddk/src/android14-6.1/include/linux/siphash.h \
    $(wildcard include/config/HAVE_EFFICIENT_UNALIGNED_ACCESS) \
  /opt/ddk/src/android14-6.1/include/uapi/linux/if_ether.h \
  /opt/ddk/src/android14-6.1/include/net/netns/core.h \
  /opt/ddk/src/android14-6.1/include/net/netns/mib.h \
    $(wildcard include/config/XFRM_STATISTICS) \
    $(wildcard include/config/TLS) \
    $(wildcard include/config/MPTCP) \
  /opt/ddk/src/android14-6.1/include/net/snmp.h \
  /opt/ddk/src/android14-6.1/include/uapi/linux/snmp.h \
  /opt/ddk/src/android14-6.1/include/linux/u64_stats_sync.h \
  arch/arm64/include/generated/asm/local64.h \
  /opt/ddk/src/android14-6.1/include/asm-generic/local64.h \
  arch/arm64/include/generated/asm/local.h \
  /opt/ddk/src/android14-6.1/include/asm-generic/local.h \
  /opt/ddk/src/android14-6.1/include/net/netns/unix.h \
  /opt/ddk/src/android14-6.1/include/net/netns/packet.h \
  /opt/ddk/src/android14-6.1/include/net/netns/ipv4.h \
    $(wildcard include/config/IP_MULTIPLE_TABLES) \
    $(wildcard include/config/IP_ROUTE_CLASSID) \
    $(wildcard include/config/NET_L3_MASTER_DEV) \
    $(wildcard include/config/IP_MROUTE) \
    $(wildcard include/config/IP_MROUTE_MULTIPLE_TABLES) \
    $(wildcard include/config/IP_ROUTE_MULTIPATH) \
  /opt/ddk/src/android14-6.1/include/net/inet_frag.h \
  /opt/ddk/src/android14-6.1/include/net/netns/ipv6.h \
    $(wildcard include/config/IPV6_MULTIPLE_TABLES) \
    $(wildcard include/config/IPV6_SUBTREES) \
    $(wildcard include/config/IPV6_MROUTE) \
    $(wildcard include/config/IPV6_MROUTE_MULTIPLE_TABLES) \
    $(wildcard include/config/NF_DEFRAG_IPV6) \
  /opt/ddk/src/android14-6.1/include/net/dst_ops.h \
  /opt/ddk/src/android14-6.1/include/uapi/linux/icmpv6.h \
  /opt/ddk/src/android14-6.1/include/net/netns/nexthop.h \
  /opt/ddk/src/android14-6.1/include/net/netns/ieee802154_6lowpan.h \
  /opt/ddk/src/android14-6.1/include/net/netns/sctp.h \
  /opt/ddk/src/android14-6.1/include/net/netns/netfilter.h \
    $(wildcard include/config/NETFILTER_FAMILY_ARP) \
    $(wildcard include/config/NF_DEFRAG_IPV4) \
  /opt/ddk/src/android14-6.1/include/linux/netfilter_defs.h \
  /opt/ddk/src/android14-6.1/include/uapi/linux/netfilter.h \
  /opt/ddk/src/android14-6.1/include/net/netns/conntrack.h \
    $(wildcard include/config/NF_CT_PROTO_DCCP) \
    $(wildcard include/config/NF_CT_PROTO_SCTP) \
    $(wildcard include/config/NF_CT_PROTO_GRE) \
    $(wildcard include/config/NF_CONNTRACK_EVENTS) \
    $(wildcard include/config/NF_CONNTRACK_LABELS) \
  /opt/ddk/src/android14-6.1/include/linux/netfilter/nf_conntrack_tcp.h \
  /opt/ddk/src/android14-6.1/include/uapi/linux/netfilter/nf_conntrack_tcp.h \
  /opt/ddk/src/android14-6.1/include/linux/netfilter/nf_conntrack_dccp.h \
  /opt/ddk/src/android14-6.1/include/uapi/linux/netfilter/nf_conntrack_tuple_common.h \
  /opt/ddk/src/android14-6.1/include/linux/netfilter/nf_conntrack_common.h \
  /opt/ddk/src/android14-6.1/include/uapi/linux/netfilter/nf_conntrack_common.h \
  /opt/ddk/src/android14-6.1/include/linux/netfilter/nf_conntrack_sctp.h \
  /opt/ddk/src/android14-6.1/include/uapi/linux/netfilter/nf_conntrack_sctp.h \
  /opt/ddk/src/android14-6.1/include/net/netns/nftables.h \
  /opt/ddk/src/android14-6.1/include/net/netns/xfrm.h \
  /opt/ddk/src/android14-6.1/include/uapi/linux/xfrm.h \
  /opt/ddk/src/android14-6.1/include/net/netns/mpls.h \
  /opt/ddk/src/android14-6.1/include/net/netns/can.h \
  /opt/ddk/src/android14-6.1/include/net/netns/xdp.h \
  /opt/ddk/src/android14-6.1/include/net/netns/smc.h \
  /opt/ddk/src/android14-6.1/include/net/netns/bpf.h \
  /opt/ddk/src/android14-6.1/include/net/netns/mctp.h \
  /opt/ddk/src/android14-6.1/include/net/net_trackers.h \
    $(wildcard include/config/NET_DEV_REFCNT_TRACKER) \
  /opt/ddk/src/android14-6.1/include/linux/ref_tracker.h \
    $(wildcard include/config/REF_TRACKER) \
  /opt/ddk/src/android14-6.1/include/linux/skbuff.h \
    $(wildcard include/config/BRIDGE_NETFILTER) \
    $(wildcard include/config/NET_TC_SKB_EXT) \
    $(wildcard include/config/DEBUG_KMAP_LOCAL_FORCE_MAP) \
    $(wildcard include/config/NET_SOCK_MSG) \
    $(wildcard include/config/SKB_EXTENSIONS) \
    $(wildcard include/config/NET_CLS_ACT) \
    $(wildcard include/config/IPV6_NDISC_NODETYPE) \
    $(wildcard include/config/NET_SWITCHDEV) \
    $(wildcard include/config/NET_REDIRECT) \
    $(wildcard include/config/NETFILTER_SKIP_EGRESS) \
    $(wildcard include/config/TLS_DEVICE) \
    $(wildcard include/config/NET_SCHED) \
    $(wildcard include/config/NET_RX_BUSY_POLL) \
    $(wildcard include/config/XPS) \
    $(wildcard include/config/NETWORK_SECMARK) \
    $(wildcard include/config/DEBUG_NET) \
    $(wildcard include/config/PAGE_POOL) \
    $(wildcard include/config/NETWORK_PHY_TIMESTAMPING) \
    $(wildcard include/config/MCTP_FLOWS) \
    $(wildcard include/config/NETFILTER_XT_TARGET_TRACE) \
  /opt/ddk/src/android14-6.1/include/linux/bvec.h \
  /opt/ddk/src/android14-6.1/include/linux/highmem.h \
  /opt/ddk/src/android14-6.1/include/linux/cacheflush.h \
  /opt/ddk/src/android14-6.1/arch/arm64/include/asm/cacheflush.h \
  /opt/ddk/src/android14-6.1/include/linux/kgdb.h \
    $(wildcard include/config/HAVE_ARCH_KGDB) \
    $(wildcard include/config/KGDB) \
    $(wildcard include/config/SERIAL_KGDB_NMI) \
    $(wildcard include/config/KGDB_HONOUR_BLOCKLIST) \
  /opt/ddk/src/android14-6.1/include/linux/kprobes.h \
    $(wildcard include/config/KRETPROBE_ON_RETHOOK) \
    $(wildcard include/config/KPROBES_SANITY_TEST) \
    $(wildcard include/config/OPTPROBES) \
    $(wildcard include/config/KPROBES_ON_FTRACE) \
  /opt/ddk/src/android14-6.1/include/linux/ftrace.h \
    $(wildcard include/config/FUNCTION_TRACER) \
    $(wildcard include/config/DYNAMIC_FTRACE) \
    $(wildcard include/config/HAVE_DYNAMIC_FTRACE_WITH_ARGS) \
    $(wildcard include/config/DYNAMIC_FTRACE_WITH_REGS) \
    $(wildcard include/config/DYNAMIC_FTRACE_WITH_DIRECT_CALLS) \
    $(wildcard include/config/HAVE_DYNAMIC_FTRACE_WITH_DIRECT_CALLS) \
    $(wildcard include/config/STACK_TRACER) \
    $(wildcard include/config/FRAME_POINTER) \
    $(wildcard include/config/FUNCTION_PROFILER) \
    $(wildcard include/config/FTRACE_SYSCALLS) \
  /opt/ddk/src/android14-6.1/include/linux/trace_recursion.h \
    $(wildcard include/config/FTRACE_RECORD_RECURSION) \
  /opt/ddk/src/android14-6.1/include/linux/interrupt.h \
    $(wildcard include/config/IRQ_FORCED_THREADING) \
    $(wildcard include/config/RT_SOFTIRQ_AWARE_SCHED) \
    $(wildcard include/config/GENERIC_IRQ_PROBE) \
    $(wildcard include/config/IRQ_TIMINGS) \
  /opt/ddk/src/android14-6.1/include/linux/irqreturn.h \
  /opt/ddk/src/android14-6.1/include/linux/hardirq.h \
  /opt/ddk/src/android14-6.1/include/linux/context_tracking_state.h \
    $(wildcard include/config/CONTEXT_TRACKING_USER) \
    $(wildcard include/config/CONTEXT_TRACKING) \
  /opt/ddk/src/android14-6.1/include/linux/ftrace_irq.h \
    $(wildcard include/config/HWLAT_TRACER) \
    $(wildcard include/config/OSNOISE_TRACER) \
  /opt/ddk/src/android14-6.1/include/linux/vtime.h \
    $(wildcard include/config/VIRT_CPU_ACCOUNTING) \
    $(wildcard include/config/IRQ_TIME_ACCOUNTING) \
  /opt/ddk/src/android14-6.1/arch/arm64/include/asm/hardirq.h \
  /opt/ddk/src/android14-6.1/arch/arm64/include/asm/irq.h \
  /opt/ddk/src/android14-6.1/include/asm-generic/irq.h \
  /opt/ddk/src/android14-6.1/arch/arm64/include/asm/kvm_arm.h \
  /opt/ddk/src/android14-6.1/include/asm-generic/hardirq.h \
  /opt/ddk/src/android14-6.1/include/linux/irq.h \
    $(wildcard include/config/GENERIC_IRQ_EFFECTIVE_AFF_MASK) \
    $(wildcard include/config/GENERIC_IRQ_IPI) \
    $(wildcard include/config/IRQ_DOMAIN_HIERARCHY) \
    $(wildcard include/config/DEPRECATED_IRQ_CPU_ONOFFLINE) \
    $(wildcard include/config/GENERIC_IRQ_MIGRATION) \
    $(wildcard include/config/GENERIC_PENDING_IRQ) \
    $(wildcard include/config/HARDIRQS_SW_RESEND) \
    $(wildcard include/config/GENERIC_IRQ_LEGACY) \
    $(wildcard include/config/GENERIC_IRQ_MULTI_HANDLER) \
  /opt/ddk/src/android14-6.1/include/linux/irqhandler.h \
  /opt/ddk/src/android14-6.1/include/linux/io.h \
    $(wildcard include/config/HAS_IOPORT_MAP) \
    $(wildcard include/config/PCI) \
  /opt/ddk/src/android14-6.1/arch/arm64/include/asm/io.h \
  arch/arm64/include/generated/asm/early_ioremap.h \
  /opt/ddk/src/android14-6.1/include/asm-generic/early_ioremap.h \
    $(wildcard include/config/GENERIC_EARLY_IOREMAP) \
  /opt/ddk/src/android14-6.1/include/asm-generic/io.h \
    $(wildcard include/config/GENERIC_IOMAP) \
    $(wildcard include/config/TRACE_MMIO_ACCESS) \
    $(wildcard include/config/GENERIC_IOREMAP) \
  /opt/ddk/src/android14-6.1/include/asm-generic/pci_iomap.h \
    $(wildcard include/config/NO_GENERIC_PCI_IOPORT_MAP) \
    $(wildcard include/config/GENERIC_PCI_IOMAP) \
  /opt/ddk/src/android14-6.1/include/linux/logic_pio.h \
    $(wildcard include/config/INDIRECT_PIO) \
  /opt/ddk/src/android14-6.1/include/linux/fwnode.h \
  arch/arm64/include/generated/asm/irq_regs.h \
  /opt/ddk/src/android14-6.1/include/asm-generic/irq_regs.h \
  /opt/ddk/src/android14-6.1/include/linux/irqdesc.h \
    $(wildcard include/config/GENERIC_IRQ_DEBUGFS) \
    $(wildcard include/config/SPARSE_IRQ) \
    $(wildcard include/config/IRQ_DOMAIN) \
  /opt/ddk/src/android14-6.1/include/linux/kobject.h \
    $(wildcard include/config/UEVENT_HELPER) \
    $(wildcard include/config/DEBUG_KOBJECT_RELEASE) \
  /opt/ddk/src/android14-6.1/include/linux/sysfs.h \
  /opt/ddk/src/android14-6.1/include/linux/kernfs.h \
    $(wildcard include/config/KERNFS) \
  /opt/ddk/src/android14-6.1/include/linux/kobject_ns.h \
  arch/arm64/include/generated/asm/hw_irq.h \
  /opt/ddk/src/android14-6.1/include/asm-generic/hw_irq.h \
  /opt/ddk/src/android14-6.1/include/linux/trace_clock.h \
  arch/arm64/include/generated/asm/trace_clock.h \
  /opt/ddk/src/android14-6.1/include/asm-generic/trace_clock.h \
  /opt/ddk/src/android14-6.1/include/linux/kallsyms.h \
    $(wildcard include/config/KALLSYMS_ALL) \
    $(wildcard include/config/KALLSYMS) \
  /opt/ddk/src/android14-6.1/include/linux/buildid.h \
    $(wildcard include/config/STACKTRACE_BUILD_ID) \
    $(wildcard include/config/CRASH_CORE) \
  /opt/ddk/src/android14-6.1/include/linux/module.h \
    $(wildcard include/config/MODULES_TREE_LOOKUP) \
    $(wildcard include/config/ARCH_USES_CFI_TRAPS) \
    $(wildcard include/config/ARCH_WANTS_MODULES_DATA_IN_VMALLOC) \
    $(wildcard include/config/BPF_EVENTS) \
    $(wildcard include/config/DEBUG_INFO_BTF_MODULES) \
    $(wildcard include/config/EVENT_TRACING) \
    $(wildcard include/config/MODULE_UNLOAD) \
    $(wildcard include/config/MITIGATION_ITS) \
    $(wildcard include/config/CONSTRUCTORS) \
    $(wildcard include/config/FUNCTION_ERROR_INJECTION) \
    $(wildcard include/config/RETPOLINE) \
    $(wildcard include/config/MODULE_SIG) \
  /opt/ddk/src/android14-6.1/include/linux/kmod.h \
  /opt/ddk/src/android14-6.1/include/linux/umh.h \
  /opt/ddk/src/android14-6.1/include/linux/elf.h \
    $(wildcard include/config/ARCH_USE_GNU_PROPERTY) \
    $(wildcard include/config/ARCH_HAVE_ELF_PROT) \
  /opt/ddk/src/android14-6.1/arch/arm64/include/asm/elf.h \
    $(wildcard include/config/COMPAT_VDSO) \
  arch/arm64/include/generated/asm/user.h \
  /opt/ddk/src/android14-6.1/include/asm-generic/user.h \
  /opt/ddk/src/android14-6.1/include/uapi/linux/elf.h \
  /opt/ddk/src/android14-6.1/include/uapi/linux/elf-em.h \
  /opt/ddk/src/android14-6.1/include/linux/moduleparam.h \
    $(wildcard include/config/ALPHA) \
    $(wildcard include/config/PPC64) \
  /opt/ddk/src/android14-6.1/include/linux/rbtree_latch.h \
  /opt/ddk/src/android14-6.1/include/linux/error-injection.h \
  /opt/ddk/src/android14-6.1/include/asm-generic/error-injection.h \
  /opt/ddk/src/android14-6.1/arch/arm64/include/asm/module.h \
    $(wildcard include/config/ARM64_MODULE_PLTS) \
    $(wildcard include/config/HAVE_MOD_ARCH_SPECIFIC) \
    $(wildcard include/config/ARM64_ERRATUM_843419) \
  /opt/ddk/src/android14-6.1/include/asm-generic/module.h \
    $(wildcard include/config/MODULES_USE_ELF_REL) \
    $(wildcard include/config/MODULES_USE_ELF_RELA) \
  /opt/ddk/src/android14-6.1/arch/arm64/include/asm/ftrace.h \
  /opt/ddk/src/android14-6.1/include/linux/compat.h \
    $(wildcard include/config/ARCH_HAS_SYSCALL_WRAPPER) \
    $(wildcard include/config/X86_X32_ABI) \
    $(wildcard include/config/COMPAT_OLD_SIGACTION) \
    $(wildcard include/config/ODD_RT_SIGACTION) \
  /opt/ddk/src/android14-6.1/include/uapi/linux/if.h \
  /opt/ddk/src/android14-6.1/include/uapi/linux/hdlc/ioctl.h \
  /opt/ddk/src/android14-6.1/include/uapi/linux/aio_abi.h \
  /opt/ddk/src/android14-6.1/arch/arm64/include/asm/syscall_wrapper.h \
  /opt/ddk/src/android14-6.1/include/linux/freelist.h \
  /opt/ddk/src/android14-6.1/include/linux/rethook.h \
  /opt/ddk/src/android14-6.1/arch/arm64/include/asm/kprobes.h \
  /opt/ddk/src/android14-6.1/include/asm-generic/kprobes.h \
  /opt/ddk/src/android14-6.1/arch/arm64/include/asm/kgdb.h \
  /opt/ddk/src/android14-6.1/include/asm-generic/cacheflush.h \
  /opt/ddk/src/android14-6.1/include/linux/kmsan.h \
  /opt/ddk/src/android14-6.1/include/linux/dma-direction.h \
  /opt/ddk/src/android14-6.1/include/linux/highmem-internal.h \
  /opt/ddk/src/android14-6.1/include/linux/net.h \
  /opt/ddk/src/android14-6.1/include/linux/sockptr.h \
  /opt/ddk/src/android14-6.1/include/uapi/linux/net.h \
  /opt/ddk/src/android14-6.1/include/linux/textsearch.h \
  /opt/ddk/src/android14-6.1/include/net/checksum.h \
  /opt/ddk/src/android14-6.1/arch/arm64/include/asm/checksum.h \
  /opt/ddk/src/android14-6.1/include/asm-generic/checksum.h \
  /opt/ddk/src/android14-6.1/include/linux/dma-mapping.h \
    $(wildcard include/config/DMA_API_DEBUG) \
    $(wildcard include/config/HAS_DMA) \
    $(wildcard include/config/NEED_DMA_MAP_STATE) \
  /opt/ddk/src/android14-6.1/include/linux/device.h \
    $(wildcard include/config/GENERIC_MSI_IRQ_DOMAIN) \
    $(wildcard include/config/GENERIC_MSI_IRQ) \
    $(wildcard include/config/ENERGY_MODEL) \
    $(wildcard include/config/PINCTRL) \
    $(wildcard include/config/DMA_OPS) \
    $(wildcard include/config/DMA_DECLARE_COHERENT) \
    $(wildcard include/config/DMA_CMA) \
    $(wildcard include/config/SWIOTLB) \
    $(wildcard include/config/ARCH_HAS_SYNC_DMA_FOR_DEVICE) \
    $(wildcard include/config/ARCH_HAS_SYNC_DMA_FOR_CPU) \
    $(wildcard include/config/ARCH_HAS_SYNC_DMA_FOR_CPU_ALL) \
    $(wildcard include/config/DMA_OPS_BYPASS) \
    $(wildcard include/config/PM) \
    $(wildcard include/config/OF) \
    $(wildcard include/config/DEVTMPFS) \
    $(wildcard include/config/SYSFS_DEPRECATED) \
  /opt/ddk/src/android14-6.1/include/linux/dev_printk.h \
  /opt/ddk/src/android14-6.1/include/linux/energy_model.h \
  /opt/ddk/src/android14-6.1/include/linux/sched/cpufreq.h \
    $(wildcard include/config/CPU_FREQ) \
  /opt/ddk/src/android14-6.1/include/linux/sched/topology.h \
    $(wildcard include/config/SCHED_DEBUG) \
    $(wildcard include/config/SCHED_CLUSTER) \
    $(wildcard include/config/SCHED_MC) \
    $(wildcard include/config/CPU_FREQ_GOV_SCHEDUTIL) \
  /opt/ddk/src/android14-6.1/include/linux/sched/idle.h \
  /opt/ddk/src/android14-6.1/include/linux/sched/sd_flags.h \
  /opt/ddk/src/android14-6.1/include/linux/klist.h \
  /opt/ddk/src/android14-6.1/include/linux/pm.h \
    $(wildcard include/config/VT_CONSOLE_SLEEP) \
    $(wildcard include/config/CXL_SUSPEND) \
    $(wildcard include/config/PM_CLK) \
    $(wildcard include/config/PM_GENERIC_DOMAINS) \
  /opt/ddk/src/android14-6.1/include/linux/device/bus.h \
    $(wildcard include/config/ACPI) \
  /opt/ddk/src/android14-6.1/include/linux/device/class.h \
  /opt/ddk/src/android14-6.1/include/linux/device/driver.h \
  /opt/ddk/src/android14-6.1/arch/arm64/include/asm/device.h \
  /opt/ddk/src/android14-6.1/include/linux/pm_wakeup.h \
  /opt/ddk/src/android14-6.1/include/linux/scatterlist.h \
    $(wildcard include/config/NEED_SG_DMA_LENGTH) \
    $(wildcard include/config/DEBUG_SG) \
    $(wildcard include/config/SGL_ALLOC) \
    $(wildcard include/config/ARCH_NO_SG_CHAIN) \
    $(wildcard include/config/SG_POOL) \
  /opt/ddk/src/android14-6.1/include/linux/mem_encrypt.h \
    $(wildcard include/config/ARCH_HAS_MEM_ENCRYPT) \
  /opt/ddk/src/android14-6.1/arch/arm64/include/asm/mem_encrypt.h \
  /opt/ddk/src/android14-6.1/include/linux/netdev_features.h \
  /opt/ddk/src/android14-6.1/include/linux/sched/clock.h \
    $(wildcard include/config/HAVE_UNSTABLE_SCHED_CLOCK) \
  /opt/ddk/src/android14-6.1/include/linux/splice.h \
  /opt/ddk/src/android14-6.1/include/linux/pipe_fs_i.h \
  /opt/ddk/src/android14-6.1/include/uapi/linux/if_packet.h \
  /opt/ddk/src/android14-6.1/include/net/page_pool.h \
    $(wildcard include/config/PAGE_POOL_STATS) \
  /opt/ddk/src/android14-6.1/include/linux/ptr_ring.h \
  /opt/ddk/src/android14-6.1/include/net/net_debug.h \
  /opt/ddk/src/android14-6.1/include/net/dropreason.h \
  /opt/ddk/src/android14-6.1/include/linux/seq_file_net.h \
  /opt/ddk/src/android14-6.1/include/linux/seq_file.h \
  /opt/ddk/src/android14-6.1/include/linux/string_helpers.h \
  /opt/ddk/src/android14-6.1/include/linux/ctype.h \
  /opt/ddk/src/android14-6.1/security/selinux/include/avc.h \
    $(wildcard include/config/SECURITY_SELINUX_AVC_STATS) \
  /opt/ddk/src/android14-6.1/include/linux/audit.h \
    $(wildcard include/config/AUDIT_COMPAT_GENERIC) \
  /opt/ddk/src/android14-6.1/include/linux/audit_arch.h \
  /opt/ddk/src/android14-6.1/include/uapi/linux/audit.h \
  /opt/ddk/src/android14-6.1/include/uapi/linux/netfilter/nf_tables.h \
  /opt/ddk/src/android14-6.1/arch/arm64/include/asm/syscall.h \
  /opt/ddk/src/android14-6.1/include/linux/lsm_audit.h \
    $(wildcard include/config/SECURITY_SMACK) \
    $(wildcard include/config/SECURITY_SELINUX) \
    $(wildcard include/config/SECURITY_APPARMOR) \
  /opt/ddk/src/android14-6.1/include/rdma/ib_verbs.h \
    $(wildcard include/config/CGROUP_RDMA) \
    $(wildcard include/config/INFINIBAND_VIRT_DMA) \
  /opt/ddk/src/android14-6.1/include/linux/ethtool.h \
  /opt/ddk/src/android14-6.1/include/linux/netlink.h \
  /opt/ddk/src/android14-6.1/include/net/scm.h \
  /opt/ddk/src/android14-6.1/include/uapi/linux/netlink.h \
  /opt/ddk/src/android14-6.1/include/uapi/linux/ethtool.h \
  /opt/ddk/src/android14-6.1/include/linux/if_ether.h \
  /opt/ddk/src/android14-6.1/include/linux/irq_poll.h \
  /opt/ddk/src/android14-6.1/include/net/ipv6.h \
  /opt/ddk/src/android14-6.1/include/linux/ipv6.h \
    $(wildcard include/config/IPV6_ROUTER_PREF) \
    $(wildcard include/config/IPV6_ROUTE_INFO) \
    $(wildcard include/config/IPV6_OPTIMISTIC_DAD) \
    $(wildcard include/config/IPV6_SEG6_HMAC) \
    $(wildcard include/config/IPV6_MIP6) \
  /opt/ddk/src/android14-6.1/include/uapi/linux/ipv6.h \
  /opt/ddk/src/android14-6.1/include/linux/tcp.h \
    $(wildcard include/config/BPF) \
    $(wildcard include/config/TCP_MD5SIG) \
  /opt/ddk/src/android14-6.1/include/linux/win_minmax.h \
  /opt/ddk/src/android14-6.1/include/net/sock.h \
    $(wildcard include/config/SOCK_RX_QUEUE_MAPPING) \
    $(wildcard include/config/SOCK_VALIDATE_XMIT) \
    $(wildcard include/config/RPS) \
    $(wildcard include/config/SOCK_CGROUP_DATA) \
    $(wildcard include/config/INET) \
  /opt/ddk/src/android14-6.1/include/linux/netdevice.h \
    $(wildcard include/config/DCB) \
    $(wildcard include/config/HYPERV_NET) \
    $(wildcard include/config/WLAN) \
    $(wildcard include/config/AX25) \
    $(wildcard include/config/MAC80211_MESH) \
    $(wildcard include/config/NET_IPIP) \
    $(wildcard include/config/NET_IPGRE) \
    $(wildcard include/config/IPV6_SIT) \
    $(wildcard include/config/IPV6_TUNNEL) \
    $(wildcard include/config/NETPOLL) \
    $(wildcard include/config/BQL) \
    $(wildcard include/config/RFS_ACCEL) \
    $(wildcard include/config/FCOE) \
    $(wildcard include/config/XFRM_OFFLOAD) \
    $(wildcard include/config/NET_POLL_CONTROLLER) \
    $(wildcard include/config/LIBFCOE) \
    $(wildcard include/config/VLAN_8021Q) \
    $(wildcard include/config/NET_DSA) \
    $(wildcard include/config/TIPC) \
    $(wildcard include/config/ATALK) \
    $(wildcard include/config/IEEE802154) \
    $(wildcard include/config/6LOWPAN) \
    $(wildcard include/config/MPLS_ROUTING) \
    $(wildcard include/config/NETFILTER_INGRESS) \
    $(wildcard include/config/NETFILTER_EGRESS) \
    $(wildcard include/config/PCPU_DEV_REFCNT) \
    $(wildcard include/config/GARP) \
    $(wildcard include/config/MRP) \
    $(wildcard include/config/NET_DROP_MONITOR) \
    $(wildcard include/config/CGROUP_NET_PRIO) \
    $(wildcard include/config/MACSEC) \
    $(wildcard include/config/NET_FLOW_LIMIT) \
    $(wildcard include/config/NET_EGRESS) \
    $(wildcard include/config/ETHTOOL_NETLINK) \
  /opt/ddk/src/android14-6.1/include/linux/prefetch.h \
  /opt/ddk/src/android14-6.1/include/linux/dynamic_queue_limits.h \
  /opt/ddk/src/android14-6.1/include/net/netprio_cgroup.h \
  /opt/ddk/src/android14-6.1/include/linux/cgroup.h \
    $(wildcard include/config/CGROUP_CPUACCT) \
    $(wildcard include/config/CGROUP_DATA) \
    $(wildcard include/config/CGROUP_BPF) \
  /opt/ddk/src/android14-6.1/include/uapi/linux/cgroupstats.h \
  /opt/ddk/src/android14-6.1/include/uapi/linux/taskstats.h \
  /opt/ddk/src/android14-6.1/include/linux/user_namespace.h \
    $(wildcard include/config/INOTIFY_USER) \
    $(wildcard include/config/FANOTIFY) \
    $(wildcard include/config/PERSISTENT_KEYRINGS) \
  /opt/ddk/src/android14-6.1/include/linux/kernel_stat.h \
  /opt/ddk/src/android14-6.1/include/linux/cgroup-defs.h \
    $(wildcard include/config/CGROUP_NET_CLASSID) \
  /opt/ddk/src/android14-6.1/include/linux/bpf-cgroup-defs.h \
    $(wildcard include/config/BPF_LSM) \
  /opt/ddk/src/android14-6.1/include/linux/psi_types.h \
  /opt/ddk/src/android14-6.1/include/linux/kthread.h \
  /opt/ddk/src/android14-6.1/include/linux/cgroup_subsys.h \
    $(wildcard include/config/CGROUP_DEVICE) \
    $(wildcard include/config/CGROUP_FREEZER) \
    $(wildcard include/config/CGROUP_PERF) \
    $(wildcard include/config/CGROUP_HUGETLB) \
    $(wildcard include/config/CGROUP_PIDS) \
    $(wildcard include/config/CGROUP_MISC) \
    $(wildcard include/config/CGROUP_DEBUG) \
  /opt/ddk/src/android14-6.1/include/net/xdp.h \
  /opt/ddk/src/android14-6.1/include/uapi/linux/neighbour.h \
  /opt/ddk/src/android14-6.1/include/uapi/linux/netdevice.h \
  /opt/ddk/src/android14-6.1/include/linux/if_link.h \
  /opt/ddk/src/android14-6.1/include/uapi/linux/if_link.h \
  /opt/ddk/src/android14-6.1/include/uapi/linux/if_bonding.h \
  /opt/ddk/src/android14-6.1/include/uapi/linux/pkt_cls.h \
  /opt/ddk/src/android14-6.1/include/uapi/linux/pkt_sched.h \
  /opt/ddk/src/android14-6.1/include/linux/hashtable.h \
  /opt/ddk/src/android14-6.1/include/linux/page_counter.h \
  /opt/ddk/src/android14-6.1/include/linux/memcontrol.h \
  /opt/ddk/src/android14-6.1/include/linux/vmpressure.h \
  /opt/ddk/src/android14-6.1/include/linux/eventfd.h \
  /opt/ddk/src/android14-6.1/include/linux/writeback.h \
  /opt/ddk/src/android14-6.1/include/linux/flex_proportions.h \
  /opt/ddk/src/android14-6.1/include/linux/backing-dev-defs.h \
    $(wildcard include/config/DEBUG_FS) \
  /opt/ddk/src/android14-6.1/include/linux/blk_types.h \
    $(wildcard include/config/FAIL_MAKE_REQUEST) \
    $(wildcard include/config/BLK_CGROUP_IOCOST) \
    $(wildcard include/config/BLK_INLINE_ENCRYPTION) \
    $(wildcard include/config/DM_DEFAULT_KEY) \
    $(wildcard include/config/BLK_DEV_INTEGRITY) \
  /opt/ddk/src/android14-6.1/include/linux/bio.h \
  /opt/ddk/src/android14-6.1/include/linux/mempool.h \
  /opt/ddk/src/android14-6.1/include/linux/rculist_nulls.h \
  /opt/ddk/src/android14-6.1/include/linux/poll.h \
  /opt/ddk/src/android14-6.1/include/uapi/linux/poll.h \
  arch/arm64/include/generated/uapi/asm/poll.h \
  /opt/ddk/src/android14-6.1/include/uapi/asm-generic/poll.h \
  /opt/ddk/src/android14-6.1/include/uapi/linux/eventpoll.h \
  /opt/ddk/src/android14-6.1/include/linux/indirect_call_wrapper.h \
  /opt/ddk/src/android14-6.1/include/net/dst.h \
  /opt/ddk/src/android14-6.1/include/linux/rtnetlink.h \
    $(wildcard include/config/NET_INGRESS) \
  /opt/ddk/src/android14-6.1/include/uapi/linux/rtnetlink.h \
  /opt/ddk/src/android14-6.1/include/uapi/linux/if_addr.h \
  /opt/ddk/src/android14-6.1/include/net/neighbour.h \
  /opt/ddk/src/android14-6.1/include/net/rtnetlink.h \
  /opt/ddk/src/android14-6.1/include/net/netlink.h \
  /opt/ddk/src/android14-6.1/include/net/tcp_states.h \
  /opt/ddk/src/android14-6.1/include/uapi/linux/net_tstamp.h \
  /opt/ddk/src/android14-6.1/include/net/l3mdev.h \
  /opt/ddk/src/android14-6.1/include/net/fib_rules.h \
  /opt/ddk/src/android14-6.1/include/uapi/linux/fib_rules.h \
  /opt/ddk/src/android14-6.1/include/net/fib_notifier.h \
  /opt/ddk/src/android14-6.1/include/net/inet_connection_sock.h \
  /opt/ddk/src/android14-6.1/include/net/inet_sock.h \
  /opt/ddk/src/android14-6.1/include/linux/jhash.h \
  /opt/ddk/src/android14-6.1/include/linux/unaligned/packed_struct.h \
  /opt/ddk/src/android14-6.1/include/net/request_sock.h \
  /opt/ddk/src/android14-6.1/include/net/netns/hash.h \
  /opt/ddk/src/android14-6.1/include/net/inet_timewait_sock.h \
  /opt/ddk/src/android14-6.1/include/net/timewait_sock.h \
  /opt/ddk/src/android14-6.1/include/uapi/linux/tcp.h \
  /opt/ddk/src/android14-6.1/include/linux/udp.h \
  /opt/ddk/src/android14-6.1/include/uapi/linux/udp.h \
  /opt/ddk/src/android14-6.1/include/linux/jump_label_ratelimit.h \
  /opt/ddk/src/android14-6.1/include/net/if_inet6.h \
  /opt/ddk/src/android14-6.1/include/net/inet_dscp.h \
  /opt/ddk/src/android14-6.1/include/net/ip.h \
  /opt/ddk/src/android14-6.1/include/linux/ip.h \
  /opt/ddk/src/android14-6.1/include/uapi/linux/ip.h \
  /opt/ddk/src/android14-6.1/include/net/route.h \
  /opt/ddk/src/android14-6.1/include/net/inetpeer.h \
  /opt/ddk/src/android14-6.1/include/net/ip_fib.h \
  /opt/ddk/src/android14-6.1/include/net/arp.h \
  /opt/ddk/src/android14-6.1/include/linux/if_arp.h \
    $(wildcard include/config/FIREWIRE_NET) \
  /opt/ddk/src/android14-6.1/include/uapi/linux/if_arp.h \
  /opt/ddk/src/android14-6.1/include/net/ndisc.h \
  /opt/ddk/src/android14-6.1/include/net/ipv6_stubs.h \
  /opt/ddk/src/android14-6.1/include/linux/icmpv6.h \
    $(wildcard include/config/NF_NAT) \
  /opt/ddk/src/android14-6.1/include/uapi/linux/in_route.h \
  /opt/ddk/src/android14-6.1/include/uapi/linux/route.h \
  /opt/ddk/src/android14-6.1/include/net/lwtunnel.h \
    $(wildcard include/config/LWTUNNEL) \
  /opt/ddk/src/android14-6.1/include/uapi/linux/lwtunnel.h \
  /opt/ddk/src/android14-6.1/include/linux/mmu_notifier.h \
  /opt/ddk/src/android14-6.1/include/linux/interval_tree.h \
  /opt/ddk/src/android14-6.1/include/linux/cgroup_rdma.h \
  /opt/ddk/src/android14-6.1/include/linux/dim.h \
  /opt/ddk/src/android14-6.1/include/uapi/rdma/ib_user_verbs.h \
  /opt/ddk/src/android14-6.1/include/rdma/rdma_counter.h \
  /opt/ddk/src/android14-6.1/include/rdma/restrack.h \
  /opt/ddk/src/android14-6.1/include/uapi/rdma/rdma_netlink.h \
  /opt/ddk/src/android14-6.1/include/rdma/rdma_netlink.h \
  /opt/ddk/src/android14-6.1/include/rdma/signature.h \
  /opt/ddk/src/android14-6.1/include/uapi/rdma/rdma_user_ioctl.h \
  /opt/ddk/src/android14-6.1/include/uapi/rdma/ib_user_mad.h \
  /opt/ddk/src/android14-6.1/include/uapi/rdma/hfi/hfi1_ioctl.h \
  /opt/ddk/src/android14-6.1/include/uapi/rdma/rdma_user_ioctl_cmds.h \
  /opt/ddk/src/android14-6.1/include/uapi/rdma/ib_user_ioctl_verbs.h \
  security/selinux/av_permissions.h \
  /opt/ddk/src/android14-6.1/security/selinux/ss/context.h \
  /opt/ddk/src/android14-6.1/security/selinux/ss/ebitmap.h \
  /opt/ddk/src/android14-6.1/include/net/netlabel.h \
  /opt/ddk/src/android14-6.1/security/selinux/ss/mls_types.h \
  /opt/ddk/src/android14-6.1/security/selinux/ss/conditional.h \
  /opt/ddk/src/android14-6.1/security/selinux/ss/avtab.h \
  /opt/ddk/src/android14-6.1/security/selinux/ss/symtab.h \
  /opt/ddk/src/android14-6.1/security/selinux/ss/hashtab.h \
  /opt/ddk/src/android14-6.1/security/selinux/ss/policydb.h \
  /opt/ddk/src/android14-6.1/security/selinux/ss/sidtab.h \
    $(wildcard include/config/SECURITY_SELINUX_SID2STR_CACHE_SIZE) \
    $(wildcard include/config/SECURITY_SELINUX_SIDTAB_HASH_BITS) \
  /opt/ddk/src/android14-6.1/security/selinux/ss/constraint.h \
  /opt/ddk/src/android14-6.1/security/selinux/ss/../include/conditional.h \
  /opt/ddk/src/android14-6.1/security/selinux/ss/mls.h \
  /opt/ddk/src/android14-6.1/security/selinux/ss/services.h \
  /output/android14-6.1/policy_view.h \
  /output/android14-6.1/policy_dynamic_layout.h \
  /output/android14-6.1/policy_layout_slots.h \

/output/android14-6.1/ksu_setprocattr.o: $(deps_/output/android14-6.1/ksu_setprocattr.o)

$(deps_/output/android14-6.1/ksu_setprocattr.o):
