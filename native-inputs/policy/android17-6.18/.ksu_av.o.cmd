savedcmd_ksu_av.o := python3 /source/scripts/policy-kernel-clang.py clang -Wp,-MMD,./.ksu_av.o.d -nostdinc -I/kernel/arch/arm64/include -I/kernel-build/arch/arm64/include/generated -I/kernel/include -I/kernel-build/include -I/kernel/arch/arm64/include/uapi -I/kernel-build/arch/arm64/include/generated/uapi -I/kernel/include/uapi -I/kernel-build/include/generated/uapi -include /kernel/include/linux/compiler-version.h -include /kernel/include/linux/kconfig.h -include /kernel/include/linux/compiler_types.h -D__KERNEL__ --target=aarch64-linux-gnu -fintegrated-as -Werror=unknown-warning-option -Werror=ignored-optimization-argument -Werror=option-ignored -Werror=unused-command-line-argument -mlittle-endian -DKASAN_SHADOW_SCALE_SHIFT= -Werror -std=gnu11 -fshort-wchar -funsigned-char -fno-common -fno-PIE -fno-strict-aliasing -mgeneral-regs-only -DCONFIG_CC_HAS_K_CONSTRAINT=1 -Wno-psabi -fasynchronous-unwind-tables -mbranch-protection=pac-ret+bti -Wa,-march=armv8.5-a -DARM64_ASM_ARCH='"armv8.5-a"' -ffixed-x18 -DKASAN_SHADOW_SCALE_SHIFT= -fno-delete-null-pointer-checks -O2 -fstack-protector-strong -fno-omit-frame-pointer -fno-optimize-sibling-calls -ftrivial-auto-var-init=zero -fno-stack-clash-protection -fsanitize=kcfi -fsanitize-cfi-icall-experimental-normalize-integers -falign-functions=4 -fstrict-flex-arrays=3 -fno-strict-overflow -fno-stack-check -fno-builtin-wcslen -Wall -Wextra -Wundef -Werror=implicit-function-declaration -Werror=implicit-int -Werror=return-type -Werror=strict-prototypes -Wno-format-security -Wno-trigraphs -Wno-frame-address -Wno-address-of-packed-member -Wmissing-declarations -Wmissing-prototypes -Wframe-larger-than=2048 -Wno-gnu -Wno-format-overflow-non-kprintf -Wno-format-truncation-non-kprintf -Wno-pointer-sign -Wcast-function-type -Wimplicit-fallthrough -Werror=date-time -Werror=incompatible-pointer-types -Wenum-conversion -Wunused -Wno-unused-but-set-variable -Wno-unused-const-variable -Wno-format-overflow -Wno-override-init -Wno-pointer-to-enum-cast -Wno-tautological-constant-out-of-range-compare -Wno-unaligned-access -Wno-enum-compare-conditional -Wno-missing-field-initializers -Wno-type-limits -Wno-shift-negative-value -Wno-enum-enum-conversion -Wno-sign-compare -Wno-unused-parameter -g -gdwarf-5 -gz=zstd -mstack-protector-guard=sysreg -mstack-protector-guard-reg=sp_el0 -mstack-protector-guard-offset=1824 -I./. -I././.. -I/kernel/security/selinux -I/kernel/security/selinux/include -I/kernel-build/security/selinux -Werror -fno-lto -fno-sanitize=cfi -DMAPLESU_POLICY_HAS_VM_FLAGS_CLEAR -DMAPLESU_POLICY_MMAP_SEQCOUNT -fPIC -DMAPLESU_POLICY_PIC -mbranch-protection=standard  -fsanitize=array-bounds -fsanitize=local-bounds -fsanitize-trap=undefined    -fdebug-info-for-profiling -mllvm -enable-fs-discriminator=true -mllvm -improved-fs-discriminator=true  -DMODULE  -DKBUILD_BASENAME='"ksu_av"' -DKBUILD_MODNAME='"maplesu_policy_view"' -D__KBUILD_MODNAME=kmod_maplesu_policy_view -c -o ksu_av.o ksu_av.c  

source_ksu_av.o := ksu_av.c

deps_ksu_av.o := \
  /kernel/include/linux/compiler-version.h \
    $(wildcard include/config/CC_VERSION_TEXT) \
  /kernel/include/linux/kconfig.h \
    $(wildcard include/config/CPU_BIG_ENDIAN) \
    $(wildcard include/config/BOOGER) \
    $(wildcard include/config/FOO) \
  /kernel/include/linux/compiler_types.h \
    $(wildcard include/config/DEBUG_INFO_BTF) \
    $(wildcard include/config/PAHOLE_HAS_BTF_TAG) \
    $(wildcard include/config/FUNCTION_ALIGNMENT) \
    $(wildcard include/config/CC_HAS_SANE_FUNCTION_ALIGNMENT) \
    $(wildcard include/config/X86_64) \
    $(wildcard include/config/ARM64) \
    $(wildcard include/config/LD_DEAD_CODE_DATA_ELIMINATION) \
    $(wildcard include/config/LTO_CLANG) \
    $(wildcard include/config/HAVE_ARCH_COMPILER_H) \
    $(wildcard include/config/KCSAN) \
    $(wildcard include/config/CC_HAS_ASSUME) \
    $(wildcard include/config/CC_HAS_COUNTED_BY) \
    $(wildcard include/config/CC_HAS_MULTIDIMENSIONAL_NONSTRING) \
    $(wildcard include/config/UBSAN_INTEGER_WRAP) \
    $(wildcard include/config/CFI) \
    $(wildcard include/config/ARCH_USES_CFI_GENERIC_LLVM_PASS) \
    $(wildcard include/config/CC_HAS_ASM_INLINE) \
  /kernel/include/linux/compiler_attributes.h \
  /kernel/include/linux/compiler-clang.h \
    $(wildcard include/config/ARCH_USE_BUILTIN_BSWAP) \
    $(wildcard include/config/CC_HAS_TYPEOF_UNQUAL) \
  /kernel/arch/arm64/include/asm/compiler.h \
    $(wildcard include/config/ARM64_PTR_AUTH_KERNEL) \
    $(wildcard include/config/ARM64_PTR_AUTH) \
    $(wildcard include/config/BUILTIN_RETURN_ADDRESS_STRIPS_PAC) \
  policy_view_internal.h \
  /kernel/include/linux/jump_label.h \
    $(wildcard include/config/JUMP_LABEL) \
    $(wildcard include/config/HAVE_ARCH_JUMP_LABEL_RELATIVE) \
  /kernel/include/linux/types.h \
    $(wildcard include/config/HAVE_UID16) \
    $(wildcard include/config/UID16) \
    $(wildcard include/config/ARCH_DMA_ADDR_T_64BIT) \
    $(wildcard include/config/PHYS_ADDR_T_64BIT) \
    $(wildcard include/config/64BIT) \
    $(wildcard include/config/ARCH_32BIT_USTAT_F_TINODE) \
  /kernel/include/uapi/linux/types.h \
  /kernel-build/arch/arm64/include/generated/uapi/asm/types.h \
  /kernel/include/uapi/asm-generic/types.h \
  /kernel/include/asm-generic/int-ll64.h \
  /kernel/include/uapi/asm-generic/int-ll64.h \
  /kernel/arch/arm64/include/uapi/asm/bitsperlong.h \
  /kernel/include/asm-generic/bitsperlong.h \
  /kernel/include/uapi/asm-generic/bitsperlong.h \
  /kernel/include/uapi/linux/posix_types.h \
  /kernel/include/linux/stddef.h \
  /kernel/include/uapi/linux/stddef.h \
  /kernel/arch/arm64/include/uapi/asm/posix_types.h \
  /kernel/include/uapi/asm-generic/posix_types.h \
  /kernel/include/linux/compiler.h \
    $(wildcard include/config/TRACE_BRANCH_PROFILING) \
    $(wildcard include/config/PROFILE_ALL_BRANCHES) \
    $(wildcard include/config/OBJTOOL) \
  /kernel/arch/arm64/include/asm/rwonce.h \
    $(wildcard include/config/LTO) \
  /kernel/include/asm-generic/rwonce.h \
  /kernel/include/linux/kasan-checks.h \
    $(wildcard include/config/KASAN_GENERIC) \
    $(wildcard include/config/KASAN_SW_TAGS) \
  /kernel/include/linux/kcsan-checks.h \
    $(wildcard include/config/KCSAN_WEAK_MEMORY) \
    $(wildcard include/config/KCSAN_IGNORE_ATOMICS) \
  /kernel/include/linux/cleanup.h \
  /kernel/include/linux/err.h \
  /kernel-build/arch/arm64/include/generated/uapi/asm/errno.h \
  /kernel/include/uapi/asm-generic/errno.h \
  /kernel/include/uapi/asm-generic/errno-base.h \
  /kernel/include/linux/args.h \
  /kernel/arch/arm64/include/asm/jump_label.h \
  /kernel/arch/arm64/include/asm/insn.h \
    $(wildcard include/config/ARM64_LSE_ATOMICS) \
  /kernel/include/linux/build_bug.h \
  /kernel/arch/arm64/include/asm/insn-def.h \
  /kernel/arch/arm64/include/asm/brk-imm.h \
  /kernel/include/linux/cred.h \
    $(wildcard include/config/MULTIUSER) \
    $(wildcard include/config/KEYS) \
    $(wildcard include/config/SECURITY) \
    $(wildcard include/config/USER_NS) \
  /kernel/include/linux/capability.h \
  /kernel/include/uapi/linux/capability.h \
  /kernel/include/linux/uidgid.h \
  /kernel/include/linux/uidgid_types.h \
  /kernel/include/linux/highuid.h \
  /kernel/include/linux/bits.h \
  /kernel/include/vdso/bits.h \
  /kernel/include/vdso/const.h \
  /kernel/include/uapi/linux/const.h \
  /kernel/include/uapi/linux/bits.h \
  /kernel/include/linux/overflow.h \
  /kernel/include/linux/limits.h \
  /kernel/include/uapi/linux/limits.h \
  /kernel/include/vdso/limits.h \
  /kernel/include/linux/const.h \
  /kernel/include/linux/init.h \
    $(wildcard include/config/MEMORY_HOTPLUG) \
    $(wildcard include/config/HAVE_ARCH_PREL32_RELOCATIONS) \
  /kernel/include/linux/stringify.h \
  /kernel/include/linux/key.h \
    $(wildcard include/config/KEY_NOTIFICATIONS) \
    $(wildcard include/config/NET) \
  /kernel/include/linux/list.h \
    $(wildcard include/config/LIST_HARDENED) \
    $(wildcard include/config/DEBUG_LIST) \
  /kernel/include/linux/container_of.h \
  /kernel/include/linux/poison.h \
    $(wildcard include/config/ILLEGAL_POINTER_VALUE) \
  /kernel/arch/arm64/include/asm/barrier.h \
    $(wildcard include/config/ARM64_PSEUDO_NMI) \
  /kernel/arch/arm64/include/asm/alternative-macros.h \
  /kernel/arch/arm64/include/asm/cpucaps.h \
    $(wildcard include/config/ARM64_PAN) \
    $(wildcard include/config/ARM64_EPAN) \
    $(wildcard include/config/ARM64_SVE) \
    $(wildcard include/config/ARM64_SME) \
    $(wildcard include/config/ARM64_CNP) \
    $(wildcard include/config/ARM64_MTE) \
    $(wildcard include/config/ARM64_BTI) \
    $(wildcard include/config/ARM64_TLB_RANGE) \
    $(wildcard include/config/ARM64_POE) \
    $(wildcard include/config/ARM64_GCS) \
    $(wildcard include/config/ARM64_HAFT) \
    $(wildcard include/config/UNMAP_KERNEL_AT_EL0) \
    $(wildcard include/config/ARM64_ERRATUM_843419) \
    $(wildcard include/config/ARM64_ERRATUM_1742098) \
    $(wildcard include/config/ARM64_ERRATUM_2645198) \
    $(wildcard include/config/ARM64_ERRATUM_2658417) \
    $(wildcard include/config/CAVIUM_ERRATUM_23154) \
    $(wildcard include/config/NVIDIA_CARMEL_CNP_ERRATUM) \
    $(wildcard include/config/ARM64_WORKAROUND_REPEAT_TLBI) \
    $(wildcard include/config/ARM64_ERRATUM_3194386) \
    $(wildcard include/config/ARM64_ERRATUM_4193714) \
    $(wildcard include/config/HW_PERF_EVENTS) \
  /kernel-build/arch/arm64/include/generated/asm/cpucap-defs.h \
  /kernel/include/asm-generic/barrier.h \
    $(wildcard include/config/SMP) \
  /kernel/include/linux/rbtree.h \
  /kernel/include/linux/rbtree_types.h \
  /kernel/include/linux/rcupdate.h \
    $(wildcard include/config/PREEMPT_RCU) \
    $(wildcard include/config/TINY_RCU) \
    $(wildcard include/config/RCU_STRICT_GRACE_PERIOD) \
    $(wildcard include/config/RCU_LAZY) \
    $(wildcard include/config/RCU_STALL_COMMON) \
    $(wildcard include/config/NO_HZ_FULL) \
    $(wildcard include/config/GENERIC_ENTRY) \
    $(wildcard include/config/VIRT_XFER_TO_GUEST_WORK) \
    $(wildcard include/config/RCU_NOCB_CPU) \
    $(wildcard include/config/TASKS_RCU_GENERIC) \
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
  /kernel/include/linux/atomic.h \
  /kernel/arch/arm64/include/asm/atomic.h \
  /kernel/arch/arm64/include/asm/cmpxchg.h \
  /kernel/arch/arm64/include/asm/lse.h \
  /kernel/arch/arm64/include/asm/atomic_ll_sc.h \
    $(wildcard include/config/CC_HAS_K_CONSTRAINT) \
  /kernel/include/linux/export.h \
    $(wildcard include/config/MODVERSIONS) \
    $(wildcard include/config/GENDWARFKSYMS) \
  /kernel/include/linux/linkage.h \
    $(wildcard include/config/ARCH_USE_SYM_ANNOTATIONS) \
  /kernel/arch/arm64/include/asm/linkage.h \
  /kernel/arch/arm64/include/asm/alternative.h \
    $(wildcard include/config/MODULES) \
  /kernel/arch/arm64/include/asm/atomic_lse.h \
  /kernel/include/linux/atomic/atomic-arch-fallback.h \
    $(wildcard include/config/GENERIC_ATOMIC64) \
  /kernel/include/linux/atomic/atomic-long.h \
  /kernel/include/linux/atomic/atomic-instrumented.h \
  /kernel/include/linux/instrumented.h \
  /kernel/include/linux/kmsan-checks.h \
    $(wildcard include/config/KMSAN) \
  /kernel/include/linux/irqflags.h \
    $(wildcard include/config/PROVE_LOCKING) \
    $(wildcard include/config/TRACE_IRQFLAGS) \
    $(wildcard include/config/IRQSOFF_TRACER) \
    $(wildcard include/config/PREEMPT_TRACER) \
    $(wildcard include/config/DEBUG_IRQFLAGS) \
    $(wildcard include/config/TRACE_IRQFLAGS_SUPPORT) \
  /kernel/include/linux/irqflags_types.h \
  /kernel/include/linux/typecheck.h \
  /kernel/arch/arm64/include/asm/irqflags.h \
    $(wildcard include/config/ARM64_DEBUG_PRIORITY_MASKING) \
  /kernel/arch/arm64/include/asm/ptrace.h \
    $(wildcard include/config/COMPAT) \
  /kernel/arch/arm64/include/asm/cpufeature.h \
    $(wildcard include/config/ARM64_SW_TTBR0_PAN) \
    $(wildcard include/config/ARM64_BTI_KERNEL) \
    $(wildcard include/config/ARM64_PA_BITS) \
    $(wildcard include/config/ARM64_HW_AFDBM) \
    $(wildcard include/config/ARM64_AMU_EXTN) \
    $(wildcard include/config/ARM64_LPA2) \
  /kernel/arch/arm64/include/asm/cputype.h \
  /kernel/arch/arm64/include/asm/sysreg.h \
    $(wildcard include/config/BROKEN_GAS_INST) \
    $(wildcard include/config/ARM64_PA_BITS_52) \
    $(wildcard include/config/ARM64_4K_PAGES) \
    $(wildcard include/config/ARM64_16K_PAGES) \
    $(wildcard include/config/ARM64_64K_PAGES) \
    $(wildcard include/config/KASAN_HW_TAGS) \
    $(wildcard include/config/AMPERE_ERRATUM_AC04_CPU_23) \
  /kernel/include/linux/kasan-tags.h \
  /kernel/arch/arm64/include/asm/gpr-num.h \
  /kernel-build/arch/arm64/include/generated/asm/sysreg-defs.h \
  /kernel/include/linux/bitfield.h \
  /kernel/arch/arm64/include/uapi/asm/byteorder.h \
  /kernel/include/linux/byteorder/little_endian.h \
  /kernel/include/uapi/linux/byteorder/little_endian.h \
  /kernel/include/linux/swab.h \
  /kernel/include/uapi/linux/swab.h \
  /kernel-build/arch/arm64/include/generated/uapi/asm/swab.h \
  /kernel/include/uapi/asm-generic/swab.h \
  /kernel/include/linux/byteorder/generic.h \
  /kernel/arch/arm64/include/asm/hwcap.h \
  /kernel/arch/arm64/include/uapi/asm/hwcap.h \
  /kernel/include/linux/log2.h \
    $(wildcard include/config/ARCH_HAS_ILOG2_U32) \
    $(wildcard include/config/ARCH_HAS_ILOG2_U64) \
  /kernel/include/linux/bitops.h \
  /kernel/include/uapi/linux/kernel.h \
  /kernel/include/uapi/linux/sysinfo.h \
  /kernel/include/asm-generic/bitops/generic-non-atomic.h \
  /kernel/arch/arm64/include/asm/bitops.h \
  /kernel/include/asm-generic/bitops/builtin-__ffs.h \
  /kernel/include/asm-generic/bitops/builtin-ffs.h \
  /kernel/include/asm-generic/bitops/builtin-__fls.h \
  /kernel/include/asm-generic/bitops/builtin-fls.h \
  /kernel/include/asm-generic/bitops/ffz.h \
  /kernel/include/asm-generic/bitops/fls64.h \
  /kernel/include/asm-generic/bitops/sched.h \
  /kernel/include/asm-generic/bitops/hweight.h \
  /kernel/include/asm-generic/bitops/arch_hweight.h \
  /kernel/include/asm-generic/bitops/const_hweight.h \
  /kernel/include/asm-generic/bitops/atomic.h \
  /kernel/include/asm-generic/bitops/instrumented-atomic.h \
  /kernel/include/asm-generic/bitops/lock.h \
  /kernel/include/asm-generic/bitops/instrumented-lock.h \
  /kernel/include/asm-generic/bitops/non-atomic.h \
  /kernel/include/asm-generic/bitops/non-instrumented-non-atomic.h \
  /kernel/include/asm-generic/bitops/le.h \
  /kernel/include/asm-generic/bitops/ext2-atomic-setbit.h \
  /kernel/include/linux/bug.h \
    $(wildcard include/config/GENERIC_BUG) \
    $(wildcard include/config/PRINTK) \
    $(wildcard include/config/BUG_ON_DATA_CORRUPTION) \
  /kernel/arch/arm64/include/asm/bug.h \
  /kernel/arch/arm64/include/asm/asm-bug.h \
    $(wildcard include/config/DEBUG_BUGVERBOSE) \
  /kernel/include/asm-generic/bug.h \
    $(wildcard include/config/BUG) \
    $(wildcard include/config/GENERIC_BUG_RELATIVE_POINTERS) \
  /kernel/include/linux/instrumentation.h \
    $(wildcard include/config/NOINSTR_VALIDATION) \
  /kernel/include/linux/once_lite.h \
  /kernel/include/linux/panic.h \
    $(wildcard include/config/PANIC_TIMEOUT) \
  /kernel/include/linux/stdarg.h \
  /kernel/include/linux/printk.h \
    $(wildcard include/config/MESSAGE_LOGLEVEL_DEFAULT) \
    $(wildcard include/config/CONSOLE_LOGLEVEL_DEFAULT) \
    $(wildcard include/config/CONSOLE_LOGLEVEL_QUIET) \
    $(wildcard include/config/EARLY_PRINTK) \
    $(wildcard include/config/PRINTK_INDEX) \
    $(wildcard include/config/DYNAMIC_DEBUG) \
    $(wildcard include/config/DYNAMIC_DEBUG_CORE) \
  /kernel/include/linux/kern_levels.h \
  /kernel/include/linux/ratelimit_types.h \
  /kernel/include/uapi/linux/param.h \
  /kernel/arch/arm64/include/uapi/asm/param.h \
  /kernel/include/asm-generic/param.h \
    $(wildcard include/config/HZ) \
  /kernel/include/uapi/asm-generic/param.h \
  /kernel/include/linux/spinlock_types_raw.h \
    $(wildcard include/config/DEBUG_SPINLOCK) \
  /kernel/arch/arm64/include/asm/spinlock_types.h \
  /kernel/include/asm-generic/qspinlock_types.h \
    $(wildcard include/config/NR_CPUS) \
  /kernel/include/asm-generic/qrwlock_types.h \
  /kernel/include/linux/lockdep_types.h \
    $(wildcard include/config/PROVE_RAW_LOCK_NESTING) \
    $(wildcard include/config/LOCKDEP) \
    $(wildcard include/config/LOCK_STAT) \
  /kernel/include/linux/kernel.h \
    $(wildcard include/config/PREEMPT_VOLUNTARY_BUILD) \
    $(wildcard include/config/PREEMPT_DYNAMIC) \
    $(wildcard include/config/HAVE_PREEMPT_DYNAMIC_CALL) \
    $(wildcard include/config/HAVE_PREEMPT_DYNAMIC_KEY) \
    $(wildcard include/config/PREEMPT_) \
    $(wildcard include/config/DEBUG_ATOMIC_SLEEP) \
    $(wildcard include/config/MMU) \
    $(wildcard include/config/TRACING) \
    $(wildcard include/config/DYNAMIC_FTRACE) \
  /kernel/include/linux/align.h \
  /kernel/include/vdso/align.h \
  /kernel/include/linux/array_size.h \
  /kernel/include/linux/hex.h \
  /kernel/include/linux/kstrtox.h \
  /kernel/include/linux/math.h \
  /kernel-build/arch/arm64/include/generated/asm/div64.h \
  /kernel/include/asm-generic/div64.h \
    $(wildcard include/config/CC_OPTIMIZE_FOR_PERFORMANCE) \
  /kernel/include/linux/minmax.h \
  /kernel/include/linux/sprintf.h \
  /kernel/include/linux/static_call_types.h \
    $(wildcard include/config/HAVE_STATIC_CALL) \
    $(wildcard include/config/HAVE_STATIC_CALL_INLINE) \
  /kernel/include/linux/instruction_pointer.h \
  /kernel/include/linux/util_macros.h \
    $(wildcard include/config/FOO_SUSPEND) \
  /kernel/include/linux/wordpart.h \
  /kernel/include/linux/cpumask.h \
    $(wildcard include/config/FORCE_NR_CPUS) \
    $(wildcard include/config/DEBUG_PER_CPU_MAPS) \
    $(wildcard include/config/CPUMASK_OFFSTACK) \
  /kernel/include/linux/bitmap.h \
  /kernel/include/linux/errno.h \
  /kernel/include/uapi/linux/errno.h \
  /kernel/include/linux/find.h \
  /kernel/include/linux/string.h \
    $(wildcard include/config/BINARY_PRINTF) \
    $(wildcard include/config/FORTIFY_SOURCE) \
  /kernel/include/uapi/linux/string.h \
  /kernel/arch/arm64/include/asm/string.h \
    $(wildcard include/config/ARCH_HAS_UACCESS_FLUSHCACHE) \
  /kernel/include/linux/fortify-string.h \
    $(wildcard include/config/CC_HAS_KASAN_MEMINTRINSIC_PREFIX) \
  /kernel/include/linux/bitmap-str.h \
  /kernel/include/linux/cpumask_types.h \
  /kernel/include/linux/threads.h \
    $(wildcard include/config/BASE_SMALL) \
  /kernel/include/linux/gfp_types.h \
    $(wildcard include/config/SLAB_OBJ_EXT) \
    $(wildcard include/config/CMA) \
  /kernel/include/linux/numa.h \
    $(wildcard include/config/NUMA_KEEP_MEMINFO) \
    $(wildcard include/config/NUMA) \
    $(wildcard include/config/HAVE_ARCH_NODE_DEV_GROUP) \
  /kernel/include/linux/nodemask.h \
    $(wildcard include/config/HIGHMEM) \
  /kernel/include/linux/nodemask_types.h \
    $(wildcard include/config/NODES_SHIFT) \
  /kernel/include/linux/random.h \
    $(wildcard include/config/VMGENID) \
  /kernel/include/uapi/linux/random.h \
  /kernel/include/uapi/linux/ioctl.h \
  /kernel-build/arch/arm64/include/generated/uapi/asm/ioctl.h \
  /kernel/include/asm-generic/ioctl.h \
  /kernel/include/uapi/asm-generic/ioctl.h \
  /kernel/include/linux/irqnr.h \
  /kernel/include/uapi/linux/irqnr.h \
  /kernel/arch/arm64/include/uapi/asm/ptrace.h \
  /kernel/arch/arm64/include/uapi/asm/sve_context.h \
  /kernel/include/linux/irqchip/arm-gic-v3-prio.h \
  /kernel/arch/arm64/include/asm/stacktrace/frame.h \
  /kernel/arch/arm64/include/asm/percpu.h \
    $(wildcard include/config/DEBUG_PREEMPT) \
  /kernel/include/linux/preempt.h \
    $(wildcard include/config/PREEMPT_COUNT) \
    $(wildcard include/config/TRACE_PREEMPT_TOGGLE) \
    $(wildcard include/config/PREEMPT_NOTIFIERS) \
    $(wildcard include/config/PREEMPT_NONE) \
    $(wildcard include/config/PREEMPT_VOLUNTARY) \
    $(wildcard include/config/PREEMPT) \
    $(wildcard include/config/PREEMPT_LAZY) \
  /kernel/arch/arm64/include/asm/preempt.h \
  /kernel/include/linux/thread_info.h \
    $(wildcard include/config/THREAD_INFO_IN_TASK) \
    $(wildcard include/config/ARCH_HAS_PREEMPT_LAZY) \
    $(wildcard include/config/HAVE_ARCH_WITHIN_STACK_FRAMES) \
    $(wildcard include/config/SH) \
  /kernel/include/linux/restart_block.h \
  /kernel/arch/arm64/include/asm/current.h \
  /kernel/arch/arm64/include/asm/thread_info.h \
    $(wildcard include/config/SHADOW_CALL_STACK) \
  /kernel/arch/arm64/include/asm/memory.h \
    $(wildcard include/config/ARM64_VA_BITS) \
    $(wildcard include/config/KASAN_SHADOW_OFFSET) \
    $(wildcard include/config/KASAN) \
    $(wildcard include/config/EXECMEM) \
    $(wildcard include/config/RANDOMIZE_BASE) \
    $(wildcard include/config/DEBUG_VIRTUAL) \
    $(wildcard include/config/EFI) \
    $(wildcard include/config/ARM_GIC_V3_ITS) \
  /kernel/include/linux/sizes.h \
  /kernel/arch/arm64/include/asm/page-def.h \
  /kernel/include/vdso/page.h \
    $(wildcard include/config/PAGE_SHIFT) \
  /kernel/include/linux/mmdebug.h \
    $(wildcard include/config/DEBUG_VM) \
    $(wildcard include/config/DEBUG_VM_IRQSOFF) \
    $(wildcard include/config/DEBUG_VM_PGFLAGS) \
  /kernel/arch/arm64/include/asm/boot.h \
  /kernel/arch/arm64/include/asm/sections.h \
  /kernel/include/asm-generic/sections.h \
    $(wildcard include/config/HAVE_FUNCTION_DESCRIPTORS) \
  /kernel/include/asm-generic/memory_model.h \
    $(wildcard include/config/FLATMEM) \
    $(wildcard include/config/SPARSEMEM_VMEMMAP) \
    $(wildcard include/config/SPARSEMEM) \
  /kernel/include/linux/pfn.h \
  /kernel/arch/arm64/include/asm/stack_pointer.h \
  /kernel/include/asm-generic/percpu.h \
    $(wildcard include/config/HAVE_SETUP_PER_CPU_AREA) \
  /kernel/include/linux/percpu-defs.h \
    $(wildcard include/config/ARCH_MODULE_NEEDS_WEAK_PER_CPU) \
    $(wildcard include/config/DEBUG_FORCE_WEAK_PER_CPU) \
    $(wildcard include/config/AMD_MEM_ENCRYPT) \
  /kernel/include/linux/sched.h \
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
    $(wildcard include/config/MEM_ALLOC_PROFILING) \
    $(wildcard include/config/SCHED_CLASS_EXT) \
    $(wildcard include/config/CGROUP_SCHED) \
    $(wildcard include/config/CFS_BANDWIDTH) \
    $(wildcard include/config/BLK_DEV_IO_TRACE) \
    $(wildcard include/config/MEMCG_V1) \
    $(wildcard include/config/LRU_GEN) \
    $(wildcard include/config/COMPAT_BRK) \
    $(wildcard include/config/CGROUPS) \
    $(wildcard include/config/BLK_CGROUP) \
    $(wildcard include/config/PSI) \
    $(wildcard include/config/PAGE_OWNER) \
    $(wildcard include/config/EVENTFD) \
    $(wildcard include/config/ARCH_HAS_CPU_PASID) \
    $(wildcard include/config/X86_BUS_LOCK_DETECT) \
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
    $(wildcard include/config/SCHED_PROXY_EXEC) \
    $(wildcard include/config/DETECT_HUNG_TASK_BLOCKER) \
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
    $(wildcard include/config/DEBUG_RSEQ) \
    $(wildcard include/config/SCHED_MM_CID) \
    $(wildcard include/config/FAULT_INJECTION) \
    $(wildcard include/config/LATENCYTOP) \
    $(wildcard include/config/KUNIT) \
    $(wildcard include/config/FUNCTION_GRAPH_TRACER) \
    $(wildcard include/config/KCOV) \
    $(wildcard include/config/MEMCG) \
    $(wildcard include/config/UPROBES) \
    $(wildcard include/config/BCACHE) \
    $(wildcard include/config/VMAP_STACK) \
    $(wildcard include/config/LIVEPATCH) \
    $(wildcard include/config/BPF_SYSCALL) \
    $(wildcard include/config/KSTACK_ERASE) \
    $(wildcard include/config/KSTACK_ERASE_METRICS) \
    $(wildcard include/config/X86_MCE) \
    $(wildcard include/config/KRETPROBES) \
    $(wildcard include/config/RETHOOK) \
    $(wildcard include/config/ARCH_HAS_PARANOID_L1D_FLUSH) \
    $(wildcard include/config/RV) \
    $(wildcard include/config/RV_PER_TASK_MONITORS) \
    $(wildcard include/config/USER_EVENTS) \
    $(wildcard include/config/UNWIND_USER) \
    $(wildcard include/config/MEM_ALLOC_PROFILING_DEBUG) \
  /kernel/include/uapi/linux/sched.h \
  /kernel/arch/arm64/include/asm/processor.h \
    $(wildcard include/config/KUSER_HELPERS) \
    $(wildcard include/config/ARM64_FORCE_52BIT) \
    $(wildcard include/config/HAVE_HW_BREAKPOINT) \
    $(wildcard include/config/ARM64_TAGGED_ADDR_ABI) \
  /kernel/include/linux/cache.h \
    $(wildcard include/config/ARCH_HAS_CACHE_LINE_SIZE) \
  /kernel/include/vdso/cache.h \
  /kernel/arch/arm64/include/asm/cache.h \
  /kernel/include/linux/kasan-enabled.h \
    $(wildcard include/config/ARCH_DEFER_KASAN) \
  /kernel/include/linux/static_key.h \
  /kernel/arch/arm64/include/asm/mte-def.h \
  /kernel/include/linux/android_vendor.h \
    $(wildcard include/config/ANDROID_VENDOR_OEM_DATA) \
  /kernel/include/vdso/processor.h \
  /kernel/arch/arm64/include/asm/vdso/processor.h \
  /kernel/arch/arm64/include/asm/hw_breakpoint.h \
    $(wildcard include/config/CPU_PM) \
  /kernel/arch/arm64/include/asm/virt.h \
    $(wildcard include/config/KVM) \
  /kernel/arch/arm64/include/asm/kasan.h \
  /kernel/arch/arm64/include/asm/mte-kasan.h \
  /kernel/arch/arm64/include/asm/pgtable-types.h \
    $(wildcard include/config/PGTABLE_LEVELS) \
  /kernel/include/asm-generic/pgtable-nopud.h \
  /kernel/include/asm-generic/pgtable-nop4d.h \
  /kernel/arch/arm64/include/asm/pgtable-hwdef.h \
    $(wildcard include/config/ARM64_CONT_PTE_SHIFT) \
    $(wildcard include/config/ARM64_CONT_PMD_SHIFT) \
    $(wildcard include/config/ARM64_VA_BITS_52) \
  /kernel/arch/arm64/include/asm/pointer_auth.h \
  /kernel/include/uapi/linux/prctl.h \
  /kernel/arch/arm64/include/asm/spectre.h \
  /kernel/include/linux/smp.h \
    $(wildcard include/config/UP_LATE_INIT) \
    $(wildcard include/config/CSD_LOCK_WAIT_DEBUG) \
  /kernel/include/linux/smp_types.h \
  /kernel/include/linux/llist.h \
    $(wildcard include/config/ARCH_HAVE_NMI_SAFE_CMPXCHG) \
  /kernel/arch/arm64/include/asm/smp.h \
    $(wildcard include/config/ARM64_ACPI_PARKING_PROTOCOL) \
  /kernel/arch/arm64/include/asm/fpsimd.h \
  /kernel/arch/arm64/include/uapi/asm/sigcontext.h \
  /kernel/include/linux/pid_types.h \
  /kernel/include/linux/sem_types.h \
  /kernel/include/linux/shm.h \
  /kernel/arch/arm64/include/asm/page.h \
  /kernel/include/linux/personality.h \
  /kernel/include/uapi/linux/personality.h \
  /kernel/include/asm-generic/getorder.h \
  /kernel/arch/arm64/include/asm/shmparam.h \
  /kernel/include/asm-generic/shmparam.h \
  /kernel/include/linux/kmsan_types.h \
  /kernel/include/linux/mutex_types.h \
    $(wildcard include/config/MUTEX_SPIN_ON_OWNER) \
    $(wildcard include/config/DEBUG_MUTEXES) \
  /kernel/include/linux/osq_lock.h \
  /kernel/include/linux/spinlock_types.h \
  /kernel/include/linux/rwlock_types.h \
  /kernel/include/linux/plist_types.h \
  /kernel/include/linux/hrtimer_types.h \
  /kernel/include/linux/timerqueue_types.h \
  /kernel/include/linux/timer_types.h \
  /kernel/include/linux/seccomp_types.h \
    $(wildcard include/config/SECCOMP) \
  /kernel/include/linux/refcount_types.h \
  /kernel/include/linux/resource.h \
  /kernel/include/uapi/linux/resource.h \
  /kernel/include/uapi/linux/time_types.h \
  /kernel-build/arch/arm64/include/generated/uapi/asm/resource.h \
  /kernel/include/asm-generic/resource.h \
  /kernel/include/uapi/asm-generic/resource.h \
  /kernel/include/linux/latencytop.h \
  /kernel/include/linux/sched/prio.h \
  /kernel/include/linux/sched/types.h \
  /kernel/include/linux/signal_types.h \
    $(wildcard include/config/OLD_SIGACTION) \
  /kernel/include/uapi/linux/signal.h \
  /kernel/arch/arm64/include/asm/signal.h \
  /kernel/arch/arm64/include/uapi/asm/signal.h \
  /kernel/include/asm-generic/signal.h \
  /kernel/include/uapi/asm-generic/signal.h \
  /kernel/include/uapi/asm-generic/signal-defs.h \
  /kernel-build/arch/arm64/include/generated/uapi/asm/siginfo.h \
  /kernel/include/uapi/asm-generic/siginfo.h \
  /kernel/include/linux/spinlock.h \
  /kernel/include/linux/bottom_half.h \
  /kernel/include/linux/lockdep.h \
    $(wildcard include/config/DEBUG_LOCKING_API_SELFTESTS) \
  /kernel-build/arch/arm64/include/generated/asm/mmiowb.h \
  /kernel/include/asm-generic/mmiowb.h \
    $(wildcard include/config/MMIOWB) \
  /kernel/arch/arm64/include/asm/spinlock.h \
  /kernel-build/arch/arm64/include/generated/asm/qspinlock.h \
  /kernel/include/asm-generic/qspinlock.h \
  /kernel-build/arch/arm64/include/generated/asm/qrwlock.h \
  /kernel/include/asm-generic/qrwlock.h \
  /kernel/include/linux/rwlock.h \
  /kernel/include/linux/spinlock_api_smp.h \
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
  /kernel/include/linux/rwlock_api_smp.h \
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
  /kernel/include/linux/syscall_user_dispatch_types.h \
  /kernel/include/linux/mm_types_task.h \
    $(wildcard include/config/ARCH_WANT_BATCHED_UNMAP_TLB_FLUSH) \
  /kernel/arch/arm64/include/asm/tlbbatch.h \
  /kernel/include/linux/android_kabi.h \
    $(wildcard include/config/ANDROID_KABI_RESERVE) \
  /kernel/include/linux/netdevice_xmit.h \
    $(wildcard include/config/NET_EGRESS) \
    $(wildcard include/config/NET_ACT_MIRRED) \
    $(wildcard include/config/NF_DUP_NETDEV) \
  /kernel/include/linux/task_io_accounting.h \
    $(wildcard include/config/TASK_IO_ACCOUNTING) \
  /kernel/include/linux/posix-timers_types.h \
    $(wildcard include/config/POSIX_TIMERS) \
  /kernel/include/uapi/linux/rseq.h \
  /kernel/include/linux/seqlock_types.h \
  /kernel/include/linux/kcsan.h \
  /kernel/include/linux/rv.h \
    $(wildcard include/config/RV_LTL_MONITOR) \
    $(wildcard include/config/RV_REACTORS) \
  /kernel/include/linux/tracepoint-defs.h \
    $(wildcard include/config/TRACEPOINTS) \
  /kernel/include/linux/unwind_deferred_types.h \
  /kernel-build/arch/arm64/include/generated/asm/kmap_size.h \
  /kernel/include/asm-generic/kmap_size.h \
    $(wildcard include/config/DEBUG_KMAP_LOCAL) \
  /kernel-build/include/generated/rq-offsets.h \
  /kernel/include/linux/sched/ext.h \
    $(wildcard include/config/EXT_GROUP_SCHED) \
  /kernel/include/linux/rhashtable-types.h \
  /kernel/include/linux/alloc_tag.h \
    $(wildcard include/config/MEM_ALLOC_PROFILING_ENABLED_BY_DEFAULT) \
  /kernel/include/linux/codetag.h \
    $(wildcard include/config/CODE_TAGGING) \
  /kernel/include/linux/mutex.h \
  /kernel/include/linux/debug_locks.h \
  /kernel/include/linux/workqueue_types.h \
  /kernel/include/linux/context_tracking_irq.h \
    $(wildcard include/config/CONTEXT_TRACKING_IDLE) \
  /kernel/include/linux/rcutree.h \
  /kernel/include/linux/sysctl.h \
    $(wildcard include/config/SYSCTL) \
  /kernel/include/linux/wait.h \
  /kernel/include/uapi/linux/sysctl.h \
  /kernel/include/linux/rwsem.h \
    $(wildcard include/config/RWSEM_SPIN_ON_OWNER) \
    $(wildcard include/config/DEBUG_RWSEMS) \
  /kernel/include/linux/assoc_array.h \
    $(wildcard include/config/ASSOCIATIVE_ARRAY) \
  /kernel/include/linux/refcount.h \
  /kernel/include/linux/time64.h \
  /kernel/include/linux/math64.h \
    $(wildcard include/config/ARCH_SUPPORTS_INT128) \
  /kernel/include/vdso/math64.h \
  /kernel/include/vdso/time64.h \
  /kernel/include/uapi/linux/time.h \
  /kernel/include/linux/sched/user.h \
    $(wildcard include/config/EPOLL) \
    $(wildcard include/config/VFIO_PCI_ZDEV_KVM) \
    $(wildcard include/config/IOMMUFD) \
    $(wildcard include/config/WATCH_QUEUE) \
  /kernel/include/linux/percpu_counter.h \
  /kernel/include/linux/percpu.h \
    $(wildcard include/config/RANDOM_KMALLOC_CACHES) \
    $(wildcard include/config/PAGE_SIZE_4KB) \
    $(wildcard include/config/NEED_PER_CPU_PAGE_FIRST_CHUNK) \
  /kernel/include/linux/ratelimit.h \
  /kernel/include/linux/fs.h \
    $(wildcard include/config/FANOTIFY_ACCESS_PERMISSIONS) \
    $(wildcard include/config/READ_ONLY_THP_FOR_FS) \
    $(wildcard include/config/FS_POSIX_ACL) \
    $(wildcard include/config/CGROUP_WRITEBACK) \
    $(wildcard include/config/IMA) \
    $(wildcard include/config/FILE_LOCKING) \
    $(wildcard include/config/FSNOTIFY) \
    $(wildcard include/config/UNICODE) \
    $(wildcard include/config/FS_ENCRYPTION) \
    $(wildcard include/config/FS_VERITY) \
    $(wildcard include/config/QUOTA) \
    $(wildcard include/config/FS_DAX) \
    $(wildcard include/config/SWAP) \
    $(wildcard include/config/BLOCK) \
  /kernel/include/linux/vfsdebug.h \
    $(wildcard include/config/DEBUG_VFS) \
  /kernel/include/linux/wait_bit.h \
  /kernel/include/linux/kdev_t.h \
  /kernel/include/uapi/linux/kdev_t.h \
  /kernel/include/linux/dcache.h \
  /kernel/include/linux/rculist.h \
    $(wildcard include/config/PROVE_RCU_LIST) \
  /kernel/include/linux/rculist_bl.h \
  /kernel/include/linux/list_bl.h \
  /kernel/include/linux/bit_spinlock.h \
  /kernel/include/linux/seqlock.h \
  /kernel/include/linux/lockref.h \
    $(wildcard include/config/ARCH_USE_CMPXCHG_LOCKREF) \
  /kernel-build/include/generated/bounds.h \
  /kernel/include/linux/stringhash.h \
    $(wildcard include/config/DCACHE_WORD_ACCESS) \
  /kernel/include/linux/hash.h \
    $(wildcard include/config/HAVE_ARCH_HASH) \
  /kernel/include/linux/path.h \
  /kernel/include/linux/stat.h \
  /kernel/arch/arm64/include/asm/stat.h \
  /kernel-build/arch/arm64/include/generated/uapi/asm/stat.h \
  /kernel/include/uapi/asm-generic/stat.h \
  /kernel/include/linux/time.h \
  /kernel/include/linux/time32.h \
  /kernel/include/linux/timex.h \
  /kernel/include/uapi/linux/timex.h \
  /kernel/arch/arm64/include/asm/timex.h \
  /kernel/arch/arm64/include/asm/arch_timer.h \
    $(wildcard include/config/ARM_ARCH_TIMER_OOL_WORKAROUND) \
  /kernel/include/clocksource/arm_arch_timer.h \
    $(wildcard include/config/ARM_ARCH_TIMER) \
  /kernel/include/linux/timecounter.h \
  /kernel/include/asm-generic/timex.h \
  /kernel/include/vdso/time32.h \
  /kernel/include/vdso/time.h \
  /kernel/arch/arm64/include/asm/compat.h \
  /kernel/include/asm-generic/compat.h \
    $(wildcard include/config/COMPAT_FOR_U64_ALIGNMENT) \
  /kernel/include/linux/sched/task_stack.h \
    $(wildcard include/config/STACK_GROWSUP) \
    $(wildcard include/config/DEBUG_STACK_USAGE) \
  /kernel/include/uapi/linux/magic.h \
  /kernel/include/linux/kasan.h \
    $(wildcard include/config/KASAN_STACK) \
    $(wildcard include/config/KASAN_VMALLOC) \
  /kernel/include/uapi/linux/stat.h \
  /kernel/include/linux/list_lru.h \
  /kernel/include/linux/shrinker.h \
    $(wildcard include/config/SHRINKER_DEBUG) \
  /kernel/include/linux/completion.h \
  /kernel/include/linux/swait.h \
  /kernel/include/linux/xarray.h \
    $(wildcard include/config/XARRAY_MULTI) \
  /kernel/include/linux/gfp.h \
    $(wildcard include/config/ZONE_DMA) \
    $(wildcard include/config/ZONE_DMA32) \
    $(wildcard include/config/ZONE_DEVICE) \
    $(wildcard include/config/CONTIG_ALLOC) \
  /kernel/include/linux/mmzone.h \
    $(wildcard include/config/ARCH_FORCE_MAX_ORDER) \
    $(wildcard include/config/PAGE_BLOCK_MAX_ORDER) \
    $(wildcard include/config/MEMORY_ISOLATION) \
    $(wildcard include/config/ZSMALLOC) \
    $(wildcard include/config/UNACCEPTED_MEMORY) \
    $(wildcard include/config/IOMMU_SUPPORT) \
    $(wildcard include/config/HUGETLB_PAGE) \
    $(wildcard include/config/TRANSPARENT_HUGEPAGE) \
    $(wildcard include/config/LRU_GEN_STATS) \
    $(wildcard include/config/LRU_GEN_WALKS_MMU) \
    $(wildcard include/config/MEMORY_FAILURE) \
    $(wildcard include/config/PAGE_EXTENSION) \
    $(wildcard include/config/DEFERRED_STRUCT_PAGE_INIT) \
    $(wildcard include/config/HAVE_MEMORYLESS_NODES) \
    $(wildcard include/config/SPARSEMEM_EXTREME) \
    $(wildcard include/config/SPARSEMEM_VMEMMAP_PREINIT) \
    $(wildcard include/config/HAVE_ARCH_PFN_VALID) \
  /kernel/include/linux/list_nulls.h \
  /kernel/include/linux/pageblock-flags.h \
    $(wildcard include/config/HUGETLB_PAGE_SIZE_VARIABLE) \
  /kernel/include/linux/page-flags-layout.h \
  /kernel/arch/arm64/include/asm/sparsemem.h \
  /kernel/arch/arm64/include/asm/pgtable-prot.h \
    $(wildcard include/config/HAVE_ARCH_USERFAULTFD_WP) \
  /kernel/arch/arm64/include/asm/rsi.h \
  /kernel/arch/arm64/include/asm/rsi_cmds.h \
  /kernel/include/linux/arm-smccc.h \
    $(wildcard include/config/HAVE_ARM_SMCCC) \
    $(wildcard include/config/ARM) \
  /kernel/include/linux/uuid.h \
  /kernel/arch/arm64/include/asm/rsi_smc.h \
  /kernel/include/linux/mm_types.h \
    $(wildcard include/config/HAVE_ALIGNED_STRUCT_PAGE) \
    $(wildcard include/config/HUGETLB_PMD_PAGE_TABLE_SHARING) \
    $(wildcard include/config/SLAB_FREELIST_HARDENED) \
    $(wildcard include/config/USERFAULTFD) \
    $(wildcard include/config/ANON_VMA_NAME) \
    $(wildcard include/config/PER_VMA_LOCK) \
    $(wildcard include/config/HAVE_ARCH_COMPAT_MMAP_BASES) \
    $(wildcard include/config/MEMBARRIER) \
    $(wildcard include/config/FUTEX_PRIVATE_HASH) \
    $(wildcard include/config/ARCH_HAS_ELF_CORE_EFLAGS) \
    $(wildcard include/config/AIO) \
    $(wildcard include/config/MMU_NOTIFIER) \
    $(wildcard include/config/SPLIT_PMD_PTLOCKS) \
    $(wildcard include/config/IOMMU_MM_DATA) \
    $(wildcard include/config/KSM) \
    $(wildcard include/config/MM_ID) \
    $(wildcard include/config/CORE_DUMP_DEFAULT_ELF_HEADERS) \
  /kernel/include/linux/auxvec.h \
  /kernel/include/uapi/linux/auxvec.h \
  /kernel/arch/arm64/include/uapi/asm/auxvec.h \
  /kernel/include/linux/kref.h \
  /kernel/include/linux/maple_tree.h \
    $(wildcard include/config/MAPLE_RCU_DISABLED) \
    $(wildcard include/config/DEBUG_MAPLE_TREE) \
  /kernel/include/linux/uprobes.h \
  /kernel/include/linux/timer.h \
    $(wildcard include/config/DEBUG_OBJECTS_TIMERS) \
  /kernel/include/linux/ktime.h \
  /kernel/include/linux/jiffies.h \
  /kernel/include/vdso/jiffies.h \
  /kernel-build/include/generated/timeconst.h \
  /kernel/include/vdso/ktime.h \
  /kernel/include/linux/timekeeping.h \
    $(wildcard include/config/POSIX_AUX_CLOCKS) \
    $(wildcard include/config/GENERIC_CMOS_UPDATE) \
  /kernel/include/linux/clocksource_ids.h \
  /kernel/include/linux/debugobjects.h \
    $(wildcard include/config/DEBUG_OBJECTS) \
    $(wildcard include/config/DEBUG_OBJECTS_FREE) \
  /kernel/arch/arm64/include/asm/uprobes.h \
  /kernel/arch/arm64/include/asm/debug-monitors.h \
  /kernel/arch/arm64/include/asm/esr.h \
  /kernel/arch/arm64/include/asm/probes.h \
    $(wildcard include/config/KPROBES) \
  /kernel/include/linux/workqueue.h \
    $(wildcard include/config/DEBUG_OBJECTS_WORK) \
    $(wildcard include/config/FREEZER) \
    $(wildcard include/config/SYSFS) \
    $(wildcard include/config/WQ_WATCHDOG) \
  /kernel/arch/arm64/include/asm/mmu.h \
    $(wildcard include/config/ARM64_E0PD) \
  /kernel/include/linux/page-flags.h \
    $(wildcard include/config/PAGE_IDLE_FLAG) \
    $(wildcard include/config/ARCH_USES_PG_ARCH_2) \
    $(wildcard include/config/ARCH_USES_PG_ARCH_3) \
    $(wildcard include/config/MIGRATION) \
    $(wildcard include/config/HUGETLB_PAGE_OPTIMIZE_VMEMMAP) \
    $(wildcard include/config/DEBUG_KMAP_LOCAL_FORCE_MAP) \
  /kernel/include/linux/local_lock.h \
  /kernel/include/linux/local_lock_internal.h \
  /kernel/include/linux/zswap.h \
    $(wildcard include/config/ZSWAP) \
  /kernel/include/linux/memory_hotplug.h \
    $(wildcard include/config/ARCH_HAS_ADD_PAGES) \
    $(wildcard include/config/MEMORY_HOTREMOVE) \
  /kernel/include/linux/notifier.h \
    $(wildcard include/config/TREE_SRCU) \
  /kernel/include/linux/srcu.h \
    $(wildcard include/config/TINY_SRCU) \
    $(wildcard include/config/NEED_SRCU_NMI_SAFE) \
  /kernel/include/linux/rcu_segcblist.h \
  /kernel/include/linux/srcutree.h \
  /kernel/include/linux/rcu_node_tree.h \
    $(wildcard include/config/RCU_FANOUT) \
    $(wildcard include/config/RCU_FANOUT_LEAF) \
  /kernel/include/linux/topology.h \
    $(wildcard include/config/USE_PERCPU_NUMA_NODE_ID) \
    $(wildcard include/config/SCHED_SMT) \
    $(wildcard include/config/GENERIC_ARCH_TOPOLOGY) \
  /kernel/include/linux/arch_topology.h \
  /kernel/arch/arm64/include/asm/topology.h \
  /kernel/include/asm-generic/topology.h \
  /kernel/include/linux/sched/mm.h \
    $(wildcard include/config/MMU_LAZY_TLB_REFCOUNT) \
    $(wildcard include/config/ARCH_HAS_MEMBARRIER_CALLBACKS) \
    $(wildcard include/config/ARCH_HAS_SYNC_CORE_BEFORE_USERMODE) \
  /kernel/include/linux/sync_core.h \
    $(wildcard include/config/ARCH_HAS_PREPARE_SYNC_CORE_CMD) \
  /kernel/include/linux/sched/coredump.h \
  /kernel/include/linux/radix-tree.h \
  /kernel/include/linux/pid.h \
  /kernel/include/linux/semaphore.h \
  /kernel/include/linux/fcntl.h \
    $(wildcard include/config/ARCH_32BIT_OFF_T) \
  /kernel/include/uapi/linux/fcntl.h \
  /kernel/arch/arm64/include/uapi/asm/fcntl.h \
  /kernel/include/uapi/asm-generic/fcntl.h \
  /kernel/include/uapi/linux/openat2.h \
  /kernel/include/linux/migrate_mode.h \
  /kernel/include/linux/percpu-rwsem.h \
  /kernel/include/linux/rcuwait.h \
  /kernel/include/linux/sched/signal.h \
    $(wildcard include/config/SCHED_AUTOGROUP) \
    $(wildcard include/config/BSD_PROCESS_ACCT) \
    $(wildcard include/config/TASKSTATS) \
  /kernel/include/linux/signal.h \
    $(wildcard include/config/DYNAMIC_SIGFRAME) \
    $(wildcard include/config/PROC_FS) \
  /kernel/include/linux/sched/jobctl.h \
  /kernel/include/linux/sched/task.h \
    $(wildcard include/config/GKI_DYNAMIC_TASK_STRUCT_SIZE) \
    $(wildcard include/config/GKI_TASK_STRUCT_VENDOR_SIZE_MAX) \
    $(wildcard include/config/HAVE_EXIT_THREAD) \
    $(wildcard include/config/ARCH_WANTS_DYNAMIC_TASK_STRUCT) \
    $(wildcard include/config/HAVE_ARCH_THREAD_STRUCT_WHITELIST) \
  /kernel/include/linux/uaccess.h \
    $(wildcard include/config/ARCH_HAS_SUBPAGE_FAULTS) \
    $(wildcard include/config/HARDENED_USERCOPY) \
  /kernel/include/linux/fault-inject-usercopy.h \
    $(wildcard include/config/FAULT_INJECTION_USERCOPY) \
  /kernel/include/linux/nospec.h \
  /kernel/include/linux/ucopysize.h \
    $(wildcard include/config/HARDENED_USERCOPY_DEFAULT_ON) \
  /kernel/arch/arm64/include/asm/uaccess.h \
    $(wildcard include/config/CC_HAS_ASM_GOTO_OUTPUT) \
  /kernel/arch/arm64/include/asm/kernel-pgtable.h \
    $(wildcard include/config/RELOCATABLE) \
  /kernel/arch/arm64/include/asm/asm-extable.h \
  /kernel/arch/arm64/include/asm/mte.h \
  /kernel/arch/arm64/include/asm/extable.h \
    $(wildcard include/config/BPF_JIT) \
  /kernel/include/asm-generic/access_ok.h \
    $(wildcard include/config/ALTERNATE_USER_ADDRESS_SPACE) \
  /kernel/include/linux/posix-timers.h \
  /kernel/include/linux/alarmtimer.h \
    $(wildcard include/config/RTC_CLASS) \
  /kernel/include/linux/hrtimer.h \
    $(wildcard include/config/HIGH_RES_TIMERS) \
    $(wildcard include/config/TIME_LOW_RES) \
    $(wildcard include/config/TIMERFD) \
  /kernel/include/linux/hrtimer_defs.h \
  /kernel/include/linux/timerqueue.h \
  /kernel/include/linux/rcuref.h \
  /kernel/include/linux/rcu_sync.h \
  /kernel/include/linux/delayed_call.h \
  /kernel/include/linux/errseq.h \
  /kernel/include/linux/ioprio.h \
  /kernel/include/linux/sched/rt.h \
  /kernel/include/linux/iocontext.h \
    $(wildcard include/config/BLK_ICQ) \
  /kernel/include/uapi/linux/ioprio.h \
  /kernel/include/linux/fs_types.h \
  /kernel/include/linux/mount.h \
  /kernel/include/linux/mnt_idmapping.h \
  /kernel/include/linux/slab.h \
    $(wildcard include/config/FAILSLAB) \
    $(wildcard include/config/KFENCE) \
    $(wildcard include/config/SLUB_TINY) \
    $(wildcard include/config/SLUB_DEBUG) \
    $(wildcard include/config/SLAB_BUCKETS) \
    $(wildcard include/config/KVFREE_RCU_BATCHED) \
  /kernel/include/linux/percpu-refcount.h \
  /kernel/include/linux/rw_hint.h \
  /kernel/include/linux/file_ref.h \
  /kernel/include/linux/unicode.h \
  /kernel/include/uapi/linux/fs.h \
  /kernel/include/linux/quota.h \
    $(wildcard include/config/QUOTA_NETLINK_INTERFACE) \
  /kernel/include/uapi/linux/dqblk_xfs.h \
  /kernel/include/linux/dqblk_v1.h \
  /kernel/include/linux/dqblk_v2.h \
  /kernel/include/linux/dqblk_qtree.h \
  /kernel/include/linux/projid.h \
  /kernel/include/uapi/linux/quota.h \
  /kernel/include/linux/mm.h \
    $(wildcard include/config/HAVE_ARCH_MMAP_RND_BITS) \
    $(wildcard include/config/HAVE_ARCH_MMAP_RND_COMPAT_BITS) \
    $(wildcard include/config/MEM_SOFT_DIRTY) \
    $(wildcard include/config/ARCH_USES_HIGH_VMA_FLAGS) \
    $(wildcard include/config/ARCH_HAS_PKEYS) \
    $(wildcard include/config/ARCH_PKEY_BITS) \
    $(wildcard include/config/X86_USER_SHADOW_STACK) \
    $(wildcard include/config/PPC64) \
    $(wildcard include/config/PARISC) \
    $(wildcard include/config/SPARC64) \
    $(wildcard include/config/HAVE_ARCH_USERFAULTFD_MINOR) \
    $(wildcard include/config/PPC32) \
    $(wildcard include/config/FIND_NORMAL_PAGE) \
    $(wildcard include/config/SHMEM) \
    $(wildcard include/config/HAVE_ARCH_TRANSPARENT_HUGEPAGE_PUD) \
    $(wildcard include/config/HAVE_GIGANTIC_FOLIOS) \
    $(wildcard include/config/ARCH_HAS_PTE_SPECIAL) \
    $(wildcard include/config/ARCH_SUPPORTS_PMD_PFNMAP) \
    $(wildcard include/config/ARCH_SUPPORTS_PUD_PFNMAP) \
    $(wildcard include/config/ASYNC_KERNEL_PGTABLE_FREE) \
    $(wildcard include/config/SPLIT_PTE_PTLOCKS) \
    $(wildcard include/config/HIGHPTE) \
    $(wildcard include/config/DEBUG_VM_RB) \
    $(wildcard include/config/PAGE_POISONING) \
    $(wildcard include/config/INIT_ON_ALLOC_DEFAULT_ON) \
    $(wildcard include/config/INIT_ON_FREE_DEFAULT_ON) \
    $(wildcard include/config/DEBUG_PAGEALLOC) \
    $(wildcard include/config/ARCH_WANT_OPTIMIZE_DAX_VMEMMAP) \
    $(wildcard include/config/HUGETLBFS) \
    $(wildcard include/config/MAPPING_DIRTY_HELPERS) \
    $(wildcard include/config/MSEAL_SYSTEM_MAPPINGS) \
    $(wildcard include/config/PAGE_POOL) \
  /kernel/include/linux/pgalloc_tag.h \
  /kernel/include/linux/page_ext.h \
  /kernel/include/linux/stacktrace.h \
    $(wildcard include/config/ARCH_STACKWALK) \
    $(wildcard include/config/STACKTRACE) \
    $(wildcard include/config/HAVE_RELIABLE_STACKTRACE) \
  /kernel/include/linux/mmap_lock.h \
  /kernel/include/linux/range.h \
  /kernel/include/linux/page_ref.h \
    $(wildcard include/config/DEBUG_PAGE_REF) \
  /kernel/include/linux/pgtable.h \
    $(wildcard include/config/ARCH_HAS_NONLEAF_PMD_YOUNG) \
    $(wildcard include/config/ARCH_HAS_HW_PTE_YOUNG) \
    $(wildcard include/config/GUP_GET_PXX_LOW_HIGH) \
    $(wildcard include/config/ARCH_WANT_PMD_MKWRITE) \
    $(wildcard include/config/HAVE_ARCH_SOFT_DIRTY) \
    $(wildcard include/config/ARCH_ENABLE_THP_MIGRATION) \
    $(wildcard include/config/HAVE_ARCH_HUGE_VMAP) \
    $(wildcard include/config/X86_ESPFIX64) \
  /kernel/arch/arm64/include/asm/pgtable.h \
    $(wildcard include/config/PAGE_TABLE_CHECK) \
    $(wildcard include/config/ARM64_CONTPTE) \
  /kernel/arch/arm64/include/asm/proc-fns.h \
  /kernel/arch/arm64/include/asm/tlbflush.h \
  /kernel/include/linux/mmu_notifier.h \
  /kernel/include/linux/interval_tree.h \
  /kernel/arch/arm64/include/asm/fixmap.h \
    $(wildcard include/config/ACPI_APEI_GHES) \
    $(wildcard include/config/ARM_SDE_INTERFACE) \
  /kernel/include/asm-generic/fixmap.h \
  /kernel/arch/arm64/include/asm/por.h \
  /kernel/include/linux/page_table_check.h \
  /kernel/include/asm-generic/pgtable_uffd.h \
  /kernel/include/linux/pgsize_migration_inline.h \
  /kernel/include/linux/memremap.h \
    $(wildcard include/config/DEVICE_PRIVATE) \
    $(wildcard include/config/PCI_P2PDMA) \
  /kernel/include/linux/ioport.h \
  /kernel/include/linux/cacheinfo.h \
    $(wildcard include/config/ACPI_PPTT) \
    $(wildcard include/config/ARCH_HAS_CPU_CACHE_ALIASING) \
  /kernel/include/linux/cpuhplock.h \
  /kernel/include/linux/huge_mm.h \
    $(wildcard include/config/PGTABLE_HAS_HUGE_LEAVES) \
    $(wildcard include/config/PERSISTENT_HUGE_ZERO_FOLIO) \
  /kernel/include/linux/kobject.h \
    $(wildcard include/config/UEVENT_HELPER) \
    $(wildcard include/config/DEBUG_KOBJECT_RELEASE) \
  /kernel/include/linux/sysfs.h \
  /kernel/include/linux/kernfs.h \
    $(wildcard include/config/KERNFS) \
  /kernel/include/linux/idr.h \
  /kernel/include/linux/kobject_ns.h \
  /kernel/include/linux/vmstat.h \
    $(wildcard include/config/VM_EVENT_COUNTERS) \
    $(wildcard include/config/DEBUG_TLBFLUSH) \
    $(wildcard include/config/PER_VMA_LOCK_STATS) \
  /kernel/include/linux/vm_event_item.h \
    $(wildcard include/config/MEMORY_BALLOON) \
    $(wildcard include/config/BALLOON_COMPACTION) \
    $(wildcard include/config/X86) \
  /kernel/include/linux/ptrace.h \
  /kernel/include/linux/pid_namespace.h \
    $(wildcard include/config/MEMFD_CREATE) \
    $(wildcard include/config/PID_NS) \
  /kernel/include/linux/nsproxy.h \
  /kernel/include/linux/ns_common.h \
    $(wildcard include/config/IPC_NS) \
    $(wildcard include/config/NET_NS) \
    $(wildcard include/config/TIME_NS) \
    $(wildcard include/config/UTS_NS) \
  /kernel/include/uapi/linux/ptrace.h \
  /kernel/include/linux/seccomp.h \
    $(wildcard include/config/HAVE_ARCH_SECCOMP_FILTER) \
    $(wildcard include/config/SECCOMP_FILTER) \
    $(wildcard include/config/CHECKPOINT_RESTORE) \
    $(wildcard include/config/SECCOMP_CACHE_DEBUG) \
  /kernel/include/uapi/linux/seccomp.h \
  /kernel/arch/arm64/include/asm/seccomp.h \
  /kernel-build/arch/arm64/include/generated/asm/unistd_compat_32.h \
  /kernel/include/asm-generic/seccomp.h \
  /kernel/include/uapi/linux/unistd.h \
  /kernel/arch/arm64/include/asm/unistd.h \
  /kernel-build/arch/arm64/include/generated/uapi/asm/unistd_64.h \
  /kernel-build/include/generated/uapi/linux/version.h \
  /kernel/include/linux/vmalloc.h \
    $(wildcard include/config/HAVE_ARCH_HUGE_VMALLOC) \
  /kernel/arch/arm64/include/asm/vmalloc.h \
  /kernel/security/selinux/include/security.h \
    $(wildcard include/config/SECURITY_SELINUX_DEVELOP) \
    $(wildcard include/config/NETLABEL) \
  /kernel/include/linux/delay.h \
  /kernel-build/arch/arm64/include/generated/asm/delay.h \
  /kernel/include/asm-generic/delay.h \
  /kernel-build/security/selinux/flask.h \
  /kernel/security/selinux/include/policycap.h \
  /kernel/security/selinux/include/objsec.h \
  /kernel/include/linux/binfmts.h \
    $(wildcard include/config/COREDUMP) \
    $(wildcard include/config/BINFMT_MISC) \
  /kernel/arch/arm64/include/asm/exec.h \
  /kernel/include/uapi/linux/binfmts.h \
  /kernel/include/linux/in.h \
  /kernel/include/uapi/linux/in.h \
  /kernel/include/uapi/linux/libc-compat.h \
  /kernel/include/linux/socket.h \
  /kernel-build/arch/arm64/include/generated/uapi/asm/socket.h \
  /kernel/include/uapi/asm-generic/socket.h \
  /kernel-build/arch/arm64/include/generated/uapi/asm/sockios.h \
  /kernel/include/uapi/asm-generic/sockios.h \
  /kernel/include/uapi/linux/sockios.h \
  /kernel/include/linux/uio.h \
    $(wildcard include/config/ARCH_HAS_COPY_MC) \
  /kernel/include/uapi/linux/uio.h \
  /kernel/include/uapi/linux/socket.h \
  /kernel/include/linux/lsm_hooks.h \
    $(wildcard include/config/LSM) \
  /kernel/include/uapi/linux/lsm.h \
  /kernel/include/linux/security.h \
    $(wildcard include/config/SECURITY_NETWORK) \
    $(wildcard include/config/SECURITY_INFINIBAND) \
    $(wildcard include/config/SECURITY_NETWORK_XFRM) \
    $(wildcard include/config/SECURITY_PATH) \
    $(wildcard include/config/SECURITYFS) \
  /kernel/include/linux/kernel_read_file.h \
  /kernel/include/linux/file.h \
  /kernel/include/linux/sockptr.h \
  /kernel/include/linux/bpf.h \
    $(wildcard include/config/CGROUP_BPF) \
    $(wildcard include/config/DEBUG_KERNEL) \
    $(wildcard include/config/FINEIBT) \
    $(wildcard include/config/BPF_LSM) \
    $(wildcard include/config/BPF_JIT_ALWAYS_ON) \
    $(wildcard include/config/BPF_EVENTS) \
    $(wildcard include/config/INET) \
  /kernel/include/uapi/linux/bpf.h \
    $(wildcard include/config/BPF_LIRC_MODE2) \
    $(wildcard include/config/EFFICIENT_UNALIGNED_ACCESS) \
    $(wildcard include/config/CGROUP_NET_CLASSID) \
    $(wildcard include/config/IP_ROUTE_CLASSID) \
    $(wildcard include/config/BPF_KPROBE_OVERRIDE) \
    $(wildcard include/config/XFRM) \
    $(wildcard include/config/SOCK_CGROUP_DATA) \
    $(wildcard include/config/IPV6) \
  /kernel/include/uapi/linux/bpf_common.h \
  /kernel/include/uapi/linux/filter.h \
  /kernel/include/crypto/sha2.h \
  /kernel/include/linux/rbtree_latch.h \
  /kernel/include/linux/module.h \
    $(wildcard include/config/MODULES_TREE_LOOKUP) \
    $(wildcard include/config/STACKTRACE_BUILD_ID) \
    $(wildcard include/config/ARCH_USES_CFI_TRAPS) \
    $(wildcard include/config/KALLSYMS) \
    $(wildcard include/config/DEBUG_INFO_BTF_MODULES) \
    $(wildcard include/config/EVENT_TRACING) \
    $(wildcard include/config/MODULE_UNLOAD) \
    $(wildcard include/config/CONSTRUCTORS) \
    $(wildcard include/config/FUNCTION_ERROR_INJECTION) \
    $(wildcard include/config/MITIGATION_RETPOLINE) \
    $(wildcard include/config/MODULE_SIG) \
  /kernel/include/linux/buildid.h \
    $(wildcard include/config/VMCORE_INFO) \
  /kernel/include/linux/kmod.h \
  /kernel/include/linux/umh.h \
  /kernel/include/linux/elf.h \
    $(wildcard include/config/ARCH_HAVE_EXTRA_ELF_NOTES) \
    $(wildcard include/config/ARCH_USE_GNU_PROPERTY) \
    $(wildcard include/config/ARCH_HAVE_ELF_PROT) \
  /kernel/arch/arm64/include/asm/elf.h \
    $(wildcard include/config/COMPAT_VDSO) \
  /kernel-build/arch/arm64/include/generated/asm/user.h \
  /kernel/include/asm-generic/user.h \
  /kernel/include/uapi/linux/elf.h \
  /kernel/include/uapi/linux/elf-em.h \
  /kernel/include/linux/moduleparam.h \
    $(wildcard include/config/ALPHA) \
  /kernel/include/linux/error-injection.h \
  /kernel/include/asm-generic/error-injection.h \
  /kernel/include/linux/dynamic_debug.h \
  /kernel/arch/arm64/include/asm/module.h \
  /kernel/include/asm-generic/module.h \
    $(wildcard include/config/HAVE_MOD_ARCH_SPECIFIC) \
  /kernel/include/linux/kallsyms.h \
    $(wildcard include/config/KALLSYMS_ALL) \
  /kernel/include/linux/bpfptr.h \
  /kernel/include/linux/btf.h \
  /kernel/include/linux/bsearch.h \
  /kernel/include/linux/btf_ids.h \
  /kernel/include/uapi/linux/btf.h \
  /kernel/include/linux/rcupdate_trace.h \
    $(wildcard include/config/TASKS_TRACE_RCU_READ_MB) \
  /kernel/include/linux/static_call.h \
  /kernel/include/linux/cpu.h \
    $(wildcard include/config/GENERIC_CPU_DEVICES) \
    $(wildcard include/config/PM_SLEEP_SMP) \
    $(wildcard include/config/PM_SLEEP_SMP_NONZERO_CPU) \
    $(wildcard include/config/ARCH_HAS_CPU_FINALIZE_INIT) \
    $(wildcard include/config/CPU_MITIGATIONS) \
  /kernel/include/linux/node.h \
    $(wildcard include/config/HMEM_REPORTING) \
  /kernel/include/linux/device.h \
    $(wildcard include/config/GENERIC_MSI_IRQ) \
    $(wildcard include/config/ENERGY_MODEL) \
    $(wildcard include/config/PINCTRL) \
    $(wildcard include/config/ARCH_HAS_DMA_OPS) \
    $(wildcard include/config/DMA_DECLARE_COHERENT) \
    $(wildcard include/config/DMA_CMA) \
    $(wildcard include/config/SWIOTLB) \
    $(wildcard include/config/SWIOTLB_DYNAMIC) \
    $(wildcard include/config/ARCH_HAS_SYNC_DMA_FOR_DEVICE) \
    $(wildcard include/config/ARCH_HAS_SYNC_DMA_FOR_CPU) \
    $(wildcard include/config/ARCH_HAS_SYNC_DMA_FOR_CPU_ALL) \
    $(wildcard include/config/DMA_OPS_BYPASS) \
    $(wildcard include/config/DMA_NEED_SYNC) \
    $(wildcard include/config/IOMMU_DMA) \
    $(wildcard include/config/PM) \
    $(wildcard include/config/PM_SLEEP) \
    $(wildcard include/config/OF) \
    $(wildcard include/config/DEVTMPFS) \
  /kernel/include/linux/dev_printk.h \
  /kernel/include/linux/energy_model.h \
  /kernel/include/linux/sched/cpufreq.h \
    $(wildcard include/config/CPU_FREQ) \
  /kernel/include/linux/sched/topology.h \
    $(wildcard include/config/SCHED_CLUSTER) \
    $(wildcard include/config/SCHED_MC) \
    $(wildcard include/config/CPU_FREQ_GOV_SCHEDUTIL) \
  /kernel/include/linux/sched/idle.h \
  /kernel/include/linux/sched/sd_flags.h \
  /kernel/include/linux/klist.h \
  /kernel/include/linux/pm.h \
    $(wildcard include/config/VT_CONSOLE_SLEEP) \
    $(wildcard include/config/CXL_SUSPEND) \
    $(wildcard include/config/PM_CLK) \
    $(wildcard include/config/PM_GENERIC_DOMAINS) \
  /kernel/include/linux/device/bus.h \
    $(wildcard include/config/ACPI) \
  /kernel/include/linux/device/class.h \
  /kernel/include/linux/device/devres.h \
    $(wildcard include/config/HAS_IOMEM) \
  /kernel/include/linux/device/driver.h \
  /kernel/arch/arm64/include/asm/device.h \
  /kernel/include/linux/pm_wakeup.h \
  /kernel/include/linux/cpuhotplug.h \
    $(wildcard include/config/HOTPLUG_CORE_SYNC_DEAD) \
  /kernel/include/linux/cpu_smt.h \
    $(wildcard include/config/HOTPLUG_SMT) \
  /kernel/include/linux/memcontrol.h \
    $(wildcard include/config/MEMCG_NMI_SAFETY_REQUIRES_ATOMIC) \
  /kernel/include/linux/cgroup.h \
    $(wildcard include/config/DEBUG_CGROUP_REF) \
    $(wildcard include/config/CGROUP_CPUACCT) \
    $(wildcard include/config/CGROUP_DATA) \
  /kernel/include/uapi/linux/cgroupstats.h \
  /kernel/include/uapi/linux/taskstats.h \
  /kernel/include/linux/seq_file.h \
  /kernel/include/linux/string_helpers.h \
  /kernel/include/linux/ctype.h \
  /kernel/include/linux/string_choices.h \
  /kernel/include/linux/user_namespace.h \
    $(wildcard include/config/INOTIFY_USER) \
    $(wildcard include/config/FANOTIFY) \
    $(wildcard include/config/PERSISTENT_KEYRINGS) \
  /kernel/include/linux/rculist_nulls.h \
  /kernel/include/linux/kernel_stat.h \
    $(wildcard include/config/GENERIC_IRQ_STAT_SNAPSHOT) \
  /kernel/include/linux/interrupt.h \
    $(wildcard include/config/IRQ_FORCED_THREADING) \
    $(wildcard include/config/RT_SOFTIRQ_AWARE_SCHED) \
    $(wildcard include/config/GENERIC_IRQ_PROBE) \
    $(wildcard include/config/IRQ_TIMINGS) \
  /kernel/include/linux/irqreturn.h \
  /kernel/include/linux/hardirq.h \
  /kernel/include/linux/context_tracking_state.h \
    $(wildcard include/config/CONTEXT_TRACKING_USER) \
    $(wildcard include/config/CONTEXT_TRACKING) \
  /kernel/include/linux/ftrace_irq.h \
    $(wildcard include/config/HWLAT_TRACER) \
    $(wildcard include/config/OSNOISE_TRACER) \
  /kernel/include/linux/vtime.h \
    $(wildcard include/config/VIRT_CPU_ACCOUNTING) \
    $(wildcard include/config/IRQ_TIME_ACCOUNTING) \
  /kernel/arch/arm64/include/asm/hardirq.h \
  /kernel/arch/arm64/include/asm/irq.h \
  /kernel/include/asm-generic/irq.h \
  /kernel/arch/arm64/include/asm/kvm_arm.h \
  /kernel/include/asm-generic/hardirq.h \
  /kernel/include/linux/irq.h \
    $(wildcard include/config/GENERIC_IRQ_EFFECTIVE_AFF_MASK) \
    $(wildcard include/config/GENERIC_IRQ_IPI) \
    $(wildcard include/config/IRQ_DOMAIN_HIERARCHY) \
    $(wildcard include/config/DEPRECATED_IRQ_CPU_ONOFFLINE) \
    $(wildcard include/config/GENERIC_IRQ_MIGRATION) \
    $(wildcard include/config/GENERIC_PENDING_IRQ) \
    $(wildcard include/config/HARDIRQS_SW_RESEND) \
    $(wildcard include/config/GENERIC_IRQ_CHIP) \
    $(wildcard include/config/GENERIC_IRQ_MULTI_HANDLER) \
  /kernel/include/linux/irqhandler.h \
  /kernel/include/linux/io.h \
    $(wildcard include/config/HAS_IOPORT_MAP) \
    $(wildcard include/config/PCI) \
    $(wildcard include/config/STRICT_DEVMEM) \
  /kernel/arch/arm64/include/asm/io.h \
  /kernel-build/arch/arm64/include/generated/asm/early_ioremap.h \
  /kernel/include/asm-generic/early_ioremap.h \
    $(wildcard include/config/GENERIC_EARLY_IOREMAP) \
  /kernel/include/asm-generic/io.h \
    $(wildcard include/config/GENERIC_IOMAP) \
    $(wildcard include/config/TRACE_MMIO_ACCESS) \
    $(wildcard include/config/HAS_IOPORT) \
    $(wildcard include/config/GENERIC_IOREMAP) \
  /kernel/include/asm-generic/pci_iomap.h \
    $(wildcard include/config/NO_GENERIC_PCI_IOPORT_MAP) \
    $(wildcard include/config/GENERIC_PCI_IOMAP) \
  /kernel/include/linux/logic_pio.h \
    $(wildcard include/config/INDIRECT_PIO) \
  /kernel/include/linux/fwnode.h \
  /kernel-build/arch/arm64/include/generated/asm/irq_regs.h \
  /kernel/include/asm-generic/irq_regs.h \
  /kernel/include/linux/irqdesc.h \
    $(wildcard include/config/GENERIC_IRQ_DEBUGFS) \
    $(wildcard include/config/SPARSE_IRQ) \
    $(wildcard include/config/IRQ_DOMAIN) \
  /kernel-build/arch/arm64/include/generated/asm/hw_irq.h \
  /kernel/include/asm-generic/hw_irq.h \
  /kernel/include/linux/cgroup-defs.h \
    $(wildcard include/config/CGROUP_NET_PRIO) \
  /kernel/include/linux/u64_stats_sync.h \
  /kernel-build/arch/arm64/include/generated/asm/local64.h \
  /kernel/include/asm-generic/local64.h \
  /kernel-build/arch/arm64/include/generated/asm/local.h \
  /kernel/include/asm-generic/local.h \
  /kernel/include/linux/bpf-cgroup-defs.h \
  /kernel/include/linux/psi_types.h \
  /kernel/include/linux/kthread.h \
  /kernel/include/linux/cgroup_subsys.h \
    $(wildcard include/config/CGROUP_DEVICE) \
    $(wildcard include/config/CGROUP_FREEZER) \
    $(wildcard include/config/CGROUP_PERF) \
    $(wildcard include/config/CGROUP_HUGETLB) \
    $(wildcard include/config/CGROUP_PIDS) \
    $(wildcard include/config/CGROUP_RDMA) \
    $(wildcard include/config/CGROUP_MISC) \
    $(wildcard include/config/CGROUP_DMEM) \
    $(wildcard include/config/CGROUP_DEBUG) \
  /kernel/include/linux/cgroup_namespace.h \
  /kernel/include/linux/cgroup_refcnt.h \
  /kernel/include/linux/page_counter.h \
  /kernel/include/linux/vmpressure.h \
  /kernel/include/linux/eventfd.h \
  /kernel/include/uapi/linux/eventfd.h \
  /kernel/include/linux/writeback.h \
  /kernel/include/linux/flex_proportions.h \
  /kernel/include/linux/backing-dev-defs.h \
    $(wildcard include/config/DEBUG_FS) \
  /kernel/include/linux/blk_types.h \
    $(wildcard include/config/FAIL_MAKE_REQUEST) \
    $(wildcard include/config/BLK_CGROUP_IOCOST) \
    $(wildcard include/config/BLK_INLINE_ENCRYPTION) \
    $(wildcard include/config/DM_DEFAULT_KEY) \
    $(wildcard include/config/BLK_DEV_INTEGRITY) \
  /kernel/include/linux/bvec.h \
  /kernel/include/linux/highmem.h \
  /kernel/include/linux/cacheflush.h \
  /kernel/arch/arm64/include/asm/cacheflush.h \
  /kernel/include/linux/kgdb.h \
    $(wildcard include/config/HAVE_ARCH_KGDB) \
    $(wildcard include/config/KGDB) \
    $(wildcard include/config/KGDB_HONOUR_BLOCKLIST) \
  /kernel/include/linux/kprobes.h \
    $(wildcard include/config/KRETPROBE_ON_RETHOOK) \
    $(wildcard include/config/OPTPROBES) \
    $(wildcard include/config/KPROBES_ON_FTRACE) \
  /kernel/include/linux/ftrace.h \
    $(wildcard include/config/HAVE_FUNCTION_GRAPH_FREGS) \
    $(wildcard include/config/FUNCTION_TRACER) \
    $(wildcard include/config/HAVE_DYNAMIC_FTRACE_WITH_ARGS) \
    $(wildcard include/config/HAVE_FTRACE_REGS_HAVING_PT_REGS) \
    $(wildcard include/config/HAVE_REGS_AND_STACK_ACCESS_API) \
    $(wildcard include/config/DYNAMIC_FTRACE_WITH_REGS) \
    $(wildcard include/config/DYNAMIC_FTRACE_WITH_ARGS) \
    $(wildcard include/config/DYNAMIC_FTRACE_WITH_DIRECT_CALLS) \
    $(wildcard include/config/STACK_TRACER) \
    $(wildcard include/config/DYNAMIC_FTRACE_WITH_CALL_OPS) \
    $(wildcard include/config/FRAME_POINTER) \
    $(wildcard include/config/FUNCTION_GRAPH_RETVAL) \
    $(wildcard include/config/FTRACE_SYSCALLS) \
  /kernel/include/linux/trace_recursion.h \
    $(wildcard include/config/FTRACE_RECORD_RECURSION) \
    $(wildcard include/config/FTRACE_VALIDATE_RCU_IS_WATCHING) \
  /kernel/include/linux/trace_clock.h \
  /kernel-build/arch/arm64/include/generated/asm/trace_clock.h \
  /kernel/include/asm-generic/trace_clock.h \
  /kernel/arch/arm64/include/asm/ftrace.h \
  /kernel/include/linux/compat.h \
    $(wildcard include/config/ARCH_HAS_SYSCALL_WRAPPER) \
    $(wildcard include/config/X86_X32_ABI) \
    $(wildcard include/config/COMPAT_OLD_SIGACTION) \
    $(wildcard include/config/ODD_RT_SIGACTION) \
  /kernel/include/linux/sem.h \
  /kernel/include/uapi/linux/sem.h \
  /kernel/include/linux/ipc.h \
  /kernel/include/uapi/linux/ipc.h \
  /kernel-build/arch/arm64/include/generated/uapi/asm/ipcbuf.h \
  /kernel/include/uapi/asm-generic/ipcbuf.h \
  /kernel-build/arch/arm64/include/generated/uapi/asm/sembuf.h \
  /kernel/include/uapi/asm-generic/sembuf.h \
  /kernel/include/uapi/linux/if.h \
  /kernel/include/uapi/linux/hdlc/ioctl.h \
  /kernel/include/uapi/linux/aio_abi.h \
  /kernel/arch/arm64/include/asm/syscall_wrapper.h \
  /kernel/include/linux/objpool.h \
  /kernel/include/linux/rethook.h \
  /kernel/arch/arm64/include/asm/kprobes.h \
  /kernel/include/asm-generic/kprobes.h \
  /kernel/arch/arm64/include/asm/kgdb.h \
  /kernel/include/asm-generic/cacheflush.h \
  /kernel/include/linux/kmsan.h \
  /kernel/include/linux/dma-direction.h \
  /kernel/include/linux/highmem-internal.h \
  /kernel/include/linux/pagevec.h \
  /kernel/include/linux/bio.h \
    $(wildcard include/config/BLK_DEV_ZONED) \
  /kernel/include/linux/mempool.h \
  /kernel/include/linux/cfi.h \
  /kernel/arch/arm64/include/asm/cfi.h \
  /kernel/arch/arm64/include/asm/rqspinlock.h \
  /kernel/include/asm-generic/rqspinlock.h \
    $(wildcard include/config/QUEUED_SPINLOCKS) \
  /kernel/include/linux/bpf_types.h \
    $(wildcard include/config/NETFILTER_BPF_LINK) \
    $(wildcard include/config/FUSE_BPF) \
    $(wildcard include/config/XDP_SOCKETS) \
  /kernel/include/linux/lsm/selinux.h \
    $(wildcard include/config/SECURITY_SELINUX) \
  /kernel/include/linux/lsm/smack.h \
    $(wildcard include/config/SECURITY_SMACK) \
  /kernel/include/linux/lsm/apparmor.h \
    $(wildcard include/config/SECURITY_APPARMOR) \
  /kernel/include/linux/lsm/bpf.h \
  /kernel/include/linux/xattr.h \
  /kernel/include/uapi/linux/xattr.h \
  /kernel/include/linux/unroll.h \
    $(wildcard include/config/CC_IS_CLANG) \
  /kernel/include/linux/lsm_count.h \
    $(wildcard include/config/SECURITY_TOMOYO) \
    $(wildcard include/config/SECURITY_YAMA) \
    $(wildcard include/config/SECURITY_LOADPIN) \
    $(wildcard include/config/SECURITY_LOCKDOWN_LSM) \
    $(wildcard include/config/SECURITY_SAFESETID) \
    $(wildcard include/config/SECURITY_LANDLOCK) \
    $(wildcard include/config/EVM) \
    $(wildcard include/config/SECURITY_IPE) \
  /kernel/include/linux/lsm_hook_defs.h \
  /kernel/include/linux/msg.h \
  /kernel/include/uapi/linux/msg.h \
  /kernel-build/arch/arm64/include/generated/uapi/asm/msgbuf.h \
  /kernel/include/uapi/asm-generic/msgbuf.h \
  /kernel/include/net/net_namespace.h \
    $(wildcard include/config/NF_CONNTRACK) \
    $(wildcard include/config/NF_FLOW_TABLE) \
    $(wildcard include/config/UNIX) \
    $(wildcard include/config/IEEE802154_6LOWPAN) \
    $(wildcard include/config/IP_SCTP) \
    $(wildcard include/config/NETFILTER) \
    $(wildcard include/config/NF_TABLES) \
    $(wildcard include/config/WEXT_CORE) \
    $(wildcard include/config/IP_VS) \
    $(wildcard include/config/MPLS) \
    $(wildcard include/config/CAN) \
    $(wildcard include/config/MCTP) \
    $(wildcard include/config/CRYPTO_USER) \
    $(wildcard include/config/SMC) \
    $(wildcard include/config/DEBUG_NET_SMALL_RTNL) \
    $(wildcard include/config/NET_NS_REFCNT_TRACKER) \
  /kernel/include/net/flow.h \
  /kernel/include/linux/in6.h \
  /kernel/include/uapi/linux/in6.h \
  /kernel/include/net/inet_dscp.h \
  /kernel/include/net/netns/core.h \
    $(wildcard include/config/RPS) \
  /kernel/include/net/netns/mib.h \
    $(wildcard include/config/XFRM_STATISTICS) \
    $(wildcard include/config/TLS) \
    $(wildcard include/config/MPTCP) \
  /kernel/include/net/snmp.h \
  /kernel/include/uapi/linux/snmp.h \
  /kernel/include/net/netns/unix.h \
  /kernel/include/net/netns/packet.h \
  /kernel/include/net/netns/ipv4.h \
    $(wildcard include/config/IP_ROUTE_MULTIPATH) \
    $(wildcard include/config/NET_UDP_TUNNEL) \
    $(wildcard include/config/IP_MULTIPLE_TABLES) \
    $(wildcard include/config/NET_L3_MASTER_DEV) \
    $(wildcard include/config/IP_MROUTE) \
    $(wildcard include/config/IP_MROUTE_MULTIPLE_TABLES) \
  /kernel/include/net/inet_frag.h \
  /kernel/include/net/dropreason-core.h \
  /kernel/include/linux/siphash.h \
    $(wildcard include/config/HAVE_EFFICIENT_UNALIGNED_ACCESS) \
  /kernel/include/net/netns/ipv6.h \
    $(wildcard include/config/IPV6_MULTIPLE_TABLES) \
    $(wildcard include/config/IPV6_SUBTREES) \
    $(wildcard include/config/IPV6_MROUTE) \
    $(wildcard include/config/IPV6_MROUTE_MULTIPLE_TABLES) \
    $(wildcard include/config/NF_DEFRAG_IPV6) \
  /kernel/include/net/dst_ops.h \
  /kernel/include/uapi/linux/icmpv6.h \
  /kernel/include/net/netns/nexthop.h \
  /kernel/include/net/netns/ieee802154_6lowpan.h \
  /kernel/include/net/netns/sctp.h \
  /kernel/include/net/netns/netfilter.h \
    $(wildcard include/config/LWTUNNEL) \
    $(wildcard include/config/NETFILTER_FAMILY_ARP) \
    $(wildcard include/config/NETFILTER_FAMILY_BRIDGE) \
    $(wildcard include/config/NF_DEFRAG_IPV4) \
  /kernel/include/linux/netfilter_defs.h \
  /kernel/include/uapi/linux/netfilter.h \
  /kernel/include/net/netns/conntrack.h \
    $(wildcard include/config/NF_CT_PROTO_SCTP) \
    $(wildcard include/config/NF_CT_PROTO_GRE) \
    $(wildcard include/config/NF_CONNTRACK_EVENTS) \
    $(wildcard include/config/NF_CONNTRACK_LABELS) \
  /kernel/include/linux/netfilter/nf_conntrack_tcp.h \
  /kernel/include/uapi/linux/netfilter/nf_conntrack_tcp.h \
  /kernel/include/linux/netfilter/nf_conntrack_sctp.h \
  /kernel/include/uapi/linux/netfilter/nf_conntrack_sctp.h \
  /kernel/include/uapi/linux/netfilter/nf_conntrack_tuple_common.h \
  /kernel/include/linux/netfilter/nf_conntrack_common.h \
  /kernel/include/uapi/linux/netfilter/nf_conntrack_common.h \
  /kernel/include/net/netns/nftables.h \
  /kernel/include/net/netns/xfrm.h \
  /kernel/include/uapi/linux/xfrm.h \
  /kernel/include/net/netns/mpls.h \
  /kernel/include/net/netns/can.h \
  /kernel/include/net/netns/xdp.h \
  /kernel/include/net/netns/smc.h \
  /kernel/include/net/netns/bpf.h \
  /kernel/include/net/netns/mctp.h \
  /kernel/include/linux/hashtable.h \
  /kernel/include/net/net_trackers.h \
    $(wildcard include/config/NET_DEV_REFCNT_TRACKER) \
  /kernel/include/linux/ref_tracker.h \
    $(wildcard include/config/REF_TRACKER) \
  /kernel/include/linux/stackdepot.h \
    $(wildcard include/config/STACKDEPOT) \
    $(wildcard include/config/STACKDEPOT_MAX_FRAMES) \
    $(wildcard include/config/STACKDEPOT_ALWAYS_INIT) \
  /kernel/include/linux/skbuff.h \
    $(wildcard include/config/BRIDGE_NETFILTER) \
    $(wildcard include/config/NET_TC_SKB_EXT) \
    $(wildcard include/config/MAX_SKB_FRAGS) \
    $(wildcard include/config/NET_SOCK_MSG) \
    $(wildcard include/config/SKB_EXTENSIONS) \
    $(wildcard include/config/NET_XGRESS) \
    $(wildcard include/config/WIRELESS) \
    $(wildcard include/config/IPV6_NDISC_NODETYPE) \
    $(wildcard include/config/NETFILTER_XT_TARGET_TRACE) \
    $(wildcard include/config/NET_SWITCHDEV) \
    $(wildcard include/config/NET_REDIRECT) \
    $(wildcard include/config/NETFILTER_SKIP_EGRESS) \
    $(wildcard include/config/SKB_DECRYPTED) \
    $(wildcard include/config/NET_SCHED) \
    $(wildcard include/config/NET_RX_BUSY_POLL) \
    $(wildcard include/config/XPS) \
    $(wildcard include/config/NETWORK_SECMARK) \
    $(wildcard include/config/DEBUG_NET) \
    $(wildcard include/config/FAIL_SKB_REALLOC) \
    $(wildcard include/config/NETWORK_PHY_TIMESTAMPING) \
    $(wildcard include/config/MCTP_FLOWS) \
    $(wildcard include/config/INET_PSP) \
  /kernel/include/net/checksum.h \
  /kernel/arch/arm64/include/asm/checksum.h \
  /kernel/include/asm-generic/checksum.h \
  /kernel/include/linux/dma-mapping.h \
    $(wildcard include/config/DMA_API_DEBUG) \
    $(wildcard include/config/HAS_DMA) \
    $(wildcard include/config/NEED_DMA_MAP_STATE) \
  /kernel/include/linux/scatterlist.h \
    $(wildcard include/config/NEED_SG_DMA_LENGTH) \
    $(wildcard include/config/NEED_SG_DMA_FLAGS) \
    $(wildcard include/config/DEBUG_SG) \
    $(wildcard include/config/SGL_ALLOC) \
    $(wildcard include/config/ARCH_NO_SG_CHAIN) \
    $(wildcard include/config/SG_POOL) \
  /kernel/include/linux/netdev_features.h \
  /kernel/include/net/flow_dissector.h \
  /kernel/include/uapi/linux/if_ether.h \
  /kernel/include/uapi/linux/pkt_cls.h \
    $(wildcard include/config/NET_CLS_ACT) \
  /kernel/include/uapi/linux/pkt_sched.h \
  /kernel/include/uapi/linux/if_packet.h \
  /kernel/include/linux/page_frag_cache.h \
  /kernel/include/net/net_debug.h \
  /kernel/include/net/netmem.h \
  /kernel/include/linux/seq_file_net.h \
  /kernel/security/selinux/include/avc.h \
    $(wildcard include/config/SECURITY_SELINUX_AVC_STATS) \
  /kernel/include/linux/audit.h \
    $(wildcard include/config/AUDIT_COMPAT_GENERIC) \
  /kernel/include/linux/audit_arch.h \
  /kernel/include/uapi/linux/audit.h \
  /kernel/include/uapi/linux/netfilter/nf_tables.h \
  /kernel/include/uapi/linux/fanotify.h \
  /kernel/arch/arm64/include/asm/syscall.h \
  /kernel/include/linux/lsm_audit.h \
  /kernel/include/rdma/ib_verbs.h \
    $(wildcard include/config/INFINIBAND_USER_ACCESS) \
    $(wildcard include/config/INFINIBAND_VIRT_DMA) \
  /kernel/include/linux/ethtool.h \
  /kernel/include/linux/if_ether.h \
  /kernel/include/linux/netlink.h \
  /kernel/include/net/scm.h \
  /kernel/include/linux/net.h \
  /kernel/include/linux/once.h \
  /kernel/include/uapi/linux/net.h \
  /kernel/include/net/compat.h \
  /kernel/include/uapi/linux/netlink.h \
  /kernel/include/uapi/linux/ethtool.h \
  /kernel/include/uapi/linux/ethtool_netlink_generated.h \
  /kernel/include/uapi/linux/net_tstamp.h \
  /kernel/include/linux/irq_poll.h \
  /kernel/include/net/ipv6.h \
  /kernel/include/linux/ipv6.h \
    $(wildcard include/config/IPV6_ROUTER_PREF) \
    $(wildcard include/config/IPV6_ROUTE_INFO) \
    $(wildcard include/config/IPV6_OPTIMISTIC_DAD) \
    $(wildcard include/config/IPV6_SEG6_HMAC) \
    $(wildcard include/config/IPV6_MIP6) \
  /kernel/include/uapi/linux/ipv6.h \
  /kernel/include/linux/tcp.h \
    $(wildcard include/config/TCP_AO) \
    $(wildcard include/config/TLS_DEVICE) \
    $(wildcard include/config/BPF) \
    $(wildcard include/config/TCP_MD5SIG) \
  /kernel/include/linux/win_minmax.h \
  /kernel/include/net/sock.h \
    $(wildcard include/config/SOCK_RX_QUEUE_MAPPING) \
    $(wildcard include/config/SOCK_VALIDATE_XMIT) \
    $(wildcard include/config/BT) \
  /kernel/include/linux/netdevice.h \
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
    $(wildcard include/config/NET_SHAPER) \
    $(wildcard include/config/NETFILTER_EGRESS) \
    $(wildcard include/config/VLAN_8021Q) \
    $(wildcard include/config/NET_DSA) \
    $(wildcard include/config/TIPC) \
    $(wildcard include/config/ATALK) \
    $(wildcard include/config/IEEE802154) \
    $(wildcard include/config/6LOWPAN) \
    $(wildcard include/config/MPLS_ROUTING) \
    $(wildcard include/config/NETFILTER_INGRESS) \
    $(wildcard include/config/PCPU_DEV_REFCNT) \
    $(wildcard include/config/GARP) \
    $(wildcard include/config/MRP) \
    $(wildcard include/config/NET_DROP_MONITOR) \
    $(wildcard include/config/MACSEC) \
    $(wildcard include/config/DPLL) \
    $(wildcard include/config/DIMLIB) \
    $(wildcard include/config/NET_FLOW_LIMIT) \
    $(wildcard include/config/ETHTOOL_NETLINK) \
  /kernel/include/linux/prefetch.h \
  /kernel/include/linux/dynamic_queue_limits.h \
  /kernel/include/net/netprio_cgroup.h \
  /kernel/include/uapi/linux/neighbour.h \
  /kernel/include/uapi/linux/netdevice.h \
  /kernel/include/linux/if_link.h \
  /kernel/include/uapi/linux/if_link.h \
  /kernel/include/uapi/linux/if_bonding.h \
  /kernel/include/uapi/linux/netdev.h \
  /kernel/include/net/neighbour_tables.h \
  /kernel/include/linux/poll.h \
  /kernel/include/uapi/linux/poll.h \
  /kernel-build/arch/arm64/include/generated/uapi/asm/poll.h \
  /kernel/include/uapi/asm-generic/poll.h \
  /kernel/include/uapi/linux/eventpoll.h \
  /kernel/include/linux/indirect_call_wrapper.h \
  /kernel/include/net/dst.h \
  /kernel/include/linux/rtnetlink.h \
    $(wildcard include/config/NET_INGRESS) \
  /kernel/include/uapi/linux/rtnetlink.h \
  /kernel/include/uapi/linux/if_addr.h \
  /kernel/include/net/neighbour.h \
  /kernel/include/net/rtnetlink.h \
  /kernel/include/net/netlink.h \
  /kernel/include/net/tcp_states.h \
  /kernel/include/linux/net_tstamp.h \
  /kernel/include/net/l3mdev.h \
  /kernel/include/net/fib_rules.h \
  /kernel/include/uapi/linux/fib_rules.h \
  /kernel/include/net/fib_notifier.h \
  /kernel/include/net/inet_connection_sock.h \
  /kernel/include/net/inet_sock.h \
  /kernel/include/linux/jhash.h \
  /kernel/include/linux/unaligned.h \
  /kernel/include/linux/unaligned/packed_struct.h \
  /kernel/include/vdso/unaligned.h \
  /kernel/include/net/request_sock.h \
    $(wildcard include/config/SYN_COOKIES) \
  /kernel/include/net/rstreason.h \
  /kernel/include/uapi/linux/mptcp.h \
  /kernel/include/uapi/linux/mptcp_pm.h \
  /kernel/include/net/netns/hash.h \
  /kernel/include/net/inet_timewait_sock.h \
  /kernel/include/net/timewait_sock.h \
  /kernel/include/uapi/linux/tcp.h \
  /kernel/include/linux/udp.h \
  /kernel/include/uapi/linux/udp.h \
  /kernel/include/linux/jump_label_ratelimit.h \
  /kernel/include/net/if_inet6.h \
  /kernel/include/net/ip.h \
  /kernel/include/linux/ip.h \
  /kernel/include/uapi/linux/ip.h \
  /kernel/include/net/route.h \
  /kernel/include/net/inetpeer.h \
  /kernel/include/net/ip_fib.h \
  /kernel/include/uapi/linux/in_route.h \
  /kernel/include/net/arp.h \
  /kernel/include/linux/if_arp.h \
    $(wildcard include/config/FIREWIRE_NET) \
  /kernel/include/uapi/linux/if_arp.h \
  /kernel/include/net/ndisc.h \
  /kernel/include/net/ipv6_stubs.h \
  /kernel/include/linux/icmpv6.h \
    $(wildcard include/config/NF_NAT) \
  /kernel/include/uapi/linux/route.h \
  /kernel/include/net/lwtunnel.h \
  /kernel/include/uapi/linux/lwtunnel.h \
  /kernel/include/linux/cgroup_rdma.h \
  /kernel/include/linux/dim.h \
  /kernel/include/uapi/rdma/ib_user_verbs.h \
  /kernel/include/rdma/rdma_counter.h \
  /kernel/include/rdma/restrack.h \
  /kernel/include/uapi/rdma/rdma_netlink.h \
  /kernel/include/rdma/rdma_netlink.h \
  /kernel/include/rdma/signature.h \
  /kernel/include/uapi/rdma/rdma_user_ioctl.h \
  /kernel/include/uapi/rdma/ib_user_mad.h \
  /kernel/include/uapi/rdma/hfi/hfi1_ioctl.h \
  /kernel/include/uapi/rdma/rdma_user_ioctl_cmds.h \
  /kernel/include/uapi/rdma/ib_user_ioctl_verbs.h \
  /kernel/include/linux/pci-tph.h \
    $(wildcard include/config/PCIE_TPH) \
  /kernel-build/security/selinux/av_permissions.h \
  /kernel/security/selinux/ss/context.h \
  /kernel/security/selinux/ss/ebitmap.h \
  /kernel/include/net/netlabel.h \
  /kernel/security/selinux/ss/mls_types.h \
  /kernel/security/selinux/ss/conditional.h \
  /kernel/security/selinux/ss/avtab.h \
    $(wildcard include/config/SECURITY_SELINUX_DEBUG) \
  /kernel/security/selinux/ss/symtab.h \
  /kernel/security/selinux/ss/hashtab.h \
  /kernel/security/selinux/ss/policydb.h \
  /kernel/security/selinux/ss/sidtab.h \
    $(wildcard include/config/SECURITY_SELINUX_SID2STR_CACHE_SIZE) \
    $(wildcard include/config/SECURITY_SELINUX_SIDTAB_HASH_BITS) \
  /kernel/security/selinux/ss/constraint.h \
  /kernel/security/selinux/ss/../include/conditional.h \
  /kernel/security/selinux/ss/../include/security.h \
  /kernel/security/selinux/ss/mls.h \
  /kernel/security/selinux/ss/services.h \
  policy_view.h \
  policy_dynamic_layout.h \
  policy_layout_slots.h \

ksu_av.o: $(deps_ksu_av.o)

$(deps_ksu_av.o):
