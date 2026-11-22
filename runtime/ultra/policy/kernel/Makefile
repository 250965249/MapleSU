# The SDK payload is a relocatable object, not a second root framework/LKM.
obj-m += maplesu_policy_view.o maplesu_policy_layout.o
maplesu_policy_layout-y := abi_anchors.o
maplesu_policy_view-y := policy_view.o ksu_context.o ksu_sid.o ksu_queries.o ksu_setprocattr.o ksu_av.o policy_status.o policy_notifications.o policy_reload.o policy_cred_status.o policy_dynamic_layout.o
ccflags-y += -I$(src) -I$(src)/.. -I$(srctree)/security/selinux -I$(srctree)/security/selinux/include
ccflags-y += -I$(objtree)/security/selinux -Werror
# Emit a relocatable ELF instead of LLVM bitcode. Legacy LTO CFI requires LTO;
# SDK inline dispatch does not replace typed function-table entries. KCFI,
# PAC/BTI, shadow-call-stack and stack-protector follow the target Kbuild flags.
ccflags-y += -fno-lto -fno-sanitize=cfi

# Android backports the const vm_flags API independently of version numbers.
ifneq ($(shell grep -l 'vm_flags_clear' $(srctree)/include/linux/mm.h),)
ccflags-y += -DMAPLESU_POLICY_HAS_VM_FLAGS_CLEAR
endif

# Android 6.12+ backports seqcount begin/end; 6.6 uses a u32 unlock epoch.
ifneq ($(shell grep -l 'mm_lock_seqcount_begin' $(srctree)/include/linux/mmap_lock.h),)
ccflags-y += -DMAPLESU_POLICY_MMAP_SEQCOUNT
endif

CFLAGS_abi_anchors.o += -fstandalone-debug

# SDK payloads use a private PIC image; static-key tests read the actual counter
# instead of emitting unregistered jump-label sites. Structure layouts stay intact.
ifeq ($(MAPLESU_POLICY_PIC),1)
ccflags-y += -fPIC -DMAPLESU_POLICY_PIC -mbranch-protection=standard
maplesu_policy_view-y += policy_entry.o
endif
