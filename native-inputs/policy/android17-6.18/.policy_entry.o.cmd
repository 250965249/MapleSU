savedcmd_policy_entry.o := python3 /source/scripts/policy-kernel-clang.py clang -Wp,-MMD,./.policy_entry.o.d -nostdinc -I/kernel/arch/arm64/include -I/kernel-build/arch/arm64/include/generated -I/kernel/include -I/kernel-build/include -I/kernel/arch/arm64/include/uapi -I/kernel-build/arch/arm64/include/generated/uapi -I/kernel/include/uapi -I/kernel-build/include/generated/uapi -include /kernel/include/linux/compiler-version.h -include /kernel/include/linux/kconfig.h -D__KERNEL__ --target=aarch64-linux-gnu -fintegrated-as -Werror=unknown-warning-option -Werror=ignored-optimization-argument -Werror=option-ignored -Werror=unused-command-line-argument -mlittle-endian -DKASAN_SHADOW_SCALE_SHIFT= -Werror -D__ASSEMBLY__ -fno-PIE -fasynchronous-unwind-tables -DKASAN_SHADOW_SCALE_SHIFT= -Wa,--fatal-warnings -g -gdwarf-5 -gz=zstd  -DMODULE  -DKBUILD_MODNAME='"maplesu_policy_view"' -D__KBUILD_MODNAME=kmod_maplesu_policy_view -c -o policy_entry.o policy_entry.S 

source_policy_entry.o := policy_entry.S

deps_policy_entry.o := \
  /kernel/include/linux/compiler-version.h \
    $(wildcard include/config/CC_VERSION_TEXT) \
  /kernel/include/linux/kconfig.h \
    $(wildcard include/config/CPU_BIG_ENDIAN) \
    $(wildcard include/config/BOOGER) \
    $(wildcard include/config/FOO) \

policy_entry.o: $(deps_policy_entry.o)

$(deps_policy_entry.o):
