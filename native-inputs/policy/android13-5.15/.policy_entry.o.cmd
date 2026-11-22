cmd_/output/android13-5.15/policy_entry.o := clang -Wp,-MMD,/output/android13-5.15/.policy_entry.o.d -nostdinc -isystem /opt/ddk/clang/clang-r450784e/lib64/clang/14.0.7/include -I/opt/ddk/src/android13-5.15/arch/arm64/include -I./arch/arm64/include/generated -I/opt/ddk/src/android13-5.15/include -I./include -I/opt/ddk/src/android13-5.15/arch/arm64/include/uapi -I./arch/arm64/include/generated/uapi -I/opt/ddk/src/android13-5.15/include/uapi -I./include/generated/uapi -include /opt/ddk/src/android13-5.15/include/linux/compiler-version.h -include /opt/ddk/src/android13-5.15/include/linux/kconfig.h -D__KERNEL__ --target=aarch64-linux-gnu -fintegrated-as -Werror=unknown-warning-option -Werror=ignored-optimization-argument -mlittle-endian -DKASAN_SHADOW_SCALE_SHIFT= -Qunused-arguments -fmacro-prefix-map=/opt/ddk/src/android13-5.15/= -D__ASSEMBLY__ -fno-PIE -fno-asynchronous-unwind-tables -fno-unwind-tables -DKASAN_SHADOW_SCALE_SHIFT= -g -gdwarf-4 -fno-lto  -DMODULE  -c -o /output/android13-5.15/policy_entry.o /output/android13-5.15/policy_entry.S

source_/output/android13-5.15/policy_entry.o := /output/android13-5.15/policy_entry.S

deps_/output/android13-5.15/policy_entry.o := \
  /opt/ddk/src/android13-5.15/include/linux/compiler-version.h \
    $(wildcard include/config/CC_VERSION_TEXT) \
  /opt/ddk/src/android13-5.15/include/linux/kconfig.h \
    $(wildcard include/config/CPU_BIG_ENDIAN) \
    $(wildcard include/config/BOOGER) \
    $(wildcard include/config/FOO) \

/output/android13-5.15/policy_entry.o: $(deps_/output/android13-5.15/policy_entry.o)

$(deps_/output/android13-5.15/policy_entry.o):
