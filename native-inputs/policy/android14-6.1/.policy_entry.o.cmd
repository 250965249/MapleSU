cmd_/output/android14-6.1/policy_entry.o := clang -Wp,-MMD,/output/android14-6.1/.policy_entry.o.d -nostdinc -I/opt/ddk/src/android14-6.1/arch/arm64/include -I./arch/arm64/include/generated -I/opt/ddk/src/android14-6.1/include -I./include -I/opt/ddk/src/android14-6.1/arch/arm64/include/uapi -I./arch/arm64/include/generated/uapi -I/opt/ddk/src/android14-6.1/include/uapi -I./include/generated/uapi -include /opt/ddk/src/android14-6.1/include/linux/compiler-version.h -include /opt/ddk/src/android14-6.1/include/linux/kconfig.h -D__KERNEL__ --target=aarch64-linux-gnu -fintegrated-as -Werror=unknown-warning-option -Werror=ignored-optimization-argument -mlittle-endian -DKASAN_SHADOW_SCALE_SHIFT= -Qunused-arguments -fmacro-prefix-map=/opt/ddk/src/android14-6.1/= -D__ASSEMBLY__ -fno-PIE -fasynchronous-unwind-tables -DKASAN_SHADOW_SCALE_SHIFT= -g -gdwarf-4  -DMODULE  -c -o /output/android14-6.1/policy_entry.o /output/android14-6.1/policy_entry.S 

source_/output/android14-6.1/policy_entry.o := /output/android14-6.1/policy_entry.S

deps_/output/android14-6.1/policy_entry.o := \
  /opt/ddk/src/android14-6.1/include/linux/compiler-version.h \
    $(wildcard include/config/CC_VERSION_TEXT) \
  /opt/ddk/src/android14-6.1/include/linux/kconfig.h \
    $(wildcard include/config/CPU_BIG_ENDIAN) \
    $(wildcard include/config/BOOGER) \
    $(wildcard include/config/FOO) \

/output/android14-6.1/policy_entry.o: $(deps_/output/android14-6.1/policy_entry.o)

$(deps_/output/android14-6.1/policy_entry.o):
