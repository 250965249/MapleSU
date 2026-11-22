// Compiled into the helper's added RX segment. No libc or dynamic relocations.
#include <fcntl.h>
#include <sys/syscall.h>
#ifdef MAPLESU_SOURCE_HELPER
#include "../boot/helper_capability_contract.h"
#include "helper_sdk_version.h"

/* The source loader calls this TU's gate before executing each module. */
__attribute__((used, retain, section(".note.maplesu.helper"), aligned(4)))
static const struct maplesu_helper_capability_note module_capability = {
    8, 16, MAPLESU_HELPER_CAPABILITY_NOTE_TYPE,
    {'M', 'a', 'p', 'l', 'e', 'S', 'U', '\0'},
    MAPLESU_HELPER_CAPABILITY_ABI, MAPLESU_HELPER_SDK_VERSION_CODE,
    MAPLESU_HELPER_CAPABILITY_MODULE_BOOT_GATE, 0
};
#endif

static long call4(long nr, long a, long b, long c, long d) {
    register long x0 __asm__("x0") = a;
    register long x1 __asm__("x1") = b;
    register long x2 __asm__("x2") = c;
    register long x3 __asm__("x3") = d;
    register long x8 __asm__("x8") = nr;
    __asm__ volatile("svc #0" : "+r"(x0) : "r"(x1), "r"(x2), "r"(x3), "r"(x8) : "memory", "cc");
    return x0;
}
int maplesu_skip_disabled(const char* directory) {
    long dir = call4(SYS_openat, AT_FDCWD, (long)directory, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC, 0);
    if (dir < 0) return 1;
    long fd = call4(SYS_openat, dir, (long)".maplesu-state", O_RDONLY | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC, 0);
    call4(SYS_close, dir, 0, 0, 0);
    if (fd == -2) return 0; // legacy modules default to enabled
    if (fd < 0) return 1;
    char record[39];
    long size = call4(SYS_read, fd, (long)record, sizeof(record), 0);
    call4(SYS_close, fd, 0, 0, 0);
    return size != 38 || record[0] != '1' || record[37] != '\n';
}
