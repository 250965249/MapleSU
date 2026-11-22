// kstat implementation.
//
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <cstdint>

#include "kernel_module_kit_umbrella.h"
#include "maplesu_kernel_layout_private.h"

#include "offset_probe_private.h"
#include "offsets_internal.h"

namespace kernel_module {

// Locates the ino field of the kernel's struct kstat by comparing the inode
// numbers the kernel fills for two different proc files against the numbers the
// host sees: vfs_fstat() writes a full struct kstat into a kernel buffer, and
// the field that matches both host inode numbers at the same aligned offset is
// the ino field.
KModErr get_kstat_ino_offset(uint32_t& offset) {
    KernelFieldDescription field;
    bool available = false;
    KModErr btf_error = maplesu_resolve_btf_field("kstat", "ino", 8, field, available);
    if (available) {
        if (is_ok(btf_error)) offset = field.offset_bytes;
        return btf_error;
    }

    KModErr err = get_offset_cache("kstat_ino", offset);
    if (is_ok(err)) {
        return KModErr::OK;  // already cached
    }

    int version_fd = open("/proc/version", O_RDONLY);
    if (version_fd < 0) {
        return KModErr::ERR_MODULE_OPEN_FILE;
    }
    fd_guard version_guard(version_fd);
    struct stat version_stat{};
    if (fstat(version_fd, &version_stat) != 0) {
        return KModErr::ERR_MODULE_READ_FILE;
    }

    int cmdline_fd = open("/proc/cmdline", O_RDONLY);
    if (cmdline_fd < 0) {
        return KModErr::ERR_MODULE_OPEN_FILE;
    }
    fd_guard cmdline_guard(cmdline_fd);
    struct stat cmdline_stat{};
    if (fstat(cmdline_fd, &cmdline_stat) != 0) {
        return KModErr::ERR_MODULE_READ_FILE;
    }

    if (version_stat.st_ino == cmdline_stat.st_ino) {
        return KModErr::ERR_MODULE_INO;
    }

    uint64_t version_kstat = 0;
    err = alloc_kernel_mem(256, version_kstat);
    if (is_failed(err)) {
        return err;
    }
    maplesu_alloc_mem_guard version_mem_guard(version_kstat, 0);
    uint64_t cmdline_kstat = 0;
    err = alloc_kernel_mem(256, cmdline_kstat);
    if (is_failed(err)) {
        return err;
    }

    maplesu_alloc_mem_guard cmdline_mem_guard(cmdline_kstat, 0);

    err = fill00_kernel_mem(version_kstat, 256, KernMemProt::KMP_RW);
    if (is_failed(err)) {
        return err;
    }
    err = fill00_kernel_mem(cmdline_kstat, 256, KernMemProt::KMP_RW);
    if (is_failed(err)) {
        return err;
    }

    // vfs_fstat(fd, kernel_kstat): fills the whole struct kstat at the kernel
    // address passed in x1.
    err = exec_kernel_shellcode_no_result(
            [version_fd, version_kstat](asmjit::a64::Assembler* a) -> KModErr {
                KModErr call_err = KModErr::ERR_MODULE_ASM;
                a->mov(asmjit::a64::regs::w0, asmjit::Imm(version_fd));
                aarch64_asm_mov_x(a, asmjit::a64::regs::x1, version_kstat);
                export_symbol::vfs_fstat(a, call_err, asmjit::a64::regs::w0,
                                         asmjit::a64::regs::x1);
                return call_err;
            });
    if (is_failed(err)) {
        return err;
    }
    err = exec_kernel_shellcode_no_result(
            [cmdline_fd, cmdline_kstat](asmjit::a64::Assembler* a) -> KModErr {
                KModErr call_err = KModErr::ERR_MODULE_ASM;
                a->mov(asmjit::a64::regs::w0, asmjit::Imm(cmdline_fd));
                aarch64_asm_mov_x(a, asmjit::a64::regs::x1, cmdline_kstat);
                export_symbol::vfs_fstat(a, call_err, asmjit::a64::regs::w0,
                                         asmjit::a64::regs::x1);
                return call_err;
            });
    if (is_failed(err)) {
        return err;
    }

    unsigned char version_buf[256] = {0};
    unsigned char cmdline_buf[256] = {0};
    err = read_kernel_mem(version_kstat, version_buf, 256);
    if (is_failed(err)) {
        return err;
    }
    err = read_kernel_mem(cmdline_kstat, cmdline_buf, 256);
    if (is_failed(err)) {
        return err;
    }

    // Both kernel pages are released before the scan: only the two copies are
    // needed from here on.
    version_mem_guard.reset(0, 0);
    cmdline_mem_guard.reset(0, 0);

    for (uint64_t i = 0; i <= 256 - sizeof(uint64_t); i += sizeof(uint64_t)) {
        uint64_t version_slot = 0, cmdline_slot = 0;
        memcpy(&version_slot, version_buf + i, sizeof(version_slot));
        memcpy(&cmdline_slot, cmdline_buf + i, sizeof(cmdline_slot));
        if (version_slot != static_cast<uint64_t>(version_stat.st_ino)) {
            continue;
        }
        if (cmdline_slot != static_cast<uint64_t>(cmdline_stat.st_ino)) {
            continue;
        }
        const uint32_t found_offset = static_cast<uint32_t>(i);
        offset = found_offset;
        return put_offset_cache("kstat_ino", found_offset);
    }

    return KModErr::ERR_MODULE_OFFSET_NOT_FOUND;
}

}  // namespace kernel_module
