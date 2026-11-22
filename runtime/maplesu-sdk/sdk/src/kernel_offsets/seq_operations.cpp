// seq_operations implementation.
//
#include <fcntl.h>
#include <unistd.h>

#include <cstdint>

#include "kernel_module_kit_umbrella.h"
#include "maplesu_kernel_layout_private.h"

#include "offset_probe_private.h"
#include "offsets_internal.h"
#include "private_module_tombstone_purge.h"

namespace kernel_module {

namespace {

// Kernel addresses are the pointer values at or above the top of the canonical
// user range; lower values are not kernel pointers.
constexpr uint64_t kKernelAddrMin = 0xFFFF000000000000ULL;

}  // namespace

// Locates the show slot of struct seq_operations by reading the seq_file of two
// proc files.  Both files share the generic start/stop/next callbacks and only
// their show callback differs, so for the seq_file field holding the
// seq_operations pointer the two 4-entry callback tables match in exactly three
// entries; the index of the one that differs is the show slot.
KModErr get_seq_operations_show_offset(uint32_t& offset) {
    KernelFieldDescription field;
    bool available = false;
    KModErr btf_error = maplesu_resolve_btf_field("seq_operations", "show", 8, field, available);
    if (available) {
        if (is_ok(btf_error)) offset = field.offset_bytes;
        return btf_error;
    }

    KModErr err = get_offset_cache("seq_operations_show", offset);
    if (is_ok(err)) {
        return err;  // already cached
    }

    uint32_t private_data_offset = 0;
    err = get_file_private_data_offset(private_data_offset);
    if (is_failed(err)) {
        return err;
    }

    fd_guard cmdline_fd(open("/proc/cmdline", O_RDONLY));
    if (cmdline_fd.get() < 0) {
        return KModErr::ERR_MODULE_OPEN_FILE;
    }
    fd_guard version_fd(open("/proc/version", O_RDONLY));
    if (version_fd.get() < 0) {
        return KModErr::ERR_MODULE_OPEN_FILE;
    }

    uint64_t cmdline_file = 0;
    err = get_current_task_file_ptr(cmdline_fd.get(), cmdline_file);
    if (is_failed(err)) {
        return err;
    }
    uint64_t version_file = 0;
    err = get_current_task_file_ptr(version_fd.get(), version_file);
    if (is_failed(err)) {
        return err;
    }
    if (cmdline_file == 0 || version_file == 0) {
        return KModErr::ERR_MODULE_NOT_KADDR;
    }

    // Both files carry a struct seq_file in file->private_data.
    uint64_t cmdline_seq = 0;
    bool read_ok = false;
    err = safe_read_kaddr_t(cmdline_file + private_data_offset, read_ok, cmdline_seq);
    if (is_failed(err)) {
        return err;
    }
    if (!read_ok || cmdline_seq < kKernelAddrMin) {
        return KModErr::ERR_MODULE_NOT_KADDR;
    }
    uint64_t version_seq = 0;
    err = safe_read_kaddr_t(version_file + private_data_offset, read_ok, version_seq);
    if (is_failed(err)) {
        return err;
    }
    if (!read_ok || version_seq < kKernelAddrMin) {
        return KModErr::ERR_MODULE_NOT_KADDR;
    }

    // seq_file::op sits after the inline mutex, so the scan starts at 64 and
    // covers the rest of the structure.
    for (uint64_t seq_offset = 64; seq_offset < 256; seq_offset += 8) {
        uint64_t cmdline_ops = 0;
        err = safe_read_kaddr_t(cmdline_seq + seq_offset, read_ok, cmdline_ops);
        if (is_failed(err)) {
            return err;
        }
        if (!read_ok) {
            return KModErr::ERR_MODULE_OFFSET_NOT_FOUND;
        }
        uint64_t version_ops = 0;
        err = safe_read_kaddr_t(version_seq + seq_offset, read_ok, version_ops);
        if (is_failed(err)) {
            return err;
        }
        if (!read_ok) {
            return KModErr::ERR_MODULE_OFFSET_NOT_FOUND;
        }
        if (cmdline_ops < kKernelAddrMin || version_ops < kKernelAddrMin) {
            continue;
        }
        if (cmdline_ops == version_ops) {
            continue;
        }

        uint64_t cmdline_entries[4] = {0, 0, 0, 0};
        uint64_t version_entries[4] = {0, 0, 0, 0};
        err = read_kernel_mem(cmdline_ops, cmdline_entries, sizeof(cmdline_entries));
        if (is_failed(err)) {
            return err;
        }
        err = read_kernel_mem(version_ops, version_entries, sizeof(version_entries));
        if (is_failed(err)) {
            return err;
        }

        bool all_callbacks = true;
        for (int i = 0; i < 4; ++i) {
            if (cmdline_entries[i] < kKernelAddrMin || version_entries[i] < kKernelAddrMin) {
                all_callbacks = false;
                break;
            }
        }
        if (!all_callbacks) {
            continue;
        }

        int equal_count = 0;
        int diff_index = -1;
        for (int i = 0; i < 4; ++i) {
            if (cmdline_entries[i] == version_entries[i]) {
                ++equal_count;
            } else {
                diff_index = i;
            }
        }

        if (equal_count == 3 && diff_index != -1) {
            const uint32_t show_offset = static_cast<uint32_t>(diff_index) * 8;
            offset = show_offset;
            return put_offset_cache("seq_operations_show", show_offset);
        }
    }

    return KModErr::ERR_MODULE_OFFSET_NOT_FOUND;
}

// Locates the CFI type hash that guards the show callback.  A proc file's
// seq_file points at a seq_operations table; the first table entry that is a
// kernel text address and carries a non-zero 32-bit value right before the
// function entry leads to that value, because the kernel records the CFI type
// hash immediately ahead of a CFI-checked function.
KModErr get_seq_operations_show_kcfi_hash(uint32_t& out_hash) {
    KModErr err = get_offset_cache("seq_operations_show_kcfi_hash", out_hash);
    if (is_ok(err)) {
        return err;  // already cached
    }

    uint32_t show_offset = 0;
    err = get_seq_operations_show_offset(show_offset);
    if (is_failed(err)) {
        return err;
    }

    uint32_t private_data_offset = 0;
    err = get_file_private_data_offset(private_data_offset);
    if (is_failed(err)) {
        return err;
    }

    fd_guard cmdline_fd(open("/proc/cmdline", O_RDONLY));
    if (cmdline_fd.get() < 0) {
        return KModErr::ERR_MODULE_OPEN_FILE;
    }

    uint64_t cmdline_file = 0;
    err = get_current_task_file_ptr(cmdline_fd.get(), cmdline_file);
    if (is_failed(err)) {
        return err;
    }

    uint64_t cmdline_seq = 0;
    bool read_ok = false;
    err = safe_read_kaddr_t(cmdline_file + private_data_offset, read_ok, cmdline_seq);
    if (is_failed(err)) {
        return err;
    }
    if (!read_ok) {
        return KModErr::ERR_MODULE_NOT_KADDR;
    }

    for (uint64_t seq_offset = 64; seq_offset <= 255; seq_offset += 8) {
        uint64_t ops = 0;
        err = safe_read_kaddr_t(cmdline_seq + seq_offset, read_ok, ops);
        if (is_failed(err)) {
            return err;
        }
        if (!read_ok || ops <= kKernelAddrMin) {
            continue;
        }

        uint64_t show_func = 0;
        err = safe_read_kaddr_t(ops + show_offset, read_ok, show_func);
        if (is_failed(err)) {
            return err;
        }
        if (!read_ok || show_func <= kKernelAddrMin) {
            continue;
        }

        uint32_t cfi_hash = 0;
        err = safe_read_kaddr(show_func - 4, read_ok, &cfi_hash, sizeof(cfi_hash));
        if (is_failed(err)) {
            return err;
        }
        if (!read_ok || cfi_hash == 0) {
            continue;
        }

        out_hash = cfi_hash;
        return put_offset_cache("seq_operations_show_kcfi_hash", cfi_hash);
    }

    return KModErr::ERR_MODULE_OFFSET_NOT_FOUND;
}

}  // namespace kernel_module
