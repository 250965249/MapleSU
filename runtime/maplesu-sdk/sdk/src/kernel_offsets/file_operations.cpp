// file_operations implementation.
//
#include <fcntl.h>
#include <sys/eventfd.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cstdint>
#include <set>

#include "kernel_module_kit_umbrella.h"
#include "maplesu_kernel_layout_private.h"

#include "offset_probe_private.h"
#include "offsets_internal.h"

// Silences the symbol-lookup trace for the duration of one lookup.
class SymbolLookupSilentGuard_c67c0e4fed21dd11b34c67e0a5b878c8 final {
public:
    SymbolLookupSilentGuard_c67c0e4fed21dd11b34c67e0a5b878c8() noexcept {
        active_ = get_symbol_lookup_printf_silent_d8685f89f10ca8eb96df766c8babd6c3();
        if (active_) {
            set_symbol_lookup_printf_silent_d8685f89f10ca8eb96df766c8babd6c3(false);
        }
    }

    ~SymbolLookupSilentGuard_c67c0e4fed21dd11b34c67e0a5b878c8() noexcept {
        if (active_) {
            set_symbol_lookup_printf_silent_d8685f89f10ca8eb96df766c8babd6c3(true);
        }
    }

    SymbolLookupSilentGuard_c67c0e4fed21dd11b34c67e0a5b878c8(
        const SymbolLookupSilentGuard_c67c0e4fed21dd11b34c67e0a5b878c8&) = delete;
    SymbolLookupSilentGuard_c67c0e4fed21dd11b34c67e0a5b878c8& operator=(
        const SymbolLookupSilentGuard_c67c0e4fed21dd11b34c67e0a5b878c8&) = delete;

private:
    bool active_ = false;
};

namespace kernel_module {

namespace {

// Kernel addresses are the pointer values at or above the top of the canonical
// user range; lower values are not kernel pointers.
constexpr uint64_t kKernelAddrMin = 0xFFFF000000000000ULL;

KModErr resolve_file_operations_btf_offset(const char* member, uint32_t& offset,
                                           bool& available) {
    KernelFieldDescription field;
    KModErr error = maplesu_resolve_btf_field("file_operations", member, 8, field, available);
    if (available && is_ok(error)) offset = field.offset_bytes;
    return error;
}

}  // namespace

// Looks one kernel symbol up without printing the lookup trace.
static uint64_t get_func_ka(const char* name) {
    SymbolLookupSilentGuard_c67c0e4fed21dd11b34c67e0a5b878c8 guard;
    uint64_t kaddr = 0;
    kallsyms_lookup_name(name, kaddr);
    return kaddr;
}

// True while the collected table is empty or holds only unresolved symbols.
static bool is_empty(const std::set<uint64_t>& kaddrs) {
    for (uint64_t kaddr : kaddrs) {
        if (kaddr != 0) {
            return false;
        }
    }
    return true;
}

// Resolves the llseek slot of struct file_operations: the slot that holds one
// of the kernel functions `generic_file_llseek` / `generic_file_llseek.cfi_jt` is llseek.
KModErr get_file_operations_llseek_offset(uint32_t& offset) {
    bool available = false;
    KModErr btf_error = resolve_file_operations_btf_offset("llseek", offset, available);
    if (available) return btf_error;

    KModErr err = get_offset_cache("file_operations_llseek", offset);
    if (is_ok(err)) {
        return KModErr::OK;  // already cached
    }

    std::set<uint64_t> field_symbols;
    field_symbols.insert(get_func_ka("generic_file_llseek"));
    field_symbols.insert(get_func_ka("generic_file_llseek.cfi_jt"));
    if (is_empty(field_symbols)) {
        return KModErr::ERR_MODULE_SYMBOL_NOT_EXIST;
    }

    fd_guard probe_fd(open("/proc", O_RDONLY));
    if (probe_fd.get() < 0) {
        return KModErr::ERR_MODULE_OPEN_FILE;
    }

    uint64_t file_ptr = 0;
    err = get_current_task_file_ptr(probe_fd.get(), file_ptr);
    if (is_failed(err)) {
        return err;
    }

    uint32_t f_op_offset = 0;
    err = get_file_f_op_offset(f_op_offset);
    if (is_failed(err)) {
        return err;
    }

    uint64_t f_op = 0;
    err = read_kernel_mem(file_ptr + f_op_offset, &f_op, sizeof(f_op));
    if (is_failed(err)) {
        return err;
    }
    if (f_op < kKernelAddrMin) {
        return KModErr::ERR_MODULE_NOT_KADDR;
    }

    // Scan the whole operations table: the first slot whose value is one of the
    // collected kernel functions is the field.
    for (uint64_t field_offset = 0; field_offset <= 255; field_offset += 8) {
        uint64_t slot_value = 0;
        err = read_kernel_mem(f_op + field_offset, &slot_value, sizeof(slot_value));
        if (is_failed(err)) {
            return err;
        }
        if (slot_value == 0) {
            continue;
        }
        if (field_symbols.find(slot_value) == field_symbols.end()) {
            continue;
        }
        offset = static_cast<uint32_t>(field_offset);
        return put_offset_cache("file_operations_llseek", offset);
    }

    return KModErr::ERR_MODULE_OFFSET_NOT_FOUND;
}

// Resolves the read slot of struct file_operations: the slot that holds one
// of the kernel functions `generic_read_dir` / `generic_read_dir.cfi_jt` is read.
KModErr get_file_operations_read_offset(uint32_t& offset) {
    bool available = false;
    KModErr btf_error = resolve_file_operations_btf_offset("read", offset, available);
    if (available) return btf_error;

    KModErr err = get_offset_cache("file_operations_read", offset);
    if (is_ok(err)) {
        return KModErr::OK;  // already cached
    }

    std::set<uint64_t> field_symbols;
    field_symbols.insert(get_func_ka("generic_read_dir"));
    field_symbols.insert(get_func_ka("generic_read_dir.cfi_jt"));
    if (is_empty(field_symbols)) {
        return KModErr::ERR_MODULE_SYMBOL_NOT_EXIST;
    }

    fd_guard probe_fd(open("/proc", O_RDONLY));
    if (probe_fd.get() < 0) {
        return KModErr::ERR_MODULE_OPEN_FILE;
    }

    uint64_t file_ptr = 0;
    err = get_current_task_file_ptr(probe_fd.get(), file_ptr);
    if (is_failed(err)) {
        return err;
    }

    uint32_t f_op_offset = 0;
    err = get_file_f_op_offset(f_op_offset);
    if (is_failed(err)) {
        return err;
    }

    uint64_t f_op = 0;
    err = read_kernel_mem(file_ptr + f_op_offset, &f_op, sizeof(f_op));
    if (is_failed(err)) {
        return err;
    }
    if (f_op < kKernelAddrMin) {
        return KModErr::ERR_MODULE_NOT_KADDR;
    }

    // Scan the whole operations table: the first slot whose value is one of the
    // collected kernel functions is the field.
    for (uint64_t field_offset = 0; field_offset <= 255; field_offset += 8) {
        uint64_t slot_value = 0;
        err = read_kernel_mem(f_op + field_offset, &slot_value, sizeof(slot_value));
        if (is_failed(err)) {
            return err;
        }
        if (slot_value == 0) {
            continue;
        }
        if (field_symbols.find(slot_value) == field_symbols.end()) {
            continue;
        }
        offset = static_cast<uint32_t>(field_offset);
        return put_offset_cache("file_operations_read", offset);
    }

    return KModErr::ERR_MODULE_OFFSET_NOT_FOUND;
}

// Resolves the write slot of struct file_operations: the slot that holds one
// of the kernel functions `eventfd_write` / `eventfd_write.cfi_jt` is write.
KModErr get_file_operations_write_offset(uint32_t& offset) {
    bool available = false;
    KModErr btf_error = resolve_file_operations_btf_offset("write", offset, available);
    if (available) return btf_error;

    KModErr err = get_offset_cache("file_operations_write", offset);
    if (is_ok(err)) {
        return KModErr::OK;  // already cached
    }

    std::set<uint64_t> field_symbols;
    field_symbols.insert(get_func_ka("eventfd_write"));
    field_symbols.insert(get_func_ka("eventfd_write.cfi_jt"));
    if (is_empty(field_symbols)) {
        return KModErr::ERR_MODULE_SYMBOL_NOT_EXIST;
    }

    fd_guard probe_fd(eventfd(0, 0));
    if (probe_fd.get() < 0) {
        return KModErr::ERR_MODULE_OPEN_FILE;
    }

    uint64_t file_ptr = 0;
    err = get_current_task_file_ptr(probe_fd.get(), file_ptr);
    if (is_failed(err)) {
        return err;
    }

    uint32_t f_op_offset = 0;
    err = get_file_f_op_offset(f_op_offset);
    if (is_failed(err)) {
        return err;
    }

    uint64_t f_op = 0;
    err = read_kernel_mem(file_ptr + f_op_offset, &f_op, sizeof(f_op));
    if (is_failed(err)) {
        return err;
    }
    if (f_op < kKernelAddrMin) {
        return KModErr::ERR_MODULE_NOT_KADDR;
    }

    // Scan the whole operations table: the first slot whose value is one of the
    // collected kernel functions is the field.
    for (uint64_t field_offset = 0; field_offset <= 255; field_offset += 8) {
        uint64_t slot_value = 0;
        err = read_kernel_mem(f_op + field_offset, &slot_value, sizeof(slot_value));
        if (is_failed(err)) {
            return err;
        }
        if (slot_value == 0) {
            continue;
        }
        if (field_symbols.find(slot_value) == field_symbols.end()) {
            continue;
        }
        offset = static_cast<uint32_t>(field_offset);
        return put_offset_cache("file_operations_write", offset);
    }

    return KModErr::ERR_MODULE_OFFSET_NOT_FOUND;
}

// Resolves the read_iter slot of struct file_operations: the slot that holds one
// of the kernel functions `sock_read_iter` / `sock_read_iter.cfi_jt` / `sock_aio_read.cfi_jt` is read_iter.
KModErr get_file_operations_read_iter_offset(uint32_t& offset) {
    bool available = false;
    KModErr btf_error = resolve_file_operations_btf_offset("read_iter", offset, available);
    if (available) return btf_error;

    KModErr err = get_offset_cache("file_operations_read_iter", offset);
    if (is_ok(err)) {
        return KModErr::OK;  // already cached
    }

    std::set<uint64_t> field_symbols;
    field_symbols.insert(get_func_ka("sock_read_iter"));
    field_symbols.insert(get_func_ka("sock_read_iter.cfi_jt"));
    field_symbols.insert(get_func_ka("sock_aio_read.cfi_jt"));
    if (is_empty(field_symbols)) {
        return KModErr::ERR_MODULE_SYMBOL_NOT_EXIST;
    }

    fd_guard probe_fd(socket(AF_INET, SOCK_STREAM, 0));
    if (probe_fd.get() < 0) {
        return KModErr::ERR_MODULE_OPEN_FILE;
    }

    uint64_t file_ptr = 0;
    err = get_current_task_file_ptr(probe_fd.get(), file_ptr);
    if (is_failed(err)) {
        return err;
    }

    uint32_t f_op_offset = 0;
    err = get_file_f_op_offset(f_op_offset);
    if (is_failed(err)) {
        return err;
    }

    uint64_t f_op = 0;
    err = read_kernel_mem(file_ptr + f_op_offset, &f_op, sizeof(f_op));
    if (is_failed(err)) {
        return err;
    }
    if (f_op < kKernelAddrMin) {
        return KModErr::ERR_MODULE_NOT_KADDR;
    }

    // Scan the whole operations table: the first slot whose value is one of the
    // collected kernel functions is the field.
    for (uint64_t field_offset = 0; field_offset <= 255; field_offset += 8) {
        uint64_t slot_value = 0;
        err = read_kernel_mem(f_op + field_offset, &slot_value, sizeof(slot_value));
        if (is_failed(err)) {
            return err;
        }
        if (slot_value == 0) {
            continue;
        }
        if (field_symbols.find(slot_value) == field_symbols.end()) {
            continue;
        }
        offset = static_cast<uint32_t>(field_offset);
        return put_offset_cache("file_operations_read_iter", offset);
    }

    return KModErr::ERR_MODULE_OFFSET_NOT_FOUND;
}

// Resolves the write_iter slot of struct file_operations: the slot that holds one
// of the kernel functions `sock_write_iter` / `sock_write_iter.cfi_jt` / `sock_aio_write.cfi_jt` is write_iter.
KModErr get_file_operations_write_iter_offset(uint32_t& offset) {
    bool available = false;
    KModErr btf_error = resolve_file_operations_btf_offset("write_iter", offset, available);
    if (available) return btf_error;

    KModErr err = get_offset_cache("file_operations_write_iter", offset);
    if (is_ok(err)) {
        return KModErr::OK;  // already cached
    }

    std::set<uint64_t> field_symbols;
    field_symbols.insert(get_func_ka("sock_write_iter"));
    field_symbols.insert(get_func_ka("sock_write_iter.cfi_jt"));
    field_symbols.insert(get_func_ka("sock_aio_write.cfi_jt"));
    if (is_empty(field_symbols)) {
        return KModErr::ERR_MODULE_SYMBOL_NOT_EXIST;
    }

    fd_guard probe_fd(socket(AF_INET, SOCK_STREAM, 0));
    if (probe_fd.get() < 0) {
        return KModErr::ERR_MODULE_OPEN_FILE;
    }

    uint64_t file_ptr = 0;
    err = get_current_task_file_ptr(probe_fd.get(), file_ptr);
    if (is_failed(err)) {
        return err;
    }

    uint32_t f_op_offset = 0;
    err = get_file_f_op_offset(f_op_offset);
    if (is_failed(err)) {
        return err;
    }

    uint64_t f_op = 0;
    err = read_kernel_mem(file_ptr + f_op_offset, &f_op, sizeof(f_op));
    if (is_failed(err)) {
        return err;
    }
    if (f_op < kKernelAddrMin) {
        return KModErr::ERR_MODULE_NOT_KADDR;
    }

    // Scan the whole operations table: the first slot whose value is one of the
    // collected kernel functions is the field.
    for (uint64_t field_offset = 0; field_offset <= 255; field_offset += 8) {
        uint64_t slot_value = 0;
        err = read_kernel_mem(f_op + field_offset, &slot_value, sizeof(slot_value));
        if (is_failed(err)) {
            return err;
        }
        if (slot_value == 0) {
            continue;
        }
        if (field_symbols.find(slot_value) == field_symbols.end()) {
            continue;
        }
        offset = static_cast<uint32_t>(field_offset);
        return put_offset_cache("file_operations_write_iter", offset);
    }

    return KModErr::ERR_MODULE_OFFSET_NOT_FOUND;
}

// Resolves the iterate_shared slot of struct file_operations: the slot that holds one
// of the kernel functions `dcache_readdir` / `dcache_readdir.cfi_jt` is iterate_shared.
KModErr get_file_operations_iterate_shared_offset(uint32_t& offset) {
    bool available = false;
    KModErr btf_error = resolve_file_operations_btf_offset("iterate_shared", offset, available);
    if (available) return btf_error;

    KModErr err = get_offset_cache("file_operations_iterate_shared", offset);
    if (is_ok(err)) {
        return KModErr::OK;  // already cached
    }

    std::set<uint64_t> field_symbols;
    field_symbols.insert(get_func_ka("dcache_readdir"));
    field_symbols.insert(get_func_ka("dcache_readdir.cfi_jt"));
    if (is_empty(field_symbols)) {
        return KModErr::ERR_MODULE_SYMBOL_NOT_EXIST;
    }

    fd_guard probe_fd(open("/dev", O_RDONLY));
    if (probe_fd.get() < 0) {
        return KModErr::ERR_MODULE_OPEN_FILE;
    }

    uint64_t file_ptr = 0;
    err = get_current_task_file_ptr(probe_fd.get(), file_ptr);
    if (is_failed(err)) {
        return err;
    }

    uint32_t f_op_offset = 0;
    err = get_file_f_op_offset(f_op_offset);
    if (is_failed(err)) {
        return err;
    }

    uint64_t f_op = 0;
    err = read_kernel_mem(file_ptr + f_op_offset, &f_op, sizeof(f_op));
    if (is_failed(err)) {
        return err;
    }
    if (f_op < kKernelAddrMin) {
        return KModErr::ERR_MODULE_NOT_KADDR;
    }

    // Scan the whole operations table: the first slot whose value is one of the
    // collected kernel functions is the field.
    for (uint64_t field_offset = 0; field_offset <= 255; field_offset += 8) {
        uint64_t slot_value = 0;
        err = read_kernel_mem(f_op + field_offset, &slot_value, sizeof(slot_value));
        if (is_failed(err)) {
            return err;
        }
        if (slot_value == 0) {
            continue;
        }
        if (field_symbols.find(slot_value) == field_symbols.end()) {
            continue;
        }
        offset = static_cast<uint32_t>(field_offset);
        return put_offset_cache("file_operations_iterate_shared", offset);
    }

    return KModErr::ERR_MODULE_OFFSET_NOT_FOUND;
}

// Resolves the unlocked_ioctl slot of struct file_operations: the slot that holds one
// of the kernel functions `sock_ioctl` / `sock_ioctl.cfi_jt` is unlocked_ioctl.
KModErr get_file_operations_unlocked_ioctl_offset(uint32_t& offset) {
    bool available = false;
    KModErr btf_error = resolve_file_operations_btf_offset("unlocked_ioctl", offset, available);
    if (available) return btf_error;

    KModErr err = get_offset_cache("file_operations_unlocked_ioctl", offset);
    if (is_ok(err)) {
        return KModErr::OK;  // already cached
    }

    std::set<uint64_t> field_symbols;
    field_symbols.insert(get_func_ka("sock_ioctl"));
    field_symbols.insert(get_func_ka("sock_ioctl.cfi_jt"));
    if (is_empty(field_symbols)) {
        return KModErr::ERR_MODULE_SYMBOL_NOT_EXIST;
    }

    fd_guard probe_fd(socket(AF_INET, SOCK_STREAM, 0));
    if (probe_fd.get() < 0) {
        return KModErr::ERR_MODULE_OPEN_FILE;
    }

    uint64_t file_ptr = 0;
    err = get_current_task_file_ptr(probe_fd.get(), file_ptr);
    if (is_failed(err)) {
        return err;
    }

    uint32_t f_op_offset = 0;
    err = get_file_f_op_offset(f_op_offset);
    if (is_failed(err)) {
        return err;
    }

    uint64_t f_op = 0;
    err = read_kernel_mem(file_ptr + f_op_offset, &f_op, sizeof(f_op));
    if (is_failed(err)) {
        return err;
    }
    if (f_op < kKernelAddrMin) {
        return KModErr::ERR_MODULE_NOT_KADDR;
    }

    // Scan the whole operations table: the first slot whose value is one of the
    // collected kernel functions is the field.
    for (uint64_t field_offset = 0; field_offset <= 255; field_offset += 8) {
        uint64_t slot_value = 0;
        err = read_kernel_mem(f_op + field_offset, &slot_value, sizeof(slot_value));
        if (is_failed(err)) {
            return err;
        }
        if (slot_value == 0) {
            continue;
        }
        if (field_symbols.find(slot_value) == field_symbols.end()) {
            continue;
        }
        offset = static_cast<uint32_t>(field_offset);
        return put_offset_cache("file_operations_unlocked_ioctl", offset);
    }

    return KModErr::ERR_MODULE_OFFSET_NOT_FOUND;
}

// Resolves the poll slot of struct file_operations: the slot that holds one
// of the kernel functions `sock_poll` / `sock_poll.cfi_jt` is poll.
KModErr get_file_operations_poll_offset(uint32_t& offset) {
    bool available = false;
    KModErr btf_error = resolve_file_operations_btf_offset("poll", offset, available);
    if (available) return btf_error;

    KModErr err = get_offset_cache("file_operations_poll", offset);
    if (is_ok(err)) {
        return KModErr::OK;  // already cached
    }

    std::set<uint64_t> field_symbols;
    field_symbols.insert(get_func_ka("sock_poll"));
    field_symbols.insert(get_func_ka("sock_poll.cfi_jt"));
    if (is_empty(field_symbols)) {
        return KModErr::ERR_MODULE_SYMBOL_NOT_EXIST;
    }

    fd_guard probe_fd(socket(AF_INET, SOCK_STREAM, 0));
    if (probe_fd.get() < 0) {
        return KModErr::ERR_MODULE_OPEN_FILE;
    }

    uint64_t file_ptr = 0;
    err = get_current_task_file_ptr(probe_fd.get(), file_ptr);
    if (is_failed(err)) {
        return err;
    }

    uint32_t f_op_offset = 0;
    err = get_file_f_op_offset(f_op_offset);
    if (is_failed(err)) {
        return err;
    }

    uint64_t f_op = 0;
    err = read_kernel_mem(file_ptr + f_op_offset, &f_op, sizeof(f_op));
    if (is_failed(err)) {
        return err;
    }
    if (f_op < kKernelAddrMin) {
        return KModErr::ERR_MODULE_NOT_KADDR;
    }

    // Scan the whole operations table: the first slot whose value is one of the
    // collected kernel functions is the field.
    for (uint64_t field_offset = 0; field_offset <= 255; field_offset += 8) {
        uint64_t slot_value = 0;
        err = read_kernel_mem(f_op + field_offset, &slot_value, sizeof(slot_value));
        if (is_failed(err)) {
            return err;
        }
        if (slot_value == 0) {
            continue;
        }
        if (field_symbols.find(slot_value) == field_symbols.end()) {
            continue;
        }
        offset = static_cast<uint32_t>(field_offset);
        return put_offset_cache("file_operations_poll", offset);
    }

    return KModErr::ERR_MODULE_OFFSET_NOT_FOUND;
}

// Resolves the mmap slot of struct file_operations: the slot that holds one
// of the kernel functions `sock_mmap` / `sock_mmap.cfi_jt` is mmap.
KModErr get_file_operations_mmap_offset(uint32_t& offset) {
    bool available = false;
    KModErr btf_error = resolve_file_operations_btf_offset("mmap", offset, available);
    if (available) return btf_error;

    KModErr err = get_offset_cache("file_operations_mmap", offset);
    if (is_ok(err)) {
        return KModErr::OK;  // already cached
    }

    std::set<uint64_t> field_symbols;
    field_symbols.insert(get_func_ka("sock_mmap"));
    field_symbols.insert(get_func_ka("sock_mmap.cfi_jt"));
    if (is_empty(field_symbols)) {
        return KModErr::ERR_MODULE_SYMBOL_NOT_EXIST;
    }

    fd_guard probe_fd(socket(AF_INET, SOCK_STREAM, 0));
    if (probe_fd.get() < 0) {
        return KModErr::ERR_MODULE_OPEN_FILE;
    }

    uint64_t file_ptr = 0;
    err = get_current_task_file_ptr(probe_fd.get(), file_ptr);
    if (is_failed(err)) {
        return err;
    }

    uint32_t f_op_offset = 0;
    err = get_file_f_op_offset(f_op_offset);
    if (is_failed(err)) {
        return err;
    }

    uint64_t f_op = 0;
    err = read_kernel_mem(file_ptr + f_op_offset, &f_op, sizeof(f_op));
    if (is_failed(err)) {
        return err;
    }
    if (f_op < kKernelAddrMin) {
        return KModErr::ERR_MODULE_NOT_KADDR;
    }

    // Scan the whole operations table: the first slot whose value is one of the
    // collected kernel functions is the field.
    for (uint64_t field_offset = 0; field_offset <= 255; field_offset += 8) {
        uint64_t slot_value = 0;
        err = read_kernel_mem(f_op + field_offset, &slot_value, sizeof(slot_value));
        if (is_failed(err)) {
            return err;
        }
        if (slot_value == 0) {
            continue;
        }
        if (field_symbols.find(slot_value) == field_symbols.end()) {
            continue;
        }
        offset = static_cast<uint32_t>(field_offset);
        return put_offset_cache("file_operations_mmap", offset);
    }

    return KModErr::ERR_MODULE_OFFSET_NOT_FOUND;
}

// Resolves the open slot of struct file_operations: the slot that holds one
// of the kernel functions `dcache_dir_open` / `dcache_dir_open.cfi_jt` is open.
KModErr get_file_operations_open_offset(uint32_t& offset) {
    bool available = false;
    KModErr btf_error = resolve_file_operations_btf_offset("open", offset, available);
    if (available) return btf_error;

    KModErr err = get_offset_cache("file_operations_open", offset);
    if (is_ok(err)) {
        return KModErr::OK;  // already cached
    }

    std::set<uint64_t> field_symbols;
    field_symbols.insert(get_func_ka("dcache_dir_open"));
    field_symbols.insert(get_func_ka("dcache_dir_open.cfi_jt"));
    if (is_empty(field_symbols)) {
        return KModErr::ERR_MODULE_SYMBOL_NOT_EXIST;
    }

    fd_guard probe_fd(open("/dev", O_RDONLY));
    if (probe_fd.get() < 0) {
        return KModErr::ERR_MODULE_OPEN_FILE;
    }

    uint64_t file_ptr = 0;
    err = get_current_task_file_ptr(probe_fd.get(), file_ptr);
    if (is_failed(err)) {
        return err;
    }

    uint32_t f_op_offset = 0;
    err = get_file_f_op_offset(f_op_offset);
    if (is_failed(err)) {
        return err;
    }

    uint64_t f_op = 0;
    err = read_kernel_mem(file_ptr + f_op_offset, &f_op, sizeof(f_op));
    if (is_failed(err)) {
        return err;
    }
    if (f_op < kKernelAddrMin) {
        return KModErr::ERR_MODULE_NOT_KADDR;
    }

    // Scan the whole operations table: the first slot whose value is one of the
    // collected kernel functions is the field.
    for (uint64_t field_offset = 0; field_offset <= 255; field_offset += 8) {
        uint64_t slot_value = 0;
        err = read_kernel_mem(f_op + field_offset, &slot_value, sizeof(slot_value));
        if (is_failed(err)) {
            return err;
        }
        if (slot_value == 0) {
            continue;
        }
        if (field_symbols.find(slot_value) == field_symbols.end()) {
            continue;
        }
        offset = static_cast<uint32_t>(field_offset);
        return put_offset_cache("file_operations_open", offset);
    }

    return KModErr::ERR_MODULE_OFFSET_NOT_FOUND;
}

// Resolves the release slot of struct file_operations: the slot that holds one
// of the kernel functions `dcache_dir_close` / `dcache_dir_close.cfi_jt` is release.
KModErr get_file_operations_release_offset(uint32_t& offset) {
    bool available = false;
    KModErr btf_error = resolve_file_operations_btf_offset("release", offset, available);
    if (available) return btf_error;

    KModErr err = get_offset_cache("file_operations_release", offset);
    if (is_ok(err)) {
        return KModErr::OK;  // already cached
    }

    std::set<uint64_t> field_symbols;
    field_symbols.insert(get_func_ka("dcache_dir_close"));
    field_symbols.insert(get_func_ka("dcache_dir_close.cfi_jt"));
    if (is_empty(field_symbols)) {
        return KModErr::ERR_MODULE_SYMBOL_NOT_EXIST;
    }

    fd_guard probe_fd(open("/dev", O_RDONLY));
    if (probe_fd.get() < 0) {
        return KModErr::ERR_MODULE_OPEN_FILE;
    }

    uint64_t file_ptr = 0;
    err = get_current_task_file_ptr(probe_fd.get(), file_ptr);
    if (is_failed(err)) {
        return err;
    }

    uint32_t f_op_offset = 0;
    err = get_file_f_op_offset(f_op_offset);
    if (is_failed(err)) {
        return err;
    }

    uint64_t f_op = 0;
    err = read_kernel_mem(file_ptr + f_op_offset, &f_op, sizeof(f_op));
    if (is_failed(err)) {
        return err;
    }
    if (f_op < kKernelAddrMin) {
        return KModErr::ERR_MODULE_NOT_KADDR;
    }

    // Scan the whole operations table: the first slot whose value is one of the
    // collected kernel functions is the field.
    for (uint64_t field_offset = 0; field_offset <= 255; field_offset += 8) {
        uint64_t slot_value = 0;
        err = read_kernel_mem(f_op + field_offset, &slot_value, sizeof(slot_value));
        if (is_failed(err)) {
            return err;
        }
        if (slot_value == 0) {
            continue;
        }
        if (field_symbols.find(slot_value) == field_symbols.end()) {
            continue;
        }
        offset = static_cast<uint32_t>(field_offset);
        return put_offset_cache("file_operations_release", offset);
    }

    return KModErr::ERR_MODULE_OFFSET_NOT_FOUND;
}

}  // namespace kernel_module
