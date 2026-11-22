// inode_operations implementation.
//
#include <fcntl.h>
#include <unistd.h>

#include <cstdint>
#include <set>
#include <string>

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

// One probe path: a path whose inode_operations table is known to install the
// given entry callback, plus the CFI variant of the same callback.
struct TargetInfo {
    const char* path;
    const char* entry_symbol;
    const char* cfi_entry_symbol;
};

KModErr resolve_inode_operations_btf_offset(const char* member, uint32_t& offset,
                                            bool& available) {
    KernelFieldDescription field;
    KModErr error = maplesu_resolve_btf_field("inode_operations", member, 8, field, available);
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

// Resolves the lookup slot of struct inode_operations: for a path whose inode
// installs lookup through a known kernel function, the operations slot that
// holds that function (or its CFI variant) is the lookup slot.
KModErr get_inode_operations_lookup_offset(uint32_t& offset) {
    bool available = false;
    KModErr btf_error = resolve_inode_operations_btf_offset("lookup", offset, available);
    if (available) return btf_error;

    KModErr err = get_offset_cache("inode_operations_lookup", offset);
    if (is_ok(err)) {
        return KModErr::OK;  // already cached
    }

    uint32_t i_op_offset = 0;
    err = get_inode_i_op_offset(i_op_offset);
    if (is_failed(err)) {
        return err;
    }
    uint32_t d_inode_offset = 0;
    err = get_dentry_d_inode_offset(d_inode_offset);
    if (is_failed(err)) {
        return err;
    }

    static const TargetInfo targets[2] = {{"/sys", "kernfs_iop_lookup", "kernfs_iop_lookup.cfi_jt"}, {"/proc", "proc_root_lookup", "proc_root_lookup.cfi_jt"}};
    for (uint64_t target_index = 0; target_index < 2; ++target_index) {
        const TargetInfo& target = targets[target_index];
        std::set<uint64_t> target_symbols;
        target_symbols.insert(get_func_ka(target.entry_symbol));
        target_symbols.insert(get_func_ka(target.cfi_entry_symbol));
        if (is_empty(target_symbols)) {
            continue;
        }

        fd_guard path_fd(open(target.path, O_DIRECTORY));
        if (path_fd.get() < 0) {
            continue;
        }

        scoped_kpath path_entry;
        std::string path_name(target.path);
        err = acquire_kpath(path_name, path_entry);
        if (is_failed(err)) {
            continue;
        }

        // dentry->d_inode -> inode->i_op
        uint64_t inode = 0;
        err = read_kernel_mem(path_entry.kp.dentry + d_inode_offset, &inode, sizeof(inode));
        if (is_failed(err) || inode < kKernelAddrMin) {
            continue;
        }
        uint64_t i_op = 0;
        err = read_kernel_mem(inode + i_op_offset, &i_op, sizeof(i_op));
        if (is_failed(err) || i_op < kKernelAddrMin) {
            continue;
        }

        for (uint64_t field_offset = 0; field_offset < 256; field_offset += 8) {
            bool read_ok = false;
            uint64_t slot_value = 0;
            err = safe_read_kaddr_t(i_op + field_offset, read_ok, slot_value);
            if (is_failed(err)) {
                return err;
            }
            if (!read_ok) {
                break;
            }
            if (slot_value == 0) {
                continue;
            }
            if (target_symbols.find(slot_value) == target_symbols.end()) {
                continue;
            }
            offset = static_cast<uint32_t>(field_offset);
            return put_offset_cache("inode_operations_lookup", offset);
        }
    }

    return KModErr::ERR_MODULE_OFFSET_NOT_FOUND;
}

// Resolves the permission slot of struct inode_operations: for a path whose inode
// installs permission through a known kernel function, the operations slot that
// holds that function (or its CFI variant) is the permission slot.
KModErr get_inode_operations_permission_offset(uint32_t& offset) {
    bool available = false;
    KModErr btf_error = resolve_inode_operations_btf_offset("permission", offset, available);
    if (available) return btf_error;

    KModErr err = get_offset_cache("inode_operations_permission", offset);
    if (is_ok(err)) {
        return KModErr::OK;  // already cached
    }

    uint32_t i_op_offset = 0;
    err = get_inode_i_op_offset(i_op_offset);
    if (is_failed(err)) {
        return err;
    }
    uint32_t d_inode_offset = 0;
    err = get_dentry_d_inode_offset(d_inode_offset);
    if (is_failed(err)) {
        return err;
    }

    static const TargetInfo targets[2] = {{"/sys", "kernfs_iop_permission", "kernfs_iop_permission.cfi_jt"}, {"/proc/self", "proc_pid_permission", "proc_pid_permission.cfi_jt"}};
    for (uint64_t target_index = 0; target_index < 2; ++target_index) {
        const TargetInfo& target = targets[target_index];
        std::set<uint64_t> target_symbols;
        target_symbols.insert(get_func_ka(target.entry_symbol));
        target_symbols.insert(get_func_ka(target.cfi_entry_symbol));
        if (is_empty(target_symbols)) {
            continue;
        }

        fd_guard path_fd(open(target.path, O_DIRECTORY));
        if (path_fd.get() < 0) {
            continue;
        }

        scoped_kpath path_entry;
        std::string path_name(target.path);
        err = acquire_kpath(path_name, path_entry);
        if (is_failed(err)) {
            continue;
        }

        // dentry->d_inode -> inode->i_op
        uint64_t inode = 0;
        err = read_kernel_mem(path_entry.kp.dentry + d_inode_offset, &inode, sizeof(inode));
        if (is_failed(err) || inode < kKernelAddrMin) {
            continue;
        }
        uint64_t i_op = 0;
        err = read_kernel_mem(inode + i_op_offset, &i_op, sizeof(i_op));
        if (is_failed(err) || i_op < kKernelAddrMin) {
            continue;
        }

        for (uint64_t field_offset = 0; field_offset < 256; field_offset += 8) {
            bool read_ok = false;
            uint64_t slot_value = 0;
            err = safe_read_kaddr_t(i_op + field_offset, read_ok, slot_value);
            if (is_failed(err)) {
                return err;
            }
            if (!read_ok) {
                break;
            }
            if (slot_value == 0) {
                continue;
            }
            if (target_symbols.find(slot_value) == target_symbols.end()) {
                continue;
            }
            offset = static_cast<uint32_t>(field_offset);
            return put_offset_cache("inode_operations_permission", offset);
        }
    }

    return KModErr::ERR_MODULE_OFFSET_NOT_FOUND;
}

// Resolves the getattr slot of struct inode_operations: for a path whose inode
// installs getattr through a known kernel function, the operations slot that
// holds that function (or its CFI variant) is the getattr slot.
KModErr get_inode_operations_getattr_offset(uint32_t& offset) {
    bool available = false;
    KModErr btf_error = resolve_inode_operations_btf_offset("getattr", offset, available);
    if (available) return btf_error;

    KModErr err = get_offset_cache("inode_operations_getattr", offset);
    if (is_ok(err)) {
        return KModErr::OK;  // already cached
    }

    uint32_t i_op_offset = 0;
    err = get_inode_i_op_offset(i_op_offset);
    if (is_failed(err)) {
        return err;
    }
    uint32_t d_inode_offset = 0;
    err = get_dentry_d_inode_offset(d_inode_offset);
    if (is_failed(err)) {
        return err;
    }

    static const TargetInfo targets[2] = {{"/sys", "kernfs_iop_getattr", "kernfs_iop_getattr.cfi_jt"}, {"/proc/self", "proc_pid_getattr", "proc_pid_getattr.cfi_jt"}};
    for (uint64_t target_index = 0; target_index < 2; ++target_index) {
        const TargetInfo& target = targets[target_index];
        std::set<uint64_t> target_symbols;
        target_symbols.insert(get_func_ka(target.entry_symbol));
        target_symbols.insert(get_func_ka(target.cfi_entry_symbol));
        if (is_empty(target_symbols)) {
            continue;
        }

        fd_guard path_fd(open(target.path, O_DIRECTORY));
        if (path_fd.get() < 0) {
            continue;
        }

        scoped_kpath path_entry;
        std::string path_name(target.path);
        err = acquire_kpath(path_name, path_entry);
        if (is_failed(err)) {
            continue;
        }

        // dentry->d_inode -> inode->i_op
        uint64_t inode = 0;
        err = read_kernel_mem(path_entry.kp.dentry + d_inode_offset, &inode, sizeof(inode));
        if (is_failed(err) || inode < kKernelAddrMin) {
            continue;
        }
        uint64_t i_op = 0;
        err = read_kernel_mem(inode + i_op_offset, &i_op, sizeof(i_op));
        if (is_failed(err) || i_op < kKernelAddrMin) {
            continue;
        }

        for (uint64_t field_offset = 0; field_offset < 256; field_offset += 8) {
            bool read_ok = false;
            uint64_t slot_value = 0;
            err = safe_read_kaddr_t(i_op + field_offset, read_ok, slot_value);
            if (is_failed(err)) {
                return err;
            }
            if (!read_ok) {
                break;
            }
            if (slot_value == 0) {
                continue;
            }
            if (target_symbols.find(slot_value) == target_symbols.end()) {
                continue;
            }
            offset = static_cast<uint32_t>(field_offset);
            return put_offset_cache("inode_operations_getattr", offset);
        }
    }

    return KModErr::ERR_MODULE_OFFSET_NOT_FOUND;
}

// Resolves the setattr slot of struct inode_operations: for a path whose inode
// installs setattr through a known kernel function, the operations slot that
// holds that function (or its CFI variant) is the setattr slot.
KModErr get_inode_operations_setattr_offset(uint32_t& offset) {
    bool available = false;
    KModErr btf_error = resolve_inode_operations_btf_offset("setattr", offset, available);
    if (available) return btf_error;

    KModErr err = get_offset_cache("inode_operations_setattr", offset);
    if (is_ok(err)) {
        return KModErr::OK;  // already cached
    }

    uint32_t i_op_offset = 0;
    err = get_inode_i_op_offset(i_op_offset);
    if (is_failed(err)) {
        return err;
    }
    uint32_t d_inode_offset = 0;
    err = get_dentry_d_inode_offset(d_inode_offset);
    if (is_failed(err)) {
        return err;
    }

    static const TargetInfo targets[2] = {{"/sys", "kernfs_iop_setattr", "kernfs_iop_setattr.cfi_jt"}, {"/proc/self", "proc_setattr", "proc_setattr.cfi_jt"}};
    for (uint64_t target_index = 0; target_index < 2; ++target_index) {
        const TargetInfo& target = targets[target_index];
        std::set<uint64_t> target_symbols;
        target_symbols.insert(get_func_ka(target.entry_symbol));
        target_symbols.insert(get_func_ka(target.cfi_entry_symbol));
        if (is_empty(target_symbols)) {
            continue;
        }

        fd_guard path_fd(open(target.path, O_DIRECTORY));
        if (path_fd.get() < 0) {
            continue;
        }

        scoped_kpath path_entry;
        std::string path_name(target.path);
        err = acquire_kpath(path_name, path_entry);
        if (is_failed(err)) {
            continue;
        }

        // dentry->d_inode -> inode->i_op
        uint64_t inode = 0;
        err = read_kernel_mem(path_entry.kp.dentry + d_inode_offset, &inode, sizeof(inode));
        if (is_failed(err) || inode < kKernelAddrMin) {
            continue;
        }
        uint64_t i_op = 0;
        err = read_kernel_mem(inode + i_op_offset, &i_op, sizeof(i_op));
        if (is_failed(err) || i_op < kKernelAddrMin) {
            continue;
        }

        for (uint64_t field_offset = 0; field_offset < 256; field_offset += 8) {
            bool read_ok = false;
            uint64_t slot_value = 0;
            err = safe_read_kaddr_t(i_op + field_offset, read_ok, slot_value);
            if (is_failed(err)) {
                return err;
            }
            if (!read_ok) {
                break;
            }
            if (slot_value == 0) {
                continue;
            }
            if (target_symbols.find(slot_value) == target_symbols.end()) {
                continue;
            }
            offset = static_cast<uint32_t>(field_offset);
            return put_offset_cache("inode_operations_setattr", offset);
        }
    }

    return KModErr::ERR_MODULE_OFFSET_NOT_FOUND;
}

// Reads the CFI type hash that guards the lookup callback: the hash is stored in
// the 32-bit word right before a CFI-checked kernel function entry, so the first
// resolvable target symbol with a non-zero preceding word provides it.
KModErr get_inode_operations_lookup_kcfi_hash(uint32_t& out_hash) {
    KModErr err = get_offset_cache("inode_operations_lookup_kcfi_hash", out_hash);
    if (is_ok(err)) {
        return KModErr::OK;  // already cached
    }

    static const char* target_syms[2] = {"kernfs_iop_lookup", "proc_root_lookup"};
    for (uint64_t symbol_index = 0; symbol_index < 2; ++symbol_index) {
        const uint64_t func_ka = get_func_ka(target_syms[symbol_index]);
        if (func_ka == 0) {
            continue;
        }
        uint32_t cfi_hash = 0;
        bool read_ok = false;
        err = safe_read_kaddr_t(func_ka - 4, read_ok, cfi_hash);
        if (is_failed(err)) {
            return err;
        }
        if (read_ok && cfi_hash != 0) {
            out_hash = cfi_hash;
            return put_offset_cache("inode_operations_lookup_kcfi_hash", cfi_hash);
        }
    }

    return KModErr::ERR_MODULE_OFFSET_NOT_FOUND;
}

// Reads the CFI type hash that guards the permission callback: the hash is stored in
// the 32-bit word right before a CFI-checked kernel function entry, so the first
// resolvable target symbol with a non-zero preceding word provides it.
KModErr get_inode_operations_permission_kcfi_hash(uint32_t& out_hash) {
    KModErr err = get_offset_cache("inode_operations_permission_kcfi_hash", out_hash);
    if (is_ok(err)) {
        return KModErr::OK;  // already cached
    }

    static const char* target_syms[2] = {"kernfs_iop_permission", "proc_pid_permission"};
    for (uint64_t symbol_index = 0; symbol_index < 2; ++symbol_index) {
        const uint64_t func_ka = get_func_ka(target_syms[symbol_index]);
        if (func_ka == 0) {
            continue;
        }
        uint32_t cfi_hash = 0;
        bool read_ok = false;
        err = safe_read_kaddr_t(func_ka - 4, read_ok, cfi_hash);
        if (is_failed(err)) {
            return err;
        }
        if (read_ok && cfi_hash != 0) {
            out_hash = cfi_hash;
            return put_offset_cache("inode_operations_permission_kcfi_hash", cfi_hash);
        }
    }

    return KModErr::ERR_MODULE_OFFSET_NOT_FOUND;
}

// Reads the CFI type hash that guards the getattr callback: the hash is stored in
// the 32-bit word right before a CFI-checked kernel function entry, so the first
// resolvable target symbol with a non-zero preceding word provides it.
KModErr get_inode_operations_getattr_kcfi_hash(uint32_t& out_hash) {
    KModErr err = get_offset_cache("inode_operations_getattr_kcfi_hash", out_hash);
    if (is_ok(err)) {
        return KModErr::OK;  // already cached
    }

    static const char* target_syms[2] = {"kernfs_iop_getattr", "proc_pid_getattr"};
    for (uint64_t symbol_index = 0; symbol_index < 2; ++symbol_index) {
        const uint64_t func_ka = get_func_ka(target_syms[symbol_index]);
        if (func_ka == 0) {
            continue;
        }
        uint32_t cfi_hash = 0;
        bool read_ok = false;
        err = safe_read_kaddr_t(func_ka - 4, read_ok, cfi_hash);
        if (is_failed(err)) {
            return err;
        }
        if (read_ok && cfi_hash != 0) {
            out_hash = cfi_hash;
            return put_offset_cache("inode_operations_getattr_kcfi_hash", cfi_hash);
        }
    }

    return KModErr::ERR_MODULE_OFFSET_NOT_FOUND;
}

// Reads the CFI type hash that guards the setattr callback: the hash is stored in
// the 32-bit word right before a CFI-checked kernel function entry, so the first
// resolvable target symbol with a non-zero preceding word provides it.
KModErr get_inode_operations_setattr_kcfi_hash(uint32_t& out_hash) {
    KModErr err = get_offset_cache("inode_operations_setattr_kcfi_hash", out_hash);
    if (is_ok(err)) {
        return KModErr::OK;  // already cached
    }

    static const char* target_syms[2] = {"kernfs_iop_setattr", "proc_setattr"};
    for (uint64_t symbol_index = 0; symbol_index < 2; ++symbol_index) {
        const uint64_t func_ka = get_func_ka(target_syms[symbol_index]);
        if (func_ka == 0) {
            continue;
        }
        uint32_t cfi_hash = 0;
        bool read_ok = false;
        err = safe_read_kaddr_t(func_ka - 4, read_ok, cfi_hash);
        if (is_failed(err)) {
            return err;
        }
        if (read_ok && cfi_hash != 0) {
            out_hash = cfi_hash;
            return put_offset_cache("inode_operations_setattr_kcfi_hash", cfi_hash);
        }
    }

    return KModErr::ERR_MODULE_OFFSET_NOT_FOUND;
}

}  // namespace kernel_module
