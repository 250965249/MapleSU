// fdtable implementation.
//
#include "kernel_module_kit_umbrella.h"
#include "maplesu_kernel_layout_private.h"

#include "offsets_internal.h"

namespace kernel_module {

KModErr get_fdtable_fd_offset(uint32_t& offset) {
    KernelFieldDescription field;
    bool available = false;
    const KModErr btf_error = maplesu_resolve_btf_field("fdtable", "fd", 8, field, available);
    if (available) {
        if (is_ok(btf_error)) offset = field.offset_bytes;
        return btf_error;
    }
    KModErr err = get_offset_cache("fdtable_fd", offset);
    if (is_ok(err)) {
        return err;  // already cached
    }

    uint64_t init_files_kaddr = 0;
    err = kallsyms_lookup_name("init_files", init_files_kaddr);
    if (is_failed(err)) {
        return err;
    }

    uint32_t fdtab_offset = 0;
    err = get_file_struct_fdtab_offset(fdtab_offset);
    if (is_failed(err)) {
        return err;
    }

    offset = 0;
    for (uint64_t i = 0; i < 32; i += 4) {
        uint64_t candidate = 0;
        err = read_kernel_mem(init_files_kaddr + i + fdtab_offset, &candidate, sizeof(candidate));
        if (is_failed(err)) {
            return err;
        }
        if (candidate > init_files_kaddr && candidate < init_files_kaddr + 300) {
            offset = static_cast<uint32_t>(i);
            break;
        }
    }

    if (offset == 0) {
        return KModErr::ERR_MODULE_OFFSET_NOT_FOUND;
    }
    return put_offset_cache("fdtable_fd", offset);
}

}  // namespace kernel_module
