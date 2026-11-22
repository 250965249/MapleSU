// file struct implementation.
//
#include "kernel_module_kit_umbrella.h"
#include "maplesu_kernel_layout_private.h"

#include "offsets_internal.h"

namespace kernel_module {

KModErr get_file_struct_fdt_offset(uint32_t& offset) {
    KernelFieldDescription field;
    bool available = false;
    const KModErr btf_error = maplesu_resolve_btf_field("files_struct", "fdt", 8, field, available);
    if (available) {
        if (is_ok(btf_error)) offset = field.offset_bytes;
        return btf_error;
    }
    uint32_t fdtab_offset = 0;
    KModErr err = get_file_struct_fdtab_offset(fdtab_offset);
    if (is_ok(err)) {
        if (fdtab_offset < 8) return KModErr::ERR_MODULE_OFFSET_NOT_FOUND;
        offset = fdtab_offset - 8;
    }
    return err;
}

KModErr get_file_struct_fdtab_offset(uint32_t& offset) {
    KernelFieldDescription field;
    bool available = false;
    const KModErr btf_error = maplesu_resolve_btf_field("files_struct", "fdtab", 0, field, available);
    if (available) {
        if (is_ok(btf_error)) offset = field.offset_bytes;
        return btf_error;
    }
    KModErr err = get_offset_cache("file_struct_fdtab", offset);
    if (is_ok(err)) {
        return err;  // already cached
    }

    uint32_t files_offset = 0;
    err = get_task_struct_files_offset(files_offset);
    if (is_failed(err)) {
        return err;
    }

    uint64_t init_files_kaddr = 0;
    err = kallsyms_lookup_name("init_files", init_files_kaddr);
    if (is_failed(err)) {
        return err;
    }

    uint32_t candidate = 0;
    bool found = false;
    for (uint64_t i = 0; i < 64; i += 4) {
        uint32_t max_fds = 0;
        err = read_kernel_mem(init_files_kaddr + i, &max_fds, sizeof(max_fds));
        if (is_failed(err)) {
            return err;
        }
        if (max_fds == 64) {
            candidate = static_cast<uint32_t>(i);
            found = true;
            break;
        }
    }

    if (!found) {
        return KModErr::ERR_MODULE_OFFSET_NOT_FOUND;
    }
    err = put_offset_cache("file_struct_fdtab", candidate);
    if (is_ok(err)) offset = candidate;
    return err;
}

}  // namespace kernel_module
