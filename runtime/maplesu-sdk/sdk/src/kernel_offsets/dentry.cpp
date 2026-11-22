// dentry implementation.
//
#include <cstddef>
#include <functional>

#include "kernel_module_kit_umbrella.h"
#include "maplesu_kernel_layout_private.h"

#include "offsets_internal.h"
#include "private_maplesu_paths.h"

#include "offset_probe_private.h"

namespace kernel_module {

KModErr get_dentry_d_iname_offset(uint32_t& offset) {
    KModErr err = get_offset_cache("dentry_d_iname", offset);
    if (is_ok(err)) {
        return err;  // cached, *offset already valid
    }

    std::string dir_path = maplesu::sdk::get_system_file_dir_path();
    std::string dir_name = maplesu::sdk::get_system_file_dir_name();

    scoped_kpath sk;
    err = acquire_kpath(dir_path, sk);
    if (is_failed(err)) {
        return err;
    }

    offset = 0;
    const uint64_t name_len = dir_name.size();
    if (name_len == 0) {
        return KModErr::ERR_MODULE_OFFSET_NOT_FOUND;
    }
    if (name_len > 200) {
        return KModErr::ERR_MODULE_PARAM;
    }

    std::string probe(name_len, '\0');
    for (uint64_t i = 0; i + name_len < 201; i += 4) {
        KModErr read_err = read_kernel_mem(sk.kp.dentry + i, probe.data(),
                                           static_cast<uint32_t>(name_len));
        if (is_failed(read_err)) {
            return read_err;
        }
        if (memcmp(probe.data(), dir_name.data(), name_len) == 0) {
            offset = static_cast<uint32_t>(i);
            break;
        }
    }

    // Index 0 means "not found": a real dentry never starts with d_iname.
    if (offset == 0) {
        return KModErr::ERR_MODULE_OFFSET_NOT_FOUND;
    }
    return put_offset_cache("dentry_d_iname", offset);
}

KModErr get_dentry_d_shortname_offset(uint32_t& offset) {
    return get_dentry_d_iname_offset(offset);
}

KModErr get_dentry_d_name_offset(uint32_t& offset) {
    KernelFieldDescription field;
    bool available = false;
    KModErr error = maplesu_resolve_btf_field("dentry", "d_name", 0, field, available);
    if (available) {
        if (is_ok(error)) offset = field.offset_bytes;
        return error;
    }

    uint32_t anchor = 0;
    KModErr err = get_dentry_d_iname_offset(anchor);
    if (is_ok(err)) {
        if (anchor < 24) return KModErr::ERR_MODULE_OFFSET_NOT_FOUND;
        offset = anchor - 24;
    }
    return err;
}

KModErr get_dentry_d_inode_offset(uint32_t& offset) {
    KernelFieldDescription field;
    bool available = false;
    KModErr error = maplesu_resolve_btf_field("dentry", "d_inode", 8, field, available);
    if (available) {
        if (is_ok(error)) offset = field.offset_bytes;
        return error;
    }

    uint32_t anchor = 0;
    KModErr err = get_dentry_d_iname_offset(anchor);
    if (is_ok(err)) {
        if (anchor < 8) return KModErr::ERR_MODULE_OFFSET_NOT_FOUND;
        offset = anchor - 8;
    }
    return err;
}

KModErr get_dentry_d_parent_offset(uint32_t& offset) {
    KernelFieldDescription field;
    bool available = false;
    KModErr error = maplesu_resolve_btf_field("dentry", "d_parent", 8, field, available);
    if (available) {
        if (is_ok(error)) offset = field.offset_bytes;
        return error;
    }

    uint32_t anchor = 0;
    KModErr err = get_dentry_d_iname_offset(anchor);
    if (is_ok(err)) {
        if (anchor < 32) return KModErr::ERR_MODULE_OFFSET_NOT_FOUND;
        offset = anchor - 32;
    }
    return err;
}

}  // namespace kernel_module
