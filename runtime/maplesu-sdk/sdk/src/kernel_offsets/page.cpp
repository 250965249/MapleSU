// page implementation.
//
#include "kernel_module_kit_umbrella.h"
#include "maplesu_kernel_layout_private.h"

#include "offsets_internal.h"

namespace kernel_module {

KModErr get_struct_page_size(uint32_t& size) {
    KernelFieldDescription field;
    bool available = false;
    const KModErr btf_error = maplesu_resolve_btf_field("page", nullptr, 0, field, available);
    if (available) {
        if (is_ok(btf_error)) size = field.owner_size_bytes;
        return btf_error;
    }
    KModErr err = get_offset_cache("struct_page_size", size);
    if (is_ok(err)) {
        return err;  // already cached
    }

    uint64_t vmemmap = 0;
    uint64_t struct_page_size = 0;
    err = calibrate_vmemmap_dynamic(vmemmap, struct_page_size);
    if (is_failed(err)) {
        return err;
    }

    size = static_cast<uint32_t>(struct_page_size);
    if (size == 0) {
        return KModErr::ERR_MODULE_OFFSET_NOT_FOUND;
    }
    return put_offset_cache("struct_page_size", size);
}

}  // namespace kernel_module
