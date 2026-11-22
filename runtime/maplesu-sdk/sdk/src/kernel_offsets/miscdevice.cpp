// miscdevice implementation.
//
#include "kernel_module_kit_umbrella.h"
#include "maplesu_kernel_layout_private.h"

namespace kernel_module {

KModErr get_miscdevice_offsets(miscdevice_offsets& offsets) {
    const struct {
        const char* name;
        uint32_t width;
        uint32_t miscdevice_offsets::*offset;
    } members[] = {
        {"minor", 4, &miscdevice_offsets::minor_offset},
        {"name", 8, &miscdevice_offsets::name_offset},
        {"fops", 8, &miscdevice_offsets::fops_offset},
        {"list", 16, &miscdevice_offsets::list_offset},
    };
    miscdevice_offsets resolved;
    uint32_t owner_size = 0;
    for (const auto& member : members) {
        KernelFieldDescription field;
        bool available = false;
        KModErr error = maplesu_resolve_btf_field("miscdevice", member.name, member.width, field, available);
        if (!owner_size && !available) break;
        if (is_failed(error)) return error;
        if (!available || (owner_size && owner_size != field.owner_size_bytes))
            return KModErr::ERR_MODULE_OFFSET_NOT_FOUND;
        owner_size = field.owner_size_bytes;
        resolved.*member.offset = field.offset_bytes;
    }
    if (owner_size) {
        offsets = resolved;
        return KModErr::OK;
    }

    offsets.minor_offset = 0;
    offsets.name_offset = 8;
    offsets.fops_offset = 16;
    offsets.list_offset = 24;
    return KModErr::OK;
}

}  // namespace kernel_module
