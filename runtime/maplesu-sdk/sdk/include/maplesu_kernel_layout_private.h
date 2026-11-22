#pragma once

#include <cstdint>
#include "module_err_def.h"

namespace kernel_module {
struct KernelFieldDescription {
    uint32_t offset_bytes = 0;
    uint32_t width_bytes = 0;
    uint32_t owner_size_bytes = 0;
    const char* source = "btf";
    const char* reader = nullptr;
    uint32_t parser_version = 1;
};

// A missing blob permits a separate read-only compatibility entry. A present but invalid blob
// returns its parsing error and must never trigger candidate credential writes.
KModErr maplesu_resolve_btf_field(const char* owner, const char* member,
    uint32_t expected_width, KernelFieldDescription& field, bool& blob_available);

// Resolve native kprobe address/opcode fields. BTF is authoritative; when
// the target has no BTF, derive both fields from arch_prepare_kprobe only after
// its actual instruction dataflow proves the copy/store pair.
KModErr maplesu_resolve_kprobe_fields(KernelFieldDescription& addr,
    KernelFieldDescription& opcode, bool& blob_available);

// Only the missing-blob branches call this bounded target-code reader.
KModErr maplesu_resolve_accessor_field(const char* owner, const char* member,
    uint32_t expected_width, KernelFieldDescription& field);
}
