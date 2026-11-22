#pragma once
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace maplesu::module_policy {
struct LayoutField {
    std::string name;
    uint32_t bit_offset;
    uint32_t bit_size;
};
struct LayoutType {
    std::string name;
    // Zero permits a container to grow when all accessed fields still match.
    uint32_t size;
    std::vector<LayoutField> fields;
};
struct KernelFunctionAbi {
    std::string name;
    std::string signature;
};
struct LayoutTypeRequest {
    std::string name;
    std::vector<std::string> fields;
};
struct KernelLayoutDescription {
    std::vector<LayoutType> types;
    std::vector<KernelFunctionAbi> functions;
};
// Resolve only consumed types/fields. Duplicate definitions must agree; callers
// still validate field widths and supported function semantics before use.
// Dotted field paths select embedded members, for example seccomp.mode.
// An empty type request with nonempty functions describes only function ABIs.
KernelLayoutDescription describe_kernel_layout(const std::vector<uint8_t>& btf,
    const std::vector<LayoutTypeRequest>& required,
    const std::vector<std::string>& functions = {});
// Resolve cred through each complete task_struct.cred pointer, rather than an
// unrelated globally named cred. Both returned layouts must agree across tasks.
KernelLayoutDescription describe_task_credential_layout(const std::vector<uint8_t>& btf,
    const std::vector<std::string>& task_fields,
    const std::vector<std::string>& credential_fields);
// Return field ABIs from those same task/pointee pairs, in task then cred order.
// The output is replaced only after every linked definition agrees.
KernelLayoutDescription describe_task_credential_layout(const std::vector<uint8_t>& btf,
    const std::vector<std::string>& task_fields,
    const std::vector<std::string>& credential_fields,
    std::vector<KernelFunctionAbi>& field_abis);
// Value-type ABI when transport semantics require more than a field's width.
std::vector<KernelFunctionAbi> describe_kernel_fields(const std::vector<uint8_t>& btf,
    const std::vector<LayoutTypeRequest>& required);
struct KernelFieldRelocation {
    std::string type, member;
    bool embedded = false;
    bool bitfield = false;
    uint32_t alignment_bits = 0;
};
// Resolve the same BTF contract used by verification. Only explicitly consumed
// relocations may differ; all remaining inline/object/function ABIs stay checked.
std::vector<LayoutType> resolve_kernel_layout(
    const std::vector<uint8_t>& btf, const std::vector<LayoutType>& required,
    const std::vector<KernelFieldRelocation>& relocated_fields,
    const std::vector<std::string>& resized_types,
    const std::vector<KernelFunctionAbi>& functions = {});
// Validate all required layouts before the first payload allocation or hook.
// Reads only the supplied BTF image; never caches a verdict across boots.
void verify_kernel_layout(const std::vector<uint8_t>& btf,
                          const std::vector<LayoutType>& required,
                          const std::vector<KernelFunctionAbi>& functions = {});
}
