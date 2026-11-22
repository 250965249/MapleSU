#include "jailbreak_status_layout.h"
#include "kernel_layout.h"
#include <stdexcept>
#include <string>

namespace maplesu::module_policy {
msu_selinux_layout resolve_jailbreak_status_anchors(const msu_selinux_anchors& anchors,
                                                   uint32_t page_bytes) {
    msu_selinux_layout result{};
    if (!msu_status_layout_from_anchors(&anchors, page_bytes, &result) || !msu_status_layout_valid(&result))
        throw std::runtime_error("JAILBREAK_SELINUX_NATIVE_ANCHORS_UNRESOLVED");
    return result;
}
msu_selinux_layout resolve_jailbreak_status_layout(const std::vector<uint8_t>& btf,
                                                  uint32_t page_bytes) {
    const std::vector<KernelFunctionAbi> common = {
        {"vm_map_ram", "f*v(**spage;i4:32;i4:16777248;)"},
        {"vm_unmap_ram", "fv(*v;i4:32;)"},
        {"mutex_lock", "fv(*smutex;)"}, {"mutex_unlock", "fv(*smutex;)"},
        {"try_module_get", "fi1:67108872(*smodule;)"},
        {"simple_read_from_buffer", "fi8:16777280(*v;i8:64;*i8:16777280;*v;i8:64;)"},
        {"copy_from_user_nofault", "fi8:16777280(*v;*v;i8:64;)"},
        {"copy_to_user_nofault", "fi8:16777280(*v;*v;i8:64;)"},
        {"sel_read_handle_status", "fi8:16777280(*sfile;*i1:8;i8:64;*i8:16777280;)"},
    };
    std::vector<std::string> functions;
    for (const auto& function : common) functions.push_back(function.name);
    functions.push_back("selinux_kernel_status_page");
    auto description = describe_kernel_layout(btf, {
        {"selinux_state", {"status_lock"}}, {"mutex", {}},
        {"selinux_kernel_status", {"version", "sequence", "enforcing", "policyload", "deny_unknown"}},
    }, functions);
    for (size_t i = 0; i < common.size(); ++i)
        if (description.functions[i].signature != common[i].signature)
            throw std::runtime_error("JAILBREAK_SELINUX_ABI:" + common[i].name);
    const auto& status = description.types[2];
    if (status.size != sizeof(msu_selinux_status))
        throw std::runtime_error("JAILBREAK_SELINUX_STATUS_SIZE");
    for (size_t i = 0; i < status.fields.size(); ++i)
        if (status.fields[i].bit_offset != i * 32 || status.fields[i].bit_size != 32)
            throw std::runtime_error("JAILBREAK_SELINUX_STATUS_FIELD:" + status.fields[i].name);
    const auto& signature = description.functions.back().signature;
    if (signature != "f*spage()" && signature != "f*spage(*sselinux_state;)")
        throw std::runtime_error("JAILBREAK_SELINUX_ABI:selinux_kernel_status_page");
    const auto& state = description.types[0];
    const auto& lock = state.fields[0];
    const auto& mutex = description.types[1];
    if (lock.bit_offset % 8 || uint64_t(lock.bit_size) != uint64_t(mutex.size) * 8)
        throw std::runtime_error("JAILBREAK_SELINUX_MUTEX_LAYOUT");
    msu_selinux_layout result{MSU_STATUS_RUNTIME_BTF, state.size, lock.bit_offset / 8,
        mutex.size, page_bytes, signature == "f*spage(*sselinux_state;)" ? 1u : 0u};
    if (!msu_status_layout_valid(&result)) throw std::runtime_error("JAILBREAK_SELINUX_LAYOUT_RANGE");
    return result;
}
}
