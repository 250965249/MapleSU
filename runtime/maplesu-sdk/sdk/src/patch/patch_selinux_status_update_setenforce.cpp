// patch selinux status update setenforce implementation.
//
#include "kernel_module_kit_umbrella.h"

#include <cstdint>

#include "aarch64_asm_helper.h"
#include "aarch64_asm_reg_protect_guard.h"
#include "module_base_kernel_func_hook.h"
#include "maplesu_hook_private.h"

#include "patch_base_0091.h"

using namespace asmjit;
using namespace asmjit::a64;

namespace {

// 这里直接复用 aarch64_asm_helper.h 里的同名实现，见 .cpp 顶部 include。

}  // namespace

class PatchSelinuxStatusUpdateSetenforce : public PatchBase {
public:
    PatchSelinuxStatusUpdateSetenforce(const PatchBase& base, uint64_t hook_kaddr);
    ~PatchSelinuxStatusUpdateSetenforce();

    // selinux_status_update_setenforce 的 before-hook 桩生成 + 安装。
    //   func_addr  : 目标函数入口（本机内核地址）
    //   new_value  : 写入 x10 的新值
    KModErr patch_selinux_status_update_setenforce(uint64_t func_addr,
                                                   uint32_t patch_len,
                                                   uint64_t new_value);
    KModErr patch_selinux_status_update_setenforce(uint64_t func_addr,
                                                   uint32_t patch_len,
                                                   uint64_t new_value,
                                                   kernel_module::HookHandle* handle);
    __attribute__((visibility("hidden"))) KModErr patch_selinux_status_update_setenforce(uint64_t func_addr,
                                                   uint32_t patch_len,
                                                   uint64_t new_value,
                                                   kernel_module::HookHandle* handle,
                                                   const kernel_module::RequestSharedBool* dependency);

private:
    uint64_t m_hook_kaddr = 0;
};

static_assert(sizeof(PatchSelinuxStatusUpdateSetenforce) == 8,
              "PatchSelinuxStatusUpdateSetenforce must stay 8 bytes (empty PatchBase + u64)");

PatchSelinuxStatusUpdateSetenforce::PatchSelinuxStatusUpdateSetenforce(const PatchBase& base,
                                                                      uint64_t hook_kaddr)
    : PatchBase(base), m_hook_kaddr(hook_kaddr) {}

PatchSelinuxStatusUpdateSetenforce::~PatchSelinuxStatusUpdateSetenforce() {}

KModErr PatchSelinuxStatusUpdateSetenforce::patch_selinux_status_update_setenforce(
    uint64_t func_addr, uint32_t patch_len, uint64_t new_value) {
    return patch_selinux_status_update_setenforce(func_addr, patch_len, new_value, nullptr);
}

KModErr PatchSelinuxStatusUpdateSetenforce::patch_selinux_status_update_setenforce(
    uint64_t func_addr, uint32_t patch_len, uint64_t new_value,
    kernel_module::HookHandle* handle) {
    return patch_selinux_status_update_setenforce(func_addr, patch_len, new_value, handle, nullptr);
}

KModErr PatchSelinuxStatusUpdateSetenforce::patch_selinux_status_update_setenforce(
    uint64_t func_addr, uint32_t patch_len, uint64_t new_value,
    kernel_module::HookHandle* handle, const kernel_module::RequestSharedBool* dependency) {
    if (dependency && dependency->address != new_value) return KModErr::ERR_MODULE_PARAM;
    const uint64_t status_word_addr = func_addr + static_cast<uint64_t>(patch_len);

    aarch64_asm_ctx asm_ctx = init_aarch64_asm();
    auto* a = asm_ctx.assembler();

    Label skip = a->newLabel();

    kernel_module::arm64_before_hook_start(a);

    // mov x10, #new_value ; ldrb w10, [x10] ; cbz w10, skip
    aarch64_asm_mov_x(a, x10, new_value);
    a->ldrb(w10, ptr(x10));
    a->cbz(w10, skip);

    // mov x10, status_word_addr ; ldr w11, [x10]
    aarch64_asm_mov_x(a, x10, status_word_addr);
    a->ldr(w11, ptr(x10));
    {
        // 手动调用原函数，必须保护 x10 / x11（原函数可自由改写 caller-saved 寄存器）。
        RegProtectGuard g(a, x10, x11);
        kernel_module::arm64_emit_call_original(a);
    }
    // 把原函数写过的那个字恢复回去。
    a->str(w11, ptr(x10));

    kernel_module::arm64_before_hook_end(a, false);
    a->bind(skip);
    kernel_module::arm64_before_hook_end(a, true);

    if (handle || dependency) {
        auto bytes = aarch64_asm_to_bytes(a);
        if (asm_ctx.has_error() || bytes.empty()) return KModErr::ERR_MODULE_PARAM;
        if (dependency)
            return kernel_module::maplesu_install_owned_hook_with_shared_bools(m_hook_kaddr,
                bytes.data(), static_cast<uint32_t>(bytes.size()), false, dependency, 1, handle);
        return kernel_module::install_kernel_function_before_hook(m_hook_kaddr, bytes, handle);
    }
    return PatchBase::patch_kernel_before_hook(m_hook_kaddr, a);
}
