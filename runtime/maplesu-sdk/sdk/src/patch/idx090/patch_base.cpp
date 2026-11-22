// patch base implementation.
//
#include "kernel_module_kit_umbrella.h"

#include <cstdint>
#include <vector>

#include "aarch64_asm_helper.h"
#include "module_base_kernel_func_hook.h"
#include "module_base_kernel_symbol_kaddr.h"
#include "third_party/____DO_NOT_EDIT____/private_mod_api_runtime_helper.h"

#include "../patch_base_0091.h"

PatchBase::PatchBase() {}
PatchBase::PatchBase(const PatchBase&) {}
PatchBase::~PatchBase() {}

// install_kernel_function_before_hook 是 private_mod_api_runtime_helper.h 里的
// kernel_module::install_kfunc_before_hook_with_buf(kaddr, data, len, nullptr)。
KModErr PatchBase::patch_kernel_before_hook(uint64_t kaddr,
                                            const asmjit::v1_16::a64::Assembler* a) {
    std::vector<uint8_t> bytes = aarch64_asm_to_bytes(a);
    return kernel_module::install_kernel_function_before_hook(kaddr, bytes);
}

KModErr PatchBase::patch_kernel_after_hook(uint64_t kaddr,
                                           const asmjit::v1_16::a64::Assembler* a) {
    std::vector<uint8_t> bytes = aarch64_asm_to_bytes(a);
    return kernel_module::install_kernel_function_after_hook(kaddr, bytes);
}
