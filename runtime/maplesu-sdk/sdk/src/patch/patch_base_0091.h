// patch base 0091 implementation.
//
#pragma once

#include <cstdint>

#include "module_err_def.h"

namespace asmjit {
namespace v1_16 {
namespace a64 {
class Assembler;
}  // namespace a64
}  // namespace v1_16
}  // namespace asmjit

class PatchBase {
public:
    PatchBase();
    PatchBase(const PatchBase&);
    ~PatchBase();

    // 生成好的 AArch64 桩代码直接就地安装为内核函数 hook。
    // 两条路径都以 aarch64_asm_to_bytes() 取字节流，再交给 kernel_module 的
    KModErr patch_kernel_before_hook(uint64_t kaddr, const asmjit::v1_16::a64::Assembler* a);
    KModErr patch_kernel_after_hook(uint64_t kaddr, const asmjit::v1_16::a64::Assembler* a);
};

static_assert(sizeof(PatchBase) == 1, "PatchBase must stay an empty marker class");
