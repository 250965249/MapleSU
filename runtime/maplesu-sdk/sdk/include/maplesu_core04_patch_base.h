// maplesu core04 patch base implementation.
//
#pragma once

#include <cstdint>

#include "kernel_module_kit_umbrella.h"

namespace default_modules {
namespace module_root {

class PatchBase {
public:
    PatchBase() = default;
    PatchBase(const PatchBase& other);   // _ZN15default_modules11module_root9PatchBaseC2ERKS1_
    ~PatchBase();                        // _ZN15default_modules11module_root9PatchBaseD2Ev

    // 在 kaddr 处安装 before-hook；handler 的机器码由 a 生成。
    KModErr patch_kernel_before_hook(uint64_t kaddr, const asmjit::a64::Assembler* a);

private:
    uint32_t m_opaque[4];
};

static_assert(sizeof(PatchBase) == 16, "unexpected layout size");
static_assert(alignof(PatchBase) == 4, "layout constraint violated");

}  // namespace module_root
}  // namespace default_modules
