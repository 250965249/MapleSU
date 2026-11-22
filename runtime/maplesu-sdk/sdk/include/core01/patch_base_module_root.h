// patch base module root implementation.
//
#pragma once

#include <cstdint>

#include "kernel_module_kit_umbrella.h"

namespace default_modules {
namespace module_root {

/***************************************************************************
 * 基座。成员函数由 patch_base.o (idx 83) 提供；这里只声明 + 钉住布局。
 ***************************************************************************/
class PatchBase {
public:
    PatchBase(uint32_t arg0, uint32_t arg1);
    PatchBase(const PatchBase& other);
    ~PatchBase();

protected:
    uint32_t m_arg0 = 0;
    uint32_t m_arg1 = 0;
    uint32_t m_arg2 = 0;
    uint32_t m_arg3 = 0;
};

static_assert(sizeof(PatchBase) == 16, "module_root::PatchBase 必须为 16 字节");
static_assert(alignof(PatchBase) == 4, "module_root::PatchBase 对齐必须为 4");

}  // namespace module_root
}  // namespace default_modules
