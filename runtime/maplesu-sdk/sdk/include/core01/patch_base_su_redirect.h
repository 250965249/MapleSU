// patch base su redirect implementation.
//
#pragma once

#include <cstdint>
#include <string>

#include "kernel_module_kit_umbrella.h"

namespace default_modules {
namespace module_su_redirect {

/***************************************************************************
 * 补丁基座。
 *
 * 该类的成员函数由 patch_base.o (idx 84) 提供，本头文件只负责声明与布局；
 * 任何在此新增数据成员都会破坏 PatchSysFaccessat 等派生成员的 ABI。
 ***************************************************************************/
class PatchBase {
public:
    PatchBase(uint32_t arg0, uint32_t arg1);
    PatchBase(const PatchBase& other);
    ~PatchBase();

protected:
    // ---- 实测量：3 个 32 位标量 + 1 个 std::string ----------------------
    uint32_t m_arg0 = 0;
    uint32_t m_arg1 = 0;
    uint32_t m_arg2 = 0;
    std::string m_name;

    // Emit the current full real-UID allowlist decision into x10.
    KModErr emit_check_current_allow_su_to_x10_checked(asmjit::a64::Assembler* a, uint64_t arg);
    void emit_check_current_allow_su_to_x10(asmjit::a64::Assembler* a, uint64_t check_arg);

    // 比较被访问的文件名是否为 "su"/"magisk" 等提权关键字，结果写 x10。
    void emit_check_user_filename_is_su(asmjit::a64::Assembler* a,
                                       KModErr& err,
                                       asmjit::a64::GpX filename_ptr);

    // 把生成好的 before-hook 代码安装到 kaddr。
    KModErr patch_kernel_before_hook(uint64_t kaddr, const asmjit::a64::Assembler* a);
};

static_assert(sizeof(PatchBase) == 40,
              "PatchBase 布局必须为 40 字节（3*u32 + std::string）");
static_assert(alignof(PatchBase) == 8, "PatchBase 对齐必须为 8");

}  // namespace module_su_redirect
}  // namespace default_modules
