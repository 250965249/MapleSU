// patch do execve implementation.
//
#include "kernel_module_kit_umbrella.h"

#include <cstdint>
#include <string>

#include "aarch64_asm_helper.h"
#include "aarch64_asm_reg_protect_guard.h"
#include "module_base_kernel_func_hook.h"
#include "module_base_kernel_string_ops.h"

using namespace asmjit;
using namespace asmjit::a64;

// ExecveSymInfo：全局命名空间的 packed 结构（mangling 里是 `13ExecveSymInfo`，
struct __attribute__((packed)) ExecveSymInfo {
    uint64_t kaddr = 0;
    uint8_t  reg_index = 0;
    uint8_t  deref = 0;
};
static_assert(sizeof(ExecveSymInfo) == 10, "layout constraint violated");
static_assert(offsetof(ExecveSymInfo, reg_index) == 8, "layout constraint violated");
static_assert(offsetof(ExecveSymInfo, deref) == 9, "layout constraint violated");

namespace default_modules {
namespace module_su_redirect {

// PatchBase（40 字节）与 PatchDoExecve 的成员函数都由别的成员定义，
// 本 TU 只调用。这里的声明只为拿到正确的 mangling 与对象布局，
class PatchBase {
public:
    PatchBase(const PatchBase&);
    ~PatchBase();

    std::string get_fake_su_path();

    // 生成"current 是否允许 su"的判定代码，结果放 x10（非 0 表示允许）。
    void emit_check_current_allow_su_to_x10(asmjit::v1_16::a64::Assembler* a, uint64_t hook_kaddr);

    // 把 a 里已经生成好的桩代码安装成 before-hook。
    KModErr patch_kernel_before_hook(uint64_t kaddr, const asmjit::v1_16::a64::Assembler* a);

private:
    int32_t     field_0_ = 0;
    int32_t     field_1_ = 0;
    int32_t     field_2_ = 0;
    std::string field_3_;
};
static_assert(sizeof(PatchBase) == 40, "layout constraint violated");

class PatchDoExecve : public PatchBase {
public:
    PatchDoExecve(const PatchBase& base, const ExecveSymInfo& info);
    ~PatchDoExecve();

    // regs / hook_kaddr 传给 emit_check_current_allow_su_to_x10。
    KModErr patch_do_execve(uint64_t hook_kaddr);

private:
    ExecveSymInfo m_info = {};
};
static_assert(sizeof(PatchDoExecve) == 56, "layout constraint violated");

//   这与 `: PatchBase(base) { m_info = info; }` + 成员 `= {}` 的代码形状一致。
PatchDoExecve::PatchDoExecve(const PatchBase& base, const ExecveSymInfo& info) : PatchBase(base) {
    m_info = info;
}

PatchDoExecve::~PatchDoExecve() {}

KModErr PatchDoExecve::patch_do_execve(uint64_t hook_kaddr) {
    const std::string fake_su_path = get_fake_su_path();

    aarch64_asm_ctx asm_ctx = init_aarch64_asm();
    auto* a = asm_ctx.assembler();

    Label skip = a->newLabel();

    kernel_module::arm64_before_hook_start(a);

    // x10 = 1 表示"当前进程被允许走 su 路径"。
    emit_check_current_allow_su_to_x10(a, hook_kaddr);
    a->cbz(x10, skip);

    // 路径参数为错误码（unsigned >= -4095）时不做改写。
    a->mov(x11, Imm(static_cast<int64_t>(-4095)));
    a->cmp(x(m_info.reg_index), x11);
    a->b(CondCode::kHS, skip);

    // 取出路径字符串指针：deref 时先解引用一次。
    if (m_info.deref != 0) {
        a->mov(x10, x(m_info.reg_index));
    } else {
        a->ldr(x10, ptr(x(m_info.reg_index)));
    }

    // 后缀比较：x10 指向的字符串是否以 "/su" 结尾。
    aarch64_asm_set_x_cstr_ptr(a, x11, std::string("/su"));
    {
        RegProtectGuard g(a, x0);
        kernel_module::string_ops::kendswith(a, x10, x11);
        a->mov(x11, x0);
    }
    a->cbz(x11, skip);

    // 命中：把路径替换成本模块的 fake su 路径。
    aarch64_asm_set_x_cstr_ptr(a, x11, fake_su_path);
    {
        RegProtectGuard g(a, x0);
        kernel_module::string_ops::kstrcpy(a, x10, x11);
    }

    a->bind(skip);
    kernel_module::arm64_before_hook_end(a, true);

    return PatchBase::patch_kernel_before_hook(m_info.kaddr, a);
}

}  // namespace module_su_redirect
}  // namespace default_modules
