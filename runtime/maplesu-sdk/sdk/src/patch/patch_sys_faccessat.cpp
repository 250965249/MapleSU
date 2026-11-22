// patch sys faccessat implementation.
//
#include "core01/patch_sys_faccessat.h"

#include "kernel_module_kit_umbrella.h"

using namespace asmjit;
using namespace asmjit::a64;

namespace default_modules {
namespace module_su_redirect {

// 偏移 40（即 PatchBase(40B) 之后的第一个字段）。
PatchSysFaccessat::PatchSysFaccessat(const PatchBase& patch_base,
                                     uint64_t sys_faccessat_kaddr)
    : PatchBase(patch_base), m_sys_faccessat(sys_faccessat_kaddr) {}

PatchSysFaccessat::~PatchSysFaccessat() = default;

/***************************************************************************
 * patch_sys_faccessat — 生成 before-hook 代码并安装。
 *
 *                   a->ldr(x11, ptr(x0, 8));   // Mem{x0, +8}
 *               else
 *                   a->mov(x11, x1);
 *                 emit_check_user_filename_is_su(a, err, GpX(x11));
 *                 if (err) return err;
 *                 a->mov(x10, x0); }
 *
 * 调用 aarch64_asm_ctx::~aarch64_asm_ctx）；hook 的安装/回滚由
 * PatchBase::patch_kernel_before_hook 负责（失败时返回错误码，不留下半装状态）。
 ***************************************************************************/
KModErr PatchSysFaccessat::patch_sys_faccessat(uint64_t check_arg) {
    KModErr err = KModErr::OK;

    aarch64_asm_ctx asm_ctx = init_aarch64_asm();
    auto a = asm_ctx.assembler();

    // 跳转到"执行原始 faccessat"的出口标签。
    Label L_default = a->newLabel();

    // before-hook 入口恢复 x28 和栈，保留原始入口的 x0/x1。
    kernel_module::arm64_before_hook_start(a);

    // 依据当前进程身份生成放行判定，结果在 x10（0 = 未放行，走原始流程）。
    err = emit_check_current_allow_su_to_x10_checked(a, check_arg);
    if (is_failed(err)) return err;

    // x10 == 0（不是放行进程）→ 直接走原始流程，不做文件名判定。
    a->cbz(x10, L_default);

    // 取得用户态传入的 filename 指针：
    //   - 走 syscall 包装路径时，真实参数在 pt_regs 里（x0 指向 pt_regs，
    //     regs[1] 位于 +8）；
    //   - 否则 x1 已经是 filename。
    if (kernel_module::is_syscall_args_in_ptregs()) {
        a->ldr(x11, ptr(x0, 8));
    } else {
        a->mov(x11, x1);
    }

    {
        // 保护 x0：下面会用它承接"是否为 su 路径"的布尔结果。
        RegProtectGuard g(a, x0);
        emit_check_user_filename_is_su(a, err, GpX(x11));
        if (err != KModErr::OK) {
            return err;
        }
        a->mov(x10, x0);
    }

    // x10 == 0：不是 su 路径 → 走原始流程。
    a->cbz(x10, L_default);

    // 命中 su 路径：让 faccessat 直接"成功"，从而对上层隐藏该路径的真实
    // 存在性（原始 sys_faccessat 不再执行）。
    a->mov(w0, wzr);

    // before-hook 尾部（不继续执行原始函数）。
    kernel_module::arm64_before_hook_end(a, false);

    // 原始流程出口。
    a->bind(L_default);
    kernel_module::arm64_before_hook_end(a, true);

    // 落盘：把生成的机器码安装为 sys_faccessat 的 before-hook。
    return patch_kernel_before_hook(m_sys_faccessat, a);
}

}  // namespace module_su_redirect
}  // namespace default_modules
