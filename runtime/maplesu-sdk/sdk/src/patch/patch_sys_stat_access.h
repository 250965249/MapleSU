// patch sys stat access implementation.
//
// 共享主体：sys_newfstatat / sys_statx 两条"按路径 stat"的 before-hook 生成器。
// 两个系统调用的参数形态一致——(路径指针, 结果缓冲指针)——只有结果缓冲参数所在的
// 寄存器、以及它在 syscall 参数帧里的槽位不同；因此主体写成一份，由成员文件通过
// 宏参数传入差异，成员文件本身只保留类定义与薄薄一层转发。
#pragma once

#include <cstdint>
#include <string>

#include "kernel_module_kit_umbrella.h"
#include "default_module/module_su_redirect/patch_base.h"

// 同批交付的 UID 路径辅助 TU（stat_uid_path.cpp）导出的两个函数：
//   maplesu_stat_uid_template：取基座配置的 fake su 路径，把结尾的 "/su" 改写成
//     带 8 位 UID 占位符的 u-XXXXXXXX/su 模板串；
//   maplesu_emit_uid_stat_copy：生成"把模板串拷进调用方结果缓冲、把当前 UID 的
//     十六进制写法填进占位符、再 copy_to_user 交回用户态"的机器码。
// 两个成员共用这份 TU，构建时用 -D 把符号名分别改写成 _84 / _85。
extern "C" std::string maplesu_stat_uid_template(
    default_modules::module_su_redirect::PatchBase* patch_base);
extern "C" void maplesu_emit_uid_stat_copy(asmjit::a64::Assembler* a, KModErr& error,
                                           asmjit::a64::GpX destination,
                                           asmjit::a64::GpX source, uint64_t size,
                                           const void* patch_base);

namespace default_modules {
namespace module_su_redirect {

// sys_newfstatat 的 before-hook 生成器；布局为 PatchBase(40) + u64 = 48 字节。
class PatchSysNewfstatat : public PatchBase {
public:
    PatchSysNewfstatat(const PatchBase& patch_base, uint64_t patch_kaddr);
    ~PatchSysNewfstatat();

    // check_arg 原样透传给 emit_check_current_allow_su_to_x10。
    KModErr patch_sys_newfstatat(uint64_t check_arg);

    // 目标 sys_newfstatat 的内核地址（基类之后唯一的布局字段，必须留在 offset 40）。
    uint64_t m_patch_kaddr = 0;
};

// sys_statx 的 before-hook 生成器；布局同 PatchSysNewfstatat。
class PatchSysStatx : public PatchBase {
public:
    PatchSysStatx(const PatchBase& patch_base, uint64_t patch_kaddr);
    ~PatchSysStatx();

    // check_arg 原样透传给 emit_check_current_allow_su_to_x10。
    KModErr patch_sys_statx(uint64_t check_arg);

    uint64_t m_patch_kaddr = 0;
};

static_assert(sizeof(PatchSysNewfstatat) == 48, "PatchSysNewfstatat layout violated");
static_assert(offsetof(PatchSysNewfstatat, m_patch_kaddr) == 40,
              "PatchSysNewfstatat layout violated");
static_assert(sizeof(PatchSysStatx) == 48, "PatchSysStatx layout violated");
static_assert(offsetof(PatchSysStatx, m_patch_kaddr) == 40, "PatchSysStatx layout violated");

// 生成整条 before-hook 并安装。宏原地展开在成员函数体内，参数只有两个：
//   stat_buffer_reg           —— 结果缓冲参数所在的 X 寄存器；
//   stat_buffer_ptregs_offset —— 该参数在 syscall 参数帧里的字节偏移。
//
// 行为：
//   1. 取 fake su 路径并改写成带 UID 占位符的模板串；
//   2. 依据当前进程身份生成放行判定，未被放行时直接执行原始系统调用；
//   3. 取得路径指针与结果缓冲指针（syscall 包装形态下它们在 pt_regs 参数帧里，
//      否则路径在 x1、结果缓冲在传入的寄存器里），判断被 stat 的路径是否为
//      su 提权路径，不是则直接执行原始系统调用；
//   4. 是 su 路径时，把 UID 私有路径写进调用方的结果缓冲（该缓冲随后会被系统
//      调用自己写成 stat 结果），并把"路径指针"参数改指这块缓冲，让原系统调用
//      去 stat UID 私有路径；
//   5. 绑定出口标签、收尾并安装 hook；任一步发射失败都原样返回错误码。
#define MAPLESU_EMIT_PATH_STAT_ACCESS_PATCH(path_reg, path_offset, stat_buffer_reg, stat_buffer_ptregs_offset, compat_path)   \
    KModErr error = KModErr::OK;                                                     \
    const std::string fake_su_path = maplesu_stat_uid_template(this);                \
                                                                                     \
    aarch64_asm_ctx asm_ctx = init_aarch64_asm();                                    \
    auto* a = asm_ctx.assembler();                                                   \
                                                                                     \
    /* "执行原始系统调用"的出口。 */                                                 \
    Label label_end = a->newLabel();                                                 \
                                                                                     \
    kernel_module::arm64_before_hook_start(a);                                       \
                                                                                     \
    /* x10 == 0：当前进程未被放行 → 走原始流程。 */                                  \
    error = emit_check_current_allow_su_to_x10_checked(a, check_arg);                \
    if (is_failed(error)) return error;                                \
    a->cbz(x10, label_end);                                                          \
                                                                                     \
    /* 取参数：syscall 包装形态下真实参数在 pt_regs（x0 指向参数帧），              \
       否则路径与结果缓冲已经在 x1 / 传入的寄存器里。 */                              \
    if (kernel_module::is_syscall_args_in_ptregs()) {                                 \
        a->ldr(x11, ptr(x0, path_offset));                                                     \
        a->ldr(x12, ptr(x0, stat_buffer_ptregs_offset));                             \
    } else {                                                                         \
        a->mov(x11, path_reg);                                                             \
        a->mov(x12, stat_buffer_reg);                                                \
    }                                                                                \
                                                                                     \
    if (compat_path) { a->mov(w11, w11); a->mov(w12, w12); }                         \
                                                                                     \
    /* x10 == 0：路径不是 su 提权路径 → 走原始流程。 */                              \
    {                                                                                \
        RegProtectGuard guard(a, x0);                                                \
        emit_check_user_filename_is_su(a, error, GpX(x11));                          \
        if (error != KModErr::OK) {                                                  \
            return error;                                                            \
        }                                                                            \
        a->mov(x10, x0);                                                             \
    }                                                                                \
    a->cbz(x10, label_end);                                                          \
                                                                                     \
    /* x10 = UID 模板串指针。 */                                                     \
    aarch64_asm_set_x_cstr_ptr(a, x10, fake_su_path);                               \
                                                                                     \
    /* x10 == 0：UID 私有路径已交回用户态 → 改指参数；失败则走原始流程。 */          \
    {                                                                                \
        RegProtectGuard guard(a, x0);                                                \
        maplesu_emit_uid_stat_copy(a, error, GpX(x12), GpX(x10),                     \
                                   fake_su_path.size() + 1, this);                   \
        if (error != KModErr::OK) {                                                  \
            return error;                                                            \
        }                                                                            \
        a->mov(x10, x0);                                                             \
    }                                                                                \
    a->cbnz(x10, label_end);                                                         \
                                                                                     \
    /* 参数改指：让原系统调用去 stat 刚才写入结果缓冲的 UID 私有路径。 */            \
    if (kernel_module::is_syscall_args_in_ptregs()) {                                 \
        a->str(x12, ptr(x0, path_offset));                                                     \
    } else {                                                                         \
        a->mov(path_reg, x12);                                                             \
    }                                                                                \
                                                                                     \
    a->bind(label_end);                                                              \
    kernel_module::arm64_before_hook_end(a, true);                                   \
                                                                                     \
    return patch_kernel_before_hook(m_patch_kaddr, a);

}  // namespace module_su_redirect
}  // namespace default_modules

#define MAPLESU_EMIT_STAT_ACCESS_PATCH(buffer, offset) \
    MAPLESU_EMIT_PATH_STAT_ACCESS_PATCH(asmjit::a64::x1, 8, buffer, offset, false)
