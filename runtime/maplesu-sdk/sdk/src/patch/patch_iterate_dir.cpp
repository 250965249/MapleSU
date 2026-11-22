// patch iterate dir implementation.
//
#include <cstddef>
#include <cstdint>

#include "kernel_module_kit_umbrella.h"
#include "maplesu_hook_private.h"

using namespace asmjit;
using namespace asmjit::a64;

namespace {

// filldir64 之前的 iterate_dir 上下文（内核 struct dir_context 的前两个字段）。
struct dir_context {
    uint64_t actor;
    uint64_t pos;
};

}  // namespace

// 同一 lib 的 src/jni 私有树）。为了本成员可以单独编译，这里按成员 72
// (patch_base.o) 的 ABI 声明基类：
//     以及 PatchIterateDir 大小 24（基类 16 + m_iterate_dir 8）。
//   * 只声明不定义：PatchBase 的成员函数由 patch_base.o 提供，本 TU 只产生 U 引用
// 【推断】成员变量按 4 个 uint32_t 建模（对齐 4 排除了 8 字节成员/指针）。
namespace default_modules {
namespace module_root {

class PatchBase {
public:
    PatchBase(const PatchBase& other);
    ~PatchBase();

protected:
    uint32_t m_task_struct_offset_cred;
    uint32_t m_cred_euid_offset;
    uint32_t m_task_struct_offset_task;
    uint32_t m_cred_offset;

    // 把 a 里已生成的 shellcode 安装成 target 函数入口的 before-hook。
    KModErr patch_kernel_before_hook(uint64_t kaddr, const asmjit::a64::Assembler* a);
};

static_assert(sizeof(PatchBase) == 16, "layout constraint violated");
static_assert(alignof(PatchBase) == 4, "layout constraint violated");

class PatchIterateDir : public PatchBase {
public:
    PatchIterateDir(const PatchBase& patch_base, uint64_t iterate_dir);
    ~PatchIterateDir();

    // 把 (iterate_dir, original_filldir64, target_filldir64) 三元组打成
    // “iterate_dir 的 actor 字段等于 original_filldir64 时改写成 target_filldir64”
    // 的 before-hook。
    KModErr patch_iterate_dir(uint64_t original_filldir64, uint64_t target_filldir64);
    KModErr patch_iterate_dir_owned(uint64_t original_filldir64, uint64_t target_filldir64,
        const kernel_module::OwnedHookActor& actor, bool& transferred);

private:
    uint64_t m_iterate_dir = 0;
};

static_assert(sizeof(PatchIterateDir) == 24, "PatchIterateDir = PatchBase(16) + uint64_t(8)");

PatchIterateDir::PatchIterateDir(const PatchBase& patch_base, uint64_t iterate_dir)
    : PatchBase(patch_base), m_iterate_dir(iterate_dir) {}

PatchIterateDir::~PatchIterateDir() {}

//   GpX x1_ctx = x1;                 // vfs_readdir 的 dir_context*
//   init_aarch64_asm();              // 局部 asmjit 环境（匿名 namespace 的 aarch64_asm_ctx）
//   Label L_end = a->newLabel();
//   arm64_before_hook_start(a);
//   a->cbz(x1_ctx, L_end);           // ctx == nullptr 直接返回原逻辑
//   a->ldr(x10, ptr(x1_ctx, offsetof(dir_context, actor)));
//   aarch64_asm_mov_x(a, x11, original_filldir64);
//   a->cmp(x10, x11);
//   a->b(CondCode::kNE, L_end);      // actor 不是目标 filldir 就放过
//   aarch64_asm_mov_x(a, x11, target_filldir64);
//   a->str(x11, ptr(x1_ctx, offsetof(dir_context, actor)));
//   a->bind(L_end);
//   arm64_before_hook_end(a, true);  // true = 继续执行被 hook 的原指令
//   return patch_kernel_before_hook(m_iterate_dir, a);
KModErr PatchIterateDir::patch_iterate_dir(uint64_t original_filldir64, uint64_t target_filldir64) {
    GpX x1_ctx = x1;

    // 生成 Hook func 汇编命令
    aarch64_asm_ctx asm_ctx = init_aarch64_asm();
    auto a = asm_ctx.assembler();
    Label L_end = a->newLabel();
    kernel_module::arm64_before_hook_start(a);
    a->cbz(x1_ctx, L_end);

    a->ldr(x10, ptr(x1_ctx, offsetof(dir_context, actor)));
    aarch64_asm_mov_x(a, x11, original_filldir64);
    a->cmp(x10, x11);
    a->b(CondCode::kNE, L_end);

    aarch64_asm_mov_x(a, x11, target_filldir64);
    a->str(x11, ptr(x1_ctx, offsetof(dir_context, actor)));

    a->bind(L_end);
    kernel_module::arm64_before_hook_end(a, true);
    return patch_kernel_before_hook(m_iterate_dir, a);
}

KModErr PatchIterateDir::patch_iterate_dir_owned(uint64_t original_filldir64,
    uint64_t target_filldir64, const kernel_module::OwnedHookActor& actor,
    bool& transferred) {
    transferred = false;
    if (actor.target != original_filldir64 || actor.allocation > UINT64_MAX - 4 ||
        target_filldir64 != actor.allocation + 4)
        return KModErr::ERR_MODULE_PARAM;
    bool boot_retained = false;
    RETURN_IF_ERROR(kernel_module::maplesu_hook_legacy_boot_selected(boot_retained));
    aarch64_asm_ctx asm_ctx = init_aarch64_asm();
    auto* a = asm_ctx.assembler();
    if (!a) return KModErr::ERR_MODULE_ASM;
    const Label unchanged = a->newLabel();
    const Label original = a->newLabel();
    kernel_module::arm64_before_hook_start(a);
    // iterate_dir has two register arguments. Its callee-saved pair survives a
    // sleeping original while the enclosing publication or boot lifetime holds.
    a->stp(x19, x20, ptr(sp).pre(-16));
    a->stp(x21, x30, ptr(sp).pre(-16));
    a->mov(x19, x1);
    a->mov(x21, xzr);
    a->cbz(x19, original);
    a->ldr(x20, ptr(x19, offsetof(dir_context, actor)));
    aarch64_asm_mov_x(a, x10, original_filldir64);
    a->cmp(x20, x10);
    a->b(CondCode::kNE, original);
    aarch64_asm_mov_x(a, x10, target_filldir64);
    a->str(x10, ptr(x19, offsetof(dir_context, actor)));
    a->mov(x21, Imm(1));
    a->bind(original);
    kernel_module::arm64_emit_call_original(a);
    a->cbz(x21, unchanged);
    // Restore the caller's context before leaving the retained callback;
    // no generated actor pointer escapes the complete iterate_dir invocation.
    a->str(x20, ptr(x19, offsetof(dir_context, actor)));
    a->bind(unchanged);
    a->ldp(x21, x30, ptr(sp).post(16));
    a->ldp(x19, x20, ptr(sp).post(16));
    kernel_module::arm64_before_hook_end(a, false);
    const auto bytes = aarch64_asm_to_bytes(a);
    if (asm_ctx.has_error() || bytes.empty() || bytes.size() > UINT32_MAX)
        return KModErr::ERR_MODULE_ASM;
    if (boot_retained) {
        // The actor and this before callback remain resident for the boot,
        // including unknown publication. Keep the original invocation and its
        // actor restoration above; no provider ownership is manufactured.
        transferred = true;
        return kernel_module::install_kernel_function_before_hook(m_iterate_dir, bytes, nullptr);
    }
    return kernel_module::maplesu_install_owned_hook_with_actor(m_iterate_dir,
        bytes.data(), static_cast<uint32_t>(bytes.size()), actor, transferred, nullptr);
}

}  // namespace module_root
}  // namespace default_modules
