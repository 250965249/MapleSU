// patch filldir64 implementation.
//
#include "default_modules_module_root_patch_base.h"

#include <cstdint>
#include <string>
#include <vector>

#include "aarch64_asm_helper.h"   // init_aarch64_asm / aarch64_asm_ctx / aarch64_asm_set_x_cstr_ptr

namespace default_modules {
namespace module_root {

// filldir64 的按名字过滤钩子。
class PatchFilldir64 : public PatchBase {
public:
    PatchFilldir64(const PatchBase& base, uint64_t filldir64_kaddr);
    ~PatchFilldir64();

    // 生成并安装 before hook：把命中的目录项名字过滤成固定返回值。
    KModErr patch_filldir64(const std::vector<std::string>& names);

private:
    uint64_t m_filldir64_kaddr;
};

static_assert(sizeof(PatchFilldir64) == 24, "layout constraint violated");
static_assert(alignof(PatchFilldir64) == 8, "layout constraint violated");

PatchFilldir64::PatchFilldir64(const PatchBase& base, uint64_t filldir64_kaddr)
    : PatchBase(base), m_filldir64_kaddr(filldir64_kaddr) {}

PatchFilldir64::~PatchFilldir64() {}

KModErr PatchFilldir64::patch_filldir64(const std::vector<std::string>& names) {
    using namespace asmjit;
    using namespace asmjit::a64;

    // filldir64(ctx /*x0*/, name /*x1*/, namlen /*w2*/, offset, ino, d_type)
    // 长度先用 w2 做一次 O(1) 预筛，省掉绝大多数名字的逐字节比较。
    GpW namlen = w2;

    aarch64_asm_ctx ctx = init_aarch64_asm();
    Assembler* a = ctx.assembler();
    if (!a) {
        return KModErr::ERR_MODULE_ASM;
    }

    kernel_module::arm64_before_hook_start(a);

    for (size_t i = 0; i < names.size(); ++i) {
        const std::string& name = names[i];

        Label next = a->newLabel();
        Label cmp_loop = a->newLabel();

        a->cmp(namlen, Imm(name.size()));
        a->b(CondCode::kNE, next);

        // 把名字以 C 字符串常量形式内嵌到指令流正后方，并让 x11 指向它。
        aarch64_asm_set_x_cstr_ptr(a, x11, name);

        a->mov(x12, Imm(0));
        a->bind(cmp_loop);
        a->ldrb(w13, Mem(x1, x12));
        a->ldrb(w14, Mem(x11, x12));
        a->cmp(w13, w14);
        a->b(CondCode::kNE, next);
        a->add(x12, x12, Imm(1));
        a->cmp(x12, Imm(name.size()));
        a->b(CondCode::kLT, cmp_loop);

        // 命中：按内核版本给出 filldir64 的返回值。
        // 6.1.0 起 filldir64 的“已消费”返回 1；更早内核返回 0。
        if (kernel_module::is_kernel_version_less("6.1.0")) {
            a->mov(x0, xzr);
        } else {
            a->mov(x0, Imm(1));
        }
        kernel_module::arm64_before_hook_end(a, false);

        a->bind(next);
    }

    kernel_module::arm64_before_hook_end(a, true);

    return patch_kernel_before_hook(m_filldir64_kaddr, a);
}

} // namespace module_root
} // namespace default_modules
