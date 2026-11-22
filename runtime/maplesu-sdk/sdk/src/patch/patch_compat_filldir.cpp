// patch compat filldir implementation.
//
#include "kernel_module_kit_umbrella.h"
#include "maplesu_core04_patch_base.h"
#include <cstring>
#include <string>
#include <vector>

namespace default_modules {
namespace module_root {
class PatchCompatFilldir : public PatchBase {
public:
    PatchCompatFilldir(const PatchBase& base, uint64_t offset);
    ~PatchCompatFilldir();
    KModErr patch_compat_filldir(const std::vector<std::string>& hide_so_paths);
private:
    uint64_t m_offset;
};
static_assert(sizeof(PatchCompatFilldir) == 24 && alignof(PatchCompatFilldir) == 8);
PatchCompatFilldir::PatchCompatFilldir(const PatchBase& base, uint64_t offset)
    : PatchBase(base), m_offset(offset) {}
PatchCompatFilldir::~PatchCompatFilldir() = default;

KModErr PatchCompatFilldir::patch_compat_filldir(
    const std::vector<std::string>& hide_so_paths) {
    using namespace asmjit;
    using namespace asmjit::a64;
    const GpW len_reg = w2;
    aarch64_asm_ctx ctx = init_aarch64_asm();
    Assembler* a = ctx.assembler();
    kernel_module::arm64_before_hook_start(a);
    for (size_t i = 0; i < hide_so_paths.size(); ++i) {
        const Label next = a->newLabel();
        const Label compare = a->newLabel();
        const std::string& path = hide_so_paths[i];
        a->cmp(len_reg, Imm(path.size()));
        a->_emitI(BaseInst::composeARMInstId(Inst::kIdB, CondCode::kNE), next);
        {
            std::vector<uint8_t> name(path.size() + 1, 0);
            if (!path.empty()) std::memcpy(name.data(), path.data(), path.size());
            std::vector<uint8_t> padded((name.size() + 3) & ~size_t(3), 0);
            if (!name.empty()) std::memcpy(padded.data(), name.data(), name.size());
            const Label over = a->newLabel();
            a->b(over);
            const size_t data_offset = a->offset();
            a->embed(padded.data(), padded.size());
            a->bind(over);
            // emits a temporary assembler's ADR bytes; preserve that path.
            const int32_t delta = static_cast<int32_t>(data_offset - a->offset());
            aarch64_asm_adr_x(a, x11, delta);
        }
        a->mov(x12, Imm(0));
        a->bind(compare);
        a->ldrb(w13, ptr(x1, x12));
        a->ldrb(w14, ptr(x11, x12));
        a->cmp(w13, w14);
        a->_emitI(BaseInst::composeARMInstId(Inst::kIdB, CondCode::kNE), next);
        a->add(x12, x12, Imm(1));
        a->cmp(x12, Imm(path.size()));
        a->_emitI(BaseInst::composeARMInstId(Inst::kIdB, CondCode::kLT), compare);
        if (kernel_module::is_kernel_version_less("6.1.0"))
            a->mov(x0, xzr);
        else
            a->mov(x0, Imm(1));
        kernel_module::arm64_before_hook_end(a, false);
        a->bind(next);
    }
    kernel_module::arm64_before_hook_end(a, true);
    return patch_kernel_before_hook(m_offset, a);
}
} // namespace module_root
} // namespace default_modules
