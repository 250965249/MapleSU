// patch selinux status update policyload implementation.
//
#include "kernel_module_kit_umbrella.h"
#include "maplesu_hook_private.h"

// 私有头 default_module/module_selinux/patch_base.h 没有随 SDK 发布；下面按
//   _ZN9PatchBaseC2ERKS_                                    -> 拷贝构造
//   _ZN9PatchBaseD2Ev                                       -> 析构
//   _ZN9PatchBase24patch_kernel_before_hookEmPKN6asmjit
//      5v1_163a649AssemblerE                               -> 成员函数，
//      (uint64_t, const asmjit::a64::Assembler*) 参数，非 const 成员函数。
// 别的成员里（idx 90 patch_base.o），本 TU 只声明、不重复定义。
class PatchBase {
public:
    PatchBase(const PatchBase& other);   // _ZN9PatchBaseC2ERKS_
    ~PatchBase();                        // _ZN9PatchBaseD2Ev

    // 把 a 里生成好的 before-hook 桩安装到 kaddr，返回 KModErr。
    KModErr patch_kernel_before_hook(uint64_t kaddr,
                                     const asmjit::a64::Assembler* a);
};

// PatchSelinuxStatusUpdatePolicyload：本成员的类（全局命名空间，mangling 里
// 的 34 就是类名长度）。
class PatchSelinuxStatusUpdatePolicyload : public PatchBase {
public:
    PatchSelinuxStatusUpdatePolicyload(const PatchBase& base, uint64_t offset);
    ~PatchSelinuxStatusUpdatePolicyload();

    // 生成 selinux_status_update_policyload 的 before-hook 桩并安装。
    //   offset : 前 4 个 16-bit 半字被 movz/movk 装进 x10 的内核地址
    KModErr patch_selinux_status_update_policyload(uint64_t offset);
    KModErr patch_selinux_status_update_policyload(uint64_t offset,
                                                  kernel_module::HookHandle* handle);
    __attribute__((visibility("hidden"))) KModErr patch_selinux_status_update_policyload(uint64_t offset,
                                                  kernel_module::HookHandle* handle,
                                                  const kernel_module::RequestSharedBool* dependency);

private:
    uint64_t m_offset = 0;
};

static_assert(sizeof(PatchBase) == 1,
              "layout constraint violated");
static_assert(sizeof(PatchSelinuxStatusUpdatePolicyload) == 8,
              "unexpected layout size");
static_assert(alignof(PatchSelinuxStatusUpdatePolicyload) == 8,
              "layout constraint violated");

//   tail call void @_ZN9PatchBaseC2ERKS_(this, &base)
//   store i64 %2, ptr %this, align 8
PatchSelinuxStatusUpdatePolicyload::PatchSelinuxStatusUpdatePolicyload(
    const PatchBase& base, uint64_t offset)
    : PatchBase(base), m_offset(offset) {}

//   tail call void @_ZN9PatchBaseD2Ev(this)
PatchSelinuxStatusUpdatePolicyload::~PatchSelinuxStatusUpdatePolicyload() = default;

KModErr PatchSelinuxStatusUpdatePolicyload::patch_selinux_status_update_policyload(
    uint64_t offset) {
    return patch_selinux_status_update_policyload(offset, nullptr);
}

KModErr PatchSelinuxStatusUpdatePolicyload::patch_selinux_status_update_policyload(
    uint64_t offset, kernel_module::HookHandle* handle) {
    return patch_selinux_status_update_policyload(offset, handle, nullptr);
}

KModErr PatchSelinuxStatusUpdatePolicyload::patch_selinux_status_update_policyload(
    uint64_t offset, kernel_module::HookHandle* handle,
    const kernel_module::RequestSharedBool* dependency) {
    if (dependency && dependency->address != offset) return KModErr::ERR_MODULE_PARAM;
    // 构造、CodeHolder/StringLogger/MyAsmJitErrorHandler/Assembler 的
    // 从 C++ 的 RAII 自动生成，不需要手写）。
    aarch64_asm_ctx asm_ctx = init_aarch64_asm();
    asmjit::a64::Assembler* a = asm_ctx.assembler();

    asmjit::Label skip = a->newLabel();

    kernel_module::arm64_before_hook_start(a);

    asmjit::a64::GpX addr = asmjit::a64::regs::x10;

    bool have_movz = false;
    for (unsigned i = 0; i < 4; ++i) {
        const uint32_t shift = i * 16u;
        const uint32_t part = static_cast<uint32_t>((offset >> shift) & 0xFFFFu);
        if (part == 0u) {
            continue;
        }
        if (!have_movz) {
            a->movz(addr, asmjit::Imm(part), asmjit::Imm(shift));
            have_movz = true;
        } else {
            a->movk(addr, asmjit::Imm(part), asmjit::Imm(shift));
        }
    }
    if (!have_movz) {
        a->movz(addr, asmjit::Imm(0), asmjit::Imm(0));
    }

    // 58（kMem|kARM_GpX），基址 = x10，offset 0。这里用 ptr(regs::x10)
    // 让同样的常量折叠发生（用局部 addr 会得到运行时 and/or 组装）。
    a->ldrb(asmjit::a64::regs::w10,
            asmjit::a64::ptr(asmjit::a64::regs::x10));

    a->cbz(asmjit::a64::regs::w10, skip);

    kernel_module::arm64_before_hook_end(a, /*continue_original=*/false);

    a->bind(skip);

    kernel_module::arm64_before_hook_end(a, /*continue_original=*/true);

    if (handle || dependency) {
        auto bytes = aarch64_asm_to_bytes(a);
        if (asm_ctx.has_error() || bytes.empty()) return KModErr::ERR_MODULE_PARAM;
        if (dependency)
            return kernel_module::maplesu_install_owned_hook_with_shared_bools(m_offset,
                bytes.data(), static_cast<uint32_t>(bytes.size()), false, dependency, 1, handle);
        return kernel_module::install_kernel_function_before_hook(m_offset, bytes, handle);
    }
    return patch_kernel_before_hook(m_offset, a);
}
