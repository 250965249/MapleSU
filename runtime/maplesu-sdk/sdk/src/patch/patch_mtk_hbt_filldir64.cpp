// patch mtk hbt filldir64 implementation.
//
#include "core01/patch_mtk_hbt_filldir64.h"

#include <cstdio>
#include <cstring>
#include <limits>

#include "maplesu_request_identity.h"
#include "maplesu_hook_private.h"
#include "module_base_kernel_request.h"

#include "kernel_module_kit_umbrella.h"

using namespace asmjit;
using namespace asmjit::a64;

namespace kernel_module { KModErr icache_invalidate_all_cpus(); }

namespace default_modules {
namespace module_root {

namespace {

// The actor is reached through dir_context::actor's indirect call.
constexpr uint32_t kFakeFuncPrologueWord = 0xD503245Fu; // BTI C

constexpr const char* kHideReturnSwitchKernel = "6.1.0";

struct ActorStaging {
    kernel_module::RequestIdentity identity;
    uint64_t address = 0;
    bool allocation_attempted = false;
    bool transferred = false;
    bool typed = false;
    bool boot_retained = false;

    ~ActorStaging() noexcept {
        if (transferred || boot_retained || !allocation_attempted) return;
        const kernel_module::HookCleanupReceiptScope preserve_receipt;
        if (!identity.matches()) {
            if (address) std::fprintf(stderr, "MapleSU actor staging retained after identity change\n");
            return;
        }
        try {
            const bool owner = (identity.auth_state & 1) != 0;
            const auto reply = typed ? kernel_module::maplesu_hook_reply() : kernel_module::maplesu_request_management_reply();
            if ((typed || owner) && (!reply.completed || reply.status == MAPLESU_REQUEST_STATUS_DENIED ||
                reply.status == MAPLESU_REQUEST_STATUS_STALE ||
                (reply.effects & MAPLESU_EFFECT_SESSION_CLOSED))) {
                const auto cleanup = kernel_module::maplesu_hook_close();
                if (cleanup != KModErr::OK)
                    std::fprintf(stderr, "MapleSU actor staging close failed: %lld\n", static_cast<long long>(cleanup));
                return;
            }
            if (!address) return;
            const auto cleanup = typed ? kernel_module::maplesu_hook_release(address)
                                       : kernel_module::free_kernel_mem(address);
            if (cleanup == KModErr::OK) return;
            std::fprintf(stderr, "MapleSU actor staging release failed: %lld\n", static_cast<long long>(cleanup));
            if (typed || owner) {
                const auto released = typed ? kernel_module::maplesu_hook_reply() : kernel_module::maplesu_request_management_reply();
                if (!released.completed || !(released.effects &
                    (MAPLESU_EFFECT_RELEASED | MAPLESU_EFFECT_QUARANTINED)))
                    (void)kernel_module::maplesu_hook_close();
            }
        } catch (...) {
            std::fprintf(stderr, "MapleSU actor staging cleanup interrupted\n");
            if ((typed || (identity.auth_state & 1)) && identity.matches()) {
                try { (void)kernel_module::maplesu_hook_close(); } catch (...) {}
            }
        }
    }
};

}  // namespace

PatchMtkHbtFilldir64::PatchMtkHbtFilldir64(const PatchBase& patch_base,
                                           uint64_t hbt_filldir64_kaddr)
    : PatchBase(patch_base), m_hbt_filldir64(hbt_filldir64_kaddr) {}

PatchMtkHbtFilldir64::~PatchMtkHbtFilldir64() = default;

/***************************************************************************
 * generate_hook_fake_filldir64 — 生成"假 filldir64"的机器码并安装。
 *
 *
 *   <prologue 4B>
 *       adr  x11, <内联字符串>                 ; aarch64_asm_set_x_cstr_ptr
 *       mov  x12, #0                          ; ll:%351
 *     L_matched:                              ; ll:%356 bind
 *       ldrb w13, [x1,  x12]                  ; ll:%357（Mem base=x1, index=x12）
 *       ldrb w14, [x11, x12]                  ; ll:%359（Mem base=x11, index=x12）
 *       cmp  w13, w14                         ; ll:%361
 *       b.ne L_next                           ; ll:%363
 *       add  x12, x12, #1                     ; ll:%365
 *       cmp  x12, #name.len                   ; ll:%367
 *       b.lo L_matched                        ; ll:%379（_emitI kIdBlo）
 *       mov  x0, xzr   (kernel < 6.1.0)       ; ll:%384
 *       mov  x0, #1    (kernel >= 6.1.0)      ; ll:%404
 *       ret  x30                              ; ll:%409
 *     L_next:                                 ; ll:%411 bind
 *
 *   ; 尾跳回原始 hbt:filldir64：x10 = 目标地址后 br x10
 *   movz/movk x10, #imm16, lsl #shift …       ; ll:%98-%129
 *
 * 未发布的分配由 create_kcfi_kernel_function 保有，完整生成成功后才转交调用者。
 ***************************************************************************/
KModErr PatchMtkHbtFilldir64::generate_hook_fake_filldir64(
    const std::vector<std::string>& hide_names, uint64_t& out_func_kaddr) {
    return generate_hook_fake_filldir64_impl(hide_names, out_func_kaddr, nullptr);
}

KModErr PatchMtkHbtFilldir64::generate_hook_fake_filldir64_owned(
    const std::vector<std::string>& hide_names, uint64_t& out_func_kaddr,
    kernel_module::OwnedHookActor& actor) {
    actor = {};
    return generate_hook_fake_filldir64_impl(hide_names, out_func_kaddr, &actor);
}

KModErr PatchMtkHbtFilldir64::generate_hook_fake_filldir64_impl(
    const std::vector<std::string>& hide_names, uint64_t& out_func_kaddr,
    kernel_module::OwnedHookActor* actor) {
    if (m_hbt_filldir64 == 0) {
        return KModErr::ERR_MODULE_PARAM;
    }

    // 后面每条 cmp 都用它（避免内联字符串操作污染 w2 的语义假设）。
    GpW w2_namelen = w2;

    aarch64_asm_ctx asm_ctx = init_aarch64_asm();
    auto a = asm_ctx.assembler();
    if (!a) return KModErr::ERR_MODULE_ASM;

    // 假函数入口字（见 kFakeFuncPrologueWord 的说明）。
    a->embed(reinterpret_cast<const uint8_t*>(&kFakeFuncPrologueWord),
             sizeof(kFakeFuncPrologueWord));

    for (size_t i = 0; i < hide_names.size(); ++i) {
        Label L_next = a->newLabel();     // 名字不匹配 → 下一个
        Label L_matched = a->newLabel();  // 字节比较循环入口

        const std::string& dir_name = hide_names[i];

        // 长度不等就不必比内容。
        a->cmp(w2_namelen, Imm(dir_name.size()));
        a->b(CondCode::kNE, L_next);

        // 把目录名以"内联 c 字符串"的形式放进代码流，并用 adr 取址到 x11。
        aarch64_asm_set_x_cstr_ptr(a, x11, dir_name);

        // 逐字节比较：x12 同时作为两个 ldrb 的索引寄存器。
        a->mov(x12, Imm(0));
        a->bind(L_matched);
        a->ldrb(w13, ptr(x1, x12));   // 实际目录项名字
        a->ldrb(w14, ptr(x11, x12));  // 内联的隐藏名
        a->cmp(w13, w14);
        a->b(CondCode::kNE, L_next);
        a->add(x12, x12, Imm(1));
        a->cmp(x12, Imm(dir_name.size()));
        a->b(CondCode::kLO, L_matched);

        // 命中：直接返回，不执行原始 filldir64（= 该目录项不可见）。
        // 返回值按内核版本区分：< 6.1.0 返回 0，否则返回 1。
        if (kernel_module::is_kernel_version_less(kHideReturnSwitchKernel)) {
            a->mov(x0, xzr);
        } else {
            a->mov(x0, Imm(1));
        }
        a->ret(x30);

        a->bind(L_next);
    }

    // 没有任何命中 → 尾跳回原始 hbt:filldir64。
    // 用 movz/movk 组出 64 位目标地址（跳过为 0 的 16 位段）。
    bool emitted_any = false;
    for (int shift = 0; shift < 4; ++shift) {
        const uint32_t imm16 =
            static_cast<uint32_t>((m_hbt_filldir64 >> (shift * 16)) & 0xFFFFu);
        if (imm16 == 0) continue;
        if (!emitted_any) {
            a->movz(x16, Imm(imm16), Imm(shift * 16));
        } else {
            a->movk(x16, Imm(imm16), Imm(shift * 16));
        }
        emitted_any = true;
    }
    if (!emitted_any) {
        // 全部 16 位段为 0（地址 0）：仍然要生成一条 movz 以保持指令形状。
        a->movz(x16, Imm(0), Imm(0));
    }
    a->br(x16);

    std::vector<uint8_t> code = aarch64_asm_to_bytes(a);
    if (asm_ctx.has_error() || code.empty()) return KModErr::ERR_MODULE_ASM;
    return create_kcfi_kernel_function(m_hbt_filldir64, code, out_func_kaddr, actor);
}

// Keep the allocation private until code, permissions and CPU visibility are ready.
KModErr PatchMtkHbtFilldir64::create_kcfi_kernel_function(
    uint64_t hbt_filldir64_kaddr, const std::vector<uint8_t>& code,
    uint64_t& out_func_kaddr) {
    return create_kcfi_kernel_function(hbt_filldir64_kaddr, code, out_func_kaddr, nullptr);
}

KModErr PatchMtkHbtFilldir64::create_kcfi_kernel_function(
    uint64_t hbt_filldir64_kaddr, const std::vector<uint8_t>& code,
    uint64_t& out_func_kaddr, kernel_module::OwnedHookActor* actor) {
    if (hbt_filldir64_kaddr < UINT64_C(0xffff000000000004) || (hbt_filldir64_kaddr & 3u) ||
        code.empty() || (code.size() & 3u) || code.size() > std::numeric_limits<uint32_t>::max() - 4u)
        return KModErr::ERR_MODULE_PARAM;
    const uint32_t total_size = static_cast<uint32_t>(code.size() + 4u);
    ActorStaging staging;
    if (!staging.identity.capture()) return KModErr::ERR_MODULE_ROOT_KEY;

    uint32_t kcfi_type_id = 0;
    KModErr err = kernel_module::read_kernel_mem(hbt_filldir64_kaddr - 4u, &kcfi_type_id,
                                                sizeof(kcfi_type_id));
    if (err != KModErr::OK) return err;
    if (!staging.identity.matches()) return KModErr::ERR_MODULE_ROOT_KEY;

    if (actor) {
        err = kernel_module::maplesu_hook_legacy_boot_selected(staging.boot_retained);
        if (err != KModErr::OK) return err;
    }
    staging.allocation_attempted = true;
    const bool staged_code = actor != nullptr && !staging.boot_retained;
    staging.typed = staged_code;
    err = staged_code ? kernel_module::maplesu_hook_reserve_code(total_size, 0, staging.address)
                      : staging.boot_retained ? kernel_module::request_kernel_alloc_mem(total_size, staging.address)
                                              : kernel_module::alloc_kernel_mem(total_size, staging.address);
    if (err != KModErr::OK) return err;
    if (!staging.identity.matches()) return KModErr::ERR_MODULE_ROOT_KEY;
    err = staged_code ? kernel_module::maplesu_hook_write(staging.address,
        &kcfi_type_id, sizeof(kcfi_type_id)) : kernel_module::write_kernel_mem(staging.address,
        &kcfi_type_id, sizeof(kcfi_type_id), kernel_module::KernMemProt::KMP_RW);
    if (err != KModErr::OK) return err;
    if (!staging.identity.matches()) return KModErr::ERR_MODULE_ROOT_KEY;

    const uint64_t code_addr = staging.address + 4u;
    err = staged_code ? kernel_module::maplesu_hook_write(code_addr, code.data(),
        static_cast<uint32_t>(code.size())) : kernel_module::write_kernel_mem(code_addr,
        code.data(), static_cast<uint32_t>(code.size()), kernel_module::KernMemProt::KMP_RW);
    if (err != KModErr::OK) return err;
    if (!staging.identity.matches()) return KModErr::ERR_MODULE_ROOT_KEY;
    if (!staged_code) {
        err = kernel_module::set_kernel_mem_protection(staging.address, total_size,
                                                      kernel_module::KernMemProt::KMP_X);
        if (err != KModErr::OK) return err;
        if (!staging.identity.matches()) return KModErr::ERR_MODULE_ROOT_KEY;
        err = kernel_module::icache_invalidate_all_cpus();
        if (err != KModErr::OK) return err;
        if (!staging.identity.matches()) return KModErr::ERR_MODULE_ROOT_KEY;
    }
    staging.transferred = true;
    out_func_kaddr = code_addr;
    if (actor) *actor = {staging.address, hbt_filldir64_kaddr, total_size, kcfi_type_id};
    return KModErr::OK;
}

}  // namespace module_root
}  // namespace default_modules
