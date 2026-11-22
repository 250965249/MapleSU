// module bypass oplus inte implementation.
//
#define SymbolLookupSilentGuard_8dfccc5cf454087c7314725d3487e703 \
    SymbolLookupSilentGuard_c67c0e4fed21dd11b34c67e0a5b878c8

#include "kernel_module_kit_umbrella.h"
#include "maplesu_early_fixed_private.h"

#include <cstdint>
#include <cstdio>
#include <set>
#include <vector>

#include "aarch64_asm_helper.h"
#include "module_base_kernel_mem.h"
#include "module_base_kernel_symbol_kaddr.h"
#include "third_party/____DO_NOT_EDIT____/private_mod_api_runtime_helper.h"

using namespace asmjit;
using namespace asmjit::a64;

namespace default_modules {
namespace module_bypass_oplus_inte {

const char* get_module_eng_name();

// PAC prologue 的 4 个编码与它们对应的 AUT 写回值。
namespace {

constexpr uint32_t kInsnPaciaz = 0xD503231Fu;
constexpr uint32_t kInsnPaciasp = 0xD503233Fu;
constexpr uint32_t kInsnPacibz = 0xD503235Fu;
constexpr uint32_t kInsnPacibsp = 0xD503237Fu;
constexpr uint32_t kInsnBtiMask = 0xFFFFFF3Fu;
constexpr uint32_t kInsnBtiVal = 0xD503241Fu;

constexpr size_t kPatchStubMaxBytes = 8;

// λA：`mov x0, xzr` —— 被 hook 的函数恒返回 0。
std::vector<uint8_t> build_return_zero_prefix() {
    aarch64_asm_ctx asm_ctx = init_aarch64_asm();
    auto* a = asm_ctx.assembler();
    a->mov(x0, xzr);
    return aarch64_asm_to_bytes(a);
}

// λB：把首条 PAC 指令换成配对的 AUT，再 ret。
// 非 PAC prologue 时只产生 `ret x30`。
std::vector<uint8_t> build_pac_fix_and_ret(uint32_t prologue_insn) {
    aarch64_asm_ctx asm_ctx = init_aarch64_asm();
    auto* a = asm_ctx.assembler();

    switch (prologue_insn) {
        case kInsnPaciaz:
            aarch64_asm_autiaz(a);
            break;
        case kInsnPaciasp:
            aarch64_asm_autiasp(a);
            break;
        case kInsnPacibz:
            aarch64_asm_autibz(a);
            break;
        case kInsnPacibsp:
            aarch64_asm_autibsp(a);
            break;
        default:
            break;
    }
    a->ret(x30);

    std::vector<uint8_t> bytes = aarch64_asm_to_bytes(a);
    if (bytes.size() > kPatchStubMaxBytes) return std::vector<uint8_t>();
    return std::vector<uint8_t>(bytes);
}

//     ==> aarch64_insn_is_pac_or_bti(insn)（谓词表见 .research/MapleSU 的 aarch64_insn.h）
bool is_pac_or_bti(uint32_t insn) {
    return insn == kInsnPaciaz || insn == kInsnPaciasp || insn == kInsnPacibz ||
           insn == kInsnPacibsp || (insn & kInsnBtiMask) == kInsnBtiVal;
}

}  // namespace

// 这里保持同样的静态函数形态，让编译器做同样的内联。
static KModErr resolve_oplus_inte_ret0_patch_targets() {
    static const char* const kSymbols[] = {
        "inte:add_ko_event",
        "inte:add_systbl_event",
        "inte:ko_proc_show",
        "inte:systbl_proc_show",
    };

    SymbolLookupSilentGuard_c67c0e4fed21dd11b34c67e0a5b878c8 silent_guard;

    std::set<uint64_t> targets;
    for (const char* symbol_name : kSymbols) {
        uint64_t kaddr = 0;
        const KModErr lookup_error = kernel_module::kallsyms_lookup_name(symbol_name, kaddr);
        if (lookup_error == KModErr::ERR_MODULE_SYMBOL_NOT_EXIST) continue;
        if (lookup_error != KModErr::OK) return lookup_error;
        if (kaddr == 0) continue;
        targets.insert(kaddr);
    }

    if (targets.empty()) return KModErr::OK;
    printf("oplus_kfunc cnt: %zu\n", targets.size());

    for (uint64_t target : targets) {
        uint32_t prologue_insn = 0;
        KModErr err = kernel_module::read_kernel_mem(target, &prologue_insn, sizeof(prologue_insn));
        if (err != KModErr::OK) return err;

        // 12 字节桩：返回 0（+ 必要时 AUT 掉首条 PAC）+ ret。
        std::vector<uint8_t> patch_bytes = build_return_zero_prefix();
        {
            std::vector<uint8_t> pac_fix = build_pac_fix_and_ret(prologue_insn);
            patch_bytes.insert(patch_bytes.end(), pac_fix.begin(), pac_fix.end());
        }

        // PAC/BTI 占位的首条指令要保留，改写点后移一条指令。
        const uint64_t patch_addr =
            is_pac_or_bti(prologue_insn) ? target + 4 : target;

        std::vector<uint8_t> expect(patch_bytes.size());
        err = kernel_module::read_kernel_mem(patch_addr, expect.data(),
                                            static_cast<uint32_t>(expect.size()));
        if (err == KModErr::OK) {
            const bool already_patched =
                expect.size() == patch_bytes.size() &&
                std::equal(expect.begin(), expect.end(), patch_bytes.begin());
            if (!already_patched) {
                err = kernel_module::write_kernel_mem(
                    patch_addr, patch_bytes.data(),
                    static_cast<uint32_t>(patch_bytes.size()),
                    kernel_module::KernMemProt::KMP_X);
            }
        }
        if (err != KModErr::OK) return err;
    }

    uint64_t ko_events_list = 0;
    uint64_t systbl_events_list = 0;
    KModErr lookup_error = kernel_module::kallsyms_lookup_name("inte:ko_events_list", ko_events_list);
    if (lookup_error != KModErr::OK && lookup_error != KModErr::ERR_MODULE_SYMBOL_NOT_EXIST)
        return lookup_error;
    lookup_error = kernel_module::kallsyms_lookup_name("inte:systbl_events_list", systbl_events_list);
    if (lookup_error != KModErr::OK && lookup_error != KModErr::ERR_MODULE_SYMBOL_NOT_EXIST)
        return lookup_error;
    if (ko_events_list != 0) {
        RETURN_IF_ERROR(kernel_module::fill00_kernel_mem(ko_events_list, 80,
                                        kernel_module::KernMemProt::KMP_RW));
    }
    if (systbl_events_list != 0) {
        RETURN_IF_ERROR(kernel_module::fill00_kernel_mem(systbl_events_list, 80,
                                        kernel_module::KernMemProt::KMP_RW));
    }
    puts("patch_kernel_handler ret: OK");

    return KModErr::OK;
}

KModErr init() {
    kernel_module::RequestEarlyFixedResult fixed{};
    const KModErr ret = kernel_module::maplesu_request_helper_mode() ?
        kernel_module::maplesu_request_helper_fixed_business(MAPLESU_EARLY_FIXED_OEM_OPLUS_INTE, 0, 0, 0, fixed) :
        resolve_oplus_inte_ret0_patch_targets();
    if (ret != KModErr::OK) {
        const int saved_errno = errno;
        printf("patch_kernel_handler ret: %s\n", to_string(ret).c_str());
        errno = saved_errno;
    }
    return ret;
}

const char* get_module_eng_name() { return "module_bypass_oplus_inte"; }

}  // namespace module_bypass_oplus_inte
}  // namespace default_modules
