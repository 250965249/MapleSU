// module bypass mtk mkp implementation.
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
namespace module_bypass_mtk_mkp {

const char* get_module_eng_name();

namespace {

// PAC prologue 的 4 个编码，以及每个编码对应的“写回值”。
// case 里用 w25 + 0x20/0x40/0x60 生成另外三条（0x34c/0x35c/0x36c）。
//   case 输入（原首指令）        写出的桩指令
//   0xD503231F PACIAZ   ->  0xD503239F AUTIAZ
//   0xD503233F PACIASP  ->  0xD50323BF AUTIASP
//   0xD503235F PACIBZ   ->  0xD50323DF AUTIBZ
//   0xD503237F PACIBSP  ->  0xD50323FF AUTIBSP
constexpr uint32_t kInsnPaciaz = 0xD503231Fu;
constexpr uint32_t kInsnPaciasp = 0xD503233Fu;
constexpr uint32_t kInsnPacibz = 0xD503235Fu;
constexpr uint32_t kInsnPacibsp = 0xD503237Fu;
constexpr uint32_t kInsnBtiMask = 0xFFFFFF3Fu;
constexpr uint32_t kInsnBtiVal = 0xD503241Fu;

// 桩最多两条指令（8 字节），超出就当作“生成失败”，返回空 vector。
constexpr size_t kPatchStubMaxBytes = 8;

// 生成“立即返回”桩。
//   PAC prologue -> [配对 AUT]*; ret x30   （8 字节）
//   其它         -> ret x30                （4 字节）
std::vector<uint8_t> build_return_patch(uint32_t prologue_insn) {
    aarch64_asm_ctx asm_ctx = init_aarch64_asm();
    auto* assembler = asm_ctx.assembler();

    // 签名指令必须先“验签”再返回，否则在内核里会触发 PAC 校验失败。
    switch (prologue_insn) {
        case kInsnPaciaz:
            aarch64_asm_autiaz(assembler);
            break;
        case kInsnPaciasp:
            aarch64_asm_autiasp(assembler);
            break;
        case kInsnPacibz:
            aarch64_asm_autibz(assembler);
            break;
        case kInsnPacibsp:
            aarch64_asm_autibsp(assembler);
            break;
        default:
            break;
    }
    assembler->ret(x30);

    std::vector<uint8_t> bytes = aarch64_asm_to_bytes(assembler);
    if (bytes.size() > kPatchStubMaxBytes) return std::vector<uint8_t>();
    return std::vector<uint8_t>(bytes);
}

//   ==> 首指令是 PAC 或 BTI 占位指令，改写点必须后移一条指令。
bool is_pac_or_bti(uint32_t insn) {
    return insn == kInsnPaciaz || insn == kInsnPaciasp || insn == kInsnPacibz ||
           insn == kInsnPacibsp || (insn & kInsnBtiMask) == kInsnBtiVal;
}

}  // namespace

// 里没有独立符号，只有它内部 lambda 的符号
// `_ZZN15default_modules21module_bypass_mtk_mkpL20patch_kernel_handlerEvENK3$_0clEm`）。
// 名字/链接性必须保持 `static` + 恰好 `patch_kernel_handler`，否则该 lambda 的
// mangled name 会变（mangling 也是 ABI）。
static KModErr patch_kernel_handler() {
    SymbolLookupSilentGuard_c67c0e4fed21dd11b34c67e0a5b878c8 silent_guard;

    // 三个候选符号：新内核在 pkvm/mkp 命名空间下导出，老内核直接导出。
    // 字面量取自 .rodata.str1.1（偏移 0x122/0x141/0x15b）。
    uint64_t pkvm_mkp_handle_mkp_err_action = 0;
    uint64_t mkp_handle_mkp_err_action = 0;
    uint64_t handle_mkp_err_action = 0;
    KModErr lookup_error = kernel_module::kallsyms_lookup_name("pkvm_mkp:handle_mkp_err_action",
                                        pkvm_mkp_handle_mkp_err_action);
    if (lookup_error != KModErr::OK && lookup_error != KModErr::ERR_MODULE_SYMBOL_NOT_EXIST)
        return lookup_error;
    lookup_error = kernel_module::kallsyms_lookup_name("mkp:handle_mkp_err_action",
                                        mkp_handle_mkp_err_action);
    if (lookup_error != KModErr::OK && lookup_error != KModErr::ERR_MODULE_SYMBOL_NOT_EXIST)
        return lookup_error;
    lookup_error = kernel_module::kallsyms_lookup_name("handle_mkp_err_action",
                                        handle_mkp_err_action);
    if (lookup_error != KModErr::OK && lookup_error != KModErr::ERR_MODULE_SYMBOL_NOT_EXIST)
        return lookup_error;

    if (pkvm_mkp_handle_mkp_err_action != 0) {
        printf("pkvm_mkp_handle_mkp_err_action, addr: %p\n",
               reinterpret_cast<void*>(pkvm_mkp_handle_mkp_err_action));
    }
    if (mkp_handle_mkp_err_action != 0) {
        printf("mkp_handle_mkp_err_action, addr: %p\n",
               reinterpret_cast<void*>(mkp_handle_mkp_err_action));
    }
    if (handle_mkp_err_action != 0) {
        printf("handle_mkp_err_action, addr: %p\n",
               reinterpret_cast<void*>(handle_mkp_err_action));
    }

    if (!(pkvm_mkp_handle_mkp_err_action || mkp_handle_mkp_err_action ||
          handle_mkp_err_action)) {
        return KModErr::OK;
    }

    // 去重：不同内核版本上三个符号可能指向同一个函数，避免重复 patch。
    std::set<uint64_t> targets;
    auto collect_target = [&targets](uint64_t kaddr) {
        if (kaddr == 0) return;
        targets.insert(kaddr);
    };
    collect_target(pkvm_mkp_handle_mkp_err_action);
    collect_target(mkp_handle_mkp_err_action);
    collect_target(handle_mkp_err_action);

    for (uint64_t target : targets) {
        uint32_t prologue_insn = 0;
        KModErr err = kernel_module::read_kernel_mem(target, &prologue_insn,
                                                    sizeof(prologue_insn));
        if (err != KModErr::OK) return err;

        std::vector<uint8_t> patch_bytes = build_return_patch(prologue_insn);

        const uint64_t patch_addr =
            is_pac_or_bti(prologue_insn) ? target + 4 : target;

        // 相同 => 之前已经打过，跳过写（幂等，内核里多处调用本模块不会重复改写）。
        std::vector<uint8_t> expect(patch_bytes.size());
        err = kernel_module::read_kernel_mem(patch_addr, expect.data(),
                                             static_cast<uint32_t>(expect.size()));
        if (err == KModErr::OK) {
            const bool already_patched =
                expect.size() == patch_bytes.size() &&
                std::equal(expect.begin(), expect.end(), patch_bytes.begin());
            if (!already_patched) {
                // 目标函数在 .text（只执行）区域，按 KMP_X 写入。
                err = kernel_module::write_kernel_mem(
                    patch_addr, patch_bytes.data(),
                    static_cast<uint32_t>(patch_bytes.size()),
                    kernel_module::KernMemProt::KMP_X);
            }
        }
        if (err != KModErr::OK) return err;
    }

    puts("patch_kernel_handler ret: OK");
    return KModErr::OK;
}

// 模块入口：只做 mkp 拒绝动作的就地改写。
KModErr init() {
    kernel_module::RequestEarlyFixedResult fixed{};
    const KModErr ret = kernel_module::maplesu_request_helper_mode() ?
        kernel_module::maplesu_request_helper_fixed_business(MAPLESU_EARLY_FIXED_OEM_MTK, 0, 0, 0, fixed) :
        patch_kernel_handler();
    if (ret != KModErr::OK) {
        const int saved_errno = errno;
        printf("patch_kernel_handler ret: %s\n", to_string(ret).c_str());
        errno = saved_errno;
    }
    return ret;
}

const char* get_module_eng_name() { return "module_bypass_mtk_mkp"; }

}  // namespace module_bypass_mtk_mkp
}  // namespace default_modules
