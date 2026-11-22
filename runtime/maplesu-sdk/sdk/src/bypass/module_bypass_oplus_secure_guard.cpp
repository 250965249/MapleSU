// module bypass oplus secure guard implementation.
//
#define SymbolLookupSilentGuard_8dfccc5cf454087c7314725d3487e703 \
    SymbolLookupSilentGuard_c67c0e4fed21dd11b34c67e0a5b878c8

#include "kernel_module_kit_umbrella.h"
#include "maplesu_early_fixed_private.h"

#include <algorithm>
#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <set>
#include <string>
#include <system_error>
#include <vector>

#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/system_properties.h>
#include <sys/types.h>
#include <sys/xattr.h>
#include <unistd.h>

#include "aarch64_asm_helper.h"
#include "module_base_kernel_mem.h"
#include "module_base_kernel_symbol_kaddr.h"
#include "maplesu_storage_private.h"
#include "maplesu_status_query_private.h"
#include "third_party/____DO_NOT_EDIT____/private_mod_api_runtime_helper.h"

using namespace asmjit;
using namespace asmjit::a64;

//   file_exists               @0xc9c  error_code{system_category,0} + fs::exists(path,ec)
//   set_file_selinux_access_mode @0xab0 chmod(path,0777) 成功后
//                                     setxattr(path,"security.selinux",
//                                              "u:object_r:system_file:s0",26,0)
//   create_empty_file         @0x9e0  ofstream(path, out|trunc|binary)，rdbuf()!=null 即成功
//   delete_path               @0xb08  remove_all(path,ec) 后 `!file_exists(path)`
namespace file_utils {

enum class SelinuxFileFlag : int {
    UNSPECIFIED = 0,
};

static bool file_exists(const std::filesystem::path& path) {
    std::error_code error;
    return std::filesystem::exists(path, error);
}

static bool set_file_selinux_access_mode(const char* file_path,
                                         SelinuxFileFlag /*flag*/ = SelinuxFileFlag::UNSPECIFIED) {
    if (file_path == nullptr) {
        return false;
    }
    if (::chmod(file_path, 0777) != 0) {
        return false;
    }
    const char kSystemFileContext[] = "u:object_r:system_file:s0";
    return ::setxattr(file_path, "security.selinux", kSystemFileContext,
                      sizeof(kSystemFileContext), 0) == 0;
}

static bool create_empty_file(const char* file_path) {
    std::ofstream ofs(file_path, std::ios::out | std::ios::trunc | std::ios::binary);
    if (!ofs.is_open()) return false;
    ofs.close();
    return !ofs.fail();
}

static bool delete_path(const std::filesystem::path& path) {
    std::error_code error;
    std::filesystem::remove_all(path, error);
    if (error) { errno = error.value(); return false; }
    const bool exists = std::filesystem::exists(path, error);
    if (error) errno = error.value();
    return !error && !exists;
}

}  // namespace file_utils

namespace {

constexpr uint32_t kInsnPaciaz = 0xD503231Fu;   // PACIAZ
constexpr uint32_t kInsnPaciasp = 0xD503233Fu;  // PACIASP
constexpr uint32_t kInsnPacibz = 0xD503235Fu;   // PACIBZ
constexpr uint32_t kInsnPacibsp = 0xD503237Fu;  // PACIBSP
constexpr uint32_t kInsnBtiMask = 0xFFFFFF3Fu;
constexpr uint32_t kInsnBtiVal = 0xD503241Fu;  // aarch64_insn_is_bti()

constexpr size_t kPatchStubMaxBytes = 8;

}  // namespace

// operator/ 的结果再经 path::operator string_type() 转回 std::string 返回。
static KModErr get_remove_bypass_mode_flag_path(std::string& out) {
    out.clear();
    std::string directory;
    RETURN_IF_ERROR(maplesu::storage::current_system_directory(directory));
    out = std::filesystem::path(directory) / "CM4tzWcGSrGSaFifGnqFsxyUNi0rcD0s";
    return KModErr::OK;
}

static KModErr get_work_normal_flag_path(std::string& out) {
    out.clear();
    std::string directory;
    RETURN_IF_ERROR(maplesu::storage::current_system_directory(directory));
    out = std::filesystem::path(directory) / "WRh8MJSIqEyB0E1WHTfIqCbjbckXAihS";
    return KModErr::OK;
}

//   true  : create_empty_file(flag) 成功后 set_file_selinux_access_mode(flag)
//   false : delete_path(flag)
static KModErr set_work_normal(bool work_normal) {
    std::string path;
    RETURN_IF_ERROR(get_work_normal_flag_path(path));
    if (work_normal) {
        if (!file_utils::create_empty_file(path.c_str())) {
            return KModErr::ERR_MODULE_OPEN_FILE;
        }
        return file_utils::set_file_selinux_access_mode(path.c_str())
            ? KModErr::OK : KModErr::ERR_MODULE_OPEN_FILE;
    }
    return file_utils::delete_path(path) ? KModErr::OK : KModErr::ERR_MODULE_OPEN_FILE;
}

//   ret==0        -> printf("remove module success: %s\n")
//   errno==ENOENT -> printf("module not found, skip: %s\n")
//   其它          -> printf("delete_module(\"%s\") failed: errno=%d (%s)\n", strerror(errno))
static void rmmod(const std::string& module_name) {
    constexpr long kDeleteModuleFlags = 0x800;  // O_NONBLOCK
    errno = 0;
    const long ret = ::syscall(__NR_delete_module, module_name.c_str(), kDeleteModuleFlags);
    if (ret == 0) {
        printf("remove module success: %s\n", module_name.c_str());
        return;
    }
    if (errno == ENOENT) {
        printf("module not found, skip: %s\n", module_name.c_str());
        return;
    }
    printf("delete_module(\"%s\") failed: errno=%d (%s)\n", module_name.c_str(), errno,
           strerror(errno));
}

// kSymbols 表来自 .data.rel.ro+0xb8（3 项，逐字节解码）。
static KModErr resolve_oplus_guard_boot_state_targets(std::set<uint64_t>& targets) {
    static const char* const kSymbols[] = {
        "oplus_secure_guard:g_boot_state",
        "oplus_secure_guard_new:g_boot_state",
        "oplus_security_guard:g_boot_state",
    };

    SymbolLookupSilentGuard_c67c0e4fed21dd11b34c67e0a5b878c8 silent_guard;

    targets.clear();
    for (const char* symbol_name : kSymbols) {
        uint64_t kaddr = 0;
        const KModErr lookup_error = kernel_module::kallsyms_lookup_name(symbol_name, kaddr);
        if (lookup_error == KModErr::ERR_MODULE_SYMBOL_NOT_EXIST) continue;
        if (lookup_error != KModErr::OK) return lookup_error;
        if (kaddr == 0) {
            continue;
        }
        targets.insert(kaddr);
    }
    return KModErr::OK;
}

namespace default_modules {
namespace module_bypass_oplus_secure_guard {

const char* get_module_eng_name();

bool first_install_init();

KModErr init();

bool is_work_normal();

static bool equals_ignore_case(const std::string& lhs, const std::string& rhs) {
    if (lhs.size() != rhs.size()) {
        return false;
    }
    for (size_t index = 0; index < lhs.size(); ++index) {
        char lhs_char = lhs[index];
        char rhs_char = rhs[index];
        if (lhs_char >= 'A' && lhs_char <= 'Z') {
            lhs_char = static_cast<char>(lhs_char | 0x20);
        }
        if (rhs_char >= 'A' && rhs_char <= 'Z') {
            rhs_char = static_cast<char>(rhs_char | 0x20);
        }
        if (lhs_char != rhs_char) {
            return false;
        }
    }
    return true;
}

//   rotr(insn + 0x2AFCDCE1, 5) < 4  ==> insn ∈ {PACIAZ,PACIASP,PACIBZ,PACIBSP}
//   (insn & 0xFFFFFF3F) == 0xD503241F ==> BTI
static bool is_pac_or_bti(uint32_t insn) {
    return insn == kInsnPaciaz || insn == kInsnPaciasp || insn == kInsnPacibz ||
           insn == kInsnPacibsp || (insn & kInsnBtiMask) == kInsnBtiVal;
}

//   mov x0, xzr                     4 B（恒返回 0）
//   ret x30                         4 B
static std::vector<uint8_t> build_return_zero_patch_bytes(uint32_t prologue_insn) {
    aarch64_asm_ctx head_ctx = init_aarch64_asm();
    head_ctx.assembler()->mov(x0, xzr);
    std::vector<uint8_t> patch_bytes = aarch64_asm_to_bytes(head_ctx.assembler());

    aarch64_asm_ctx fix_ctx = init_aarch64_asm();
    Assembler* fix_assembler = fix_ctx.assembler();
    switch (prologue_insn) {
        case kInsnPaciaz:
            aarch64_asm_autiaz(fix_assembler);
            break;
        case kInsnPaciasp:
            aarch64_asm_autiasp(fix_assembler);
            break;
        case kInsnPacibz:
            aarch64_asm_autibz(fix_assembler);
            break;
        case kInsnPacibsp:
            aarch64_asm_autibsp(fix_assembler);
            break;
        default:
            break;
    }
    fix_assembler->ret(x30);
    std::vector<uint8_t> pac_fix_bytes = aarch64_asm_to_bytes(fix_assembler);
    std::vector<uint8_t> fix_bytes =
        pac_fix_bytes.size() > kPatchStubMaxBytes ? std::vector<uint8_t>() : pac_fix_bytes;
    patch_bytes.insert(patch_bytes.end(), fix_bytes.begin(), fix_bytes.end());
    return patch_bytes;
}

// 函数体自身没有独立符号；kSymbols = .data.rel.ro+0 的 18 项）。
// 返回：KModErr（成功 = OK）。
static KModErr resolve_oplus_guard_ret0_patch_targets() {
    static const char* const kSymbols[] = {
        "oplus_exe_block_ret_handler",
        "oplus_harden_pre_handler",
        "oplus_root_check_post_handler",
        "oplus_root_check_succ_upload",
        "oplus_root_check_succ",
        "oplus_report_execveat_new",
        "do_execveat_common_entry_handler",
        "report_security_event",
        "oplus_secure_harden_kevent",
        "oplus_check_execveat_perm",
        "oplus_exec_block",
        "oplus_root_reboot",
        "oplus_secure_guard:handler_pre",
        "oplus_secure_guard_new:handler_pre",
        "oplus_security_guard:handler_pre",
        "oplus_secure_guard:uid_ret_handler",
        "oplus_secure_guard_new:uid_ret_handler",
        "oplus_security_guard:uid_ret_handler",
    };

    SymbolLookupSilentGuard_c67c0e4fed21dd11b34c67e0a5b878c8 silent_guard;

    std::set<uint64_t> targets;
    for (const char* symbol_name : kSymbols) {
        uint64_t kaddr = 0;
        const KModErr lookup_error = kernel_module::kallsyms_lookup_name(symbol_name, kaddr);
        if (lookup_error == KModErr::ERR_MODULE_SYMBOL_NOT_EXIST) continue;
        if (lookup_error != KModErr::OK) return lookup_error;
        if (kaddr == 0) {
            continue;
        }
        targets.insert(kaddr);
    }

    if (targets.empty()) {
        return KModErr::OK;
    }
    printf("oplus_kfunc cnt: %zu\n", targets.size());

    for (uint64_t target : targets) {
        uint32_t prologue_insn = 0;
        KModErr err =
            kernel_module::read_kernel_mem(target, &prologue_insn, sizeof(prologue_insn));
        if (err != KModErr::OK) {
            return err;
        }

        std::vector<uint8_t> patch_bytes = build_return_zero_patch_bytes(prologue_insn);

        const uint64_t patch_addr = is_pac_or_bti(prologue_insn) ? target + 4 : target;

        std::vector<uint8_t> expect_bytes(patch_bytes.size());
        err = kernel_module::read_kernel_mem(patch_addr, expect_bytes.data(),
                                             static_cast<uint32_t>(expect_bytes.size()));
        if (err == KModErr::OK) {
            const bool already_patched =
                expect_bytes.size() == patch_bytes.size() &&
                std::equal(expect_bytes.begin(), expect_bytes.end(), patch_bytes.begin());
            if (!already_patched) {
                err = kernel_module::write_kernel_mem(
                    patch_addr, patch_bytes.data(),
                    static_cast<uint32_t>(patch_bytes.size()),
                    kernel_module::KernMemProt::KMP_X);
            }
        }
        if (err != KModErr::OK) {
            return err;
        }
    }

    // 读每个 g_boot_state 的第 1 字节：读取失败原样返回，最后一次读到的字节非 0 时，
    // 逐个 set_kernel_mem_protection(RW) -> write 0 -> set_kernel_mem_protection(RO)。
    std::set<uint64_t> boot_state_targets;
    RETURN_IF_ERROR(resolve_oplus_guard_boot_state_targets(boot_state_targets));
    uint8_t boot_state_value = 0;
    for (uint64_t target : boot_state_targets) {
        boot_state_value = 0;
        RETURN_IF_ERROR(kernel_module::read_kernel_mem(target, &boot_state_value,
                                           sizeof(boot_state_value)));
    }

    if (!boot_state_targets.empty() && boot_state_value != 0) {
        std::set<uint64_t> patch_targets;
        RETURN_IF_ERROR(resolve_oplus_guard_boot_state_targets(patch_targets));
        const uint8_t zero_value = 0;
        for (uint64_t target : patch_targets) {
            KModErr err = kernel_module::set_kernel_mem_protection(
                target, sizeof(zero_value), kernel_module::KernMemProt::KMP_RW);
            if (err == KModErr::OK) {
                err = kernel_module::write_kernel_mem(target, &zero_value, sizeof(zero_value),
                                                      kernel_module::KernMemProt::KMP_RW);
            }
            if (err == KModErr::OK) {
                err = kernel_module::set_kernel_mem_protection(
                    target, sizeof(zero_value), kernel_module::KernMemProt::KMP_RO);
            }
            if (err != KModErr::OK) {
                return err;
            }
        }
        if (patch_targets.empty()) {
            return KModErr::ERR_MODULE_SYMBOL_PARAM;
        }
    }

    const KModErr work_error = set_work_normal(true);
    if (is_failed(work_error)) {
        const int saved_errno = errno;
        puts("set_work_normal failed");
        errno = saved_errno;
        return work_error;
    }
    puts("patch_kernel_handler ret: OK");
    return KModErr::OK;
}

// 92 字节缓冲 = PROP_VALUE_MAX；返回长度 <1 视为空串。
static std::string get_product_model() {
    static_assert(PROP_VALUE_MAX == 92, "layout constraint violated");
    char value[PROP_VALUE_MAX] = {0};
    const int value_len = __system_property_get("ro.product.model", value);
    if (value_len <= 0) {
        return {};
    }
    return std::string(value, static_cast<size_t>(value_len));
}

const char* get_module_eng_name() { return "module_bypass_oplus_secure_guard"; }

KModErr query_work_normal(bool& value) {
    std::string path;
    RETURN_IF_ERROR(get_work_normal_flag_path(path));
    std::error_code error;
    const bool observed = std::filesystem::exists(path, error);
    if (error) { errno = error.value(); return KModErr::ERR_MODULE_OPEN_FILE; }
    value = observed;
    return KModErr::OK;
}
bool is_work_normal() {
    bool value = false;
    (void)query_work_normal(value);
    return value;
}

//   model == PLF110 / PHP110（大小写不敏感）
//       -> printf("model is %s, remove oplus secure guard\n", model)
//          create_empty_file(remove_bypass_mode_flag) 成功后再 set_selinux_access_mode
//   否则 -> delete_path(remove_bypass_mode_flag)
bool first_install_init() {
    std::string model = get_product_model();
    std::string path;
    if (is_failed(get_remove_bypass_mode_flag_path(path))) return false;
    if (equals_ignore_case(model, "PLF110") || equals_ignore_case(model, "PHP110")) {
        printf("model is %s, remove oplus secure guard\n", model.c_str());
        if (!file_utils::create_empty_file(path.c_str())) {
            return false;
        }
        return file_utils::set_file_selinux_access_mode(
            path.c_str());
    }
    return file_utils::delete_path(path);
}

//   1) remove_bypass_mode_flag 存在 => 已经是"删除 bypass"模式：
//        打印提示、rmmod 三个 OPLUS secure guard 模块、置 work_normal=true、原样返回标志写入结果。
//   2) 否则先清 work_normal 标志（失败 => "set_work_normal failed" + -19933）。
//   3) 解析并 patch ret0 目标 + boot_state，最后置 work_normal=true；
//      失败时打印 "patch_kernel_handler ret: %s"（to_string(KModErr)）。
KModErr init() {
    std::string path;
    RETURN_IF_ERROR(get_remove_bypass_mode_flag_path(path));
    std::error_code path_error;
    const bool remove_mode = std::filesystem::exists(path, path_error);
    if (path_error) { errno = path_error.value(); return KModErr::ERR_MODULE_OPEN_FILE; }
    if (remove_mode) {
        puts("is remove bypass mode, remove oplus secure guard");
        rmmod("oplus_secure_guard");
        rmmod("oplus_secure_guard_new");
        rmmod("oplus_security_guard");
        return set_work_normal(true);
    }

    const KModErr work_error = set_work_normal(false);
    if (is_failed(work_error)) {
        const int saved_errno = errno;
        puts("set_work_normal failed");
        errno = saved_errno;
        return work_error;
    }

    KModErr ret;
    if (kernel_module::maplesu_request_helper_mode()) {
        kernel_module::RequestEarlyFixedResult fixed{};
        ret = kernel_module::maplesu_request_helper_fixed_business(
            MAPLESU_EARLY_FIXED_OEM_OPLUS_GUARD, 0, 0, 0, fixed);
        if (ret == KModErr::OK && fixed.values[0]) ret = set_work_normal(true);
    } else {
        ret = resolve_oplus_guard_ret0_patch_targets();
    }
    if (ret != KModErr::OK) {
        const int saved_errno = errno;
        printf("patch_kernel_handler ret: %s\n", to_string(ret).c_str());
        errno = saved_errno;
    }
    return ret;
}

}  // namespace module_bypass_oplus_secure_guard
}  // namespace default_modules
