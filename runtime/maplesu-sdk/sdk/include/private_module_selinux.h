// private module selinux implementation.
//
#pragma once

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <cerrno>
#include <string>
#include <sys/types.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/syscall.h>

#include "kernel_module_kit_umbrella.h"
#include "module_err_def.h"
#include "private_maple_runtime.h"
#include "maplesu_storage_private.h"
#include "maplesu_early_fixed_private.h"

// Ultra 私有错误段数值（不是 module_err_def.h 的 98 个枚举之一）。
//
// MapleSU 的 Ultra 段用 -199xx 编号（icache_policy.h 里 kAsm=-19990 与这里同段），
// 不向公共枚举塞新值。
constexpr ssize_t kUltraErrAsmInit               = -19990;
constexpr ssize_t kUltraErrSelinuxStatusPageNull = -19909;
constexpr ssize_t kUltraErrSelinuxStatusPageAddr = -19987;
constexpr ssize_t kUltraErrSetSelinuxEnforce     = -19933;
// Restricted EarlyHelper SELinux fixed business transport.
enum class EarlySelinuxOperation : uint32_t { Prepare=5, Enable=6, ReadStatus=7, WriteSequence=8 };
using RequestEarlySelinuxResult = kernel_module::RequestEarlyFixedResult;
inline KModErr maplesu_request_helper_selinux(EarlySelinuxOperation operation, uint32_t mode,
    uint32_t exploit, uint64_t value, RequestEarlySelinuxResult& result) {
    return kernel_module::maplesu_request_helper_fixed_business(static_cast<uint32_t>(operation),
        mode, exploit, value, result);
}


//   %struct.selinux_kernel_status = type { i32, i32, i32, i32, i32 }
// 成员顺序取 Linux security/selinux/include/status.h 的同名结构：
//   version / sequence / enforcing / policyload / deny_unknown
struct selinux_kernel_status {
    uint32_t version      = 0;
    uint32_t sequence     = 0;
    uint32_t enforcing    = 0;
    uint32_t policyload   = 0;
    uint32_t deny_unknown = 0;
};
static_assert(sizeof(selinux_kernel_status) == 20,
              "layout constraint violated");
static_assert(offsetof(selinux_kernel_status, sequence) == 4, "unexpected layout size");
static_assert(offsetof(selinux_kernel_status, policyload) == 12, "unexpected layout size");

//
//        fd = open_self_attr(name, O_WRONLY);
//        if fd < 0 return -1;
//        if (con) { n = strlen(con)+1; do write(fd, con, n) while (errno==EINTR) }
//        else     { do write(fd, "", 0)        while (errno==EINTR) }
//        saved = errno; close(fd); errno = saved; return rc<0 ? -1 : 0;
//        snprintf(buf,128,"/proc/thread-self/attr/%s", name);
//        fd = open(buf, flags|O_CLOEXEC);
//        if (fd>=0 || errno != ENOENT) return fd>=0?fd:-1;
//        snprintf(buf,128,"/proc/self/task/%d/attr/%s", gettid(), name);
//        return open(buf, flags|O_CLOEXEC);
namespace selinux_procattr {

namespace detail {

inline pid_t gettid_compat() {
#ifdef SYS_gettid
    return static_cast<pid_t>(syscall(SYS_gettid));
#else
    return static_cast<pid_t>(syscall(__NR_gettid));
#endif
}

inline int open_self_attr(const char* attr, int flags) {
    char path[128];
    snprintf(path, sizeof(path), "/proc/thread-self/attr/%s", attr);
    const int open_flags = flags | O_CLOEXEC;
    int fd = open(path, open_flags);
    if (fd >= 0) return fd;
    if (errno != ENOENT) return -1;
    const pid_t tid = gettid_compat();
    snprintf(path, sizeof(path), "/proc/self/task/%d/attr/%s", static_cast<int>(tid), attr);
    return open(path, open_flags);
}

inline int write_attr(const char* attr, const char* con) {
    const int fd = open_self_attr(attr, O_WRONLY);
    if (fd < 0) return -1;

    ssize_t rc;
    if (con) {
        const size_t n = strlen(con) + 1;
        do {
            rc = write(fd, con, n);
        } while (rc < 0 && errno == EINTR);
    } else {
        do {
            rc = write(fd, "", 0);
        } while (rc < 0 && errno == EINTR);
    }

    const int saved = errno;
    close(fd);
    errno = saved;
    return (rc < 0) ? -1 : 0;
}

}  // namespace detail

inline int setcon(const char* con) { return detail::write_attr("current", con); }
inline int setexeccon(const char* con) { return detail::write_attr("exec", con); }

}  // namespace selinux_procattr

// 文件级 static helper 前置声明
//
// 定义写在 module_selinux.cpp；resetprop 的 check_and_set_property（在下面
// 头文件内定义）要提前看到它们：
// 后两者带第 2 个参数（mangling 里有 PKPc）但所有调用点只传 1 个实参，
static std::string get_system_property(const char* name);
static void execve_cmdline(const char* cmdline, char* const* envp = nullptr);
static void fork_execve_cmdline(const char* cmdline, char* const* envp = nullptr);

// c67c0e4fed21dd11b34c67e0a5b878c8（与 private_mod_api_runtime_helper.h 里
// 8dfccc5c… 那份同构，只是类名不同）。语义：
//   ctor: active_ = get_symbol_lookup_printf_silent(); if (active_) set(false)
//   dtor: if (active_) set(true)
class SymbolLookupSilentGuard_c67c0e4fed21dd11b34c67e0a5b878c8 final {
public:
    SymbolLookupSilentGuard_c67c0e4fed21dd11b34c67e0a5b878c8() noexcept {
        active_ = get_symbol_lookup_printf_silent_d8685f89f10ca8eb96df766c8babd6c3();
        if (active_) {
            set_symbol_lookup_printf_silent_d8685f89f10ca8eb96df766c8babd6c3(false);
        }
    }

    ~SymbolLookupSilentGuard_c67c0e4fed21dd11b34c67e0a5b878c8() noexcept {
        if (active_) {
            set_symbol_lookup_printf_silent_d8685f89f10ca8eb96df766c8babd6c3(true);
        }
    }

    SymbolLookupSilentGuard_c67c0e4fed21dd11b34c67e0a5b878c8(
        const SymbolLookupSilentGuard_c67c0e4fed21dd11b34c67e0a5b878c8&) = delete;
    SymbolLookupSilentGuard_c67c0e4fed21dd11b34c67e0a5b878c8& operator=(
        const SymbolLookupSilentGuard_c67c0e4fed21dd11b34c67e0a5b878c8&) = delete;

private:
    bool active_ = false;
};

// resetprop 的两个枚举类型在 mangling 里**没有命名空间前缀**
//   _ZN9resetpropL22check_and_set_propertyEPKcS1_S1_17PropertyCheckMode13ResetPropMode
// ），所以它们必须是全局命名空间的 enum class，不能放进 resetprop 里。
// 做“不等才写”。
enum class PropertyCheckMode : int32_t {
    EqualsThenSet = 0,
    DifferentThenSet = 1,
};

enum class ResetPropMode : int32_t {
    Default = 0,
};

//
//          由 init 在启动时写入 "/data/<dir>/resetprop"；
//          s==nullptr -> "''"；否则 reserve(len+8)、'"'、逐字符（'\'' 展开成
//          "'\\''"）、结尾补 '；实测常量 .str.165="''"、.str.166="'\\''"；
//          name 为空 / value 为空 -> false；
//          cur = get_system_property(name)；
//          mode0: expect!=nullptr && cur==expect  才继续；
//          mode1: cur==value 则直接返回 false，否则继续；
//          其余 mode 直接 false；
//          继续后要求 name 非空、resetprop path 非空，
//          拼 "<quoted path> -n <quoted name> <quoted value>"（.str.162/163），
//          puts 打印后用 fork_execve_cmdline 执行，成功返回 true。
namespace resetprop {

namespace detail {

static std::string& resetprop_bin_path_ref() {
    static std::string path;
    return path;
}

static std::string shell_quote(const char* s) {
    if (s == nullptr) return std::string("''");

    std::string quoted;
    quoted.reserve(strlen(s) + 8);
    quoted.push_back('\'');
    for (const char* p = s; *p != '\0'; ++p) {
        if (*p == '\'') {
            quoted.append("'\\''");
        } else {
            quoted.push_back(*p);
        }
    }
    quoted.push_back('\'');
    return quoted;
}

}  // namespace detail

static bool check_and_set_property(const char* name,
                                   const char* expect_value,
                                   const char* new_value,
                                   PropertyCheckMode mode,
                                   ResetPropMode /*reset_prop_mode*/ = ResetPropMode::Default) {
    if (name == nullptr) return false;
    if (*name == '\0') return false;
    if (new_value == nullptr) return false;

    std::string current;
    {
        char buffer[92] = {0};
        const int len = __system_property_get(name, buffer);
        if (len >= 1) current.assign(buffer, static_cast<size_t>(len));
    }

    bool should_set = false;
    switch (mode) {
        case PropertyCheckMode::EqualsThenSet:
            if (expect_value == nullptr) return false;
            should_set = (current == expect_value);
            break;
        case PropertyCheckMode::DifferentThenSet:
            if (current == new_value) return false;
            should_set = true;
            break;
        default:
            return false;
    }
    if (!should_set) return false;

    if (*name == '\0') return false;

    const std::string& bin_path = detail::resetprop_bin_path_ref();
    if (bin_path.empty()) return false;

    std::string cmd;
    cmd.append(detail::shell_quote(bin_path.c_str()));
    cmd.append(" -n");
    cmd.append(" ");
    cmd.append(detail::shell_quote(name));
    cmd.append(" ");
    cmd.append(detail::shell_quote(new_value));

    puts(cmd.c_str());
    // fork_execve_cmdline 是 module_selinux.cpp 里的文件级 static 函数
    // （mangling _ZL19fork_execve_cmdlinePKcPKPc），在上面前置声明。
    fork_execve_cmdline(cmd.c_str());
    return true;
}

}  // namespace resetprop

//
//   fp = fopen("/proc/sys/kernel/random/boot_id", "r");   // .str.35/.str.36
//   if (!fp) return "";
//   char buf[128] = {0};
//   if (!fgets(buf, 128, fp)) { fclose(fp); return ""; }
//   fclose(fp);
//   std::string s(buf);
//   若首尾都无需裁剪则原样返回，否则返回 substr(first, last-first)。
namespace boot_session_utils {

static bool is_trim_char(char c) {
    return c == ' ' || c == '\r' || c == '\t' || c == '\n';
}

static std::string read_boot_session() {
    FILE* fp = fopen("/proc/sys/kernel/random/boot_id", "r");
    if (fp == nullptr) return std::string();

    char buffer[128] = {0};
    char* got = fgets(buffer, sizeof(buffer), fp);
    fclose(fp);
    if (got == nullptr) return std::string();

    std::string text(buffer);
    size_t first = 0;
    while (first < text.size() && is_trim_char(text[first])) ++first;
    size_t last = text.size();
    while (last > first && is_trim_char(text[last - 1])) --last;
    if (!(first == 0 && last == text.size())) {
        // （_ZNSt6__ndk1…basic_string…aSB7v170000EOS5_ / __move_assign），
        // 不是直接 return substr。这样 NRVO 后 text 就是 sret 本体。
        text = text.substr(first, last - first);
    }
    return text;
}

}  // namespace boot_session_utils

namespace maplesu::sdk {

static KModErr get_kernel_file_dir_name(std::string& out) {
    out.clear();
    storage::StorageContext context;
    RETURN_IF_ERROR(storage::current_context(context));
    out = context.locator.kernel_component;
    return KModErr::OK;
}

static std::string get_kernel_file_dir_name() {
    std::string out;
    (void)get_kernel_file_dir_name(out);
    return out;
}

}  // namespace maplesu::sdk

// Patch 面（全局命名空间；定义在 idx 90/91/92 三个成员里，本成员只引用）
//
//   _ZN9PatchBaseC1Ev / _ZN9PatchBaseD1Ev
//   _ZN34PatchSelinuxStatusUpdateSetenforceC1ERK9PatchBasem
//   _ZN34PatchSelinuxStatusUpdateSetenforceD1Ev
//   _ZN34PatchSelinuxStatusUpdateSetenforce38patch_selinux_status_update_setenforceEmjm
//   _ZN34PatchSelinuxStatusUpdatePolicyloadC1ERK9PatchBasem
//   _ZN34PatchSelinuxStatusUpdatePolicyloadD1Ev
//   _ZN34PatchSelinuxStatusUpdatePolicyload38patch_selinux_status_update_policyloadEm
//
// PatchBase 是 1 字节空标记类（patch_base_0091.h 的实施说明）；派生类在
// 说明 EBO 之后派生对象就是 8 字节 = { uint64_t }。
namespace kernel_module { struct RequestSharedBool; }

class PatchBase {
public:
    PatchBase();
    ~PatchBase();
};

class PatchSelinuxStatusUpdateSetenforce : public PatchBase {
public:
    PatchSelinuxStatusUpdateSetenforce(const PatchBase& base, uint64_t func_kaddr);
    ~PatchSelinuxStatusUpdateSetenforce();
    KModErr patch_selinux_status_update_setenforce(uint64_t status_page_kaddr,
                                                   uint32_t patch_len,
                                                   uint64_t new_value_kaddr);
    KModErr patch_selinux_status_update_setenforce(uint64_t status_page_kaddr,
                                                   uint32_t patch_len,
                                                   uint64_t new_value_kaddr,
                                                   kernel_module::HookHandle* handle);
    __attribute__((visibility("hidden"))) KModErr patch_selinux_status_update_setenforce(uint64_t status_page_kaddr,
                                                   uint32_t patch_len,
                                                   uint64_t new_value_kaddr,
                                                   kernel_module::HookHandle* handle,
                                                   const kernel_module::RequestSharedBool* dependency);

private:
    uint64_t func_kaddr_ = 0;
};
static_assert(sizeof(PatchSelinuxStatusUpdateSetenforce) == 8,
              "derived patch object must be 8 bytes");

class PatchSelinuxStatusUpdatePolicyload : public PatchBase {
public:
    PatchSelinuxStatusUpdatePolicyload(const PatchBase& base, uint64_t func_kaddr);
    ~PatchSelinuxStatusUpdatePolicyload();
    KModErr patch_selinux_status_update_policyload(uint64_t new_value_kaddr);
    KModErr patch_selinux_status_update_policyload(uint64_t new_value_kaddr,
                                                  kernel_module::HookHandle* handle);
    __attribute__((visibility("hidden"))) KModErr patch_selinux_status_update_policyload(uint64_t new_value_kaddr,
                                                  kernel_module::HookHandle* handle,
                                                  const kernel_module::RequestSharedBool* dependency);

private:
    uint64_t func_kaddr_ = 0;
};
static_assert(sizeof(PatchSelinuxStatusUpdatePolicyload) == 8,
              "derived patch object must be 8 bytes");
