// module proc bootconfig implementation.
//
// 目标：把内核保存的 bootconfig 文本（/proc/bootconfig 的内容来源）里暴露
// 设备解锁/调试状态的 androidboot.* 键值改写成“已锁”形态，并过滤掉可疑条目，
// 从而让依赖 /proc/bootconfig 的检测看到一致的可信状态。
//
// 处理流程：
//   1. kallsyms 查 saved_boot_config，读指针，再逐字节读内核里的 bootconfig 文本；
//   2. 用 istringstream + getline 逐行解析，每行拆成 key / value（去空格、去引号）；
//   3. 按 key 归三类：丢弃、改写值、原样保留；
//   4. 需要改写的行按 "key = \"value\"" 形态重排，值里的 \ " \n \r \t 转义；
//   5. 结果与原文不同时，把新文本写进内核缓冲，再用原子 64 位写把
//      saved_boot_config 指针换成新缓冲；槽位本身在只读段时跳过（不可写）。
//
// 改写规则：
//   androidboot.selinux = "permissive"            -> "enforcing"
//   androidboot.vbmeta.device_state = "unlocked"  -> "locked"
//   androidboot.verifiedbootstate = orange/yellow/red -> "green"
//   msm_kgsl.preempt_enable 的值不是 0/1 时丢弃
//   value 里内嵌 androidboot.<x>=... 的行丢弃
#define SymbolLookupSilentGuard_8dfccc5cf454087c7314725d3487e703 \
    SymbolLookupSilentGuard_c67c0e4fed21dd11b34c67e0a5b878c8

#include "kernel_module_kit_umbrella.h"

#include <cstdint>
#include <cstdio>
#include <sstream>
#include <string>

#include "module_proc_bootconfig_private.h"

namespace default_modules {
namespace module_proc_bootconfig {

// 文件级 static helper 前置声明：init 在它们之前定义（与冻结成员的发射顺序一致）。
static std::string trim_copy(std::string s);
static std::string unquote_copy(std::string s);
static std::string lower_copy(std::string s);

// init —— /proc/bootconfig 内容改写。
//   返回值即 KModErr；失败时打印 "patch_kernel_handler ret: <err>"。
KModErr init() {
    KModErr ret = KModErr::OK;
    {
        SymbolLookupSilentGuard_c67c0e4fed21dd11b34c67e0a5b878c8 silent_guard;

        uint64_t bootconfig_kaddr = 0;
        ret = kernel_module::kallsyms_lookup_name("saved_boot_config", bootconfig_kaddr);
        if (is_ok(ret)) {
            uint64_t bootconfig_ptr = 0;
            ret = kernel_module::read_kernel_mem(bootconfig_kaddr, &bootconfig_ptr,
                                                 sizeof(bootconfig_ptr));
            if (is_ok(ret)) {
                if (bootconfig_ptr != 0) {
                    // ---- 逐字节把内核里的 bootconfig 文本读出来（上限 64 KiB）----
                    std::string raw_bootconfig;
                    for (uint64_t i = 0;; ++i) {
                        if (i == 65536) {
                            ret = KModErr::ERR_MODULE_ALLOC_MEM;
                            break;
                        }
                        char ch = 0;
                        ret = kernel_module::read_kernel_mem(bootconfig_ptr + i, &ch, 1);
                        if (is_failed(ret)) {
                            break;
                        }
                        if (ch == 0) {
                            break;
                        }
                        raw_bootconfig.push_back(ch);
                    }

                    if (is_ok(ret)) {
                        if (raw_bootconfig.empty()) {
                            puts("raw_bootconfig is empty!");
                        } else {
                            std::istringstream stream(raw_bootconfig);
                            std::string line;
                            std::string patched;

                            while (std::getline(stream, line)) {
                                std::string name;
                                std::string value;

                                std::string entry = trim_copy(line);
                                const std::string::size_type eq = entry.find('=');
                                if (entry.empty() || eq == std::string::npos) {
                                    // 无 '='：注释等原样保留（空行丢弃）。
                                    const std::string kept = trim_copy(line);
                                    if (!kept.empty()) {
                                        patched.append(line);
                                        patched.push_back('\n');
                                    }
                                    continue;
                                }

                                name = trim_copy(entry.substr(0, eq));
                                value = unquote_copy(entry.substr(eq + 1));
                                if (name.empty()) {
                                    const std::string kept = trim_copy(line);
                                    if (!kept.empty()) {
                                        patched.append(line);
                                        patched.push_back('\n');
                                    }
                                    continue;
                                }

                                const std::string key_lower = lower_copy(trim_copy(name));
                                const std::string value_lower =
                                    lower_copy(unquote_copy(value));

                                // 0 = 原样保留，1 = 丢弃该行，2 = 用 replacement 替换值。
                                const char* replacement_text = "";
                                int action = 0;
                                if (key_lower == "msm_kgsl.preempt_enable") {
                                    if (value_lower != "0" && value_lower != "1") {
                                        action = 1;
                                    }
                                } else if (key_lower == "androidboot.selinux") {
                                    if (value_lower == "permissive") {
                                        replacement_text = "enforcing";
                                        action = 2;
                                    }
                                } else if (key_lower == "androidboot.vbmeta.device_state") {
                                    if (value_lower == "unlocked") {
                                        replacement_text = "locked";
                                        action = 2;
                                    }
                                } else if (key_lower == "androidboot.verifiedbootstate") {
                                    if (value_lower == "orange" || value_lower == "yellow" ||
                                        value_lower == "red") {
                                        replacement_text = "green";
                                        action = 2;
                                    }
                                } else {
                                    const std::string::size_type p =
                                        value_lower.find("androidboot.");
                                    if (p != std::string::npos) {
                                        const std::string::size_type q =
                                            value_lower.find('=', p);
                                        if (q != std::string::npos && q > p + 12) {
                                            action = 1;
                                        }
                                    }
                                }

                                const std::string replacement(replacement_text);
                                if (action == 1) {
                                    continue;
                                }
                                if (action != 2) {
                                    patched.append(line);
                                    patched.push_back('\n');
                                    continue;
                                }

                                // ---- 值转义：\ " \n \r \t 各换成两字符序列 ----
                                std::string escaped;
                                escaped.reserve(replacement.size());
                                for (char c : replacement) {
                                    switch (c) {
                                        case '\\':
                                            escaped.append("\\\\");
                                            break;
                                        case '"':
                                            escaped.append("\\\"");
                                            break;
                                        case '\n':
                                            escaped.append("\\n");
                                            break;
                                        case '\r':
                                            escaped.append("\\r");
                                            break;
                                        case '\t':
                                            escaped.append("\\t");
                                            break;
                                        default:
                                            escaped.push_back(c);
                                            break;
                                    }
                                }

                                patched.append(trim_copy(name) + " = \"" + std::move(escaped) +
                                               "\"");
                                patched.push_back('\n');
                            }

                            if (patched == raw_bootconfig) {
                                puts("patch_kernel_handler ret: OK, no change");
                            } else {
                                uint64_t patched_kaddr = 0;
                                if (bootconfig_kaddr != 0 &&
                                    !kernel_ro_section_helper::
                                        is_addr_in_kernel_known_readonly_section(
                                            bootconfig_kaddr, nullptr)) {
                                    const uint32_t patched_size =
                                        static_cast<uint32_t>(patched.size() + 1);
                                    ret = kernel_module::alloc_kernel_mem(patched_size,
                                                                          patched_kaddr);
                                    if (is_ok(ret)) {
                                        ret = kernel_module::fill00_kernel_mem(
                                            patched_kaddr, patched_size,
                                            kernel_module::KernMemProt::KMP_RW);
                                    }
                                    if (is_ok(ret)) {
                                        ret = kernel_module::write_kernel_mem(
                                            patched_kaddr, patched.data(), patched_size,
                                            kernel_module::KernMemProt::KMP_RW);
                                    }
                                    if (is_ok(ret)) {
                                        ret = kernel_module::write_kernel_rw_mem_atomic64(
                                            bootconfig_kaddr, patched_kaddr);
                                    }
                                    if (is_ok(ret)) {
                                        puts("patch_kernel_handler ret: OK");
                                    }
                                } else {
                                    puts("pointer slot is in readonly section, skip");
                                    ret = KModErr::ERR_MODULE_READONLY_KADDR;
                                }
                            }
                        }
                    }
                } else {
                    ret = KModErr::ERR_MODULE_PARAM;
                }
            }
        }
    }

    if (is_failed(ret)) {
        printf("patch_kernel_handler ret: %s\n", to_string(ret).c_str());
    }
    return ret;
}

const char* get_module_eng_name() {
    return "module_proc_bootconfig";
}

// 判定空白字符：空格与 \t,\n,\v,\f,\r（等价 isspace 的子集）。
static bool is_bootconfig_sep(char c) {
    const unsigned char uc = static_cast<unsigned char>(c);
    return uc == static_cast<unsigned char>(' ') ||
           (uc >= static_cast<unsigned char>('\t') &&
            uc <= static_cast<unsigned char>('\r'));
}

// 去掉首尾空白。
//   左：begin 前进到第一个非空白；erase(s.begin(), begin)。
//   右：从 rbegin 起到最后一个非空白；erase(rit.base(), s.end())。
static std::string trim_copy(std::string s) {
    std::string::iterator begin = s.begin();
    while (begin != s.end() && is_bootconfig_sep(*begin)) {
        ++begin;
    }
    s.erase(s.begin(), begin);

    std::string::reverse_iterator rit = s.rbegin();
    while (rit != s.rend()) {
        if (!is_bootconfig_sep(*rit)) {
            break;
        }
        ++rit;
    }
    s.erase(rit.base(), s.end());
    return s;
}

// 去空白；若还剩下 >1 个字符且首尾都是双引号，去掉这对引号。
static std::string unquote_copy(std::string s) {
    s = trim_copy(std::move(s));
    if (s.size() > 1 && s.front() == '"' && s.back() == '"') {
        s = s.substr(1, s.size() - 2);
    }
    return s;
}

// 只把 ASCII 大写字母转小写。
static std::string lower_copy(std::string s) {
    for (char& c : s) {
        const unsigned char uc = static_cast<unsigned char>(c);
        if (uc >= static_cast<unsigned char>('A') && uc <= static_cast<unsigned char>('Z')) {
            c = static_cast<char>(uc | 0x20u);
        }
    }
    return s;
}

}  // namespace module_proc_bootconfig
}  // namespace default_modules
