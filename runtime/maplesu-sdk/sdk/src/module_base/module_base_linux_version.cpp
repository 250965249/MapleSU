// module base linux version implementation.
//
#include "module_base_linux_version.h"

#include <cstddef>
#include <sstream>
#include <string>
#include <sys/utsname.h>
#include <vector>

namespace kernel_module {

// bionic 的 utsname 是 6 个 65 字节数组；release 位于第 3 个字段（offset 130）。
static_assert(sizeof(struct utsname) == 390, "bionic struct utsname must be 6 * 65 bytes");
static_assert(offsetof(struct utsname, release) == 130, "utsname.release must sit at offset 130");

namespace {

// 版本号最多保留三段（parse_version 会把短版本补零到 3 段）。
constexpr std::size_t kVersionSegments = 3;
// std::stoi 的进制。
constexpr int kDecimalBase = 10;
constexpr char kVersionSeparator = '.';

}  // namespace

// 读一次 uname(2) 的 release 字段，裁剪成 “数字与点” 的前缀并缓存。
//
// `L` 紧跟在 namespace 之后——这是 namespace 作用域内的 static 函数，不是匿名
// namespace（那样会变成 _ZN13kernel_module12_GLOBAL__N_1...）。ABI 要求照抄。
static std::string find_kernel_versions() {
    // 进程内缓存：成功后不再重复 uname()。
    static std::string last_ver;

    if (!last_ver.empty()) {
        return last_ver;
    }

    struct utsname buf {};
    if (uname(&buf) != 0) {
        return "";
    }

    std::string release(buf.release);

    std::string ver;
    for (char c : release) {
        const bool is_digit = (c >= '0' && c <= '9');
        if (!is_digit && c != kVersionSeparator) {
            break;
        }
        ver.push_back(c);
    }

    last_ver = ver;
    return ver;
}

// 把 “5.10.82” 这类字符串切成整数段，并补零到 3 段。
//
static std::vector<int> parse_version(const char* ver) {
    std::vector<int> out;

    //   24 = ios_base::in(8) | ios_base::out(16)，即 stringstream 的默认 openmode。
    std::stringstream ss{std::string(ver)};

    std::string item;
    while (std::getline(ss, item, kVersionSeparator)) {
        out.push_back(std::stoi(item, nullptr, kDecimalBase));
    }

    while (out.size() < kVersionSegments) {
        out.push_back(0);
    }
    return out;
}

// 公开接口

std::string get_kernel_version() {
    return find_kernel_versions();
}

bool is_kernel_version_less(const char* ver) {
    std::string current = find_kernel_versions();
    if (current.empty()) {
        return false;
    }

    std::vector<int> cur = parse_version(current.c_str());
    std::vector<int> want = parse_version(ver);

    for (std::size_t i = 0; i < kVersionSegments; ++i) {
        if (cur[i] < want[i]) {
            return true;
        }
        if (cur[i] > want[i]) {
            return false;
        }
    }
    return false;
}

}  // namespace kernel_module
