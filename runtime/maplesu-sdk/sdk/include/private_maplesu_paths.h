// private MapleSU paths implementation.
//
#pragma once

#include <cstdio>
#include <filesystem>
#include <string>

#include "kernel_module_kit_umbrella.h"
#include "private_maple_runtime.h"

namespace maplesu::sdk {

// 由 root_key 推导出的模块系统文件目录名（17 字符）。
// 例：root_key = "abcdefghijklmnop…" -> "abcdefghijklmnop" + 'a'
static inline std::string get_system_file_dir_name() {
    // 冻结 IR 形态：root_key 是 std::string(...) 临时量，substr 的完整表达式结束时
    // 即析构（不是函数末尾），临时量的栈槽随后被 operator+ 的结果复用。
    std::string head = std::string(__get_current_module_root_key_hd04aBTnbSZlTRP7S4mQpIeVvr2ssGjW())
                           .substr(0, FOLDER_HEAD_ROOT_KEY_LEN);
    return head + head[0];
}

// 模块系统文件目录，形如 "/data/<17 字符>/"。目录名临时量在 snprintf 的
// 完整表达式结束时析构，返回值的构造在其后（冻结成员的内联形态如此）。
static std::string get_system_file_dir_path() {
    char path_buf[1024] = {0};
    snprintf(path_buf, sizeof(path_buf), "/data/%s/", get_system_file_dir_name().c_str());
    return std::string(path_buf);
}

}  // namespace maplesu::sdk
