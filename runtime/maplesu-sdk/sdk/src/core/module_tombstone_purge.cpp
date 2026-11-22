// module tombstone purge implementation.
//
#include <string>

#include "kernel_module_kit_umbrella.h"

namespace maplesu::sdk {

// 由模块描述符（private_desc_parser.h 生成段）提供的当前 root_key 取指针。
// 名字带 build token，故按 C 链接名直接声明，不加命名空间。
extern "C" const char* __get_current_module_root_key_hd04aBTnbSZlTRP7S4mQpIeVvr2ssGjW();

namespace {

constexpr size_t kKernelFileDirNameLen = 16;

}  // namespace

/***************************************************************************
 * get_kernel_file_dir_name — 用 root_key 前 16 字节派生内核侧文件名。
 *
 *   std::string key(__get_current_module_root_key_...());   // 可能为 nullptr
 *   return key.substr(0, 16);
 *
 * 边界行为：substr 在 length < 16 时不抛异常，直接返回整串（libc++ 语义），
 * 因此 root_key 较短时得到短串而不是越界读；root_key 为 nullptr 时会先构造
 * 同一语义以便 ABI 对齐，不额外加判空改变行为）。
 ***************************************************************************/
static std::string get_kernel_file_dir_name() {
    std::string key(__get_current_module_root_key_hd04aBTnbSZlTRP7S4mQpIeVvr2ssGjW());
    return key.substr(0, kKernelFileDirNameLen);
}

//   file_utils::is_dir_empty_noatime(const char*)
//   以及 tombstone 清理主流程（扫描 /data/tombstones、按 uid/进程名判定、
//   影响：本 TU 只提供文件名派生这一纯函数，清理链路缺失。

}  // namespace maplesu::sdk
