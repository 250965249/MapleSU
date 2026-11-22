// MapleSU module list private implementation.
//
#pragma once

#include <cstdint>
#include <string>
#include <vector>

// maplesu::sdk::fork_pipe_info / fork_base_info 与 fork 管道收发原语。
#include "private_maplesu_fork.h"

#include "kernel_module_kit_umbrella.h"

namespace maplesu::sdk {

KModErr __attribute__((visibility("hidden")))
unsafe_get_all_modules(std::vector<module_record>& out_list);

KModErr __attribute__((visibility("hidden")))
safe_get_all_modules(std::vector<module_record>& out_list);

// 由 maplesu_module_elf_meta.o 提供：从模块 ELF 字节里解析 module_desc。
KModErr parse_module_meta_from_elf_bytes(const std::vector<uint8_t>& elf_bytes,
                                        module_desc&                  out_desc);

// 由 maplesu_fork_helper.o 提供：fork 管道上的字节块收发。
bool write_transfer_data_from_child(const fork_pipe_info&         pipe,
                                    const std::vector<uint8_t>&   data);
bool read_transfer_data_from_child(fork_pipe_info&        pipe,
                                   std::vector<uint8_t>&  out_data);

}  // namespace maplesu::sdk

// 由安装器注入的运行时提供：当前模块 ROOT 密钥文本（hash 后缀不可改）。
extern "C" const char*
__get_current_module_root_key_hd04aBTnbSZlTRP7S4mQpIeVvr2ssGjW(void);

// 调用方 maplesu_module_control.o 的符号表里它是 UND，重定位类型
// 因此形参是"调用方提供的 std::string 槽位"。
extern "C" __attribute__((visibility("hidden")))
void maplesu_system_directory(std::string& out);

namespace default_modules {
namespace module_root {
KModErr set_current_root(bool enable_root);
}  // namespace module_root
}  // namespace default_modules
