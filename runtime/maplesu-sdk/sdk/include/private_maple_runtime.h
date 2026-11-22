// private maple runtime implementation.
//
#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "kernel_module_kit_umbrella.h"

// 当前模块上下文 getter（extern "C"，由安装器注入的运行时提供）。
//   __get_current_module_root_key_hd04aBTnbSZlTRP7S4mQpIeVvr2ssGjW
//   __get_current_module_id32_1b0494ae8a788541db46b82cc1f0577c
extern "C" const char* __get_current_module_root_key_hd04aBTnbSZlTRP7S4mQpIeVvr2ssGjW(void);
extern "C" const char* __get_current_module_id32_1b0494ae8a788541db46b82cc1f0577c(void);
extern "C" void __set_current_module_root_key_hd04aBTnbSZlTRP7S4mQpIeVvr2ssGjW(const char* root_key);

//   _ZN15default_modules11module_root16set_current_rootEb
// = default_modules::module_root::set_current_root(bool)，返回 KModErr。
namespace default_modules {
namespace module_root {
KModErr set_current_root(bool enable_root);
}  // namespace module_root
}  // namespace default_modules

namespace maplesu::sdk {

// 枚举全部已安装模块（不经 root_key 校验的原始通道）。
KModErr unsafe_get_all_modules(std::vector<module_record>& out_list);

}  // namespace maplesu::sdk

namespace maplesu::runtime_log {

// Internal query keeps a disabled log distinct from an SDK or worker failure.
__attribute__((visibility("hidden")))
KModErr query_enabled(const char* root_key, bool& enabled);

}  // namespace maplesu::runtime_log
