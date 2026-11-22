// MapleSU module install callback implementation.
//
#include "kernel_module_kit_umbrella.h"

#include <string>

namespace maplesu::sdk {
namespace features {
namespace callback {

// 触发模块的 on_install 回调：准备模块私有目录、重定向日志、设置运行环境，
// 然后调用模块 ELF 里的 ____INTERNEL_MAPLESU_MODULE_ON_INSTALL(root_key, dir, cb)。
// 失败时 out_reason 带出拒绝原因。
KModErr invoke_module_on_install(const std::string& module_id32, std::string& out_reason) {
    (void)module_id32;
    (void)out_reason;
    return KModErr::ERR_MODULE_INTERNAL_APPEND;
}

// 触发模块的 on_uninstall 回调（同样先准备环境、重定向日志）。
KModErr invoke_module_on_uninstall(const std::string& module_id32) {
    (void)module_id32;
    return KModErr::ERR_MODULE_INTERNAL_APPEND;
}

}  // namespace callback
}  // namespace features
}  // namespace maplesu::sdk
