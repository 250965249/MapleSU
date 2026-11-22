#pragma once
#include "maplesu_sdk/module_callback.h"
#include "maplesu/compat/native_module_abi.h"
#include "kernel_module_kit_umbrella.h"

namespace maplesu::sdk {
bool module_has_install_callback(const std::vector<uint8_t>&);
bool module_has_uninstall_callback(const std::vector<uint8_t>&);
}

namespace maplesu::compat {
using maplesu::sdk::module_has_install_callback;
using maplesu::sdk::module_has_uninstall_callback;
using native_module::kModuleIdentitySymbol;
using native_module::kModuleInstallSymbol;
using native_module::kModuleUninstallSymbol;
}
