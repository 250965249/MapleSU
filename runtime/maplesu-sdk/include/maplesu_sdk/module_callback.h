#pragma once
#include "module_err_def.h"
#include <string>

namespace maplesu::sdk::features::callback {
KModErr invoke_module_on_install(const std::string&, std::string&);
KModErr invoke_module_on_uninstall(const std::string&) asm("maplesu_module_uninstall_callback");
}
