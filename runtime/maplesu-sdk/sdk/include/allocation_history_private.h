#pragma once

#include "module_err_def.h"

namespace maplesu::allocation_history {

__attribute__((visibility("hidden"))) KModErr reset_idle_memory();
__attribute__((visibility("hidden"))) KModErr reset_hook_flags();

}  // namespace maplesu::allocation_history
