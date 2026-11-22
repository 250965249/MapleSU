#pragma once
#include <cstdint>
#include <tuple>
#include "helper_core.h"
#include "module_err_def.h"
#include "../../maplesu/module/types.h"
#include "maplesu_sdk/maplesu_installer.h"

namespace maplesu::bootstrap {
KModErr initialize(helper_context& context);
KModErr initialize_core(helper_context& context);
KModErr initialize_modules(helper_context& context);
KModErr acquire_root(const char* key);
int load_single(helper_context& context, const char* id);
module::SdkVersion sdk_version();
}
