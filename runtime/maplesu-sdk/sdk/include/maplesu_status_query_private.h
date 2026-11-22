#pragma once
#include "module_err_def.h"
namespace maplesu::sdk::runtime_settings {
__attribute__((visibility("hidden"))) KModErr query_boot_fail_protect(const char*, bool&);
__attribute__((visibility("hidden"))) KModErr query_adb_forced_disabled(const char*, bool&);
}
__attribute__((visibility("hidden"))) KModErr oneplus_bypass_query_work_normal(const char*, bool&);

namespace default_modules::module_bypass_oplus_secure_guard {
__attribute__((visibility("hidden"))) KModErr query_work_normal(bool&);
}
