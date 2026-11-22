#pragma once

#include <cstddef>
#include "module_err_def.h"
#include "maplesu_sdk/maplesu_module.h"
#include "maplesu_module_control.h"

// The nested version member keeps its measured padding despite packed spelling.
static_assert(sizeof(maplesu::sdk::module_desc) == 9232 && alignof(maplesu::sdk::module_desc) == 4);
static_assert(offsetof(maplesu::sdk::module_desc, name) == 0);
static_assert(offsetof(maplesu::sdk::module_desc, version) == 1024);
static_assert(offsetof(maplesu::sdk::module_desc, desc) == 2048);
static_assert(offsetof(maplesu::sdk::module_desc, author) == 6144);
static_assert(offsetof(maplesu::sdk::module_desc, id32) == 7168);
static_assert(offsetof(maplesu::sdk::module_desc, update_json) == 8192);
static_assert(offsetof(maplesu::sdk::module_desc, web_ui) == 9216);
static_assert(offsetof(maplesu::sdk::module_desc, min_sdk_ver) == 9220);
static_assert(sizeof(maplesu::sdk::module_record) == 9236 && alignof(maplesu::sdk::module_record) == 1);
static_assert(offsetof(maplesu::sdk::module_record, desc) == 0);
static_assert(offsetof(maplesu::sdk::module_record, state) == 9232);

namespace maplesu::compat {
// Vector/record layout is unchanged; do not copy or reinterpret the input.
std::vector<ModuleControlResult> get_module_controls_legacy(
    const char* key, const std::vector<sdk::module_record>& records)
    asm("_ZN7maplesu19get_module_controlsEPKcRKNSt6__ndk16vectorIN10skroot_env13module_recordENS2_9allocatorIS5_EEEE");
} // namespace maplesu::compat
