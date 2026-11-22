#pragma once

#include <cstdint>
#include <type_traits>
#include "module_err_def.h"
#include "maplesu_sdk/maplesu_module.h"
#include "module_base_change_status.h"

static_assert(std::is_same_v<std::underlying_type_t<maplesu::sdk::ModuleRunState>, uint32_t>);
static_assert(static_cast<uint32_t>(maplesu::sdk::ModuleRunState::NotRunning) == 0);
static_assert(static_cast<uint32_t>(maplesu::sdk::ModuleRunState::Running) == 1);
static_assert(static_cast<uint32_t>(maplesu::sdk::ModuleRunState::Abnormal) == 2);
static_assert(static_cast<uint32_t>(maplesu::sdk::ModuleRunState::RemovedPendingReboot) == 3);

namespace maplesu::compat {
// The parameter remains the same u32 enum; preserve the frozen namespace name.
void set_current_module_run_state_legacy(sdk::ModuleRunState state)
    asm("_ZN13kernel_module28set_current_module_run_stateEN10skroot_env14ModuleRunStateE");
} // namespace maplesu::compat
