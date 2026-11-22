#pragma once

#include "module_err_def.h"

namespace maplesu::install {

namespace state { class Mutation; }

// Payload publication and version commitment precede bootstrap recovery state.
__attribute__((visibility("hidden"))) KModErr prepare_environment_bootstrap();
// Called only after payload/config/version publication succeeded; safe is cleared last.
__attribute__((visibility("hidden"))) KModErr prepare_environment_bootstrap_state();
// Replace helper bytes without resetting the current boot's execution state.
__attribute__((visibility("hidden"))) KModErr refresh_environment_bootstrap();
__attribute__((visibility("hidden"))) KModErr commit_environment_version();
__attribute__((visibility("hidden"))) KModErr commit_environment_version(state::Mutation& mutation);

}  // namespace maplesu::install

namespace maplesu::sdk {

// State operations remain available before the helper payload is embedded.
__attribute__((visibility("hidden"))) KModErr unsafe_reset_autorun_bootstrap_safe_flag();
__attribute__((visibility("hidden"))) KModErr unsafe_reset_autorun_bootstrap_duplicate_boot_session_flag();

}  // namespace maplesu::sdk
