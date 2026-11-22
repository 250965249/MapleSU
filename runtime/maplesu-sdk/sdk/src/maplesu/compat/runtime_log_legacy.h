// Frozen external pipe ABI used by the runtime log compatibility boundary.
#pragma once
#include <cstddef>
#include <string>
#include <unistd.h>
#include "module_err_def.h"

#include "fork_legacy_abi.h"

namespace skroot_env {
KModErr read_skroot_log_cb(const char* root_key, void (*callback)(const char*));
KModErr set_skroot_log_enabled(const char* root_key, bool enable);
bool is_skroot_log_enabled(const char* root_key);
KModErr clear_skroot_log(const char* root_key);
}  // namespace skroot_env
