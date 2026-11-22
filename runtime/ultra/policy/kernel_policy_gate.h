#pragma once
#include "module_policy_config.h"

namespace maplesu::module_policy {
// Runs once before native SELinux setup and custom modules. A preparation
// failure holds custom modules without replacing native SDK initialization.
unsigned prepare_kernel_policy(Mode mode, bool allow_unverified = false);
}
