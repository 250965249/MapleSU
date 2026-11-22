#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "module_err_def.h"

namespace maplesu::module_state {

enum class List : uint8_t {
    Running = 0,
    Abnormal = 1,
    Removed = 2,
    PendingRunOnce = 3,
    FinishedRunOnce = 4,
    PendingRemoval = 5,
};

__attribute__((visibility("hidden"))) std::string path(List state);
__attribute__((visibility("hidden"))) KModErr read(List state, std::vector<std::string>& out);
__attribute__((visibility("hidden"))) KModErr save(List state, const std::vector<std::string>& ids);
__attribute__((visibility("hidden"))) KModErr add(List state, const std::string& id);
__attribute__((visibility("hidden"))) KModErr remove(List state, const std::string& id);

}  // namespace maplesu::module_state
