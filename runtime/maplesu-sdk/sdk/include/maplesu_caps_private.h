#pragma once

#include <cstdint>
#include "kernel_offsets/cred.h"

namespace kernel_module {

// Keep presence metadata with the same status snapshot without changing caps_info.
__attribute__((visibility("hidden")))
KModErr get_current_caps_snapshot(caps_info& out, bool& ambient_present);

}  // namespace kernel_module
