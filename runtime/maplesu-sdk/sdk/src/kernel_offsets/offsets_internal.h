// offsets internal implementation.
//
#pragma once

#include <stdint.h>

#include "kernel_module_kit_umbrella.h"

namespace kernel_module {

// Reads an optional offset from this thread/process and module identity scope.
// A miss leaves out_offset unchanged; the caller recomputes. No disk persistence.
KModErr get_offset_cache(const char* key, uint32_t& out_offset);

// Retains a freshly discovered offset when caching is available. Cache resource
// failure does not turn a successful discovery into an error. ABI remains unchanged.
KModErr put_offset_cache(const char* key, uint32_t offset);

}  // namespace kernel_module
