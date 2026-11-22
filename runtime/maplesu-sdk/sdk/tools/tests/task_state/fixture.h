#pragma once
// Extract the complete production function unchanged; stub SDK boundaries only.
#include <array>
#include <atomic>
#include <cerrno>
#include <cstdint>
#include <thread>
#include <vector>
#include <unistd.h>
#include "module_err_def.h"

namespace kernel_module {
KModErr get_offset_cache(const char*, uint32_t&);
KModErr put_offset_cache(const char*, uint32_t);
KModErr read_kernel_mem(uint64_t, void*, uint32_t);
KModErr get_task_struct_state_offset(uint32_t&);
}
KModErr shellcode_current_task(uint64_t&);
