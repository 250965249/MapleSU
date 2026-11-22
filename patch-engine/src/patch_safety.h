#pragma once
#include <cstddef>
#include <cstdint>
#include <vector>

namespace maplesu {
// Single-instruction trampoline support. PC-relative/control-flow instructions are rejected.
void restore_instruction(const std::vector<char>& source, size_t from,
                         std::vector<uint8_t>& destination, size_t to);
}
