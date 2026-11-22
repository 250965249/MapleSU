#pragma once
#include <cstdint>

namespace maplesu::aarch64 {
// Validate the full address difference before narrowing the signed imm26.
static inline bool encode_b(uint64_t from, uint64_t to, uint32_t& word) noexcept {
    if ((from | to) & 3u) return false;
    uint64_t displacement;
    if (to >= from) {
        displacement = to - from;
        if (displacement > 0x07fffffcULL) return false;
    } else {
        const uint64_t distance = from - to;
        if (distance > 0x08000000ULL) return false;
        displacement = uint64_t{0} - distance;
    }
    word = 0x14000000u | (static_cast<uint32_t>(displacement >> 2) & 0x03ffffffu);
    return true;
}
}
