#pragma once
#include "module_err_def.h"
#include <algorithm>
#include <array>
#include <cstdint>
#include <cstring>

namespace maplesu_task_comm {
// Keep the original 8192-byte window and four-byte candidate order. Each read
// includes every byte of the last candidate, including matches across blocks.
template<class Read>
KModErr scan(uint64_t task, const uint8_t (&name)[16], uint32_t& offset, Read read) {
    constexpr uint32_t limit = 8192, length = 15, stride = 4;
    std::array<uint8_t, 256> block{};
    offset = 0;
    for (uint32_t begin = 0; begin + length <= limit;) {
        const auto candidates = std::min<uint32_t>(
            (block.size() - length) / stride + 1, (limit - length - begin) / stride + 1);
        const auto bytes = (candidates - 1) * stride + length;
        const auto error = read(task + begin, block.data(), bytes);
        if (is_ok(error)) {
            for (uint32_t index = 0; index < candidates; ++index) {
                if (std::memcmp(block.data() + index * stride, name, length) == 0) {
                    offset = begin + index * stride;
                    return offset ? KModErr::OK : KModErr::ERR_MODULE_OFFSET_NOT_FOUND;
                }
            }
        } else {
            // A wider nofault read can touch unreadable bytes after a valid
            // match. Retain the original exact-read result in that case.
            for (uint32_t index = 0; index < candidates; ++index) {
                const auto candidate = begin + index * stride;
                const auto exact = read(task + candidate, block.data(), length);
                if (is_failed(exact)) return exact;
                if (std::memcmp(block.data(), name, length) == 0) {
                    offset = candidate;
                    return offset ? KModErr::OK : KModErr::ERR_MODULE_OFFSET_NOT_FOUND;
                }
            }
        }
        begin += candidates * stride;
    }
    return KModErr::ERR_MODULE_OFFSET_NOT_FOUND;
}
}
