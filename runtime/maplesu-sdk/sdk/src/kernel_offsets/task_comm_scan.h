// task comm scan implementation.
//
#pragma once

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstring>

#include "module_err_def.h"

// Bounded scan of the first 8 KiB of a task_struct image for the `comm`
// character array. The window and the four-byte candidate stride are part of
// the observable contract: the scan stops at the first candidate block whose
// bytes match the installed marker.
namespace maplesu_task_comm {

// `task`    kernel address of the task_struct to scan
// `name`    the NUL terminated marker installed in the process name
// `offset`  receives the byte offset of the first match
// `read`    callback that copies kernel memory into a local buffer
template <class Read>
KModErr scan(uint64_t task, const uint8_t (&name)[16], uint32_t& offset, Read read) {
    // The scan window is 8 KiB and candidates are evaluated every four bytes.
    constexpr uint32_t limit = 8192;
    constexpr uint32_t length = 15;
    constexpr uint32_t stride = 4;
    std::array<uint8_t, 256> block{};
    offset = 0;
    for (uint32_t begin = 0; begin + length <= limit;) {
        // Read as many complete candidates as fit into one block; the block
        // always carries every byte of its last candidate.
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
            // A wider fault tolerant read can touch unreadable bytes after a
            // valid match. Keep the original exact-read result in that case.
            for (uint32_t index = 0; index < candidates; ++index) {
                const auto candidate = begin + index * stride;
                const auto exact = read(task + candidate, block.data(), length);
                if (is_failed(exact)) {
                    return exact;
                }
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

}  // namespace maplesu_task_comm
