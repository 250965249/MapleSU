#pragma once

#include "maplesu_request_private.h"
#include <cerrno>

namespace kernel_module {

// Transport errors can carry a completed, validated business failure. Keep its
// original module code and native errno without replaying the fixed operation.
inline KModErr maplesu_request_helper_fixed_business(uint32_t operation, uint32_t mode,
    uint32_t exploit, uint64_t value, RequestEarlyFixedResult& output) {
    const KModErr transport = maplesu_request_helper_fixed(operation, mode, exploit, value, output);
    if (output.native_errno) errno = output.native_errno;
    if (output.code) return static_cast<KModErr>(output.code);
    if (transport == KModErr::OK && output.native_errno)
        return KModErr::ERR_MODULE_TEST_CHANNEL;
    return transport;
}

}  // namespace kernel_module
