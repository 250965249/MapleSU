#pragma once
#include <cstdint>
#include "../maplesu/compat/fork_legacy_abi.h"

namespace maplesu::sdk {
enum class FixedTransferStatus : uint32_t { Complete, SizeMismatch, Truncated, IoError };
struct FixedTransferRead {
    FixedTransferStatus status = FixedTransferStatus::Complete;
    int32_t systemErrno = 0;
    uint64_t transferredBytes = 0;
};
FixedTransferRead read_fixed_transfer_data_from_child(
    const fork_pipe_info&, void* output, uint64_t expectedBytes);
}
