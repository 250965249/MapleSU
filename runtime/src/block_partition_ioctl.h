#pragma once

#include <cerrno>
#include <linux/fs.h>

namespace maplesu {

using BlockIoctl = int (*)(int, unsigned long, int*);

// -1 queries; 0/1 change the held block device's flag and verify it by reading back.
inline int block_partition_read_only(int descriptor, int desired, BlockIoctl control) {
    if (descriptor < 0 || desired < -1 || desired > 1) return -EINVAL;
    auto invoke = [&](unsigned long operation, int* value) {
        int result;
        do { result = control(descriptor, operation, value); } while (result < 0 && errno == EINTR);
        return result < 0 ? -errno : 0;
    };
    int value = -1;
    int error = invoke(BLKROGET, &value);
    if (error) return error;
    if (value != 0 && value != 1) return -EIO;
    if (desired < 0) return value;
    // Dispatch explicit changes even when the generic flag already matches: the
    // driver may have work in set_read_only that BLKROGET never performs.
    value = desired;
    error = invoke(BLKROSET, &value);
    if (error) return error;
    value = -1;
    error = invoke(BLKROGET, &value);
    if (error) return error;
    return value == desired ? value : -EIO;
}

}  // namespace maplesu
