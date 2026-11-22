// Offline probe: emit bytes from the production dispatcher and real SDK.
// This entry does not resolve symbols, write kernel memory, or install hooks.
#include "kernel_payload_loader.h"
#include <cstring>
extern "C" __attribute__((visibility("default"))) int maplesu_policy_dispatch_bytes(
        unsigned operation, uint64_t predicate, uint64_t handler, unsigned char* output, unsigned capacity, uint64_t activation) {
    auto bytes = maplesu::module_policy::emit_policy_query_dispatch(operation, predicate, handler, activation);
    if (bytes.empty() || bytes.size() > capacity) return -1;
    memcpy(output, bytes.data(), bytes.size());
    return static_cast<int>(bytes.size());
}
