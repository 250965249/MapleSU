// SPDX-License-Identifier: GPL-3.0-only
#pragma once
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <vector>

namespace maplesu::su_auth::detail {
constexpr uint64_t uid_index_magic = UINT64_C(0x3158444955534d);
constexpr uint32_t uid_index_max = 4095;
struct UidIndexState {
    uint64_t magic, control, slots[2];
};
struct UidIndexHeader {
    uint64_t table;
    uint32_t count, buckets[256], reserved;
};
struct UidIndexEntry { uint32_t uid, next; };
static_assert(sizeof(UidIndexState) == 32 && sizeof(UidIndexHeader) == 1040);
static_assert(offsetof(UidIndexHeader, buckets) == 12 && sizeof(UidIndexEntry) == 8);

inline bool build_uid_index(uint64_t table, const std::vector<uint32_t>& uids,
                            std::vector<uint8_t>& output) {
    if (!table || uids.size() < 2 || uids.size() > uid_index_max + 1 || uids.back()) return false;
    UidIndexHeader header{};
    header.table = table;
    header.count = static_cast<uint32_t>(uids.size() - 1);
    std::vector<UidIndexEntry> entries(header.count);
    uint32_t previous = 0;
    for (uint32_t i = 0; i < header.count; ++i) {
        const auto uid = uids[i];
        if (uid <= previous || uid > 0x7fffffffU) return false;
        previous = uid;
        const uint32_t bucket = (uid * UINT32_C(0x61c88647)) >> 24;
        entries[i] = {uid, header.buckets[bucket]};
        header.buckets[bucket] = i + 1;
    }
    output.resize(sizeof(header) + entries.size() * sizeof(entries[0]));
    memcpy(output.data(), &header, sizeof(header));
    memcpy(output.data() + sizeof(header), entries.data(), entries.size() * sizeof(entries[0]));
    return true;
}
} // namespace maplesu::su_auth::detail
