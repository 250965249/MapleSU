#pragma once

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <map>
#include <string>
#include <vector>

namespace maplesu {

// Recovery reads only the supplied image. A candidate still needs a live SDK
// uid-0 response before the manager may replace its running identity.
inline std::vector<std::string> image_credentials(const uint8_t* bytes, size_t size) {
    if (!bytes || size < 64 || size > 256u * 1024u * 1024u ||
        std::memcmp(bytes + 56, "ARM\x64", 4) != 0) return {};
    auto word = [&](size_t at) {
        return uint32_t(bytes[at]) | uint32_t(bytes[at + 1]) << 8 |
            uint32_t(bytes[at + 2]) << 16 | uint32_t(bytes[at + 3]) << 24;
    };
    auto digit = [](uint8_t value) -> int {
        if (value >= '0' && value <= '9') return value - '0';
        if (value >= 'a' && value <= 'z') return value - 'a' + 10;
        if (value >= 'A' && value <= 'Z') return value - 'A' + 36;
        return -1;
    };
    std::map<std::string, std::vector<size_t>> envelopes;
    for (size_t at = 8; at + 28 <= size; at += 4) {
        if (bytes[at] != '/' || std::memcmp(bytes + at, "/data/", 6) != 0 ||
            std::memcmp(bytes + at + 22, "/init\0", 6) != 0) continue;
        bool valid = true;
        for (size_t i = 6; i < 22; ++i) if (digit(bytes[at + i]) < 0) valid = false;
        const size_t self = at - 8;
        const uint32_t lookup = word(at - 4);
        if (!valid || word(self) != self || lookup >= size || (lookup & 3)) continue;
        envelopes[std::string(reinterpret_cast<const char*>(bytes + at + 6), 16)].push_back(self);
    }
    if (envelopes.empty()) return {};
    std::vector<std::string> result;
    for (size_t at = 0; at + 48 <= size; at += 4) {
        bool valid = true;
        for (size_t i = 0; i < 48; ++i) if (digit(bytes[at + i]) < 0) { valid = false; break; }
        if (!valid) continue;
        const auto found = envelopes.find(std::string(reinterpret_cast<const char*>(bytes + at), 16));
        if (found == envelopes.end()) continue;
        const int count = (digit(bytes[at + 1]) - digit(bytes[at]) + 62) % 62;
        if (count < 3 || count > 8) continue;
        auto extended = [&](int index) { return bytes[at + (index == 48 ? 15 : index == 49 ? 2 : index)]; };
        const int start = 50 - count;
        const int seed = digit(extended(start));
        int64_t magnitude = 0;
        int sign = 0;
        for (int i = 0; i < count - 1; ++i) {
            const int value = (digit(extended(start + 1 + i)) - seed - i + 124) % 62;
            if (i == count - 2) sign = value;
            else magnitude = magnitude * 62 + value;
        }
        const int64_t delta = sign == 0 ? -magnitude : magnitude;
        if (!delta || delta % 4 || delta < -128ll * 1024 * 1024 || delta > 128ll * 1024 * 1024) continue;
        for (const size_t metadata : found->second) {
            const int64_t call = int64_t(metadata) - delta;
            if (call < 0 || call + 4 > int64_t(size) || call % 4 || word(size_t(call)) != 0xd63f0140u) continue;
            const std::string key(reinterpret_cast<const char*>(bytes + at), 48);
            bool duplicate = false;
            for (const auto& previous : result) if (previous == key) duplicate = true;
            if (!duplicate) result.push_back(key);
            break;
        }
    }
    return result;
}

} // namespace maplesu
