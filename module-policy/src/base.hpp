#pragma once
#include <algorithm>
#include <array>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <string_view>
#include <vector>
// Captured by the CLI at the source rule boundary; never silently discarded.
inline std::string policy_diagnostic;
inline void policy_warning(const char *text) { policy_diagnostic += text; }
template<typename... Args>
inline void policy_warning(const char *format, Args... args) {
    int n = std::snprintf(nullptr, 0, format, args...);
    if (n > 0) {
        std::vector<char> text(static_cast<size_t>(n) + 1);
        std::snprintf(text.data(), text.size(), format, args...);
        policy_diagnostic.append(text.data(), static_cast<size_t>(n));
    }
}
#define LOGW(...) policy_warning(__VA_ARGS__)
