// resetprop -- NAME=VALUE line parsing for -f/--file input.
//
// Ported from Magisk v30.7 ``base/files.rs`` (``BufReadExt::for_each_prop``):
// lines are trimmed, comment lines start with '#', and a line is a property only
// when it contains an '='; key and value are trimmed independently.
//
#pragma once

#include <string>

namespace maplesu::payload::resetprop {

struct PropLine {
    bool valid = false;
    std::string key;
    std::string value;
};

inline std::string trim_ascii(const std::string& text) {
    size_t first = 0;
    size_t last = text.size();
    while (first < last) {
        const char c = text[first];
        if (c != ' ' && c != '\t' && c != '\n' && c != '\r' && c != '\v' && c != '\f') break;
        ++first;
    }
    while (last > first) {
        const char c = text[last - 1];
        if (c != ' ' && c != '\t' && c != '\n' && c != '\r' && c != '\v' && c != '\f') break;
        --last;
    }
    return text.substr(first, last - first);
}

inline PropLine parse_prop_line(const std::string& line) {
    PropLine result;
    const std::string trimmed = trim_ascii(line);
    if (trimmed.empty()) return result;
    if (trimmed[0] == '#') return result;
    const size_t separator = trimmed.find('=');
    if (separator == std::string::npos) return result;
    result.valid = true;
    result.key = trim_ascii(trimmed.substr(0, separator));
    result.value = trim_ascii(trimmed.substr(separator + 1));
    return result;
}

}  // namespace maplesu::payload::resetprop
