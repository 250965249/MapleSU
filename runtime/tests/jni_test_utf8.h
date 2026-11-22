#pragma once

#include <jni.h>
#include <cstdint>
#include <stdexcept>
#include <string>

inline std::string jni_test_utf16_to_utf8(const jchar* characters, jsize length) {
    std::string output;
    for (jsize i = 0; i < length; ++i) {
        uint32_t code = characters[i];
        if (code >= 0xd800 && code <= 0xdbff) {
            if (++i >= length || characters[i] < 0xdc00 || characters[i] > 0xdfff)
                throw std::range_error("unpaired UTF-16 surrogate in JNI receipt");
            code = 0x10000 + ((code - 0xd800) << 10) + (characters[i] - 0xdc00);
        } else if (code >= 0xdc00 && code <= 0xdfff) {
            throw std::range_error("unpaired UTF-16 surrogate in JNI receipt");
        }
        if (code < 0x80) {
            output += static_cast<char>(code);
        } else if (code < 0x800) {
            output += static_cast<char>(0xc0 | (code >> 6));
            output += static_cast<char>(0x80 | (code & 0x3f));
        } else if (code < 0x10000) {
            output += static_cast<char>(0xe0 | (code >> 12));
            output += static_cast<char>(0x80 | ((code >> 6) & 0x3f));
            output += static_cast<char>(0x80 | (code & 0x3f));
        } else {
            output += static_cast<char>(0xf0 | (code >> 18));
            output += static_cast<char>(0x80 | ((code >> 12) & 0x3f));
            output += static_cast<char>(0x80 | ((code >> 6) & 0x3f));
            output += static_cast<char>(0x80 | (code & 0x3f));
        }
    }
    return output;
}
