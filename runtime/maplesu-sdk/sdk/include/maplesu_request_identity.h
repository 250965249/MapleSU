#pragma once

#include <array>
#include <cstdint>
#include <cstring>
#include <unistd.h>
#include "maplesu_request_private.h"

extern "C" const char*
__get_current_module_root_key_hd04aBTnbSZlTRP7S4mQpIeVvr2ssGjW(void);

namespace kernel_module {
// Bind one ordinary consumer operation to its copied Key and process. These
// checks detect observed changes; they do not make multiple calls atomic.
struct RequestIdentity {
    std::array<char, 1024> key{};
    size_t length = 0;
    pid_t process = 0;
    std::uint32_t uid = 0;
    uint64_t auth_state = 0;

    bool capture() {
        process = getpid();
        auth_state = maplesu_request_auth_state();
        if (!maplesu_request_auth_usable(auth_state)) return false;
        if (maplesu_request_auth_authenticated(auth_state)) {
            uid = getuid();
            length = 0;
            return matches();
        }
        const char* current = __get_current_module_root_key_hd04aBTnbSZlTRP7S4mQpIeVvr2ssGjW();
        length = current ? strnlen(current, key.size()) : 0;
        if (!length || length == key.size()) return false;
        std::memcpy(key.data(), current, length + 1);
        return matches();
    }

    bool matches() const {
        if (!maplesu_request_auth_usable(auth_state) ||
            auth_state != maplesu_request_auth_state() || process != getpid()) return false;
        if (maplesu_request_auth_authenticated(auth_state)) return uid == getuid() && process == getpid() &&
            auth_state == maplesu_request_auth_state();
        if (!length || length == key.size() || process != getpid()) return false;
        const char* current = __get_current_module_root_key_hd04aBTnbSZlTRP7S4mQpIeVvr2ssGjW();
        return current && strnlen(current, key.size()) == length &&
            !std::memcmp(key.data(), current, length + 1) && process == getpid() &&
            auth_state == maplesu_request_auth_state();
    }
};
}  // namespace kernel_module
