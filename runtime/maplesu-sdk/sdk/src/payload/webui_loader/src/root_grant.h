// webui_loader -- obtaining the root identity the kit expects.
//
// The kernel module grants root to a caller that presents the current module
// root key: the key is passed to the kernel's exec hook as an execve() path and
// the hook turns the calling task's credentials into uid 0 before the path
// lookup happens.  Both the SDK runtime and the installed payloads use the same
// handshake, so this file implements it directly and verifies the result instead
// of trusting the syscall return value (the lookup itself still fails).
//
#pragma once

#include <string>

namespace maplesu::payload::webui {

// Returns 0 when the process holds uid 0 afterwards, otherwise the negative
// module error code the SDK maps this failure to (no root = -19968).
long long acquire_root(const char* root_key);

}  // namespace maplesu::payload::webui
