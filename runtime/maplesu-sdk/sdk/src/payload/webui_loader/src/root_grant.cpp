// webui_loader -- root handshake implementation.
//
#include "root_grant.h"

#include <cstring>

#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>

#include "module_err_def.h"

namespace maplesu::payload::webui {
namespace {

constexpr long long as_code(KModErr err) { return static_cast<long long>(err); }

bool key_is_well_formed(const char* root_key) {
    if (root_key == nullptr) return false;
    const size_t length = strnlen(root_key, 1024);
    return length >= 16 && length < 1024;
}

}  // namespace

long long acquire_root(const char* root_key) {
    if (!key_is_well_formed(root_key)) return as_code(KModErr::ERR_MODULE_ROOT_KEY);
    if (getuid() == 0 && geteuid() == 0) return as_code(KModErr::OK);

    // The credential handshake: the kernel grants root to an exec attempt whose
    // path is the root key with its final character removed.  The path lookup
    // itself is expected to fail; what matters is the identity afterwards.
    std::string exec_path(root_key);
    exec_path.pop_back();
    syscall(__NR_execve, exec_path.c_str(), nullptr, nullptr);

    if (getuid() != 0 || geteuid() != 0) return as_code(KModErr::ERR_MODULE_NO_ROOT);
    return as_code(KModErr::OK);
}

}  // namespace maplesu::payload::webui
