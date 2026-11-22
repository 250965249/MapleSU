#include "fixture_config.h"
#include <cerrno>
#include <cstring>
#include <sys/stat.h>
#include <unistd.h>

namespace fixture {
std::string key = "0123456789abcdefghijklmnop";
KModErr root_result = KModErr::OK, reset_result = KModErr::OK, install_result = KModErr::OK;
bool fail_chmod = false, fail_label = false, label_contract_ok = true;
unsigned chmod_calls = 0, label_calls = 0;
}
extern "C" const char* __get_current_module_root_key_hd04aBTnbSZlTRP7S4mQpIeVvr2ssGjW() {
    return fixture::key.c_str();
}
extern "C" KModErr maplesu_lock_module_root(bool) { return fixture::root_result; }
extern "C" [[noreturn]] void maplesu_module_worker_exit(int status) { _exit(status); }
namespace default_modules::module_root {
KModErr set_current_root(bool) { return fixture::root_result; }
}
extern "C" int __real_chmod(const char*, mode_t);
extern "C" int __wrap_chmod(const char* path, mode_t mode) {
    ++fixture::chmod_calls;
    if (fixture::fail_chmod) { errno = EACCES; return -1; }
    return __real_chmod(path, mode);
}
extern "C" int __wrap_setxattr(const char*, const char* name, const void* value, size_t size, int flags) {
    ++fixture::label_calls;
    const char* context = static_cast<const char*>(value);
    fixture::label_contract_ok &= !strcmp(name, "security.selinux") && flags == 0
        && size == strlen(context) + 1
        && (!strcmp(context, "u:object_r:kernel:s0") || !strcmp(context, "u:object_r:system_file:s0"));
    if (fixture::fail_label) { errno = EACCES; return -1; }
    return 0;  // Android file-label operation is the only simulated OS boundary.
}
