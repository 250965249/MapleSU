#include "module_err_def.h"
#include "module_base_disk_storage.h"
#include <cstdint>
#include <string>
#include <vector>
#include <cstring>
#include <unistd.h>

extern "C" void __set_current_module_root_key_hd04aBTnbSZlTRP7S4mQpIeVvr2ssGjW(const char*);
extern "C" void __set_current_module_id32_1b0494ae8a788541db46b82cc1f0577c(const char*);
extern "C" KModErr maplesu_write_su_allowlist(const std::vector<std::string>&, const char*, bool);
extern "C" KModErr maplesu_prepare_su_exec(const char*);
extern "C" KModErr maplesu_freeze_su_copies(const char*);
extern "C" KModErr maplesu_open_su_copies_from_control(const char*, uint64_t);
extern "C" void maplesu_thaw_su_copies();

namespace default_modules { namespace module_su_redirect {
class PatchDoExecve {
public:
    KModErr patch_do_execve(uint64_t);
};
}}

namespace {
bool context(const char* key, const char* module) {
    if (getuid() != 0 || geteuid() != 0 || !key || !module ||
        strnlen(key, 49) != 48 || strnlen(module, 33) != 32) return false;
    __set_current_module_root_key_hd04aBTnbSZlTRP7S4mQpIeVvr2ssGjW(key);
    __set_current_module_id32_1b0494ae8a788541db46b82cc1f0577c(module);
    return true;
}
struct BootDelivery {
    const char* key;
    bool opened = false;
    ~BootDelivery() {
        if (!opened) {
            try { (void)maplesu_freeze_su_copies(key); } catch (...) { }
        }
        maplesu_thaw_su_copies();
    }
};
}

extern "C" __attribute__((visibility("default")))
int64_t maplesu_helper_su_write(const void* packages, const char* key, const char* module) {
    if (!packages || !context(key, module)) return static_cast<int64_t>(KModErr::ERR_MODULE_PARAM);
    BootDelivery delivery{key};
    try {
        auto error = maplesu_prepare_su_exec(key);
        if (is_failed(error)) return static_cast<int64_t>(error);
        error = maplesu_freeze_su_copies(key);
        if (is_failed(error)) return static_cast<int64_t>(error);
        error = maplesu_write_su_allowlist(*static_cast<const std::vector<std::string>*>(packages), nullptr, false);
        if (is_failed(error)) return static_cast<int64_t>(error);
        uint64_t control = 0;
        error = kernel_module::read_uint64_disk_storage(
            "uid_control_kaddr.e842572c094b847aed9d11840a807b46", control);
        if (is_failed(error)) return static_cast<int64_t>(error);
        error = maplesu_open_su_copies_from_control(key, control);
        delivery.opened = !is_failed(error);
        return static_cast<int64_t>(error);
    } catch (...) {
        return static_cast<int64_t>(KModErr::ERR_MODULE_OPEN_FILE);
    }
}

extern "C" __attribute__((visibility("default")))
int64_t maplesu_helper_su_exec(void* object, uint64_t control, const char* key, const char* module) {
    if (!object || !control || !context(key, module)) return static_cast<int64_t>(KModErr::ERR_MODULE_PARAM);
    try {
        return static_cast<int64_t>(static_cast<default_modules::module_su_redirect::PatchDoExecve*>(object)
            ->patch_do_execve(control));
    } catch (...) {
        return static_cast<int64_t>(KModErr::ERR_MODULE_OPEN_FILE);
    }
}
