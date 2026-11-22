#include "kernel_policy_gate.h"
#include <cstdio>
#include <cstring>
#include <exception>
#include <unistd.h>

// Retain the SDK's existing C ABI without rerunning its OEM/root initializers.
extern "C" void __set_current_module_root_key_hd04aBTnbSZlTRP7S4mQpIeVvr2ssGjW(const char*);

// An environment-owned synchronous entry, not a user module or an app probe.
// The bootstrap calls it before native SELinux setup. A preparation failure
// cancels hiding and preserves ordinary loading when the user allowed it;
// unrecoverable configuration errors still leave SDK setup and Identity intact.
extern "C" __attribute__((visibility("default")))
int maplesu_environment_policy_start(const char* key) {
    if (getuid() != 0 || geteuid() != 0 || !key) return 1;
    const auto length = strnlen(key, 1024);
    if (length < 16 || length == 1024) return 1;
    __set_current_module_root_key_hd04aBTnbSZlTRP7S4mQpIeVvr2ssGjW(key);
    try {
        auto store = maplesu::module_policy::Store::open(true);
        store.prepare_boot(maplesu::module_policy::current_boot_id(),
                           maplesu::module_policy::prepare_kernel_policy,
#ifdef MAPLESU_POLICY_HIDE_PAYLOAD
                           true
#else
                           false
#endif
        );
        return 0;
    } catch (const std::exception& error) {
        // Reasons contain fixed operation/symbol names, never the credential.
        fprintf(stderr, "MapleSU module policy preparation failed: %s\n", error.what());
        try {
            maplesu::module_policy::Store::open(false).record_compatibility(
                "schema=1 operation=boot-preparation boot=" + maplesu::module_policy::current_boot_id() +
                "\nresult=failed reason=" + error.what() + "\nEND\n");
        } catch (...) { }
        return 3;
    }
}
