// Device-only read preflight. The key is supplied on stdin, never argv/logs.
#include "kernel_payload_loader.h"
#include "kernel_module_kit_umbrella.h"
#include <cstdio>
#include <cstring>
#include <exception>
#include <unistd.h>

extern "C" void __set_current_module_root_key_hd04aBTnbSZlTRP7S4mQpIeVvr2ssGjW(const char*);

int main() {
    char key[1024]{};
    if (!fgets(key, sizeof(key), stdin)) return 2;
    auto length = strcspn(key, "\r\n");
    if (length < 16 || length >= sizeof(key) - 1) return 2;
    key[length] = 0;
    if (geteuid() && is_failed(maplesu::sdk::get_root(key))) return 3;
    __set_current_module_root_key_hd04aBTnbSZlTRP7S4mQpIeVvr2ssGjW(key);
    try {
        auto capabilities = maplesu::module_policy::preflight_hidden_kernel_policy();
        puts(capabilities == 3 ? "{\"preflight\":true,\"capabilities\":3,\"hookInstalled\":false}" :
                                "{\"preflight\":false,\"hookInstalled\":false}");
        return capabilities == 3 ? 0 : 4;
    } catch (const std::exception& error) {
        // Only fixed SDK/loader error identifiers are emitted, never input.
        fprintf(stderr, "%s\n", error.what());
        return 5;
    }
}
