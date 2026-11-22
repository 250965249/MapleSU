// Exercise Block and Load with a kernel that has no optional policy symbols.
// Hiding is off: symbol availability must not change the original policy path.
#include "kernel_policy_gate.h"
#include "kernel_module_kit_umbrella.h"
#include <cassert>
#include <cstdio>
#include <exception>

namespace {
unsigned kernel_operations = 0, hide_preparations = 0, probes = 0;
bool hide_available = false;
}
namespace kernel_module {
KModErr kallsyms_lookup_name(const char*, uint64_t&) {
    ++kernel_operations;
    return KModErr::ERR_MODULE_SYMBOL_NOT_EXIST;
}
KModErr read_kernel_mem(uint64_t, void*, uint32_t) {
    ++kernel_operations;
    return KModErr::ERR_MODULE_PARAM;
}
KModErr install_kernel_function_before_hook(uint64_t, const std::vector<uint8_t>&, HookHandle*) {
    ++kernel_operations;
    return KModErr::ERR_MODULE_PARAM;
}
}
#ifdef MAPLESU_POLICY_HIDE_PAYLOAD
namespace maplesu::module_policy {
void cancel_hidden_kernel_policy() {}
bool hidden_kernel_policy_supported() { ++probes; return hide_available; }
unsigned prepare_hidden_kernel_policy(bool) { ++hide_preparations; return 3; }
}
#endif
int main() {
    unsigned cases = 0;
    for (auto mode : {maplesu::module_policy::Mode::Block, maplesu::module_policy::Mode::Load})
    for (bool available : {false, true}) {
        kernel_operations = hide_preparations = probes = 0;
        hide_available = available;
        unsigned expected = 1;
#ifdef MAPLESU_POLICY_HIDE_PAYLOAD
        if (available) expected = 3;
#endif
        try {
            assert(maplesu::module_policy::prepare_kernel_policy(mode) == expected);
        } catch (const std::exception& error) {
            fprintf(stderr, "FAIL hiding disabled changed native startup: %s\n", error.what());
            return 1;
        }
        assert(kernel_operations == 0 && hide_preparations == 0);
        assert(probes ==
#ifdef MAPLESU_POLICY_HIDE_PAYLOAD
            1
#else
            0
#endif
        );
        ++cases;
    }
    printf("PASS %u hiding-disabled native-policy passthrough cases\n", cases);
}
