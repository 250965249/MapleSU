#include "kernel_policy_gate.h"
#include "kernel_module_kit_umbrella.h"
#include <cassert>
#include <cstdio>
#include <stdexcept>
#include <string>
#include <vector>

using namespace maplesu::module_policy;
namespace {
std::vector<std::string> events;
bool hide_supported = false, cancel_error = false;
unsigned hide_probes = 0, hide_preparations = 0;
void reset() {
    events.clear();
    hide_supported = cancel_error = false;
    hide_probes = hide_preparations = 0;
}
bool fails(Mode mode, const std::string& part) {
    try { (void)prepare_kernel_policy(mode); }
    catch (const std::runtime_error& e) { return std::string(e.what()).find(part) != std::string::npos; }
    return false;
}
}
#ifdef MAPLESU_POLICY_HIDE_PAYLOAD
namespace maplesu::module_policy {
void cancel_hidden_kernel_policy() { if (cancel_error) throw std::runtime_error("CANCEL_TRANSPORT"); }
bool hidden_kernel_policy_supported() { ++hide_probes; return hide_supported; }
unsigned prepare_hidden_kernel_policy(bool allow_unverified) {
    ++hide_preparations;
    if (!hide_supported && !allow_unverified) throw std::runtime_error("HIDE_UNSUPPORTED");
    return 3;
}
}
#endif
namespace kernel_module {
KModErr kallsyms_lookup_name(const char*, uint64_t&) {
    events.push_back("lookup");
    return KModErr::ERR_MODULE_SYMBOL_NOT_EXIST;
}
KModErr read_kernel_mem(uint64_t, void*, uint32_t) {
    events.push_back("read");
    return KModErr::ERR_MODULE_PARAM;
}
KModErr install_kernel_function_before_hook(uint64_t, const std::vector<uint8_t>&, HookHandle*) {
    events.push_back("install");
    return KModErr::ERR_MODULE_PARAM;
}
}
int main() {
    unsigned tests = 0;
    reset();
    assert(prepare_kernel_policy(Mode::Load) == 1 && events.empty()); ++tests;
    reset();
    assert(prepare_kernel_policy(Mode::Block) == 1 && events.empty() && hide_preparations == 0); ++tests;
    reset();
    assert(fails(Mode::Hide, "HIDE_UNSUPPORTED") && events.empty()); ++tests;
#ifdef MAPLESU_POLICY_HIDE_PAYLOAD
    reset(); hide_supported = true;
    assert(prepare_kernel_policy(Mode::Load) == 3 && events.empty() && hide_probes == 1 && hide_preparations == 0); ++tests;
    reset(); hide_supported = true;
    assert(prepare_kernel_policy(Mode::Block) == 3 && events.empty() && hide_probes == 1 && hide_preparations == 0); ++tests;
    reset(); hide_supported = true;
    assert(prepare_kernel_policy(Mode::Hide) == 3 && events.empty() && hide_probes == 0 && hide_preparations == 1); ++tests;
    reset();
    assert(prepare_kernel_policy(Mode::Hide, true) == 3 && events.empty() && hide_probes == 0 && hide_preparations == 1); ++tests;
    reset();
    assert(prepare_kernel_policy(Mode::Load, true) == 1 && hide_preparations == 0); ++tests;
    for (auto mode : {Mode::Load, Mode::Block}) {
        reset(); cancel_error = true;
        assert(fails(mode, "CANCEL_TRANSPORT") && events.empty() && hide_probes == 0 && hide_preparations == 0); ++tests;
    }
#endif
    reset();
    assert(fails(static_cast<Mode>(2), "UNSUPPORTED") && events.empty()); ++tests;
    printf("PASS %u kernel gate mode/scope fixture cases\n", tests);
}
