// Test the real C entry without linking any SDK OEM/root initializer.
#include "kernel_policy_gate.h"
#include <cassert>
#include <cstdio>
#include <cstring>
#include <stdexcept>
#include <string>
#include <sys/types.h>

extern "C" int maplesu_environment_policy_start(const char*);
namespace {
uid_t real_uid = 0, effective_uid = 0;
unsigned assigned = 0, opened = 0, prepared = 0;
unsigned failure = 0;
const char* expected_key = nullptr;
const std::string boot = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee";
void reset(unsigned error = 0) {
    real_uid = effective_uid = 0;
    assigned = opened = prepared = 0;
    failure = error;
}
}
extern "C" uid_t __wrap_getuid() { return real_uid; }
extern "C" uid_t __wrap_geteuid() { return effective_uid; }
extern "C" void __set_current_module_root_key_hd04aBTnbSZlTRP7S4mQpIeVvr2ssGjW(const char* key) {
    assert(key == expected_key);
    ++assigned;
}
namespace maplesu::module_policy {
Store::Store(int directory) : directory_(directory) {}
Store::~Store() = default;
Store Store::open(bool create) {
    assert(assigned == 1);
    if (!create) return Store(-1);
    ++opened;
    if (failure == 1) throw std::runtime_error("FIXTURE_OPEN");
    return Store(-1);
}
void Store::record_compatibility(const std::string& report) const noexcept {
    assert(report.find("result=failed reason=FIXTURE_") != std::string::npos);
}
std::string current_boot_id() {
    if (failure == 2) throw std::runtime_error("FIXTURE_BOOT_ID");
    return boot;
}
unsigned prepare_kernel_policy(Mode mode, bool allow_unverified) {
    assert(mode == Mode::Block);
    assert(!allow_unverified);
    ++prepared;
    if (failure == 3) throw std::runtime_error("FIXTURE_BACKEND");
    return 1;
}
BootState Store::prepare_boot(const std::string& id, unsigned (*prepare)(Mode, bool), bool supports_unverified) {
    assert(id == boot);
    assert(!supports_unverified);
    return {Mode::Block, prepare(Mode::Block, false), id};
}
}
int main() {
    unsigned tests = 0;
    for (unsigned length : {0U, 1U, 15U, 16U, 32U, 1023U, 1024U, 1025U}) {
        reset();
        std::string key(length, 'F'); expected_key = key.c_str();
        bool accepted = length >= 16 && length < 1024;
        assert(maplesu_environment_policy_start(expected_key) == (accepted ? 0 : 1));
        assert(assigned == unsigned(accepted) && opened == unsigned(accepted) && prepared == unsigned(accepted));
        ++tests;
    }
    reset(); expected_key = nullptr;
    assert(maplesu_environment_policy_start(nullptr) == 1 && assigned == 0); ++tests;
    std::string key(32, 'F'); expected_key = key.c_str();
    reset(); real_uid = 2000;
    assert(maplesu_environment_policy_start(expected_key) == 1 && assigned == 0); ++tests;
    reset(); effective_uid = 2000;
    assert(maplesu_environment_policy_start(expected_key) == 1 && assigned == 0); ++tests;
    for (unsigned stage : {1U, 2U, 3U}) {
        reset(stage);
        assert(maplesu_environment_policy_start(expected_key) == 3);
        assert(assigned == 1 && opened == 1 && prepared == unsigned(stage == 3));
        ++tests;
    }
    printf("PASS %u environment policy credential/entry cases\n", tests);
}
