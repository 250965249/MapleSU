#include "module_err_def.h"
#include "module_base_kernel_mem.h"
#include <vector>
#include "maplesu_sdk/maplesu_su_auth.h"
#include <cassert>
#include <cstdio>
#include <sys/wait.h>
#include <unistd.h>

namespace default_modules::module_su_redirect { KModErr add_su_allowlist(const char*); }
extern "C" KModErr maplesu_write_su_allowlist(const std::vector<std::string>&, const char*, bool) { return KModErr::OK; }
extern "C" const char* __get_current_module_root_key_hd04aBTnbSZlTRP7S4mQpIeVvr2ssGjW() { return "fixture"; }
namespace maplesu::sdk { KModErr get_root(const char*) { return KModErr::OK; } }
extern "C" KModErr maplesu_prepare_su_exec(const char*) { return KModErr::OK; }
namespace kernel_module {
KModErr read_uint64_disk_storage(const char*, uint64_t& out) { out = 1; return KModErr::OK; }
KModErr read_kernel_mem(uint64_t, void* out, uint32_t) { *static_cast<uint64_t*>(out) = 2; return KModErr::OK; }
KModErr write_uint64_disk_storage(const char*, uint64_t) { return KModErr::OK; }
KModErr write_kernel_rw_mem_atomic64(uint64_t, uint64_t) { return KModErr::OK; }
}

static const char* state = "/data/adb/maplesu/counter-fixture";
extern "C" KModErr maplesu_sdk_add_su_allowlist(const char*) {
    // Deliberately race a load -> delay -> persist sequence. The production
    // transaction wrapper must serialize this complete body across processes.
    FILE* file = fopen(state, "r");
    unsigned value = 0;
    if (file) { assert(fscanf(file, "%u", &value) == 1); fclose(file); }
    usleep(10000);
    file = fopen(state, "w");
    assert(file);
    fprintf(file, "%u\n", value + 1);
    fclose(file);
    return KModErr::OK;
}
extern "C" KModErr maplesu_sdk_remove_su_allowlist(const char*) { return KModErr::OK; }
extern "C" KModErr maplesu_sdk_clear_su_allowlist() { return KModErr::OK; }
extern "C" KModErr maplesu_sdk_get_su_allowlist(void (*)(const maplesu::sdk::su_auth_item*)) { return KModErr::OK; }

int main() {
    // Populate the lock directory once, then reset only this fixture's counter.
    assert(default_modules::module_su_redirect::add_su_allowlist("initial") == KModErr::OK);
    assert(unlink(state) == 0);
    for (unsigned i = 0; i < 20; ++i) {
        const pid_t child = fork();
        assert(child >= 0);
        if (child == 0) _exit(is_failed(default_modules::module_su_redirect::add_su_allowlist("target")) ? 1 : 0);
    }
    for (unsigned i = 0; i < 20; ++i) {
        int status;
        assert(wait(&status) > 0 && WIFEXITED(status) && WEXITSTATUS(status) == 0);
    }
    FILE* file = fopen(state, "r");
    unsigned value = 0;
    assert(file && fscanf(file, "%u", &value) == 1);
    fclose(file);
    assert(value == 20);
    assert(unlink(state) == 0);
    puts("PASS 20 concurrent processes: no lost load/update/persist transactions");
}
