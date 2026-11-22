#include "module_err_def.h"
#include "module_base_disk_storage.h"
#include <cassert>
#include <algorithm>
#include <cstdint>
#include <string>
#include <vector>
#include <iostream>

namespace default_modules::module_su_redirect {
class PatchDoExecve { public: KModErr patch_do_execve(uint64_t); uint64_t seen = 0; };
}
extern "C" int64_t maplesu_helper_su_write(const void*, const char*, const char*);
extern "C" int64_t maplesu_helper_su_exec(void*, uint64_t, const char*, const char*);
static int checks = 0, failure = 0;
static std::vector<std::string> calls, captured;
static const char key[] = "1234567890abcdef1234567890abcdef1234567890abcdef";
static const char id[] = "0123456789abcdefghijklmnopqrstuv";
static uint64_t seen_control = 0;
static void check(bool ok) { ++checks; if (!ok) std::exit(1); }
static KModErr stage(const char* name, int at) { calls.push_back(name); return failure == at ? KModErr::ERR_MODULE_STORAGE_READ : KModErr::OK; }
extern "C" void __set_current_module_root_key_hd04aBTnbSZlTRP7S4mQpIeVvr2ssGjW(const char* v) { check(v == key); }
extern "C" void __set_current_module_id32_1b0494ae8a788541db46b82cc1f0577c(const char* v) { check(v == id); }
extern "C" KModErr maplesu_prepare_su_exec(const char*) { return stage("prepare", 1); }
extern "C" KModErr maplesu_freeze_su_copies(const char*) { return stage("freeze", 2); }
extern "C" KModErr maplesu_write_su_allowlist(const std::vector<std::string>& packages, const char*, bool) { captured = packages; return stage("publish", 3); }
namespace kernel_module {
KModErr read_uint64_disk_storage(const char*, uint64_t& out) { out = 0xffff000012345678ULL; return stage("control", 4); }
}
extern "C" KModErr maplesu_open_su_copies_from_control(const char*, uint64_t control) { seen_control = control; return stage("open", 5); }
extern "C" void maplesu_thaw_su_copies() { calls.push_back("thaw"); }
KModErr default_modules::module_su_redirect::PatchDoExecve::patch_do_execve(uint64_t control) { seen = control; return stage("patch", 6); }
int main() {
    std::vector<std::string> packages{"com.example.one", std::string(200, 'a') + ".app"};
    check(maplesu_helper_su_write(&packages, key, id) == 0);
    check(captured == packages && seen_control == 0xffff000012345678ULL);
    check(calls == std::vector<std::string>{"prepare", "freeze", "publish", "control", "open", "thaw"});
    for (int fail = 1; fail <= 5; ++fail) {
        failure = fail; calls.clear();
        check(maplesu_helper_su_write(&packages, key, id) == static_cast<int64_t>(KModErr::ERR_MODULE_STORAGE_READ));
        check(calls.size() >= 3 && calls[calls.size() - 2] == "freeze" && calls.back() == "thaw");
        check(std::find(calls.begin(), calls.end(), "open") == calls.end() || fail == 5);
    }
    failure = 0; packages.clear();
    check(maplesu_helper_su_write(&packages, key, id) == 0 && captured.empty());
    default_modules::module_su_redirect::PatchDoExecve object;
    check(maplesu_helper_su_exec(&object, 0xffffabcd12345678ULL, key, id) == 0);
    check(object.seen == 0xffffabcd12345678ULL);
    failure = 6;
    check(maplesu_helper_su_exec(&object, 0x100000000ULL, key, id) == static_cast<int64_t>(KModErr::ERR_MODULE_STORAGE_READ));
    check(maplesu_helper_su_write(nullptr, key, id) == static_cast<int64_t>(KModErr::ERR_MODULE_PARAM));
    check(maplesu_helper_su_exec(nullptr, 0x100000000ULL, key, id) == static_cast<int64_t>(KModErr::ERR_MODULE_PARAM));
    check(maplesu_helper_su_exec(&object, 0, key, id) == static_cast<int64_t>(KModErr::ERR_MODULE_PARAM));
    std::cout << "PASS helper original ABI " << checks << " assertions\n";
}
