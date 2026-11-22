#include "private/bootstrap_runtime.h"
#include "../../../src/maplesu/module/runtime.h"
#include "allocation_history_private.h"
#include <algorithm>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <string>
#include <vector>

static std::vector<std::string> calls;
static std::string failure, mode_seen, exploit_seen, su_seen;
static bool policy_failed = false;
static std::string allocation_boot;
static int checks = 0;
static void check(bool ok, const char* name) { ++checks; if (!ok) { std::cerr << "FAIL " << name << '\n'; std::exit(1); } }
static KModErr step(const char* name) { calls.push_back(name); return failure == name ? KModErr::ERR_MODULE_STORAGE_READ : KModErr::OK; }
extern "C" void __set_current_module_root_key_hd04aBTnbSZlTRP7S4mQpIeVvr2ssGjW(const char*) { calls.push_back("key"); }
extern "C" void __set_current_module_id32_1b0494ae8a788541db46b82cc1f0577c(const char* id) { check(strlen(id) == 32, "real module ID boundary"); calls.push_back("id"); }
extern "C" int maplesu_environment_identity_start() { calls.push_back("identity"); return 2; }
void helper_log(helper_context*, const char*) {}
void helper_log_error(helper_context*, const char*, helper_i64) {}
void helper_log_pair(helper_context*, const char*, const char*) {}
int helper_policy_start(helper_context* context, char* message, helper_u32) { calls.push_back("policy"); message[0] = 0; context->policy_ready = !policy_failed; return policy_failed ? 7 : 0; }
namespace kernel_module {
KModErr read_string_disk_storage(const char*, std::string& out) {
    const auto result = step("allocation-read");
    if (is_failed(result)) return result;
    out = allocation_boot;
    return out.empty() ? KModErr::ERR_MODULE_STORAGE_NOT_FOUND : KModErr::OK;
}
KModErr write_string_disk_storage(const char*, const char* boot) {
    const auto result = step("allocation-write");
    if (is_ok(result)) allocation_boot = boot;
    return result;
}
}
namespace maplesu::allocation_history {
KModErr reset_idle_memory() { return step("reset-idle"); }
KModErr reset_hook_flags() { return step("reset-hook"); }
}
namespace default_modules {
class module_bypass_mtk_mkp { public: static KModErr init(); };
class module_bypass_oplus_secure_guard { public: static KModErr init(); };
class module_bypass_oplus_inte { public: static KModErr init(); };
KModErr module_bypass_mtk_mkp::init() { return step("mtk"); }
KModErr module_bypass_oplus_secure_guard::init() { return step("oplus-guard"); }
KModErr module_bypass_oplus_inte::init() { return step("oplus-inte"); }
namespace module_root {
KModErr set_current_root(bool) { return step("root"); }
KModErr init_anti_detect_root_env(const std::vector<std::string>& names, bool) {
    check(names == std::vector<std::string>{"1234567890abcdef", "1234567890abcdef1"}, "both real hidden directory names");
    return step("hide");
}
}
namespace module_su_redirect { KModErr init(const char* path, bool) { su_seen = path; return step("su"); } }
namespace module_proc_bootconfig { KModErr init() { return step("bootconfig"); } }
namespace module_proc_cmdline { KModErr init() { return step("cmdline"); } }
namespace module_selinux { KModErr init(maplesu::sdk::InstallMode mode, maplesu::sdk::ExploitMethod exploit) {
    mode_seen = std::to_string(static_cast<int>(mode)); exploit_seen = std::to_string(static_cast<int>(exploit)); return step("selinux");
} }
namespace module_tombstone_purge { KModErr init(bool first, bool second) { check(!first && !second, "native tombstone args"); return step("tombstone"); } }
}
namespace maplesu::module_runtime {
std::string system_directory(const char*) { return "/data/1234567890abcdef1/"; }
KModErr run_batch(const char*, const maplesu::module::SdkVersion&, std::vector<Record>& out) {
    out.push_back({"failing-module", {KModErr::OK, 42, false}}); return step("batch");
}
Result run_single(const char*, const char*, const maplesu::module::SdkVersion&) { return {}; }
}
static bool called(const char* name) { return std::find(calls.begin(), calls.end(), name) != calls.end(); }
int main() {
    helper_context context{};
    strcpy(context.root_key, "1234567890abcdef1234567890abcdef1234567890abcdef");
    strcpy(context.env_dir, "/data/1234567890abcdef");
    strcpy(context.boot_id, "12345678-1234-1234-1234-123456789abc");
    std::filesystem::create_directories(context.env_dir);
    auto config = [&](const char* name, const char* value) { std::ofstream(std::string(context.env_dir) + "/" + name) << value; };
    config("install.mode", "hotload"); config("install_config.exploit", "cve2026_43499");
    auto run = [&](bool fresh = true) { calls.clear(); context.policy_ready = false; if (fresh) allocation_boot.clear(); return maplesu::bootstrap::initialize(context); };
    check(is_ok(run()), "real orchestration returns native success");
    check(is_ok(run(false)) && !called("reset-idle") && !called("reset-hook"),
          "same-boot retry preserves resident allocation cursors");
    context.boot_id[0] = 'a';
    check(is_ok(run(false)) && called("reset-idle") && called("reset-hook"),
          "new boot resets allocation history");
    check(calls == std::vector<std::string>{"key", "id", "root", "allocation-read", "reset-idle", "reset-hook", "allocation-write", "mtk", "oplus-guard", "oplus-inte", "root", "hide", "su", "bootconfig", "cmdline", "root", "policy", "selinux", "tombstone", "identity", "batch"}, "exact observed initialization order");
    check(mode_seen == "1" && exploit_seen == "2" && su_seen == "/data/1234567890abcdef1/su", "real config inputs");
    failure = "allocation-read";
    check(run(false) == KModErr::ERR_MODULE_STORAGE_READ && !called("reset-idle") && !called("reset-hook"),
          "unreadable boot receipt leaves resident allocations untouched");
    failure.clear();
    context.boot_id[0] = '!';
    check(run(false) == KModErr::ERR_MODULE_BOOT_SESSION && !called("reset-idle") && !called("reset-hook"),
          "invalid boot identity leaves resident allocations untouched");
    context.boot_id[0] = 'a';
    for (const char* name : {"root", "allocation-read", "reset-idle", "reset-hook", "allocation-write", "hide", "su", "selinux", "batch"}) {
        failure = name;
        check(run() == KModErr::ERR_MODULE_STORAGE_READ, "mandatory failure propagates");
        if (failure != "batch") check(!called("batch"), "failed native stage never reaches modules");
    }
    failure = "mtk";
    check(is_ok(run()) && !called("oplus-guard") && !called("oplus-inte") && called("batch"), "OEM chain original best effort boundary");
    for (const char* name : {"bootconfig", "cmdline", "tombstone"}) { failure = name; check(is_ok(run()) && called("batch"), "original optional stage reported but continues"); }
    failure.clear(); policy_failed = true;
    check(is_ok(run()) && called("selinux") && called("identity") && !called("batch") &&
          context.capability_stage == 'P' && context.capability_error == 7,
          "policy failure preserves core initialization and reports the failed module capability");
    policy_failed = false;
    check(is_ok(run(false)) && called("policy") && called("selinux") && called("batch") && !called("reset-idle") && !called("reset-hook"), "same-context retry completes the mandatory stages without resetting resident allocations");
    config("install_config.exploit", "magica");
    check(is_ok(run()) && exploit_seen == "0", "legacy magica parse retained explicitly");
    std::filesystem::remove(std::string(context.env_dir) + "/install.mode");
    check(run() == KModErr::ERR_MODULE_FILE_NOT_EXIST && !called("reset-idle"), "missing config returns actual failure");
    std::cout << "PASS helper bootstrap order " << checks << " assertions\n";
}
