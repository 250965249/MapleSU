#include "module_err_def.h"
#include "module_base_kernel_mem.h"
#include "module_base_disk_storage.h"
#include <algorithm>
#include <cassert>
#include <cstdio>
#include <cstring>
#include <map>
#include <unordered_map>
#include <vector>

extern "C" int64_t test_write(const std::vector<std::string>&);
extern "C" int64_t test_add(const char*);
extern "C" int64_t test_remove(const char*);
extern "C" int64_t test_clear();
KModErr maplesu_store_su_retention(const void* data, uint64_t size) {
    return kernel_module::write_blob_disk_storage("uid_retention_budget.20261105", data, size);
}
static uint64_t control = 0x1000, live = 0x2000, retired = 0, allocated = 0;
static std::unordered_map<std::string, unsigned> mappings;
static std::map<uint64_t, std::vector<unsigned>> memory;
static std::string failure;
static int zeros = 0;
static bool saved = false;
static std::string scenario;
static std::map<std::string, std::vector<uint8_t>> blobs;

extern "C" const char* __get_current_module_root_key_hd04aBTnbSZlTRP7S4mQpIeVvr2ssGjW() { return "fixture"; }
namespace maplesu::sdk { KModErr get_root(const char*) { return KModErr::OK; } }
// File deployment is exercised by pro_su_execution_test.cpp, separately from
// the kernel-memory/storage fault injection in this fixture.
extern "C" KModErr maplesu_prepare_su_exec(const char*) { return KModErr::OK; }
namespace default_modules::module_su_redirect {
class SuAllowList {
public:
    bool load();
    std::vector<std::string> get_apps();
    bool add_app(const std::string&);
    bool remove_app(const std::string&);
    bool clear_app();
};
bool SuAllowList::load() { return scenario != "refresh_readfail"; }
std::vector<std::string> SuAllowList::get_apps() {
    if (scenario == "refresh_empty") return {};
    if (scenario.rfind("refresh_partial_", 0) == 0 || scenario == "refresh_boot_partial_pm_failure") return {"manager", "target"};
    return scenario == "revoke" || scenario == "revoke_persist" ? std::vector<std::string>{"manager", "target"} : std::vector<std::string>{"manager"};
}
bool SuAllowList::add_app(const std::string& p) { assert(p == "target"); if (failure == "persist") return false; saved = true; return true; }
bool SuAllowList::remove_app(const std::string&) { return scenario != "revoke_persist"; }
bool SuAllowList::clear_app() { return scenario != "clear_persist"; }
}

extern "C" FILE* __wrap_popen(const char* command, const char*) {
    assert(strstr(command, "list packages -U --user 0"));
    FILE* stream = tmpfile();
    if (scenario == "refresh_partial_fallback") fputs("package:manager uid:10371\npackage:target uid:10372\n", stream);
    else if (scenario == "refresh_fallback") fputs("package:manager uid:10371\n", stream);
    else if (scenario == "fallback") fputs("package:target uid:10372\npackage:other uid:19999\n", stream);
    else if (scenario == "bad_fallback") fputs("package:target uid:4294967296\n", stream);
    else if (scenario == "failed_fallback") fputs("package:target uid:10372\n", stream);
    rewind(stream);
    return stream;
}
extern "C" int __wrap_pclose(FILE* stream) { fclose(stream); return scenario == "failed_fallback" || scenario == "refresh_partial_pm_failure" || scenario == "refresh_boot_partial_pm_failure" ? 256 : 0; }

namespace android_pkgmap {
std::unordered_map<std::string, unsigned> read_pkg_uids_from_packages_list(
        const std::vector<std::string>& packages, const std::string&) {
    std::unordered_map<std::string, unsigned> result;
    for (const auto& p : packages) result[p] = mappings[p];
    return result;
}
}
namespace kernel_module {
KModErr read_uint64_disk_storage(const char* key, uint64_t& out) {
    out = std::string(key).find("next_free") == 0 ? retired : control;
    return KModErr::OK;
}
KModErr write_uint64_disk_storage(const char*, uint64_t value) {
    retired = value;
    return KModErr::OK;
}
KModErr read_blob_disk_storage_with_cb(const char* key, void (*cb)(const void*, uint64_t)) {
    const auto found = blobs.find(key);
    if (found == blobs.end()) return KModErr::ERR_MODULE_STORAGE_NOT_FOUND;
    const auto& out = found->second; cb(out.data(), out.size()); return KModErr::OK;
}
KModErr write_blob_disk_storage(const char* key, const void* data, uint64_t size) {
    const auto* bytes = static_cast<const uint8_t*>(data);
    blobs[key] = {bytes, bytes + size}; return KModErr::OK;
}
KModErr read_kernel_mem(uint64_t address, void* out, uint32_t size) {
    if (failure == "read") return KModErr::ERR_MODULE_PARAM;
    if (address == control) {
        assert(size == 8);
        std::memcpy(out, &live, 8);
    } else {
        const auto& block = *std::prev(memory.upper_bound(address));
        assert(address - block.first + size <= block.second.size() * 4);
        std::memcpy(out, reinterpret_cast<const uint8_t*>(block.second.data()) + address - block.first, size);
        if (failure == "corrupt") static_cast<unsigned*>(out)[0] ^= 1;
    }
    return KModErr::OK;
}
KModErr write_kernel_rw_mem_atomic64(uint64_t address, uint64_t value) {
    assert(address == control);
    if (failure == "publish" && value != 0) return KModErr::ERR_MODULE_PARAM;
    if (value == 0) ++zeros;
    live = value;
    return KModErr::OK;
}
KModErr alloc_kernel_mem(uint32_t size, uint64_t& out) {
    if (failure == "alloc") return KModErr::ERR_MODULE_ALLOC_MEM;
    out = allocated = 0x3000;
    memory[out].resize(size / 4);
    return KModErr::OK;
}
KModErr write_kernel_mem(uint64_t address, const void* data, uint32_t size, KernMemProt) {
    if (failure == "write") return KModErr::ERR_MODULE_PARAM;
    std::memcpy(memory[address].data(), data, size);
    return KModErr::OK;
}
KModErr free_kernel_mem(uint64_t address) {
    assert(address != live);
    memory.erase(address);
    return KModErr::OK;
}
}

int main(int argc, char** argv) {
    assert(argc == 2);
    std::string test = argv[1];
    scenario = test;
    mappings = {{"manager",10371}, {"target",10372}};
    memory[live] = {10371,0};
    std::vector<std::string> packages = {"manager","target"};
    if (test == "missing_uid" || test == "fallback" || test == "bad_fallback" || test == "failed_fallback") mappings["target"] = 0;
    else if (test == "all_missing") mappings.clear();
    else if (test == "stale") mappings["manager"] = 0;
    else if (test == "clear") packages.clear();
    else if (test == "duplicate") mappings["target"] = 10371;
    else if (test == "boot_missing") { mappings.clear(); live = 0; }
    else if (test == "refresh_missing") mappings.clear();
    else if (test == "refresh_existing") memory[live] = {10371,10372,0};
    else if (test == "refresh_empty") memory[live] = {10371,10372,0};
    else if (test == "refresh_fallback") mappings["manager"] = 0;
    else if (test == "refresh_unresolved") mappings.clear();
    else if (test == "refresh_boot_unresolved") { mappings.clear(); live = 0; }
    else if (test.rfind("refresh_partial_", 0) == 0) { mappings["target"] = 0; memory[live] = {10371,10372,0}; }
    else if (test == "refresh_boot_partial_pm_failure") { mappings["target"] = 0; live = 0; }
    else if (test == "refresh_readfail") {}
    else if (test == "revoke_persist" || test == "clear_persist") failure = "persist";
    else if (test == "revoke" || test == "clear_sdk") {}
    else if (test != "grant") failure = test;
    const int64_t result = test.rfind("refresh_", 0) == 0 && test != "refresh_missing" ? test_add(nullptr) :
        test == "revoke" || test == "revoke_persist" ? test_remove("target") :
        test == "clear_sdk" || test == "clear_persist" ? test_clear() :
        test == "clear" || test == "boot_missing" || test == "refresh_missing" ? test_write(packages) : test_add("target");
    const bool rejected = test == "missing_uid" || test == "all_missing" || test == "bad_fallback" || test == "failed_fallback" || test == "refresh_missing" || test == "refresh_unresolved" || test == "refresh_boot_unresolved" || test == "refresh_readfail" || test == "refresh_partial_pm_failure" || test == "refresh_boot_partial_pm_failure" || !failure.empty();
    bool pass;
    if (rejected) pass = result != 0 && live == ((test == "refresh_boot_unresolved" || test == "refresh_boot_partial_pm_failure") ? 0 : 0x2000);
    else if (test == "clear" || test == "clear_sdk" || test == "boot_missing" || test == "refresh_empty") pass = result == 0 && (live == 0 || memory[live] == std::vector<unsigned>{0});
    else {
        auto actual = memory[live];
        std::sort(actual.begin(), actual.end());
        pass = result == 0 && zeros == 0 && actual ==
            (test == "duplicate" || test == "revoke" || test == "refresh_existing" || test == "refresh_fallback" ? std::vector<unsigned>{0,10371} : test == "stale" ? std::vector<unsigned>{0,10372} : std::vector<unsigned>{0,10371,10372});
    }
    if (test == "refresh_partial_uninstalled") pass = result == 0 && memory[live] == std::vector<unsigned>{10371,0};
    if (test == "refresh_partial_pm_failure" || test == "refresh_boot_partial_pm_failure") {
        pass = pass && result == static_cast<int64_t>(KModErr::ERR_MODULE_SU_LIST_NOT_FOUND) && allocated == 0;
        if (test == "refresh_partial_pm_failure") pass = pass && memory[live] == std::vector<unsigned>{10371,10372,0};
    }
    if (test.rfind("refresh_", 0) == 0) pass = pass && !saved;
    if (rejected) pass = pass && !saved;
    if (rejected && allocated) pass = pass &&
        (failure == "persist" || failure == "publish" ? memory.count(allocated) == 1 : memory.count(allocated) == 0);
    std::printf("%s %s result=%lld live=%llx zero_publications=%d\n", pass ? "PASS" : "FAIL", argv[1],
                static_cast<long long>(result), static_cast<unsigned long long>(live), zeros);
    return pass ? 0 : 1;
}
