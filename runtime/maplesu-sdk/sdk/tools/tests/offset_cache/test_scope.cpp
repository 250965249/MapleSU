// Link the actual cache TU; identity/PID are controlled, filesystem fixtures stay real.
#include "kernel_module_kit_umbrella.h"
#include <array>
#include <atomic>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <new>
#include <string>
#include <sys/wait.h>
#include <thread>
#include <unistd.h>

namespace kernel_module {
KModErr get_offset_cache(const char*, uint32_t&);
KModErr put_offset_cache(const char*, uint32_t);
}
namespace {
thread_local std::string module = "offset-cache-module", root_key(48, 'K');
thread_local bool null_module = false, null_key = false, fail_allocation = false;
thread_local pid_t process_override = 0;
std::atomic<unsigned> checks{0}, failures{0};
void check(bool ok, const char* message) {
    ++checks;
    if (!ok) { ++failures; std::fprintf(stderr, "FAIL %s\n", message); }
}
void miss(const char* name) {
    uint32_t value = 0xabcdef01;
    check(kernel_module::get_offset_cache(name, value) == KModErr::ERR_MODULE_OFFSET_CACHE_NOT_FOUND &&
          value == 0xabcdef01, "cache miss preserves caller output");
}
void hit(const char* name, uint32_t expected) {
    uint32_t value = ~expected;
    check(kernel_module::get_offset_cache(name, value) == KModErr::OK && value == expected,
          "same-scope value is preserved");
}
}
extern "C" const char* __get_current_module_id32_1b0494ae8a788541db46b82cc1f0577c() {
    return null_module ? nullptr : module.c_str();
}
extern "C" const char* __get_current_module_root_key_hd04aBTnbSZlTRP7S4mQpIeVvr2ssGjW() {
    return null_key ? nullptr : root_key.c_str();
}
extern "C" pid_t __real_getpid();
extern "C" pid_t __wrap_getpid() { return process_override ? process_override : __real_getpid(); }
extern "C" void* __real__Znwm(size_t);
extern "C" void* __wrap__Znwm(size_t size) {
    if (fail_allocation) { fail_allocation = false; throw std::bad_alloc(); }
    return __real__Znwm(size);
}

int main() {
    using namespace kernel_module;
    for (uint32_t value : {0u, 1u, UINT32_MAX}) {
        check(put_offset_cache("value", value) == KModErr::OK, "optional put succeeds");
        hit("value", value);
    }
    root_key[47] = 'Z'; miss("value");
    check(put_offset_cache("value", 41) == KModErr::OK, "new Key scope stores"); hit("value", 41);
    root_key[47] = 'K'; miss("value"); // Returning to an old identity never revives its map.
    check(put_offset_cache("value", 42) == KModErr::OK, "current scope stores");
    module[0] = 'Z'; miss("value"); module[0] = 'o'; miss("value");
    check(put_offset_cache("value", 43) == KModErr::OK, "new module scope stores");
    process_override = __real_getpid() + 1; miss("value");
    check(put_offset_cache("value", 44) == KModErr::OK, "new PID scope stores");
    process_override = 0; miss("value");

    for (unsigned invalid = 0; invalid < 6; ++invalid) {
        root_key.assign(48, 'K'); module = "offset-cache-module";
        check(put_offset_cache("value", 45) == KModErr::OK, "scope before invalid identity stores");
        if (invalid == 0) null_key = true;
        if (invalid == 1) null_module = true;
        if (invalid == 2) root_key.clear();
        if (invalid == 3) module.clear();
        if (invalid == 4) root_key.assign(1024, 'K');
        if (invalid == 5) module.assign(1024, 'M');
        miss("value");
        check(put_offset_cache("value", 46) == KModErr::OK, "missing cache identity does not fail discovery");
        null_key = null_module = false; root_key.assign(48, 'K'); module = "offset-cache-module";
        miss("value");
    }
    root_key.assign(1023, 'K'); module.assign(1023, 'M');
    check(put_offset_cache("max-identity", 47) == KModErr::OK, "existing maximum identity length retained");
    hit("max-identity", 47);
    uint32_t out = 88;
    check(get_offset_cache(nullptr, out) == KModErr::ERR_MODULE_PARAM && out == 88,
          "null cache name has explicit error without changing output");
    check(put_offset_cache("", 1) == KModErr::ERR_MODULE_PARAM, "empty cache name remains invalid");

    std::array<char, 96> long_name{}; long_name.fill('L'); long_name.back() = 0;
    fail_allocation = true;
    check(put_offset_cache(long_name.data(), 48) == KModErr::OK && !fail_allocation,
          "allocation failure drops optional cache without failing discovery");
    miss(long_name.data());
    check(put_offset_cache(long_name.data(), 49) == KModErr::OK, "cache works after allocation failure");
    fail_allocation = true;
    check(get_offset_cache(long_name.data(), out) == KModErr::ERR_MODULE_OFFSET_CACHE_NOT_FOUND &&
          out == 88 && !fail_allocation, "lookup allocation failure is a miss");
    hit(long_name.data(), 49);

    root_key.assign(48, 'a'); module = "legacy-cache-fixture";
    const auto legacy = std::filesystem::path("/data/aaaaaaaaaaaaaaaaa/offset_cache/legacy-cache-fixture/value");
    std::filesystem::create_directories(legacy.parent_path());
    const uint32_t disk_value = 0x12345678;
    { std::ofstream file(legacy, std::ios::binary); file.write(reinterpret_cast<const char*>(&disk_value), 4); }
    miss("value");
    check(put_offset_cache("value", 50) == KModErr::OK, "old files never block current discovery"); hit("value", 50);
    uint32_t preserved = 0;
    { std::ifstream file(legacy, std::ios::binary); file.read(reinterpret_cast<char*>(&preserved), 4); }
    check(preserved == disk_value && std::filesystem::file_size(legacy) == 4,
          "cache never reads, overwrites or deletes legacy file");

    check(put_offset_cache("fork-value", 51) == KModErr::OK, "parent fork fixture stores");
    const pid_t child = fork();
    if (child == 0) {
        uint32_t value = 77;
        const bool ok = get_offset_cache("fork-value", value) == KModErr::ERR_MODULE_OFFSET_CACHE_NOT_FOUND &&
            value == 77 && put_offset_cache("fork-value", 52) == KModErr::OK &&
            get_offset_cache("fork-value", value) == KModErr::OK && value == 52;
        _exit(ok ? 0 : 1);
    }
    int status = 0;
    check(child > 0 && waitpid(child, &status, 0) == child && WIFEXITED(status) && WEXITSTATUS(status) == 0,
          "real fork child ignores inherited cache and can recompute");
    hit("fork-value", 51);
    const pid_t nonroot = fork();
    if (nonroot == 0) {
        uint32_t value = 0;
        const bool ok = setuid(1000) == 0 && getuid() == 1000 &&
            put_offset_cache("nonroot", 53) == KModErr::OK &&
            get_offset_cache("nonroot", value) == KModErr::OK && value == 53;
        _exit(ok ? 0 : 1);
    }
    status = 0;
    check(nonroot > 0 && waitpid(nonroot, &status, 0) == nonroot && WIFEXITED(status) && WEXITSTATUS(status) == 0,
          "nonroot runtime caching requires no writable private directory or SELinux change");

    std::array<std::thread, 4> workers;
    for (unsigned index = 0; index < workers.size(); ++index) workers[index] = std::thread([index] {
        module = "same-thread-fixture"; root_key.assign(48, 'T');
        miss("shared-name");
        check(put_offset_cache("shared-name", index) == KModErr::OK, "thread local put");
        for (unsigned n = 0; n < 8; ++n) hit("shared-name", index);
    });
    for (auto& worker : workers) worker.join();
    std::printf("offset-cache-scope: %u checks, %u failures\n", checks.load(), failures.load());
    return failures ? 1 : 0;
}
