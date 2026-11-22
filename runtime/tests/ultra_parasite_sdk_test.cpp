// Executes the production worker/transaction with fixture process and package data.
#include "maplesu_parasite.h"
#include "module_err_def.h"
#include "maplesu_sdk/maplesu_root.h"
#include "maplesu_sdk/maplesu_su_auth.h"
#include <cassert>
#include <chrono>
#include <cerrno>
#include <csignal>
#include <cstring>
#include <dlfcn.h>
#include <elf.h>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <map>
#include <sys/stat.h>
#include <unistd.h>

namespace fs = std::filesystem;
using namespace kernel_root;
// Android libc adapters for the delivered patch-engine IR retargeted to glibc.
extern "C" size_t __strlen_chk(const char* value, size_t size) {
    size_t result = strnlen(value, size);
    if (result == size) abort();
    return result;
}
extern "C" int* __errno() { return &errno; }
extern "C" int maplesu_host_android_stat(const char* path, void* output) {
    struct stat host{};
    int result = stat(path, &host);
    if (result == 0) {
        // The delivered readFile only consumes st_size, at offset 48 in arm64 Bionic.
        memset(output, 0, 128);
        memcpy(static_cast<char*>(output) + 48, &host.st_size, sizeof(host.st_size));
    }
    return result;
}
namespace {
constexpr const char* key = "kkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkk";
const fs::path root = "/tmp/maplesu-parasite-test";
const fs::path app = root / "host";
const fs::path lib = app / "lib/arm64";
const fs::path so = lib / "libfixture.so";
const fs::path other = lib / "libother.so";
std::map<std::string, int> captured;
pid_t parent;
void callback(const char* path, AppDynlibStatus status) {
    assert(getpid() == parent); // Callback must run in caller, not the elevated worker.
    captured[path] = status;
}
void put(const fs::path& path, const std::string& text) {
    std::ofstream file(path, std::ios::binary); file.write(text.data(), text.size());
    assert(file.good());
}
std::string bytes(const fs::path& path) {
    std::ifstream file(path, std::ios::binary);
    return {std::istreambuf_iterator<char>(file), {}};
}
void expect(ParasiteError result, ParasiteError expected, const char* name) {
    if (result != expected) { std::cerr << name << ": " << result << " != " << expected << '\n'; abort(); }
    std::cout << "PASS " << name << '\n';
}
}
namespace maplesu::sdk {
KModErr get_root(const char*) {
    if (getenv("FIXTURE_ROOT_FAIL")) return static_cast<KModErr>(-23456);
    if (getenv("FIXTURE_ROOT_CRASH")) raise(SIGSEGV);
    if (getenv("FIXTURE_ROOT_HANG")) sleep(10);
    return KModErr::OK;
}
KModErr get_su_auth_list_with_cb(const char*, void (*callback)(const su_auth_item*)) {
    if (!getenv("FIXTURE_NO_AUTH")) {
        su_auth_item item{}; strcpy(item.app_package_name, "dev.fixture.host"); callback(&item);
    }
    return KModErr::OK;
}
}

int main(int argc, char** argv) {
    assert(argc == 2);
    assert(!fs::exists(root));
    parent = getpid();
    auto precheck_export = reinterpret_cast<decltype(&parasite_precheck_app_with_cb)>(dlsym(
        RTLD_DEFAULT, "_ZN11kernel_root29parasite_precheck_app_with_cbEPKcS1_PFvS1_NS_15AppDynlibStatusEE"));
    auto app_export = reinterpret_cast<decltype(&parasite_implant_app)>(dlsym(
        RTLD_DEFAULT, "_ZN11kernel_root20parasite_implant_appEPKcS1_S1_"));
    auto su_export = reinterpret_cast<decltype(&parasite_implant_su_env)>(dlsym(
        RTLD_DEFAULT, "_ZN11kernel_root23parasite_implant_su_envEPKcS1_S1_S1_"));
    assert(precheck_export == &parasite_precheck_app_with_cb && app_export == &parasite_implant_app &&
           su_export == &parasite_implant_su_env);
    expect(precheck_export("short", "dev.fixture.host", callback), PARASITE_PARAM, "runtime precheck ABI lookup");
    expect(app_export("short", "dev.fixture.host", "/fixture.so"), PARASITE_PARAM, "runtime app ABI lookup");
    expect(su_export("short", "dev.fixture.host", "/fixture.so", "/fixture/su"), PARASITE_PARAM, "runtime su ABI lookup");
    fs::create_directories(lib);
    fs::create_directories(root / "proc/101");
    fs::copy_file(argv[1], so);
    fs::copy_file(argv[1], other);
    const std::string original = bytes(so);
    const std::string process("dev.fixture.host\0ignored", 24);
    put(root / "proc/101/cmdline", process);
    put(root / "proc/101/maps", "1000-2000 r-xp 0 00:00 1 " + so.string() + "\n");
    put(root / "pm", "#!/bin/sh\nprintf 'package:" + (app / "base.apk").string() + "\\n'\n");
    chmod((root / "pm").c_str(), 0700);
    auto check = [&] { captured.clear(); return parasite_precheck_app_with_cb(key, "dev.fixture.host", callback); };
    auto implant_app = [&] { return parasite_implant_app(key, "dev.fixture.host", so.c_str()); };
    expect(parasite_precheck_app_with_cb(key, "dev.fixture.host", nullptr), PARASITE_PARAM, "null callback");
    expect(parasite_precheck_app_with_cb("short", "dev.fixture.host", callback), PARASITE_PARAM, "invalid key");
    expect(parasite_precheck_app_with_cb(key, "dev.fixture;touch", callback), PARASITE_PARAM, "invalid identifier");
    setenv("FIXTURE_ROOT_FAIL", "1", 1);
    expect(check(), -23456, "root error retained"); assert(captured.empty());
    unsetenv("FIXTURE_ROOT_FAIL");
    setenv("FIXTURE_ROOT_CRASH", "1", 1);
    expect(check(), PARASITE_CHILD, "worker crash isolated");
    unsetenv("FIXTURE_ROOT_CRASH");
    setenv("FIXTURE_ROOT_HANG", "1", 1);
    auto start = std::chrono::steady_clock::now();
    expect(check(), PARASITE_CHILD, "worker timeout bounded");
    assert(std::chrono::steady_clock::now() - start < std::chrono::seconds(3));
    unsetenv("FIXTURE_ROOT_HANG");
    expect(parasite_precheck_app_with_cb(key, "dev.fixture.missing", callback), PARASITE_PROCESS, "missing process");
    expect(check(), 0, "precheck actual ELF inventory");
    assert(captured.size() == 2 && captured[so.string()] == Running && captured[other.string()] == NotRunning);
    put(root / "proc/101/maps", "1000-2000 r-xp 0 00:00 1 " + (app / "lib/arm/libbad.so").string() + "\n");
    expect(check(), PARASITE_32BIT, "32-bit host rejected");
    put(root / "proc/101/maps", "1000-2000 r-xp 0 00:00 1 " + so.string() + "\n");
    put(lib / "bad.so", "not ELF");
    expect(check(), 0, "non-ELF excluded"); assert(captured.size() == 2);
    expect(implant_app(), PARASITE_RECOVERY_MISSING, "missing recovery blocks mutation");
    assert(bytes(so) == original);
    put(root / "start.sh", "#!/bin/sh\nexit 0\n"); chmod((root / "start.sh").c_str(), 0600);
    setenv("FIXTURE_NO_AUTH", "1", 1);
    expect(implant_app(), -31003, "existing host grant required");
    unsetenv("FIXTURE_NO_AUTH");
    fs::copy_file(argv[1], root / "outside.so");
    expect(parasite_implant_app(key, "dev.fixture.host", (root / "outside.so").c_str()), PARASITE_ORIGINAL, "out-of-host path rejected");
    fs::create_symlink(so, lib / "libsymlink.so");
    expect(parasite_implant_app(key, "dev.fixture.host", (lib / "libsymlink.so").c_str()), PARASITE_ORIGINAL, "symlink original rejected");
    fs::remove(lib / "libsymlink.so");
    const auto malformed = lib / "libmalformed.so";
    put(malformed, original.substr(0, sizeof(Elf64_Ehdr)));
    expect(parasite_implant_app(key, "dev.fixture.host", malformed.c_str()), PARASITE_VERIFY,
           "patch failure preserves original");
    assert(bytes(malformed) == original.substr(0, sizeof(Elf64_Ehdr)));
    assert(!fs::exists(malformed.string() + ".maplesu-parasite.orig"));
    fs::remove(malformed);
    put(so.string() + ".maplesu-parasite.orig", "invalid backup");
    expect(implant_app(), PARASITE_CONFLICT, "invalid backup never overwritten");
    assert(bytes(so) == original && bytes(so.string() + ".maplesu-parasite.orig") == "invalid backup");
    fs::remove(so.string() + ".maplesu-parasite.orig");
    expect(implant_app(), 0, "app implant actual patch engine");
    const auto once = bytes(so);
    assert(once != original && bytes(so.string() + ".maplesu-parasite.orig") == original);
    assert(fs::exists(lib / "libmaplesu_parasite.so"));
    expect(implant_app(), 0, "app implant idempotent"); assert(bytes(so) == once);
    expect(parasite_implant_app(key, "dev.fixture.host", other.c_str()), 0, "second library unaffected by patch globals");
    assert(bytes(other.string() + ".maplesu-parasite.orig") == original);
    fs::create_directories(root / "su");
    const auto su_dir = (root / "su").string();
    auto su_implant = [&] { return parasite_implant_su_env(key, "dev.fixture.host", so.c_str(), su_dir.c_str()); };
    expect(su_implant(), PARASITE_PAYLOAD, "su executable required");
    put(root / "su/su", "fixture"); chmod((root / "su/su").c_str(), 0755);
    expect(su_implant(), 0, "distinct su environment implant");
    assert(bytes(so.string() + ".maplesu-parasite.orig") == original);
    const auto both = bytes(so);
    expect(su_implant(), 0, "su environment idempotent"); assert(bytes(so) == both);
    assert(bytes(lib / "libmaplesu_su_env.so") != bytes(lib / "libmaplesu_parasite.so"));
    assert(bytes(lib / "libmaplesu_su_env.so").find(su_dir) != std::string::npos);
    assert(bytes(lib / "libmaplesu_parasite.so").find(key) == std::string::npos);
    auto alternate = (root / "alternate").string(); fs::create_directories(alternate);
    fs::copy_file(root / "su/su", fs::path(alternate) / "su");
    expect(parasite_implant_su_env(key, "dev.fixture.host", so.c_str(), alternate.c_str()), PARASITE_CONFLICT, "conflicting su configuration preserved");
    assert(bytes(so) == both);
    put(lib / "libmaplesu_parasite.so", "damaged payload");
    expect(implant_app(), PARASITE_CONFLICT, "damaged existing payload rejected"); assert(bytes(so) == both);
    std::cout << "ALL PARASITE FIXTURE CHECKS PASSED\n";
}
