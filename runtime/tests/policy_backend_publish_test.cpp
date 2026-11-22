#include "backend_publish.h"
#include "../maplesu-sdk/sdk/include/maplesu_request_private.h"
#include "module_err_def.h"
#include "maplesu_sdk/maplesu_root.h"
#include <cassert>
#include <cerrno>
#include <cstring>
#include <filesystem>
#include <fcntl.h>
#include <fstream>
#include <iterator>
#include <string>
#include <sys/stat.h>
#include <sys/xattr.h>
#include <unistd.h>
#include <vector>

static std::string scenario;
static uint64_t auth_state = 0;
static pid_t parent_pid = 0;
namespace kernel_module {
uint64_t maplesu_request_auth_state() { return auth_state; }
KModErr maplesu_request_set_auth_mode(RequestAuthMode mode) {
    assert(getpid() != parent_pid);
    if (scenario == "owner_select_failure") return KModErr::ERR_MODULE_TEST_CHANNEL;
    auth_state = static_cast<uint64_t>(mode);
    return KModErr::OK;
}
KModErr maplesu_request_owner_close() {
    assert(getpid() != parent_pid && auth_state == 1);
    return scenario == "owner_close_failure" || scenario == "owner_first_failure"
        ? KModErr::ERR_MODULE_TEST_CHANNEL : KModErr::OK;
}
CleanupReceiptScope::CleanupReceiptScope() noexcept {}
CleanupReceiptScope::~CleanupReceiptScope() noexcept {}
}

namespace maplesu::sdk {
KModErr get_root(const char* key) {
    assert(getpid() != parent_pid);
    assert(auth_state == (key ? 0u : 1u));
    if (key) assert(!strcmp(key, "ABCDEFGHIJKLMNOP0123456789ABCDEFGHIJKLMNOP012345"));
    return scenario == "root_failure" || scenario == "owner_root_failure" || scenario == "owner_first_failure"
        ? KModErr::ERR_MODULE_ROOT_KEY : KModErr::OK;
}
}
extern "C" ssize_t __real_write(int, const void*, size_t);
extern "C" ssize_t __wrap_write(int fd, const void* data, size_t size) {
    if (scenario == "write_failure" && size > 8) { errno = ENOSPC; return -1; }
    return __real_write(fd, data, size);
}
extern "C" int __real_fsetxattr(int, const char*, const void*, size_t, int);
extern "C" ssize_t __real_fgetxattr(int, const char*, void*, size_t);
extern "C" ssize_t __wrap_fgetxattr(int fd, const char* name, void* data, size_t size) {
    assert(strcmp(name, "security.selinux") == 0);
    return __real_fgetxattr(fd, "user.maplesu.selinux", data, size);
}
extern "C" int __wrap_fsetxattr(int fd, const char* name, const void* data, size_t size, int flags) {
    assert(strcmp(name, "security.selinux") == 0);
    if (scenario == "idempotent") { errno = EACCES; return -1; }
    return __real_fsetxattr(fd, "user.maplesu.selinux", data, size, flags);
}
static std::string contents(const std::filesystem::path& path) {
    std::ifstream stream(path, std::ios::binary);
    return {std::istreambuf_iterator<char>(stream), std::istreambuf_iterator<char>()};
}
int main(int argc, char** argv) {
    assert(argc == 2);
    scenario = argv[1];
    parent_pid = getpid();
    auth_state = scenario.rfind("owner_", 0) == 0 || scenario == "legacy_from_owner" ? 1 : 0;
    if (scenario == "null_invalid") auth_state = UINT64_MAX;
    if (scenario == "null_helper") auth_state = 3;
    const uint64_t parent_auth = auth_state;
    const std::filesystem::path root("/tmp/maplesu-policy-publish-entry");
    std::filesystem::remove_all(root);
    std::filesystem::create_directories(root / "adb");
    const std::string digest(64, 'a');
    const auto directory = root / "adb/maplesu/bin";
    const auto target = directory / ("libmaplesu_policy_boot." + digest + ".so");
    const auto old = directory / ("libmaplesu_policy_boot." + std::string(64, 'b') + ".so");
    const char* key = "ABCDEFGHIJKLMNOP0123456789ABCDEFGHIJKLMNOP012345";
    if (scenario.rfind("owner_", 0) == 0 || scenario.rfind("null_", 0) == 0) key = nullptr;
    std::vector<unsigned char> bytes(1024 * 1024, 'N');
    memcpy(bytes.data(), "\177ELF\2\1", 6);
    bytes[16] = 3; bytes[17] = 0; bytes[18] = 183; bytes[19] = 0;
    std::filesystem::create_directories(directory);
    std::ofstream(old) << "old-backend";
    if (scenario == "write_failure" || scenario == "symlink_file" || scenario == "hardlink_file") {
        if (scenario == "symlink_file") assert(symlink(old.c_str(), target.c_str()) == 0);
        else if (scenario == "hardlink_file") assert(link(old.c_str(), target.c_str()) == 0);
        else std::ofstream(target) << "previous";
    }
    if (scenario == "unsafe_bin") assert(chmod(directory.c_str(), 0777) == 0);
    if (scenario == "symlink_parent") {
        std::filesystem::rename(directory, root / "bin-other");
        assert(symlink((root / "bin-other").c_str(), directory.c_str()) == 0);
    }
    int64_t result;
    if (scenario == "invalid_digest") result = maplesu::module_policy::publish_backend(key, "../invalid", bytes.data(), bytes.size());
    else if (scenario == "invalid_elf") {
        bytes[18] = 62;
        result = maplesu::module_policy::publish_backend(key, digest.c_str(), bytes.data(), bytes.size());
    } else if (scenario == "missing_key") result = maplesu::module_policy::publish_backend(nullptr, digest.c_str(), bytes.data(), bytes.size());
    else if (scenario == "oversize") result = maplesu::module_policy::publish_backend(key, digest.c_str(), bytes.data(), 33 * 1024 * 1024);
    else {
        if (scenario == "idempotent" || scenario == "repair_label") {
            const auto saved_scenario = scenario;
            scenario = "fresh";
            assert(maplesu::module_policy::publish_backend(key, digest.c_str(), bytes.data(), bytes.size()) == 0);
            scenario = saved_scenario;
            if (scenario == "repair_label") assert(removexattr(target.c_str(), "user.maplesu.selinux") == 0);
        }
        struct stat before{};
        if (scenario == "idempotent") assert(stat(target.c_str(), &before) == 0);
        result = maplesu::module_policy::publish_backend(key, digest.c_str(), bytes.data(), bytes.size());
        if (scenario == "idempotent") {
            struct stat after{};
            assert(stat(target.c_str(), &after) == 0 && before.st_ino == after.st_ino);
        }
    }
    assert(auth_state == parent_auth);
    if (scenario == "owner_first_failure" || scenario == "owner_root_failure")
        assert(result == static_cast<int64_t>(KModErr::ERR_MODULE_ROOT_KEY));
    if (scenario == "owner_select_failure" || scenario == "owner_close_failure")
        assert(result == static_cast<int64_t>(KModErr::ERR_MODULE_TEST_CHANNEL));
    if (scenario == "fresh" || scenario == "idempotent" || scenario == "repair_label" ||
        scenario == "owner_fresh" || scenario == "legacy_from_owner" || scenario == "owner_close_failure") {
        assert((scenario == "owner_close_failure" ? result != 0 : result == 0) &&
            contents(target) == std::string(reinterpret_cast<char*>(bytes.data()), bytes.size()));
        struct stat st{};
        assert(stat(target.c_str(), &st) == 0 && st.st_uid == 0 && st.st_nlink == 1 && (st.st_mode & 07777) == 0700);
        char label[64]{};
        constexpr char expected[] = "u:object_r:system_file:s0";
        assert(getxattr(target.c_str(), "user.maplesu.selinux", label, sizeof(label)) == sizeof(expected));
        assert(memcmp(label, expected, sizeof(expected)) == 0);
    } else {
        assert(result != 0);
        if (scenario == "write_failure") assert(contents(target) == "previous");
        else if (scenario != "symlink_file" && scenario != "hardlink_file") assert(!std::filesystem::exists(target));
    }
    if (scenario == "symlink_parent") assert(contents(root / "bin-other" / old.filename()) == "old-backend");
    else assert(contents(old) == "old-backend");
    for (const auto& file : std::filesystem::recursive_directory_iterator(root))
        assert(file.path().filename().string().find(".maplesu-exec-") != 0);
    std::filesystem::remove_all(root);
    printf("PASS forked boot-backend publication %s\n", scenario.c_str());
}
