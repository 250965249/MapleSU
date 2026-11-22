#include "module_err_def.h"
#include <cassert>
#include <cerrno>
#include <cstdarg>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fcntl.h>
#include <fstream>
#include <iterator>
#include <string>
#include <sys/stat.h>
#include <sys/xattr.h>
#include <unistd.h>

extern "C" KModErr test_install();
static bool fail_write = false;
static bool fail_open = false;
extern "C" FILE* __real_fopen(const char*, const char*);
extern "C" int __real_openat(int, const char*, int, ...);
extern "C" FILE* __wrap_fopen(const char* path, const char* mode) {
    if (fail_open && strchr(mode, 'w')) { errno = EACCES; return nullptr; }
    return __real_fopen(path, mode);
}
extern "C" int __wrap_openat(int directory, const char* path, int flags, ...) {
    mode_t mode = 0;
    if (flags & O_CREAT) {
        va_list args;
        va_start(args, flags);
        mode = va_arg(args, mode_t);
        va_end(args);
        if (fail_open) { errno = EACCES; return -1; }
    }
    return __real_openat(directory, path, flags, mode);
}
extern "C" ssize_t __real_write(int, const void*, size_t);
extern "C" int __real_setxattr(const char*, const char*, const void*, size_t, int);
extern "C" int __real_fsetxattr(int, const char*, const void*, size_t, int);
extern "C" ssize_t __wrap_write(int fd, const void* bytes, size_t size) {
    if (fail_write) { errno = ENOSPC; return -1; }
    return __real_write(fd, bytes, size);
}
extern "C" int __wrap_setxattr(const char* path, const char* name, const void* value, size_t size, int flags) {
    assert(strcmp(name, "security.selinux") == 0);
    return __real_setxattr(path, "user.maplesu.selinux", value, size, flags);
}
extern "C" int __wrap_fsetxattr(int fd, const char* name, const void* value, size_t size, int flags) {
    assert(strcmp(name, "security.selinux") == 0);
    return __real_fsetxattr(fd, "user.maplesu.selinux", value, size, flags);
}
extern "C" char* __strncpy_chk2(char* dest, const char* source, size_t size, size_t capacity, size_t) {
    assert(size <= capacity);
    return strncpy(dest, source, size);
}
extern "C" const char* __get_current_module_root_key_hd04aBTnbSZlTRP7S4mQpIeVvr2ssGjW() {
    return "ABCDEFGHIJKLMNOP0123456789ABCDEFGHIJKLMNOP012345";
}
namespace default_modules::module_root { KModErr set_current_root(bool) { return KModErr::OK; } }
namespace maplesu::sdk {
struct Version { unsigned major, minor, patch; };
Version get_sdk_version() { return {5, 1, 0}; }
}

static std::string contents(const std::string& path) {
    std::ifstream input(path, std::ios::binary);
    return std::string(std::istreambuf_iterator<char>(input), std::istreambuf_iterator<char>());
}

int main(int argc, char** argv) {
    assert(argc == 4 || argc == 5);
    const std::string path = argv[1], scenario = argv[2];
    const auto size = static_cast<size_t>(strtoul(argv[3], nullptr, 10));
    std::filesystem::create_directories("/data/ABCDEFGHIJKLMNOP");
    std::filesystem::create_directories("/data/ABCDEFGHIJKLMNOPA/modules");
    {
        std::ofstream output(path, std::ios::binary);
        output << "previous";
        assert(output.good());
    }
    const bool bootstrap = path == "/data/ABCDEFGHIJKLMNOP/init";
    if (bootstrap) {
        std::ofstream(path + ".safe_flag") << '3';
        std::ofstream(path + ".boot_session.duplicate") << "previous-boot";
    }
    fail_write = scenario == "write_failure";
    fail_open = scenario == "open_failure";
    const auto first = test_install();
    fail_write = false;
    fail_open = false;
    bool ok;
    if (scenario == "write_failure" || scenario == "open_failure") {
        const auto expected = scenario == "write_failure" ? KModErr::ERR_MODULE_WRITE_FILE : KModErr::ERR_MODULE_OPEN_FILE;
        ok = first == expected && contents(path) == "previous";
        if (bootstrap) ok = ok && contents(path + ".safe_flag") == "3" &&
            contents(path + ".boot_session.duplicate") == "previous-boot";
    } else {
        const auto bytes = contents(path);
        ok = first == KModErr::OK && bytes.size() == size && bytes.compare(0, 4, "\177ELF") == 0;
        if (argc == 5) ok = ok && bytes == contents(argv[4]);
        if (bootstrap) ok = ok && std::filesystem::is_regular_file(path + ".safe_flag") &&
            contents(path + ".safe_flag").empty() &&
            std::filesystem::is_regular_file(path + ".boot_session.duplicate") &&
            contents(path + ".boot_session.duplicate").empty();
        if (ok) {
            const auto again = test_install();
            ok = again == KModErr::OK && contents(path) == bytes;
        }
    }
    for (const auto& entry : std::filesystem::directory_iterator(std::filesystem::path(path).parent_path()))
        ok = ok && entry.path().filename().string().find(".maplesu-exec-") != 0;
    printf("%s installer=%s scenario=%s sdkError=%s\n", ok ? "PASS" : "FAIL", path.c_str(), scenario.c_str(), to_string(first).c_str());
    std::filesystem::remove_all("/data/ABCDEFGHIJKLMNOP");
    std::filesystem::remove_all("/data/ABCDEFGHIJKLMNOPA");
    return ok ? 0 : 1;
}
