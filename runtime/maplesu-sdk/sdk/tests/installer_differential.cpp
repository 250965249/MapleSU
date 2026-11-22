#include "module_err_def.h"
#include "maplesu_sdk/maplesu_installer.h"
#include <algorithm>
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <new>
#include <string>
#include <vector>
#include <sys/stat.h>
#include <sys/xattr.h>
#include <unistd.h>

extern "C" KModErr test_install();
namespace fs = std::filesystem;
namespace {
bool active = false;
std::string fault;
std::vector<std::string> trace;
unsigned roots = 0, publishes = 0, chmods = 0, labels = 0, opens = 0;
bool fails(const char* operation, unsigned count) {
    return fault == std::string(operation) + ":" + std::to_string(count);
}
void note(const std::string& item) { if (active) trace.push_back(item); }
std::string read(const fs::path& path) {
    std::ifstream in(path, std::ios::binary);
    return {std::istreambuf_iterator<char>(in), {}};
}
void put(const fs::path& path, const char* value) {
    std::ofstream(path, std::ios::binary) << value;
}
std::string hex(const char* bytes, size_t size) {
    static const char digits[] = "0123456789abcdef";
    std::string out;
    for (size_t i = 0; i < size; ++i) {
        const auto ch = static_cast<unsigned char>(bytes[i]);
        out += digits[ch >> 4]; out += digits[ch & 15];
    }
    return out;
}
}

extern "C" FILE* __real_fopen(const char*, const char*);
extern "C" FILE* __wrap_fopen(const char* path, const char* mode) {
    if (active && strchr(mode, 'w')) {
        note("open:" + std::string(path));
        if (fails("open", ++opens)) { errno = EACCES; return nullptr; }
    }
    return __real_fopen(path, mode);
}
extern "C" int __real_chmod(const char*, mode_t);
extern "C" int __wrap_chmod(const char* path, mode_t mode) {
    if (active) {
        note("chmod:" + std::string(path) + ":" + std::to_string(mode));
        if (fails("chmod", ++chmods)) { errno = EACCES; return -1; }
    }
    return __real_chmod(path, mode);
}
extern "C" int __real_setxattr(const char*, const char*, const void*, size_t, int);
extern "C" int __real_fsetxattr(int, const char*, const void*, size_t, int);
extern "C" int __wrap_setxattr(const char* path, const char* name, const void* value,
                                size_t size, int flags) {
    if (active) {
        note("label:" + std::string(path) + ":" + hex(static_cast<const char*>(value), size));
        if (fails("label", ++labels)) { errno = EACCES; return -1; }
    }
    if (strcmp(name, "security.selinux") != 0) std::abort();
    return __real_setxattr(path, "user.maplesu.selinux", value, size, flags);
}
extern "C" int __wrap_fsetxattr(int fd, const char* name, const void* value,
                                 size_t size, int flags) {
    if (strcmp(name, "security.selinux") != 0) std::abort();
    return __real_fsetxattr(fd, "user.maplesu.selinux", value, size, flags);
}
extern "C" KModErr __real_maplesu_publish_executable(const char*, const void*, size_t, const char*);
extern "C" KModErr __wrap_maplesu_publish_executable(const char* path, const void* data,
                                                      size_t size, const char* context) {
    note("publish:" + std::string(path) + ":" + std::to_string(size) + ":" + context);
    if (fails("publish", ++publishes)) return static_cast<KModErr>(-19930);
    return __real_maplesu_publish_executable(path, data, size, context);
}
extern "C" void* __real__ZnamRKSt9nothrow_t(size_t, const std::nothrow_t&);
extern "C" void* __wrap__ZnamRKSt9nothrow_t(size_t size, const std::nothrow_t& tag) {
    if (active && (fault == "payloadalloc" && size > 4096 || fault == "tokenalloc" && size == 4096))
        return nullptr;
    return __real__ZnamRKSt9nothrow_t(size, tag);
}
extern "C" int __real_memcmp(const void*, const void*, size_t);
extern "C" int __wrap_memcmp(const void* a, const void* b, size_t size) {
    if (active && size == 4096 && fault == "tokenmissing") return 1;
    return __real_memcmp(a, b, size);
}
extern "C" char* __strncpy_chk2(char* to, const char* from, size_t size, size_t cap, size_t) {
    if (size > cap) std::abort();
    return strncpy(to, from, size);
}
extern "C" const char* __get_current_module_root_key_hd04aBTnbSZlTRP7S4mQpIeVvr2ssGjW() {
    return "ABCDEFGHIJKLMNOP0123456789ABCDEFGHIJKLMNOP012345";
}
namespace default_modules::module_root {
KModErr set_current_root(bool enabled) {
    note(enabled ? "root:true" : "root:false");
    return fails("root", ++roots) ? static_cast<KModErr>(-12345) : KModErr::OK;
}
}
namespace maplesu::sdk {
MapleSUSdkVersion get_sdk_version() { note("sdk-version"); return {5, 2, 0}; }
}

int main(int argc, char** argv) {
    if (argc != 4) return 2;
    const int member = atoi(argv[1]);
    fault = argv[2];
    const fs::path output = argv[3];
    fs::create_directories("/data/ABCDEFGHIJKLMNOPA/modules");
    fs::create_directories("/data/ABCDEFGHIJKLMNOP");
    if (member == 48) {
        put("/data/ABCDEFGHIJKLMNOPA/su", "previous-system");
        put("/data/ABCDEFGHIJKLMNOP/su", "previous-kernel");
    } else if (member == 49) put("/data/ABCDEFGHIJKLMNOPA/resetprop", "previous");
    else if (member == 50) put("/data/ABCDEFGHIJKLMNOPA/modules/webui_loader", "previous");
    else if (member == 52) {
        put("/data/ABCDEFGHIJKLMNOP/init", "previous");
        put("/data/ABCDEFGHIJKLMNOP/init.safe_flag", "3");
        put("/data/ABCDEFGHIJKLMNOP/init.boot_session.duplicate", "previous-boot");
    } else return 2;
    active = true;
    const auto status = test_install();
    active = false;
    fs::create_directories(output / "files");
    std::ofstream metadata(output / "state.tsv");
    metadata << "status\t" << static_cast<long long>(status) << '\n';
    for (const auto& item : trace) metadata << "trace\t" << item << '\n';
    std::vector<fs::path> paths;
    for (const auto& entry : fs::recursive_directory_iterator("/data"))
        if (entry.is_regular_file()) paths.push_back(entry.path());
    std::sort(paths.begin(), paths.end());
    for (const auto& path : paths) {
        struct stat st{};
        if (stat(path.c_str(), &st) != 0) return 3;
        char label[128]{};
        const auto count = getxattr(path.c_str(), "user.maplesu.selinux", label, sizeof(label));
        const auto relative = path.lexically_relative("/data");
        const auto target = output / "files" / relative;
        fs::create_directories(target.parent_path());
        fs::copy_file(path, target, fs::copy_options::overwrite_existing);
        metadata << "file\t" << relative.string() << '\t' << (st.st_mode & 07777) << '\t'
                 << (count >= 0 ? hex(label, static_cast<size_t>(count)) : "-") << '\n';
    }
    return 0;
}
