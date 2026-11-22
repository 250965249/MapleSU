#include "maplesu/compat/persisted_inputs.h"
#include "module_err_def.h"
#include "maplesu_sdk/maplesu_installer.h"
#include <algorithm>
#include <cerrno>
#include <cstdarg>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <iterator>
#include <map>
#include <string>
#include <vector>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/xattr.h>
#include <unistd.h>

namespace maplesu::sdk {
KModErr unsafe_install_autorun_bootstrap();
KModErr unsafe_reset_autorun_bootstrap_safe_flag();
KModErr unsafe_reset_autorun_bootstrap_duplicate_boot_session_flag();
}
extern "C" void maplesu_installed_helper_path(std::string*);

namespace fs = std::filesystem;
namespace {
constexpr const char* directory = "/data/ABCDEFGHIJKLMNOP";
constexpr const char* label = "u:object_r:kernel:s0";
const std::vector<std::string> names = {"init", "init.running.lock", "init.boot_session.work",
    "init.log", "init.log.last", "init.log.crash", maplesu::compat::kEnvironmentVersionFile,
    "init.boot_session.duplicate", "init.safe_flag"};
bool active = false;
std::string fault, key;
unsigned hits = 0, write_calls = 0, root_calls = 0;
int staging_fd = -1;
bool published = false;
std::map<FILE*, std::string> streams;
std::vector<std::string> trace;
std::string read(const fs::path& p) {
    std::ifstream stream(p, std::ios::binary);
    return {std::istreambuf_iterator<char>(stream), {}};
}
bool target(FILE* stream) {
    const auto it = streams.find(stream);
    return it != streams.end() && it->second == std::string(directory) + "/MapleSU.sdk.ver";
}
bool consume(const char* name) {
    if (active && fault == name && hits == 0) { ++hits; return true; }
    return false;
}
struct File { std::string bytes, context; unsigned mode; };
std::map<std::string, File> snapshot() {
    std::map<std::string, File> result;
    for (const auto& item : fs::directory_iterator(directory)) {
        struct stat st {};
        if (stat(item.path().c_str(), &st) != 0 || !S_ISREG(st.st_mode)) continue;
        char context[128] {};
        const auto count = getxattr(item.path().c_str(), "user.maplesu.selinux", context, sizeof(context));
        result.emplace(item.path().filename(), File{read(item.path()),
            count >= 0 ? std::string(context, count) : std::string(), unsigned(st.st_mode & 07777)});
    }
    return result;
}
bool same(const std::map<std::string, File>& a, const std::map<std::string, File>& b) {
    if (a.size() != b.size()) return false;
    for (const auto& [name, file] : a) {
        const auto it = b.find(name);
        if (it == b.end() || file.bytes != it->second.bytes || file.mode != it->second.mode ||
            file.context != it->second.context) return false;
    }
    return true;
}
}

extern "C" FILE* __real_fopen(const char*, const char*);
extern "C" FILE* __wrap_fopen(const char* path, const char* mode) {
    FILE* result = __real_fopen(path, mode);
    if (active && result) { streams[result] = path; trace.push_back("open:" + std::string(path)); }
    return result;
}
extern "C" size_t __real_fwrite(const void*, size_t, size_t, FILE*);
extern "C" size_t __wrap_fwrite(const void* data, size_t size, size_t count, FILE* stream) {
    if (active && target(stream)) {
        trace.push_back("fwrite:" + std::to_string(size) + ":" + std::to_string(count));
        if (consume("stream-eintr")) { errno = EINTR; return 0; }
        if (consume("stream-short")) {
            if (count > 1) return __real_fwrite(data, size, count - 1, stream);
            (void)__real_fwrite(data, 1, size / 2, stream);
            return 0;
        }
    }
    return __real_fwrite(data, size, count, stream);
}
extern "C" int __real_fflush(FILE*);
extern "C" int __wrap_fflush(FILE* stream) {
    if (active && target(stream)) {
        trace.push_back("fflush:version");
        if (consume("stream-flush")) { errno = EIO; return EOF; }
    }
    return __real_fflush(stream);
}
extern "C" int __real_fclose(FILE*);
extern "C" int __wrap_fclose(FILE* stream) {
    bool fail = false;
    if (active) {
        const auto it = streams.find(stream);
        if (it != streams.end()) {
            trace.push_back("fclose:" + it->second);
            fail = target(stream) && consume("stream-close");
            if (it->second == std::string(directory) + "/init.running.lock")
                fail = consume("empty-close") || fail;
            if (it->second == std::string(directory) + "/init.safe_flag" ||
                it->second == std::string(directory) + "/init.boot_session.duplicate")
                fail = consume("flag-close") || fail;
            streams.erase(it);
        }
    }
    const int result = __real_fclose(stream);
    if (fail) { errno = EIO; return EOF; }
    return result;
}
extern "C" int __real_openat(int, const char*, int, ...);
extern "C" int __wrap_openat(int dir, const char* path, int flags, ...) {
    mode_t mode = 0;
    if (flags & O_CREAT) { va_list args; va_start(args, flags); mode = va_arg(args, int); va_end(args); }
    const int fd = __real_openat(dir, path, flags, mode);
    if (active && fd >= 0 && strncmp(path, ".maplesu-exec-", 14) == 0) staging_fd = fd;
    return fd;
}
extern "C" ssize_t __real_write(int, const void*, size_t);
extern "C" ssize_t __wrap_write(int fd, const void* data, size_t size) {
    if (active && fd == staging_fd) {
        ++write_calls;
        if (consume("publish-eintr")) { errno = EINTR; return -1; }
        if (consume("publish-write")) { errno = EIO; return -1; }
        if (consume("publish-short")) return __real_write(fd, data, std::min<size_t>(size, 7));
    }
    return __real_write(fd, data, size);
}
extern "C" int __real_fsync(int);
extern "C" int __wrap_fsync(int fd) {
    if (active) {
        if (fd == staging_fd && consume("publish-fsync-file")) { errno = EIO; return -1; }
        struct stat st {};
        if (fstat(fd, &st) == 0 && S_ISDIR(st.st_mode) && consume("publish-fsync-dir")) {
            errno = EIO; return -1;
        }
    }
    return __real_fsync(fd);
}
extern "C" int __real_close(int);
extern "C" int __wrap_close(int fd) {
    const bool fail = active && fd == staging_fd && consume("publish-close");
    if (fd == staging_fd) staging_fd = -1;
    const int result = __real_close(fd);
    if (fail) { errno = EIO; return -1; }
    return result;
}
extern "C" int __real_renameat(int, const char*, int, const char*);
extern "C" int __wrap_renameat(int from, const char* name, int to, const char* target) {
    if (consume("publish-rename")) { errno = EIO; return -1; }
    const int result = __real_renameat(from, name, to, target);
    if (active && result == 0) published = true;
    return result;
}
extern "C" int __real_setxattr(const char*, const char*, const void*, size_t, int);
extern "C" int __real_fsetxattr(int, const char*, const void*, size_t, int);
extern "C" int __wrap_setxattr(const char* path, const char* name, const void* value, size_t size, int flags) {
    if (strcmp(name, "security.selinux") != 0) std::abort();
    return __real_setxattr(path, "user.maplesu.selinux", value, size, flags);
}
extern "C" int __wrap_fsetxattr(int fd, const char* name, const void* value, size_t size, int flags) {
    if (strcmp(name, "security.selinux") != 0) std::abort();
    return __real_fsetxattr(fd, "user.maplesu.selinux", value, size, flags);
}
extern "C" KModErr __real_maplesu_publish_executable(const char*, const void*, size_t, const char*);
extern "C" KModErr __wrap_maplesu_publish_executable(const char* path, const void* data, size_t size, const char* context) {
    if (consume("publish-outer")) return static_cast<KModErr>(-19930);
    return __real_maplesu_publish_executable(path, data, size, context);
}
extern "C" const char* __get_current_module_root_key_hd04aBTnbSZlTRP7S4mQpIeVvr2ssGjW() { return key.c_str(); }
namespace default_modules::module_root {
KModErr set_current_root(bool) {
    ++root_calls;
    return consume("root") ? static_cast<KModErr>(-12345) : KModErr::OK;
}
}
namespace maplesu::sdk { MapleSUSdkVersion get_sdk_version() { return {5, 2, 0}; } }

int main(int argc, char** argv) {
    if (argc != 7) return 2;
    const std::string operation = argv[1]; fault = argv[2];
    const unsigned length = std::strtoul(argv[3], nullptr, 10), rounds = std::strtoul(argv[4], nullptr, 10);
    const fs::path output = argv[5];
    key = "ABCDEFGHIJKLMNOP" + std::string(length - 16, 'z');
    const std::string payload = read(argv[6]);
    fs::remove_all(directory); fs::create_directories(directory);
    for (const auto& name : names) {
        const auto path = fs::path(directory) / name;
        std::ofstream(path, std::ios::binary) << "previous:" << name;
        chmod(path.c_str(), 0600);
        __real_setxattr(path.c_str(), "user.maplesu.selinux", "previous-label", 14, 0);
    }
    const auto before = snapshot();
    long status = 0;
    bool earlier_success = true;
    std::string helper_path;
    for (unsigned round = 0; round < rounds; ++round) {
        active = true;
        if (operation == "install") status = static_cast<long>(maplesu::sdk::unsafe_install_autorun_bootstrap());
        else if (operation == "safe") status = static_cast<long>(maplesu::sdk::unsafe_reset_autorun_bootstrap_safe_flag());
        else if (operation == "duplicate") status = static_cast<long>(maplesu::sdk::unsafe_reset_autorun_bootstrap_duplicate_boot_session_flag());
        else if (operation == "path") {
            helper_path = round == 0 ? "" : std::string(256, 'x');
            maplesu_installed_helper_path(&helper_path);
            status = helper_path == std::string(directory) + "/init" ? 0 : 1001;
        } else return 2;
        active = false;
        if (round + 1 < rounds && status != 0) earlier_success = false;
    }
    std::string expected = payload;
    const std::string token = std::string("5d31494d2e18e3fdef2afaf740b0febc19229cb292f57ebc3bc1c96c6d70b7098d2dc1f356b733e8c999e6ac85bdca24c8c74f03ae7d5b2a402e96804576e925") + std::string(3968, '\0');
    for (size_t at = 0; (at = expected.find(token, at)) != std::string::npos; ++at)
        expected.replace(at, key.size() + 1, key + '\0');
    const auto after = snapshot();
    bool install_files = after.size() == 9;
    for (const auto& name : names) {
        const auto it = after.find(name);
        const auto wanted = name == "init" ? expected : name == maplesu::compat::kEnvironmentVersionFile ? "5.2.0" :
            name == "init.log" ? "[FATAL] autorun_bootstrap: NEVER EXECUTED" : std::string();
        install_files = install_files && it != after.end() && it->second.bytes == wanted &&
            it->second.mode == 0777 && it->second.context == std::string(label, strlen(label) + 1);
    }
    bool reset_files = after.size() == before.size();
    for (const auto& [name, file] : before) {
        const auto& now = after.at(name);
        const auto changed = operation == "safe" ? "init.safe_flag" : "init.boot_session.duplicate";
        reset_files = reset_files && (name == changed ? now.bytes.empty() && now.mode == 0777 &&
            now.context == std::string(label, strlen(label) + 1) : file.bytes == now.bytes &&
            file.mode == now.mode && file.context == now.context);
    }
    fs::create_directories(output / "files");
    std::ofstream state(output / "state.tsv");
    state << "status\t" << status << "\nfault_hits\t" << hits << "\nwrite_calls\t" << write_calls
        << "\nroot_calls\t" << root_calls << "\npublished\t" << published
        << "\nall_seed_files_unchanged\t" << same(before, after)
        << "\nhelper_payload_matches\t" << (after.at("init").bytes == expected)
        << "\ninstall_files_match\t" << install_files << "\nreset_files_match\t" << reset_files
        << "\nearlier_rounds_success\t" << earlier_success << "\nhelper_path\t" << helper_path << '\n';
    for (const auto& item : trace) state << "trace\t" << item << '\n';
    for (const auto& [name, file] : after) {
        std::ofstream(output / "files" / name, std::ios::binary).write(file.bytes.data(), file.bytes.size());
        state << "file\t" << name << '\t' << file.mode << '\t' << file.context.size() << '\n';
    }
    return 0;
}
