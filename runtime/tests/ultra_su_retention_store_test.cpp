#include "module_err_def.h"
#include "../ultra/authorization/su_retention_store.h"
#include <algorithm>
#include <array>
#include <cerrno>
#include <cstdarg>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <fcntl.h>
#include <fstream>
#include <stdexcept>
#include <string>
#include <sys/stat.h>
#include <unistd.h>
#include <vector>

namespace {
const char* root_key = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
const char* module_id = "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB";
const std::string root = "/data/AAAAAAAAAAAAAAAAA";
const std::string directory = root + "/storage/BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB";
const std::string name = "uid_retention_budget.20261105";
const std::string path = directory + "/" + name;
std::string scenario;
int temporary = -1;
unsigned write_calls = 0, read_calls = 0, sync_calls = 0;
std::vector<std::string> events;
std::array<unsigned char, 64> old_bytes{}, new_bytes{};
void require(bool condition, const char* message) {
    if (!condition) throw std::runtime_error(message);
}
std::vector<unsigned char> contents(const std::string& file) {
    std::ifstream input(file, std::ios::binary);
    return {std::istreambuf_iterator<char>(input), std::istreambuf_iterator<char>()};
}
void put(const std::string& file, const void* bytes, size_t size) {
    std::ofstream output(file, std::ios::binary);
    output.write(static_cast<const char*>(bytes), size);
    output.close();
    chmod(file.c_str(), 0600);
}
void reset(const std::string& test) {
    std::filesystem::remove_all(root);
    std::filesystem::remove_all(root + "-real");
    std::filesystem::create_directories(directory);
    chmod(root.c_str(), 0711);
    chmod((root + "/storage").c_str(), 0700);
    chmod(directory.c_str(), 0700);
    old_bytes.fill(7); old_bytes[0] = 1;
    new_bytes.fill(11); new_bytes[0] = 1;
    put(path, old_bytes.data(), old_bytes.size());
    scenario = test; temporary = -1;
    write_calls = read_calls = sync_calls = 0; events.clear();
}
}

extern "C" const char* __get_current_module_root_key_hd04aBTnbSZlTRP7S4mQpIeVvr2ssGjW() {
    return scenario == "invalid_key" ? "../bad" : root_key;
}
extern "C" const char* __get_current_module_id32_1b0494ae8a788541db46b82cc1f0577c() {
    return scenario == "invalid_module" ? "../bad" : module_id;
}
extern "C" int __real_openat(int, const char*, int, ...);
extern "C" ssize_t __real_write(int, const void*, size_t);
extern "C" ssize_t __real_pread(int, void*, size_t, off_t);
extern "C" int __real_fsync(int);
extern "C" int __real_fstat(int, struct stat*);
extern "C" int __real_renameat(int, const char*, int, const char*);
extern "C" int __real_close(int);
extern "C" int __wrap_openat(int parent, const char* file, int flags, ...) {
    mode_t mode = 0;
    if (flags & O_CREAT) {
        va_list values; va_start(values, flags); mode = va_arg(values, unsigned); va_end(values);
    }
    const int fd = __real_openat(parent, file, flags, mode);
    if ((flags & O_CREAT) && fd >= 0) temporary = fd;
    return fd;
}
extern "C" int __wrap_fsetxattr(int fd, const char* attribute, const void* value, size_t size, int flags) {
    require(fd == temporary && std::string(attribute) == "security.selinux" && flags == 0,
        "label boundary mismatch");
    require(size == 26 && !strcmp(static_cast<const char*>(value), "u:object_r:system_file:s0"), "label content");
    if (scenario == "label_failure") { errno = EPERM; return -1; }
    return 0; // Only SELinux xattr is a fixture; all file I/O uses the real FS.
}
extern "C" ssize_t __wrap_write(int fd, const void* data, size_t size) {
    if (fd != temporary) return __real_write(fd, data, size);
    ++write_calls;
    if (scenario == "write_failure") { errno = EIO; return -1; }
    if (scenario == "write_eintr" && write_calls == 1) { errno = EINTR; return -1; }
    if (scenario == "write_partial") size = std::min(size, size_t(7));
    return __real_write(fd, data, size);
}
extern "C" ssize_t __wrap_pread(int fd, void* data, size_t size, off_t offset) {
    ++read_calls;
    if (scenario == "read_failure") { errno = EIO; return -1; }
    if (scenario == "read_eintr" && read_calls == 1) { errno = EINTR; return -1; }
    if (scenario == "read_partial") size = std::min(size, size_t(7));
    const auto count = __real_pread(fd, data, size, offset);
    if (scenario == "read_mismatch" && count > 0) static_cast<unsigned char*>(data)[0] ^= 1;
    return count;
}
extern "C" int __wrap_fstat(int fd, struct stat* st) {
    const int result = __real_fstat(fd, st);
    if (!result && fd == temporary && read_calls && scenario == "length_mismatch") ++st->st_size;
    return result;
}
extern "C" int __wrap_fsync(int fd) {
    ++sync_calls;
    struct stat st{}; require(__real_fstat(fd, &st) == 0, "fsync fd");
    const bool is_directory = S_ISDIR(st.st_mode);
    if ((scenario == "file_fsync_failure" && !is_directory) ||
        (scenario == "directory_fsync_failure" && is_directory)) { errno = EIO; return -1; }
    if (scenario == "fsync_eintr" && sync_calls == 1) { errno = EINTR; return -1; }
    events.push_back(is_directory ? "directory_fsync" : "file_fsync");
    return __real_fsync(fd);
}
extern "C" int __wrap_renameat(int a, const char* b, int c, const char* d) {
    require(events == std::vector<std::string>{"file_fsync"}, "publication before data fsync");
    if (scenario == "rename_failure") { errno = EIO; return -1; }
    events.emplace_back("rename");
    return __real_renameat(a, b, c, d);
}
extern "C" int __wrap_close(int fd) {
    const int result = __real_close(fd);
    if (fd == temporary && scenario == "close_failure") { errno = EIO; return -1; }
    return result;
}

int main() {
    unsigned failed = 0;
    const std::vector<std::string> success{"success", "write_partial", "write_eintr", "read_partial",
        "read_eintr", "fsync_eintr", "stale_temporary", "temporary_symlink"};
    const std::vector<std::string> tests{"success", "write_partial", "write_eintr", "read_partial", "read_eintr",
        "fsync_eintr", "label_failure", "write_failure", "read_failure", "read_mismatch", "length_mismatch",
        "file_fsync_failure", "rename_failure", "directory_fsync_failure", "close_failure", "final_symlink",
        "final_hardlink", "final_foreign_owner", "parent_symlink", "root_symlink", "foreign_parent",
        "invalid_key", "invalid_module", "stale_temporary", "temporary_symlink"};
    for (const auto& test : tests) {
        try {
            reset(test);
            const auto temp = path + ".tmp." + std::to_string(getpid()) + ".0";
            const auto untouched = root + "/untouched";
            if (test == "stale_temporary") put(temp, old_bytes.data(), 64);
            if (test == "temporary_symlink") {
                put(untouched, old_bytes.data(), 64); symlink(untouched.c_str(), temp.c_str());
            }
            if (test == "final_symlink") { rename(path.c_str(), untouched.c_str()); symlink(untouched.c_str(), path.c_str()); }
            if (test == "final_hardlink") link(path.c_str(), untouched.c_str());
            if (test == "final_foreign_owner") chown(path.c_str(), 10513, 10513);
            if (test == "parent_symlink") {
                rename((root + "/storage").c_str(), (root + "/storage-real").c_str());
                symlink((root + "/storage-real").c_str(), (root + "/storage").c_str());
            }
            if (test == "root_symlink") {
                rename(root.c_str(), (root + "-real").c_str()); symlink((root + "-real").c_str(), root.c_str());
            }
            if (test == "foreign_parent") chown(directory.c_str(), 10513, 10513);
            const auto result = maplesu_store_su_retention(new_bytes.data(), new_bytes.size());
            const bool expected = std::find(success.begin(), success.end(), test) != success.end();
            require(!is_failed(result) == expected, "result disagrees with failure boundary");
            const auto observed = contents(path);
            const auto& wanted = expected || test == "directory_fsync_failure" ? new_bytes : old_bytes;
            require(observed == std::vector<unsigned char>(wanted.begin(), wanted.end()), "partial or lost ledger");
            if (expected) {
                struct stat st{}; require(stat(path.c_str(), &st) == 0 && (st.st_mode & 0777) == 0600 &&
                    st.st_uid == 0 && st.st_gid == 0 && st.st_nlink == 1 && st.st_size == 64, "inode contract");
                require(events == std::vector<std::string>{"file_fsync", "rename", "directory_fsync"}, "durability order");
            }
            if (test == "temporary_symlink") require(contents(untouched) ==
                std::vector<unsigned char>(old_bytes.begin(), old_bytes.end()), "temporary symlink followed");
            printf("PASS %s\n", test.c_str());
        } catch (const std::exception& error) { ++failed; printf("FAIL %s: %s\n", test.c_str(), error.what()); }
    }
    std::filesystem::remove_all(root); std::filesystem::remove_all(root + "-real");
    return failed ? 1 : 0;
}
