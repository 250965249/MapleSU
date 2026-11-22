// SPDX-License-Identifier: GPL-3.0-only
#include "../../module-policy/src/boot_sdk_layout.h"
#include <algorithm>
#include <array>
#include <cerrno>
#include <cstdarg>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <stdexcept>
#include <string>
#include <unistd.h>
#include <vector>

int boot_sdk_control(int, char**);
extern "C" int __real_open(const char*, int, ...);
extern "C" FILE* __real_fopen(const char*, const char*);
extern "C" FILE* __real_fopen64(const char*, const char*);
extern "C" ssize_t __real_read(int, void*, size_t);
extern "C" int __real_close(int);

namespace {
std::string scenario;
std::vector<unsigned> commands;
size_t available = 8, consumed = 0;
int tracked = -1, opened = 0, closed = 0, reads = 0, resolved = 0;
bool interrupted = false;
void require(bool condition, const char* reason) {
    if (!condition) throw std::runtime_error(reason);
}
bool btf_path(const char* path) { return !strcmp(path, "/sys/kernel/btf/vmlinux"); }
int fixture_fd() {
    ++opened;
    if (scenario == "missing" || scenario == "denied" || scenario == "open-interrupted") {
        errno = scenario == "missing" ? ENOENT : scenario == "denied" ? EACCES : EINTR;
        return -1;
    }
    // A real seekable sparse file also exercises the old std::ifstream path.
    FILE* file = tmpfile();
    require(file, "TMPFILE");
    require(!ftruncate(fileno(file), available), "TRUNCATE");
    tracked = dup(fileno(file));
    fclose(file);
    require(tracked >= 0, "DUP");
    return tracked;
}
void ready(msu_boot_sdk_request* request) {
    request->state = MSU_BOOT_SDK_READY;
    request->capabilities = 3;
    request->kernel_base = 0xffff800000000000ull;
    memset(request->key, 'A', MSU_BOOT_SDK_KEY_BYTES);
}
}

extern "C" int __wrap_open(const char* path, int flags, ...) {
    if (btf_path(path)) return fixture_fd();
    mode_t mode = 0;
    if (flags & O_CREAT) {
        va_list args; va_start(args, flags); mode = va_arg(args, int); va_end(args);
    }
    return __real_open(path, flags, mode);
}
extern "C" FILE* __wrap_fopen(const char* path, const char* mode) {
    if (!btf_path(path)) return __real_fopen(path, mode);
    int fd = fixture_fd();
    return fd < 0 ? nullptr : fdopen(fd, mode);
}
extern "C" FILE* __wrap_fopen64(const char* path, const char* mode) {
    if (!btf_path(path)) return __real_fopen64(path, mode);
    int fd = fixture_fd();
    return fd < 0 ? nullptr : fdopen(fd, mode);
}
extern "C" ssize_t __wrap_read(int fd, void* data, size_t bytes) {
    if (fd != tracked) return __real_read(fd, data, bytes);
    ++reads;
    if (scenario == "read-interrupted" && !interrupted) {
        interrupted = true; errno = EINTR; return -1;
    }
    if (scenario == "read-error" && consumed) { errno = EIO; return -1; }
    const size_t count = std::min(bytes, available - consumed);
    memset(data, 0, count);
    consumed += count;
    return static_cast<ssize_t>(count);
}
extern "C" int __wrap_close(int fd) {
    if (fd == tracked) { ++closed; tracked = -1; }
    return __real_close(fd);
}
extern "C" uid_t __wrap_getuid() { return 0; }
extern "C" uid_t __wrap_geteuid() { return 0; }
extern "C" long __wrap_sysconf(int) { return 4096; }
extern "C" int __wrap_prctl(int option, ...) {
    va_list args; va_start(args, option);
    (void)va_arg(args, unsigned long); (void)va_arg(args, unsigned long);
    (void)va_arg(args, unsigned long);
    auto* request = va_arg(args, msu_boot_sdk_request*); va_end(args);
    commands.push_back(request->command);
    if (scenario == "transport-interrupted") { errno = EINTR; return -1; }
    request->status = 0;
    if (request->command == MSU_BOOT_SDK_QUERY) {
        request->state = MSU_BOOT_SDK_EMPTY;
        request->padding[0] = 1;
        if (scenario == "info-ready" || scenario == "start-ready") ready(request);
        if (scenario == "start-failed") request->state = MSU_BOOT_SDK_FAILED;
        if (scenario == "start-initializing") request->state = MSU_BOOT_SDK_INITIALIZING;
        if (scenario == "start-configured") request->padding[2] = 1;
        if (scenario == "start-static") request->padding[0] = 0;
        if (scenario == "query-error") request->status = -13;
    } else if (request->command == MSU_BOOT_SDK_CONFIGURE) {
        require(closed == 1, "CONFIGURE_BEFORE_SOURCE_CLOSE");
        if (scenario == "clean-retry" || scenario == "dirty-no-retry") {
            static_assert(offsetof(msu_boot_sdk_configuration, reply) == 0);
            const auto* configuration = reinterpret_cast<const msu_boot_sdk_configuration*>(request);
            require(bool(configuration->layout.allocator_noprof & MSU_BOOT_SDK_ALLOCATOR_INNER) ==
                (commands.size() == 2), "RETRY_ALLOCATOR_PAYLOAD");
        }
        if (scenario == "config-error" || scenario == "clean-retry" || scenario == "dirty-no-retry") {
            request->status = -61;
            request->padding[3] = MSU_BS_CONFIG_CAPTURE;
            request->state = MSU_BOOT_SDK_EMPTY;
            if (scenario == "dirty-no-retry") request->padding[2] = 1;
            if (scenario == "clean-retry" && commands.size() == 3) request->status = 0;
        }
    } else if (request->command == MSU_BOOT_SDK_BOOTSTRAP) ready(request);
    if (scenario == "bad-response") request->reserved = 1;
    return 0;
}

msu_boot_sdk_layout resolve_boot_sdk_layout(const std::vector<uint8_t>& input,
    uint32_t page, bool, bool, bool) {
    ++resolved;
    require(closed == 1, "RESOLVE_BEFORE_SOURCE_CLOSE");
    require(input.size() == available && page == 4096, "RESOLVER_INPUT");
    if (scenario == "invalid-btf") throw std::runtime_error("MODULE_POLICY_LAYOUT_BTF_HEADER");
    msu_boot_sdk_layout layout{};
    if (scenario == "clean-retry" || scenario == "dirty-no-retry")
        layout.allocator_noprof = MSU_BOOT_SDK_ALLOCATOR_INNER;
    return layout;
}

int main(int argc, char** argv) {
    if (argc != 2) return 2;
    scenario = argv[1];
    if (scenario == "empty") available = 0;
    if (scenario == "limit" || scenario == "oversize") available = 64u * 1024 * 1024 + (scenario == "oversize");
    if (scenario == "read-error") available = 65537;
    const bool info = scenario.rfind("info-", 0) == 0;
    char command[] = "boot-sdk-start", info_command[] = "boot-sdk-info", name[] = "probe";
    char* arguments[] = {name, info ? info_command : command};
    std::string error;
    try { boot_sdk_control(2, arguments); }
    catch (const std::runtime_error& exception) { error = exception.what(); }
    try {
        std::string expected;
        if (scenario == "missing") expected = "BOOT_SDK_BTF_UNAVAILABLE:2";
        if (scenario == "denied") expected = "BOOT_SDK_BTF_OPEN:13";
        if (scenario == "open-interrupted") expected = "BOOT_SDK_BTF_OPEN:4";
        if (scenario == "empty") expected = "BOOT_SDK_BTF_EMPTY";
        if (scenario == "read-error") expected = "BOOT_SDK_BTF_READ:5";
        if (scenario == "oversize") expected = "BOOT_SDK_BTF_SIZE";
        if (scenario == "invalid-btf") expected = "MODULE_POLICY_LAYOUT_BTF_HEADER";
        if (scenario == "config-error" || scenario == "dirty-no-retry") expected = "BOOT_SDK_CONFIG_CAPTURE:-61";
        if (scenario == "transport-interrupted") expected = "BOOT_SDK_TRANSPORT:4";
        if (scenario == "bad-response") expected = "BOOT_SDK_RESPONSE";
        if (error != expected) {
            fprintf(stderr, "error=%s expected=%s opened=%d reads=%d\n", error.c_str(), expected.c_str(), opened, reads);
            throw std::runtime_error("ERROR_MISMATCH");
        }
        const bool no_layout = info || scenario == "start-ready" || scenario == "start-failed" ||
            scenario == "start-initializing" || scenario == "start-configured" || scenario == "start-static" ||
            scenario == "query-error" || scenario == "transport-interrupted" || scenario == "bad-response";
        require(opened == (no_layout ? 0 : 1), "SOURCE_OPEN_COUNT");
        if (!expected.empty() && scenario != "config-error" && scenario != "dirty-no-retry")
            require(commands == std::vector<unsigned>{MSU_BOOT_SDK_QUERY}, "FAILED_SOURCE_TRANSACTED");
        if (no_layout) {
            const bool bootstrap = scenario == "start-configured" || scenario == "start-static";
            require(commands == (bootstrap ? std::vector<unsigned>{MSU_BOOT_SDK_QUERY, MSU_BOOT_SDK_BOOTSTRAP}
                                          : std::vector<unsigned>{MSU_BOOT_SDK_QUERY}), "STATE_COMMANDS");
            require(resolved == 0, "UNNEEDED_RESOLVE");
        } else if (expected.empty()) {
            require(commands == (scenario == "clean-retry"
                ? std::vector<unsigned>{MSU_BOOT_SDK_QUERY, MSU_BOOT_SDK_CONFIGURE, MSU_BOOT_SDK_CONFIGURE, MSU_BOOT_SDK_BOOTSTRAP}
                : std::vector<unsigned>{MSU_BOOT_SDK_QUERY, MSU_BOOT_SDK_CONFIGURE, MSU_BOOT_SDK_BOOTSTRAP}), "SUCCESS_COMMANDS");
            require(resolved == 1, "RESOLVE_COUNT");
        } else if (scenario == "config-error" || scenario == "dirty-no-retry") {
            require(commands == std::vector<unsigned>{MSU_BOOT_SDK_QUERY, MSU_BOOT_SDK_CONFIGURE}, "RETRY_WITH_DIRTY_STATE");
        }
        if (!no_layout && scenario != "missing" && scenario != "denied" && scenario != "open-interrupted")
            require(closed == 1, "SOURCE_CLOSE_COUNT");
        if (scenario == "read-interrupted") require(interrupted && reads >= 3, "READ_EINTR_NOT_EXERCISED");
        printf("PASS %s commands=%zu opened=%d closed=%d reads=%d\n", scenario.c_str(), commands.size(), opened, closed, reads);
        return 0;
    } catch (const std::runtime_error& exception) {
        fprintf(stderr, "FAIL %s %s\n", scenario.c_str(), exception.what()); return 1;
    }
}
