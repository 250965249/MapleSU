// Device-side read-only probe for the fixed prebuilt Ultra SDK.
//
// Purpose: prove on an actual Android device that the imported archive links, loads and
// executes, and report the SDK's self-declared version plus the host's SELinux/seccomp
// state. It activates no environment, installs no module, needs no root key and writes
// nothing.
//
// Output is one JSON object on stdout so a caller can record it verbatim as evidence.
// Exit code 0 means the probe ran; it does not mean a Ultra environment exists.

#include <fcntl.h>
#include <unistd.h>

#include <cstdio>
#include <cstdlib>
#include <cstring>

#include "kernel_module_kit_umbrella.h"

namespace {

int read_first_int(const char* path, int* out) {
    const int fd = open(path, O_RDONLY);
    if (fd < 0) return 0;
    char buffer[32] = {0};
    const ssize_t count = read(fd, buffer, sizeof(buffer) - 1);
    close(fd);
    if (count <= 0) return 0;
    if (buffer[0] < '0' || buffer[0] > '9') return 0;
    *out = std::atoi(buffer);
    return 1;
}

int seccomp_status() {
    const int fd = open("/proc/self/status", O_RDONLY);
    if (fd < 0) return -1;
    char buffer[8192];
    const ssize_t count = read(fd, buffer, sizeof(buffer) - 1);
    close(fd);
    if (count <= 0) return -1;
    buffer[count] = '\0';
    const char* field = std::strstr(buffer, "Seccomp:");
    if (field == nullptr) return -1;
    field += std::strlen("Seccomp:");
    while (*field == ' ' || *field == '\t') ++field;
    if (*field < '0' || *field > '9') return -1;
    return std::atoi(field);
}

}  // namespace

int main() {
    const maplesu::sdk::MapleSUSdkVersion version = maplesu::sdk::get_sdk_version();

    int selinux = -1;
    const bool selinux_readable = read_first_int("/sys/fs/selinux/enforce", &selinux) == 1;
    const int seccomp = seccomp_status();

    std::printf(
        "{\"probe\":\"maplesu-ultra-version\",\"schemaVersion\":1,"
        "\"sdkVersion\":\"%u.%u.%u\",\"sdkMajor\":%u,\"sdkMinor\":%u,\"sdkPatch\":%u,"
        "\"selinuxReadable\":%s,\"selinuxEnforce\":%d,\"selinuxEnforcing\":%s,"
        "\"seccomp\":%d}\n",
        version.major, version.minor, version.patch,
        version.major, version.minor, version.patch,
        selinux_readable ? "true" : "false",
        selinux,
        (selinux_readable && selinux == 1) ? "true" : "false",
        seccomp);
    return 0;
}
