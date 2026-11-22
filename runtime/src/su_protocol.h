#pragma once
#include <array>
#include <cerrno>
#include <cstdint>
#include <cstring>
#include <fcntl.h>
#include <string>
#include <sys/socket.h>
#include <unistd.h>
#include <vector>

namespace maplesu {
constexpr uint32_t MAGIC = 0x4d535531;
// Module tool directory, mirroring KSU `defs.rs::BINARY_DIR`. KSU appends this to
// the interactive su PATH (`su.rs:318-319` add_path_to_env(defs::BINARY_DIR)), so a
// `su -c resetprop` resolves the bundled tool. It lives under the Root-only
// /data/adb tree, so it is not enumerable by non-Root callers.
constexpr const char* MODULE_BIN = "/data/adb/maplesu/bin";
// Installed application id of the manager. The published client derives its own
// APK and bootstrap library from /proc/self/exe and refuses any image that is not
// inside this product's application directory.
constexpr const char* MANAGER_PACKAGE = "dev.maplesu.manager";
constexpr const char* BOOTSTRAP_CLASS = "dev.maplesu.manager.runtime.NativeSuBootstrap";
constexpr size_t MAX_FRAME = 131072;
inline bool read_all(int fd, void* bytes, size_t size) {
    auto* out = static_cast<char*>(bytes);
    while (size) {
        const ssize_t count = read(fd, out, size);
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) return false;
        out += count; size -= static_cast<size_t>(count);
    }
    return true;
}
inline bool write_all(int fd, const void* bytes, size_t size) {
    const auto* in = static_cast<const char*>(bytes);
    while (size) {
        const ssize_t count = write(fd, in, size);
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) return false;
        in += count; size -= static_cast<size_t>(count);
    }
    return true;
}
inline bool read_u32(int fd, uint32_t& value) {
    unsigned char data[4];
    if (!read_all(fd, data, sizeof(data))) return false;
    value = (uint32_t(data[0]) << 24) | (uint32_t(data[1]) << 16) |
        (uint32_t(data[2]) << 8) | uint32_t(data[3]);
    return true;
}
inline bool write_u32(int fd, uint32_t value) {
    const unsigned char data[] = {static_cast<unsigned char>(value >> 24),
        static_cast<unsigned char>(value >> 16), static_cast<unsigned char>(value >> 8),
        static_cast<unsigned char>(value)};
    return write_all(fd, data, sizeof(data));
}
inline bool write_string(int fd, const std::string& value) {
    return value.size() <= MAX_FRAME && write_u32(fd, value.size()) &&
        write_all(fd, value.data(), value.size());
}
inline bool read_string(int fd, std::string& value, size_t& remaining) {
    uint32_t size;
    if (!read_u32(fd, size) || size > remaining || size > MAX_FRAME) return false;
    remaining -= size;
    value.resize(size);
    return read_all(fd, value.data(), value.size()) && value.find('\0') == std::string::npos;
}
inline bool send_fds(int socket, char tag, const int* descriptors, size_t count) {
    if (count == 0 || count > 3) return false;
    alignas(cmsghdr) unsigned char ancillary[CMSG_SPACE(3 * sizeof(int))]{};
    iovec data{&tag, 1};
    msghdr message{};
    message.msg_iov = &data; message.msg_iovlen = 1;
    message.msg_control = ancillary; message.msg_controllen = CMSG_SPACE(count * sizeof(int));
    cmsghdr* header = CMSG_FIRSTHDR(&message);
    header->cmsg_level = SOL_SOCKET; header->cmsg_type = SCM_RIGHTS;
    header->cmsg_len = CMSG_LEN(count * sizeof(int));
    memcpy(CMSG_DATA(header), descriptors, count * sizeof(int));
    ssize_t result;
    do { result = sendmsg(socket, &message, MSG_NOSIGNAL); } while (result < 0 && errno == EINTR);
    return result == 1;
}
inline bool receive_fds(int socket, char tag, int* descriptors, size_t expected) {
    alignas(cmsghdr) unsigned char ancillary[CMSG_SPACE(16 * sizeof(int))]{};
    char received = 0;
    iovec data{&received, 1};
    msghdr message{};
    message.msg_iov = &data; message.msg_iovlen = 1;
    message.msg_control = ancillary; message.msg_controllen = sizeof(ancillary);
    ssize_t result;
    do { result = recvmsg(socket, &message, MSG_CMSG_CLOEXEC); } while (result < 0 && errno == EINTR);
    std::vector<int> found;
    bool valid = result == 1 && received == tag && !(message.msg_flags & (MSG_CTRUNC | MSG_TRUNC));
    for (cmsghdr* header = CMSG_FIRSTHDR(&message); header; header = CMSG_NXTHDR(&message, header)) {
        if (header->cmsg_level != SOL_SOCKET || header->cmsg_type != SCM_RIGHTS ||
            header->cmsg_len < CMSG_LEN(0)) { valid = false; continue; }
        const size_t size = header->cmsg_len - CMSG_LEN(0);
        if (size % sizeof(int)) valid = false;
        for (size_t offset = 0; offset + sizeof(int) <= size; offset += sizeof(int)) {
            int fd; memcpy(&fd, CMSG_DATA(header) + offset, sizeof(fd)); found.push_back(fd);
        }
    }
    valid = valid && found.size() == expected;
    if (!valid) { for (int fd : found) close(fd); return false; }
    for (size_t i = 0; i < expected; ++i) descriptors[i] = found[i];
    return true;
}
struct SuRequest {
    uint32_t terminals = 0, uid = 0, global_mount = 0;
    std::array<uint32_t, 4> window{};
    std::string executable, directory;
    std::vector<std::string> arguments, environment;
    bool write_to(int fd) const {
        if (!write_u32(fd, MAGIC) || !write_u32(fd, terminals) || !write_u32(fd, uid) || !write_u32(fd, global_mount)) return false;
        for (auto value : window) if (!write_u32(fd, value)) return false;
        if (!write_string(fd, executable) || !write_string(fd, directory) || !write_u32(fd, arguments.size())) return false;
        for (const auto& value : arguments) if (!write_string(fd, value)) return false;
        if (!write_u32(fd, environment.size())) return false;
        for (const auto& value : environment) if (!write_string(fd, value)) return false;
        return true;
    }
    bool read_from(int fd) {
        uint32_t magic, count; size_t remaining = MAX_FRAME;
        if (!read_u32(fd, magic) || magic != MAGIC || !read_u32(fd, terminals) || terminals > 7 ||
            !read_u32(fd, uid) || !read_u32(fd, global_mount) || global_mount > 1) return false;
        for (auto& value : window) if (!read_u32(fd, value) || value > 65535) return false;
        if (!read_string(fd, executable, remaining) || executable.empty() || executable[0] != '/' || !read_string(fd, directory, remaining) || directory.empty() || directory[0] != '/' ||
            !read_u32(fd, count) || count == 0 || count > 256) return false;
        arguments.resize(count);
        for (auto& value : arguments) if (!read_string(fd, value, remaining)) return false;
        if (arguments[0].empty() || !read_u32(fd, count) || count > 512) return false;
        environment.resize(count);
        for (auto& value : environment)
            if (!read_string(fd, value, remaining) || value.find('=') == std::string::npos || value[0] == '=') return false;
        return true;
    }
};
int su_session(int control, bool gated);
}
