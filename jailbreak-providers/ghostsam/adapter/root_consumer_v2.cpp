// MapleSU self-built GhostSam consumer (V2) — design draft; build with NDK (not built in CI here).
// Wire: MJBL v2 BIG-ENDIAN identity frame; GhostSam 'A'+3 SCM_RIGHTS stdio; results R/F/P.
// Differences vs upstream V1: nonce read from STDIN (not argv); NEVER writes /sys/fs/selinux/enforce;
// restore is handed back to the GhostSam primitive (this consumer only reports observed baseline).
#include <array>
#include <cerrno>
#include <cstdint>
#include <cstddef>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

namespace {
constexpr uint32_t kMagic = 0x4D4A424Cu;
constexpr uint32_t kVersion = 2u;
constexpr uint32_t kCapRootWorker = 1u;

bool send_all(int fd, const void* data, size_t len) {
    const auto* p = static_cast<const unsigned char*>(data);
    while (len) { const ssize_t n = ::write(fd, p, len); if (n <= 0) return false; p += n; len -= static_cast<size_t>(n); }
    return true;
}
bool number(int fd, uint32_t v) {
    const std::array<unsigned char, 4> b{static_cast<unsigned char>(v >> 24), static_cast<unsigned char>(v >> 16),
                                         static_cast<unsigned char>(v >> 8), static_cast<unsigned char>(v)};
    return send_all(fd, b.data(), b.size());
}
bool field(int fd, const std::string& s) { return number(fd, static_cast<uint32_t>(s.size())) && send_all(fd, s.data(), s.size()); }

struct LeaseArgs { unsigned char nonce[32]; std::string endpoint, boot; uint32_t uid = 0; };

// stdin first packet is a TLV stream (t21 §4.3): [tag u8][len u16 BE][value] ... 0x00.
bool read_tlv_stdin(LeaseArgs& a) {
    unsigned char buf[4096];
    size_t total = 0;
    while (total < sizeof(buf)) {
        const ssize_t n = ::read(0, buf + total, sizeof(buf) - total);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) break;
        total += static_cast<size_t>(n);
        if (total && buf[total - 1] == 0x00) break;
    }
    size_t pos = 0; bool have_nonce = false, have_ep = false, have_uid = false, have_boot = false;
    while (pos < total) {
        const unsigned char tag = buf[pos++];
        if (tag == 0x00) return have_nonce && have_ep && have_uid && have_boot;
        if (pos + 2 > total) return false;
        const uint16_t len = static_cast<uint16_t>((buf[pos] << 8) | buf[pos + 1]); pos += 2;
        if (pos + len > total) return false;
        const unsigned char* v = buf + pos; pos += len;
        switch (tag) {
            case 0x01: if (len != 32) return false; std::memcpy(a.nonce, v, 32); have_nonce = true; break;
            case 0x02: a.endpoint.assign(reinterpret_cast<const char*>(v), len); have_ep = true; break;
            case 0x03: if (len != 4) return false; a.uid = (static_cast<uint32_t>(v[0]) << 24) | (v[1] << 16) | (v[2] << 8) | v[3]; have_uid = true; break;
            case 0x04: a.boot.assign(reinterpret_cast<const char*>(v), len); have_boot = true; break;
            default: return false;
        }
    }
    return have_nonce && have_ep && have_uid && have_boot;
}

// Field 22 of /proc/self/stat = process starttime in clock ticks (anti-pid-reuse).
// N1: /proc/<pid>/stat field 22 = starttime. The comm field (2) is in parentheses and may
// itself contain spaces or ')', so we must anchor on the LAST ')' and only then parse the
// remaining space-separated fields; field 3 is a state *character* (R/S/D), not a number.
uint64_t parse_self_starttime(const char* line) {
    if (!line) return 0;
    const char* p = std::strrchr(line, ')');
    if (!p) return 0;
    ++p;                         // past comm
    while (*p == ' ') ++p;
    while (*p && *p != ' ') ++p; // skip state character (field 3)
    uint64_t value = 0;
    for (int field = 4; field <= 22; ++field) {
        while (*p == ' ') ++p;
        char* end = nullptr;
        value = std::strtoull(p, &end, 10);
        if (end == p) return 0;
        p = end;
        if (field == 22) return value > 0 ? value : 0;
    }
    return 0;
}

bool read_self_starttime(uint64_t& out) {
    FILE* f = std::fopen("/proc/self/stat", "r");
    if (!f) return false;
    char line[1024];
    const size_t n = std::fread(line, 1, sizeof(line) - 1, f);
    std::fclose(f);
    if (n == 0) return false;
    line[n] = 0;
    const uint64_t value = parse_self_starttime(line);
    if (value == 0) return false;
    out = value;
    return true;
}

bool send_identity(int fd, uint32_t provider, uint32_t pid, uint64_t starttime, const unsigned char nonce[32],
                   const std::string& boot, const std::string& domain, int enforcing, int seccomp) {
    const uint32_t hi = static_cast<uint32_t>(starttime >> 32);
    const uint32_t lo = static_cast<uint32_t>(starttime & 0xffffffffu);
    return number(fd, kMagic) && number(fd, kVersion) && number(fd, provider) && number(fd, pid) && number(fd, 0u)
        && number(fd, hi) && number(fd, lo) && number(fd, kCapRootWorker)
        && send_all(fd, nonce, 32) && field(fd, boot) && field(fd, domain)
        && number(fd, static_cast<uint32_t>(enforcing)) && number(fd, static_cast<uint32_t>(seccomp));
}
bool send_ready(int fd, uint32_t child) { return send_all(fd, "R", 1) && number(fd, child); }
bool send_failure(int fd, unsigned char stage) { const std::array<unsigned char,5> f{'F', stage, 0,0,0}; return send_all(fd, f.data(), f.size()); }
// 'P' is exactly 10 bytes: applied,origin,enforcing,checkreqprot,policy + BE u32 unload_errno.
bool send_report(int fd, unsigned char applied, unsigned char origin, unsigned char enforcing,
                 unsigned char checkreqprot, unsigned char policy, int32_t unload_errno) {
    const std::array<unsigned char,10> f{'P', applied, origin, enforcing, checkreqprot, policy,
        static_cast<unsigned char>(unload_errno >> 24), static_cast<unsigned char>(unload_errno >> 16),
        static_cast<unsigned char>(unload_errno >> 8), static_cast<unsigned char>(unload_errno)};
    return send_all(fd, f.data(), f.size());
}
} // namespace

// argv: [0]=exe [1]=--fd-args [2?]=enforce  (NO nonce/endpoint/uid/boot in argv)
// stdin: TLV first packet carrying nonce/endpoint/uid/boot, then 'A'+3 SCM_RIGHTS stdio.
int main(int argc, char** argv) {
    // F2: V2 contract form --fd-args; all lease params arrive via stdin TLV, none in argv.
    if (argc < 2 || std::strcmp(argv[1], "--fd-args") != 0) return 2;
    if (getuid() != 0 || geteuid() != 0) return 3;                 // ROOT_WORKER
    uint64_t starttime = 0;
    if (!read_self_starttime(starttime)) return 12;                // LEASE_WORKER_STARTTIME_INVALID
    LeaseArgs a;
    if (!read_tlv_stdin(a)) return 4;                              // LEASE_TLV_INVALID
    const std::string endpoint = a.endpoint;
    const std::string boot = a.boot;
    const unsigned char* nonce = a.nonce;
    const std::string domain = "u:r:shell:s0";
    int sock = ::socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (sock < 0) { return 6; }
    sockaddr_un sun{}; sun.sun_family = AF_UNIX;
    sun.sun_path[0] = '\0'; std::memcpy(sun.sun_path + 1, endpoint.data(), endpoint.size());
    socklen_t len = static_cast<socklen_t>(offsetof(sockaddr_un, sun_path) + 1 + endpoint.size());
    if (::connect(sock, reinterpret_cast<sockaddr*>(&sun), len) != 0) { return 7; }
    ucred cred{}; socklen_t clen = sizeof(cred);
    if (::getsockopt(sock, SOL_SOCKET, SO_PEERCRED, &cred, &clen) != 0 || cred.uid != 0 || cred.pid <= 1) return 8;
    if (!send_identity(sock, 1u, static_cast<uint32_t>(::getpid()), starttime, nonce, boot, domain, 1, 0)) return 9;
    // (stdin 'A' + SCM_RIGHTS stdio admission and exec of u:r:shell:s0 sh omitted in this draft)
    // Report baseline observation only; restoration is handed back to the GhostSam primitive.
    if (!send_report(sock, /*applied=*/0, /*origin=*/0, /*enforcing=*/1, /*checkreqprot=*/0, /*policy=*/0, /*unload_errno=*/-1)) return 10;
    if (!send_ready(sock, static_cast<uint32_t>(::getpid()))) return 11;
    return 0;
}
