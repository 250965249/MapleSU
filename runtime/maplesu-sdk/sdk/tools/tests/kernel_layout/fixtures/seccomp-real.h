#pragma once
// Exact target function ranges; see seccomp-real.json for provenance.
namespace layout_test {
struct RealSeccomp { const char* target; uint32_t offset; const uint8_t* bytes; size_t size; };
inline constexpr uint8_t seccomp_bytes_0[] = {0x3f, 0x23, 0x03, 0xd5, 0x08, 0x41, 0x38, 0xd5, 0x00, 0x49, 0x88, 0xb9, 0xbf, 0x23, 0x03, 0xd5, 0xc0, 0x03, 0x5f, 0xd6};
inline constexpr uint8_t seccomp_bytes_1[] = {0x08, 0x41, 0x38, 0xd5, 0x00, 0xe9, 0x88, 0xb9, 0xc0, 0x03, 0x5f, 0xd6, 0xd9, 0x34, 0x2b, 0xb0};
inline constexpr RealSeccomp real_seccomp[] = {
    {"android12-5.10-9465fbb7", 2120, seccomp_bytes_0, sizeof(seccomp_bytes_0)},
    {"android15-6.6-346d51ea", 2280, seccomp_bytes_1, sizeof(seccomp_bytes_1)},
};
}
