#include <stdint.h>

extern "C" __attribute__((visibility("hidden")))
int64_t maplesu_raw_execute(const uint8_t*, uint32_t, uint64_t&);

// Pinned SDK no-result callback frame. x17 is the reply slot for this request;
// securebits is 24 bytes after it. Never retain a cred pointer between requests.
// The no-result epilogue leaves the restored value intact.
extern "C" __attribute__((visibility("hidden")))
int64_t maplesu_restore_securebits(uint32_t saved) {
    const uint32_t frame[] = {
        0xd503245fu, 0xa9bf53f3u, 0xa9bf5bf5u, 0xa9bf63f7u, 0xa9bf6bf9u, 0xa9bf73fbu,
        0xf844416au, 0xb9404d6cu, 0xb940516du, 0xa9bf33eau, 0xa9bf47edu, 0xa9bf7bfdu,
        0x14000011u, 0x57593530u, 0x76476174u, 0x4f764364u, 0x52523038u, 0x7577354bu,
        0x69506c59u, 0x686b3550u, 0x59386c6cu, 0x50344a63u, 0x4c477a32u, 0x49463335u,
        0x4756394bu, 0x474a4533u, 0x30325942u, 0x7a436b76u, 0x004f6b31u, 0x5282468au,
        0x72a0000au, 0xb9001a2au, 0x14000011u, 0x6a417443u, 0x736c6747u, 0x30387264u,
        0x6d544c71u, 0x58617947u, 0x6f4d424du, 0x39414572u, 0x4d326374u, 0x32366c6cu,
        0x69637754u, 0x43365366u, 0x456f6a75u, 0x4a5a7a52u, 0x51747756u, 0x58336c74u,
        0x00433032u, 0xa8c17bfdu, 0xa8c147edu, 0xa8c133eau, 0xa8c173fbu, 0xa8c16bf9u,
        0xa8c163f7u, 0xa8c15bf5u, 0xa8c153f3u, 0xd65f03c0u,
    };
    uint32_t code[sizeof(frame) / sizeof(frame[0])];
    for (unsigned i = 0; i < sizeof(frame) / sizeof(frame[0]); ++i) code[i] = frame[i];
    code[29] = 0x5280000au | ((saved & 0xffffu) << 5);
    code[30] = 0x72a0000au | ((saved >> 16) << 5);
    uint64_t ignored = 0;
    return maplesu_raw_execute(reinterpret_cast<const uint8_t*>(code), sizeof(code), ignored);
}
