#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "boot_sdk_protocol.h"
#define CHECK(x) do { if (!(x)) { fprintf(stderr, "line=%d: %s\n", __LINE__, #x); exit(1); } } while (0)
static void encode(unsigned char *packet, const char *key, unsigned char op) {
    unsigned char body[18] = {0};
    body[0] = op; body[1] = 1;
    msu_sdk_store(body + 2, 0xffff800012345678ULL, 8);
    msu_sdk_store(body + 10, 4096, 4); msu_sdk_store(body + 14, 1, 4);
    memcpy(packet, key, 48); packet[84] = 0;
    for (unsigned n = 0; n < sizeof body; ++n) {
        packet[48 + n] = body[n] == 1 ? 2 : 1;
        packet[66 + n] = body[n] - packet[48 + n];
    }
}
int main(int argc, char **argv) {
    CHECK(argc == 2);
    if (!strcmp(argv[1], "packet")) {
        char key[49]; unsigned char packet[85]; memset(key, 'A', 48); key[48] = 0;
        CHECK(!msu_sdk_bind_key(key, 4096) && strlen(key) == 48);
        CHECK(msu_sdk_bind_key(key, 0) && msu_sdk_bind_key(key, 3) && msu_sdk_bind_key(key, 134217732L));
        for (unsigned char op = 0x30; op <= 0x35; ++op) {
            encode(packet, key, op);
            for (unsigned n = 0; n < 84; ++n) CHECK(packet[n]);
            CHECK(msu_sdk_decode(packet, key) == 1 && packet[66] == op && packet[67] == 1);
            CHECK(msu_sdk_le(packet + 68, 8) == 0xffff800012345678ULL);
            CHECK(msu_sdk_le(packet + 76, 4) == 4096 && msu_sdk_le(packet + 80, 4) == 1);
        }
        encode(packet, key, 0x33); unsigned char original = packet[66]; packet[0] ^= 1;
        CHECK(msu_sdk_decode(packet, key) == 0 && packet[66] == original);
        encode(packet, key, 0x33); packet[84] = 1; CHECK(msu_sdk_decode(packet, key) == -1);
        encode(packet, key, 0x36); CHECK(msu_sdk_decode(packet, key) == -1);
        return 0;
    }
    CHECK(!strcmp(argv[1], "range"));
#if ULONG_MAX > 0xffffffffUL
    unsigned long base = 0xffff800000000000UL, start = 0, end = 0;
    unsigned long low = base + 0x2000000UL, high = base + 0xffffffffUL;
    unsigned int offset = 0;
    CHECK(!msu_sdk_metadata_offset(base, base + 0xffffffffUL, &offset) && offset == 0xffffffffu);
    CHECK(msu_sdk_metadata_offset(base, base, &offset));
    CHECK(msu_sdk_metadata_offset(base, base - 1, &offset));
    CHECK(msu_sdk_metadata_offset(base, base + 0x100000000UL, &offset));
    CHECK(!msu_sdk_arena_range(base, 0x2000000, low, high, 4096, 66 * 4096, &start, &end));
    CHECK(start == low && end == (high & ~4095UL));
    CHECK(!msu_sdk_arena_range(base, 0x2000000, low, high, 4096, end - low - 4096, &start, &end));
    CHECK(msu_sdk_arena_range(base, 0x2000000, low, high, 4096, end - low, &start, &end));
    CHECK(msu_sdk_arena_range(base, 0x2000000, low + 1, high, 4096, 4096, &start, &end));
    CHECK(msu_sdk_arena_range(base, 0x2000000, low, high, 3000, 4096, &start, &end));
    CHECK(msu_sdk_arena_range(~0UL - 4095, 8192, low, high, 4096, 4096, &start, &end));
    CHECK(msu_sdk_arena_range(base, 0x2000000, base + 0x100000000UL,
        base + 0x200000000UL, 4096, 4096, &start, &end));
    return 0;
#else
    return 77; /* LP64 kernel address arithmetic needs an LP64 host. */
#endif
}
