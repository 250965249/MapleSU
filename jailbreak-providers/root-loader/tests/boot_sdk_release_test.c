#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "boot_sdk_protocol.h"
#define CHECK(x) do { if (!(x)) { fprintf(stderr, "line=%d: %s\n", __LINE__, #x); exit(1); } } while (0)
#define MSU_PH_NOCFI
#define MSU_BS_PAGE_BYTES 4096u
#define MSU_BS_ARENA_PAGES 66u
typedef uintptr_t uptr;
typedef unsigned int u32;
typedef unsigned long long u64;
struct stage { uptr address; u32 bytes, pages, written, quarantined; };
static struct stage stages[64];
static unsigned char allocation[MSU_BS_PAGE_BYTES];
static unsigned releases, native_releases, nx_calls, rw_calls;
static int fail_nx;
static uptr arena;
static void sdk_module_free(const void *address);
static void native_free(const void *address) {
    CHECK(address != NULL);
    ++native_releases;
}
static uptr lookup_name(const char *name) {
    if (!strcmp(name, "module_memfree") || !strcmp(name, "execmem_free"))
        return (uptr)native_free;
    return 0x12345678;
}
static void *allocate(unsigned long bytes) {
    CHECK(bytes == sizeof allocation);
    return allocation;
}
static void release(const void *address) {
    CHECK(address == allocation);
    ++releases;
}
static void (*release_module)(const void *) = native_free;
static int memory_nx(uptr address, int pages) {
    CHECK(address == (uptr)allocation && pages == 1);
    ++nx_calls;
    return fail_nx ? -1 : 0;
}
static int memory_rw(uptr address, int pages) {
    CHECK(address == (uptr)allocation && pages == 1);
    ++rw_calls;
    return 0;
}
static long read_kernel(void *to, const void *from, unsigned long bytes) {
    memcpy(to, from, bytes); return 0;
}
static long write_kernel(void *to, const void *from, unsigned long bytes) {
    memcpy(to, from, bytes); return 0;
}
static u64 execute(struct stage *s, unsigned char *packet) {
    (void)s; (void)packet; return 0;
}
#include "boot_sdk_release.inc"
static uptr allocate_stage(void) {
    unsigned char packet[85] = {0};
    packet[66] = 0x30;
    msu_sdk_store(packet + 76, sizeof allocation, 4);
    uptr address = (uptr)dispatch(packet);
    CHECK(address == (uptr)allocation && owned(address) != NULL);
    return address;
}
int main(int argc, char **argv) {
    CHECK(argc == 3);
    void (*jit_release)(const void *) = (void (*)(const void *))sdk_lookup(argv[1]);
    if (!strcmp(argv[2], "untracked")) {
        jit_release((const void *)0x1000);
        CHECK(native_releases == 1 && !releases && !nx_calls);
        CHECK(sdk_lookup("unrelated_symbol") == lookup_name("unrelated_symbol"));
        return 0;
    }
    uptr address = allocate_stage();
    unsigned nx_before = nx_calls;
    if (!strcmp(argv[2], "interior")) {
        jit_release((const void *)(address + 4));
        CHECK(owned(address) == &stages[0] && !releases && !native_releases);
        CHECK(nx_calls == nx_before && !rw_calls);
        return 0;
    }
    if (!strcmp(argv[2], "protection-failed")) {
        fail_nx = 1;
        jit_release((const void *)address);
        CHECK(owned(address) == &stages[0] && stages[0].quarantined);
        CHECK(!releases && !native_releases && !rw_calls);
        return 0;
    }
    jit_release((const void *)address);
    CHECK(owned(address) == NULL); /* Native free must not leave a stale ledger slot. */
    CHECK(releases == 1 && !native_releases && nx_calls == nx_before + 1 && rw_calls == 1);
    CHECK(allocate_stage() == address && owned(address) == &stages[0]);
    unsigned char packet[85] = {0};
    packet[66] = 0x35;
    msu_sdk_store(packet + 68, address, 8);
    CHECK(dispatch(packet) == 0 && owned(address) == NULL && releases == 2);
    CHECK(dispatch(packet) == (u64)-19999 && releases == 2 && !native_releases);
    return 0;
}
