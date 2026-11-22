/* Host fixtures around the production dispatcher; no generated kernel code runs. */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "boot_sdk_protocol.h"
#include "legacy_hook_private.h"
#define CHECK(x) do { if (!(x)) { fprintf(stderr, "line=%d: %s\n", __LINE__, #x); exit(1); } } while (0)
#define MSU_PH_NOCFI
#define MSU_BOOT_SDK_NATIVE 1
#define current current_task()
#define MSU_SDK_CODE_ENTRY 0UL
#define MSU_BS_PAGE_BYTES 4096u
#define MSU_BS_ARENA_PAGES 66u
#define MSU_BS_CRED_SUID 16u
#define MSU_BS_CRED_SECUREBITS 40u
typedef uintptr_t uptr;
typedef unsigned int u32;
typedef unsigned long long u64;
static unsigned char *live;
static unsigned long live_bytes;
static unsigned char external_data[8], credentials[64], changed_credentials[64];
static uptr active_cred = (uptr)credentials;
static unsigned allocations, releases, native_releases, calls, held, dropped;
static int writable, nx_error, ro_error, x_error, change_cred;
static unsigned scope_gets, scope_puts, scope_binds, scope_begins, scope_ends;
static int scope_end_error, scope_enabled, scope_lease;
static struct maplesu_legacy_hook_provider scope_provider;
static uptr arena;
static void *fixture_allocate(unsigned long bytes) {
    CHECK(!live); live = malloc(bytes); CHECK(live);
    memset(live, 0xa5, bytes); live_bytes = bytes; writable = 1; ++allocations;
    return live;
}
static void fixture_release(const void *at) {
    CHECK(at == live); free(live); live = NULL; ++releases;
}
static void fixture_native_release(const void *at) {
    CHECK(at == external_data); ++native_releases;
}
static int memory_nx(uptr at, int pages) {
    CHECK(at == (uptr)live && pages == (int)(live_bytes / MSU_BS_PAGE_BYTES));
    return nx_error;
}
static int memory_rw(uptr at, int pages) {
    CHECK(at == (uptr)live && pages == (int)(live_bytes / MSU_BS_PAGE_BYTES)); writable = 1; return 0;
}
static int memory_ro(uptr at, int pages) {
    CHECK(at == (uptr)live && pages == (int)(live_bytes / MSU_BS_PAGE_BYTES));
    if (ro_error) return ro_error;
    writable = 0; return 0;
}
static int memory_x(uptr at, int pages) {
    CHECK(at == (uptr)live && pages == (int)(live_bytes / MSU_BS_PAGE_BYTES)); return x_error;
}
static long read_kernel(void *to, const void *from, unsigned long size) {
    if (size != 1 || from != external_data) return -14;
    memcpy(to, from, size); return 0;
}
static long write_kernel(void *to, const void *from, unsigned long size) {
    uptr at = (uptr)to;
    if (size != 1 || !((live && writable && at >= (uptr)live && at - (uptr)live < live_bytes) ||
        (at >= (uptr)external_data && at - (uptr)external_data < sizeof external_data))) return -14;
    memcpy(to, from, size); return 0;
}
static void flush_code(uptr start, uptr end) { CHECK(start == (uptr)live && end > start); }
static uptr current_task(void) { return 123; }
static uptr current_cred(void) { return active_cred; }
static void *hold_cred(void *task) { CHECK((uptr)task == current_task()); ++held; return credentials; }
static void put_held_cred(uptr cred) { CHECK(cred == (uptr)credentials); ++dropped; }
static int private_cred(void) { return 0; }
static uptr lookup_name(const char *name) { CHECK(!strcmp(name, "native")); return 1234; }
static void *(*allocate)(unsigned long) = fixture_allocate;
static void (*release)(const void *) = fixture_release;
static void (*release_module)(const void *) = fixture_native_release;
/* This include is generated from real definitions, not a dispatcher replica. */
#include "boot_sdk_stage.inc"

static u64 scope_bind(u64 address, u64 size) {
    CHECK(address == (uptr)msu_boot_sdk_legacy_scope_start && size &&
        address + size == (uptr)msu_boot_sdk_legacy_scope_end);
    ++scope_binds; return 123;
}
static u64 scope_begin(u64 token) { CHECK(token == 123); ++scope_begins; return 456; }
static int scope_end(u64 token) { CHECK(token == 456); ++scope_ends; return scope_end_error; }
static int scope_get(const struct maplesu_legacy_hook_provider **provider, void **lease) {
    ++scope_gets; *provider = &scope_provider; *lease = &scope_lease; return 0;
}
static void scope_put(void *lease) { CHECK(lease == &scope_lease); ++scope_puts; }
static void enable_scope(void) {
    scope_enabled = 1;
    scope_provider = (struct maplesu_legacy_hook_provider){
        .magic = MAPLESU_LEGACY_HOOK_MAGIC, .schema = MAPLESU_LEGACY_HOOK_SCHEMA,
        .length = sizeof scope_provider, .bind_function = (uptr)scope_bind,
        .begin_function = (uptr)scope_begin, .end_function = (uptr)scope_end,
        .dispatch_function = 1 };
    legacy_provider_get = scope_get; legacy_provider_put = scope_put;
}

static void fixture_jit(uptr address, const void *packet, void *reply) {
    const unsigned char *p = packet;
    CHECK(address == (uptr)live && !writable && p[66] == 0x33);
    CHECK(reply == credentials + MSU_BS_CRED_SUID);
    if (scope_enabled) CHECK(scope_gets == 1 && scope_begins == 1 && !scope_ends && !scope_puts);
    for (unsigned long n = 8; n < live_bytes; ++n) CHECK(!live[n]);
    msu_sdk_store(reply, 0x123456789abcde00ULL, 8); ++calls;
    if (change_cred) {
        msu_sdk_store(credentials + MSU_BS_CRED_SECUREBITS, 0x7654, 4);
        active_cred = (uptr)changed_credentials;
    }
}
static u64 request(unsigned char op, uptr address, u32 bytes, u32 pages, unsigned char value) {
    unsigned char packet[MSU_BOOT_SDK_PACKET_BYTES] = {0};
    packet[66] = op; packet[67] = value;
    msu_sdk_store(packet + 68, address, 8);
    msu_sdk_store(packet + 76, bytes, 4);
    msu_sdk_store(packet + 80, pages, 4);
    return dispatch(packet);
}
static uptr stage(void) {
    uptr at = request(0x30, 0, MSU_BS_PAGE_BYTES, 1, 0);
    CHECK(at == (uptr)live && owned(at));
    for (unsigned n = 0; n < MSU_BS_PAGE_BYTES; ++n) CHECK(!live[n]);
    return at;
}
static void upload(uptr at, unsigned bytes) {
    for (unsigned n = 0; n < bytes; ++n) CHECK(!request(0x31, at + n, 0, 0, n + 1));
}
int main(int argc, char **argv) {
    CHECK(argc == 2); arena = (uptr)fixture_jit;
    const char *name = argv[1];
    if (!strcmp(name, "rounded") || !strcmp(name, "credentials")) {
        uptr at = stage(); upload(at, 8); change_cred = !strcmp(name, "credentials");
        CHECK(request(0x33, at, MSU_BS_PAGE_BYTES, 1, 0) == 0x123456789abcde00ULL);
        CHECK(calls == 1 && held == 1 && dropped == 1 && releases == 1 && !owned(at));
        if (change_cred) CHECK(msu_sdk_le(changed_credentials + MSU_BS_CRED_SECUREBITS, 4) == 0x7654);
    } else if (!strcmp(name, "rewrite")) {
        uptr at = stage(); upload(at, 8);
        CHECK(!request(0x31, at, 0, 0, 42) && live[0] == 42 && owned(at)->written == 8);
        CHECK(!request(0x31, at + 4, 0, 0, 24) && live[4] == 24 && owned(at)->written == 8);
        CHECK(request(0x33, at, MSU_BS_PAGE_BYTES, 1, 0) == 0x123456789abcde00ULL);
    } else if (!strcmp(name, "rw-state")) {
        CHECK(!request(0x31, (uptr)external_data, 0, 0, 12) && external_data[0] == 12);
        CHECK(!request(0x31, (uptr)external_data, 0, 0, 13));
        CHECK(request(0x32, (uptr)external_data, 0, 0, 0) == 13);
        CHECK(request(0x31, 0, 0, 0, 1) == (u64)-19999);
        uptr at = stage(); upload(at, 8); CHECK(!memory_ro(at, 1));
        CHECK(request(0x31, at, 0, 0, 99) == (u64)-19999 && live[0] == 1);
        CHECK(!request(0x35, at, 0, 0, 0));
    } else if (!strcmp(name, "free-reuse")) {
        CHECK(sdk_lookup("module_memfree") == (uptr)sdk_module_free && sdk_lookup("native") == 1234);
        for (unsigned n = 0; n < 80; ++n) {
            uptr at = stage(); sdk_module_free((void *)(at + 1)); CHECK(live);
            sdk_module_free((void *)at); CHECK(!live && !owned(at));
        }
        CHECK(allocations == 80 && releases == 80 && !native_releases);
        sdk_module_free(external_data); CHECK(native_releases == 1);
    } else if (!strcmp(name, "scope-error") || !strcmp(name, "scope-discard-error")) {
        uptr at = stage(); upload(at, 8); enable_scope(); scope_end_error = -116;
        if (!strcmp(name, "scope-discard-error")) nx_error = -5;
        CHECK(request(0x33, at, MSU_BS_PAGE_BYTES, 1, 0) == (u64)-19999);
        CHECK(calls == 1 && held == 1 && dropped == 1 && scope_gets == 1 &&
            scope_binds == 1 && scope_begins == 1 && scope_ends == 1 && scope_puts == 1);
        if (nx_error) {
            CHECK(!releases && owned(at)->quarantined);
            CHECK(request(0x33, at, MSU_BS_PAGE_BYTES, 1, 0) == (u64)-19999 && calls == 1);
            nx_error = 0; CHECK(!request(0x35, at, 0, 0, 0) && releases == 1);
        } else CHECK(releases == 1 && !owned(at));
    } else if (!strcmp(name, "quarantine") || !strcmp(name, "ro-error") || !strcmp(name, "x-error")) {
        uptr at = stage(); upload(at, 8);
        if (!strcmp(name, "quarantine")) nx_error = -5;
        if (!strcmp(name, "ro-error")) ro_error = -5;
        if (!strcmp(name, "x-error")) x_error = -5;
        CHECK(request(0x33, at, MSU_BS_PAGE_BYTES, 1, 0) == (u64)-19999);
        if (nx_error) {
            CHECK(owned(at)->quarantined && !releases && calls == 1 && held == 1 && dropped == 1);
            CHECK(request(0x31, at, 0, 0, 9) == (u64)-19999);
            sdk_module_free((void *)at); CHECK(!releases && !native_releases);
            nx_error = 0; CHECK(!request(0x35, at, 0, 0, 0));
        } else CHECK(!calls && releases == 1);
    } else if (!strcmp(name, "invalid")) {
        CHECK(request(0x30, 0, 0, 0, 0) == (u64)-19999);
        CHECK(request(0x30, 0, MSU_BOOT_SDK_MAX_STAGE + 1, 0, 0) == (u64)-19999 && !allocations);
        uptr at = stage();
        CHECK(request(0x33, at, MSU_BS_PAGE_BYTES, 1, 0) == (u64)-19999);
        upload(at, 3); CHECK(request(0x33, at, MSU_BS_PAGE_BYTES, 1, 0) == (u64)-19999);
        upload(at + 3, 1);
        CHECK(request(0x33, at + 4, MSU_BS_PAGE_BYTES, 1, 0) == (u64)-19999);
        CHECK(request(0x33, at, MSU_BS_PAGE_BYTES - 1, 1, 0) == (u64)-19999);
        CHECK(request(0x33, at, MSU_BS_PAGE_BYTES, 2, 0) == (u64)-19999 && !calls);
        CHECK(!request(0x35, at, 0, 0, 0));
        CHECK(request(0x35, at, 0, 0, 0) == (u64)-19999 && releases == 1);
    } else CHECK(0);
    CHECK(!live); return 0;
}
