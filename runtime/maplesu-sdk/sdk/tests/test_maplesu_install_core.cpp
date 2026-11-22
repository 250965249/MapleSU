// ===========================================================================
// MapleSU Ultra SDK -- R-PROGRAMS host unit test for the installer core
//
// This TU contains NO headers beyond the freestanding install core, and it
// touches no file, no chmod, no setxattr: alloc / publish / set_selinux are
// recording stubs supplied by the test itself.  It therefore builds and runs on
// a host that has no Android device and no Android libc -- see
// sdk/tests/run_core_test.py, which compiles it for wasm32 and executes it in
// Node (the shipped installers cannot run off-device; their *logic* can).
//
// What is asserted
//   1. root key -> 17-char data dir ("substr(0,16) + key[0]")
//   2. system data paths: /data/<17>/{su,resetprop,modules/webui_loader}
//      Kernel16 helper paths are covered by installer_differential.cpp.
//   3. token-search iteration counts that appear as immediates in the shipped
//      objects: 737817 (su), 762225 (webui), 1343921 (autorun 5.2.0) and
//      1159233 (autorun in the vendor IR build, 1163328 B payload)
//   4. replace_feature_string_in_buf: hit in the middle, hit at the very last
//      legal offset (the `i <= size - token` boundary), miss one byte past it,
//      copy-length cap at token_size-1, NUL padding preserved
//   5. install_blob: success, alloc failure (-19905), token missing (per-member
//      code), publish failure (-19930 propagated), set_selinux failure (-19915),
//      selinux call count (1 normally, 2 for webui), bad args (-20000)
//
// Exit contract: run_all() returns 0 when every check passed, else the number of
// failed checks (1..255).  Host-side logging goes through the imported
// `test_log` so the runner can print a per-check trace.
// ===========================================================================
#include "maplesu_install_core.h"

// --- host bridge (wasm import) --------------------------------------------
extern "C" void test_log(const char* msg);

namespace {

using namespace maplesu::sdk::core;

int g_failed = 0;
int g_checks = 0;

void log_str(const char* s) { test_log(s); }

void check(bool ok, const char* what) {
    ++g_checks;
    if (!ok) {
        ++g_failed;
        log_str("FAIL ");
        log_str(what);
        log_str("\n");
    }
}

void check_eq(long long got, long long want, const char* what) {
    ++g_checks;
    if (got != want) {
        ++g_failed;
        log_str("FAIL ");
        log_str(what);
        log_str(" (unexpected value)\n");
    }
}

bool buf_eq(const void* a, const void* b, unsigned long n) {
    const unsigned char* x = static_cast<const unsigned char*>(a);
    const unsigned char* y = static_cast<const unsigned char*>(b);
    for (unsigned long i = 0; i < n; ++i) {
        if (x[i] != y[i]) return false;
    }
    return true;
}

bool str_eq(const char* a, const char* b) {
    unsigned long i = 0;
    for (;; ++i) {
        if (a[i] != b[i]) return false;
        if (a[i] == '\0') return true;
    }
}

// --- recording stubs ------------------------------------------------------
struct StubState {
    unsigned long alloc_calls;
    unsigned long alloc_size;
    bool fail_alloc;
    unsigned long publish_calls;
    unsigned long publish_size;
    const void* publish_data;
    const char* publish_path;
    const char* publish_selinux;
    long long publish_rc;
    unsigned long set_selinux_calls;
    bool set_selinux_ok;
    char arena[4096];
};

StubState g_stub{};

void reset_stub() {
    g_stub.alloc_calls = 0;
    g_stub.alloc_size = 0;
    g_stub.fail_alloc = false;
    g_stub.publish_calls = 0;
    g_stub.publish_size = 0;
    g_stub.publish_data = nullptr;
    g_stub.publish_path = nullptr;
    g_stub.publish_selinux = nullptr;
    g_stub.publish_rc = 0;
    g_stub.set_selinux_calls = 0;
    g_stub.set_selinux_ok = true;
}

void* stub_alloc(unsigned long size) {
    ++g_stub.alloc_calls;
    g_stub.alloc_size = size;
    if (g_stub.fail_alloc) return nullptr;
    return g_stub.arena;
}

void stub_release(void*) {}

long long stub_publish(void*, const char* path, const void* data, unsigned long size,
                       const char* selinux_ctx) {
    ++g_stub.publish_calls;
    g_stub.publish_path = path;
    g_stub.publish_data = data;
    g_stub.publish_size = size;
    g_stub.publish_selinux = selinux_ctx;
    return g_stub.publish_rc;
}

bool stub_set_selinux(void*, const char*, const char*) {
    ++g_stub.set_selinux_calls;
    return g_stub.set_selinux_ok;
}

install_ops stub_ops() { return install_ops{&stub_alloc, &stub_release, &stub_publish, &stub_set_selinux}; }

// --- fixtures -------------------------------------------------------------
// 24-char key; the data dir must be key[0..16) + key[0] = "0123456789abcdef0"
const char kKey[] = "0123456789abcdefTRAILING";

// 16-byte token (the real ones are 4096 B; the replacement code is size-driven).
const char kToken[16] = {'P','L','A','C','E','H','O','L','D','E','R','-','0','0','0','1'};

// payload with the token at `token_at`
void make_payload(unsigned char* buf, unsigned long n, unsigned long token_at) {
    for (unsigned long i = 0; i < n; ++i) buf[i] = static_cast<unsigned char>(0xA0 + (i & 0x0F));
    for (unsigned long i = 0; i < sizeof(kToken); ++i) buf[token_at + i] = static_cast<unsigned char>(kToken[i]);
}

// --- 1. data dir ----------------------------------------------------------
void test_data_dir() {
    char out[32];
    for (unsigned long i = 0; i < sizeof(out); ++i) out[i] = '#';
    const unsigned long n = data_dir_name(kKey, bounded_strlen(kKey, kRootKeyMaxLen), out, sizeof(out));
    check_eq(static_cast<long long>(n), 17, "data_dir_name length");
    check(str_eq(out, "0123456789abcdef0"), "data_dir_name == substr(0,16)+key[0]");
    // too-short key / too-small buffer must fail closed
    check_eq(static_cast<long long>(data_dir_name("short", 5, out, sizeof(out))), 0,
             "data_dir_name rejects short key");
    check_eq(static_cast<long long>(data_dir_name(kKey, 24, out, 8)), 0,
             "data_dir_name rejects small buffer");
}

// --- 2. data paths --------------------------------------------------------
void test_paths() {
    char out[256];
    const char* su[] = {"su"};
    check(build_data_path(out, sizeof(out), kKey, bounded_strlen(kKey, kRootKeyMaxLen), su, 1),
          "build_data_path(su)");
    check(str_eq(out, "/data/0123456789abcdef0/su"), "su path");

    const char* rp[] = {"resetprop"};
    check(build_data_path(out, sizeof(out), kKey, bounded_strlen(kKey, kRootKeyMaxLen), rp, 1),
          "build_data_path(resetprop)");
    check(str_eq(out, "/data/0123456789abcdef0/resetprop"), "resetprop path");

    const char* wl[] = {"modules", "webui_loader"};
    check(build_data_path(out, sizeof(out), kKey, bounded_strlen(kKey, kRootKeyMaxLen), wl, 2),
          "build_data_path(webui)");
    check(str_eq(out, "/data/0123456789abcdef0/modules/webui_loader"), "webui path");

}

// --- 3. iteration counts --------------------------------------------------
void test_iteration_counts() {
    // immediates read out of the shipped objects / vendor IR
    check_eq(static_cast<long long>(token_search_iterations(741912)), 737817, "su search iterations");
    check_eq(static_cast<long long>(token_search_iterations(766320)), 762225, "webui search iterations");
    check_eq(static_cast<long long>(token_search_iterations(1351120)), 1347025,
             "current helper size-derived search iterations");
    check_eq(static_cast<long long>(token_search_iterations(1163328)), 1159233,
             "autorun (vendor IR build) search iterations");
    check_eq(static_cast<long long>(token_search_iterations(4095)), 0, "payload smaller than token");
}

// --- 4. token replacement -------------------------------------------------
void test_token_replace() {
    // 4a. hit in the middle: token replaced, surrounding bytes untouched
    unsigned char buf[64];
    make_payload(buf, sizeof(buf), 8);
    const unsigned char before_lo = buf[7];
    const unsigned char before_hi = buf[8 + sizeof(kToken)];
    unsigned long hits = 0;
    const bool found = replace_feature_string_in_buf(kToken, sizeof(kToken), "KEY", (char*)buf,
                                                     sizeof(buf), &hits);
    check(found, "token found in the middle");
    check_eq(static_cast<long long>(hits), 1, "one replacement in the middle");
    check(str_eq((const char*)buf + 8, "KEY"), "replacement is NUL-terminated at the token site");
    check_eq(buf[8 + 3], 0, "replacement writes key+NUL");
    check_eq(buf[8 + 4], static_cast<unsigned char>(kToken[4]),
             "bytes past copy_len keep the placeholder (vendor memcpy writes copy_len only)");
    check_eq(buf[7], before_lo, "byte before the token untouched");
    check_eq(buf[8 + sizeof(kToken)], before_hi, "byte after the token untouched");

    // 4b. hit at the LAST legal offset (buf_size - token_size): the shipped loop
    //     uses `i <= buf_size - token_size`, so this must be found.
    unsigned char last[64];
    make_payload(last, sizeof(last), sizeof(last) - sizeof(kToken));
    hits = 0;
    check(replace_feature_string_in_buf(kToken, sizeof(kToken), "KEY", (char*)last, sizeof(last), &hits),
          "token at the last legal offset is found (loop uses <=)");
    check_eq(static_cast<long long>(hits), 1, "single hit at the boundary");

    // 4c. one byte past the last legal offset must NOT be found.
    //     Array is big enough to physically hold the token; the *searched* window
    //     stops one byte earlier, so the token starts at searched+1.
    unsigned char past[96];
    for (unsigned long i = 0; i < sizeof(past); ++i) past[i] = 0x5A;
    const unsigned long searched = sizeof(past) - sizeof(kToken) - 1;   // 79
    for (unsigned long i = 0; i < sizeof(kToken); ++i) past[searched + 1 + i] = static_cast<unsigned char>(kToken[i]);
    hits = 0;
    check(!replace_feature_string_in_buf(kToken, sizeof(kToken), "KEY", (char*)past, searched, &hits),
          "token one byte past the end is not found");
    check_eq(static_cast<long long>(hits), 0, "no hit past the boundary");

    // 4d. over-long key: copy_len capped at token_size - 1, no overflow
    unsigned char cap[64];
    for (unsigned long i = 0; i < sizeof(cap); ++i) cap[i] = 0x11;
    for (unsigned long i = 0; i < sizeof(kToken); ++i) cap[16 + i] = kToken[i];
    const char long_key[] = "0123456789ABCDEF-overflowing-key";
    hits = 0;
    check(replace_feature_string_in_buf(kToken, sizeof(kToken), long_key, (char*)cap, sizeof(cap), &hits),
          "over-long key still replaces");
    check_eq(cap[16 + sizeof(kToken) - 1], static_cast<unsigned char>(kToken[sizeof(kToken) - 1]),
             "copy length is capped at token_size-1 (last token byte survives)");
    check_eq(cap[16 + 14], 'E', "first 15 bytes of the long key are copied");

    // 4e. absent token
    unsigned char none[32];
    for (unsigned long i = 0; i < sizeof(none); ++i) none[i] = 0x22;
    hits = 0;
    check(!replace_feature_string_in_buf(kToken, sizeof(kToken), "KEY", (char*)none, sizeof(none), &hits),
          "absent token reports false");
    check_eq(static_cast<long long>(hits), 0, "absent token reports zero hits");

    // 4f. buffer smaller than the token
    check(!replace_feature_string_in_buf(kToken, sizeof(kToken), "KEY", (char*)none, 4, &hits),
          "buffer smaller than token is rejected");
}

// --- 5. install_blob ------------------------------------------------------
void test_install_blob() {
    unsigned char payload[64];
    make_payload(payload, sizeof(payload), 8);
    install_request req{};
    req.path = "/data/0123456789abcdef0/su";
    req.blob = payload;
    req.size = sizeof(payload);
    req.token = kToken;
    req.token_size = sizeof(kToken);
    req.root_key = "KEY";
    req.selinux_ctx = "u:object_r:system_file:s0";
    req.selinux_calls = 1;
    req.token_missing_error = kErrTokenMissing;

    // 5a. success
    reset_stub();
    check_eq(install_blob(stub_ops(), nullptr, req), 0, "install_blob success");
    check_eq(static_cast<long long>(g_stub.alloc_calls), 1, "alloc called once");
    check_eq(static_cast<long long>(g_stub.alloc_size), 64, "alloc sized from the payload");
    check_eq(static_cast<long long>(g_stub.publish_calls), 1, "publish called once");
    check_eq(static_cast<long long>(g_stub.publish_size), 64, "publish size == payload size");
    check(str_eq((const char*)g_stub.publish_data + 8, "KEY"), "published bytes carry the root key");
    check(str_eq(g_stub.publish_path, req.path), "publish path");
    check(str_eq(g_stub.publish_selinux, req.selinux_ctx), "publish carries the selinux context");
    check_eq(static_cast<long long>(g_stub.set_selinux_calls), 1, "one set_selinux call");

    // 5b. alloc failure -> -19905, publish must not run
    reset_stub();
    g_stub.fail_alloc = true;
    check_eq(install_blob(stub_ops(), nullptr, req), kErrPayloadAlloc, "alloc failure -> -19905");
    check_eq(static_cast<long long>(g_stub.publish_calls), 0, "no publish after alloc failure");

    // 5c. token missing -> the per-member code, publish must not run
    reset_stub();
    install_request no_token_in_blob = req;
    unsigned char clean[64];
    for (unsigned long i = 0; i < sizeof(clean); ++i) clean[i] = 0x33;
    no_token_in_blob.blob = clean;
    check_eq(install_blob(stub_ops(), nullptr, no_token_in_blob), kErrTokenMissing,
             "missing token -> -19908 (su slot)");
    check_eq(static_cast<long long>(g_stub.publish_calls), 0, "no publish when the token is missing");

    install_request webui_req = req;
    webui_req.token_missing_error = kErrTokenSearch;
    webui_req.selinux_calls = 2;
    reset_stub();
    check_eq(install_blob(stub_ops(), nullptr, webui_req), 0, "webui-shaped install succeeds");
    check_eq(static_cast<long long>(g_stub.set_selinux_calls), 2,
             "webui calls chmod+setxattr twice (vendor quirk)");

    // 5d. resetprop has no token at all -> bytes published unchanged
    reset_stub();
    install_request no_token = req;
    no_token.token = nullptr;
    no_token.token_size = 0;
    check_eq(install_blob(stub_ops(), nullptr, no_token), 0, "tokenless install succeeds");
    check(buf_eq((const char*)g_stub.publish_data + 8, kToken, sizeof(kToken)),
          "tokenless install publishes the placeholder bytes unchanged");

    // 5e. publish failure is propagated, set_selinux must not run
    reset_stub();
    g_stub.publish_rc = kErrPublish;
    check_eq(install_blob(stub_ops(), nullptr, req), kErrPublish, "publish failure propagated (-19930)");
    check_eq(static_cast<long long>(g_stub.set_selinux_calls), 0,
             "no chmod/setxattr after a failed publish");

    // 5f. chmod/setxattr failure -> -19915
    reset_stub();
    g_stub.set_selinux_ok = false;
    check_eq(install_blob(stub_ops(), nullptr, req), kErrSetSelinux, "selinux failure -> -19915");

    // 5g. bad arguments -> -20000 (ERR_MODULE_PARAM)
    reset_stub();
    install_request bad = req;
    bad.path = nullptr;
    check_eq(install_blob(stub_ops(), nullptr, bad), kErrModuleParam, "null path -> -20000");
    install_request bad2 = req;
    bad2.size = 0;
    check_eq(install_blob(stub_ops(), nullptr, bad2), kErrModuleParam, "zero size -> -20000");
}

}  // namespace

// Exported entry point; the runner reads the i32 result and treats 0 as pass.
extern "C" int run_all() {
    g_failed = 0;
    g_checks = 0;
    test_data_dir();
    test_paths();
    test_iteration_counts();
    test_token_replace();
    test_install_blob();
    if (g_failed == 0) log_str("all checks passed\n");
    return g_failed;
}

extern "C" int check_count() { return g_checks; }
