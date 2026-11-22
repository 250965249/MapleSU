
//
#pragma once

namespace maplesu::install {
namespace core {

constexpr unsigned long kDataDirBufSize = 1024;
constexpr unsigned long kFeatureTokenSize = 4096;
constexpr unsigned long kRootKeyDirChars = 16;
constexpr unsigned long kRootKeyMaxLen = 4096;    // defensive cap for the key we read
constexpr char kDataDirFormat[] = "/data/%s/";
constexpr char kSelinuxXattr[] = "security.selinux";
// u:object_r:system_file:s0 -- 25 chars + NUL; setxattr passes strlen+1
constexpr char kSelinuxSystemFile[] = "u:object_r:system_file:s0";
// u:object_r:kernel:s0 -- 20 chars + NUL (autorun_bootstrap flags)
constexpr char kSelinuxKernel[] = "u:object_r:kernel:s0";
constexpr unsigned int kExecMode0777 = 0777;       // chmod(path, 0777)

// --- installer error codes --------------------------------------------------
// the whole -199xx range is NOT in that header (expanding KMODERR_LIST_* there
// yields 0 and -20001..-20096 only), so the -199xx *symbolic* names are
using err_t = long long;
constexpr err_t kOk = 0;
constexpr err_t kErrModuleParam = -20000;      // KModErr::ERR_MODULE_PARAM (verified in header)
constexpr err_t kErrPayloadAlloc = -19905;
constexpr err_t kErrTokenBufAlloc = -19906;
constexpr err_t kErrTokenSearch = -19907;
constexpr err_t kErrTokenMissing = -19908;
constexpr err_t kErrSetSelinux = -19915;
constexpr err_t kErrPublish = -19930;          // disas: maplesu_publish_executable failure path
constexpr err_t kErrWriteFile = -19933;
constexpr err_t kErrOpenFile = -19934;
constexpr err_t kErrCreateEmptyFile = -19935;

constexpr const char* kErrProvenance =
    "0=OK; -20000=module_err_def.h ERR_MODULE_PARAM; -19905/-19906/-19907/-19908/-19915/"
    "unexpected layout size";

// Root-key -> data dir
//
//   key  = __get_current_module_root_key_<tag>()
//   dir  = key.substr(0, 16)                       // basic_string::substr(0,16)
//   dir += dir[0]                                  // operator+(string const&, char)
//   snprintf(buf, 1024, "/data/%s/", dir.c_str())
//
// i.e. a 17-character directory: the first 16 characters of the root key with
// the 1st character appended.  The append is what makes the path length odd;
// it is a deliberate vendor obfuscation, not an accident, and is reproduced
// exactly.
// Writes the 17-char dir name + NUL into `out` (needs >= 18 bytes).
// Returns the length (17) or 0 when the key is too short / out of space.
inline unsigned long data_dir_name(const char* key, unsigned long key_len,
                                   char* out, unsigned long out_cap) {
    if (key == nullptr || out == nullptr) return 0;
    if (key_len < kRootKeyDirChars) return 0;
    if (out_cap < kRootKeyDirChars + 2) return 0;
    for (unsigned long i = 0; i < kRootKeyDirChars; ++i) out[i] = key[i];
    out[kRootKeyDirChars] = key[0];
    out[kRootKeyDirChars + 1] = '\0';
    return kRootKeyDirChars + 1;
}

// strnlen() without libc.
inline unsigned long bounded_strlen(const char* s, unsigned long cap) {
    if (s == nullptr) return 0;
    unsigned long n = 0;
    while (n < cap && s[n] != '\0') ++n;
    return n;
}

// Minimal "%s" formatter for the single constant format above: reproduces
// snprintf(buf, kDataDirBufSize, "/data/%s/", dir) without pulling in stdio.
// Returns the produced length, or 0 if it cannot be written losslessly in `cap`.
inline unsigned long format_data_dir(const char* dir, unsigned long cap) {
    if (dir == nullptr) return 0;
    const unsigned long dir_len = bounded_strlen(dir, kDataDirBufSize);
    const unsigned long total = 6u /* "/data/" */ + dir_len + 1u /* '/' */;
    if (total + 1u > cap) return 0;
    return total;
}

// Appends `src` to `dst` (bounded, always NUL-terminated). Returns false on
// overflow and leaves `dst` untouched.
inline bool append_bounded(char* dst, unsigned long cap, unsigned long* len, const char* src) {
    if (dst == nullptr || len == nullptr || src == nullptr || cap == 0) return false;
    unsigned long l = *len;
    for (unsigned long i = 0;; ++i) {
        const char c = src[i];
        if (c == '\0') break;
        if (l + 1 >= cap) return false;   // keep room for NUL
        dst[l++] = c;
    }
    dst[l] = '\0';
    *len = l;
    return true;
}

// "/data/<dir>/" then a trailing component, mirroring
//   path("/data/<dir>/") / path(<name>)     (su, resetprop)
//   path("/data/<dir>/") / "modules" / path("") / "webui_loader"   (webui)
// The intermediate empty path component the vendor build passes through
// std::filesystem::operator/ is a no-op once the separator is present, so the
// produced string is identical; it is kept explicit here so the reconstruction
// Returns false when `out` cannot hold the result.
inline bool build_data_path(char* out, unsigned long cap, const char* key, unsigned long key_len,
                            const char* const* components, unsigned long component_count) {
    if (out == nullptr || cap == 0) return false;
    char dir[kRootKeyDirChars + 2];
    if (data_dir_name(key, key_len, dir, sizeof(dir)) == 0) return false;

    out[0] = '\0';
    unsigned long len = 0;
    // "/data/" + dir + "/"
    if (!append_bounded(out, cap, &len, "/data/")) return false;
    if (!append_bounded(out, cap, &len, dir)) return false;
    if (!append_bounded(out, cap, &len, "/")) return false;
    for (unsigned long i = 0; i < component_count; ++i) {
        if (!append_bounded(out, cap, &len, components[i])) return false;
        if (i + 1 < component_count) {
            if (!append_bounded(out, cap, &len, "/")) return false;
        }
    }
    return len != 0;
}

// Equal-length feature-token replacement
//
// (`static_inline_*_rootkey`: 128 hex chars + 3968 NULs).  At install time the
// real root key is copied over every occurrence **in place**, padded with NULs,
// so the payload length never changes.
//
// This is the vendor `replace_feature_string_in_buf()` (Lite SDK
//
//   copy_len = min(token_size - 1, strlen(new_key) + 1)          // llvm.umin
//   for (i = 0; i <= buf_size - token_size; ++i)                  // NB: <=
//       if (!memcmp(buf + i, token, token_size)) { memcpy(buf + i, padded, copy_len); found = true; }
//
// The loop bound is the classic off-by-one trap: for a 741912-byte payload and a
// (741912 - 4095), NOT 737816. The install-core test asserts the count.
// `padded` must be kFeatureTokenSize bytes; `new_key_len` is strlen(new_key).
// Returns true when at least one occurrence was replaced.
inline bool replace_feature_string_in_buf(const char* token, unsigned long token_size,
                                          const char* new_key, char* buf,
                                          unsigned long buf_size, unsigned long* out_hits) {
    if (out_hits != nullptr) *out_hits = 0;
    if (token == nullptr || buf == nullptr || new_key == nullptr) return false;
    if (token_size == 0 || buf_size < token_size) return false;

    // NUL-padded replacement image, capped at token_size - 1 bytes.
    char padded[kFeatureTokenSize];
    if (token_size > kFeatureTokenSize) return false;   // only 4096-byte tokens exist
    for (unsigned long i = 0; i < token_size; ++i) padded[i] = '\0';
    const unsigned long key_len = bounded_strlen(new_key, kRootKeyMaxLen);
    unsigned long copy_len = key_len + 1;
    if (copy_len > token_size - 1) copy_len = token_size - 1;
    for (unsigned long i = 0; i < copy_len; ++i) padded[i] = new_key[i];

    bool found = false;
    unsigned long hits = 0;
    const unsigned long last = buf_size - token_size;
    for (unsigned long i = 0; i <= last; ++i) {
        bool equal = true;
        for (unsigned long j = 0; j < token_size; ++j) {
            if (buf[i + j] != token[j]) { equal = false; break; }
        }
        if (!equal) continue;
        for (unsigned long j = 0; j < copy_len; ++j) buf[i + j] = padded[j];
        found = true;
        ++hits;
    }
    if (out_hits != nullptr) *out_hits = hits;
    return found;
}

// `payload_size` bytes.  Kept as a function so the test can assert it against
// (e.g. su: 737817, webui: 762225, autorun(5.2.0): 1343921).
constexpr unsigned long token_search_iterations(unsigned long payload_size) {
    return payload_size >= kFeatureTokenSize ? payload_size - (kFeatureTokenSize - 1) : 0;
}

// The whole "install one payload" step, with every foreign call behind hooks.
//
// This is the part that is identical in all four members:
//
//     buf = alloc(size)                       // new (nothrow) char[size]
//     copy(buf, blob, size)
//     [token] replace_feature_string_in_buf(token, 4096, key, buf, size)
//     publish(path, buf, size, selinux_ctx)   // write + chmod/xattr + rename
//     set_selinux(path, selinux_ctx)          // chmod(0777) + setxattr
//     free(buf)
//
// Differences between the members are carried by `install_request`:
//   * resetprop passes token == nullptr (its member has no 4096-byte token),
//   * the "token not found / token buffer" error code differs per member
//     (-19908 su, -19907 webui, -19906 autorun) -- hence `token_missing_error`,
//   * webui calls set_selinux twice (vendor quirk) -- hence `selinux_calls`,
//   * autorun's context is u:object_r:kernel:s0, the others system_file.
//
// Keeping it here means the host unit test (sdk/tests/) exercises the exact same
// code the device build compiles, with alloc/publish/set_selinux stubbed.
struct install_ops {
    void* (*alloc)(unsigned long size);
    void (*release)(void* p);
    // returns 0 on success (publish's own error code otherwise)
    long long (*publish)(void* ctx, const char* path, const void* data, unsigned long size,
                         const char* selinux_ctx);
    bool (*set_selinux)(void* ctx, const char* path, const char* selinux_ctx);
};

struct install_request {
    const char* path;
    const unsigned char* blob;
    unsigned long size;
    const char* token;            // nullptr => no token replacement (resetprop)
    unsigned long token_size;
    const char* root_key;
    const char* selinux_ctx;
    unsigned int selinux_calls;   // 1 normally, 2 for webui_loader
    err_t token_missing_error;    // -19908 / -19907 / -19906 per member
};

inline void copy_bytes(unsigned char* dst, const unsigned char* src, unsigned long n) {
    for (unsigned long i = 0; i < n; ++i) dst[i] = src[i];
}

inline err_t install_blob(const install_ops& ops, void* ctx, const install_request& req) {
    if (ops.alloc == nullptr || ops.release == nullptr || ops.publish == nullptr ||
        ops.set_selinux == nullptr || req.path == nullptr || req.blob == nullptr || req.size == 0) {
        return kErrModuleParam;
    }
    void* buf = ops.alloc(req.size);
    if (buf == nullptr) return kErrPayloadAlloc;                   // -19905
    copy_bytes(static_cast<unsigned char*>(buf), req.blob, req.size);

    if (req.token != nullptr) {
        unsigned long hits = 0;
        if (!replace_feature_string_in_buf(req.token, req.token_size, req.root_key,
                                           static_cast<char*>(buf), req.size, &hits)) {
            ops.release(buf);
            return req.token_missing_error;
        }
    }

    const err_t publish_err =
        ops.publish(ctx, req.path, buf, req.size, req.selinux_ctx);
    ops.release(buf);
    if (publish_err != kOk) return publish_err;

    for (unsigned int i = 0; i < req.selinux_calls; ++i) {
        if (!ops.set_selinux(ctx, req.path, req.selinux_ctx)) return kErrSetSelinux;  // -19915
    }
    return kOk;
}

}  // namespace core
}  // namespace maplesu::install
