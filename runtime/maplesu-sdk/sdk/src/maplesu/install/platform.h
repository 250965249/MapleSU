
//
#pragma once

#include <cerrno>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <new>
#include <string>

#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/xattr.h>
#include <unistd.h>

#include "core.h"
#include "executable_publish.h"

namespace maplesu::install::platform {

// --- production implementations -------------------------------------------
inline bool write_file_publish(const char* path, const unsigned char* data,
                               unsigned long size, const char* selinux_ctx) {
    return maplesu_publish_executable(path, data, size, selinux_ctx) == KModErr::OK;
}

// (`std::ios::binary | std::ios::out` == libc++ 4|16 == 20).
inline bool write_file_direct(const char* path, const unsigned char* data, unsigned long size) {
    std::ofstream out(path, std::ios::binary | std::ios::out);
    if (!out.is_open()) return false;
    out.write(reinterpret_cast<const char*>(data), static_cast<std::streamsize>(size));
    out.close();
    return out.good();
}

inline bool create_empty_file(const char* path) {
    std::ofstream out(path, std::ios::binary | std::ios::out | std::ios::trunc);
    if (!out.is_open()) return false;
    out.close();
    return out.good();
}

inline bool set_file_selinux_access_mode(const char* path, const char* context) {
    if (::chmod(path, core::kExecMode0777) != 0) return false;
    if (context == nullptr) return false;
    const std::size_t n = std::strlen(context) + 1;
    return ::setxattr(path, core::kSelinuxXattr, context, n, 0) == 0;
}

inline bool file_exists(const char* path) {
    struct stat st {};
    return ::stat(path, &st) == 0;
}

inline bool rename_path(const char* from, const char* to) { return ::rename(from, to) == 0; }

inline bool delete_path(const char* path) {
    if (::unlink(path) == 0) return true;
    return ::rmdir(path) == 0;
}

inline bool make_dir(const char* path) {
    if (::mkdir(path, core::kExecMode0777) == 0) return true;
    return errno == EEXIST;
}

inline int last_errno() { return errno; }

// --- hooks for core::install_blob -----------------------------------------
// These are the four foreign calls the install step makes.  Passing them as a
// table lets the host install-core test run the *same*
// install step on the host with recording stubs instead of a real filesystem.
inline void* payload_alloc(unsigned long size) {
    return new (std::nothrow) char[size];
}

inline void payload_release(void* p) {
    delete[] static_cast<char*>(p);
}

inline long long payload_publish(void* /*ctx*/, const char* path, const void* data,
                                unsigned long size, const char* selinux_ctx) {
    return static_cast<long long>(
        maplesu_publish_executable(path, data, size, selinux_ctx));
}

inline bool payload_set_selinux(void* /*ctx*/, const char* path, const char* selinux_ctx) {
    return set_file_selinux_access_mode(path, selinux_ctx);
}

inline core::install_ops install_ops_table() {
    return core::install_ops{&payload_alloc, &payload_release, &payload_publish,
                             &payload_set_selinux};
}

// Convenience wrapper: run the shared install step with the production hooks.
inline core::err_t install_payload(const char* path, const unsigned char* blob,
                                  unsigned long size, const char* token,
                                  unsigned long token_size, const char* root_key,
                                  const char* selinux_ctx, unsigned int selinux_calls,
                                  core::err_t token_missing_error) {
    core::install_request req{path, blob, size, token, token_size, root_key, selinux_ctx,
                              selinux_calls, token_missing_error};
    return core::install_blob(install_ops_table(), nullptr, req);
}

}  // namespace maplesu::install::platform
