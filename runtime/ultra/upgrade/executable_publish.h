#pragma once
#include "module_err_def.h"
#include <cstddef>

// The destination is never opened for writing: running processes keep its old
// inode until exit. New invocations see only the fully written replacement.
extern "C" KModErr maplesu_publish_executable(const char* path, const void* bytes,
                                             size_t size, const char* context);

// Boot backends use 0700 and a non-writable root-owned parent, matching the
// synchronous loader. Existing embedded executables retain their 0755 contract.
extern "C" KModErr maplesu_publish_private_backend(const char* path, const void* bytes,
                                                  size_t size, const char* context);
extern "C" KModErr maplesu_publish_private_backend_at(int directory, const char* name,
                                                     const void* bytes, size_t size, const char* context);
