#pragma once
#include "module_err_def.h"
#include "executable_publish_result.h"
#include <cstddef>

// The destination is never opened for writing: running processes keep its old
// inode until exit. New invocations see only the fully written replacement.
extern "C" KModErr maplesu_publish_executable(const char* path, const void* bytes,
                                             size_t size, const char* context);

namespace maplesu::install {
__attribute__((visibility("hidden")))
KModErr project_publish_result(const PublishResult& result);
__attribute__((visibility("hidden")))
KModErr publish_empty_state(const char* path, const char* context);
__attribute__((visibility("hidden")))
KModErr publish_version(const char* path, const void* bytes, size_t size,
                        const char* context);
}
