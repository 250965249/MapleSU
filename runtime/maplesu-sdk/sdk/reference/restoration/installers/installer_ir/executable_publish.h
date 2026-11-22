#pragma once
#include "module_err_def.h"
#include <cstddef>

// The destination is never opened for writing: running processes keep its old
// inode until exit. New invocations see only the fully written replacement.
extern "C" KModErr maplesu_publish_executable(const char* path, const void* bytes,
                                             size_t size, const char* context);
