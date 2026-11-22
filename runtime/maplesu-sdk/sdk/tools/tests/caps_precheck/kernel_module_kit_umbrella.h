#pragma once

#include <cstdint>
#include <string>
#include <vector>
#include <sched.h>
#include "module_err_def.h"
#include "kernel_offsets/cred.h"
#include "kernel_offsets/task_struct.h"

namespace kernel_module {
enum class SymbolMatchMode : uint8_t { Exact, Prefix, Suffix, Substring };
struct SymbolHit { uint64_t addr = 0; char name[1024] = {}; };
KModErr kallsyms_lookup_name(const char*, uint64_t&);
KModErr kallsyms_lookup_name(const char*, SymbolHit&, SymbolMatchMode);
KModErr get_avc_denied_kaddr(uint64_t&, uint64_t&);
}

struct SymbolLookupSilentGuard_c67c0e4fed21dd11b34c67e0a5b878c8 {};
