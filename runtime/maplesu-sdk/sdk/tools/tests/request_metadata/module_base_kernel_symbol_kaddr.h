#pragma once
#include "module_err_def.h"
namespace kernel_module {
enum class SymbolMatchMode { Exact };
struct SymbolHit { uint64_t addr=0; };
KModErr kallsyms_lookup_name(const char*,SymbolHit&,SymbolMatchMode);
KModErr kallsyms_lookup_name(const char*,uint64_t&);
}
