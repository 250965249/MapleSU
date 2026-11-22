// private helpers for the module proc bootconfig implementation.
//
// Ultra 私有头：内核只读段探测。内核把一部分启动期数据放进 __ro_after_init 与
// .rodata，这些区间在启动后不可写；改写 /proc/bootconfig 的指针槽位之前必须先
// 判断槽位是否落在这些只读段里，否则写只读页会触发内核异常。
//
// 只读段区间不是编译期常量：段的起止地址来自内核导出的
// __start_ro_after_init / __end_ro_after_init / __start_rodata / __end_rodata
// 四个符号，因此每次探测都用 kallsyms 现查一次。查符号期间临时静音 kit 的
// 符号查找打印（SymbolLookupSilentGuard），避免探测过程刷屏。
#pragma once

#include <cstdint>

#include "kernel_module_kit_umbrella.h"

namespace kernel_ro_section_helper {

// 命中的只读段描述：段名 + [起始地址, 结束地址)。
struct KernelSectionHit {
    const char* name = nullptr;
    uint64_t start = 0;
    uint64_t end = 0;
};

// 一个已知只读段的静态描述：段名与两个界定符号的名字。
struct KernelSectionRange {
    const char* name;
    const char* start_symbol;
    const char* end_symbol;
};

// 判断 addr 是否落在内核已知只读段内。
//   ranges 里每项给出段名与 [__start_x, __end_x) 两个界定符号；
//   逐个用 kallsyms 查出起止地址，命中 start <= addr < end 即返回 true。
//   hit 非空时写出命中的段名与地址区间。
static bool is_addr_in_kernel_known_readonly_section(uint64_t addr, KernelSectionHit* hit) {
    static const KernelSectionRange ranges[] = {
        {"ro_after_init", "__start_ro_after_init", "__end_ro_after_init"},
        {"rodata", "__start_rodata", "__end_rodata"},
    };

    for (const KernelSectionRange& range : ranges) {
        SymbolLookupSilentGuard_8dfccc5cf454087c7314725d3487e703 silent_guard;

        uint64_t start = 0;
        uint64_t end = 0;
        kernel_module::kallsyms_lookup_name(range.start_symbol, start);
        kernel_module::kallsyms_lookup_name(range.end_symbol, end);

        if (start != 0 && end != 0 && start <= addr && addr < end) {
            if (hit != nullptr) {
                hit->name = range.name;
                hit->start = start;
                hit->end = end;
            }
            return true;
        }
    }
    return false;
}

}  // namespace kernel_ro_section_helper
