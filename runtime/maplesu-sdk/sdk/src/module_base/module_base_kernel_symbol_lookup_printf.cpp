// module base kernel symbol lookup printf implementation.
//
#include <atomic>

// 私有 API（uint64_t 版 kallsyms_lookup_name 等）。不含 kernel_module_kit_umbrella.h：
// 而 umbrella 会经 module_descriptor.h 无条件生成它们。
#include "aarch64_asm_helper.h"
#include "module_err_def.h"
#include "module_base_kernel_mem.h"
#include "third_party/____DO_NOT_EDIT____/private_mod_api_runtime_helper.h"

// 符号查找期间的 printf 静默开关。
//
//   @g_symbol_lookup_printf = hidden local_unnamed_addr global { { i8 } }
//       { { i8 } { i8 1 } }, align 4
// { { i8 } } 与 align 4 正是 libc++ std::atomic<bool> 的 lowering（已用
// clang++ 17.0.2 + 同 profile 单独复现），初始值 i8 1 = true。
// 变量在全局作用域（符号名未 mangle），-fvisibility=hidden 使其为 hidden。
std::atomic<bool> g_symbol_lookup_printf{true};

//   define hidden void @_Z64set_symbol_lookup_printf_silent_<hash>b(i1 noundef %0)
//     %2 = zext i1 %0 to i8
//     store atomic i8 %2, ptr @g_symbol_lookup_printf seq_cst, align 4
//     ret void
// 即 std::atomic<bool>::store(value)：seq_cst 默认序、i1 -> i8 的 zext。
void set_symbol_lookup_printf_silent_d8685f89f10ca8eb96df766c8babd6c3(bool enable) {
    g_symbol_lookup_printf.store(enable);
}

//   define hidden noundef i1 @_Z64get_symbol_lookup_printf_silent_<hash>v()
//     %1 = load atomic i8, ptr @g_symbol_lookup_printf seq_cst, align 4
//     %2 = and i8 %1, 1          ; bool 规范化
//     %3 = icmp ne i8 %2, 0
//     ret i1 %3
// std::atomic<bool>::load() 的 libc++ 实现即产生 and+icmp 序列。
bool get_symbol_lookup_printf_silent_d8685f89f10ca8eb96df766c8babd6c3() {
    return g_symbol_lookup_printf.load();
}
