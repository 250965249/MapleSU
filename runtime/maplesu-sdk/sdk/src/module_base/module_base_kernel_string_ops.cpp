// module base kernel string ops implementation.
//
#include <cstdint>

#include "kernel_module_kit_umbrella.h"

#include "module_base_kernel_string_ops.h"

using namespace asmjit;
using namespace asmjit::a64;

namespace kernel_module {
namespace string_ops {

// kendswith —— 判断 str 是否以 suffix 结尾；匹配时 X0 为 1，否则为 0。
//
// 行为：
//   ret = 0;
//   if (!str || !suffix) return ret;
//   n = str 的长度（扫描到 '\0'）；
//   m = suffix 的长度；
//   if (m == 0) { ret = 1; return ret; }      // 空后缀视为匹配
//   if (n < m) return ret;                     // 后缀比串长
//   p = n - m;                                 // 尾对齐起点
//   i = 0;
//   while (i != m) {
//     if (str[p] != suffix[i]) return ret;     // 逐字节比较
//     ++p; ++i;
//   }
//   ret = 1;
//   return ret;
void kendswith(Assembler* a, GpX str, GpX suffix) {
    IdleRegPool pool = IdleRegPool::make(str, suffix);

    GpX x_strlen  = pool.acquireX();
    GpX x_suflen  = pool.acquireX();
    GpX x_diff    = pool.acquireX();
    GpX x_pos     = pool.acquireX();
    GpX x_idx     = pool.acquireX();
    GpX x_ret     = pool.acquireX();
    GpW w_char_a  = pool.acquireW();
    GpW w_char_b  = pool.acquireW();

    RegProtectGuard guard(a, excluding_x0(pool.getUsed()));

    Label L_scan_str = a->newLabel();
    Label L_str_done = a->newLabel();
    Label L_scan_suf = a->newLabel();
    Label L_suf_done = a->newLabel();
    Label L_cmp_loop = a->newLabel();
    Label L_match    = a->newLabel();
    Label L_end      = a->newLabel();

    a->mov(x_ret, xzr);
    a->cbz(str, L_end);
    a->cbz(suffix, L_end);

    a->mov(x_strlen, xzr);
    a->bind(L_scan_str);
    a->ldrb(w_char_a, ptr(str, x_strlen));
    a->cbz(w_char_a, L_str_done);
    a->add(x_strlen, x_strlen, Imm(1));
    a->b(L_scan_str);
    a->bind(L_str_done);

    a->mov(x_suflen, xzr);
    a->bind(L_scan_suf);
    a->ldrb(w_char_b, ptr(suffix, x_suflen));
    a->cbz(w_char_b, L_suf_done);
    a->add(x_suflen, x_suflen, Imm(1));
    a->b(L_scan_suf);
    a->bind(L_suf_done);

    a->cbz(x_suflen, L_match);
    a->cmp(x_strlen, x_suflen);
    a->b(CondCode::kLT, L_end);
    a->sub(x_diff, x_strlen, x_suflen);
    a->mov(x_pos, x_diff);
    a->mov(x_idx, xzr);

    //                  %207 / %212 / %217 / %219 ----------------------------
    a->bind(L_cmp_loop);
    a->cmp(x_idx, x_suflen);
    a->b(CondCode::kEQ, L_match);
    a->ldrb(w_char_a, ptr(str, x_pos));
    a->ldrb(w_char_b, ptr(suffix, x_idx));
    a->cmp(w_char_a, w_char_b);
    a->b(CondCode::kNE, L_end);
    a->add(x_pos, x_pos, Imm(1));
    a->add(x_idx, x_idx, Imm(1));
    a->b(L_cmp_loop);

    a->bind(L_match);
    a->mov(x_ret, Imm(1));
    a->bind(L_end);
    a->mov(x0, x_ret);
}

// 字符串与内存操作生成器：每个函数向给定的 Assembler 追加一段自包含的
// AArch64 指令序列，交给内核执行；X0 承载返回值，X0 以外的通用寄存器由
// RegProtectGuard 保存/恢复。带常量参数的版本先借助 IdleRegPool 申请一个
// 空闲寄存器承载常量，再调用同名的寄存器版本。
//
// 各函数的行为与同名标准 C 函数一致（memset/memcmp/memcpy/memmem/memchr/
// memrchr/strlen/strnlen/strcmp/strncmp/strcpy/strncpy/strcat/strncat/
// strstr/strchr/strrchr/startswith/endswith），空指针不产生内存访问。

// kmemset(Assembler*, GpX dst, GpW c, GpX n) —— 逐字节填充（四个重载的核心实现）
//
// 语义：dst[0..n) 全部写成 (uint8_t)c；X0 返回 dst。n==0 时循环体一次都不执行。
// 唯一"提前退出"是 n==0。
void kmemset(Assembler* a, GpX dst, GpW c, GpX n) {
    IdleRegPool pool = IdleRegPool::make(dst, c, n);
    GpX x_idx = pool.acquireX();
    GpW w_c = pool.acquireW();

    RegProtectGuard guard(a, excluding_x0(pool.getUsed()));

    Label L_loop = a->newLabel();
    Label L_end = a->newLabel();

    a->mov(x0, dst);
    a->cbz(n, L_end);
    a->uxtb(w_c, c);
    a->mov(x_idx, xzr);

    a->bind(L_loop);
    a->strb(w_c, ptr(dst, x_idx));
    a->add(x_idx, x_idx, Imm(1));
    a->cmp(x_idx, n);
    a->b(CondCode::kLO, L_loop);
    a->bind(L_end);
}

// kmemset(Assembler*, GpX dst, GpW c, uint64_t n)
//
void kmemset(Assembler* a, GpX dst, GpW c, uint64_t n) {
    IdleRegPool pool = IdleRegPool::make(dst, c);
    GpX x_n = pool.acquireX();

    RegProtectGuard guard(a, excluding_x0(pool.getUsed()));

    aarch64_asm_mov_x(a, x_n, n);
    kmemset(a, dst, c, x_n);
}

// kmemset(Assembler*, GpX dst, uint8_t c, GpX n)
//
void kmemset(Assembler* a, GpX dst, uint8_t c, GpX n) {
    IdleRegPool pool = IdleRegPool::make(dst, n);
    GpW w_c = pool.acquireW();

    RegProtectGuard guard(a, excluding_x0(pool.getUsed()));

    aarch64_asm_mov_w(a, w_c, (uint32_t)c);
    kmemset(a, dst, w_c, n);
}

// kmemset(Assembler*, GpX dst, uint8_t c, uint64_t n)
// 字节值按低 8 位、长度按 64 位常量分别装入临时寄存器后调用核心实现。
void kmemset(Assembler* a, GpX dst, uint8_t c, uint64_t n) {
    IdleRegPool pool = IdleRegPool::make(dst);
    GpW w_c = pool.acquireW();
    GpX x_n = pool.acquireX();

    RegProtectGuard guard(a, excluding_x0(pool.getUsed()));

    aarch64_asm_mov_w(a, w_c, (uint32_t)c);
    aarch64_asm_mov_x(a, x_n, n);
    kmemset(a, dst, w_c, x_n);
}

// kstrcmp(Assembler*, GpX str1, GpX str2) —— 文本字符串比较
//
// 语义：与标准 strcmp 一致（X0==0 相等；否则为有符号字节差）；任一入参为 0 时 X0=0。
void kstrcmp(Assembler* a, GpX str1, GpX str2) {
    IdleRegPool pool = IdleRegPool::make(str1, str2);
    GpX x_idx = pool.acquireX();
    GpX x_ret = pool.acquireX();
    GpW w_a = pool.acquireW();
    GpW w_b = pool.acquireW();
    GpW w_diff = pool.acquireW();

    RegProtectGuard guard(a, excluding_x0(pool.getUsed()));

    Label L_loop = a->newLabel();
    Label L_diff = a->newLabel();
    Label L_end = a->newLabel();

    a->mov(x_idx, xzr);
    a->mov(x_ret, xzr);
    a->cbz(str1, L_end);
    a->cbz(str2, L_end);

    a->bind(L_loop);
    a->ldrb(w_a, ptr(str1, x_idx));
    a->ldrb(w_b, ptr(str2, x_idx));
    a->cmp(w_a, w_b);
    a->b(CondCode::kNE, L_diff);
    a->cbz(w_a, L_end);
    a->add(x_idx, x_idx, Imm(1));
    a->b(L_loop);

    a->bind(L_diff);
    a->sub(w_diff, w_a, w_b);
    a->sxtw(x_ret, w_diff);

    a->bind(L_end);
    a->mov(x0, x_ret);
}

// kstrcpy(Assembler*, GpX dst, GpX src) —— 复制以 '\0' 结尾的字符串（含终止符）
//
// 语义：与标准 strcpy 一致（含 '\0'，循环在写终止符后由 cbnz 退出）；仅适用于
// 非重叠区域。空指针时只写 X0，不产生内存访问。
void kstrcpy(Assembler* a, GpX dst, GpX src) {
    IdleRegPool pool = IdleRegPool::make(dst, src);
    GpX x_idx = pool.acquireX();
    GpW w_ch = pool.acquireW();

    RegProtectGuard guard(a, excluding_x0(pool.getUsed()));

    Label L_loop = a->newLabel();
    Label L_end = a->newLabel();

    a->cbz(dst, L_end);
    a->cbz(src, L_end);
    a->mov(x_idx, xzr);

    a->bind(L_loop);
    a->ldrb(w_ch, ptr(src, x_idx));
    a->strb(w_ch, ptr(dst, x_idx));
    a->add(x_idx, x_idx, Imm(1));
    a->cbnz(w_ch, L_loop);

    a->bind(L_end);
    a->mov(x0, dst);
}

// kstrlen（外部调用版本）：计算内核地址 kmem 处以 '\0' 结尾的字符串长度，
// 结果写入 out_len；返回值为 OK 代表执行成功。
//
// 内核侧代码序列：从 X11 取得字符串地址调用 kstrlen 生成器，结果放在 X0，
// 由执行器回读 X0 写入 out_len；out_len 在入口处先清零，失败时保持 0。
KModErr kstrlen(uint64_t kmem, uint64_t& out_len) {
    out_len = 0;
    aarch64_asm_ctx asm_ctx = init_aarch64_asm();
    Assembler* a = asm_ctx.assembler();
    arm64_module_asm_func_start(a);

    aarch64_asm_mov_x(a, x11, kmem);
    kstrlen(a, x11);
    arm64_module_asm_func_end(a, x0);

    std::vector<uint8_t> bytes = aarch64_asm_to_bytes(a);
    return execute_kernel_asm_func(bytes, out_len);
}

// kstrnlen（外部调用版本）：计算内核地址 kmem 处字符串在 maxlen 限制内的长度，
// 结果写入 out_len；返回值为 OK 代表执行成功。
//
// 内核侧代码序列：字符串地址装入 X11、长度上限装入 X12，调用 kstrnlen 生成器；
// 结果由执行器从 X0 回读写入 out_len；out_len 在入口处先清零。
KModErr kstrnlen(uint64_t kmem, uint64_t maxlen, uint64_t& out_len) {
    out_len = 0;
    aarch64_asm_ctx asm_ctx = init_aarch64_asm();
    Assembler* a = asm_ctx.assembler();
    arm64_module_asm_func_start(a);

    aarch64_asm_mov_x(a, x11, kmem);
    aarch64_asm_mov_x(a, x12, maxlen);
    kstrnlen(a, x11, x12);
    arm64_module_asm_func_end(a, x0);

    std::vector<uint8_t> bytes = aarch64_asm_to_bytes(a);
    return execute_kernel_asm_func(bytes, out_len);
}

// strlen：从 str 起逐字节扫描 '\0'，X0 返回长度。
void kstrlen(Assembler* a, GpX str) {
    IdleRegPool pool = IdleRegPool::make(str);
    GpX r5 = pool.acquireX();
    GpW w6 = pool.acquireW();
    RegProtectGuard guard(a, excluding_x0(pool.getUsed()));
    Label L10 = a->newLabel();
    Label L11 = a->newLabel();
    a->mov(r5, xzr);
    a->cbz(str, L11);
    a->bind(L10);
    a->ldrb(w6, ptr(str, r5));
    a->cbz(w6, L11);
    a->add(r5, r5, Imm(1));
    a->b(L10);
    a->bind(L11);
    a->mov(x0, r5);
}

// _ZN13kernel_module10string_ops8kstrnlenEPN6asmjit5v1_163a649AssemblerENS3_3GpXES6_

// strnlen：最多扫描 maxlen 字节，未在限制内遇到 '\0' 时 X0 返回 maxlen。
void kstrnlen(Assembler* a, GpX str, GpX maxlen) {
    IdleRegPool pool = IdleRegPool::make(str, maxlen);
    GpX r7 = pool.acquireX();
    GpX r8 = pool.acquireX();
    GpW w9 = pool.acquireW();
    RegProtectGuard guard(a, excluding_x0(pool.getUsed()));
    Label L13 = a->newLabel();
    Label L14 = a->newLabel();
    a->mov(r7, xzr);
    a->cbz(str, L14);
    a->cbz(maxlen, L14);
    a->bind(L13);
    a->sub(r8, maxlen, r7);
    a->cbz(r8, L14);
    a->ldrb(w9, ptr(str, r7));
    a->cbz(w9, L14);
    a->add(r7, r7, Imm(1));
    a->b(L13);
    a->bind(L14);
    a->mov(x0, r7);
}

// _ZN13kernel_module10string_ops8kstrnlenEPN6asmjit5v1_163a649AssemblerENS3_3GpXEm

// strnlen：最多扫描 maxlen 字节，未在限制内遇到 '\0' 时 X0 返回 maxlen。
void kstrnlen(Assembler* a, GpX str, uint64_t maxlen) {
    IdleRegPool pool = IdleRegPool::make(str);
    GpX r6 = pool.acquireX();
    RegProtectGuard guard(a, excluding_x0(pool.getUsed()));
    aarch64_asm_mov_x(a, r6, maxlen);
    kstrnlen(a, str, r6);
}

// _ZN13kernel_module10string_ops8kstrncmpEPN6asmjit5v1_163a649AssemblerENS3_3GpXES6_S6_

// strncmp：最多比较 n 个字节，相等时 X0 为 0，否则返回首个不同字节的差值。
void kstrncmp(Assembler* a, GpX str1, GpX str2, GpX n) {
    IdleRegPool pool = IdleRegPool::make(str1, str2, n);
    GpX r9 = pool.acquireX();
    GpX r11 = pool.acquireX();
    GpW w12 = pool.acquireW();
    GpW w13 = pool.acquireW();
    GpW w14 = pool.acquireW();
    RegProtectGuard guard(a, excluding_x0(pool.getUsed()));
    Label L18 = a->newLabel();
    Label L19 = a->newLabel();
    Label L20 = a->newLabel();
    a->mov(r9, xzr);
    a->mov(r11, xzr);
    a->cbz(str1, L20);
    a->cbz(str2, L20);
    a->bind(L18);
    a->cmp(r9, n);
    a->b(CondCode::kCS, L20);
    a->ldrb(w12, ptr(str1, r9));
    a->ldrb(w13, ptr(str2, r9));
    a->cmp(w12, w13);
    a->b(CondCode::kNE, L19);
    a->cbz(w12, L20);
    a->add(r9, r9, Imm(1));
    a->b(L18);
    a->bind(L19);
    a->sub(w14, w12, w13);
    a->sxtw(r11, w14);
    a->bind(L20);
    a->mov(x0, r11);
}

// _ZN13kernel_module10string_ops8kstrncmpEPN6asmjit5v1_163a649AssemblerENS3_3GpXES6_m

// strncmp：最多比较 n 个字节，相等时 X0 为 0，否则返回首个不同字节的差值。
void kstrncmp(Assembler* a, GpX str1, GpX str2, uint64_t n) {
    IdleRegPool pool = IdleRegPool::make(str1, str2);
    GpX r8 = pool.acquireX();
    RegProtectGuard guard(a, excluding_x0(pool.getUsed()));
    aarch64_asm_mov_x(a, r8, n);
    kstrncmp(a, str1, str2, r8);
}

// _ZN13kernel_module10string_ops8kstrncpyEPN6asmjit5v1_163a649AssemblerENS3_3GpXES6_S6_

// strncpy：最多复制 n 字节；src 提前结束时用 '\0' 补齐；X0 返回 dst。
void kstrncpy(Assembler* a, GpX dst, GpX src, GpX n) {
    IdleRegPool pool = IdleRegPool::make(dst, src, n);
    GpX r9 = pool.acquireX();
    GpW w10 = pool.acquireW();
    RegProtectGuard guard(a, excluding_x0(pool.getUsed()));
    Label L14 = a->newLabel();
    Label L15 = a->newLabel();
    Label L16 = a->newLabel();
    a->cbz(dst, L16);
    a->cbz(src, L16);
    a->cbz(n, L16);
    a->mov(r9, xzr);
    a->bind(L14);
    a->cmp(r9, n);
    a->b(CondCode::kCS, L16);
    a->ldrb(w10, ptr(src, r9));
    a->strb(w10, ptr(dst, r9));
    a->add(r9, r9, Imm(1));
    a->cbnz(w10, L14);
    a->mov(w10, wzr);
    a->bind(L15);
    a->cmp(r9, n);
    a->b(CondCode::kCS, L16);
    a->strb(w10, ptr(dst, r9));
    a->add(r9, r9, Imm(1));
    a->b(L15);
    a->bind(L16);
    a->mov(x0, dst);
}

// _ZN13kernel_module10string_ops8kstrncpyEPN6asmjit5v1_163a649AssemblerENS3_3GpXES6_m

// strncpy：最多复制 n 字节；src 提前结束时用 '\0' 补齐；X0 返回 dst。
void kstrncpy(Assembler* a, GpX dst, GpX src, uint64_t n) {
    IdleRegPool pool = IdleRegPool::make(dst, src);
    GpX r8 = pool.acquireX();
    RegProtectGuard guard(a, excluding_x0(pool.getUsed()));
    aarch64_asm_mov_x(a, r8, n);
    kstrncpy(a, dst, src, r8);
}

// _ZN13kernel_module10string_ops7kstrcatEPN6asmjit5v1_163a649AssemblerENS3_3GpXES6_

// strcat：把 src 连同终止符追加到 dst 末尾；X0 返回 dst。
void kstrcat(Assembler* a, GpX dst, GpX src) {
    IdleRegPool pool = IdleRegPool::make(dst, src);
    GpX r7 = pool.acquireX();
    GpX r8 = pool.acquireX();
    GpW w9 = pool.acquireW();
    RegProtectGuard guard(a, excluding_x0(pool.getUsed()));
    Label L13 = a->newLabel();
    Label L14 = a->newLabel();
    Label L15 = a->newLabel();
    a->cbz(dst, L15);
    a->cbz(src, L15);
    a->mov(r7, dst);
    a->mov(r8, src);
    a->bind(L13);
    a->ldrb(w9, ptr(r7));
    a->cbz(w9, L14);
    a->add(r7, r7, Imm(1));
    a->b(L13);
    a->bind(L14);
    a->ldrb(w9, ptr(r8));
    a->strb(w9, ptr(r7));
    a->add(r8, r8, Imm(1));
    a->add(r7, r7, Imm(1));
    a->cbnz(w9, L14);
    a->bind(L15);
    a->mov(x0, dst);
}

// _ZN13kernel_module10string_ops8kstrncatEPN6asmjit5v1_163a649AssemblerENS3_3GpXES6_S6_

// strncat：最多追加 n 个字符并在末尾补 '\0'；X0 返回 dst。
void kstrncat(Assembler* a, GpX dst, GpX src, GpX n) {
    IdleRegPool pool = IdleRegPool::make(dst, src, n);
    GpX r9 = pool.acquireX();
    GpX r10 = pool.acquireX();
    GpX r11 = pool.acquireX();
    GpW w12 = pool.acquireW();
    RegProtectGuard guard(a, excluding_x0(pool.getUsed()));
    Label L16 = a->newLabel();
    Label L17 = a->newLabel();
    Label L18 = a->newLabel();
    Label L19 = a->newLabel();
    a->cbz(dst, L19);
    a->cbz(src, L19);
    a->cbz(n, L19);
    a->mov(r9, dst);
    a->mov(r10, src);
    a->mov(r11, n);
    a->bind(L16);
    a->ldrb(w12, ptr(r9));
    a->cbz(w12, L17);
    a->add(r9, r9, Imm(1));
    a->b(L16);
    a->bind(L17);
    a->cbz(r11, L18);
    a->ldrb(w12, ptr(r10));
    a->cbz(w12, L18);
    a->strb(w12, ptr(r9));
    a->add(r10, r10, Imm(1));
    a->add(r9, r9, Imm(1));
    a->sub(r11, r11, Imm(1));
    a->b(L17);
    a->bind(L18);
    a->mov(w12, wzr);
    a->strb(w12, ptr(r9));
    a->bind(L19);
    a->mov(x0, dst);
}

// _ZN13kernel_module10string_ops8kstrncatEPN6asmjit5v1_163a649AssemblerENS3_3GpXES6_m

// strncat：最多追加 n 个字符并在末尾补 '\0'；X0 返回 dst。
void kstrncat(Assembler* a, GpX dst, GpX src, uint64_t n) {
    IdleRegPool pool = IdleRegPool::make(dst, src);
    GpX r8 = pool.acquireX();
    RegProtectGuard guard(a, excluding_x0(pool.getUsed()));
    aarch64_asm_mov_x(a, r8, n);
    kstrncat(a, dst, src, r8);
}

// _ZN13kernel_module10string_ops7kstrstrEPN6asmjit5v1_163a649AssemblerENS3_3GpXES6_

// strstr：在 haystack 中查找 needle，找到时 X0 为首次匹配地址，否则为 0。
void kstrstr(Assembler* a, GpX haystack, GpX needle) {
    IdleRegPool pool = IdleRegPool::make(haystack, needle);
    GpX r7 = pool.acquireX();
    GpX r8 = pool.acquireX();
    GpX r9 = pool.acquireX();
    GpX r10 = pool.acquireX();
    GpW w11 = pool.acquireW();
    GpW w12 = pool.acquireW();
    RegProtectGuard guard(a, excluding_x0(pool.getUsed()));
    Label L16 = a->newLabel();
    Label L17 = a->newLabel();
    Label L18 = a->newLabel();
    Label L19 = a->newLabel();
    Label L20 = a->newLabel();
    a->mov(r7, xzr);
    a->mov(r10, xzr);
    a->cbz(haystack, L20);
    a->cbz(needle, L20);
    a->ldrb(w11, ptr(needle));
    a->cbnz(w11, L16);
    a->mov(r10, haystack);
    a->b(L20);
    a->bind(L16);
    a->mov(r8, r7);
    a->mov(r9, xzr);
    a->bind(L17);
    a->ldrb(w11, ptr(haystack, r8));
    a->ldrb(w12, ptr(needle, r9));
    a->add(r8, r8, Imm(1));
    a->add(r9, r9, Imm(1));
    a->cbz(w12, L18);
    a->cmp(w11, w12);
    a->b(CondCode::kNE, L19);
    a->b(L17);
    a->bind(L18);
    a->add(r10, haystack, r7);
    a->b(L20);
    a->bind(L19);
    a->cbz(w11, L20);
    a->add(r7, r7, Imm(1));
    a->b(L16);
    a->bind(L20);
    a->mov(x0, r10);
}

// _ZN13kernel_module10string_ops7kstrchrEPN6asmjit5v1_163a649AssemblerENS3_3GpXENS3_3GpWE

// strchr：查找字符 c 首次出现的位置，找到时 X0 为该地址，否则为 0。
void kstrchr(Assembler* a, GpX str, GpW c) {
    IdleRegPool pool = IdleRegPool::make(str, c);
    GpX r7 = pool.acquireX();
    GpX r8 = pool.acquireX();
    GpW w9 = pool.acquireW();
    GpW w10 = pool.acquireW();
    RegProtectGuard guard(a, excluding_x0(pool.getUsed()));
    Label L14 = a->newLabel();
    Label L15 = a->newLabel();
    Label L16 = a->newLabel();
    a->mov(r7, xzr);
    a->mov(r8, xzr);
    a->cbz(str, L16);
    a->and_(w10, c, Imm(255));
    a->bind(L14);
    a->ldrb(w9, ptr(str, r7));
    a->cmp(w9, w10);
    a->b(CondCode::kEQ, L15);
    a->cbz(w9, L16);
    a->add(r7, r7, Imm(1));
    a->b(L14);
    a->bind(L15);
    a->add(r8, str, r7);
    a->bind(L16);
    a->mov(x0, r8);
}

// _ZN13kernel_module10string_ops7kstrchrEPN6asmjit5v1_163a649AssemblerENS3_3GpXEh

// strchr：查找字符 c 首次出现的位置，找到时 X0 为该地址，否则为 0。
void kstrchr(Assembler* a, GpX str, uint8_t c) {
    IdleRegPool pool = IdleRegPool::make(str);
    GpW w6 = pool.acquireW();
    RegProtectGuard guard(a, excluding_x0(pool.getUsed()));
    aarch64_asm_mov_w(a, w6, c);
    kstrchr(a, str, w6);
}

// _ZN13kernel_module10string_ops8kstrrchrEPN6asmjit5v1_163a649AssemblerENS3_3GpXENS3_3GpWE

// strrchr：查找字符 c 最后一次出现的位置，找到时 X0 为该地址，否则为 0。
void kstrrchr(Assembler* a, GpX str, GpW c) {
    IdleRegPool pool = IdleRegPool::make(str, c);
    GpX r7 = pool.acquireX();
    GpX r8 = pool.acquireX();
    GpW w9 = pool.acquireW();
    GpW w10 = pool.acquireW();
    RegProtectGuard guard(a, excluding_x0(pool.getUsed()));
    Label L14 = a->newLabel();
    Label L15 = a->newLabel();
    Label L16 = a->newLabel();
    Label L17 = a->newLabel();
    a->mov(r7, xzr);
    a->mov(r8, xzr);
    a->cbz(str, L17);
    a->and_(w10, c, Imm(255));
    a->bind(L14);
    a->ldrb(w9, ptr(str, r7));
    a->cmp(w9, w10);
    a->b(CondCode::kEQ, L15);
    a->bind(L16);
    a->cbz(w9, L17);
    a->add(r7, r7, Imm(1));
    a->b(L14);
    a->bind(L15);
    a->add(r8, str, r7);
    a->b(L16);
    a->bind(L17);
    a->mov(x0, r8);
}

// _ZN13kernel_module10string_ops8kstrrchrEPN6asmjit5v1_163a649AssemblerENS3_3GpXEh

// strrchr：查找字符 c 最后一次出现的位置，找到时 X0 为该地址，否则为 0。
void kstrrchr(Assembler* a, GpX str, uint8_t c) {
    IdleRegPool pool = IdleRegPool::make(str);
    GpW w6 = pool.acquireW();
    RegProtectGuard guard(a, excluding_x0(pool.getUsed()));
    aarch64_asm_mov_w(a, w6, c);
    kstrrchr(a, str, w6);
}

// _ZN13kernel_module10string_ops7kmemcmpEPN6asmjit5v1_163a649AssemblerENS3_3GpXES6_S6_

// memcmp：按字节比较前 n 字节，相等时 X0 为 0，否则返回首个不同字节的差值。
void kmemcmp(Assembler* a, GpX buf1, GpX buf2, GpX n) {
    IdleRegPool pool = IdleRegPool::make(buf1, buf2, n);
    GpX r9 = pool.acquireX();
    GpX r10 = pool.acquireX();
    GpW w11 = pool.acquireW();
    GpW w12 = pool.acquireW();
    GpW w13 = pool.acquireW();
    RegProtectGuard guard(a, excluding_x0(pool.getUsed()));
    Label L17 = a->newLabel();
    Label L18 = a->newLabel();
    Label L19 = a->newLabel();
    a->mov(r9, xzr);
    a->mov(r10, xzr);
    a->cbz(n, L19);
    a->bind(L17);
    a->ldrb(w11, ptr(buf1, r9));
    a->ldrb(w12, ptr(buf2, r9));
    a->cmp(w11, w12);
    a->b(CondCode::kNE, L18);
    a->add(r9, r9, Imm(1));
    a->cmp(r9, n);
    a->b(CondCode::kCC, L17);
    a->b(L19);
    a->bind(L18);
    a->sub(w13, w11, w12);
    a->sxtw(r10, w13);
    a->bind(L19);
    a->mov(x0, r10);
}

// _ZN13kernel_module10string_ops7kmemcpyEPN6asmjit5v1_163a649AssemblerENS3_3GpXES6_S6_

// memcpy：从 src 复制 n 字节到 dst（非重叠区域）；X0 返回 dst。
void kmemcpy(Assembler* a, GpX dst, GpX src, GpX n) {
    IdleRegPool pool = IdleRegPool::make(dst, src, n);
    GpX r9 = pool.acquireX();
    GpX r10 = pool.acquireX();
    GpX r11 = pool.acquireX();
    GpW w12 = pool.acquireW();
    RegProtectGuard guard(a, excluding_x0(pool.getUsed()));
    Label L15 = a->newLabel();
    Label L16 = a->newLabel();
    Label L17 = a->newLabel();
    Label L18 = a->newLabel();
    a->cbz(n, L18);
    a->cbz(dst, L18);
    a->cbz(src, L18);
    a->mov(r9, xzr);
    a->lsr(r10, n, Imm(3));
    a->cbz(r10, L16);
    a->bind(L15);
    a->ldr(r11, ptr(src, r9));
    a->str(r11, ptr(dst, r9));
    a->add(r9, r9, Imm(8));
    a->subs(r10, r10, Imm(1));
    a->b(CondCode::kNE, L15);
    a->bind(L16);
    a->cmp(r9, n);
    a->b(CondCode::kCS, L18);
    a->bind(L17);
    a->ldrb(w12, ptr(src, r9));
    a->strb(w12, ptr(dst, r9));
    a->add(r9, r9, Imm(1));
    a->cmp(r9, n);
    a->b(CondCode::kCC, L17);
    a->bind(L18);
}

// _ZN13kernel_module10string_ops7kmemcpyEPN6asmjit5v1_163a649AssemblerENS3_3GpXES6_m

// memcpy：从 src 复制 n 字节到 dst（非重叠区域）；X0 返回 dst。
void kmemcpy(Assembler* a, GpX dst, GpX src, uint64_t n) {
    IdleRegPool pool = IdleRegPool::make(dst, src);
    GpX r8 = pool.acquireX();
    RegProtectGuard guard(a, excluding_x0(pool.getUsed()));
    aarch64_asm_mov_x(a, r8, n);
    kmemcpy(a, dst, src, r8);
}

// _ZN13kernel_module10string_ops7kmemmemEPN6asmjit5v1_163a649AssemblerENS3_3GpXES6_S6_S6_

// memmem：在 buf 前 n 字节内查找 needle（长度 needle_n）；找到时 X0 为匹配地址，否则为 0。
void kmemmem(Assembler* a, GpX buf, GpX n, GpX needle, GpX needle_n) {
    IdleRegPool pool = IdleRegPool::make(buf, n, needle, needle_n);
    GpX r11 = pool.acquireX();
    GpX r12 = pool.acquireX();
    GpX r13 = pool.acquireX();
    GpX r14 = pool.acquireX();
    GpX r15 = pool.acquireX();
    GpW w16 = pool.acquireW();
    GpW w17 = pool.acquireW();
    RegProtectGuard guard(a, excluding_x0(pool.getUsed()));
    Label L21 = a->newLabel();
    Label L22 = a->newLabel();
    Label L23 = a->newLabel();
    Label L24 = a->newLabel();
    Label L25 = a->newLabel();
    a->mov(r15, xzr);
    a->cbnz(needle_n, L21);
    a->mov(r15, buf);
    a->b(L25);
    a->bind(L21);
    a->cbz(buf, L25);
    a->cbz(needle, L25);
    a->cbz(n, L25);
    a->cmp(needle_n, n);
    a->b(CondCode::kHI, L25);
    a->sub(r13, n, needle_n);
    a->mov(r11, Imm(0));
    Label L27 = a->newLabel();
    a->bind(L27);
    a->cmp(r11, r13);
    a->b(CondCode::kHI, L25);
    a->mov(r12, Imm(0));
    a->mov(r14, r11);
    a->bind(L22);
    a->ldrb(w16, ptr(buf, r14));
    a->ldrb(w17, ptr(needle, r12));
    a->cmp(w16, w17);
    a->b(CondCode::kNE, L23);
    a->add(r14, r14, Imm(1));
    a->add(r12, r12, Imm(1));
    a->cmp(r12, needle_n);
    a->b(CondCode::kCS, L24);
    a->b(L22);
    a->bind(L23);
    a->add(r11, r11, Imm(1));
    a->b(L27);
    a->bind(L24);
    a->add(r15, buf, r11);
    a->bind(L25);
    a->mov(x0, r15);
}

// _ZN13kernel_module10string_ops7kmemmemEPN6asmjit5v1_163a649AssemblerENS3_3GpXES6_S6_m

// memmem：在 buf 前 n 字节内查找 needle（长度 needle_n）；找到时 X0 为匹配地址，否则为 0。
void kmemmem(Assembler* a, GpX buf, GpX n, GpX needle, uint64_t needle_n) {
    IdleRegPool pool = IdleRegPool::make(buf, n, needle);
    GpX r10 = pool.acquireX();
    RegProtectGuard guard(a, excluding_x0(pool.getUsed()));
    aarch64_asm_mov_x(a, r10, needle_n);
    kmemmem(a, buf, n, needle, r10);
}

// _ZN13kernel_module10string_ops7kmemmemEPN6asmjit5v1_163a649AssemblerENS3_3GpXEmS6_S6_

// memmem：在 buf 前 n 字节内查找 needle（长度 needle_n）；找到时 X0 为匹配地址，否则为 0。
void kmemmem(Assembler* a, GpX buf, uint64_t n, GpX needle, GpX needle_n) {
    IdleRegPool pool = IdleRegPool::make(buf, needle, needle_n);
    GpX r10 = pool.acquireX();
    RegProtectGuard guard(a, excluding_x0(pool.getUsed()));
    aarch64_asm_mov_x(a, r10, n);
    kmemmem(a, buf, r10, needle, needle_n);
}

// _ZN13kernel_module10string_ops7kmemmemEPN6asmjit5v1_163a649AssemblerENS3_3GpXEmS6_m

// memmem：在 buf 前 n 字节内查找 needle（长度 needle_n）；找到时 X0 为匹配地址，否则为 0。
void kmemmem(Assembler* a, GpX buf, uint64_t n, GpX needle, uint64_t needle_n) {
    IdleRegPool pool = IdleRegPool::make(buf, needle);
    GpX r9 = pool.acquireX();
    GpX r10 = pool.acquireX();
    RegProtectGuard guard(a, excluding_x0(pool.getUsed()));
    aarch64_asm_mov_x(a, r9, n);
    aarch64_asm_mov_x(a, r10, needle_n);
    kmemmem(a, buf, r9, needle, r10);
}

// _ZN13kernel_module10string_ops7kmemchrEPN6asmjit5v1_163a649AssemblerENS3_3GpXENS3_3GpWES6_

// memchr：在前 n 字节内查找字节 c；找到时 X0 为首次匹配地址，否则为 0。
void kmemchr(Assembler* a, GpX buf, GpW c, GpX n) {
    IdleRegPool pool = IdleRegPool::make(buf, c, n);
    GpX r9 = pool.acquireX();
    GpX r11 = pool.acquireX();
    GpW w12 = pool.acquireW();
    GpW w13 = pool.acquireW();
    RegProtectGuard guard(a, excluding_x0(pool.getUsed()));
    Label L17 = a->newLabel();
    Label L18 = a->newLabel();
    Label L19 = a->newLabel();
    a->mov(r9, xzr);
    a->mov(r11, xzr);
    a->cbz(buf, L19);
    a->cbz(n, L19);
    a->and_(w13, c, Imm(255));
    a->bind(L17);
    a->cmp(r9, n);
    a->b(CondCode::kCS, L19);
    a->ldrb(w12, ptr(buf, r9));
    a->cmp(w12, w13);
    a->b(CondCode::kEQ, L18);
    a->add(r9, r9, Imm(1));
    a->b(L17);
    a->bind(L18);
    a->add(r11, buf, r9);
    a->bind(L19);
    a->mov(x0, r11);
}

// _ZN13kernel_module10string_ops7kmemchrEPN6asmjit5v1_163a649AssemblerENS3_3GpXENS3_3GpWEm

// memchr：在前 n 字节内查找字节 c；找到时 X0 为首次匹配地址，否则为 0。
void kmemchr(Assembler* a, GpX buf, GpW c, uint64_t n) {
    IdleRegPool pool = IdleRegPool::make(buf, c);
    GpX r8 = pool.acquireX();
    RegProtectGuard guard(a, excluding_x0(pool.getUsed()));
    aarch64_asm_mov_x(a, r8, n);
    kmemchr(a, buf, c, r8);
}

// _ZN13kernel_module10string_ops7kmemchrEPN6asmjit5v1_163a649AssemblerENS3_3GpXEhS6_

// memchr：在前 n 字节内查找字节 c；找到时 X0 为首次匹配地址，否则为 0。
void kmemchr(Assembler* a, GpX buf, uint8_t c, GpX n) {
    IdleRegPool pool = IdleRegPool::make(buf, n);
    GpW w8 = pool.acquireW();
    RegProtectGuard guard(a, excluding_x0(pool.getUsed()));
    aarch64_asm_mov_w(a, w8, c);
    kmemchr(a, buf, w8, n);
}

// _ZN13kernel_module10string_ops7kmemchrEPN6asmjit5v1_163a649AssemblerENS3_3GpXEhm

// memchr：在前 n 字节内查找字节 c；找到时 X0 为首次匹配地址，否则为 0。
void kmemchr(Assembler* a, GpX buf, uint8_t c, uint64_t n) {
    IdleRegPool pool = IdleRegPool::make(buf);
    GpW w7 = pool.acquireW();
    GpX r8 = pool.acquireX();
    RegProtectGuard guard(a, excluding_x0(pool.getUsed()));
    aarch64_asm_mov_w(a, w7, c);
    aarch64_asm_mov_x(a, r8, n);
    kmemchr(a, buf, w7, r8);
}

// _ZN13kernel_module10string_ops8kmemrchrEPN6asmjit5v1_163a649AssemblerENS3_3GpXENS3_3GpWES6_

// memrchr：在 buf 前 n 字节内从后向前查找字节 c；找到时 X0 为匹配地址，否则为 0。
void kmemrchr(Assembler* a, GpX buf, GpW c, GpX n) {
    IdleRegPool pool = IdleRegPool::make(buf, c, n);
    GpX r9 = pool.acquireX();
    GpX r10 = pool.acquireX();
    GpW w11 = pool.acquireW();
    GpW w12 = pool.acquireW();
    RegProtectGuard guard(a, excluding_x0(pool.getUsed()));
    Label L16 = a->newLabel();
    Label L17 = a->newLabel();
    Label L18 = a->newLabel();
    a->mov(r10, xzr);
    a->cbz(buf, L18);
    a->cbz(n, L18);
    a->and_(w12, c, Imm(255));
    a->mov(r9, n);
    a->bind(L16);
    a->cbz(r9, L18);
    a->sub(r9, r9, Imm(1));
    a->ldrb(w11, ptr(buf, r9));
    a->cmp(w11, w12);
    a->b(CondCode::kEQ, L17);
    a->b(L16);
    a->bind(L17);
    a->add(r10, buf, r9);
    a->bind(L18);
    a->mov(x0, r10);
}

// _ZN13kernel_module10string_ops8kmemrchrEPN6asmjit5v1_163a649AssemblerENS3_3GpXENS3_3GpWEm

// memrchr：在 buf 前 n 字节内从后向前查找字节 c；找到时 X0 为匹配地址，否则为 0。
void kmemrchr(Assembler* a, GpX buf, GpW c, uint64_t n) {
    IdleRegPool pool = IdleRegPool::make(buf, c);
    GpX r8 = pool.acquireX();
    RegProtectGuard guard(a, excluding_x0(pool.getUsed()));
    aarch64_asm_mov_x(a, r8, n);
    kmemrchr(a, buf, c, r8);
}

// _ZN13kernel_module10string_ops8kmemrchrEPN6asmjit5v1_163a649AssemblerENS3_3GpXEhS6_

// memrchr：在 buf 前 n 字节内从后向前查找字节 c；找到时 X0 为匹配地址，否则为 0。
void kmemrchr(Assembler* a, GpX buf, uint8_t c, GpX n) {
    IdleRegPool pool = IdleRegPool::make(buf, n);
    GpW w8 = pool.acquireW();
    RegProtectGuard guard(a, excluding_x0(pool.getUsed()));
    aarch64_asm_mov_w(a, w8, c);
    kmemrchr(a, buf, w8, n);
}

// _ZN13kernel_module10string_ops8kmemrchrEPN6asmjit5v1_163a649AssemblerENS3_3GpXEhm

// memrchr：在 buf 前 n 字节内从后向前查找字节 c；找到时 X0 为匹配地址，否则为 0。
void kmemrchr(Assembler* a, GpX buf, uint8_t c, uint64_t n) {
    IdleRegPool pool = IdleRegPool::make(buf);
    GpW w7 = pool.acquireW();
    GpX r8 = pool.acquireX();
    RegProtectGuard guard(a, excluding_x0(pool.getUsed()));
    aarch64_asm_mov_w(a, w7, c);
    aarch64_asm_mov_x(a, r8, n);
    kmemrchr(a, buf, w7, r8);
}

// _ZN13kernel_module10string_ops11kstartswithEPN6asmjit5v1_163a649AssemblerENS3_3GpXES6_

// 前缀判断：str 以 prefix 开头时 X0 为 1，否则为 0。
void kstartswith(Assembler* a, GpX str, GpX prefix) {
    IdleRegPool pool = IdleRegPool::make(str, prefix);
    GpX r7 = pool.acquireX();
    GpX r8 = pool.acquireX();
    GpW w9 = pool.acquireW();
    GpW w10 = pool.acquireW();
    RegProtectGuard guard(a, excluding_x0(pool.getUsed()));
    Label L14 = a->newLabel();
    Label L15 = a->newLabel();
    Label L16 = a->newLabel();
    a->mov(r7, xzr);
    a->mov(r8, xzr);
    a->cbz(str, L16);
    a->cbz(prefix, L16);
    a->bind(L14);
    a->ldrb(w10, ptr(prefix, r7));
    a->cmp(w10, wzr);
    a->b(CondCode::kEQ, L15);
    a->ldrb(w9, ptr(str, r7));
    a->cbz(w9, L16);
    a->cmp(w9, w10);
    a->b(CondCode::kNE, L16);
    a->add(r7, r7, Imm(1));
    a->b(L14);
    a->bind(L15);
    a->mov(r8, Imm(1));
    a->bind(L16);
    a->mov(x0, r8);
}



}  // namespace string_ops
}  // namespace kernel_module
