// ===========================================================================
// R5 / V4a 正式用例 —— write_kernel_mem(KMP_RO|KMP_X) 的补丁闭包行为
//
//   patch_kernel_static_code::$_0
//   _ZNSt6__ndk110__function6__funcIZN13kernel_moduleL24patch_kernel_static_codeEmPKvjE
//   3$_0NS_9allocatorIS5_EEF7KModErrPN6asmjit5v1_163a649AssemblerEEEclEOSD_
//
// 做法：把 src/kernel_mem/module_base_kernel_mem.cpp **原文**编译进本用例，
//       但头文件走 tests/stub/ 下的替身：
//         * asmjit 形状桩（记录 newLabel/bind/b/embed/ldr/str/adr/movz…）
//         * RegProtectGuard 桩（记录 STP/LDP）
//         * 内核导出符号桩（set_memory_* / aarch64_insn_patch_text）、
//           执行器桩（arm64_module_asm_func_* / execute_kernel_asm_func）、
//           版本与符号解析桩
//       只记录「调用顺序 + 立即数」，不执行、不下发设备、不链 Android 库。
//
// 判据（对应任务书 §2/§3 与 ACCEPTANCE V4a）：
//   A. 成功路径按序调用：标签 → system_state 保存/清零 → STP 现场保护 →
//      B 跳过表 → 地址表(.quad ×N) → 指令表(.word ×N) → bind →
//      ADR x0(-3*size) / ADR x1(-size) / MOV W2,size/4 →
//      aarch64_insn_patch_text → LDP 恢复 → STR 写回 system_state →
//      IC IALLU(936) → DSB ISH(11) → ISB(15) → 执行 → icache_invalidate_all_cpus
//   B. 失败路径回滚：aarch64_insn_patch_text 报错时，LDP（现场）照发，
//      但 STR 写回 / IC / DSB / ISB / 执行 / icache 一律不发，错误码原样上抛。
//   C. KMP_RW 仍走 request_kernel_write_mem，完全不生成补丁汇编。
//   D. 错误码只用 include/module_err_def.h 既有枚举。
//   E. 同一输入重复调用 → 事件序列与 staging 内容逐字节一致（可重放）。
//
// 构建/运行（主机 clang，任意平台，不链 Android 库）：
//   clang++ -std=c++17 -O2 -Wall -Wextra \
//       -I runtime/maplesu-sdk/sdk/tests/stub \
//       -I runtime/maplesu-sdk/include \
//       runtime/maplesu-sdk/sdk/tests/r5_patch_closure_test.cpp \
//       -o /tmp/r5_patch_closure_test && /tmp/r5_patch_closure_test
// ===========================================================================

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <vector>

// 记录器（必须先于被测算源引入，桩头文件共用同一份）
#include "r5_probe.h"

// ---------------------------------------------------------------------------
// 被测算源：原文编译。它的 #include 由 -I tests/stub 命中替身头。
// ---------------------------------------------------------------------------
#include "../src/kernel_mem/module_base_kernel_mem.cpp"

// ---------------------------------------------------------------------------
// 外部符号定义（桩）
// ---------------------------------------------------------------------------
namespace kernel_module {

bool is_kernel_version_less(const char* ver) {
    const bool is_419_probe = (ver != nullptr) && (std::strcmp(ver, "4.19.0") == 0);
    r5::record("is_kernel_version_less", is_419_probe ? 1 : 0);
    return r5::g_kernel_4_19_less;
}

KModErr kallsyms_lookup_name(const char* name, uint64_t& out_kaddr) {
    r5::record("kallsyms_lookup_name", name != nullptr ? 1 : 0);
    out_kaddr = r5::g_system_state_addr;
    return static_cast<KModErr>(r5::g_kallsyms_err);
}

const char* current_module_root_key() { return r5::g_root_key; }

// 以下三个由 .cpp 自己前置声明（无公开头），这里给定义
void parser_root_key_info(const char* root_key, int32_t& out_info) {
    (void)root_key;
    out_info = 0;
}

KModErr get_append_package_data_offset(uint32_t& out_offset) {
    out_offset = r5::g_append_offset;
    return KModErr::OK;
}

KModErr icache_invalidate_all_cpus() {
    r5::record("icache_invalidate_all_cpus");
    return KModErr::OK;
}

KModErr request_kernel_alloc_mem(uint32_t size, uint64_t& out_kaddr) {
    r5::record("request_kernel_alloc_mem", size);
    out_kaddr = 0xFFFF000000002000ull;
    return KModErr::OK;
}

KModErr request_kernel_write_mem(uint64_t kaddr, const void* buf, uint32_t size) {
    r5::record("request_kernel_write_mem", static_cast<long long>(kaddr), size,
               buf != nullptr ? 1 : 0);
    return KModErr::OK;
}

KModErr request_kernel_read_mem(uint64_t kaddr, void* buf, uint32_t size) {
    r5::record("request_kernel_read_mem", static_cast<long long>(kaddr), size);
    (void)buf;
    return KModErr::OK;
}

namespace export_symbol {

void set_memory_ro(Assembler* a, KModErr& out_err, uint64_t addr, uint32_t numpages) {
    (void)a;
    r5::record("set_memory_ro", static_cast<long long>(addr), numpages);
    out_err = KModErr::OK;
}
void set_memory_ro(Assembler* a, KModErr& out_err, GpX addr, GpW numpages) {
    set_memory_ro(a, out_err, 0, static_cast<uint32_t>(addr.id() + numpages.id()));
}

void set_memory_rw(Assembler* a, KModErr& out_err, uint64_t addr, uint32_t numpages) {
    (void)a;
    r5::record("set_memory_rw", static_cast<long long>(addr), numpages);
    out_err = KModErr::OK;
}
void set_memory_rw(Assembler* a, KModErr& out_err, GpX addr, GpW numpages) {
    set_memory_rw(a, out_err, 0, static_cast<uint32_t>(addr.id() + numpages.id()));
}

void set_memory_x(Assembler* a, KModErr& out_err, uint64_t addr, uint32_t numpages) {
    (void)a;
    r5::record("set_memory_x", static_cast<long long>(addr), numpages);
    out_err = KModErr::OK;
}
void set_memory_x(Assembler* a, KModErr& out_err, GpX addr, GpW numpages) {
    set_memory_x(a, out_err, 0, static_cast<uint32_t>(addr.id() + numpages.id()));
}

void aarch64_insn_patch_text(Assembler* a, KModErr& out_err, GpX addrs, GpX insns, GpW cnt) {
    (void)a;
    r5::record("aarch64_insn_patch_text", addrs.id(), insns.id(), cnt.id());
    out_err = static_cast<KModErr>(r5::g_patch_sym_err);
}

namespace linux_older {
void module_memfree(Assembler* a, KModErr& out_err, GpX module_region) {
    (void)a;
    r5::record("module_memfree", module_region.id());
    out_err = KModErr::OK;
}
}  // namespace linux_older

namespace linux_above_6_12_0 {
void execmem_free(Assembler* a, KModErr& out_err, GpX ptr) {
    (void)a;
    r5::record("execmem_free", ptr.id());
    out_err = KModErr::OK;
}
}  // namespace linux_above_6_12_0

}  // namespace export_symbol

// 执行器桩：记录调用，回放脚本化的传输错误与内核返回值
KModErr execute_kernel_asm_func(const std::vector<uint8_t>& buf, uint64_t& out_result) {
    r5::record("execute_kernel_asm_func", static_cast<long long>(buf.size()));
    out_result = r5::g_kernel_ret;
    return static_cast<KModErr>(r5::g_transport_err);
}

}  // namespace kernel_module

extern "C" long sysconf(int name) noexcept {
    (void)name;
    return static_cast<long>(r5::g_page_size);
}

// ---------------------------------------------------------------------------
// 断言设施
// ---------------------------------------------------------------------------
namespace {

int g_fail = 0;
int g_checks = 0;

struct Exp {
    const char* op;
    long long a;
    long long b;
    long long c;
};

void expect_true(bool cond, const char* what, int line) {
    ++g_checks;
    if (!cond) {
        std::printf("  FAIL  L%-4d %s\n", line, what);
        ++g_fail;
    }
}

#define EXPECT(cond) expect_true((cond), #cond, __LINE__)

void show_trace(const char* name) {
    std::printf("  trace[%s] (%zu 事件):\n", name, r5::events().size());
    for (std::size_t i = 0; i < r5::events().size(); ++i) {
        const r5::Event& e = r5::events()[i];
        std::printf("    %2zu: %-28s %-16lld %-16lld %lld\n", i, e.op.c_str(), e.a, e.b, e.c);
    }
}

// 逐事件比对（op + 三个参数全等）
void check_trace(const char* name, const std::vector<Exp>& exp) {
    ++g_checks;
    const std::vector<r5::Event>& got = r5::events();
    bool ok = (got.size() == exp.size());
    if (!ok) {
        std::printf("  FAIL  [%s] 事件数 %zu != 期望 %zu\n", name, got.size(), exp.size());
    }
    const std::size_t n = got.size() < exp.size() ? got.size() : exp.size();
    for (std::size_t i = 0; i < n; ++i) {
        const bool same = (got[i].op == exp[i].op) && (got[i].a == exp[i].a) &&
                          (got[i].b == exp[i].b) && (got[i].c == exp[i].c);
        if (!same) {
            std::printf("  FAIL  [%s] 事件 %zu 不等：got(%s,%lld,%lld,%lld) exp(%s,%lld,%lld,%lld)\n",
                        name, i, got[i].op.c_str(), got[i].a, got[i].b, got[i].c, exp[i].op,
                        exp[i].a, exp[i].b, exp[i].c);
            ok = false;
        }
    }
    if (!ok) {
        ++g_fail;
        show_trace(name);
    } else {
        std::printf("  OK    [%s] 事件序列全等（%zu 事件）\n", name, got.size());
    }
}

bool has_op(const char* op) {
    for (const r5::Event& e : r5::events()) {
        if (e.op == op) return true;
    }
    return false;
}

int count_op(const char* op) {
    int n = 0;
    for (const r5::Event& e : r5::events()) {
        if (e.op == op) ++n;
    }
    return n;
}

// 每个用例前的公共复位
void reset(const char* name) {
    r5::reset();
    r5::g_kernel_4_19_less = false;
    r5::g_kallsyms_err = 0;
    r5::g_system_state_addr = 0;
    r5::g_patch_sym_err = 0;
    r5::g_transport_err = 0;
    r5::g_kernel_ret = 0;
    std::printf("\n[case] %s\n", name);
}

constexpr uint64_t kKaddr = 0xFFFF000000001000ull;   // 内核地址（>= 0xffff000000000000）
constexpr uint64_t kSysState = 0xFFFF888800000000ull;  // system_state 的地址

}  // namespace

// ---------------------------------------------------------------------------
// 用例
// ---------------------------------------------------------------------------
int main() {
    std::printf("r5_patch_closure_test: 被测算源 = src/kernel_mem/module_base_kernel_mem.cpp\n");

    const uint32_t patch_words[2] = {0x11111111u, 0x22222222u};  // 待写指令（8 字节）

    // === C1 成功路径：system_state 存在 + KMP_X + size=8 =====================
    {
        reset("C1 成功路径（KMP_X, system_state 有效, size=8）");
        r5::g_kernel_4_19_less = true;
        r5::g_system_state_addr = kSysState;

        const KModErr err = kernel_module::write_kernel_mem(
            kKaddr, patch_words, sizeof(patch_words), kernel_module::KernMemProt::KMP_X);
        EXPECT(err == KModErr::OK);

        const long long k0 = static_cast<long long>(kKaddr);
        const std::vector<Exp> exp = {
            {"is_kernel_version_less", 1, 0, 0},
            {"kallsyms_lookup_name", 1, 0, 0},
            {"init_asm_ctx", 0, 0, 0},
            {"func_start", 0, 0, 0},
            {"newLabel", 1, 0, 0},
            {"mov_x", 10, static_cast<long long>(kSysState), 0},   // MOVZ/MOVK X10,#system_state
            {"ldr", 11, 10, 0},                                    // LDR  W11,[X10]
            {"str_w", 31, 10, 0},                                  // STR  WZR,[X10]
            {"stp", 10, 11, -16},                                  // STP  X10,X11,[SP,#-16]!
            {"b", 1, 0, 0},                                        // B    <表尾>
            {"embed", 8, k0 + 0, 0},                               // .quad kaddr+0
            {"embed", 8, k0 + 4, 0},                               // .quad kaddr+4
            {"embed", 4, 0x11111111ll, 0},                         // .word insn[0]
            {"embed", 4, 0x22222222ll, 0},                         // .word insn[4]
            {"bind", 1, 0, 0},                                     // 标签落点
            {"adr", 0, -24, 0},                                    // ADR X0,#-(3*size)  → 地址表首
            {"adr", 1, -12, 0},                                    // ADR X1,#-(size+4)：第一条 ADR 已占 4 字节
            {"mov_w", 2, 2, 0},                                    // MOVZ W2,#size/4
            {"aarch64_insn_patch_text", 0, 1, 2},                  // 内核 text_poke
            {"ldp", 10, 11, 16},                                   // LDP  X10,X11,[SP],#16
            {"str_w", 11, 10, 0},                                  // STR  W11,[X10]（写回）
            {"ic", 936, 0, 0},                                     // IC   IALLU
            {"dsb", 11, 0, 0},                                     // DSB  ISH
            {"isb", 15, 0, 0},                                     // ISB  SY
            {"func_end_x", 0, 0, 0},                               // epilogue 用 x0
            {"to_bytes", 0, 0, 0},
            {"execute_kernel_asm_func", 8, 0, 0},
            {"icache_invalidate_all_cpus", 0, 0, 0},
        };
        check_trace("C1", exp);
    }

    // === C2 emit 期失败（符号解析失败）→ 现场回滚，不半提交 ==================
    {
        reset("C2 patch_text 生成失败 → 现场回滚 + 不半提交");
        r5::g_kernel_4_19_less = true;
        r5::g_system_state_addr = kSysState;
        r5::g_patch_sym_err = static_cast<long long>(KModErr::ERR_MODULE_SYMBOL_NOT_EXIST);

        const KModErr err = kernel_module::write_kernel_mem(
            kKaddr, patch_words, sizeof(patch_words), kernel_module::KernMemProt::KMP_RO);
        EXPECT(err == KModErr::ERR_MODULE_SYMBOL_NOT_EXIST);

        // 关键断言：LDP 照发（现场回滚）、STR/IC/DSB/ISB 都不发
        EXPECT(count_op("ldp") == 1);
        EXPECT(count_op("stp") == 1);
        EXPECT(count_op("ic") == 0);
        EXPECT(count_op("dsb") == 0);
        EXPECT(count_op("isb") == 0);
        EXPECT(count_op("str_w") == 1);              // 只有前置的 STR WZR
        EXPECT(count_op("execute_kernel_asm_func") == 0);  // 生成失败 → 不执行
        EXPECT(count_op("icache_invalidate_all_cpus") == 0);
        EXPECT(!has_op("func_end_x"));               // 提前返回，不走 epilogue

        const std::vector<Exp> exp = {
            {"is_kernel_version_less", 1, 0, 0},
            {"kallsyms_lookup_name", 1, 0, 0},
            {"init_asm_ctx", 0, 0, 0},
            {"func_start", 0, 0, 0},
            {"newLabel", 1, 0, 0},
            {"mov_x", 10, static_cast<long long>(kSysState), 0},
            {"ldr", 11, 10, 0},
            {"str_w", 31, 10, 0},
            {"stp", 10, 11, -16},
            {"b", 1, 0, 0},
            {"embed", 8, static_cast<long long>(kKaddr) + 0, 0},
            {"embed", 8, static_cast<long long>(kKaddr) + 4, 0},
            {"embed", 4, 0x11111111ll, 0},
            {"embed", 4, 0x22222222ll, 0},
            {"bind", 1, 0, 0},
            {"adr", 0, -24, 0},
            {"adr", 1, -12, 0},
            {"mov_w", 2, 2, 0},
            {"aarch64_insn_patch_text", 0, 1, 2},
            {"ldp", 10, 11, 16},                     // ← 唯一的“回滚”动作
        };
        check_trace("C2", exp);
    }

    // === C3 传输失败（执行器返回错误）→ 不广播 icache ========================
    {
        reset("C3 执行器传输失败");
        r5::g_kernel_4_19_less = true;
        r5::g_system_state_addr = kSysState;
        r5::g_transport_err = static_cast<long long>(KModErr::ERR_MODULE_ASM);

        const KModErr err = kernel_module::write_kernel_mem(
            kKaddr, patch_words, sizeof(patch_words), kernel_module::KernMemProt::KMP_X);
        EXPECT(err == KModErr::ERR_MODULE_ASM);
        EXPECT(count_op("execute_kernel_asm_func") == 1);
        EXPECT(count_op("icache_invalidate_all_cpus") == 0);
        EXPECT(count_op("ic") == 1);  // 汇编已完整生成
    }

    // === C4 内核返回非 0（W0 != 0）→ 映射 ERR_MODULE_ASM，不广播 icache ======
    {
        reset("C4 内核 W0 != 0");
        r5::g_kernel_4_19_less = true;
        r5::g_system_state_addr = kSysState;
        r5::g_kernel_ret = 1;  // 内核侧 patch 失败

        const KModErr err = kernel_module::write_kernel_mem(
            kKaddr, patch_words, sizeof(patch_words), kernel_module::KernMemProt::KMP_X);
        EXPECT(err == KModErr::ERR_MODULE_ASM);
        EXPECT(count_op("icache_invalidate_all_cpus") == 0);
    }

    // === C5 KMP_RW 不受影响（走 request 通道，不生成补丁汇编）================
    {
        reset("C5 KMP_RW 走 request_kernel_write_mem");
        const KModErr err = kernel_module::write_kernel_mem(
            kKaddr, patch_words, sizeof(patch_words), kernel_module::KernMemProt::KMP_RW);
        EXPECT(err == KModErr::OK);
        const std::vector<Exp> exp = {
            {"request_kernel_write_mem", static_cast<long long>(kKaddr), 8, 1},
        };
        check_trace("C5", exp);
        EXPECT(count_op("aarch64_insn_patch_text") == 0);
        EXPECT(count_op("ic") == 0);
    }

    // === C6 参数校验（错误码必须是既有枚举）=================================
    {
        reset("C6 参数校验");
        EXPECT(kernel_module::write_kernel_mem(0, patch_words, 8,
                                              kernel_module::KernMemProt::KMP_X) ==
               KModErr::ERR_MODULE_PARAM);
        EXPECT(kernel_module::write_kernel_mem(kKaddr, patch_words, 8,
                                               static_cast<kernel_module::KernMemProt>(3)) ==
               KModErr::ERR_MODULE_PARAM);
        EXPECT(kernel_module::write_kernel_mem((kKaddr | 2ull), patch_words, 8,
                                               kernel_module::KernMemProt::KMP_X) ==
               KModErr::ERR_MODULE_ADDR_NOT_ALGIN4);
        EXPECT(kernel_module::write_kernel_mem(0x1234, patch_words, 8,
                                               kernel_module::KernMemProt::KMP_X) ==
               KModErr::ERR_MODULE_NOT_KADDR);
        EXPECT(count_op("aarch64_insn_patch_text") == 0);
        EXPECT(count_op("init_asm_ctx") == 0);  // 一次汇编都没生成
    }

    // === C7 新内核（>= 4.19.0）→ 不碰 system_state ==========================
    {
        reset("C7 新内核：不解析/不改 system_state");
        r5::g_kernel_4_19_less = false;

        const KModErr err = kernel_module::write_kernel_mem(
            kKaddr, patch_words, sizeof(patch_words), kernel_module::KernMemProt::KMP_X);
        EXPECT(err == KModErr::OK);
        EXPECT(count_op("kallsyms_lookup_name") == 0);
        EXPECT(count_op("mov_x") == 0);   // 没有 MOVZ/MOVK X10
        EXPECT(count_op("ldr") == 0);
        EXPECT(count_op("str_w") == 0);   // 也没有写回
        EXPECT(count_op("stp") == 1);     // 现场保护照旧
        EXPECT(count_op("adr") == 2);
        EXPECT(count_op("ic") == 1);
        EXPECT(count_op("dsb") == 1);
        EXPECT(count_op("isb") == 1);
    }

    // === C8 system_state 解析失败 → 原样上抛，不生成汇编 =====================
    {
        reset("C8 system_state 解析失败");
        r5::g_kernel_4_19_less = true;
        r5::g_kallsyms_err = static_cast<long long>(KModErr::ERR_MODULE_SYMBOL_NOT_EXIST);

        const KModErr err = kernel_module::write_kernel_mem(
            kKaddr, patch_words, sizeof(patch_words), kernel_module::KernMemProt::KMP_X);
        EXPECT(err == KModErr::ERR_MODULE_SYMBOL_NOT_EXIST);
        EXPECT(count_op("init_asm_ctx") == 0);
        EXPECT(count_op("aarch64_insn_patch_text") == 0);
    }

    // === C9 size=0 → 两张表都是空的，cnt=0（仍走到内核）=====================
    {
        reset("C9 size=0（KMP_RO 不校验 size）");
        const KModErr err = kernel_module::write_kernel_mem(
            kKaddr, patch_words, 0, kernel_module::KernMemProt::KMP_RO);
        EXPECT(err == KModErr::OK);
        EXPECT(count_op("embed") == 0);
        EXPECT(count_op("mov_w") == 1);
        // 最后一个 mov_w 的立即数必须是 0
        long long cnt = -1;
        for (const r5::Event& e : r5::events()) {
            if (e.op == "mov_w") cnt = e.b;
        }
        EXPECT(cnt == 0);
        EXPECT(count_op("aarch64_insn_patch_text") == 1);
    }

    // === C10 可重放：同一输入两次调用，序列与 staging 逐字节一致 =============
    {
        reset("C10 可重放（两次调用序列一致）");
        r5::g_kernel_4_19_less = true;
        r5::g_system_state_addr = kSysState;

        uint32_t buf1[2] = {0xA1B2C3D4u, 0x01020304u};
        const uint32_t before[2] = {buf1[0], buf1[1]};

        EXPECT(kernel_module::write_kernel_mem(kKaddr, buf1, sizeof(buf1),
                                              kernel_module::KernMemProt::KMP_X) == KModErr::OK);
        const std::vector<r5::Event> first = r5::events();

        r5::reset();
        EXPECT(kernel_module::write_kernel_mem(kKaddr, buf1, sizeof(buf1),
                                              kernel_module::KernMemProt::KMP_X) == KModErr::OK);
        const std::vector<r5::Event>& second = r5::events();

        ++g_checks;
        bool same = (first.size() == second.size());
        for (std::size_t i = 0; same && i < first.size(); ++i) {
            same = (first[i].op == second[i].op) && (first[i].a == second[i].a) &&
                   (first[i].b == second[i].b) && (first[i].c == second[i].c);
        }
        if (!same) {
            std::printf("  FAIL  [C10] 两次调用事件序列不同\n");
            ++g_fail;
        } else {
            std::printf("  OK    [C10] 两次调用事件序列全等（%zu 事件）\n", first.size());
        }
        // 调用方缓冲未被改写（内容回滚的最小保证：源码只读 buf）
        EXPECT(buf1[0] == before[0] && buf1[1] == before[1]);
    }

    std::printf("\nr5_patch_closure_test: checks=%d failed=%d -> %s\n", g_checks, g_fail,
                g_fail == 0 ? "PASS" : "FAIL");
    return g_fail == 0 ? 0 : 1;
}
