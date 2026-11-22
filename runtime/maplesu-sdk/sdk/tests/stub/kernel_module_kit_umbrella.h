// ===========================================================================
// R5 host test —— kernel_module_kit_umbrella.h 的主机侧替身
//
// 真实 umbrella 会把 asmjit2 / kernel_offsets / civetweb / maplesu::sdk 全部拉进来，
// 只能交叉编译到 Android。主机用例只保留本 TU（m024）用到的形状：
//   * asmjit 形状桩（r5_probe.h）
//   * aarch64_asm_helper.h 里那批 **文件内链接** 的辅助函数
//     （真实文件把它们放在匿名 namespace，mangling 为 _ZN12_GLOBAL__N_1...）
//   * RegProtectGuard（真实文件里在全局作用域）
// 错误码一律用真实的 include/module_err_def.h，避免"自造码"。
// ===========================================================================
#pragma once

#include "r5_probe.h"

#include <cstddef>
#include <cstdint>
#include <vector>

// 真实错误码枚举（12 个导出符号的返回值域必须落在它里面）
#include "module_err_def.h"

namespace {

using namespace asmjit;
using namespace asmjit::a64;

// ---------------------------------------------------------------------------
// aarch64_asm_helper.h 的等价桩：形状一致、只记录
// ---------------------------------------------------------------------------
struct aarch64_asm_ctx {
public:
    Assembler* assembler() { return &assembler_; }
    bool has_error() const { return false; }

private:
    Assembler assembler_;
};

inline aarch64_asm_ctx init_aarch64_asm() {
    r5::record("init_asm_ctx");
    return aarch64_asm_ctx{};
}

inline void arm64_module_asm_func_start(Assembler* a) {
    (void)a;
    r5::record("func_start");
}

inline void arm64_module_asm_func_end(Assembler* a) {
    (void)a;
    r5::record("func_end");
}

inline void arm64_module_asm_func_end(Assembler* a, GpX ret) {
    (void)a;
    r5::record("func_end_x", ret.id());
}

inline std::vector<uint8_t> aarch64_asm_to_bytes(Assembler* a) {
    (void)a;
    r5::record("to_bytes");
    return std::vector<uint8_t>(8, 0x1f);  // 只要非空即可
}

inline void aarch64_asm_mov_x(Assembler* a, GpX dst, uint64_t value) {
    r5::record("mov_x", dst.id(), static_cast<long long>(value));
    // MOVZ 1 条 + 每个非零 16 位段 1 条 MOVK
    int insns = 0;
    for (int idx = 0; idx < 4; ++idx) {
        if (((value >> (idx * 16)) & 0xFFFFu) != 0) ++insns;
    }
    a->advance(4 * (insns == 0 ? 1 : insns));
}

inline void aarch64_asm_mov_w(Assembler* a, GpW dst, uint32_t value) {
    r5::record("mov_w", dst.id(), static_cast<long long>(value));
    int insns = 0;
    for (int idx = 0; idx < 2; ++idx) {
        if (((value >> (idx * 16)) & 0xFFFFu) != 0) ++insns;
    }
    a->advance(4 * (insns == 0 ? 1 : insns));
}

inline bool aarch64_asm_adr_x(Assembler* a, GpX dst, int32_t adr_value) {
    r5::record("adr", dst.id(), adr_value);
    a->advance(4);  // 一条 ADR 指令
    return true;
}

inline void aarch64_asm_ic_iallu(Assembler* a) {
    r5::record("ic", 936);  // Predicate::IC::encode(0,7,5,0) = IALLU
    a->advance(4);
}

inline void aarch64_asm_dsb_ish(Assembler* a) {
    r5::record("dsb", 11);  // Predicate::DB::kISH
    a->advance(4);
}

inline void aarch64_asm_isb(Assembler* a) {
    r5::record("isb", 15);  // Predicate::ISB::kSY
    a->advance(4);
}

inline void aarch64_asm_mrs_ctr_el0(Assembler* a, GpX dst) {
    r5::record("mrs_ctr_el0", dst.id(), static_cast<long long>(r5::g_ctr_el0));
    a->advance(4);
}

inline void aarch64_asm_dc_cvac(Assembler* a, GpX addr) {
    r5::record("dc_cvac", addr.id());
    a->advance(4);
}

}  // namespace

// ---------------------------------------------------------------------------
// aarch64_asm_reg_protect_guard.h 的等价桩（全局作用域，与真实文件一致）
// 语义：ctor 记 STP X10,X11,[SP,#-16]!；dtor 记 LDP X10,X11,[SP],#16
// ---------------------------------------------------------------------------
class RegProtectGuard {
public:
    template <typename... Regs>
    explicit RegProtectGuard(asmjit::a64::Assembler* a, const Regs&... regs) : a_(a) {
        (collectOne(regs), ...);
        if (regs_.empty()) return;
        if (regs_.size() & 1) regs_.push_back(31);  // 奇数补 xzr
        doPushPairs();
        pushed_ = true;
    }

    RegProtectGuard(const RegProtectGuard&) = delete;
    RegProtectGuard& operator=(const RegProtectGuard&) = delete;
    ~RegProtectGuard() { cleanup(); }

private:
    void collectOne(const asmjit::a64::GpX& r) { regs_.push_back(r.id()); }
    void collectOne(const asmjit::a64::GpW& r) { regs_.push_back(r.id()); }

    void doPushPairs() {
        for (std::size_t i = 0; i < regs_.size(); i += 2) {
            r5::record("stp", regs_[i], regs_[i + 1], -16);
        }
    }
    void doPopPairs() {
        for (std::size_t i = regs_.size(); i > 0; i -= 2) {
            r5::record("ldp", regs_[i - 2], regs_[i - 1], 16);
        }
    }
    void cleanup() {
        if (!pushed_ || !a_) return;
        doPopPairs();
        pushed_ = false;
        regs_.clear();
    }

    asmjit::a64::Assembler* a_ = nullptr;
    std::vector<int> regs_;
    bool pushed_ = false;
};

// ---------------------------------------------------------------------------
// 内核导出符号 / 内核模块运行时的外部依赖（只声明，定义在用例里）
// ---------------------------------------------------------------------------
namespace kernel_module {

// module_base_linux_version.h
bool is_kernel_version_less(const char* ver);

// module_base_kernel_symbol_kaddr.h（2 参数版本，出厂对象里是弱定义的内联壳）
KModErr kallsyms_lookup_name(const char* name, uint64_t& out_kaddr);

// kernel_module 私有运行时（出厂成员的实际依赖）
const char* current_module_root_key();

}  // namespace kernel_module

// 宿主 libc 的最小替身：真实源码里 get_page_size() 走 sysconf(_SC_PAGESIZE)
#ifndef _SC_PAGESIZE
#define _SC_PAGESIZE 30
#endif
extern "C" long sysconf(int name) noexcept;
