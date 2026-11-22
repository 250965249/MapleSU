// ===========================================================================
// R5 host test —— asmjit 与内核模块外部符号的“记录型桩”（仅测试用，不进产物）
//
// 目的：让 src/kernel_mem/module_base_kernel_mem.cpp **原文**在主机侧编译，
//       并把闭包 patch_kernel_static_code::$_0 生成的指令/数据按调用顺序记下来，
//       供 r5_patch_closure_test.cpp 断言。
//
// 边界：这里只“记录 + 回放脚本结果”，不实现任何内核语义；桩名与签名对齐
//       include/aarch64_asm_helper.h / aarch64_asm_reg_protect_guard.h /
//       module_base_kernel_export_symbol.h 的对外形状。
// ===========================================================================
#pragma once

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

// ---------------------------------------------------------------------------
// 事件记录
// ---------------------------------------------------------------------------
namespace r5 {

struct Event {
    std::string op;   // 事件名
    long long a = 0;  // 参数 1
    long long b = 0;  // 参数 2
    long long c = 0;  // 参数 3
};

inline std::vector<Event>& events() {
    static std::vector<Event> log;
    return log;
}

inline void record(const char* op, long long a = 0, long long b = 0, long long c = 0) {
    events().push_back(Event{op, a, b, c});
}

inline void reset() { events().clear(); }

// --- 脚本化外部结果（测试逐例设置） ---------------------------------------
inline bool g_kernel_4_19_less = false;    // is_kernel_version_less("4.19.0")
inline long long g_kallsyms_err = 0;       // kallsyms_lookup_name 的返回
inline uint64_t g_system_state_addr = 0;   // 写进 out 的 system_state 地址
inline long long g_patch_sym_err = 0;      // aarch64_insn_patch_text 的符号解析错误
inline long long g_transport_err = 0;      // execute_kernel_asm_func 的传输错误
inline uint64_t g_kernel_ret = 0;          // shellcode 在内核里跑出来的 W0
inline uint32_t g_append_offset = 0;
inline uint32_t g_page_size = 4096;
inline uint64_t g_ctr_el0 = 0;
inline const char* g_root_key = "r5-root-key";

}  // namespace r5

// ---------------------------------------------------------------------------
// asmjit 形状桩（只保留被本 TU 用到的部分）
// ---------------------------------------------------------------------------
namespace asmjit {
inline namespace v1_16 {
namespace a64 {

class GpX {
public:
    constexpr explicit GpX(int id = 0) : _id(id) {}
    constexpr int id() const { return _id; }
    constexpr bool operator==(const GpX& o) const { return _id == o._id; }

private:
    int _id;
};

class GpW {
public:
    constexpr explicit GpW(int id = 0) : _id(id) {}
    constexpr int id() const { return _id; }
    constexpr bool operator==(const GpW& o) const { return _id == o._id; }

private:
    int _id;
};

inline constexpr GpX x(int id) { return GpX(id); }
inline constexpr GpW w(int id) { return GpW(id); }

inline constexpr GpX x0{0}, x1{1}, x2{2}, x3{3}, x4{4}, x5{5}, x6{6}, x7{7}, x8{8}, x9{9};
inline constexpr GpX x10{10}, x11{11}, x12{12}, x13{13}, x14{14}, x15{15}, x16{16}, x17{17};
inline constexpr GpX x18{18}, x19{19}, x20{20}, x21{21}, x22{22}, x23{23}, x24{24}, x25{25};
inline constexpr GpX x26{26}, x27{27}, x28{28}, x29{29}, x30{30};
inline constexpr GpX xzr{31};
inline constexpr GpX sp{31};

inline constexpr GpW w0{0}, w1{1}, w2{2}, w3{3}, w4{4}, w5{5}, w6{6}, w7{7}, w8{8}, w9{9};
inline constexpr GpW w10{10}, w11{11}, w12{12}, w13{13}, w14{14}, w15{15}, w16{16}, w17{17};
inline constexpr GpW w18{18}, w19{19}, w20{20}, w21{21}, w22{22}, w23{23}, w24{24}, w25{25};
inline constexpr GpW w26{26}, w27{27}, w28{28}, w29{29}, w30{30};
inline constexpr GpW wzr{31};

// 简化版 Mem：只记 基址寄存器 + 立即数偏移
class Mem {
public:
    explicit Mem(GpX base, int32_t offset = 0) : _base(base.id()), _offset(offset) {}
    Mem pre(int32_t delta) const { return Mem(GpX(_base), _offset + delta); }
    Mem post(int32_t delta) const { return Mem(GpX(_base), _offset + delta); }
    int baseId() const { return _base; }
    int32_t offset() const { return _offset; }

private:
    int _base;
    int32_t _offset;
};

// 简化版 Imm：`value` 就是 asmjit Operand_ 里 _data[0] 的原始编码，
// 断言可直接核 IC IALLU=936 / DB ISH=11 / ISB SY=15。
class Imm {
public:
    explicit Imm(uint32_t value) : _value(value) {}
    uint32_t value() const { return _value; }

private:
    uint32_t _value;
};

class Label {
public:
    Label() = default;
    explicit Label(int id) : _id(id) {}
    int id() const { return _id; }

private:
    int _id = 0;
};

// ---------------------------------------------------------------------------
// Assembler：只 record + 维护“代码游标”（= asmjit BaseAssembler::offset()）。
//
// 游标不能省：闭包用 `a->offset()` 的前后差值算 ADR 相对偏移，
//   E9 ADR X0 = 地址表首 - 当前游标      → -(3*size)
//   E10 ADR X1 = 指令表首 - 当前游标      → -(size+4)   ← 第一条 ADR 已占 4 字节
// 若桩不前进游标，用例会把 E10 断言成 -(size)，与冻结成员不符（见 STATUS.md R3）。
// ---------------------------------------------------------------------------
class Assembler {
public:
    Label newLabel() {
        const int id = next_label_++;
        r5::record("newLabel", id);
        return Label(id);
    }
    void bind(const Label& l) { r5::record("bind", l.id()); }
    void b(const Label& l) {
        r5::record("b", l.id());
        advance(4);  // B <label> 是真实 4 字节分支指令
    }

    int embed(const void* data, size_t size) {
        long long payload = 0;
        if (size == 8) {
            uint64_t v = 0;
            std::memcpy(&v, data, 8);
            payload = static_cast<long long>(v);
        } else if (size == 4) {
            uint32_t v = 0;
            std::memcpy(&v, data, 4);
            payload = static_cast<long long>(v);
        }
        r5::record("embed", static_cast<long long>(size), payload);
        advance(static_cast<int>(size));
        return 0;
    }

    // 对应 asmjit BaseAssembler::offset() = _bufferPtr - _bufferData
    size_t offset() const { return static_cast<size_t>(code_size_); }

    int ldr(const GpW& r, const Mem& m) {
        r5::record("ldr", r.id(), m.baseId(), m.offset());
        advance(4);
        return 0;
    }
    int ldr(const GpX& r, const Mem& m) {
        r5::record("ldr", r.id(), m.baseId(), m.offset());
        advance(4);
        return 0;
    }
    int str(const GpW& r, const Mem& m) {
        r5::record("str_w", r.id(), m.baseId(), m.offset());
        advance(4);
        return 0;
    }
    int str(const GpX& r, const Mem& m) {
        r5::record("str_x", r.id(), m.baseId(), m.offset());
        advance(4);
        return 0;
    }
    int stlr(const GpW& r, const Mem& m) {
        r5::record("stlr", r.id(), m.baseId());
        advance(4);
        return 0;
    }
    int stlr(const GpX& r, const Mem& m) {
        r5::record("stlr", r.id(), m.baseId());
        advance(4);
        return 0;
    }
    int mov(const GpX& d, const GpX& s) {
        r5::record("mov", d.id(), s.id());
        advance(4);
        return 0;
    }
    int add(const GpX& d, const GpX& s, const Imm& i) {
        r5::record("add", d.id(), s.id(), static_cast<long long>(i.value()));
        advance(4);
        return 0;
    }
    int add(const GpX& d, const GpX& s1, const GpX& s2) {
        r5::record("add_r", d.id(), s1.id(), s2.id());
        advance(4);
        return 0;
    }
    int sub(const GpX& d, const GpX& s, const Imm& i) {
        r5::record("sub", d.id(), s.id(), static_cast<long long>(i.value()));
        advance(4);
        return 0;
    }
    int ubfm(const GpX& d, const GpX& s, const Imm& i1, const Imm& i2) {
        r5::record("ubfm", d.id(), s.id(),
                   static_cast<long long>((i1.value() << 16) | i2.value()));
        advance(4);
        return 0;
    }
    int lsr(const GpX& d, const GpX& s1, const GpX& s2) {
        r5::record("lsr", d.id(), s1.id(), s2.id());
        advance(4);
        return 0;
    }
    int lsl(const GpX& d, const GpX& s1, const GpX& s2) {
        r5::record("lsl", d.id(), s1.id(), s2.id());
        advance(4);
        return 0;
    }
    int stp(const GpX& r1, const GpX& r2, const Mem& m) {
        r5::record("stp", r1.id(), r2.id(), m.offset());
        advance(4);
        return 0;
    }
    int ldp(const GpX& r1, const GpX& r2, const Mem& m) {
        r5::record("ldp", r1.id(), r2.id(), m.offset());
        advance(4);
        return 0;
    }

    // 供桩辅助函数（aarch64_asm_adr_x / mov_w / ic / dsb / isb）前进游标
    void advance(int bytes) { code_size_ += bytes; }

private:
    int next_label_ = 1;
    int code_size_ = 0;
};

inline Mem ptr(GpX base) { return Mem(base); }
inline Mem ptr(GpW base) { return Mem(GpX(base.id())); }

}  // namespace a64
}  // namespace v1_16
}  // namespace asmjit
