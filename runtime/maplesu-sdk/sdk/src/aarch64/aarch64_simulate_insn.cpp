// aarch64 simulate insn implementation.
//
#include <cstdint>

#include "aarch64_asm_helper.h"
#include "kernel_module_kit_umbrella.h"
#include "branch_encoding.h"

using namespace asmjit;
using namespace asmjit::a64;

namespace kernel_module {
bool aarch64_insn_is_steppable(uint32_t insn);
}

namespace kernel_module {

int32_t generate_aarch64_insn_b(int32_t byte_offset);

// 在当前位置补一条 B；完整地址范围与编码失败都传回调用方。
static bool instruction_pointer_set(asmjit::a64::Assembler* a, uint64_t insn_kaddr, uint64_t pc) {
    uint32_t branch = 0;
    if (a->offset() > UINT64_MAX - insn_kaddr ||
        !maplesu::aarch64::encode_b(insn_kaddr + a->offset(), pc, branch)) return false;
    return a->embed(&branch, sizeof(branch)) == asmjit::kErrorOk;
}

static bool relative_target(uint64_t pc, int64_t displacement, uint64_t& target) {
    if (displacement >= 0) {
        const uint64_t distance = static_cast<uint64_t>(displacement);
        if (distance > UINT64_MAX - pc) return false;
        target = pc + distance;
    } else {
        const uint64_t distance = uint64_t{0} - static_cast<uint64_t>(displacement);
        if (distance > pc) return false;
        target = pc - distance;
    }
    return true;
}

static bool emit_absolute(Assembler* a, GpX destination, uint64_t value) {
    bool initialized = false;
    for (uint32_t shift = 0; shift < 64; shift += 16) {
        const uint32_t part = static_cast<uint32_t>((value >> shift) & 0xffffu);
        if (!part) continue;
        const Error error = initialized ? a->movk(destination, part, shift)
                                        : a->movz(destination, part, shift);
        if (error != kErrorOk) return false;
        initialized = true;
    }
    return initialized || a->movz(destination, 0) == kErrorOk;
}

// 保留旧 int32 位移 ABI，复用同一有界编码器；失败仍返回 -1。
int32_t generate_aarch64_insn_b(int32_t byte_offset) {
    uint32_t branch = 0;
    constexpr uint64_t origin = UINT64_C(0x100000000);
    if (!maplesu::aarch64::encode_b(origin, origin + static_cast<int64_t>(byte_offset), branch)) return -1;
    return static_cast<int32_t>(branch);
}

// 单个"不可单步"指令的等价展开。
// false 表示本次发射失败；调用方须丢弃缓冲，不得发布部分序列。
bool emit_simulate_aarch64_insn(asmjit::a64::Assembler* a, uint64_t insn_kaddr, uint32_t insn,
                                uint64_t emit_at) {
    if (!a || ((insn_kaddr | emit_at | a->offset()) & 3u) ||
        a->offset() > UINT64_MAX - insn_kaddr) return false;
    // Exceptions preserve their own PC in architectural state, so they cannot
    // be copied into a trampoline as an equivalent instruction.
    if ((insn & 0xff000000u) == 0xd4000000u || (insn & 0xffff0000u) == 0) return false;
    const uint32_t indirect = insn & 0xfffffc1fu;
    if (indirect == 0xd63f0000u) {
        const uint32_t rn = (insn >> 5) & 31u;
        uint64_t return_pc = 0;
        if (rn >= 30u || !relative_target(emit_at, 4, return_pc)) return false;
        if (!emit_absolute(a, x30, return_pc)) return false;
        const uint32_t branch = insn & ~0x00200000u;
        return a->embed(&branch, sizeof(branch)) == kErrorOk;
    }
    if ((insn & 0xfefff800u) == 0xd63f0800u) return false;
    // ---- 0) 可单步：原样复制 -------------------------------------------------
    if (aarch64_insn_is_steppable(insn)) {
        return a->embed(&insn, sizeof(insn)) == kErrorOk;
    }

    // ---- 1) B.cond：0x54000000 & 0xFF000010 ---------------------------------
    //            -> bind -> IPC(emit_at + sign_extend(imm19)*4)
    if ((insn & 0xFF000010u) == 0x54000000u) {
        uint64_t next = 0, target = 0;
        const int64_t displacement = (static_cast<int32_t>(insn << 8) >> 11) & ~3;
        if (!relative_target(emit_at, 4, next) || !relative_target(emit_at, displacement, target)) return false;
        Label label = a->newLabel();
        Error error = kErrorOk;
        switch (insn & 0xFu) {
            case 0x0: error = a->b(CondCode::kEQ, label); break;
            case 0x1: error = a->b(CondCode::kNE, label); break;
            case 0x2: error = a->b(CondCode::kCS, label); break;
            case 0x3: error = a->b(CondCode::kLO, label); break;
            case 0x4: error = a->b(CondCode::kMI, label); break;
            case 0x5: error = a->b(CondCode::kPL, label); break;
            case 0x6: error = a->b(CondCode::kVS, label); break;
            case 0x7: error = a->b(CondCode::kVC, label); break;
            case 0x8: error = a->b(CondCode::kHI, label); break;
            case 0x9: error = a->b(CondCode::kLS, label); break;
            case 0xA: error = a->b(CondCode::kGE, label); break;
            case 0xB: error = a->b(CondCode::kLT, label); break;
            case 0xC: error = a->b(CondCode::kGT, label); break;
            case 0xD: error = a->b(CondCode::kLE, label); break;
            default: error = a->b(CondCode::kAL, label); break;
        }
        if (error != kErrorOk || !instruction_pointer_set(a, insn_kaddr, next) ||
            a->bind(label) != kErrorOk) return false;
        return instruction_pointer_set(a, insn_kaddr, target);
    }

    // ---- 2) CBZ/CBNZ/TBZ/TBNZ：0x34/0x35/0x36/0x37 组 -------------------------
    const uint32_t opc_group = insn & 0x7F000000u;
    if (opc_group >= 0x34000000u && opc_group <= 0x37000000u) {
        const bool is64 = (insn & 0x80000000u) != 0;
        const GpX rt = (insn & 0x1Fu) == 31 ? xzr : x(insn & 0x1Fu);
        uint64_t next = 0, target = 0;
        const int64_t displacement = opc_group <= 0x35000000u
            ? (static_cast<int32_t>(insn << 8) >> 11) & ~3
            : (static_cast<int32_t>(insn << 13) >> 16) & ~3;
        if (!relative_target(emit_at, 4, next) || !relative_target(emit_at, displacement, target)) return false;
        Label label = a->newLabel();
        Error error;
        if (opc_group <= 0x35000000u) {
            if (insn & 0x01000000u) error = is64 ? a->cbnz(rt, label) : a->cbnz(rt.w(), label);
            else error = is64 ? a->cbz(rt, label) : a->cbz(rt.w(), label);
        } else {
            const uint32_t bit = ((insn >> 26) & 0x20u) | ((insn >> 19) & 0x1Fu);
            error = (insn & 0x01000000u) ? a->tbnz(rt, Imm(bit), label) : a->tbz(rt, Imm(bit), label);
        }
        if (error != kErrorOk || !instruction_pointer_set(a, insn_kaddr, next) ||
            a->bind(label) != kErrorOk) return false;
        return instruction_pointer_set(a, insn_kaddr, target);
    }

    // ---- 3) ADR / ADRP：0x1x000000 且 (insn & 0x1F000000) == 0x10000000 --------
    if ((insn & 0x1F000000u) == 0x10000000u) {
        const uint32_t imm21 = ((insn >> 3) & 0x1FFFFCu) | ((insn >> 29) & 0x3u);
        const int64_t displacement = static_cast<int64_t>(imm21 ^ 0x100000u) - 0x100000;
        const bool page_relative = (insn & 0x80000000u) != 0;
        uint64_t target = 0;
        if (!relative_target(page_relative ? emit_at & ~UINT64_C(0xfff) : emit_at,
                             page_relative ? displacement * 4096 : displacement, target)) return false;
        const GpX destination = (insn & 0x1Fu) == 31 ? xzr : x(insn & 0x1Fu);
        return emit_absolute(a, destination, target);
    }

    // ---- 4) B / BL ----------------------------------------------------------
    const uint32_t branch_opc = insn & 0xFC000000u;
    if (branch_opc == 0x14000000u || branch_opc == 0x94000000u) {
        uint64_t target = 0;
        const int64_t displacement = static_cast<int32_t>(insn << 6) >> 4;
        if (!relative_target(emit_at, displacement, target)) return false;
        if (branch_opc == 0x94000000u) {
            uint64_t return_pc = 0;
            if (!relative_target(emit_at, 4, return_pc) || !emit_absolute(a, x30, return_pc)) return false;
        }
        return instruction_pointer_set(a, insn_kaddr, target);
    }

    // BR and RET do not derive LR from the relocated instruction's PC.
    if (indirect == 0xd61f0000u || indirect == 0xd65f0000u) {
        if (((insn >> 5) & 31u) == 31u) return false;
        return a->embed(&insn, sizeof(insn)) == kErrorOk;
    }

    // Integer, SIMD and prefetch literals share signed imm19 addressing.
    if ((insn & 0x3b000000u) == 0x18000000u) {
        const uint32_t opc = insn >> 30;
        const bool vector = (insn & 0x04000000u) != 0;
        if (vector && opc == 3) return false;
        const int64_t displacement = (static_cast<int32_t>(insn << 8) >> 11) & ~3;
        uint64_t target = 0;
        if (!relative_target(emit_at, displacement, target) || a->offset() > UINT64_MAX - insn_kaddr) return false;
        const uint64_t here = insn_kaddr + a->offset();
        const uint64_t distance = target >= here ? target - here : here - target;
        if ((target >= here && distance <= 0xffffcULL) ||
            (target < here && distance <= 0x100000ULL)) {
            const uint32_t offset = static_cast<uint32_t>((target - here) >> 2) & 0x7ffffu;
            const uint32_t relocated = (insn & ~0x00ffffe0u) | (offset << 5);
            return a->embed(&relocated, sizeof(relocated)) == kErrorOk;
        }
        const uint32_t rt = insn & 31u;
        const bool scratch = vector || rt == 31u || opc == 3u;
        const GpX address = scratch ? x16 : x(rt);
        if (scratch && a->stp(x16, xzr, ptr(sp).pre(-16)) != kErrorOk) return false;
        if (!emit_absolute(a, address, target)) return false;
        Error error;
        if (vector) {
            if (opc == 0) error = a->ldr(s(rt), ptr(address));
            else if (opc == 1) error = a->ldr(d(rt), ptr(address));
            else error = a->ldr(v(rt), ptr(address));
        } else if (opc == 3) error = a->prfm(Imm(rt), ptr(address));
        else {
            const GpX destination = rt == 31u ? xzr : x(rt);
            if (opc == 0) error = a->ldr(destination.w(), ptr(address));
            else if (opc == 1) error = a->ldr(destination, ptr(address));
            else error = a->ldrsw(destination, ptr(address));
        }
        if (error != kErrorOk) return false;
        return !scratch || a->ldp(x16, xzr, ptr(sp).post(16)) == kErrorOk;
    }

    return false;
}

}  // namespace kernel_module
