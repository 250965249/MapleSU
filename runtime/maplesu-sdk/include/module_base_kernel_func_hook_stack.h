#pragma once
#include <algorithm>
#include <cstdint>
#include "aarch64_asm_helper.h"

namespace kernel_module {
void arm64_emit_call_original(asmjit::a64::Assembler*);

// Positions are relative to SP immediately before this helper. The caller
// supplies the complete ABI argument area, including padding, in 8-byte units.
// Arguments are copied below the active handler frame; its saved state stays
// above the callee's entry SP. This does not promise the original absolute SP.
struct CallOriginalStackFrame {
    uint32_t argument_offset;
    uint32_t argument_bytes;
};

inline void arm64_emit_call_original_with_stack(asmjit::a64::Assembler* a,
                                               CallOriginalStackFrame frame) {
    using namespace asmjit;
    using namespace asmjit::a64;
    if ((frame.argument_offset & 7) || (frame.argument_bytes & 7)) {
        a->reportError(kErrorInvalidArgument);
        return;
    }
    if (!frame.argument_bytes) {
        arm64_emit_call_original(a);
        return;
    }
    const uint64_t area = (uint64_t(frame.argument_bytes) + 15) & ~uint64_t(15);
    auto adjust = [&](uint64_t bytes, bool down) {
        while (bytes) {
            const uint64_t part = bytes >= 4096 ?
                std::min<uint64_t>(bytes >> 12, 4095) << 12 : bytes;
            if (down) a->sub(sp, sp, Imm(part));
            else a->add(sp, sp, Imm(part));
            bytes -= part;
        }
    };
    a->stp(x9, x10, ptr(sp).pre(-16));
    a->stp(x11, x12, ptr(sp).pre(-16));
    adjust(area, true);
    aarch64_asm_mov_x(a, x9, area + 32 + frame.argument_offset);
    a->add(x9, sp, x9);
    a->mov(x10, sp);
    aarch64_asm_mov_x(a, x11, frame.argument_bytes / 8);
    const Label copy = a->newLabel();
    a->bind(copy);
    a->ldr(x12, ptr(x9).post(8));
    a->str(x12, ptr(x10).post(8));
    a->sub(x11, x11, Imm(1));
    a->cbnz(x11, copy);
    adjust(area, false);
    a->ldp(x11, x12, ptr(sp));
    a->ldp(x9, x10, ptr(sp, 16));
    adjust(area, true);
    arm64_emit_call_original(a);
    adjust(area + 32, false);
}
} // namespace kernel_module
