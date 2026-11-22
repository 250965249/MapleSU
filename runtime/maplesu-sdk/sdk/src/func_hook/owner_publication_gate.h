#pragma once

#include <cstdint>
#include "third_party/asmjit2/a64.h"

namespace maplesu::hook_gate {

inline constexpr uint32_t kControlCallFrameBytes = 176;
// Architectural S3_3_C4_C2_0 encoding, independent of SDK include namespaces.
inline constexpr uint32_t kNzcvRegister = (3u << 14) | (3u << 11) | (4u << 7) | (2u << 3);

namespace detail {
inline bool valid_assembler(const asmjit::a64::Assembler* a) {
    return a && a->code() && !(a->offset() & 3u);
}

inline bool emit_u64(asmjit::a64::Assembler* a, asmjit::a64::GpX reg, uint64_t value) {
    bool initialized = false;
    for (uint32_t shift = 0; shift < 64; shift += 16) {
        const uint32_t part = static_cast<uint32_t>((value >> shift) & 0xffffu);
        if (!part) continue;
        const asmjit::Error error = initialized ? a->movk(reg, part, shift)
                                                : a->movz(reg, part, shift);
        if (error != asmjit::kErrorOk) return false;
        initialized = true;
    }
    return initialized || a->movz(reg, 0) == asmjit::kErrorOk;
}

inline bool save_call_state(asmjit::a64::Assembler* a) {
    using namespace asmjit;
    using namespace asmjit::a64;
    if (a->sub(sp, sp, Imm(kControlCallFrameBytes)) != kErrorOk) return false;
    for (uint32_t r = 0; r < 18; r += 2)
        if (a->stp(x(r), x(r + 1), ptr(sp, r * 8)) != kErrorOk) return false;
    return a->stp(x18, x30, ptr(sp, 144)) == kErrorOk &&
        a->mrs(x9, Imm(kNzcvRegister)) == kErrorOk &&
        a->str(x9, ptr(sp, 160)) == kErrorOk;
}

inline bool restore_call_state(asmjit::a64::Assembler* a) {
    using namespace asmjit;
    using namespace asmjit::a64;
    if (a->ldr(x9, ptr(sp, 160)) != kErrorOk ||
        a->msr(Imm(kNzcvRegister), x9) != kErrorOk) return false;
    for (uint32_t r = 0; r < 18; r += 2)
        if (a->ldp(x(r), x(r + 1), ptr(sp, r * 8)) != kErrorOk) return false;
    return a->ldp(x18, x30, ptr(sp, 144)) == kErrorOk &&
        a->add(sp, sp, Imm(kControlCallFrameBytes)) == kErrorOk;
}

inline bool call_control(asmjit::a64::Assembler* a, uint64_t id, uint64_t function) {
    using namespace asmjit;
    using namespace asmjit::a64;
    return emit_u64(a, x0, id) && emit_u64(a, x16, function) && a->blr(x16) == kErrorOk;
}
} // namespace detail

// Caller has pushed the original x28/xzr pair at H. Success keeps H for the
// legacy payload entry to pop; denial keeps H for the caller to pop instead.
// Functions use the qualified no-FP kernel ABI. False requires buffer discard.
inline bool emit_enter(asmjit::a64::Assembler* a, uint64_t publication_id,
    uint64_t enter_function, const asmjit::Label& denied) {
    using namespace asmjit;
    using namespace asmjit::a64;
    if (!detail::valid_assembler(a) || !publication_id || !enter_function ||
        (enter_function & 3u) || !denied.isValid()) return false;
    const Label no_payload = a->newLabel();
    const Label done = a->newLabel();
    if (!no_payload.isValid() || !done.isValid() || !detail::save_call_state(a) ||
        !detail::call_control(a, publication_id, enter_function) ||
        a->cbz(x0, no_payload) != kErrorOk || a->mov(x28, x0) != kErrorOk ||
        !detail::restore_call_state(a) || a->b(done) != kErrorOk ||
        a->bind(no_payload) != kErrorOk || !detail::restore_call_state(a) ||
        a->b(denied) != kErrorOk || a->bind(done) != kErrorOk) return false;
    return true;
}

// Run only from pinned gate code after the last payload access. Preserve the
// actual callback output; leave neither consumes nor produces payload bytes.
inline bool emit_leave(asmjit::a64::Assembler* a, uint64_t publication_id,
    uint64_t leave_function) {
    return detail::valid_assembler(a) && publication_id && leave_function && !(leave_function & 3u) &&
        detail::save_call_state(a) && detail::call_control(a, publication_id, leave_function) &&
        detail::restore_call_state(a);
}

// Append inside the referenced payload; the old ret slot branches here. The
// pinned exit restores x16/SP before leave, so no payload runs after retirement.
inline bool emit_early_return_veneer(asmjit::a64::Assembler* a, uint64_t permanent_gate) {
    using namespace asmjit;
    using namespace asmjit::a64;
    if (!detail::valid_assembler(a) || !permanent_gate || (permanent_gate & 3u)) return false;
    const Label address = a->newLabel();
    return address.isValid() && a->stp(x16, xzr, ptr(sp).pre(-16)) == kErrorOk &&
        a->ldr(x16, ptr(address)) == kErrorOk && a->br(x16) == kErrorOk &&
        a->align(AlignMode::kData, 8) == kErrorOk && a->bind(address) == kErrorOk &&
        a->embed(&permanent_gate, sizeof(permanent_gate)) == kErrorOk;
}

// This label is reached only from the veneer. Caller emits leave and the
// existing matching PAC/RET tail next, entirely in boot-pinned gate code.
inline bool emit_early_return_entry(asmjit::a64::Assembler* a) {
    using namespace asmjit;
    using namespace asmjit::a64;
    constexpr uint32_t bti_jc = 0xd50324dfu;
    return detail::valid_assembler(a) && a->embed(&bti_jc, sizeof(bti_jc)) == kErrorOk &&
        a->ldp(x16, xzr, ptr(sp).post(16)) == kErrorOk;
}

} // namespace maplesu::hook_gate
