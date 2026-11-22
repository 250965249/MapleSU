#pragma once

namespace {
struct OwnerGateLayout {
    uint64_t origin_offset = 0;
    uint64_t early_return_offset = 0;
};

bool owner_gate_input_valid(Assembler* a, uint64_t gate_address,
    const maplesu_publication_control_v3& control, const std::vector<InsnRecord>& records) {
    return maplesu::hook_gate::detail::valid_assembler(a) &&
        gate_address >= UINT64_C(0xffff000000000000) && !(gate_address & 3u) &&
        !records.empty() && control.publication_id && control.schema == 1 &&
        control.length == sizeof(control) && !control.reserved &&
        control.enter_function >= UINT64_C(0xffff000000000000) && !(control.enter_function & 3u) &&
        control.leave_function >= UINT64_C(0xffff000000000000) && !(control.leave_function & 3u) &&
        control.payload_entry >= UINT64_C(0xffff000000000000) && !(control.payload_entry & 3u) &&
        control.entry_address == records.back().addr && control.entry_address <= UINT64_MAX - 4 &&
        control.resume_address == control.entry_address + 4;
}

bool owner_gate_emit_return(Assembler* a, uint32_t entry_insn) {
    uint32_t authentication = 0;
    switch (entry_insn) {
        case 0xd503231fu: case 0xd503239fu: authentication = 0xd503239fu; break;
        case 0xd503233fu: case 0xd50323bfu: authentication = 0xd50323bfu; break;
        case 0xd503235fu: case 0xd50323dfu: authentication = 0xd50323dfu; break;
        case 0xd503237fu: case 0xd50323ffu: authentication = 0xd50323ffu; break;
        default: break;
    }
    return (!authentication || a->embed(&authentication, sizeof(authentication)) == asmjit::kErrorOk) &&
        a->ret(x30) == asmjit::kErrorOk;
}

KModErr emit_owner_before(Assembler* a, uint64_t gate_address,
    const maplesu_publication_control_v3& control, const std::vector<InsnRecord>& records,
    uint64_t return_acquire, uint64_t return_release, uint64_t return_x28,
    uint64_t return_lr, uint64_t return_payload,
    OwnerGateLayout& layout) {
    layout = {};
    if (!owner_gate_input_valid(a, gate_address, control, records) ||
        return_acquire < UINT64_C(0xffff000000000000) || (return_acquire & 3u) ||
        return_release < UINT64_C(0xffff000000000000) || (return_release & 3u) ||
        return_x28 < UINT64_C(0xffff000000000000) || (return_x28 & 3u) ||
        return_lr < UINT64_C(0xffff000000000000) || (return_lr & 3u) ||
        return_payload < UINT64_C(0xffff000000000000) || (return_payload & 3u))
        return KModErr::ERR_MODULE_PARAM;
    const Label denied = a->newLabel();
    const Label rejected = a->newLabel();
    const Label admitted = a->newLabel();
    const Label original = a->newLabel();
    const Label run = a->newLabel();
    if (!denied.isValid() || !rejected.isValid() || !admitted.isValid() ||
        !original.isValid() || !run.isValid()) return KModErr::ERR_MODULE_ASM;
    if (a->b(run) != asmjit::kErrorOk || a->bind(original) != asmjit::kErrorOk)
        return KModErr::ERR_MODULE_ASM;
    auto error = emit_old_insn_and_jump_back(a, gate_address, records);
    if (error != KModErr::OK) return error;
    // Keep the legacy callback frame exactly 96 bytes. Its saved-LR slot holds
    // the task owner; the true LR/x28 remain in that owner until original exits.
    if (a->bind(run) != asmjit::kErrorOk ||
        a->stp(x28, x29, ptr(sp).pre(-16)) != asmjit::kErrorOk ||
        a->stp(x30, xzr, ptr(sp).pre(-16)) != asmjit::kErrorOk ||
        !maplesu::hook_gate::detail::save_call_state(a) ||
        a->ldr(x1, ptr(sp, 192)) != asmjit::kErrorOk ||
        a->ldr(x2, ptr(sp, 176)) != asmjit::kErrorOk ||
        a->add(x3, sp, Imm(208)) != asmjit::kErrorOk ||
        !maplesu::hook_gate::detail::emit_u64(a, x0, control.publication_id) ||
        !maplesu::hook_gate::detail::emit_u64(a, x16, return_acquire) ||
        a->blr(x16) != asmjit::kErrorOk || a->cbz(x0, rejected) != asmjit::kErrorOk ||
        a->mov(x28, x0) != asmjit::kErrorOk ||
        !maplesu::hook_gate::detail::restore_call_state(a) ||
        a->b(admitted) != asmjit::kErrorOk || a->bind(rejected) != asmjit::kErrorOk ||
        !maplesu::hook_gate::detail::restore_call_state(a) || a->b(denied) != asmjit::kErrorOk ||
        a->bind(admitted) != asmjit::kErrorOk ||
        a->ldr(x29, ptr(sp, 24)) != asmjit::kErrorOk ||
        a->add(sp, sp, Imm(32)) != asmjit::kErrorOk ||
        a->sub(sp, sp, Imm(kHookTrampolineFrame)) != asmjit::kErrorOk ||
        a->stp(x29, x28, ptr(sp).pre(-16)) != asmjit::kErrorOk ||
        !maplesu::hook_gate::detail::save_call_state(a) ||
        a->mov(x0, x28) != asmjit::kErrorOk ||
        !maplesu::hook_gate::detail::emit_u64(a, x16, return_payload) ||
        a->blr(x16) != asmjit::kErrorOk || a->str(x0, ptr(sp, 192)) != asmjit::kErrorOk ||
        a->mov(x0, x28) != asmjit::kErrorOk ||
        !maplesu::hook_gate::detail::emit_u64(a, x16, return_x28) ||
        a->blr(x16) != asmjit::kErrorOk || a->mov(x28, x0) != asmjit::kErrorOk ||
        !maplesu::hook_gate::detail::restore_call_state(a) ||
        a->stp(x28, xzr, ptr(sp).pre(-16)) != asmjit::kErrorOk ||
        a->ldr(x28, ptr(sp, 32)) != asmjit::kErrorOk ||
        a->blr(x28) != asmjit::kErrorOk ||
        a->ldr(x28, ptr(sp, 8)) != asmjit::kErrorOk ||
        a->ldr(x29, ptr(sp)) != asmjit::kErrorOk ||
        a->add(sp, sp, Imm(kHookTrampolineFrame + 16)) != asmjit::kErrorOk ||
        a->bl(original) != asmjit::kErrorOk ||
        !maplesu::hook_gate::detail::save_call_state(a) ||
        a->str(x28, ptr(sp, 168)) != asmjit::kErrorOk)
        return KModErr::ERR_MODULE_ASM;

    // No callback/payload access or sleepable operation follows the final drop.
    auto release_owner = [&]() {
        return a->ldr(x0, ptr(sp, 168)) == asmjit::kErrorOk &&
            maplesu::hook_gate::detail::emit_u64(a, x16, return_lr) &&
            a->blr(x16) == asmjit::kErrorOk && a->str(x0, ptr(sp, 152)) == asmjit::kErrorOk &&
            a->ldr(x0, ptr(sp, 168)) == asmjit::kErrorOk &&
            maplesu::hook_gate::detail::emit_u64(a, x16, return_x28) &&
            a->blr(x16) == asmjit::kErrorOk && a->mov(x28, x0) == asmjit::kErrorOk &&
            a->ldr(x0, ptr(sp, 168)) == asmjit::kErrorOk &&
            maplesu::hook_gate::detail::emit_u64(a, x16, return_release) &&
            a->blr(x16) == asmjit::kErrorOk &&
            maplesu::hook_gate::detail::restore_call_state(a) &&
            owner_gate_emit_return(a, records.front().insn);
    };
    if (!release_owner()) return KModErr::ERR_MODULE_ASM;

    if (a->bind(denied) != asmjit::kErrorOk ||
        a->ldp(x30, xzr, ptr(sp).post(16)) != asmjit::kErrorOk ||
        a->ldp(x28, x29, ptr(sp).post(16)) != asmjit::kErrorOk)
        return KModErr::ERR_MODULE_ASM;
    error = emit_old_insn_and_jump_back(a, gate_address, std::vector<InsnRecord>{records.back()});
    if (error != KModErr::OK) return error;

    OwnerGateLayout candidate{};
    candidate.origin_offset = a->offset();
    constexpr uint32_t bti_c = 0xd503245fu;
    if (a->embed(&bti_c, sizeof(bti_c)) != asmjit::kErrorOk ||
        a->ldp(x0, x1, ptr(sp).post(16)) != asmjit::kErrorOk) return KModErr::ERR_MODULE_ASM;
    error = emit_old_insn_and_jump_back(a, gate_address, records);
    if (error != KModErr::OK) return error;

    // The old payload epilogue puts the owner token in x30 and restores its
    // unchanged 96-byte working frame before entering this gate-only exit.
    candidate.early_return_offset = a->offset();
    if (!maplesu::hook_gate::emit_early_return_entry(a) ||
        !maplesu::hook_gate::detail::save_call_state(a) ||
        a->str(x30, ptr(sp, 168)) != asmjit::kErrorOk || !release_owner())
        return KModErr::ERR_MODULE_ASM;
    layout = candidate;
    return KModErr::OK;
}

KModErr emit_owner_after(Assembler* a, uint64_t gate_address,
    const maplesu_publication_control_v3& control,
    const std::vector<InsnRecord>& records, uint64_t return_acquire,
    uint64_t return_release, uint64_t return_x28, uint64_t return_lr, uint64_t return_payload,
    OwnerGateLayout& layout) {
    layout = {};
    if (!owner_gate_input_valid(a, gate_address, control, records) ||
        return_acquire < UINT64_C(0xffff000000000000) || (return_acquire & 3u) ||
        return_release < UINT64_C(0xffff000000000000) || (return_release & 3u) ||
        return_x28 < UINT64_C(0xffff000000000000) || (return_x28 & 3u) ||
        return_lr < UINT64_C(0xffff000000000000) || (return_lr & 3u) ||
        return_payload < UINT64_C(0xffff000000000000) || (return_payload & 3u))
        return KModErr::ERR_MODULE_PARAM;

    const Label entry = a->newLabel();
    const Label original = a->newLabel();
    const Label admitted = a->newLabel();
    const Label reject = a->newLabel();
    const Label denied = a->newLabel();
    const Label callback_denied = a->newLabel();
    const Label release_owner = a->newLabel();
    if (!entry.isValid() || !original.isValid() || !admitted.isValid() ||
        !reject.isValid() || !denied.isValid() || !callback_denied.isValid() ||
        !release_owner.isValid()) return KModErr::ERR_MODULE_ASM;

    if (a->b(entry) != asmjit::kErrorOk) return KModErr::ERR_MODULE_ASM;
    OwnerGateLayout candidate{};
    candidate.origin_offset = a->offset();
    constexpr uint32_t bti_c = 0xd503245fu;
    if (a->embed(&bti_c, sizeof(bti_c)) != asmjit::kErrorOk ||
        a->ldp(x0, x1, ptr(sp).post(16)) != asmjit::kErrorOk)
        return KModErr::ERR_MODULE_ASM;
    auto error = emit_old_insn_and_jump_back(a, gate_address, records);
    if (error != KModErr::OK) return error;
    if (a->bind(original) != asmjit::kErrorOk) return KModErr::ERR_MODULE_ASM;
    error = emit_old_insn_and_jump_back(a, gate_address, records);
    if (error != KModErr::OK) return error;

    // Keep the incoming frame unchanged while the private provider admits this
    // invocation. The returned owner pointer remains in callee-saved x28.
    if (a->bind(entry) != asmjit::kErrorOk ||
        a->stp(x28, x29, ptr(sp).pre(-16)) != asmjit::kErrorOk ||
        a->stp(x30, xzr, ptr(sp).pre(-16)) != asmjit::kErrorOk ||
        !maplesu::hook_gate::detail::save_call_state(a) ||
        a->ldr(x1, ptr(sp, 192)) != asmjit::kErrorOk ||
        a->ldr(x2, ptr(sp, 176)) != asmjit::kErrorOk ||
        a->add(x3, sp, Imm(208)) != asmjit::kErrorOk ||
        !maplesu::hook_gate::detail::emit_u64(a, x0, control.publication_id) ||
        !maplesu::hook_gate::detail::emit_u64(a, x16, return_acquire) ||
        a->blr(x16) != asmjit::kErrorOk ||
        a->cbz(x0, reject) != asmjit::kErrorOk ||
        a->mov(x28, x0) != asmjit::kErrorOk ||
        !maplesu::hook_gate::detail::restore_call_state(a) ||
        a->b(admitted) != asmjit::kErrorOk ||
        a->bind(reject) != asmjit::kErrorOk ||
        !maplesu::hook_gate::detail::restore_call_state(a) ||
        a->b(denied) != asmjit::kErrorOk)
        return KModErr::ERR_MODULE_ASM;

    if (a->bind(admitted) != asmjit::kErrorOk ||
        a->add(sp, sp, Imm(32)) != asmjit::kErrorOk ||
        a->bl(original) != asmjit::kErrorOk)
        return KModErr::ERR_MODULE_ASM;

    // The owner reference spans original and callback. The private payload
    // accessor uses that admitted owner, so DISABLE cannot suppress an already
    // admitted after callback. The legacy handler start/end ABI remains unchanged.
    if (a->stp(x28, xzr, ptr(sp).pre(-16)) != asmjit::kErrorOk ||
        a->sub(sp, sp, Imm(kHookTrampolineFrame)) != asmjit::kErrorOk ||
        a->stp(x29, x30, ptr(sp).pre(-16)) != asmjit::kErrorOk ||
        !maplesu::hook_gate::detail::save_call_state(a) ||
        a->ldr(x10, ptr(sp, 272)) != asmjit::kErrorOk ||
        a->mov(x0, x10) != asmjit::kErrorOk ||
        !maplesu::hook_gate::detail::emit_u64(a, x16, return_lr) ||
        a->blr(x16) != asmjit::kErrorOk ||
        a->str(x0, ptr(sp, 184)) != asmjit::kErrorOk ||
        a->ldr(x10, ptr(sp, 272)) != asmjit::kErrorOk ||
        a->mov(x0, x10) != asmjit::kErrorOk ||
        !maplesu::hook_gate::detail::emit_u64(a, x16, return_x28) ||
        a->blr(x16) != asmjit::kErrorOk ||
        a->str(x0, ptr(sp, 192)) != asmjit::kErrorOk ||
        a->ldr(x0, ptr(sp, 272)) != asmjit::kErrorOk ||
        !maplesu::hook_gate::detail::emit_u64(a, x16, return_payload) ||
        a->blr(x16) != asmjit::kErrorOk ||
        a->mov(x28, x0) != asmjit::kErrorOk ||
        !maplesu::hook_gate::detail::restore_call_state(a) ||
        a->cbz(x28, callback_denied) != asmjit::kErrorOk ||
        a->stp(x28, x28, ptr(sp).pre(-16)) != asmjit::kErrorOk ||
        a->ldr(x28, ptr(sp, 32)) != asmjit::kErrorOk ||
        a->str(x28, ptr(sp)) != asmjit::kErrorOk ||
        a->ldr(x28, ptr(sp, 8)) != asmjit::kErrorOk ||
        a->blr(x28) != asmjit::kErrorOk ||
        a->bind(callback_denied) != asmjit::kErrorOk ||
        a->bind(release_owner) != asmjit::kErrorOk)
        return KModErr::ERR_MODULE_ASM;

    // The callback has returned with SP at the saved gate frame. Release the
    // per-invocation owner while preserving callback result registers. The
    // handler owns all 80 workspace bytes, so recover x28 again before
    // releasing the owner. Both native calls preserve callee-saved x28.
    if (!maplesu::hook_gate::detail::save_call_state(a) ||
        a->ldr(x0, ptr(sp, 272)) != asmjit::kErrorOk ||
        !maplesu::hook_gate::detail::emit_u64(a, x16, return_x28) ||
        a->blr(x16) != asmjit::kErrorOk ||
        a->mov(x28, x0) != asmjit::kErrorOk ||
        a->ldr(x0, ptr(sp, 272)) != asmjit::kErrorOk ||
        !maplesu::hook_gate::detail::emit_u64(a, x16, return_release) ||
        a->blr(x16) != asmjit::kErrorOk ||
        !maplesu::hook_gate::detail::restore_call_state(a) ||
        a->ldp(x29, x30, ptr(sp).post(16)) != asmjit::kErrorOk ||
        a->add(sp, sp, Imm(kHookTrampolineFrame + 16)) != asmjit::kErrorOk ||
        !owner_gate_emit_return(a, records.front().insn))
        return KModErr::ERR_MODULE_ASM;

    // Admission failure restores the original caller frame and follows the
    // same relocated instruction path used by disabled hooks.
    if (a->bind(denied) != asmjit::kErrorOk ||
        a->ldp(x30, xzr, ptr(sp).post(16)) != asmjit::kErrorOk ||
        a->ldp(x28, x29, ptr(sp).post(16)) != asmjit::kErrorOk)
        return KModErr::ERR_MODULE_ASM;
    error = emit_old_insn_and_jump_back(a, gate_address,
        std::vector<InsnRecord>{records.back()});
    if (error != KModErr::OK) return error;

    layout = candidate;
    return KModErr::OK;
}
} // namespace
