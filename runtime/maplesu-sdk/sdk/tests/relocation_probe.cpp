// Run the production decoder and emitter with the real AsmJit assembler.
#include <cstdint>
#include <iomanip>
#include <iostream>
#include "aarch64_asm_helper.h"

namespace kernel_module {
bool aarch64_insn_is_steppable(uint32_t);
bool emit_simulate_aarch64_insn(asmjit::a64::Assembler*, uint64_t, uint32_t, uint64_t);
}

int main() {
    uint32_t insn;
    uint64_t relocated, original;
    while (std::cin >> std::hex >> insn >> relocated >> original) {
        auto ctx = init_aarch64_asm();
        const bool ok = kernel_module::emit_simulate_aarch64_insn(
            ctx.assembler(), relocated, insn, original);
        const auto bytes = aarch64_asm_to_bytes(ctx.assembler());
        if (!ok || ctx.has_error() || bytes.empty()) return 1;
        std::cout << kernel_module::aarch64_insn_is_steppable(insn) << ' ';
        for (const auto byte : bytes)
            std::cout << std::hex << std::setw(2) << std::setfill('0')
                      << static_cast<unsigned>(byte);
        std::cout << '\n';
    }
}
