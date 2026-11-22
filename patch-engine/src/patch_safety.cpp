#include "patch_safety.h"
#include "analyze/aarch64_insn.h"
#include "analyze/base_func.h"
#include <capstone/capstone.h>
#include <cstring>
#include <stdexcept>

namespace maplesu {
void restore_instruction(const std::vector<char>& source, size_t from,
                         std::vector<uint8_t>& destination, size_t to) {
    if (from % 4 || to % 4 || to > destination.size() || 4 > destination.size() - to)
        throw std::out_of_range("RELOCATION_RANGE_INVALID");
    const uint32_t instruction = rd32_le(source, from);
    if (aarch64_insn_is_branch(instruction) || aarch64_insn_uses_literal(instruction) ||
        aarch64_insn_is_pac_or_bti(instruction))
        throw std::runtime_error("RELOCATION_INSTRUCTION_UNSUPPORTED");
    csh handle = 0;
    if (cs_open(CS_ARCH_ARM64, CS_MODE_ARM, &handle) != CS_ERR_OK)
        throw std::runtime_error("DISASSEMBLER_INIT_FAILED");
    cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);
    cs_insn* decoded = nullptr;
    const size_t count = cs_disasm(handle, reinterpret_cast<const uint8_t*>(source.data() + from),
                                   4, from, 1, &decoded);
    bool supported = count == 1 && decoded->size == 4 && decoded->detail;
    if (supported) {
        for (uint8_t i = 0; i < decoded->detail->groups_count; ++i) {
            const uint8_t group = decoded->detail->groups[i];
            if (group == CS_GRP_JUMP || group == CS_GRP_CALL || group == CS_GRP_RET ||
                group == CS_GRP_INT || group == CS_GRP_IRET || group == CS_GRP_PRIVILEGE)
                supported = false;
        }
    }
    cs_free(decoded, count);
    cs_close(&handle);
    if (!supported) throw std::runtime_error("RELOCATION_INSTRUCTION_UNSUPPORTED");
    std::memcpy(destination.data() + to, &instruction, sizeof(instruction));
}
}
