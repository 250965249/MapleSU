// aarch64 decode insn implementation.
//
#include <cstdint>

namespace kernel_module {

bool aarch64_insn_is_steppable(uint32_t insn);

namespace {

constexpr uint32_t kHintSpaceMask = 0xFFFFF01Fu;
constexpr uint32_t kHintSpaceVal = 0xD503201Fu;
constexpr uint32_t kHintOp2Mask = 0x00000FE0u;

constexpr uint32_t kHintXpaclri = 0x000000E0u;    // 0x07 << 5
constexpr uint32_t kHintPacia1716 = 0x00000100u;  // 0x08 << 5
constexpr uint32_t kHintPacib1716 = 0x00000140u;  // 0x0A << 5
constexpr uint32_t kHintPaciaz = 0x00000300u;     // 0x18 << 5
constexpr uint32_t kHintPaciasp = 0x00000320u;    // 0x19 << 5
constexpr uint32_t kHintPacibz = 0x00000340u;     // 0x1A << 5
constexpr uint32_t kHintPacibsp = 0x00000360u;    // 0x1B << 5
constexpr uint32_t kHintBti = 0x00000400u;        // 0x20 << 5
constexpr uint32_t kHintBtic = 0x00000440u;       // 0x22 << 5
constexpr uint32_t kHintBtij = 0x00000480u;       // 0x24 << 5
constexpr uint32_t kHintBtijc = 0x000004C0u;      // 0x26 << 5
constexpr uint32_t kHintNop = 0x00000000u;        // 0x00 << 5

// MRS 读取 DAIF 时不可单步：PSTATE 的 D/A/I/F 位在单步过程中会变化。
constexpr uint32_t kMrsSysregMask = 0x001FFFE0u;
constexpr uint32_t kMrsDaifSysreg = 0x001B4220u;

inline bool hint_is_steppable(uint32_t insn) noexcept {
    switch (insn & kHintOp2Mask) {
        case kHintXpaclri:
        case kHintPacia1716:
        case kHintPacib1716:
        case kHintPaciaz:
        case kHintPaciasp:
        case kHintPacibz:
        case kHintPacibsp:
        case kHintBti:
        case kHintBtic:
        case kHintBtij:
        case kHintBtijc:
        case kHintNop:
            return true;
        default:
            return false;
    }
}

bool branch_class_is_steppable(uint32_t insn) noexcept {
    // PC 相对分支须由重定位器展开，不能直接复制到 XOL 槽位。
    if ((insn & 0xFC000000u) == 0x14000000u) return false;  // B
    if ((insn & 0xFC000000u) == 0x94000000u) return false;  // BL

    // CBZ / CBNZ / TBZ / TBNZ（bit31 是 sf 位，被掩码放过）。
    if ((insn & 0x7C000000u) == 0x34000000u) return false;

    // RETAA / RETAB：与原始解码器一致，认证返回不进入单步路径。
    if ((insn & 0xFFFFFBFFu) == 0xD65F0BFFu) return false;

    // 寄存器间接跳转一律不可单步：目标地址在单步上下文里不可预测。
    if ((insn & 0xFFFFFC1Fu) == 0xD65F0000u) return false;  // RET  <Rn>
    if ((insn & 0xFFFFFC1Fu) == 0xD61F0000u) return false;  // BR   <Rn>
    if ((insn & 0xFFFFFC1Fu) == 0xD63F0000u) return false;  // BLR  <Rn>
    if ((insn & 0xFEFFF800u) == 0xD63F0800u) return false;  // BLRAA/BLRAB(+Z)
    if ((insn & 0xFEFFF800u) == 0xD61F0800u) return false;  // BRAA/BRAB(+Z)

    if ((insn & 0xFF000010u) == 0x54000000u) return false;  // B.cond

    // MSR (immediate)：写 PSTATE（SPSel/DAIFSet/DAIFClr/UAO/PAN/DIT/TCO…）。
    if ((insn & 0xFFF8F01Fu) == 0xD500401Fu) return false;
    // MSR (register)：写系统寄存器。
    if ((insn & 0xFFF00000u) == 0xD5100000u) return false;
    // 原始实现拒绝异常生成和异常返回指令的单步搬移。
    if ((insn & 0xFF000000u) == 0xD4000000u) return false;

    if (insn == 0xD69F03E0u) return false;                    // ERET
    if ((insn & 0xFFFFFBFFu) == 0xD69F0BFFu) return false;    // ERETAA/ERETAB

    // MRS：读系统寄存器本身安全，唯一例外是读 DAIF。
    if ((insn & 0xFFF00000u) == 0xD5300000u) {
        return (insn & kMrsSysregMask) != kMrsDaifSysreg;
    }

    // HINT 空间：只有一部分（PAC/BTI/NOP 等）可单步。
    if ((insn & kHintSpaceMask) == kHintSpaceVal) {
        return hint_is_steppable(insn);
    }

    return true;
}

}  // namespace

bool aarch64_insn_is_steppable(uint32_t insn) {
    if ((insn & 0xffff0000u) == 0) return false;
    if ((insn & 0x1C000000u) == 0x14000000u) {
        return branch_class_is_steppable(insn);
    }

    // Integer, SIMD and prefetch literals all carry a PC-relative imm19.
    if ((insn & 0x3B000000u) == 0x18000000u) return false;

    // ADR / ADRP。
    if ((insn & 0x1F000000u) == 0x10000000u) return false;

    // 独占访存（LDXR/STXR/LDAXR/STLXR/CAS…）：重试语义与单步冲突，不可单步。
    return (insn & 0x3F800000u) != 0x08000000u;
}

}  // namespace kernel_module
