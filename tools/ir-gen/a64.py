"""AArch64 encoder primitives for the IR spec generator.

These mirror the encoder that produced the patch candidates in
`.analysis/skroot-pro-20261028/tools/a64enc.py`: every word is round-tripped
through capstone (mnemonic + operands + branch target) before it is accepted, so a
hand-encoding mistake cannot reach a spec file.

The one difference from the analysis copy: this module is part of the product
tooling, so it fails with a clear exception instead of an assert, and it re-exports
only what the spec generator needs.
"""
from __future__ import annotations

from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM

# Link-time base the analysis used; only branch-target formatting depends on it.
BASE = 0xFFFFFFC080000000

_md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
_md.detail = True


class EncodeError(ValueError):
    pass


def _imm(value: int) -> str:
    """Capstone's spelling of a non-negative immediate.

    Capstone prints `#0`..`#9` in decimal and everything wider in hex
    (`#0xa`), so a hand-written `"#0x%x" % imm` string never matches for small
    values. Every encoder that formats an immediate must use this helper: that
    spelling mismatch is what used to abort the P3c stub builder whenever
    `init_task & 0xFFF == 0` (5.10.226, `init_task = 0x27BC000`), and it would
    silently break any future `add` with a 1..9 immediate as well.
    """
    if value < 0:
        return "#-0x%x" % -value
    return "#%d" % value if value <= 9 else "#0x%x" % value


def _check(word: int, mnemonic: str, operands: str | None = None, at: int = 0) -> int:
    decoded = list(_md.disasm(word.to_bytes(4, "little"), BASE + at))
    if len(decoded) != 1:
        raise EncodeError("0x%08x is not a single instruction" % word)
    insn = decoded[0]
    if insn.mnemonic != mnemonic:
        raise EncodeError("0x%08x decoded as %s %s, expected %s"
                          % (word, insn.mnemonic, insn.op_str, mnemonic))
    if operands is not None and insn.op_str != operands:
        raise EncodeError("0x%08x decoded as %s %s, expected operands %r"
                          % (word, insn.mnemonic, insn.op_str, operands))
    return word


def movz(rd: int, imm16: int, hw: int = 0, sf: int = 0) -> int:
    if not (0 <= imm16 <= 0xFFFF and 0 <= hw <= 3):
        raise EncodeError("bad movz operands")
    word = (0x52800000 if sf == 0 else 0xD2800000) | (hw << 21) | (imm16 << 5) | rd
    return _check(word, "mov")


def mov_wzr(rd: int) -> int:
    return _check(0x2A1F03E0 | rd, "mov", "w%d, wzr" % rd)


def cmp_reg(rn: int, rm: int) -> int:
    return _check(0x6B00001F | (rm << 16) | (rn << 5), "cmp", "w%d, w%d" % (rn, rm))


def ret() -> int:
    return _check(0xD65F03C0, "ret", "")


def nop() -> int:
    return _check(0xD503201F, "nop", "")


def paciasp() -> int:
    return _check(0xD503233F, "paciasp", "")


def str_pre(rt: int, rn: int, simm: int) -> int:
    if not (-256 <= simm <= 255 and simm % 8 == 0):
        raise EncodeError("bad str pre-index offset")
    imm9 = simm & 0x1FF
    word = 0xF8000000 | (imm9 << 12) | (0b11 << 10) | (rn << 5) | rt
    return _check(word, "str")


def ldr_post(rt: int, rn: int, simm: int) -> int:
    if not (-256 <= simm <= 255 and simm % 8 == 0):
        raise EncodeError("bad ldr post-index offset")
    imm9 = simm & 0x1FF
    word = 0xF8400000 | (imm9 << 12) | (0b01 << 10) | (rn << 5) | rt
    return _check(word, "ldr")


def add_imm(rd: int, rn: int, imm12: int) -> int:
    if not 0 <= imm12 <= 0xFFF:
        raise EncodeError("bad add immediate")
    return _check(0x91000000 | (imm12 << 10) | (rn << 5) | rd, "add",
                  "x%d, x%d, %s" % (rd, rn, _imm(imm12)))


def adrp(rd: int, pc: int, target: int) -> int:
    """pc/target are image-relative offsets (the Image is loaded at BASE)."""
    pc_page = (BASE + pc) & ~0xFFF
    target_page = (BASE + target) & ~0xFFF
    delta_pages = (target_page - pc_page) >> 12
    if not -(1 << 20) <= delta_pages < (1 << 20):
        raise EncodeError("adrp out of range")
    imm = delta_pages & ((1 << 21) - 1)
    word = 0x90000000 | ((imm & 3) << 29) | (((imm >> 2) & 0x7FFFF) << 5) | rd
    decoded = list(_md.disasm(word.to_bytes(4, "little"), BASE + pc))
    if not decoded or decoded[0].mnemonic != "adrp":
        raise EncodeError("bad adrp 0x%08x" % word)
    if not decoded[0].op_str.endswith("#0x%x" % target_page):
        raise EncodeError("adrp 0x%08x resolved to %s, expected #0x%x"
                          % (word, decoded[0].op_str, target_page))
    return word


def b(pc: int, target: int) -> int:
    imm = (target - pc) >> 2
    if not -(1 << 25) <= imm < (1 << 25):
        raise EncodeError("b out of range")
    return _check(0x14000000 | (imm & 0x3FFFFFF), "b", "#0x%x" % (BASE + target), at=pc)


def bl(pc: int, target: int) -> int:
    imm = (target - pc) >> 2
    if not -(1 << 25) <= imm < (1 << 25):
        raise EncodeError("bl out of range")
    return _check(0x94000000 | (imm & 0x3FFFFFF), "bl", "#0x%x" % (BASE + target), at=pc)


def cbz_x(rt: int, pc: int, target: int) -> int:
    imm = (target - pc) >> 2
    if not -(1 << 18) <= imm < (1 << 18):
        raise EncodeError("cbz out of range")
    return _check(0xB4000000 | ((imm & 0x7FFFF) << 5) | rt, "cbz",
                  "x%d, #0x%x" % (rt, BASE + target), at=pc)


def cbz_w(rt: int, pc: int, target: int) -> int:
    imm = (target - pc) >> 2
    if not -(1 << 18) <= imm < (1 << 18):
        raise EncodeError("cbz out of range")
    return _check(0x34000000 | ((imm & 0x7FFFF) << 5) | rt, "cbz",
                  "w%d, #0x%x" % (rt, BASE + target), at=pc)


def ldr_imm(rt: int, rn: int, byte_offset: int, width: int = 8) -> int:
    """`ldr xT, [xN, #off]` (unsigned scaled offset; width 8 or 4)."""
    if width not in (4, 8) or byte_offset < 0 or byte_offset % width:
        raise EncodeError("bad ldr immediate")
    imm12 = byte_offset // width
    if imm12 > 0xFFF:
        raise EncodeError("ldr immediate out of range")
    word = (0xF9400000 if width == 8 else 0xB9400000) | (imm12 << 10) | (rn << 5) | rt
    reg = "x" if width == 8 else "w"
    text = "%s%d, [x%d]" % (reg, rt, rn)
    if byte_offset:
        text = "%s%d, [x%d, %s]" % (reg, rt, rn, _imm(byte_offset))
    return _check(word, "ldr", text)


def mrs_sp_el0(rt: int) -> int:
    """`mrs xT, sp_el0` - `current` on arm64 (CONFIG_THREAD_INFO_IN_TASK).

    Opcode taken from a real kernel: `__arm64_sys_getuid` starts with
    `mrs x8, sp_el0` = 0xd5384108 on every release in the matrix, which is what
    makes `current->cred` resolvable from a stub at all.
    """
    return _check(0xD5384100 | rt, "mrs", "x%d, sp_el0" % rt)


def movk(rd: int, imm16: int, hw: int = 0, sf: int = 1) -> int:
    if not (0 <= imm16 <= 0xFFFF and 0 <= hw <= 3):
        raise EncodeError("bad movk operands")
    word = (0xF2800000 if sf else 0x72800000) | (hw << 21) | (imm16 << 5) | rd
    text = "%s%d, %s" % ("x" if sf else "w", rd, _imm(imm16))
    if hw:
        text += ", lsl #%d" % (hw * 16)
    return _check(word, "movk", text)


def mov_imm64(rd: int, value: int) -> list:
    """`mov xD, #value` as movz + up to three movk, low half first."""
    if not 0 <= value < (1 << 64):
        raise EncodeError("mov_imm64 out of range")
    words = [_check(0xD2800000 | ((value & 0xFFFF) << 5) | rd, "mov",
                    "x%d, %s" % (rd, _imm(value & 0xFFFF)))]
    for shift in (16, 32, 48):
        piece = (value >> shift) & 0xFFFF
        if piece:
            words.append(movk(rd, piece, shift // 16, sf=1))
    return words


def cmp_imm(rn: int, imm12: int, sf: int = 0) -> int:
    if not 0 <= imm12 <= 0xFFF:
        raise EncodeError("bad cmp immediate")
    word = (0xF100001F if sf else 0x7100001F) | (imm12 << 10) | (rn << 5)
    return _check(word, "cmp", "%s%d, %s" % ("x" if sf else "w", rn, _imm(imm12)))


def bti_c() -> int:
    return _check(0xD503245F, "bti", "c")


def b_cond(pc: int, target: int, cond: int) -> int:
    imm = (target - pc) >> 2
    if not -(1 << 18) <= imm < (1 << 18):
        raise EncodeError("b.cond out of range")
    return _check(0x54000000 | ((imm & 0x7FFFF) << 5) | cond, "b." + _COND[cond],
                  "#0x%x" % (BASE + target), at=pc)


_COND = {0b0000: "eq", 0b0001: "ne"}
COND_EQ = 0b0000
COND_NE = 0b0001
