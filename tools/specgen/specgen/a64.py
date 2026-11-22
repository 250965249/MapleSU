"""The few AArch64 encodings the Ultra recipe actually needs.

The recipe stores its replacement blobs as bytes, but every address-bearing field is
*recomputed* for the target kernel, so the generator must be able to encode and decode:

  * ``B`` / ``BL``      : imm26, PC-relative, +-128 MiB
  * ``MOVZ``/``MOVK``   : the immediate pairs the blobs use to build a 64-bit value
  * ``ADR``             : imm21, PC-relative to the instruction itself
  * ``MOVZ #1`` / ``RET``/ ``NOP`` : the three one-instruction stubs

Nothing else is decoded: the recipe never reads kernel instructions except the
``ldrsw xD, [xN, #imm]`` that yields ``task_struct.seccomp``.

All offsets are *file offsets inside the raw Image*, which is also the address space
the spec works in. Encoding is layout-independent: the caller passes the file offset
the instruction will land at, so a re-located blob branches to the right place.
"""
from __future__ import annotations

MASK64 = (1 << 64) - 1

NOP = 0xD503201F
RET = 0xD65F03C0


def sign_extend(value: int, bits: int) -> int:
    return value - (1 << bits) if value & (1 << (bits - 1)) else value


def encode_b(here: int, target: int) -> int:
    """``b <target>`` located at ``here``."""
    return _encode_branch(0x14000000, here, target)


def encode_bl(here: int, target: int) -> int:
    """``bl <target>`` located at ``here``."""
    return _encode_branch(0x94000000, here, target)


def _encode_branch(opcode: int, here: int, target: int) -> int:
    delta = target - here
    if delta % 4:
        raise ValueError("BRANCH_NOT_ALIGNED:%d" % delta)
    imm26 = delta // 4
    if not -(1 << 25) <= imm26 < (1 << 25):
        raise ValueError("BRANCH_OUT_OF_RANGE:%d" % delta)
    return opcode | (imm26 & 0x03FFFFFF)


def decode_branch(word: int, here: int) -> int | None:
    """Target of a B/BL word placed at ``here``, or ``None``."""
    if not is_branch(word):
        return None
    return (here + sign_extend(word & 0x03FFFFFF, 26) * 4) & MASK64


def is_branch(word: int) -> bool:
    """True for ``B`` and ``BL`` (bit 31 distinguishes them, so mask 0xFC000000)."""
    return (word & 0xFC000000) in (0x14000000, 0x94000000)


def is_bl(word: int) -> bool:
    return (word & 0xFC000000) == 0x94000000


def encode_adr(here: int, target: int) -> int:
    """``adr xN, <target>`` using register 0 unless the caller patches Rd itself."""
    return _encode_adr(here, target, 0)


def _encode_adr(here: int, target: int, rd: int) -> int:
    delta = target - here
    if delta % 4:
        raise ValueError("ADR_NOT_ALIGNED:%d" % delta)
    imm = delta // 4
    if not -(1 << 20) <= imm < (1 << 20):
        raise ValueError("ADR_OUT_OF_RANGE:%d" % delta)
    immlo = imm & 0x3
    immhi = (imm >> 2) & 0x7FFFF
    return 0x10000000 | (immlo << 29) | (immhi << 5) | (rd & 0x1F)


def is_adr(word: int) -> bool:
    return (word & 0x9F000000) == 0x10000000


def decode_adr(word: int, here: int) -> int | None:
    if not is_adr(word):
        return None
    imm = ((word >> 5) & 0x7FFFF) << 2 | ((word >> 29) & 0x3)
    return (here + sign_extend(imm, 21)) & MASK64


def is_movz(word: int) -> bool:
    return (word & 0x7F800000) == 0x52800000


def is_movk(word: int) -> bool:
    return (word & 0x7F800000) == 0x72800000


def movz(rd: int, imm16: int, shift: int = 0, sf: int = 1) -> int:
    return (0xD2800000 if sf else 0x52800000) | ((shift // 16) << 21) | ((imm16 & 0xFFFF) << 5) | (rd & 0x1F)


def movk(rd: int, imm16: int, shift: int = 0, sf: int = 1) -> int:
    return (0xF2800000 if sf else 0x72800000) | ((shift // 16) << 21) | ((imm16 & 0xFFFF) << 5) | (rd & 0x1F)


def encode_imm64(rd: int, value: int) -> list[int]:
    """``movz`` + up to three ``movk`` building ``value`` (two's complement accepted)."""
    value &= MASK64
    words = [movz(rd, value & 0xFFFF, 0)]
    for shift in (16, 32, 48):
        part = (value >> shift) & 0xFFFF
        if part:
            words.append(movk(rd, part, shift))
    return words


def decode_imm64(words: list[int], rd: int) -> int | None:
    """Value built by a contiguous ``movz``/``movk`` run on ``rd``."""
    if not words or not is_movz(words[0]) or (words[0] & 0x1F) != rd:
        return None
    value = 0
    expected_shift = 0
    for word in words:
        if is_movk(word):
            if (word & 0x1F) != rd:
                return None
            shift = ((word >> 21) & 0x3) * 16
            value |= ((word >> 5) & 0xFFFF) << shift
        elif is_movz(word):
            if (word & 0x1F) != rd or ((word >> 21) & 0x3) != 0:
                return None
            value = (word >> 5) & 0xFFFF
        else:
            return None
        expected_shift += 16
    return value & MASK64


def u32(value: int) -> bytes:
    return (value & 0xFFFFFFFF).to_bytes(4, "little")


def u16(value: int) -> bytes:
    return (value & 0xFFFF).to_bytes(2, "little")


def le32(data: bytes, offset: int) -> int:
    return int.from_bytes(data[offset:offset + 4], "little")


def words(data: bytes) -> list[int]:
    return [le32(data, i) for i in range(0, len(data) - 3, 4)]
