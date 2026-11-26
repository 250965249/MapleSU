"""Pure-Python mirror of `lease_contract.c` (authoritative-on-host when no C compiler/NDK).

This is a byte-for-byte semantic port of the production C validators, used by
`test_contract.py` (zero-arg mode) and by the GhostSam adapter tests as the shared
argv contract authority. It is NOT the production validator: when an NDK/host
compiler is available, `test_contract.py --ndk ...` compiles and runs the real C.
"""

from __future__ import annotations

PREFIX = b"maplesu-jb-"


def endpoint(value: bytes | None) -> bool:
    if value is None:
        return False
    if not value.startswith(PREFIX):
        return False
    i = len(PREFIX)
    for c in value[i:]:
        if i >= 100:
            return False
        if not ((ord("a") <= c <= ord("z")) or (ord("0") <= c <= ord("9")) or c == ord("-")):
            return False
        i += 1
    return i > 11


def _hex(c: int) -> int:
    if ord("0") <= c <= ord("9"):
        return c - ord("0")
    if ord("a") <= c <= ord("f"):
        return c - ord("a") + 10
    return -1


def nonce(value: bytes | None) -> bytes | None:
    if value is None:
        return None
    if len(value) < 64:
        return None
    out = bytearray(32)
    for i in range(32):
        a = _hex(value[2 * i])
        b = _hex(value[2 * i + 1])
        if a < 0 or b < 0:
            return None
        out[i] = (a << 4) | b
    if len(value) != 64:
        return None
    return bytes(out)


def boot_id(value: bytes | None) -> bool:
    if value is None or len(value) != 36:
        return False
    for i in range(36):
        if i in (8, 13, 18, 23):
            if value[i] != ord("-"):
                return False
        elif _hex(value[i]) < 0:
            return False
    return True


def decimal(value: bytes | None, minimum: int) -> int | None:
    if value is None or not value or minimum < 0:
        return None
    result = 0
    for c in value:
        digit = c - ord("0")
        if digit < 0 or digit > 9 or result > (2147483647 - digit) // 10:
            return None
        result = result * 10 + digit
    if result < minimum:
        return None
    return result


class MirrorDLL:
    """ctypes-compatible facade so the existing unittest body can run unchanged."""

    @staticmethod
    def maplesu_lease_endpoint(value):
        return 1 if endpoint(value) else 0

    @staticmethod
    def maplesu_lease_nonce(value, out):
        if out is None:
            return 0
        parsed = nonce(value)
        if parsed is None:
            return 0
        for i, b in enumerate(parsed):
            out[i] = b
        return 1

    @staticmethod
    def maplesu_lease_boot_id(value):
        return 1 if boot_id(value) else 0

    @staticmethod
    def maplesu_lease_decimal(value, minimum, out):
        if out is None:
            return 0
        parsed = decimal(value, minimum)
        if parsed is None:
            return 0
        target = getattr(out, "_obj", out)
        target.value = parsed
        return 1


def self_starttime(stat_line: str) -> int:
    """N1: parse field 22 of /proc/<pid>/stat. comm (field 2) may contain ')'/spaces, so anchor
    on the LAST ')' and parse the remaining space-separated fields; field 3 is state (R/S/D)."""
    if not stat_line:
        return 0
    idx = stat_line.rfind(")")
    if idx < 0:
        return 0
    rest = stat_line[idx + 1:].split()
    # rest[0] = state (field 3); field 4 .. field 22 -> rest[1] .. rest[19]
    if len(rest) < 20:
        return 0
    try:
        value = int(rest[19])
    except ValueError:
        return 0
    return value if value > 0 else 0
