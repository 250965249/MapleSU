"""Gate G3 for a foreign-built KernelSU LKM.

`android15-6.6_kernelsu.ko` was built by CI against a 6.6.127 "dirty" kernel, so its
vermagic prefix does not match our 6.6.89 device. That alone is fine (with a
__versions section the loader compares only the suffix), but every undefined symbol
in the .ko must still resolve through OUR kernel's export table. On a GKI build with
CONFIG_TRIM_UNUSED_KSYMS, "exported upstream" does not imply "exported here", and a
missing one turns the whole Normal target into `Unknown symbol` at load time.

Usage: python ksu_import_gate.py <kernelsu.ko> <symbols.tsv>
Exit 0 = every import is exportable on this kernel.
"""
from __future__ import annotations

import re
import struct
import sys
from pathlib import Path

SHT_SYMTAB = 2


def undefined_symbols(path: Path) -> list[str]:
    raw = path.read_bytes()
    e_shoff, = struct.unpack_from("<Q", raw, 40)
    e_shnum, e_shstrndx = struct.unpack_from("<HH", raw, 60)
    sections = []
    for index in range(e_shnum):
        sections.append(struct.unpack_from("<IIQQQQIIQQ", raw, e_shoff + index * 64))
    names = []
    symtab = next(s for s in sections if s[1] == SHT_SYMTAB)
    strings = sections[symtab[6]]
    table = raw[strings[4]: strings[4] + strings[5]]
    for index in range(symtab[5] // 24):
        base = symtab[4] + index * 24
        name_off, info, _other, shndx, _value, _size = struct.unpack_from("<IBBHQQ", raw, base)
        if shndx != 0:
            continue
        if (info >> 4) != 1 and (info >> 4) != 2:  # STB_GLOBAL / STB_WEAK
            continue
        end = table.find(b"\x00", name_off)
        name = table[name_off:end].decode()
        if name and not name.startswith("__gnu_lto"):
            names.append(name)
    return sorted(set(names))


def exported(tsv: Path) -> set[str]:
    out = set()
    for line in tsv.read_text(encoding="utf-8", errors="replace").splitlines():
        fields = line.split()
        if not fields:
            continue
        name = fields[-1]
        # A kernel symbol X is importable iff __ksymtab_X exists in kallsyms.
        if name.startswith("__ksymtab_"):
            out.add(name[len("__ksymtab_"):])
        elif name.startswith("__ksymtab_gpl_"):
            out.add(name[len("__ksymtab_gpl_"):])
    return out


def main() -> int:
    if len(sys.argv) != 3:
        raise SystemExit(__doc__)
    lkm, tsv = Path(sys.argv[1]), Path(sys.argv[2])
    imports = undefined_symbols(lkm)
    have = exported(tsv)
    missing = [name for name in imports if name not in have]
    print("module: %s (%d imports)" % (lkm.name, len(imports)))
    print("kernel: %s (%d exported symbols)" % (tsv.name, len(have)))
    if not missing:
        print("RESULT: every import resolves on this kernel")
        return 0
    print("RESULT: %d imports are NOT exported on this kernel:" % len(missing))
    for name in missing:
        print("  - " + name)
    return 1


if __name__ == "__main__":
    sys.exit(main())
