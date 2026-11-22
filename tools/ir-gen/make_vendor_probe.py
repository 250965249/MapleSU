"""Turn a device-accepted vendor module into a safe probe.

The vendor module reaches EEXIST on this device, which means it passes every
ENOEXEC check the loader performs before "is it already loaded". Our own module
does not. To find out whether the difference is our *section structure* or our
*metadata*, this tool rewrites the vendor module in place, without changing any
size or layout:

  * `.init.text` first two instructions become `mov w0, #-19; ret`, so the probe
    runs and unloads itself instead of doing the vendor init (which patches
    SELinux and calls a usermode helper);
  * `.modinfo` `name=` becomes ours, so a successful load reports our name.

Everything else -- section set, notes, PLT, altinstructions, relocations, the
build-id -- stays byte-identical to the module the kernel already accepts.

If this probe loads, our ELF's *section set* is what the loader refuses. If it
still fails, our metadata/relocation handling is.
"""
from __future__ import annotations

import struct
import sys
from pathlib import Path

MOV_W0_NEG19 = 0x12800260
RET = 0xD65F03C0
NEW_NAME = b"maplesu_probe\x00"


def find(elf: bytearray, name: str):
    e_shoff, = struct.unpack_from("<Q", elf, 40)
    e_shnum, e_shstrndx = struct.unpack_from("<HH", elf, 60)
    headers = []
    for index in range(e_shnum):
        base = e_shoff + index * 64
        headers.append(struct.unpack_from("<IIQQQQIIQQ", elf, base))
    str_hdr = headers[e_shstrndx]
    table = elf[str_hdr[4]: str_hdr[4] + str_hdr[5]]
    for index, header in enumerate(headers):
        end = table.find(b"\x00", header[0])
        if table[header[0]:end].decode() == name:
            return index, headers, e_shoff
    raise SystemExit("section not found: " + name)


def symbols(elf: bytearray, headers):
    for header in headers:
        if header[1] != 2:  # SHT_SYMTAB
            continue
        strtab = headers[header[6]]
        strings = elf[strtab[4]: strtab[4] + strtab[5]]
        out = {}
        for index in range(header[5] // 24):
            base = header[4] + index * 24
            name_off, info, other, shndx, value, size = struct.unpack_from("<IBBHQQ", elf, base)
            end = strings.find(b"\x00", name_off)
            out[strings[name_off:end].decode()] = {"shndx": shndx, "value": value, "size": size}
        return out
    raise SystemExit("no symtab")


def main() -> int:
    if len(sys.argv) != 3:
        raise SystemExit(__doc__)
    source, target = Path(sys.argv[1]), Path(sys.argv[2])
    elf = bytearray(source.read_bytes())

    index, headers, _shoff = find(elf, ".init.text")
    init_text = headers[index]
    syms = symbols(elf, headers)
    entry = syms.get("init_module")
    if entry is None:
        raise SystemExit("no init_module symbol")
    base = init_text[4] + entry["value"]
    struct.pack_into("<I", elf, base, MOV_W0_NEG19)
    struct.pack_into("<I", elf, base + 4, RET)

    index, headers, _shoff = find(elf, ".modinfo")
    info = headers[index]
    offset, size = info[4], info[5]
    blob = bytearray(elf[offset: offset + size])
    marker = blob.find(b"name=")
    if marker < 0:
        raise SystemExit("no name= tag")
    end = blob.find(b"\x00", marker)
    if end - marker - 5 < len(NEW_NAME):
        raise SystemExit("name does not fit in place")
    blob[marker + 5: marker + 5 + len(NEW_NAME)] = NEW_NAME
    for cursor in range(marker + 5 + len(NEW_NAME), end):
        blob[cursor] = 0
    elf[offset: offset + size] = blob

    target.write_bytes(bytes(elf))
    print("wrote %s (init patched to return -19, name=%s)"
          % (target, NEW_NAME[:-1].decode()))
    return 0


if __name__ == "__main__":
    sys.exit(main())
