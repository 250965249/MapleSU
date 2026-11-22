"""Derive the release-independent recipe from one published spec + its reference kernel.

This is the bootstrapping step: k22's 18 records are the only *proven* Ultra payload, so the recipe
is extracted from them once, under review, instead of being typed by hand. Everything that is a
file offset in the shipped spec becomes a symbol reference here; everything that is an address
embedded in a replacement blob becomes a relocation; the credential and the init path become
declarative slots.

The result is checked by ``make_spec.py --self-check``: re-rendering the recipe on the reference
kernel has to reproduce the published spec's records byte for byte.

Usage:
    derive_recipe.py --spec manager/src/main/assets/ultra-kernels/k22-ultra-6.6.89.spec \
        --kernel <raw Image> --out tools/specgen/specgen/recipes/k22.json [--id k22]
"""
from __future__ import annotations

import argparse
import hashlib
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from specgen import a64, kallsyms  # noqa: E402
from specgen.recipe import Record, Recipe, Reloc, _scan_struct_offset  # noqa: E402

WORD_KINDS = ("branch", "imm64_delta", "u32_target", "u32_self", "u32_const", "word")


def parse_spec(path: Path):
    kernel, key, records = "", "", []
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line:
            continue
        if line.startswith("#kernel="):
            kernel = line[len("#kernel="):].strip()
            continue
        if line.startswith("#key="):
            key = line[len("#key="):].strip()
            continue
        if line.startswith("#"):
            continue
        offset, original, replacement = line.split("|")
        records.append((int(offset), bytes.fromhex(original), bytes.fromhex(replacement)))
    return kernel, key, records


def nearest(symbols, address: int) -> dict:
    """A reference that resolves back to ``address`` (aliases and repeats are rejected)."""
    try:
        name, delta = symbols.reference(address)
    except kallsyms.KallsymsError as error:
        raise SystemExit("cannot reference 0x%X: %s" % (address, error))
    return {"symbol": name, "delta": delta}


def width_of(reloc: Reloc) -> int:
    if reloc.kind == "u16_struct":
        return 2
    if reloc.kind in ("init_path", "credential"):
        return int(reloc.options["length"])
    if reloc.kind == "imm64_delta":
        return 4 * int(reloc.options["words"])
    return 4


def word_ops(replacement: bytes) -> list[Reloc] | None:
    """Express a one-instruction stub as ops, or ``None`` when it is not one."""
    if len(replacement) not in (4, 8, 12, 16):
        return None
    ops = []
    for position in range(0, len(replacement), 4):
        word = a64.le32(replacement, position)
        if word == a64.RET:
            ops.append(Reloc(position, "word", op="ret"))
        elif word == a64.NOP:
            ops.append(Reloc(position, "word", op="nop"))
        elif a64.is_movz(word) and ((word >> 21) & 0x3) == 0:
            ops.append(Reloc(position, "word", op="movz", rd=word & 0x1F,
                             imm=(word >> 5) & 0xFFFF, sf=(word >> 31) & 1))
        elif (word & 0xFFFFFFE0) == 0x2A1F03E0:
            ops.append(Reloc(position, "word", op="mov_wzr", rd=word & 0x1F))
        else:
            return None
    return ops


def discover(symbols, offset: int, replacement: bytes, credential: bytes,
             structs: dict) -> tuple[list[Reloc], bytearray]:
    """Every address-bearing field of one replacement blob, as relocations."""
    size = len(replacement)
    relocs: list[Reloc] = []
    taken = bytearray(size)

    def reserve(at: int, width: int) -> None:
        for position in range(at, min(at + width, size)):
            taken[position] = 1

    # 1. printable fields first: their bytes must never be re-read as a number.
    credential_at = replacement.find(credential)
    if credential_at >= 0:
        relocs.append(Reloc(credential_at, "credential", length=len(credential)))
        reserve(credential_at, len(credential))
    path_at = replacement.find(b"/data/")
    if path_at >= 0:
        end = path_at
        while end < size and 0x20 <= replacement[end] < 0x7F:
            end += 1
        relocs.append(Reloc(path_at, "init_path", length=end - path_at + 1))
        reserve(path_at, end - path_at + 1)

    data_like = bool(relocs)

    # 2. instructions and numbers, on 4-byte boundaries.
    position = 0
    while position + 4 <= size:
        if taken[position]:
            position += 4
            continue
        word = a64.le32(replacement, position)
        here = offset + position
        if a64.is_branch(word):
            target = a64.decode_branch(word, here)
            if target is None or not offset <= target < offset + size:
                opcode = "bl" if a64.is_bl(word) else "b"
                relocs.append(Reloc(position, "branch", op=opcode, target=nearest(symbols, target)))
                reserve(position, 4)
            position += 4
            continue
        if a64.is_adr(word):
            target = a64.decode_adr(word, here)
            chain, cursor = [], position + 4
            while cursor + 4 <= size and len(chain) < 4:
                candidate = a64.le32(replacement, cursor)
                if not (a64.is_movz(candidate) or a64.is_movk(candidate)):
                    break
                chain.append(candidate)
                cursor += 4
            if chain:
                register = chain[0] & 0x1F
                constant = a64.decode_imm64(chain, register)
                add = a64.le32(replacement, cursor) if cursor + 4 <= size else 0
                # ``add x<adr>, x<adr>, x<constant>``: Rn carries the adr result, Rm the constant.
                uses = (
                    (add & 0xFFE0FC00) == 0x8B000000
                    and ((add >> 5) & 0x1F) == (word & 0x1F)
                    and ((add >> 16) & 0x1F) == register
                )
                if constant is not None and uses and target is not None:
                    resolved = (here + constant) & a64.MASK64
                    relocs.append(Reloc(position + 4, "imm64_delta", adr=position,
                                        reg=register, words=len(chain),
                                        target=nearest(symbols, resolved)))
                    reserve(position + 4, len(chain) * 4)
                    position = cursor
                    continue
            position += 4
            continue
        if data_like and word == a64.RET:
            relocs.append(Reloc(position, "word", op="ret"))
            reserve(position, 4)
        elif data_like and word == a64.NOP:
            relocs.append(Reloc(position, "word", op="nop"))
            reserve(position, 4)
        elif offset <= word < offset + size:
            relocs.append(Reloc(position, "u32_self", delta=word - offset))
            reserve(position, 4)
        elif word == offset:
            relocs.append(Reloc(position, "u32_self"))
            reserve(position, 4)
        elif symbols.is_symbol_start(word) and 0 < word < symbols.image_size:
            relocs.append(Reloc(position, "u32_target", target=nearest(symbols, word)))
            reserve(position, 4)
        elif data_like:
            relocs.append(Reloc(position, "u32_const", value="0x%08X" % word))
            reserve(position, 4)
        position += 4

    # 3. the 16-bit structure offset.
    for position in range(size - 1):
        if taken[position]:
            continue
        value = int.from_bytes(replacement[position:position + 2], "little")
        for name, expected in structs.items():
            if value == expected:
                relocs.append(Reloc(position, "u16_struct", name=name))
                reserve(position, 2)
                break

    relocs.sort(key=lambda item: item.at)
    return relocs, taken


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--spec", required=True, type=Path)
    parser.add_argument("--kernel", required=True, type=Path, help="reference raw ARM64 Image")
    parser.add_argument("--out", required=True, type=Path)
    parser.add_argument("--id", default="k22")
    args = parser.parse_args()

    release, key, records = parse_spec(args.spec)
    kernel = args.kernel.read_bytes()
    table = kallsyms.decode(kernel)
    if kallsyms.release_of(kernel) != release:
        raise SystemExit("spec/kernel release mismatch: %s != %s"
                         % (release, kallsyms.release_of(kernel)))
    credential = key.encode("ascii")
    structs = {"task_struct.seccomp": _scan_struct_offset(
        kernel, table.offset_of("prctl_get_seccomp"), table, "ldrsw")}
    print("resolved struct offsets:", structs)

    out_records = []
    for index, (offset, original, replacement) in enumerate(records):
        locator = nearest(table, offset)
        ops = word_ops(replacement)
        if ops is not None:
            relocs, template, note = ops, None, "one-instruction stub, assembled from ops"
        else:
            relocs, taken = discover(table, offset, replacement, credential, structs)
            if all(taken):
                template, note = None, "pure data record, assembled from fields"
            else:
                template, note = replacement.hex(), ""
        role = "%s+0x%X" % (locator["symbol"], locator["delta"])
        out_records.append(Record(role=role, symbol=locator["symbol"], delta=locator["delta"],
                                  length=len(replacement), template=template, relocs=relocs,
                                  note=note,
                                  reference_orig_sha256=hashlib.sha256(original).hexdigest()))
        print("rec %2d 0x%08X %-34s len=%3d %-9s relocs=%2d"
              % (index, offset, role, len(replacement),
                 "assembled" if template is None else "template", len(relocs)))

    recipe = Recipe(ident=args.id, reference_release=release, records=out_records,
                    note="Derived from %s by tools/specgen/derive_recipe.py. Every site offset "
                         "is a symbol reference plus a byte delta; every embedded address is a "
                         "relocation resolved from the target kernel's kallsyms."
                         % args.spec.name)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    recipe.save(args.out)
    print("wrote", args.out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
