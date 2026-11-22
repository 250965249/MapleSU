"""Resolve `task_struct` offsets from the image itself (product-side re-derivation).

`patch-engine` computes these in C++ (`parser_cred_offset`,
`parse_cred_uid_offset`, `parser_seccomp_offset` in upstream/patch_kernel_root.cpp).
The offline asset builder needs the same numbers without linking the engine, so
this module re-implements exactly those algorithms on top of a kallsyms dump and
records the instruction that produced each value. If the two ever disagree the
asset is wrong, so `make_release_assets.py` also runs the engine and compares.

Algorithm (mirrors the C++):

  cred_offset      the first `mrs xN, sp_el0` in the getuid function is `current`;
                   the first later `ldr xD, [xN, #imm]` / `add xD, xN, #imm` with
                   imm > 0x400 is `current->cred`.
  cred_uid_offset  collect the positive displacements/immediates of the same body
                   in instruction order, find cred_offset in that list, then take
                   the next value inside [min_off, 0x20]; min_off is 8 for kernels
                   >= 6.6.8 and 4 below it (struct cred switched atomic_long_t ->
                   atomic_t for usage).
  seccomp_offset   the same `current` machine applied to prctl_get_seccomp.

Usage:
  resolve_struct_offsets.py --image <Image> --symbols <symbols.tsv> [--release R]
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

from capstone import CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN, Cs
from capstone.arm64 import ARM64_OP_IMM, ARM64_OP_MEM

sys.path.insert(0, str(Path(__file__).resolve().parent))

import rules                      # noqa: E402  (SymbolTable, version_tuple)

GETUID_NAMES = ("__arm64_sys_getuid", "sys_getuid", "__arm64_sys_geteuid", "sys_geteuid")
SECCOMP_NAMES = ("prctl_get_seccomp",)
MIN_CRED_OFFSET = 0x400           # same floor the C++ uses to skip task_struct fields
UID_MIN_VERSION = (6, 6, 8)       # cred_uid floor switches 4 -> 8 here

_MD = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
_MD.detail = True

LDR_RE = re.compile(r"^(x\d+), \[x(\d+), #(0x[0-9a-f]+|\d+)\]$")
ADD_RE = re.compile(r"^(x\d+), x(\d+), #(0x[0-9a-f]+|\d+)$")
MRS_RE = re.compile(r"^(x\d+), sp_el0$")
AND_RE = re.compile(r"^(x\d+), (x\d+), #0xffffffffffffc000$")


def _disasm(image: bytes, offset: int, size: int):
    return list(_MD.disasm(image[offset:offset + size], offset))


def _track(v_code, start_index: int, base_reg: str) -> list:
    tracked = []
    for insn in v_code[start_index:]:
        if insn.mnemonic in ("ldr", "ldrsw"):
            match = LDR_RE.match(insn.op_str)
            if match and ("x" + match.group(2)) == base_reg:
                tracked.append({"dst": match.group(1), "offset": int(match.group(3), 0),
                                "insn": "%s %s" % (insn.mnemonic, insn.op_str),
                                "at": insn.address})
        elif insn.mnemonic == "add":
            match = ADD_RE.match(insn.op_str)
            if match and ("x" + match.group(2)) == base_reg:
                tracked.append({"dst": match.group(1), "offset": int(match.group(3), 0),
                                "insn": "%s %s" % (insn.mnemonic, insn.op_str),
                                "at": insn.address})
    return tracked


def resolve_current(v_code) -> tuple:
    """`current` anchor: `mrs xN, sp_el0` first, page-masked `and` as fallback."""
    for index, insn in enumerate(v_code):
        if insn.mnemonic != "mrs":
            continue
        match = MRS_RE.match(insn.op_str)
        if match:
            return _track(v_code, index + 1, match.group(1)), "mrs %s @0x%x" % (
                insn.op_str, insn.address)
    for index, insn in enumerate(v_code):
        if insn.mnemonic != "and":
            continue
        match = AND_RE.match(insn.op_str)
        if match:
            return _track(v_code, index + 1, match.group(1)), "and page-mask @0x%x" % insn.address
    return [], None


def candidate_offsets(v_code) -> list:
    """Positive mem displacement first, then up to two positive immediates."""
    values = []
    for insn in v_code:
        if insn.mnemonic == "b":
            continue
        displacement = None
        immediates = []
        for operand in insn.operands:
            if operand.type == ARM64_OP_IMM and operand.imm > 0 and len(immediates) < 2:
                immediates.append(operand.imm)
            elif operand.type == ARM64_OP_MEM:
                displacement = operand.mem.disp
        if displacement is not None and displacement > 0:
            values.append(displacement)
        values.extend(value for value in immediates if value > 0)
    return values


def uid_min_offset(release: str) -> int:
    return 8 if rules.version_tuple(release) >= UID_MIN_VERSION else 4


def _first_above(tracked: list, floor: int):
    return next((item for item in tracked if item["offset"] > floor), None)


def resolve(image: bytes, symbols: dict, release: str) -> dict:
    table = rules.SymbolTable(symbols)
    record = {"release": release, "uid_min_offset": uid_min_offset(release),
              "schemaVersion": 1}

    # ---- cred_offset + cred_uid_offset ------------------------------------ #
    name, offset = table.offset(*GETUID_NAMES)
    if not offset:
        record["cred"] = {"ok": False, "error": "no getuid symbol"}
        record["cred_uid"] = {"ok": False, "error": "no getuid symbol"}
    else:
        span = table.span(offset)
        v_code = _disasm(image, offset, span)
        tracked, anchor = resolve_current(v_code)
        cred = _first_above(tracked, MIN_CRED_OFFSET)
        record["getuid"] = {"name": name, "offset": offset, "span": span,
                            "anchor": anchor,
                            "disassembly": ["0x%x %s %s" % (i.address, i.mnemonic, i.op_str)
                                            for i in v_code]}
        record["cred"] = {
            "ok": cred is not None,
            "value": cred["offset"] if cred else None,
            "anchor": cred["insn"] if cred else None,
            "tracked": tracked,
        }
        if cred:
            candidates = candidate_offsets(v_code)
            uid = None
            if cred["offset"] in candidates:
                for value in candidates[candidates.index(cred["offset"]) + 1:]:
                    if value > 0x20 or value < record["uid_min_offset"]:
                        continue
                    uid = value
                    break
            record["cred_uid"] = {
                "ok": uid is not None,
                "value": uid,
                "candidates": ["0x%x" % value for value in candidates[:24]],
                "rule": "first candidate after cred_offset inside [%d, 0x20]"
                        % record["uid_min_offset"],
            }
        else:
            record["cred_uid"] = {"ok": False, "error": "no cred anchor"}

    # ---- seccomp_offset --------------------------------------------------- #
    name, offset = table.offset(*SECCOMP_NAMES)
    if not offset:
        record["seccomp"] = {"ok": False, "error": "prctl_get_seccomp missing"}
    else:
        span = table.span(offset)
        v_code = _disasm(image, offset, span)
        tracked, anchor = resolve_current(v_code)
        seccomp = _first_above(tracked, MIN_CRED_OFFSET)
        record["prctl"] = {"name": name, "offset": offset, "span": span, "anchor": anchor}
        record["seccomp"] = {
            "ok": seccomp is not None,
            "value": seccomp["offset"] if seccomp else None,
            "anchor": seccomp["insn"] if seccomp else None,
            "tracked": tracked,
        }
    return record


def struct_offsets(record: dict) -> dict | None:
    """`{cred, cred_uid, seccomp}` when all three resolved, else None."""
    if not (record["cred"].get("ok") and record["cred_uid"].get("ok")
            and record["seccomp"].get("ok")):
        return None
    return {"cred": record["cred"]["value"],
            "cred_uid": record["cred_uid"]["value"],
            "seccomp": record["seccomp"]["value"]}


def load_symbols(path: Path) -> dict:
    symbols = {}
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        if not line or line.startswith("#"):
            continue
        parts = line.split("\t")
        if len(parts) != 3:
            continue
        try:
            offset = int(parts[0])
        except ValueError:
            continue
        symbols.setdefault(parts[2], offset)
    return symbols


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--image", required=True)
    parser.add_argument("--symbols", required=True)
    parser.add_argument("--release", default=None)
    parser.add_argument("--out", default=None, help="write the resolution record here")
    args = parser.parse_args()

    image = Path(args.image).read_bytes()
    symbols = load_symbols(Path(args.symbols))
    release = args.release
    if not release:
        import build_ir_spec
        release = build_ir_spec.kernel_release(image)
    record = resolve(image, symbols, release)
    struct = struct_offsets(record)
    record["struct"] = struct
    print(json.dumps({"release": release, "struct": struct,
                      "cred": record["cred"].get("value"),
                      "cred_uid": record["cred_uid"].get("value"),
                      "seccomp": record["seccomp"].get("value")}, indent=2))
    if not struct:
        print("resolve_struct_offsets: unresolved task_struct offsets", file=sys.stderr)
        return 1
    if args.out:
        Path(args.out).write_text(json.dumps(record, indent=2, sort_keys=True) + "\n",
                                  encoding="utf-8", newline="\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
