#!/usr/bin/env python3
"""Derive the 12 vendor patch sites (and cave room) for an arbitrary kernel.

Why this exists
---------------
A profile (image-core/profiles/<version>.json) pins the patch offsets for one
kernel build.  When a new kernel arrives (another 6.6.x, another vendor build)
those offsets move, so they have to be *re-derived* and then confirmed by hand
before they are written into a profile.  This tool does the derivation; it
never patches anything.

How it locates a site
---------------------
1. instruction skeleton (primary).  For every site the profile carries a
   signature: the first N (12..20) instructions of the function with all
   PC-relative / immediate fields masked out (b/bl/b.cond/cbz/tbz/adr/adrp and
   the imm12 of add/sub/ldr/str/ldp/stp, imm16 of movz/movk).  The skeletons of
   these 12 functions are stable across 6.6.66 -> 6.6.89 (identical mnemonics,
   identical function sizes; only branch displacements differ), so a pack
   learned on one kernel finds the same functions in the next one.  A match
   must be unique; a non-unique match is reported with its alternatives and a
   lower confidence.
2. string anchors (secondary).  Each site lists the literals its function
   references ("%s: Fatal exception", "unused kernel", "[drm:%ps] %pV", ...).
   A candidate that also references one of them gets a confidence bump; a
   candidate that cannot see any anchor is flagged, not discarded (unused
   symbols legitimately have no strings).
3. optional symbol table (tertiary).  `--symbols tsv` (offset<TAB>type<TAB>name,
   as produced by the workspace kallsyms decoder) adds +0.10 when the named
   symbol sits exactly on the candidate.  The 6.6.89 GKI image has kallsyms, so
   this is usually available; it is never required.

Caves
-----
`--caves` reports the room available for relocating code: the four wholesale
replaceable vendor blocks (A/B/C/D), the in-body islands (C1/C2/cave_post),
plus every NOP/zero run >= 16 B and every unreachable window >= 16 B inside a
site's function.  Reachability is a linear sweep (fall-through + direct
branches); indirect jumps and computed calls are unknown by construction.

Usage
-----
    # locate on the 6.6.89 image and check against the profile (self-check)
    python image-core/tools/derive_sites.py --kernel <kernel.bin> --check

    # locate on a new kernel, human review, then learn a pack for a new profile
    python image-core/tools/derive_sites.py --kernel new/kernel.bin --caves --json out.json
    python image-core/tools/derive_sites.py --kernel ref6.6.66.bin --learn \
        --offset die=0x213e4 --offset arm64_notify_die=0x218d4 ... --json pack.json

Exit codes: 0 ok / self-check passed, 2 usage, 3 profile problem, 4 kernel
unreadable, 5 self-check failed.
"""

from __future__ import annotations

import argparse
import json
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import kernel_profile as kp  # noqa: E402

try:
    import capstone
except ImportError:  # pragma: no cover - the repo runtime always ships capstone
    capstone = None

REPO = Path(__file__).resolve().parents[2]
DEFAULT_PROFILE = REPO / "image-core" / "profiles" / "6.6.89.json"

TEXT_START = 0x10000        # _stext in this image layout
TEXT_END_DEFAULT = 0x10A0000
MIN_HOLE = 16               # bytes; the smallest island we have ever placed

EXIT_OK, EXIT_USAGE, EXIT_PROFILE, EXIT_KERNEL, EXIT_CHECK = range(5)


class DeriveError(Exception):
    def __init__(self, code: int, message: str):
        super().__init__(message)
        self.code = code


# ------------------------------------------------------------------- disassembly

def mask_for(mnemonic: str) -> int:
    """Mask of the bits that must match; 0xFFFFFFFF = compare the whole word."""
    if mnemonic in ("b", "bl"):
        return 0xFC000000
    if mnemonic.startswith("b.") and mnemonic not in ("bic", "bfi", "bfxil", "bl", "b"):
        return 0xFF00001F
    if mnemonic in ("cbz", "cbnz"):
        return 0xFF00001F
    if mnemonic in ("tbz", "tbnz"):
        return 0xFFF8001F
    if mnemonic in ("adr", "adrp"):
        return 0x9F00001F
    if mnemonic in ("add", "sub", "ldr", "str", "ldrb", "strb", "ldrh", "strh",
                    "ldrsw", "ldur", "stur", "ldp", "stp", "ldrsb", "ldrsh"):
        return 0xFFC003FF
    if mnemonic in ("movz", "movk", "movn"):
        return 0xFFE0001F
    return 0xFFFFFFFF


def disassembler() -> "capstone.Cs":
    if capstone is None:
        raise DeriveError(EXIT_KERNEL, "capstone is not installed; the workspace python runtime ships it")
    md = capstone.Cs(capstone.CS_ARCH_ARM64,
                     capstone.CS_MODE_ARM | capstone.CS_MODE_LITTLE_ENDIAN)
    md.detail = True
    return md


def signature_words(image: bytes, offset: int, count: int, md=None) -> tuple[list[str], list[str]]:
    md = md or disassembler()
    words, masks = [], []
    for insn in md.disasm(image[offset:offset + 4 * count], offset):
        word = int.from_bytes(insn.bytes, "little")
        mask = mask_for(insn.mnemonic)
        words.append(f"{word & mask:08x}")
        masks.append(f"{mask:08x}")
        if len(words) >= count:
            break
    return words, masks


# ------------------------------------------------------------------------- kernel

def load_kernel(path: Path) -> tuple[bytes, dict]:
    data = path.read_bytes()
    if data[:8] == b"ANDROID!" and len(data) > 4096:
        # a boot image: analyse the kernel it carries, report kernel-relative offsets
        header = kp.parse_boot_header(data)
        kernel = kp.extract_kernel(data, header["kernel_offset"], header["kernel_size"])
        return kernel, {"kind": "boot-image", "bytes": len(kernel),
                        "boot_bytes": len(data), "boot_sha256": kp.sha256_bytes(data),
                        "kernel_offset": header["kernel_offset"],
                        "text_base": 0, "sha256": kp.sha256_bytes(kernel)}
    if data[:4] == b"\x7fELF":
        try:
            from elftools.elf.elffile import ELFFile  # type: ignore
        except ImportError as error:  # pragma: no cover
            raise DeriveError(EXIT_KERNEL,
                              "ELF input needs pyelftools; pass the raw Image instead") from error
        with open(path, "rb") as handle:
            elf = ELFFile(handle)
            loads = [seg for seg in elf.iter_segments() if seg["p_type"] == "PT_LOAD"]
            if not loads:
                raise DeriveError(EXIT_KERNEL, "ELF has no PT_LOAD segments")
            base = min(seg["p_vaddr"] for seg in loads)
            end = max(seg["p_vaddr"] + seg["p_filesz"] for seg in loads)
            image = bytearray(end - base)
            for seg in loads:
                start = seg["p_vaddr"] - base
                image[start:start + seg["p_filesz"]] = seg.data()
        return bytes(image), {"kind": "elf", "bytes": len(image), "text_base": base,
                               "sha256": kp.sha256_bytes(bytes(image))}
    return data, {"kind": "image", "bytes": len(data), "text_base": 0,
                  "sha256": kp.sha256_bytes(data)}


def region_bytes(image: bytes, start: int, size: int) -> bytes:
    if start < 0 or size <= 0 or start + size > len(image):
        return b""
    return image[start:start + size]


# ---------------------------------------------------------------- string anchors

def find_string_offsets(image: bytes, text: str, limit: int = 4) -> list[int]:
    needle = text.encode("utf-8", "replace")
    out, at = [], 0
    while len(out) < limit:
        found = image.find(needle, at)
        if found < 0:
            break
        out.append(found)
        at = found + 1
    return out


def string_refs_in(image: bytes, start: int, size: int, targets: list[int]) -> list[dict]:
    """adrp+add/ldr pairs inside [start, start+size) that compute a target address."""
    if not targets:
        return []
    md = disassembler()
    wanted = set(targets)
    pages = {target & ~0xFFF for target in targets}
    adrp: dict[int, int] = {}
    hits = []
    for insn in md.disasm(region_bytes(image, start, size), start):
        mnemonic = insn.mnemonic
        operands = insn.operands
        if mnemonic == "adrp" and operands:
            adrp[operands[0].reg] = operands[1].imm
            continue
        if mnemonic == "add" and len(operands) >= 3:
            dst, src, imm = operands[0], operands[1], operands[2]
            if src.type == capstone.arm64.ARM64_OP_REG and src.reg in adrp and                     imm.type == capstone.arm64.ARM64_OP_IMM:
                address = adrp[src.reg] + imm.imm
                if address in wanted:
                    hits.append({"at": insn.address, "target": address})
            continue
        if mnemonic in ("ldr", "ldrb", "ldrh", "ldrsb", "ldrsh", "ldrsw",
                        "str", "strb", "strh", "stur", "ldur") and operands:
            mem = operands[-1]
            if mem.type == capstone.arm64.ARM64_OP_MEM and mem.mem.base in adrp:
                page = adrp[mem.mem.base]
                if page in pages:
                    address = page + mem.mem.disp
                    if address in wanted:
                        hits.append({"at": insn.address, "target": address})
            continue
        if mnemonic == "add" and len(operands) >= 3:
            dst, src, imm = operands[0], operands[1], operands[2]
            if src.type == capstone.arm64.ARM64_OP_REG and src.reg in adrp and \
                    imm.type == capstone.arm64.ARM64_OP_IMM:
                address = adrp[src.reg] + imm.imm
                if address in wanted:
                    hits.append({"at": insn.address, "target": address})
    return hits


# ------------------------------------------------------------------- site location

def scan_pack(image: bytes, pack: dict) -> list[dict]:
    """Run every site signature over the image.  Returns one result per site."""
    try:
        import numpy as np
    except ImportError:  # pragma: no cover
        np = None
    if np is not None:
        words_array = np.frombuffer(image[:len(image) // 4 * 4], dtype="<u4")
    results = []
    for site in pack["sites"]:
        signature = site["signature"]
        words = [int(word, 16) for word in signature["words"]]
        masks = [int(mask, 16) for mask in signature["masks"]]
        count = len(words)
        hits = []
        if np is not None:
            limit = len(words_array) - count + 1
            positions = np.nonzero((words_array[:limit] & np.uint32(masks[0]))
                                   == np.uint32(words[0]))[0]
            for index in range(1, count):
                if positions.size == 0:
                    break
                positions = positions[(words_array[positions + index] & np.uint32(masks[index]))
                                      == np.uint32(words[index])]
            hits = [int(position) * 4 for position in positions]
        else:
            for offset in range(0, len(image) - 4 * count, 4):
                if all(int.from_bytes(image[offset + 4 * i:offset + 4 * i + 4], "little")
                       & masks[i] == words[i] for i in range(count)):
                    hits.append(offset)
        results.append({"site": site, "hits": hits})
    return results


def score(image: bytes, site: dict, hits: list[int], symbols: dict[str, int] | None) -> dict:
    evidence = []
    confidence = 0.0
    if not hits:
        return {"candidate": None, "confidence": 0.0, "hits": 0,
                "evidence": ["no skeleton match"]}
    if len(hits) == 1:
        confidence += 0.75
        evidence.append("skeleton match is unique")
    else:
        confidence += 0.45
        evidence.append(f"skeleton match is not unique ({len(hits)} hits)")

    candidate = hits[0]
    host_size = int(site.get("function_size") or max(int(site["length"]), 64))
    anchors = site.get("anchor_strings") or []
    if anchors:
        targets = []
        for text in anchors:
            targets.extend(find_string_offsets(image, text))
        refs = string_refs_in(image, candidate, host_size, targets)
        if refs:
            confidence += 0.10
            evidence.append(f"references {len({ref['target'] for ref in refs})} anchor string(s)")
            if len(hits) > 1:
                # prefer a hit that both matches the skeleton and sees an anchor
                for hit in hits[1:]:
                    other = string_refs_in(image, hit, host_size, targets)
                    if other:
                        candidate = hit
                        evidence.append("anchor string disambiguated the hit")
                        break
        else:
            evidence.append("no anchor string reference in this function (allowed)")

    if symbols:
        name = site["symbol"].split("+")[0]
        if symbols.get(name) == candidate:
            confidence += 0.10
            evidence.append("symbol table agrees")
        elif name in symbols:
            evidence.append(f"symbol table says {symbols[name]:#x} (disagrees)")

    expected_digest = site.get("orig_sha256")
    if expected_digest:
        block = region_bytes(image, candidate, int(site["length"]))
        if block and kp.sha256_bytes(block) == expected_digest:
            confidence += 0.10
            evidence.append("original block bytes match the profile digest")

    return {"candidate": candidate, "confidence": round(min(confidence, 0.99), 2),
            "hits": len(hits), "alternatives": hits[1:6], "evidence": evidence}


def locate(image: bytes, pack: dict, symbols: dict[str, int] | None) -> list[dict]:
    out = []
    for item in scan_pack(image, pack):
        site = item["site"]
        scored = score(image, site, item["hits"], symbols)
        scored.update({
            "slot": site["slot"],
            "symbol": site["symbol"],
            "expected": site["offset"],
            "length": site["length"],
            "function_size": site.get("function_size"),
        })
        out.append(scored)
    return out


# --------------------------------------------------------------------- cave scan

def reachable_map(image: bytes, start: int, size: int) -> dict[int, bool]:
    md = disassembler()
    instructions = list(md.disasm(region_bytes(image, start, size), start))
    reachable: dict[int, bool] = {start: True}
    for index, insn in enumerate(instructions):
        at = insn.address
        if not reachable.get(at):
            continue
        next_at = at + insn.size
        mnemonic = insn.mnemonic
        target = None
        if mnemonic in ("b", "bl") or (mnemonic.startswith("b.") and mnemonic not in
                                       ("bic", "bfi", "bfxil")):
            operand = insn.operands[0] if insn.operands else None
            if operand is not None and operand.type == capstone.arm64.ARM64_OP_IMM:
                target = operand.imm
        elif mnemonic in ("cbz", "cbnz", "tbz", "tbnz"):
            operand = insn.operands[-1] if insn.operands else None
            if operand is not None and operand.type == capstone.arm64.ARM64_OP_IMM:
                target = operand.imm
        if target is not None and start <= target < start + size:
            reachable[target] = True
        terminal = mnemonic == "b" or mnemonic in ("ret", "br", "eret") or mnemonic.startswith("br")
        if not terminal and next_at < start + size:
            reachable[next_at] = True
    return reachable


def dead_windows(image: bytes, start: int, size: int) -> list[tuple[int, int]]:
    reachable = reachable_map(image, start, size)
    windows, run_start = [], None
    for offset in range(start, start + size, 4):
        dead = not reachable.get(offset, False)
        if dead and run_start is None:
            run_start = offset
        elif not dead and run_start is not None:
            if offset - run_start >= MIN_HOLE:
                windows.append((run_start, offset - run_start))
            run_start = None
    if run_start is not None and start + size - run_start >= MIN_HOLE:
        windows.append((run_start, start + size - run_start))
    return windows


def padding_runs(image: bytes, start: int, end: int) -> list[dict]:
    runs = []
    for pattern, label in ((b"\x1f\x20\x03\xd5" * 4, "nop"), (b"\x00\x00\x00\x00" * 4, "zero")):
        at = start
        while at < end:
            found = image.find(pattern, at, end)
            if found < 0:
                break
            at = found
            end_at = at
            while end_at + 4 <= end and image[end_at:end_at + 4] == pattern[:4]:
                end_at += 4
            runs.append({"kind": label, "offset": at, "length": end_at - at})
            at = end_at
    return sorted(runs, key=lambda item: item["offset"])


def cave_report(image: bytes, pack: dict, located: list[dict]) -> dict:
    sites = {item["slot"]: item for item in located}
    blocks = []
    holes: list[dict] = []
    for site in pack["sites"]:
        candidate = sites.get(site["slot"], {}).get("candidate")
        if candidate is None:
            continue
        host_size = int(site.get("function_size") or site["length"])
        block = {
            "slot": site["slot"],
            "symbol": site["symbol"],
            "offset": candidate,
            "block_bytes": int(site["length"]),
            "function_bytes": host_size,
            "tail_bytes": host_size - int(site["length"]),
            "dead_windows": [{"offset": start, "length": length}
                             for start, length in dead_windows(image, candidate, host_size)],
        }
        blocks.append(block)
        holes.extend({"kind": "dead", "host": site["symbol"],
                      "offset": window["offset"], "length": window["length"]}
                     for window in block["dead_windows"])
    padding = [hole for hole in padding_runs(image, TEXT_START, min(len(image), TEXT_END_DEFAULT))
               if hole["length"] >= MIN_HOLE]
    declared = []
    for name, cave in pack.get("caves", {}).items():
        if "offset" not in cave:
            continue
        inside_block = next((block for block in blocks
                             if block["offset"] <= cave["offset"]
                             < block["offset"] + block["function_bytes"]), None)
        block_start = inside_block["offset"] if inside_block else None
        block_end = block_start + inside_block["block_bytes"] if inside_block else None
        host_end = block_start + inside_block["function_bytes"] if inside_block else None
        is_block = block_start is not None and cave["offset"] == block_start
        declared.append({
            "name": name,
            "offset": cave["offset"],
            "length": cave["length"],
            "host": cave.get("host"),
            "host_matched": inside_block["symbol"] if inside_block else None,
            "block_capacity": inside_block["block_bytes"] if inside_block else None,
            "kind": "block" if is_block else "tail",
            "relative_to_block": cave["offset"] - block_start if block_start is not None else None,
            "room_fits": bool(
                inside_block and (
                    (is_block and cave["length"] <= inside_block["block_bytes"])
                    or (not is_block and cave["offset"] >= block_end
                        and cave["offset"] + cave["length"] <= host_end))),
            "in_dead_window": any(hole["offset"] <= cave["offset"] < hole["offset"] + hole["length"]
                                  for hole in holes),
        })
    return {"text_range": [TEXT_START, min(len(image), TEXT_END_DEFAULT)],
            "blocks": blocks, "dead_windows": holes, "padding_runs": padding,
            "declared_caves": declared}


# ------------------------------------------------------------------------- report

def print_locations(located: list[dict]) -> None:
    print(f"{'slot':>4} {'symbol':<26} {'expected':>10} {'candidate':>10} {'hits':>4} "
          f"{'conf':>5}  evidence")
    for item in located:
        candidate = f"{item['candidate']:#010x}" if item["candidate"] is not None else "-"
        print(f"{item['slot']:>4} {item['symbol']:<26} {item['expected']:#010x} {candidate:>10} "
              f"{item['hits']:>4} {item['confidence']:>5.2f}  {'; '.join(item['evidence'])}")


def check(located: list[dict], profile: dict, expect: dict[int, int] | None) -> int:
    problems = 0
    print()
    print(f"{'slot':>4} {'symbol':<26} {'expected':>10} {'candidate':>10} verdict")
    for item in located:
        wanted = item["expected"]
        if expect is not None:
            wanted = expect.get(item["slot"], wanted)
        ok = item["candidate"] == wanted
        problems += not ok
        print(f"{item['slot']:>4} {item['symbol']:<26} {wanted:#010x} "
              f"{(item['candidate'] or 0):#010x} {'OK' if ok else 'MISMATCH'}")
    total = len(located)
    print(f"\ncoverage: {total - problems}/{total} sites located at the expected offset")
    return EXIT_OK if not problems else EXIT_CHECK


# --------------------------------------------------------------------------- main

def load_symbols(path: str | None) -> dict[str, int] | None:
    if not path:
        return None
    symbols = {}
    for line in Path(path).read_text(encoding="utf-8", errors="replace").splitlines():
        if not line or line.startswith("#"):
            continue
        parts = line.split("\t")
        if len(parts) < 3:
            continue
        try:
            offset = int(parts[0], 0)
        except ValueError:
            continue
        symbols.setdefault(parts[2].strip(), offset)
    return symbols or None


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(
        description="Derive the 12 vendor patch sites and cave room for a kernel image.",
        formatter_class=argparse.RawDescriptionHelpFormatter, epilog=__doc__)
    parser.add_argument("--kernel", required=True, help="target kernel (raw Image or ELF vmlinux)")
    parser.add_argument("--profile", default=str(DEFAULT_PROFILE),
                        help="profile that carries the signature pack / expected sites")
    parser.add_argument("--check", action="store_true",
                        help="compare the candidates with the profile's expected offsets")
    parser.add_argument("--expect", action="append", default=[],
                        metavar="SYM=0xOFF",
                        help="expected offset for a symbol (repeatable; overrides the profile)")
    parser.add_argument("--caves", action="store_true", help="report cave room")
    parser.add_argument("--symbols", help="optional TSV: offset<TAB>type<TAB>name")
    parser.add_argument("--json", help="write the full result as JSON")
    parser.add_argument("--learn", action="store_true",
                        help="build a signature pack from --kernel and the offsets given by --offset")
    parser.add_argument("--offset", action="append", default=[], metavar="SYM=0xOFF",
                        help="known site offset for --learn (repeatable)")
    args = parser.parse_args(argv)

    try:
        profile = kp.load(Path(args.profile).resolve())
    except kp.ProfileError as error:
        raise DeriveError(EXIT_PROFILE, f"profile: {error}")

    kernel_path = Path(args.kernel).resolve()
    if not kernel_path.is_file():
        raise DeriveError(EXIT_KERNEL, f"kernel not found: {kernel_path}")
    image, meta = load_kernel(kernel_path)
    symbols = load_symbols(args.symbols)

    print(f"kernel    {kernel_path}")
    print(f"          {meta['kind']}  {meta['bytes']:,} B  sha256 {meta['sha256']}")
    print(f"profile   {Path(args.profile).resolve()}  ({len(profile['sites'])} signatures)")

    if args.learn:
        return learn(args, profile, image, meta)

    located = locate(image, profile, symbols)
    print_locations(located)

    result = {
        "tool": "image-core/tools/derive_sites.py",
        "kernel": {"path": str(kernel_path), **meta},
        "profile": {"path": str(Path(args.profile).resolve()), "profile_id": profile.get("profile_id")},
        "sites": [{key: value for key, value in item.items() if key != "site"} for item in located],
    }
    if args.caves:
        caves = cave_report(image, profile, located)
        result["caves"] = caves
        print("\ncave blocks (wholesale replaceable vendor functions)")
        for block in caves["blocks"]:
            dead = ", ".join(f"{hole['offset']:#x}+{hole['length']}" for hole in block["dead_windows"]) or "-"
            print(f"  {block['symbol']:<26} {block['offset']:#010x} block {block['block_bytes']:>3} B "
                  f"of {block['function_bytes']:>3} B (tail {block['tail_bytes']:>3} B) dead={dead}")
        print(f"\ndead windows >= {MIN_HOLE} B: {len(caves['dead_windows'])}  "
              f"padding runs >= {MIN_HOLE} B: {len(caves['padding_runs'])}")
        for cave in caves["declared_caves"]:
            print(f"  declared {cave['name']:<9} {cave['offset']:#010x} {cave['length']:>3} B  "
                  f"host={str(cave['host']):<26} block={cave['block_capacity']}  "
                  f"rel={cave['relative_to_block']}  kind={cave['kind']}  "
                  f"room_fits={cave['room_fits']}  "
                  f"dead_window={cave['in_dead_window']}")
    if args.json:
        Path(args.json).write_text(json.dumps(result, indent=1) + "\n", encoding="utf-8")
        print(f"\njson      {args.json}")

    if args.check:
        expect = None
        if args.expect:
            expect = parse_offsets(args.expect, profile)
        elif meta["sha256"] == profile["kernel_version"]["kernel_sha256"]:
            expect = {site["slot"]: site["offset"] for site in profile["sites"]}
        else:
            print("\nnote: target kernel is not the profile's kernel; --check needs --expect "
                  "or a matching kernel sha256")
            return EXIT_CHECK
        return check(located, profile, expect)
    return EXIT_OK


def parse_offsets(items: list[str], profile: dict) -> dict[int, int]:
    by_symbol = {}
    for item in items:
        name, _, value = item.partition("=")
        by_symbol[name.strip()] = int(value, 0)
    expect = {}
    for site in profile["sites"]:
        if site["symbol"] in by_symbol:
            expect[site["slot"]] = by_symbol[site["symbol"]]
    missing = set(by_symbol) - {site["symbol"] for site in profile["sites"]}
    if missing:
        raise DeriveError(EXIT_USAGE, f"--expect: unknown symbol(s): {', '.join(sorted(missing))}")
    return expect


def learn(args, profile: dict, image: bytes, meta: dict) -> int:
    if not args.offset:
        raise DeriveError(EXIT_USAGE, "--learn needs at least one --offset SYM=0xOFF")
    offsets = {}
    for item in args.offset:
        name, _, value = item.partition("=")
        offsets[name.strip()] = int(value, 0)
    pack = {"schema": "maplesu.kernel-signature-pack/1",
            "source_kernel": {"path": str(args.kernel), **meta},
            "instructions": None, "sites": []}
    md = disassembler()
    for site in profile["sites"]:
        symbol = site["symbol"]
        if symbol not in offsets:
            raise DeriveError(EXIT_USAGE, f"--learn: no --offset for {symbol}")
        count = int(site["signature"]["instructions"])
        words, masks = signature_words(image, offsets[symbol], count, md)
        if len(words) < count:
            raise DeriveError(EXIT_KERNEL, f"{symbol}: only {len(words)} instructions decoded")
        entry = dict(site)
        entry["offset"] = offsets[symbol]
        entry["signature"] = {
            "learned_from": {"kernel": meta["kind"], "kernel_sha256": meta["sha256"],
                             "offset": offsets[symbol]},
            "instructions": len(words), "words": words, "masks": masks,
        }
        pack["sites"].append(entry)
    pack["instructions"] = max(site["signature"]["instructions"] for site in pack["sites"])
    pack["note"] = ("generated by derive_sites.py --learn; paste into a profile's sites[] "
                    "after reviewing the candidates")
    if args.json:
        Path(args.json).write_text(json.dumps(pack, indent=1) + "\n", encoding="utf-8")
        print(f"learned {len(pack['sites'])} signatures -> {args.json}")
    else:
        print(json.dumps(pack, indent=1))
    return EXIT_OK


if __name__ == "__main__":
    try:
        sys.exit(main(sys.argv[1:]))
    except DeriveError as error:
        print(f"ERROR: {error}", file=sys.stderr)
        sys.exit(error.code)
