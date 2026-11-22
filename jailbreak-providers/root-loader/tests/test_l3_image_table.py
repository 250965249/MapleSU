#!/usr/bin/env python3
"""Independent host check of this image's syscall table, syscall wrappers and
`prepare_kernel_cred` -- the image facts L3's design rests on.

What this proves, and why it does not import the builder
-------------------------------------------------------
The L3 module hard-codes no index and no address: build_root_module.py measures
every fact it needs from the image and injects it. Those statements are still all
"the builder". This script is the third, independent one: it re-reads the symbols
file and the image with ~60 lines of `struct.unpack`, derives KIMAGE_BASE from the
syscall pairs the controller recorded, and requires the prctl slot to be the
unique table entry that holds `__arm64_sys_prctl`'s address. If it disagrees with
the builder, one of them is wrong and the acceptance has to stop.

The table is *read*, never written, and that is the point of the check: the L3
mechanism moved from "replace `sys_call_table[167]`" to "a kprobe on
`__arm64_sys_prctl`" because this table is plain kernel-image `.rodata` and the
page-permission helpers refuse a kernel-image address (-EINVAL from
`change_memory_common` -> `find_vm_area`). The table layout below is therefore the
*reason* the design is a kprobe; the module touches none of it.

What it checks
--------------
  1. KIMAGE_BASE from five (index, symbol) pairs -- 63 read, 64 write, 155
     getpgid, 167 prctl, 221 execve -- all the same value;
  2. `sys_call_table[167]` is the *only* slot in the first 512 that holds
     `__arm64_sys_prctl`'s address, and that address is `base + offset`;
  3. the 4 bytes in front of every `__arm64_sys_*` checked are the same KCFI type
     id and the entry is paciasp -- these are syscall wrappers called through a
     checked indirect call, which is what makes the body's `[x0]` load a pt_regs
     pointer (the fact the kprobe callback depends on);
  4. `sys_call_table`'s file offset is inside `[__start_rodata, __end_rodata)`,
     i.e. the image maps it read-only and no module can store into it without
     writing a kernel-image page;
  5. the image's `prepare_kernel_cred` rejects a NULL daemon with a WARN
     (kernel/cred.c:637 in the image's own __bug_table), which is why the module
     is built with MAPLESU_CRED_SOURCE=1 (&init_task).

Host-side only: no device, no adb, no module load. Exit status is non-zero when
any number disagrees.

Run:
  python jailbreak-providers/root-loader/tests/test_l3_image_table.py
  python -m unittest discover -s jailbreak-providers/root-loader/tests -p "test_l3_*.py"
"""
from __future__ import annotations

import json
import struct
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
ROOT_LOADER = ROOT / "jailbreak-providers" / "root-loader"
CONTRACTS = sorted((ROOT_LOADER / "contracts").glob("6.6.89-*.json"))
CONTRACT = CONTRACTS[0] if CONTRACTS else ROOT_LOADER / "contracts" / "missing.json"

# The controller's recorded pairs (the kprobe ABI's syscall entry). Stated here
# independently of the builder's L3_TABLE_CROSSCHECK on purpose: two statements,
# not one.
PAIRS = ((63, "__arm64_sys_read"), (64, "__arm64_sys_write"),
         (155, "__arm64_sys_getpgid"),
         (167, "__arm64_sys_prctl"), (221, "__arm64_sys_execve"))
PRCTL_INDEX = 167
PREFIX_ID = 0xB02B34D9
PACIASP = 0xD503233F
SCAN_SLOTS = 512
BUGFLAG_WARNING = 0x1


def _symbols(path: Path) -> dict:
    """name -> first offset, from the kallsyms TSV (`offset<TAB>type<TAB>name`)."""
    rows: dict = {}
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        parts = line.rstrip("\r\n").split("\t")
        if len(parts) != 3 or parts[0].startswith("#"):
            continue
        try:
            address = int(parts[0])
        except ValueError:
            continue
        rows.setdefault(parts[2], address)
    return rows


def _warnings(image: bytes, symbols: dict) -> dict:
    """brk address -> (file, line, flags) for every warning-flagged bug entry."""
    start, stop = symbols.get("__start___bug_table"), symbols.get("__stop___bug_table")
    out = {}
    if start is None or stop is None:
        return out
    for offset in range(start, stop - 11, 12):
        disp, file_disp, line, flags = struct.unpack_from("<iiHH", image, offset)
        if not flags & BUGFLAG_WARNING:
            continue
        at = offset + 4 + file_disp
        end = image.find(b"\x00", at) if 0 < at < len(image) else -1
        name = image[at:end].decode("ascii", "replace") if end > at else ""
        out.setdefault(offset + disp, (name, line, flags))
    return out


def check() -> dict:
    contract = json.loads(CONTRACT.read_text(encoding="utf-8"))
    image = (ROOT / contract["imagePath"]).read_bytes()
    symbols = _symbols(ROOT / contract["symbolsPath"])
    problems: list = []

    def need(condition: bool, message: str) -> None:
        if not condition:
            problems.append(message)

    table = symbols.get("sys_call_table")
    need(table is not None, "symbols carry no sys_call_table")
    table = table or 0
    need(table + 8 * SCAN_SLOTS <= len(image),
         "sys_call_table 0x%x runs past the image" % table)

    rows = []
    bases = {}
    for index, name in PAIRS:
        offset = symbols.get(name)
        need(offset is not None, "symbols carry no %s" % name)
        if offset is None:
            continue
        slot = struct.unpack_from("<Q", image, table + index * 8)[0]
        base = slot - offset
        bases[index] = base
        rows.append({"index": index, "symbol": name, "offset": offset,
                     "slot": slot, "base": base, "target": base + offset})
    distinct = sorted(set(bases.values()))
    need(len(distinct) == 1,
         "the pairs disagree on KIMAGE_BASE: %s"
         % {index: "0x%x" % value for index, value in bases.items()})
    base = distinct[0] if len(distinct) == 1 else None
    for row in rows:
        need(row["slot"] == row["target"],
             "sys_call_table[%d] 0x%x != base+0x%x" % (row["index"], row["slot"],
                                                       row["offset"]))

    prctl_offset = symbols.get("__arm64_sys_prctl")
    need(prctl_offset is not None, "symbols carry no __arm64_sys_prctl")
    prctl_offset = prctl_offset or 0
    matches = [index for index in range(SCAN_SLOTS)
               if struct.unpack_from("<Q", image, table + index * 8)[0]
               == (base or 0) + prctl_offset]
    need(matches == [PRCTL_INDEX],
         "the unique slot for __arm64_sys_prctl is %s, not [%d]"
         % (matches, PRCTL_INDEX))

    prefixes = {}
    for _index, name in PAIRS:
        offset = symbols.get(name) or 0
        prefixes[name] = (struct.unpack_from("<I", image, offset - 4)[0],
                          struct.unpack_from("<I", image, offset)[0])
    for name, (prefix, entry) in prefixes.items():
        need(prefix == PREFIX_ID,
             "%s carries KCFI prefix 0x%08x, expected 0x%08x"
             % (name, prefix, PREFIX_ID))
        need(entry == PACIASP, "%s does not start with paciasp (0x%08x)"
             % (name, entry))

    rodata_start = symbols.get("__start_rodata")
    rodata_stop = symbols.get("__end_rodata")
    in_rodata = None
    if rodata_start is not None and rodata_stop is not None:
        in_rodata = rodata_start <= table < rodata_stop
        need(in_rodata, "sys_call_table 0x%x is not inside [0x%x, 0x%x)"
             % (table, rodata_start, rodata_stop))

    prepare = symbols.get("prepare_kernel_cred") or 0
    warning = None
    for index in range(16):
        site = prepare + index * 4
        word = struct.unpack_from("<I", image, site)[0]
        if (word & 0xFF000000) != 0xB4000000 or (word & 0x1F) != 0:
            continue                    # not `cbz x0, ...`
        immediate = (word >> 5) & 0x7FFFF
        if immediate & 0x40000:
            immediate -= 0x80000
        target = site + immediate * 4
        block = [struct.unpack_from("<I", image, target + step * 4)[0]
                 for step in range(8)]
        if not any((item & 0xFFFFFFE0) == 0xAA1F03E0 for item in block):
            continue                    # no `mov xN, xzr` in the NULL path
        for step, item in enumerate(block):
            if (item & 0xFFE0001F) == 0xD4200000 and ((item >> 5) & 0xFFFF) == 0x800:
                warning = (target + step * 4, site, target)
                break
        if warning:
            break
    need(warning is not None,
         "prepare_kernel_cred has no NULL-rejecting warn branch (the cred source "
         "decision has to be re-derived)")
    warn_detail = None
    if warning:
        brk, site, target = warning
        warn_detail = _warnings(image, symbols).get(brk)
        need(warn_detail is not None,
             "the brk at 0x%x is not a BUGFLAG_WARNING entry" % brk)
        need(warn_detail is not None and warn_detail[0].endswith("cred.c"),
             "the NULL path warns in %r, not kernel/cred.c"
             % (warn_detail[0] if warn_detail else None))

    return {
        "contract": str(CONTRACT.relative_to(ROOT)),
        "image": contract["imagePath"],
        "imageSha256": contract["imageSha256"],
        "kernelImageBase": "0x%x" % base if base is not None else None,
        "sysCallTable": "0x%x" % table,
        "inRoData": in_rodata,
        "rodata": ["0x%x" % (rodata_start or 0), "0x%x" % (rodata_stop or 0)],
        "rows": rows,
        "prctlIndex": PRCTL_INDEX,
        "matches": matches,
        "prefix": "0x%08x" % PREFIX_ID,
        "prefixes": {name: "0x%08x/0x%08x" % value
                     for name, value in prefixes.items()},
        "credSource": {"source": 1 if warning else 0,
                       "nullBranch": ({"brk": "0x%x" % warning[0],
                                       "site": "0x%x" % warning[1],
                                       "target": "0x%x" % warning[2],
                                       "file": warn_detail[0] if warn_detail else None,
                                       "line": warn_detail[1] if warn_detail else None,
                                       "flags": "0x%x" % warn_detail[2]
                                       if warn_detail else None}
                                      if warning else None)},
        "problems": problems,
    }


def report_text(result: dict) -> str:
    lines = ["L3 image table cross-check (independent of build_root_module.py)",
             "  contract   %s" % result["contract"],
             "  image      %s" % result["image"],
             "  imageSha256 %s" % result["imageSha256"],
             "  KIMAGE_BASE %s (five pairs, %s)"
             % (result["kernelImageBase"],
                "all agree" if result["kernelImageBase"] else "DISAGREE"),
             "  sys_call_table file offset %s, in [%s, %s): %s"
             % (result["sysCallTable"], result["rodata"][0], result["rodata"][1],
                result["inRoData"]),
             "  idx  slot                 base+offset          symbol"]
    for row in result["rows"]:
        lines.append("  [%3d] 0x%016x 0x%016x  %s"
                     % (row["index"], row["slot"], row["target"], row["symbol"]))
    lines.append("  unique slot holding __arm64_sys_prctl: %s (expected [%d])"
                 % (result["matches"], result["prctlIndex"]))
    lines.append("  KCFI prefix of every __arm64_sys_*: %s" % result["prefix"])
    for name, value in result["prefixes"].items():
        lines.append("    %-24s prefix/entry = %s" % (name, value))
    source = result["credSource"]
    if source["nullBranch"]:
        branch = source["nullBranch"]
        lines.append("  prepare_kernel_cred(NULL): WARN + NULL (%s:%s, brk %s)"
                     % (branch["file"], branch["line"], branch["brk"]))
        lines.append("  => MAPLESU_CRED_SOURCE=1 (&init_task)")
    else:
        lines.append("  prepare_kernel_cred(NULL): accepted => MAPLESU_CRED_SOURCE=0")
    lines.append("  RESULT: %s" % ("PASS" if not result["problems"] else "FAIL"))
    for problem in result["problems"]:
        lines.append("    FAIL %s" % problem)
    return "\n".join(lines)


class ImageTableTest(unittest.TestCase):
    """The same statements as assertions, so a regression cannot be a printout."""

    @classmethod
    def setUpClass(cls):
        cls.result = check()

    def test_01_no_problem(self):
        self.assertEqual([], self.result["problems"])

    def test_02_five_pairs_agree_on_one_base(self):
        bases = {row["base"] for row in self.result["rows"]}
        self.assertEqual(1, len(bases), bases)
        self.assertEqual(self.result["rows"][0]["base"],
                         int(self.result["kernelImageBase"], 16))

    def test_03_table_layout_is_the_recorded_one(self):
        for row in self.result["rows"]:
            self.assertEqual(row["target"], row["slot"],
                             "slot %d does not hold base+offset" % row["index"])

    def test_04_prctl_slot_is_unique_at_167(self):
        self.assertEqual([167], self.result["matches"])

    def test_05_every_syscall_carries_the_same_prefix(self):
        for name, value in self.result["prefixes"].items():
            prefix, entry = (int(part, 16) for part in value.split("/"))
            self.assertEqual(0xB02B34D9, prefix, name)
            self.assertEqual(0xD503233F, entry, name)

    def test_06_table_is_plain_rodata(self):
        self.assertTrue(self.result["inRoData"])

    def test_07_cred_source_is_init_task(self):
        self.assertEqual(1, self.result["credSource"]["source"])
        self.assertEqual("kernel/cred.c",
                         self.result["credSource"]["nullBranch"]["file"])


def main(argv: list | None = None) -> int:
    result = check()
    print(report_text(result))
    if argv is None:
        argv = sys.argv[1:]
    if argv and argv[0] == "--json":
        Path(argv[1]).write_text(json.dumps(result, indent=1) + "\n",
                                 encoding="utf-8")
        print("wrote %s" % argv[1])
    return 0 if not result["problems"] else 1


if __name__ == "__main__":
    sys.exit(main())
