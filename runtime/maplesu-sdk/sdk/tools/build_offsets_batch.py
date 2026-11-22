#!/usr/bin/env python3
"""Batch compile + T/U symbol-set gate for the kernel_offsets group.

What this tool is
-----------------
One command rebuilds the 23 members of the frozen ``kernel_offsets`` group
(frozen-archive ordinals 0..22, the block that precedes the first
``module_base_*`` member) from ``sdk/src/kernel_offsets/*.cpp`` and reports, per
member, three gate columns:

    raw                both-direction diff of the T set and the U set, untouched
    baseline-adjusted  the same diff after removing the entries that the central
                       allowance file ``sdk/notes/gate-symbol-baseline.json``
                       declares, plus how many of those entries were actually
                       consumed by this member
    verdict            PASS only when the adjusted T and U diffs are empty

    T set   strong external definitions   (llvm-nm kinds T D B R A G S C)
    U set   strong imports                (llvm-nm kind U)

The raw column is never hidden: the tool always prints it, and writes both
columns into the machine-readable table. ``--exit-on-diff`` turns a non-empty
*adjusted* diff into exit code 7 so the tool can gate a pipeline.

Why the same *layout* is built as the frozen member
--------------------------------------------------
22 of the 23 members are LLVM bitcode (``llvm-ar p`` body starts with 42 43 c0
de) and one (``task_struct.o``) is a native AArch64 ELF relocatable object. A
bitcode container also lists symbols that are only *referenced* from
``available_externally`` inline bodies; a native object cannot, because codegen
drops those bodies. Comparing a .bc reference against a .o rebuild therefore
reports differences that no source change can fix. The tool builds each member
in the container the frozen member actually uses (bitcode -> ``-emit-llvm -c``,
elf -> ``-c``). Flag recipes come from ``tools/sdk_common.py``
(``FLAG_PROFILES``), never from this file.

Provenance
----------
* reference (residual): ``libkernel_module_kit_static.a`` of the frozen snapshot, read
  through ``sdk_common.load_frozen`` (archive sha256 is verified there).
* rebuild:   ``clang++`` from the pinned NDK, the ``core-oz-*`` recipe that the
  member's own IR proves (exceptions on), plus ``-D_FORTIFY_SOURCE=2``.
* symbols:   ``llvm-nm`` from the same NDK, parsed by
  ``sdk_common.parse_nm_output`` (so the T/U split matches every other tool in
  this SDK).

Outputs
-------
``build/offsets/<member>.<bc|o>``   rebuilt artifacts
``build/offsets/_ref/<member>``     frozen member bodies (read-only copies)
``build/offsets/selfcheck.json``    the table, machine readable
stdout                              the table, one row per member

Exit codes
----------
0  table produced (no gate) / gate clean
7  --exit-on-diff and at least one member has a non-empty adjusted T/U diff
   (or is missing a source / failed to compile)
3  the frozen archive / census / allowance file could not be loaded
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass, field
from pathlib import Path

SDK = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SDK / "tools"))

import sdk_common as S  # noqa: E402

SRC_DIR = SDK / "src" / "kernel_offsets"
OUT_DIR = SDK / "build" / "offsets"
REF_DIR = OUT_DIR / "_ref"
BASELINE_FILE = SDK / "notes" / "gate-symbol-baseline.json"

# The kernel_offsets block: frozen-archive ordinals before the first
# module_base_* member. Measured, not hard-coded by count.
GROUP_PREFIX_STOP = "module_base_"

# -D_FORTIFY_SOURCE=2 is not optional: without it clang folds strlen() of a
# zero-initialised array, the member stops referencing __strlen_chk, and the U
# diff grows by one symbol that no source change explains.
GROUP_EXTRA_FLAGS = ["-D_FORTIFY_SOURCE=2"]

# Every member of this group is built with exceptions on, measured (not assumed):
# the frozen bodies declare `personality ptr @__gxx_personality_v0`, carry
# `invoke`/`landingpad` pairs, and import __cxa_throw / __cxa_begin_catch /
# __cxa_free_exception / _Unwind_Resume. Building the same source with the
# -fno-exceptions profile drops 15 of the 27-32 imports (the whole libc++
# throw-path baseline), so the plain profile cannot reproduce the member.
DEFAULT_PROFILE_BY_LAYOUT = {
    "bitcode": "core-oz-bitcode-fexceptions",
    "elf": "core-oz-elf-fexceptions",
}


@dataclass
class Row:
    idx: int
    name: str
    layout: str
    bytes: int
    sha256: str
    t_ref: int = 0
    t_new: int = 0
    u_ref: int = 0
    u_new: int = 0
    t_missing: list[str] = field(default_factory=list)
    t_extra: list[str] = field(default_factory=list)
    u_missing: list[str] = field(default_factory=list)
    u_extra: list[str] = field(default_factory=list)
    status: str = ""
    detail: str = ""
    # gate columns
    consumed: list[str] = field(default_factory=list)
    u_missing_adjusted: list[str] = field(default_factory=list)

    @property
    def raw_ok(self) -> bool:
        return not (self.t_missing or self.t_extra or self.u_missing or self.u_extra)

    @property
    def adjusted_ok(self) -> bool:
        return not (self.t_missing or self.t_extra or self.u_missing_adjusted or self.u_extra)


def load_allowance() -> tuple[set[str], dict]:
    """Return (allowed u-missing symbols, full document) from the central file.

    A missing file is not an error: the gate then simply has no allowance and
    every diff is reported raw. That keeps the tool usable before the central
    file exists, without silently granting tolerance.
    """
    if not BASELINE_FILE.is_file():
        return set(), {"scope": "absent", "uMissing": []}
    doc = json.loads(BASELINE_FILE.read_text(encoding="utf-8"))
    symbols = {str(e.get("symbol", "")).strip() for e in doc.get("uMissing", []) if e.get("symbol")}
    return symbols, doc


def allowance_applies(layout: str, doc: dict) -> bool:
    scope = str(doc.get("scope", ""))
    if "bitcode" in scope.lower():
        return layout == "bitcode"  # central file: native-ELF members have ZERO allowance
    return True


def group_members(archive: S.Archive) -> list[S.ArchiveMember]:
    out: list[S.ArchiveMember] = []
    for member in archive.members:
        if member.name.startswith(GROUP_PREFIX_STOP):
            break
        out.append(member)
    return out


def source_for(member: S.ArchiveMember) -> Path:
    return SRC_DIR / (Path(member.name).stem + ".cpp")


def build_one(tc: S.Toolchain, member: S.ArchiveMember, src: Path, profile: str,
              extra_flags: list[str], out_dir: Path) -> tuple[Path | None, str]:
    """Compile one member. Returns (artifact path, diagnostic text)."""
    suffix = ".bc" if S.profile_emit_llvm(profile) else ".o"
    out = out_dir / (Path(member.name).stem + suffix)
    flags = S.profile_flags(profile, "cxx", extra_flags)
    argv = [tc.tool("clang++"), *flags, "-I", SDK / "include", "-I", SDK.parent / "include",
            "-c", src, "-o", out]
    completed = S.run(argv, cwd=SDK)
    if completed.returncode != 0:
        return None, (completed.stderr.strip() or completed.stdout.strip())[-1200:]
    return out, ""


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="batch build + T/U gate for the kernel_offsets group")
    ap.add_argument("--only", nargs="*", default=None,
                    help="member names (with or without .o) to build; default: whole group")
    ap.add_argument("--out", default=None, help="artifact directory (default build/offsets)")
    ap.add_argument("--json", default=None, help="write the table here (default build/offsets/selfcheck.json)")
    ap.add_argument("--exit-on-diff", action="store_true",
                    help="exit 7 when any member has a non-empty adjusted diff, no source, or a compile error")
    ap.add_argument("--verbose", action="store_true", help="always print the per-symbol diff detail")
    args = ap.parse_args(argv)

    try:
        tc = S.resolve_toolchain(require_all=True)
        snapshot, archive = S.load_frozen(tc)
    except (S.ToolchainMissing, S.FreezeError, S.ArchiveError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 3
    allowance, allowance_doc = load_allowance()

    out_dir = Path(args.out) if args.out else OUT_DIR
    out_dir.mkdir(parents=True, exist_ok=True)
    REF_DIR.mkdir(parents=True, exist_ok=True)

    wanted = {w[:-2] if w.endswith(".o") else w for w in args.only} if args.only else None
    rows: list[Row] = []
    for member in group_members(archive):
        stem = Path(member.name).stem
        if wanted is not None and stem not in wanted:
            continue
        profile = DEFAULT_PROFILE_BY_LAYOUT["bitcode" if member.layout == "bitcode" else "elf"]
        src = source_for(member)
        ref_path = REF_DIR / member.name
        if not ref_path.is_file() or ref_path.stat().st_size != member.size:
            ref_path.write_bytes(member.data)
        row = Row(member.idx, member.name, member.layout, member.size, member.sha256)
        if not src.is_file():
            row.status = "no-source"
            row.detail = f"missing {S.rel(src)}"
            rows.append(row)
            continue
        new_path, diag = build_one(tc, member, src, profile, GROUP_EXTRA_FLAGS, out_dir)
        if new_path is None:
            row.status = "compile-fail"
            row.detail = diag
            rows.append(row)
            continue
        ref_sym = S.nm_symbols(tc, ref_path)
        new_sym = S.nm_symbols(tc, new_path)
        row.t_ref, row.t_new = len(ref_sym.defined), len(new_sym.defined)
        row.u_ref, row.u_new = len(ref_sym.undefined), len(new_sym.undefined)
        row.t_missing = sorted(ref_sym.defined - new_sym.defined)
        row.t_extra = sorted(new_sym.defined - ref_sym.defined)
        row.u_missing = sorted(ref_sym.undefined - new_sym.undefined)
        row.u_extra = sorted(new_sym.undefined - ref_sym.undefined)
        if allowance_applies(member.layout, allowance_doc):
            row.consumed = [s for s in row.u_missing if s in allowance]
            row.u_missing_adjusted = [s for s in row.u_missing if s not in allowance]
        else:
            row.consumed = []
            row.u_missing_adjusted = list(row.u_missing)
        row.status = "ok" if row.adjusted_ok else "diff"
        rows.append(row)

    # ---- table ------------------------------------------------------------
    print(f"frozen archive : {S.rel(snapshot.archive)}")
    print(f"archive sha256 : {snapshot.archive_sha256}")
    print(f"toolchain      : {tc.ndk.name}")
    print(f"allowance      : {S.rel(BASELINE_FILE) if BASELINE_FILE.is_file() else '(absent)'} "
          f"uMissing={len(allowance)} scope={allowance_doc.get('scope', 'n/a')!r}")
    print()
    head = (f"{'idx':>3s} {'member':22s} {'layout':7s} {'bytes':>7s} {'T':>7s} {'U':>7s} "
            f"{'raw t-/t+/u-/u+':>18s} {'adj t-/t+/u-/u+':>18s} {'cons':>4s}  verdict")
    print(head)
    print("-" * len(head))
    for r in rows:
        if r.status in ("no-source", "compile-fail"):
            print(f"{r.idx:>3d} {r.name:22s} {r.layout:7s} {r.bytes:>7d} {'-':>7s} {'-':>7s} "
                  f"{'-':>18s} {'-':>18s} {'-':>4s}  {r.status}")
            continue
        raw = (f"{len(r.t_missing)}/{len(r.t_extra)}/{len(r.u_missing)}/{len(r.u_extra)}")
        adj = (f"{len(r.t_missing)}/{len(r.t_extra)}/{len(r.u_missing_adjusted)}/{len(r.u_extra)}")
        verdict = "PASS" if r.adjusted_ok else "FAIL"
        if r.adjusted_ok and not r.raw_ok:
            verdict = "PASS(raw!=0)"
        print(f"{r.idx:>3d} {r.name:22s} {r.layout:7s} {r.bytes:>7d} "
              f"{r.t_ref:>3d}/{r.t_new:<3d} {r.u_ref:>3d}/{r.u_new:<3d} {raw:>18s} {adj:>18s} "
              f"{len(r.consumed):>4d}  {verdict}")

    detailed = args.verbose or any(r.status == "diff" for r in rows) or any(r.consumed for r in rows)
    if detailed:
        print()
        for r in rows:
            if r.status in ("no-source", "compile-fail"):
                continue
            if r.raw_ok and not r.consumed:
                continue
            print(f"-- {r.name} ({r.layout})")
            for n in r.t_missing:
                print(f"   T missing from rebuild : {n}")
            for n in r.t_extra:
                print(f"   T extra in rebuild     : {n}")
            for n in r.u_missing:
                tag = "ALLOWED" if n in r.consumed else "MISSING"
                print(f"   U missing from rebuild : {n}   [{tag}]")
            for n in r.u_extra:
                print(f"   U extra in rebuild     : {n}")
    for r in rows:
        if r.status in ("no-source", "compile-fail"):
            print(f"-- {r.name}: {r.status}: {r.detail}", file=sys.stderr)

    passed = sum(1 for r in rows if r.status == "ok")
    print()
    print(f"members={len(rows)} pass={passed} fail={sum(1 for r in rows if r.status == 'diff')} "
          f"no-source={sum(1 for r in rows if r.status == 'no-source')} "
          f"compile-fail={sum(1 for r in rows if r.status == 'compile-fail')} "
          f"| raw-clean={sum(1 for r in rows if r.status == 'ok' and r.raw_ok)}")

    payload = {
        "schema": "maplesu-offsets-batch-selfcheck/1",
        "frozenArchive": S.rel(snapshot.archive),
        "archiveSha256": snapshot.archive_sha256,
        "toolchain": str(tc.ndk),
        "layoutPolicy": "each member is rebuilt in the container the frozen member uses "
                        "(bitcode -> -emit-llvm -c, elf -> -c)",
        "symbolSets": {"T": "strong external definitions", "U": "strong imports"},
        "extraFlags": GROUP_EXTRA_FLAGS,
        "allowance": {
            "path": S.rel(BASELINE_FILE) if BASELINE_FILE.is_file() else None,
            "scope": allowance_doc.get("scope"),
            "symbols": sorted(allowance),
            "note": "raw diff is reported verbatim; the adjusted column only removes these "
                    "declared toolchain-baseline entries and never hides them",
        },
        "rows": [
            {
                "idx": r.idx, "name": r.name, "layout": r.layout, "bytes": r.bytes,
                "sha256": r.sha256, "status": r.status,
                "raw": {
                    "t": {"ref": r.t_ref, "new": r.t_new, "missing": r.t_missing, "extra": r.t_extra},
                    "u": {"ref": r.u_ref, "new": r.u_new, "missing": r.u_missing, "extra": r.u_extra},
                },
                "adjusted": {
                    "t": {"missing": r.t_missing, "extra": r.t_extra},
                    "u": {"missing": r.u_missing_adjusted, "extra": r.u_extra},
                },
                "consumed": r.consumed,
                "detail": r.detail,
            }
            for r in rows
        ],
        "summary": {"members": len(rows), "pass": passed,
                    "fail": sum(1 for r in rows if r.status == "diff"),
                    "noSource": sum(1 for r in rows if r.status == "no-source"),
                    "compileFail": sum(1 for r in rows if r.status == "compile-fail"),
                    "rawClean": sum(1 for r in rows if r.status == "ok" and r.raw_ok)},
    }
    json_path = Path(args.json) if args.json else (out_dir / "selfcheck.json")
    S.write_json(json_path, payload)
    print(f"table -> {S.rel(json_path)}")

    if args.exit_on_diff and any(r.status != "ok" for r in rows):
        return 7
    return 0


if __name__ == "__main__":
    sys.exit(main())
