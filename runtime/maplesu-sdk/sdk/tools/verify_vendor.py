#!/usr/bin/env python3
"""VENDOR gate: prove the 161 vendored third-party archive members are source-equivalent.

For every member listed in ``third_party/build_rules.json`` this tool

  1. compiles the *vendored* source with the pinned profile,
  2. extracts the defined-``T`` symbol set and the undefined-``U`` symbol set
     from both the frozen archive member and the rebuilt object,
  3. diffs each set in both directions,

and writes the per-member result to ``sdk/build/report/vendor-gate.json``.

Why symbol sets and not bytes
-----------------------------
The frozen archive is a *mix* of two NDK point releases: all 101 third-party
ELF members carry ``.comment = Android (10552028, based on r487747d) clang
version 17.0.2`` (byte-identical to the pinned local clang), while the 60
third-party bitcode members carry ``!llvm.ident = Android (11349228, based on
r487747e)``.  Bitcode produced by a different point release cannot be
byte-identical, so bytes are reported as an *informational* tier only.

The authoritative criterion is the symbol surface, because a static archive is
consumed purely through "which symbols does it define / reference".
``-O`` level and inlining do not move the ``T`` set (measured: identical at
-O1/-O2/-Oz), so this criterion is stable across the profiles we can justify.

Empty vs empty is a PASS
------------------------
``a64operand.o``, ``operand.o``, ``support.o``, ``x86operand.o``,
``zonelist.o``, ``zonetree.o`` and ``zip_err_str.o`` genuinely export no ``T``
symbol.  An implementation that requires a non-empty set would report those
seven correct matches as failures.  Empty == empty is therefore PASS here.

Residual classes
----------------
An import-set difference is tolerated only when *none* of the differing symbols
belongs to the library.  Ownership is decided from evidence, not from a name
allowlist: a symbol is library-owned when it is **defined** by any of the 161
archive members, or carries the library's own namespace prefix (``_ZN6asmjit``,
``mg_``, ``zip_``, ``_zip_``, ``_ZN6Civet``).  Any import difference touching a
library-owned symbol is a hard ``MISMATCH`` -- exactly the rule "no residual may
be a library API symbol".

The tolerated differences are all bionic/toolchain artifacts of the sysroot
version and are labelled with a cause:

  libc-fortify-wrapper   ``__memset_chk`` / ``__strlen_chk`` / ``__open_2`` ...
                         The archive was built against a bionic whose headers
                         still expanded ``memset``/``strlen``/... into the
                         FORTIFY ``__*_chk`` runtime.  The pinned local NDK
                         26.1 (10552028) ``string.h`` contains no
                         ``__memcpy_chk`` wrapper at all (measured:
                         ``grep -c __memcpy_chk sysroot/usr/include/string.h``
                         = 0), so it can only emit the plain libc name.
  libc-lfs-redirect      ``open`` (archive) vs ``open64`` (local): newer bionic
                         redirects ``open`` to the 64-bit entry unconditionally.
  libc-printf-family     ``snprintf`` vs ``vsnprintf``: which member of the
                         printf family the optimiser leaves as a call.
  libcxx-template        out-of-line libc++ template instantiations.
  cxxabi-runtime         ``__gxx_personality_v0`` / ``__cxa_*`` / ``_Unwind_*``.

These never silently become ``OK``: they are reported as ``RESIDUAL`` with the
symbol, the cause, and the counterpart symbol written into the JSON.

Exit codes
----------
0  gate passes: every member has an exact export set and no unclassified
   import residual (OK + RESIDUAL == total, MISMATCH == 0)
1  gate fails (at least one MISMATCH, or a member failed to build)
2  usage / environment error (toolchain, archive, build rules)
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

SDK_DIR = Path(__file__).resolve().parent.parent
DEFAULT_RULES = SDK_DIR / "third_party" / "build_rules.json"
DEFAULT_OUT = SDK_DIR / "build" / "report" / "vendor-gate.json"
CENSUS = SDK_DIR / "notes" / "recon" / "ARCHIVE-CENSUS.json"
DEFAULT_FREEZE = (
    SDK_DIR.parent
    / "maintenance"
    / "freeze"
    / "freeze-maplesu-pro-5.2.0-su-uid-isolation-20261114-20261114"
    / "archive"
    / "libkernel_module_kit_static.a"   # residual: reference input
)

EXIT_OK = 0
EXIT_FAIL = 1
EXIT_ENV = 2

# Cause labels for import-set differences that do not involve library symbols.
# Matching is used only to *name* the cause; whether a difference is fatal is
# decided by symbol ownership (see ``library_owned``), never by this table.
CAUSE_PATTERNS: list[tuple[str, str]] = [
    (r"^__.*_chk$", "libc-fortify-wrapper"),
    (r"^__open_2$|^__read_chk$|^__write_chk$", "libc-fortify-wrapper"),
    (r"^__stack_chk(_fail|_guard)?$", "compiler-runtime"),
    (r"^__clang_", "compiler-runtime"),
    (r"^__aarch64_(ldadd|ldset|ldclr|swp|cas)", "compiler-runtime-atomic"),
    (r"^__mulodi4$|^__divdi3$|^__udivdi3$", "compiler-rt"),
    (r"^_ZTI|^_ZTS|^_ZTV|^_ZThn|^_ZTv0", "cxxabi-typeinfo"),
    (r"^_ZSt|^_ZNSt|^_ZNKSt|^_ZSt3", "libcxx-template"),
    (r"^__cxa_|^__gxx_|^_Unwind_", "cxxabi-runtime"),
    (r"^(open|open64|fopen|fopen64|fseeko|fseeko64|ftello|ftello64|stat|stat64|lseek|lseek64)$",
     "libc-lfs-redirect"),
    (r"^(printf|fprintf|sprintf|snprintf|vprintf|vfprintf|vsprintf|vsnprintf|dprintf)$",
     "libc-printf-family"),
]

# Suffixes/prefixes stripped to pair "same libc function, different spelling".
_LIBC_NORMALISE = [
    (r"^__", ""),
    (r"(_chk|_2|64)$", ""),
]


def cause_of(sym: str) -> str:
    """Best-effort human-readable cause label for a tolerated difference."""
    for pat, name in CAUSE_PATTERNS:
        if re.match(pat, sym):
            return name
    return "libc-sysroot-other"


def family_of(sym: str) -> str:
    """Canonical libc-family name, used to pair ``__strlen_chk`` with ``strlen``."""
    out = sym
    changed = True
    while changed:
        changed = False
        for pat, repl in _LIBC_NORMALISE:
            new = re.sub(pat, repl, out)
            if new != out and new:
                out = new
                changed = True
    return out


def library_owned(sym: str, defined_here: set[str], library_symbols: set[str]) -> bool:
    """Is ``sym`` part of the library's own surface (API or internal)?"""
    if sym in defined_here or sym in library_symbols:
        return True
    for prefix in ("_ZN6asmjit", "_ZN6Civet", "mg_", "zip_", "_zip_"):
        if sym.startswith(prefix):
            return True
    return False


def refine_causes(only_archive: list[str], only_rebuilt: list[str]) -> dict[str, str]:
    """Cause for every tolerated import difference, pairing the two sides.

    A difference is only tolerated when neither side is library-owned, but the
    *cause* is much more convincing when the two symbols are the same libc
    function spelled differently: ``__strlen_chk`` (archive) vs ``strlen``
    (local NDK) share the family ``strlen``.  Pairing also proves the diff is a
    spelling change rather than a missing dependency.
    """
    arch_family: dict[str, list[str]] = {}
    for s in only_archive:
        arch_family.setdefault(family_of(s), []).append(s)
    new_family: dict[str, list[str]] = {}
    for s in only_rebuilt:
        new_family.setdefault(family_of(s), []).append(s)

    causes: dict[str, str] = {}
    for side, syms in (("archive", only_archive), ("rebuilt", only_rebuilt)):
        other = new_family if side == "archive" else arch_family
        for s in syms:
            fam = family_of(s)
            counterparts = other.get(fam, [])
            if counterparts:
                # Same libc function, different spelling.
                if any(c.startswith("__") and c.endswith("_chk") for c in counterparts) or \
                   (s.startswith("__") and s.endswith("_chk")):
                    causes[s] = "libc-fortify-wrapper"
                elif re.match(r"^open64?$", s) or any(re.match(r"^open64?$", c) for c in counterparts):
                    causes[s] = "libc-lfs-redirect"
                else:
                    causes[s] = "libc-spelling"
            else:
                causes[s] = cause_of(s)
    return causes



class Toolchain:
    def __init__(self, root: str | None):
        self.root = Path(root) if root else None

    def _resolve(self, tool: str) -> str:
        if self.root:
            for suffix in ("", ".exe"):
                cand = self.root / f"{tool}{suffix}"
                if cand.is_file():
                    return str(cand)
        found = shutil.which(tool)
        if not found:
            raise SystemExit(f"{EXIT_ENV}: toolchain tool not found: {tool}")
        return found

    def run(self, tool: str, args: list[str], cwd: Path | None = None) -> tuple[int, str, str]:
        exe = self._resolve(tool)
        proc = subprocess.run(
            [exe, *args],
            cwd=str(cwd) if cwd else None,
            capture_output=True,
            text=True,
            errors="replace",
        )
        return proc.returncode, proc.stdout, proc.stderr

    def check(self, tool: str, args: list[str], cwd: Path | None = None) -> str:
        code, out, err = self.run(tool, args, cwd)
        if code != 0:
            raise RuntimeError(f"{tool} {' '.join(args)} failed ({code}): {err.strip()[:400]}")
        return out


def archive_members(tc: Toolchain, archive: Path) -> list[str]:
    """Member names in archive order.  0-based position == canonical frozen idx."""
    out = tc.check("llvm-ar", ["t", str(archive)])
    return [line.strip() for line in out.splitlines() if line.strip()]


def load_census() -> dict[str, dict]:
    """name -> census row.  The census is the single source of truth for idx.

    ``idx`` is the 0-based position in ``llvm-ar t``.  Deriving it here (instead
    of counting in this script) is what keeps the metadata off the off-by-one
    class of bug: ``tools/normalize_manifest.py`` uses the same table.
    """
    if not CENSUS.is_file():
        return {}
    data = json.loads(CENSUS.read_text(encoding="utf-8"))
    rows = data["members"] if isinstance(data, dict) else data
    return {row["name"]: row for row in rows}


def member_bytes(tc: Toolchain, archive: Path, name: str, workdir: Path) -> bytes:
    """Read one member's payload (unique names only -- caller asserts uniqueness)."""
    dest = workdir / f"extract_{abs(hash(name)) % 10**8}_{name}"
    dest.parent.mkdir(parents=True, exist_ok=True)
    # Extract into a private directory so members never clobber each other.
    sub = workdir / "arx"
    sub.mkdir(exist_ok=True)
    tc.check("llvm-ar", ["x", str(archive), name], cwd=sub)
    data = (sub / name).read_bytes()
    (sub / name).unlink()
    return data


def nm_sets(tc: Toolchain, obj: Path, want_all_defined: bool = False
            ) -> tuple[set[str], set[str]] | tuple[set[str], set[str], set[str]]:
    """(defined T set, undefined U set[, all-defined set]) for one object."""
    tset: set[str] = set()
    uset: set[str] = set()
    all_defined: set[str] = set()
    code, out, err = tc.run("llvm-nm", ["--defined-only", "--format=posix", str(obj)])
    if code != 0:
        # "no symbols" still exits 0 on llvm-nm; a real failure is fatal.
        raise RuntimeError(f"llvm-nm defined failed on {obj}: {err.strip()[:300]}")
    for line in out.splitlines():
        parts = line.split()
        if len(parts) >= 2:
            all_defined.add(parts[0])
            if parts[1] == "T":
                tset.add(parts[0])
    code, out, err = tc.run("llvm-nm", ["--undefined-only", "--format=posix", str(obj)])
    if code != 0:
        raise RuntimeError(f"llvm-nm undefined failed on {obj}: {err.strip()[:300]}")
    for line in out.splitlines():
        parts = line.split()
        if len(parts) >= 2 and parts[1] == "U":
            uset.add(parts[0])
        elif len(parts) == 1 and parts[0]:
            uset.add(parts[0])
    if want_all_defined:
        return tset, uset, all_defined
    return tset, uset


def layout_of(data: bytes) -> str:
    if data[:4] == b"\x7fELF":
        return "elf"
    if data[:4] == b"BC\xc0\xde":
        return "bitcode"
    if data[:4] == b"\xde\xc0\x17\x0b":
        return "bitcode-wrapper"
    return "unknown"


def sha256_of(data: bytes) -> str:
    import hashlib

    return hashlib.sha256(data).hexdigest()


def build_one(tc: Toolchain, rules: dict, lib: dict, member: str, src_rel: str,
              outdir: Path, log: list[str]) -> tuple[Path | None, dict]:
    """Compile one member.  Returns (path or None, effective compile spec)."""
    profile_name = lib["profile"]
    cflags = list(lib["cflags"])
    defines = list(lib["defines"])
    include_dirs = list(lib["includeDirs"])
    per = (lib.get("perSource") or {}).get(src_rel) or {}
    if per.get("profile"):
        profile_name = per["profile"]
    if per.get("cflags"):
        cflags = list(per["cflags"])
    if per.get("defines"):
        defines = defines + list(per["defines"])
    prof = rules["profiles"][profile_name]
    lib_root = SDK_DIR / "third_party" / lib["lib"] / lib["version"]
    src = lib_root / src_rel
    obj = outdir / member
    args = [
        *prof["cflags"],
        *cflags,
        *defines,
        *[f"-I{lib_root / d}" for d in include_dirs],
        *prof["emit"],
        str(src),
        "-o",
        str(obj),
    ]
    compiler = "clang++" if prof["language"] == "c++" else "clang"
    code, out, err = tc.run(compiler, args)
    spec = {
        "compiler": compiler,
        "profile": profile_name,
        "argv": [compiler, *args],
        "warnings": (err or "").strip().splitlines()[:10],
    }
    if code != 0:
        log.append(f"BUILD-FAIL {member}: {err.strip()[:500]}")
        return None, spec
    return obj, spec


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="VENDOR 161-member equivalence gate")
    ap.add_argument("--rules", default=str(DEFAULT_RULES))
    ap.add_argument("--archive", default=str(DEFAULT_FREEZE))
    ap.add_argument("--out", default=str(DEFAULT_OUT))
    ap.add_argument("--workdir", default=None, help="scratch dir (default: system temp)")
    ap.add_argument("--only", default=None, help="limit to one lib (asmjit|civetweb|libzip)")
    ap.add_argument("--emit-manifests", action="store_true",
                    help="also write sdk/manifest/<idx4>_<name>.json from the measured results")
    ap.add_argument("--quiet", action="store_true")
    args = ap.parse_args(argv)

    rules_path = Path(args.rules)
    if not rules_path.is_file():
        print(f"{EXIT_ENV}: build rules not found: {rules_path}", file=sys.stderr)
        return EXIT_ENV
    rules = json.loads(rules_path.read_text(encoding="utf-8"))

    archive = Path(args.archive)
    if not archive.is_file():
        print(f"{EXIT_ENV}: frozen archive not found: {archive}", file=sys.stderr)
        return EXIT_ENV

    tc = Toolchain(rules.get("toolchain", {}).get("root"))
    names = archive_members(tc, archive)
    # idx: canonical 0-based position in `llvm-ar t` (same basis as the census).
    first_idx: dict[str, int] = {}
    count_by_name: dict[str, int] = {}
    for pos, n in enumerate(names):
        first_idx.setdefault(n, pos)
        count_by_name[n] = count_by_name.get(n, 0) + 1

    census = load_census()
    idx_disagreements: list[str] = []
    census_dupes_skipped: list[str] = []
    if census:
        for pos, n in enumerate(names):
            if count_by_name[n] > 1:
                # e.g. patch_base.o appears three times with different bytes; the
                # census disambiguates those rows by sha256, not by position.
                if n not in census_dupes_skipped:
                    census_dupes_skipped.append(n)
                continue
            row = census.get(n)
            if row is not None and row["idx"] != pos:
                idx_disagreements.append(f"{n}: ar-position {pos} != census {row['idx']}")
        if idx_disagreements:
            print(f"{EXIT_ENV}: archive order disagrees with census for "
                  f"{len(idx_disagreements)} member(s), refusing to number by hand: "
                  f"{idx_disagreements[:3]}", file=sys.stderr)
            return EXIT_ENV
        if not args.quiet and census_dupes_skipped:
            print(f"census cross-check: skipped duplicate-named members "
                  f"{census_dupes_skipped} (census keys those rows by sha256)")

    libs = [l for l in rules["libs"] if not args.only or l["lib"] == args.only]
    wanted: list[tuple[dict, str, str]] = []
    for lib in libs:
        for member, src in lib["members"].items():
            wanted.append((lib, member, src))

    missing_in_archive = [(l["lib"], m) for l, m, _ in wanted if m not in first_idx]
    if missing_in_archive:
        print(f"{EXIT_ENV}: members declared in build rules are not in the archive: "
              f"{missing_in_archive[:5]}", file=sys.stderr)
        return EXIT_ENV
    dupes = [(l["lib"], m) for l, m, _ in wanted if count_by_name.get(m, 0) > 1]
    if dupes:
        print(f"{EXIT_ENV}: duplicate member names in archive, cannot index uniquely: "
              f"{dupes[:5]}", file=sys.stderr)
        return EXIT_ENV

    work_root = Path(args.workdir) if args.workdir else Path(tempfile.mkdtemp(prefix="vendor-gate-"))
    work_root.mkdir(parents=True, exist_ok=True)
    objdir = work_root / "obj"
    objdir.mkdir(exist_ok=True)
    arxdir = work_root / "arx"
    arxdir.mkdir(exist_ok=True)

    log: list[str] = []
    rows: list[dict] = []
    n_ok = n_residual = n_mismatch = n_build_fail = 0

    # ---- pass A: read every member and build the library-owned symbol surface.
    # A symbol is "library-owned" when any of the 161 members *defines* it; the
    # import diff may never touch such a symbol.
    cache: dict[str, dict] = {}
    library_symbols: set[str] = set()
    for lib, member, src_rel in wanted:
        idx = first_idx[member]
        data = member_bytes(tc, archive, member, arxdir)
        arch_obj = arxdir / f"arch_{idx:04d}_{member}"
        arch_obj.write_bytes(data)
        arch_t, arch_u, arch_all = nm_sets(tc, arch_obj, want_all_defined=True)
        cache[member] = {
            "idx": idx, "data": data, "layout": layout_of(data),
            "t": arch_t, "u": arch_u, "defined": arch_all,
        }
        library_symbols |= arch_all
    if not args.quiet:
        print(f"library-owned symbol surface: {len(library_symbols)} symbols "
              f"(defined by any of {len(wanted)} members)")

    # ---- pass B: rebuild each member and compare.
    for lib, member, src_rel in wanted:
        idx = cache[member]["idx"]
        data = cache[member]["data"]
        layout = cache[member]["layout"]
        arch_t, arch_u, arch_defined = cache[member]["t"], cache[member]["u"], cache[member]["defined"]

        built, spec = build_one(tc, rules, lib, member, src_rel, objdir, log)
        if built is None:
            n_build_fail += 1
            rows.append({
                "idx": idx,
                "name": member,
                "group": lib["lib"],
                "sources": [f"third_party/{lib['lib']}/{lib['version']}/{src_rel}"],
                "layout": layout,
                "verdict": "BUILD-FAIL",
                "compile": spec,
            })
            if not args.quiet:
                print(f"[{idx:04d}] {member:24s} BUILD-FAIL")
            continue

        new_t, new_u = nm_sets(tc, built)
        t_only_arch = sorted(arch_t - new_t)
        t_only_new = sorted(new_t - arch_t)
        u_only_arch = sorted(arch_u - new_u)
        u_only_new = sorted(new_u - arch_u)

        export_ok = not t_only_arch and not t_only_new
        raw_u_diff = u_only_arch + u_only_new

        # Split the import diff: anything library-owned is fatal, the rest is a
        # toolchain/sysroot artifact and is reported with its cause.
        library_owned_residual: list[str] = []
        residual_classes: dict[str, str] = {}
        residual_cause: dict[str, str] = {}
        for sym in raw_u_diff:
            if library_owned(sym, arch_defined, library_symbols):
                library_owned_residual.append(sym)
        tolerated = [s for s in raw_u_diff if s not in library_owned_residual]
        if tolerated:
            residual_cause = refine_causes(u_only_arch, u_only_new)
            for sym in tolerated:
                residual_classes[sym] = residual_cause.get(sym) or cause_of(sym)
                residual_cause.setdefault(sym, residual_classes[sym])

        if not export_ok or library_owned_residual:
            verdict = "MISMATCH"
            n_mismatch += 1
        elif raw_u_diff:
            verdict = "RESIDUAL"
            n_residual += 1
        else:
            verdict = "OK"
            n_ok += 1

        new_bytes = built.read_bytes()
        row = {
            "idx": idx,
            "name": member,
            "group": lib["lib"],
            "version": lib["version"],
            "sources": [f"third_party/{lib['lib']}/{lib['version']}/{src_rel}"],
            "layout": layout,
            "flagsProfile": spec["profile"],
            "verdict": verdict,
            "export": {
                "archiveT": len(arch_t),
                "rebuiltT": len(new_t),
                "onlyArchive": t_only_arch,
                "onlyRebuilt": t_only_new,
                "exact": export_ok,
            },
            "import": {
                "archiveU": len(arch_u),
                "rebuiltU": len(new_u),
                "onlyArchive": u_only_arch,
                "onlyRebuilt": u_only_new,
                "exact": not raw_u_diff,
                "libraryOwnedDiff": library_owned_residual,
                "toolchainDiff": residual_classes,
                "toolchainCauses": residual_cause,
            },
            "byteIdentical": new_bytes == data,
            "original": {"sha256": sha256_of(data), "bytes": len(data)},
            "rebuilt": {"sha256": sha256_of(new_bytes), "bytes": len(new_bytes)},
            "compile": spec,
        }
        rows.append(row)
        if not args.quiet:
            flag = {"OK": "OK      ", "RESIDUAL": "RESIDUAL", "MISMATCH": "MISMATCH"}[verdict]
            extra = ""
            if verdict == "RESIDUAL":
                extra = " [" + ",".join(sorted(set(residual_cause.values()))) + "]"
            if verdict == "MISMATCH":
                extra = (f" T-{len(t_only_arch)}/+{len(t_only_new)}"
                         f" library-owned={library_owned_residual[:3]}")
            print(f"[{idx:04d}] {member:24s} {flag} T={len(arch_t):3d} U={len(arch_u):3d}"
                  f"{' bytes=identical' if new_bytes == data else ''}{extra}")

    by_group: dict[str, dict[str, int]] = {}
    for row in rows:
        g = by_group.setdefault(row["group"], {"total": 0, "OK": 0, "RESIDUAL": 0,
                                               "MISMATCH": 0, "BUILD-FAIL": 0,
                                               "byteIdentical": 0})
        g["total"] += 1
        g[row["verdict"]] = g.get(row["verdict"], 0) + 1
        if row.get("byteIdentical"):
            g["byteIdentical"] += 1

    total = len(rows)
    passed = n_mismatch == 0 and n_build_fail == 0 and (n_ok + n_residual) == total
    residual_symbols: dict[str, dict] = {}
    for row in rows:
        causes = row.get("import", {}).get("toolchainCauses") or {}
        for sym, cause in causes.items():
            entry = residual_symbols.setdefault(sym, {"cause": cause, "members": []})
            entry["members"].append(row["name"])

    census_kind_agreement = 0
    census_checked = 0
    for row in rows:
        ck = (census.get(row["name"]) or {}).get("kind")
        if not ck:
            continue
        census_checked += 1
        if (ck == "llvm-bitcode" and row["layout"].startswith("bitcode")) or \
           (ck == "elf" and row["layout"] == "elf"):
            census_kind_agreement += 1

    report = {
        "schema": "maplesu.vendor.gate/1",
        "task": "VENDOR",
        "generatedUtc": subprocess.run(
            ["date", "-u", "+%Y-%m-%dT%H:%M:%SZ"], capture_output=True, text=True
        ).stdout.strip() or None,
        "archive": {
            "path": str(archive),
            "sha256": sha256_of(archive.read_bytes()),
            "bytes": archive.stat().st_size,
            "members": len(names),
        },
        "indexBasis": "0-based position in `llvm-ar t`; cross-checked against "
                      "notes/recon/ARCHIVE-CENSUS.json (tools/normalize_manifest.py uses the same table)",
        "layoutCrossCheck": {
            "against": "notes/recon/ARCHIVE-CENSUS.json kind",
            "checked": census_checked,
            "agree": census_kind_agreement,
        },
        "toolchain": rules.get("toolchain", {}),
        "rulesPath": str(rules_path),
        "criteria": {
            "export": "defines-only 'T' set, exact both-way diff (empty vs empty == PASS)",
            "import": "undefined 'U' set, exact both-way diff.  A differing symbol is fatal only "
                      "when it is library-owned (defined by any of the 161 members, or in the "
                      "library namespace); every other difference is a sysroot/toolchain artifact "
                      "and is reported with its cause.",
            "bytes": "informational only: bitcode members were built by a different NDK point "
                     "release (11349228 vs local 10552028) so byte identity is unattainable for them",
        },
        "totals": {
            "members": total,
            "OK": n_ok,
            "RESIDUAL": n_residual,
            "MISMATCH": n_mismatch,
            "BUILD-FAIL": n_build_fail,
            "byteIdentical": sum(1 for r in rows if r.get("byteIdentical")),
            "exportExact": sum(1 for r in rows if (r.get("export") or {}).get("exact")),
            "importExact": sum(1 for r in rows if (r.get("import") or {}).get("exact")),
            "libraryOwnedResiduals": sum(len((r.get("import") or {}).get("libraryOwnedDiff") or [])
                                        for r in rows),
        },
        "byGroup": by_group,
        "residualSymbols": residual_symbols,
        "members": rows,
        "verdict": "PASS" if passed else "FAIL",
    }

    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

    if args.emit_manifests:
        write_manifests(report, rules)

    print()
    print(f"members={total} OK={n_ok} RESIDUAL={n_residual} MISMATCH={n_mismatch} "
          f"BUILD-FAIL={n_build_fail} byteIdentical={report['totals']['byteIdentical']}")
    print(f"export-set exact: {report['totals']['exportExact']}/{total}   "
          f"import-set exact: {report['totals']['importExact']}/{total}   "
          f"library-owned residuals: {report['totals']['libraryOwnedResiduals']}")
    for lib_name, g in sorted(by_group.items()):
        print(f"  {lib_name:9s} total={g['total']:3d} OK={g['OK']:3d} RESIDUAL={g['RESIDUAL']:2d} "
              f"MISMATCH={g['MISMATCH']} BUILD-FAIL={g['BUILD-FAIL']} "
              f"byteIdentical={g['byteIdentical']}")
    if residual_symbols:
        print("  tolerated import residuals (none is a library symbol):")
        for sym, entry in sorted(residual_symbols.items()):
            print(f"    {sym:22s} [{entry['cause']}] in {len(entry['members'])} member(s)")
    print(f"report: {out_path}")
    print(f"VERDICT: {report['verdict']}")
    if log:
        print("build log (first 10):", file=sys.stderr)
        for line in log[:10]:
            print("  " + line, file=sys.stderr)
    return EXIT_OK if passed else EXIT_FAIL


def write_manifests(report: dict, rules: dict) -> int:
    """Write manifest/<idx4>_<name>.json for every member, from measured data."""
    manifest_dir = SDK_DIR / "manifest"
    manifest_dir.mkdir(parents=True, exist_ok=True)
    written = 0
    for row in report["members"]:
        if row["verdict"] == "BUILD-FAIL":
            continue
        u_only_arch = row["import"]["onlyArchive"]
        u_only_new = row["import"]["onlyRebuilt"]
        u_diff = [f"-{s}" for s in u_only_arch] + [f"+{s}" for s in u_only_new]
        t_diff = ([f"-{s}" for s in row["export"]["onlyArchive"]]
                  + [f"+{s}" for s in row["export"]["onlyRebuilt"]])
        note_bits = []
        if row["verdict"] == "OK":
            note_bits.append("import-set exact")
        elif row["verdict"] == "RESIDUAL":
            causes = sorted(set(row["import"]["toolchainCauses"].values()))
            note_bits.append(
                "import-set residual "
                + ", ".join(sorted(row["import"]["toolchainCauses"]))
                + f" [{'+'.join(causes)}]; sysroot/toolchain artifact, not a library symbol"
            )
        else:
            note_bits.append("MISMATCH: library-owned difference "
                             + ", ".join(row["import"]["libraryOwnedDiff"]))
        if row["byteIdentical"]:
            note_bits.append("rebuilt bytes identical")
        entry = {
            "idx": row["idx"],
            "name": row["name"],
            "group": row["group"],
            "layout": row["layout"],
            "kind": "SINGLE",
            "sources": row["sources"],
            "flagsProfile": row["flagsProfile"],
            "status": "complete",
            "recovery": {"functions": 0, "recovered": 0, "unrecovered": []},
            "original": {
                "sha256": row["original"]["sha256"],
                "bytes": row["original"]["bytes"],
            },
            "selfCheck": {
                "tDiff": t_diff,
                "uDiff": u_diff,
                "note": "; ".join(note_bits),
            },
            "notes": (
                f"source=vendored; version={row['version']}; equivalence=symbol-set"
                f" (export T exact: {len(row['export']['onlyArchive']) == 0 and len(row['export']['onlyRebuilt']) == 0})"
            ),
        }
        path = manifest_dir / f"{row['idx']:04d}_{row['name'].replace('/', '_')}.json"
        path.write_text(json.dumps(entry, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        written += 1
    print(f"manifests: {written} written to {manifest_dir}")
    return written


if __name__ == "__main__":
    sys.exit(main())
