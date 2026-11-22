"""Check how much of the consumer contract a rebuilt archive satisfies.

The five consumers of the Ultra SDK (runtime/CMakeLists.txt:87/109/193/221/230)
only need a subset of the archive's symbols.  This tool answers two questions
without building anything:

1. **Closure**: of the symbols the consumers reference, which ones does the
   rebuilt archive actually define?
2. **Ownership**: for every missing symbol, which frozen archive member is
   supposed to provide it (so the gap can be handed to a work package instead
   of being rediscovered).

Inputs
------
* ``sdk/out/recon-consumer-link/required-archive-symbols.tsv`` - the measured
  consumer requirement list (column 1 = mangled symbol).
* the rebuilt archive (residual reference).
* the frozen archive, for ownership lookup.

Exit codes: 0 fully closed, 9 symbols missing, 2 usage/environment.
"""

from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path

SDK = Path(__file__).resolve().parents[1]
REPO = SDK.parents[2]
NDK = Path("D:/Maple_Env/Android/Sdk/ndk/26.1.10909125/toolchains/llvm/prebuilt/windows-x86_64/bin")
NM = NDK / "llvm-nm.exe"
AR = NDK / "llvm-ar.exe"
CXXFILT = NDK / "llvm-cxxfilt.exe"

REQUIRED = SDK / "out" / "recon-consumer-link" / "required-archive-symbols.tsv"
FROZEN = (REPO / "runtime" / "maplesu-sdk" / "maintenance" / "freeze"
          / "freeze-maplesu-pro-5.2.0-su-uid-isolation-20261114-20261114"
          / "archive" / "libkernel_module_kit_static.a")   # residual: reference input


def defined_symbols(archive: Path) -> set[str]:
    out = subprocess.run([str(NM), "--defined-only", str(archive)],
                         capture_output=True, text=True, errors="replace")
    syms = set()
    for line in out.stdout.splitlines():
        parts = line.split()
        if len(parts) >= 2:
            syms.add(parts[-1])
    return syms


def required_symbols(path: Path) -> list[str]:
    syms = []
    for i, line in enumerate(path.read_text(encoding="utf-8").splitlines()):
        if i == 0 or not line.strip():
            continue
        col = line.split("\t")[0].strip()
        if col:
            syms.append(col)
    return sorted(set(syms))


def owner_map(frozen: Path, wanted: set[str], scratch: Path) -> dict[str, str]:
    """member file name -> [symbols] using a scratch extraction of the archive."""
    scratch.mkdir(parents=True, exist_ok=True)
    for old in scratch.glob("*.o"):
        old.unlink()
    subprocess.run([str(AR), "x", str(frozen)], cwd=scratch,
                   capture_output=True, text=True, errors="replace")
    owners: dict[str, str] = {}
    for obj in sorted(scratch.glob("*.o")):
        out = subprocess.run([str(NM), "-P", "--defined-only", str(obj)],
                             capture_output=True, text=True, errors="replace")
        for line in out.stdout.splitlines():
            parts = line.split()
            if parts and parts[0] in wanted and parts[0] not in owners:
                owners[parts[0]] = obj.name
    return owners


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--archive", default=str(SDK / "build" / "out" / "libkernel_module_kit_static.a"))
    ap.add_argument("--required", default=str(REQUIRED))
    ap.add_argument("--frozen", default=str(FROZEN))
    ap.add_argument("--scratch", default=str(REPO / ".tmp" / "consumer-symbols"))
    args = ap.parse_args()

    archive = Path(args.archive)
    for path in (archive, Path(args.required), Path(args.frozen)):
        if not path.exists():
            print(f"missing input: {path}", file=sys.stderr)
            return 2

    have = defined_symbols(archive)
    need = required_symbols(Path(args.required))
    missing = [s for s in need if s not in have]
    present = len(need) - len(missing)

    print(f"required : {len(need)}")
    print(f"present  : {present}")
    print(f"missing  : {len(missing)}")

    if not missing:
        print("consumer symbol closure: PASS")
        return 0

    owners = owner_map(Path(args.frozen), set(missing), Path(args.scratch))
    by_member: dict[str, list[str]] = {}
    for sym in missing:
        by_member.setdefault(owners.get(sym, "<not found in frozen archive>"), []).append(sym)

    demangled = {}
    if owners:
        proc = subprocess.run([str(CXXFILT)] + missing, capture_output=True, text=True, errors="replace")
        for line in proc.stdout.splitlines():
            demangled.setdefault(line.strip(), True)

    print("\nmissing symbols grouped by the frozen member that should provide them:")
    for member, syms in sorted(by_member.items(), key=lambda kv: -len(kv[1])):
        print(f"  {member:44s} {len(syms):3d}")
        for sym in syms[:4]:
            print(f"      {sym}")
        if len(syms) > 4:
            print(f"      ... (+{len(syms) - 4})")

    print("\nconsumer symbol closure: FAIL")
    return 9


if __name__ == "__main__":
    raise SystemExit(main())
