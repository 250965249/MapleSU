"""Independent compile probe over manifest records.

Compiles the primary source of every member that has one, using only the
profile flags recorded in the manifest plus explicit include paths.  It does
not touch build.py, does not write into the archive, and does not run the
symbol gate - its single job is to answer "which member sources do not
compile at all", which is the first integration risk.

Usage:
    py tools/probe_compile.py [--jobs N] [--filter substring] [--keep]

Outputs a one-line-per-member table plus a summary, and writes
build/probe/compile-probe.json.
"""

from __future__ import annotations

import argparse
import concurrent.futures as futures
import json
import subprocess
import sys
from pathlib import Path

SDK = Path(__file__).resolve().parents[1]
REPO = SDK.parents[1]
MANIFEST = SDK / "manifest"
OUT = SDK / "build" / "probe"

NDK = Path("D:/Maple_Env/Android/Sdk/ndk/26.1.10909125/toolchains/llvm/prebuilt/windows-x86_64/bin")
CLANGXX = NDK / "clang++.exe"
CLANG = NDK / "clang.exe"

TARGET = ["--target=aarch64-linux-android21"]

PROFILES = {
    "core-oz-bitcode": TARGET + ["-std=c++20", "-Oz", "-fPIC", "-ffunction-sections", "-fdata-sections",
                                  "-fno-exceptions", "-fno-rtti", "-fvisibility=hidden", "-DNDEBUG", "-flto=thin"],
    "core-oz-elf": TARGET + ["-std=c++20", "-Oz", "-fPIC", "-ffunction-sections", "-fdata-sections",
                             "-fno-exceptions", "-fno-rtti", "-fvisibility=hidden", "-DNDEBUG"],
    "core-oz-bitcode-fexceptions": TARGET + ["-std=c++20", "-Oz", "-fPIC", "-ffunction-sections", "-fdata-sections",
                                             "-fexceptions", "-fno-rtti", "-fvisibility=hidden", "-DNDEBUG", "-flto=thin"],
    "core-oz-elf-fexceptions": TARGET + ["-std=c++20", "-Oz", "-fPIC", "-ffunction-sections", "-fdata-sections",
                                         "-fexceptions", "-fno-rtti", "-fvisibility=hidden", "-DNDEBUG"],
    "vendor-cxx-bitcode": TARGET + ["-std=c++17", "-O2", "-fPIC", "-ffunction-sections", "-fdata-sections",
                                    "-fno-exceptions", "-fno-rtti", "-DNDEBUG", "-flto=thin"],
    "vendor-cxx-elf": TARGET + ["-std=c++17", "-O2", "-fPIC", "-ffunction-sections", "-fdata-sections",
                                "-fno-exceptions", "-fno-rtti", "-DNDEBUG"],
    # third-party C (libzip, civetweb): must NOT receive -std=c++* or -fno-rtti
    "vendor-c-elf": TARGET + ["-std=c11", "-O2", "-fPIC", "-ffunction-sections", "-fdata-sections",
                              "-DNDEBUG", "-DHAVE_CONFIG_H"],
}

INCLUDES = [
    f"-I{SDK.parent / 'include'}",
    f"-I{SDK / 'include'}",
    f"-I{SDK}",
    f"-I{REPO / 'runtime' / 'ultra'}",
    f"-I{REPO / 'runtime'}",
]


def members() -> list[dict]:
    rows = []
    for path in sorted(MANIFEST.glob("[0-9][0-9][0-9][0-9]_*.json")):
        data = json.loads(path.read_text(encoding="utf-8"))
        if not data.get("sources"):
            continue
        rows.append(data)
    return rows


def compile_one(record: dict, keep: bool) -> dict:
    idx = record["idx"]
    name = record["name"]
    profile = record.get("flagsProfile") or "core-oz-bitcode"
    sources = [SDK / s for s in record["sources"]]
    primary = next((s for s in sources if s.suffix == ".cpp" or s.suffix == ".c"), None)
    if primary is None or not primary.exists():
        return {"idx": idx, "name": name, "status": "skip", "detail": "no compilable source"}

    flags = list(PROFILES.get(profile, PROFILES["core-oz-bitcode"]))
    for extra in record.get("extraFlags") or []:
        if isinstance(extra, str):
            if extra.startswith("-I") and not extra.startswith("-I/"):
                # make relative include dirs absolute against the sdk root
                flags.append("-I" + str(SDK / extra[2:]))
            else:
                flags.append(extra)

    out = OUT / f"{idx:04d}_{name}.o"
    compiler = CLANG if primary.suffix == ".c" else CLANGXX
    cmd = [str(compiler), *flags, *INCLUDES, "-c", str(primary), "-o", str(out)]
    proc = subprocess.run(cmd, capture_output=True, text=True, errors="replace")
    detail = ""
    if proc.returncode != 0:
        lines = [ln for ln in proc.stderr.splitlines() if "error:" in ln]
        detail = lines[0][:400] if lines else proc.stderr.strip().splitlines()[-1][:400] if proc.stderr.strip() else "unknown"
    if not keep and out.exists():
        out.unlink()
    return {
        "idx": idx,
        "name": name,
        "profile": profile,
        "status": "ok" if proc.returncode == 0 else "fail",
        "detail": detail,
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--jobs", type=int, default=8)
    ap.add_argument("--filter", default="")
    ap.add_argument("--keep", action="store_true")
    args = ap.parse_args()

    OUT.mkdir(parents=True, exist_ok=True)
    records = [r for r in members() if args.filter in r["name"]]
    results = []
    with futures.ThreadPoolExecutor(max_workers=args.jobs) as pool:
        for res in pool.map(lambda r: compile_one(r, args.keep), records):
            results.append(res)

    ok = [r for r in results if r["status"] == "ok"]
    bad = [r for r in results if r["status"] == "fail"]
    skip = [r for r in results if r["status"] == "skip"]

    print(f"{'idx':>4} {'member':46s} {'profile':30s} result")
    for r in results:
        print(f"{r['idx']:>4} {r['name']:46s} {r.get('profile', '-'):30s} {r['status']}"
              + (f"  {r['detail']}" if r["status"] == "fail" else ""))

    print()
    print(f"members probed : {len(results)}")
    print(f"compile ok     : {len(ok)}")
    print(f"compile FAIL   : {len(bad)}")
    print(f"skipped        : {len(skip)}")

    summary = {"probed": len(results), "ok": len(ok), "fail": len(bad), "skipped": len(skip),
               "failures": [{k: r[k] for k in ("idx", "name", "profile", "detail")} for r in bad]}
    (OUT / "compile-probe.json").write_text(json.dumps(summary, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"report: {OUT / 'compile-probe.json'}")
    return 0 if not bad else 4


if __name__ == "__main__":
    raise SystemExit(main())
