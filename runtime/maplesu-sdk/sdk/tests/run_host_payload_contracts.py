#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""run_host_payload_contracts.py -- host acceptance for the embedded payload programs.

The payload programs are AArch64 Android executables; they cannot run on the build
host.  Their contracts are still testable, because the parts that define them are
platform-independent and compiled from the same sources:

1. ``host_payload_contracts`` -- contract checks:
   * ``webui_loader`` launch-argument validation and path derivation, plus the real
     static HTTP fallback server (CivetWeb started on loopback, raw HTTP client);
   * ``resetprop`` CLI grammar, ``-f`` file grammar and the persistent-properties
     protobuf codec (byte-stable round trip);
   * ``su`` CLI grammar, legacy option rewrites and ``-c`` folding;
   * the installer feature-token discipline shared by the program trees.

2. ``host_payload_differential`` -- behaviour equivalence against the reference
   implementation:
   * ``su``: production parser vs the open-edition su client parser (same argv);
   * ``resetprop``: production command logic vs the Magisk v30.7 applet logic,
     driven through the same simulated platform, comparing exit status, stdout,
     the full platform-operation trace and the resulting state.

Build toolchain: the repository's llvm-mingw prebuilt (host Windows target),
located under ``.research/toolchains/``.  Absent toolchain => exit 2 (environment
limitation, not a payload failure).

Usage
    py runtime/maplesu-sdk/sdk/tests/run_host_payload_contracts.py
    py runtime/maplesu-sdk/sdk/tests/run_host_payload_contracts.py --json out.json

Exit codes: 0 all checks pass, 1 a check failed, 2 cannot build/run.
"""
from __future__ import annotations

import argparse
import glob
import json
import subprocess
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
SDK = HERE.parent
REPO = SDK.parent.parent.parent

PAYLOAD = SDK / "src" / "payload"
CIVETWEB = PAYLOAD / "webui_loader" / "third_party" / "civetweb"
OUT_DIR = SDK / "build" / "tests"

DEFINES = ["NO_SSL", "NO_CGI", "NO_CACHING", "NO_SSL_DL"]

INCLUDE_DIRS = [
    PAYLOAD,
    PAYLOAD / "common",
    PAYLOAD / "webui_loader" / "src",
    CIVETWEB / "include",
    HERE / "host_reference",
]

C_SOURCES = [
    HERE / "host_win_compat.c",
    CIVETWEB / "src" / "civetweb.c",
]

CONTRACT_SOURCES = [
    HERE / "host_payload_contracts.cpp",
    PAYLOAD / "webui_loader" / "src" / "webroot_server.cpp",
    CIVETWEB / "src" / "CivetServer.cpp",
]

DIFFERENTIAL_SOURCES = [
    HERE / "host_payload_differential.cpp",
    PAYLOAD / "resetprop" / "src" / "prop_command.cpp",
]


def find_toolchain() -> tuple[Path, Path] | None:
    suffix = ".exe" if sys.platform == "win32" else ""
    bases = glob.glob(str(REPO / ".research" / "toolchains" / "llvm-mingw-*" / "bin"))
    for base in bases:
        cxx = Path(base) / f"x86_64-w64-mingw32-clang++{suffix}"
        cc = Path(base) / f"x86_64-w64-mingw32-clang{suffix}"
        if cxx.is_file() and cc.is_file():
            return cxx, cc
    return None


def run(command: list[str], timeout: int) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, capture_output=True, text=True, encoding="utf-8",
                          errors="replace", timeout=timeout)


def build(compiler: tuple[Path, Path], name: str, cpp_sources: list[Path],
          objects: list[Path], with_civetweb: bool) -> Path | None:
    cxx, cc = compiler
    common = ["-O1", "-g0"]
    common += [f"-D{define}" for define in DEFINES]
    common += [f"-I{directory}" for directory in INCLUDE_DIRS]

    if with_civetweb:
        for source in C_SOURCES:
            obj = OUT_DIR / (source.stem + ".o")
            result = run([str(cc), *common, "-w", "-c", str(source), "-o", str(obj)], 600)
            if result.returncode != 0:
                print(result.stderr[-6000:], file=sys.stderr)
                print(f"[E] host build failed in {source.name}", file=sys.stderr)
                return None
            objects = [*objects, obj]

    binary = OUT_DIR / f"{name}.exe"
    command = [str(cxx), "-std=c++17", *common, "-Wall", "-Wextra",
               "-Wno-unused-parameter", *[str(path) for path in cpp_sources],
               *[str(obj) for obj in objects], "-static", "-lws2_32", "-o", str(binary)]
    result = run(command, 600)
    if result.returncode != 0:
        print(result.stderr[-8000:], file=sys.stderr)
        print(f"[E] host build failed for {name}", file=sys.stderr)
        return None
    return binary


def execute(binary: Path, timeout: int) -> subprocess.CompletedProcess[str]:
    return subprocess.run([str(binary)], capture_output=True, text=True,
                          encoding="utf-8", errors="replace", timeout=timeout)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="host contract + differential tests")
    parser.add_argument("--json", default=None, help="machine-readable result path")
    parser.add_argument("--keep", action="store_true", help="keep built executables")
    args = parser.parse_args(argv)

    compiler = find_toolchain()
    if compiler is None:
        print("[E] llvm-mingw host toolchain not found under .research/toolchains/",
              file=sys.stderr)
        return 2
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    started = time.time()
    report: dict = {
        "schema": "maplesu-payload-host-contracts/1",
        "compiler": str(compiler[0]),
        "suites": {},
    }
    exit_code = 0

    contract = build(compiler, "host_payload_contracts", CONTRACT_SOURCES, [],
                     with_civetweb=True)
    if contract is not None:
        result = execute(contract, 180)
        sys.stdout.write(result.stdout)
        suite = {"exit": result.returncode, "output": result.stdout.strip().splitlines()[-1]
                 if result.stdout.strip() else ""}
        if result.returncode != 0:
            exit_code = 1
        report["suites"]["contracts"] = suite

    differential = build(compiler, "host_payload_differential", DIFFERENTIAL_SOURCES, [],
                         with_civetweb=False)
    if differential is not None:
        result = execute(differential, 180)
        sys.stdout.write(result.stdout)
        if result.stderr:
            sys.stderr.write(result.stderr)
        lines = result.stdout.strip().splitlines()
        checks = next((line.strip() for line in lines if "check(s)" in line), "")
        not_run = [line.strip() for line in lines if line.strip().startswith("- ")]
        table = [line[len("[check] "):] for line in lines if line.startswith("[check] ")]
        table_path = OUT_DIR / ".." / "test-report" / "host-payload-differential-table.txt"
        table_path.parent.mkdir(parents=True, exist_ok=True)
        table_path.write_text("\n".join(table) + "\n", encoding="utf-8")
        report["suites"]["differential"] = {
            "exit": result.returncode,
            "checks": checks,
            "table_path": str(table_path.resolve().relative_to(SDK)),
            "table": table,
            "not_run": not_run,
        }
        if result.returncode != 0:
            exit_code = 1

    # The last executed suite's summary is the interactive summary line.
    report["duration_seconds"] = round(time.time() - started, 2)
    report["exit"] = exit_code
    if args.json:
        path = Path(args.json)
        if not path.is_absolute():
            path = SDK / path
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
        print(f"[report] {path}")
    if not args.keep:
        for binary in (contract, differential):
            if binary is not None and binary.is_file() and exit_code == 0:
                binary.unlink(missing_ok=True)
    print(f"[{'ok' if exit_code == 0 else 'FAIL'}] host payload acceptance "
          f"({report['duration_seconds']}s)")
    return exit_code


if __name__ == "__main__":
    sys.exit(main())
