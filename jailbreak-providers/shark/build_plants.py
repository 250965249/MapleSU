#!/usr/bin/env python3
"""Build our own per-kernel plants from the retained upstream exploit source.

The source under ``upstream/exploit`` is the public Shark implementation
(GPL-3.0) and carries the per-kernel offset tables.  This script compiles each
``K<version>_plant.c`` with the Android NDK into a standalone AArch64
executable, so the shipped artifacts are built here from source instead of
being the upstream release binaries.

The script verifies every retained source byte against ``manifest.json`` before
building and rewrites the ``plants`` section with the produced digest and size.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
MANIFEST = HERE / "manifest.json"
SOURCE_ROOT = HERE / "upstream/exploit/src"
OUTPUT = HERE / "plants/arm64-v8a"
VERSIONS = ("61821", "61269", "61238", "61258", "61223", "66118", "66127")
TARGET = "aarch64-linux-android31"
# Pinned so two machines produce the same bytes; NDK 28.2 is what the recorded
# artifacts were built with (same generation as the upstream build inputs).
REQUIRED_NDK = "28.2.13676358"
FLAGS = ("-O2", "-fPIC", "-fno-stack-protector", "-D_GNU_SOURCE", "-pthread",
         "-Wl,-z,max-page-size=16384")


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def fail(message: str) -> "NoReturn":
    print("build_plants.py: " + message, file=sys.stderr)
    raise SystemExit(message)


def host_dir() -> str:
    if sys.platform.startswith("win"):
        return "windows-x86_64"
    if sys.platform == "darwin":
        return "darwin-x86_64"
    return "linux-x86_64"


def clang_for(ndk: Path) -> Path:
    suffix = ".exe" if os.name == "nt" else ""
    path = ndk / "toolchains/llvm/prebuilt" / host_dir() / "bin" / ("clang" + suffix)
    if not path.is_file():
        fail("NDK clang not found: " + str(path))
    return path


def default_ndk() -> str:
    explicit = os.environ.get("MAPLESU_NDK")
    if explicit:
        return explicit
    # Prefer the pinned NDK under the installed SDK before any other candidate.
    for key in ("ANDROID_HOME", "ANDROID_SDK_ROOT"):
        sdk = os.environ.get(key)
        pinned = Path(sdk) / "ndk" / REQUIRED_NDK if sdk else None
        if pinned is not None and (pinned / "toolchains/llvm/prebuilt").is_dir():
            return str(pinned)
    candidates = [os.environ.get(key) for key in ("ANDROID_NDK_HOME", "ANDROID_NDK")]
    for key in ("ANDROID_HOME", "ANDROID_SDK_ROOT"):
        sdk = os.environ.get(key)
        if sdk and (Path(sdk) / "ndk").is_dir():
            candidates.extend(str(path) for path in
                              sorted((Path(sdk) / "ndk").iterdir(), reverse=True))
    for value in candidates:
        if value and (Path(value) / "toolchains/llvm/prebuilt").is_dir():
            return value
    fail("pass --ndk or set MAPLESU_NDK / ANDROID_NDK_HOME / ANDROID_NDK")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--ndk", default=None, help="Android NDK root")
    parser.add_argument("--check", action="store_true",
                        help="verify the recorded plants instead of rebuilding")
    args = parser.parse_args()
    document = json.loads(MANIFEST.read_text(encoding="utf-8"))
    for item in document.get("sources") or []:
        source = HERE / item["path"]
        if not source.is_file() or source.stat().st_size != item["bytes"] \
                or sha(source) != item["sha256"]:
            fail("retained source drift: " + item["path"])
    ndk = None
    clang = None
    if not args.check:
        ndk = Path(args.ndk or default_ndk())
        clang = clang_for(ndk)
    OUTPUT.mkdir(parents=True, exist_ok=True)
    recorded = {item.get("name"): item for item in document.get("plants") or []}
    records = []
    for version in VERSIONS:
        source = SOURCE_ROOT / ("K" + version + "_plant.c")
        target = OUTPUT / ("plant-" + version)
        if args.check:
            item = recorded.get(target.name)
            if not target.is_file() or item is None:
                fail("missing plant: " + target.name)
            if item.get("bytes") != target.stat().st_size or item.get("sha256") != sha(target):
                fail("plant drift: " + target.name)
            if item.get("sourceSha256") != sha(source):
                fail("plant source drift: " + target.name)
        else:
            command = [str(clang), "--target=" + TARGET, *FLAGS,
                       "-o", str(target), str(source)]
            subprocess.run(command, check=True)
        records.append({
            "name": target.name,
            "source": source.relative_to(HERE).as_posix(),
            "sourceSha256": sha(source),
            "sha256": sha(target),
            "bytes": target.stat().st_size,
        })
    if not args.check:
        document["plants"] = records
        document["build"] = {
            "target": TARGET,
            "compiler": "Android NDK " + str(ndk.name) + " clang",
            "flags": list(FLAGS),
            "note": "Built by this repository from upstream/exploit; the upstream "
                    "release binaries are not distributed.",
        }
        MANIFEST.write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")
    for record in records:
        print(record["name"], record["bytes"], record["sha256"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
