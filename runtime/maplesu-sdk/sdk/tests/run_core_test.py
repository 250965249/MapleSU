#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""run_core_test.py -- execute the installer-core unit test **on the host**.

Why wasm
--------
The installers are AArch64/Android code (bionic + libc++ + setxattr), so the
shipped objects cannot run on a Windows host.  Their *logic*, however, lives in
`sdk/src/maplesu_assets/maplesu_install_core.h`, which is deliberately freestanding: no
include, no libc, no STL.  This runner compiles that same header plus
`sdk/tests/test_maplesu_install_core.cpp` for `wasm32`, links it with LLD's wasm
flavor, and executes it in Node with the three foreign calls
(alloc / publish / chmod+setxattr) supplied as recording stubs -- i.e. exactly the
"桩替换文件写入/权限调用" the acceptance asks for, running the production code.

What runs
  1. system data dir derivation, 2. the three system data paths, 3. token-search iteration
  counts (737817 / 762225 / 1343921 / 1159233), 4. token replacement boundary
  cases, 5. install_blob success + every failure branch.

Usage
    py runtime/maplesu-sdk/sdk/tests/run_core_test.py
    py runtime/maplesu-sdk/sdk/tests/run_core_test.py --keep   # keep the .wasm

Exit codes: 0 all checks passed, 1 a check failed, 2 the host cannot run the test
(no clang/ld/node) -- never a silent pass.
"""
from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
SDK = os.path.abspath(os.path.join(HERE, ".."))
SRC = os.path.join(HERE, "test_maplesu_install_core.cpp")
OUT_DIR = os.path.join(SDK, "build", "tests")
NDK_BIN = "D:/Maple_Env/Android/Sdk/ndk/26.1.10909125/toolchains/llvm/prebuilt/windows-x86_64/bin"
NODE_CANDIDATES = [
    os.environ.get("MAPLESU_NODE", ""),
    os.path.join(os.path.expanduser("~"), ".dsh", "dsh-runtimes", "dsh-primary-runtime",
                 "dependencies", "node", "bin", "node.exe"),
    "node",
]

JS_DRIVER = r"""
const fs = require('fs');
const path = process.argv[2];
let memory = null;
const text = [];
function cstr(ptr) {
  const bytes = new Uint8Array(memory.buffer);
  let end = ptr;
  while (bytes[end] !== 0) end++;
  return Buffer.from(bytes.slice(ptr, end)).toString('utf8');
}
const imports = {
  env: {
    test_log(ptr) { text.push(cstr(ptr)); },
    memset(ptr, val, n) { new Uint8Array(memory.buffer).fill(val & 0xff, ptr, ptr + n); return ptr; },
    memcpy(dst, src, n) { new Uint8Array(memory.buffer).copyWithin(dst, src, src + n); return dst; },
    memmove(dst, src, n) { new Uint8Array(memory.buffer).copyWithin(dst, src, src + n); return dst; },
  }
};
const module_ = new WebAssembly.Module(fs.readFileSync(path));
const instance = new WebAssembly.Instance(module_, imports);
memory = instance.exports.memory;
const failed = instance.exports.run_all();
const checks = instance.exports.check_count ? instance.exports.check_count() : -1;
process.stdout.write(text.join(''));
console.log(`checks=${checks} failed=${failed}`);
if (failed !== 0) process.exitCode = 1;
"""


def find_node():
    for cand in NODE_CANDIDATES:
        if not cand:
            continue
        if os.path.sep in cand or cand.endswith(".exe"):
            if os.path.isfile(cand):
                return cand
            continue
        found = shutil.which(cand)
        if found:
            return found
    return None


def run_cmd(cmd, what):
    res = subprocess.run(cmd, capture_output=True, text=True)
    if res.returncode != 0:
        print(f"[E] {what} failed (exit {res.returncode})", file=sys.stderr)
        print("    " + " ".join(cmd), file=sys.stderr)
        if res.stdout.strip():
            print(res.stdout, file=sys.stderr)
        if res.stderr.strip():
            print(res.stderr, file=sys.stderr)
        return None
    return res


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--keep", action="store_true", help="keep the generated .wasm/.js")
    args = ap.parse_args(argv)

    clang = os.path.join(NDK_BIN, "clang++.exe")
    lld = os.path.join(NDK_BIN, "ld.lld.exe")
    if not os.path.isfile(clang) or not os.path.isfile(lld):
        print(f"[E] NDK clang/ld.lld not found under {NDK_BIN}", file=sys.stderr)
        return 2
    node = find_node()
    if node is None:
        print("[E] node not found (needed to execute the wasm32 test)", file=sys.stderr)
        return 2

    os.makedirs(OUT_DIR, exist_ok=True)
    obj = os.path.join(OUT_DIR, "test_maplesu_install_core.o")
    wasm = os.path.join(OUT_DIR, "test_maplesu_install_core.wasm")
    js = os.path.join(OUT_DIR, "test_maplesu_install_core.js")

    if run_cmd([clang, "--target=wasm32", "-std=c++20", "-O1", "-Wall", "-Wextra",
                "-nostdlib", "-fno-exceptions", "-fno-rtti",
                "-isystem", os.path.join(SDK, "src", "maplesu_assets"),
                "-c", SRC, "-o", obj], "compile") is None:
        return 2
    if run_cmd([lld, "-flavor", "wasm", "--no-entry", "--export-all", "--allow-undefined",
                obj, "-o", wasm], "link") is None:
        return 2

    with open(js, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(JS_DRIVER)
    res = run_cmd([node, js, wasm], "run")
    if res is None:
        return 1
    sys.stdout.write(res.stdout)
    if not args.keep:
        for p in (obj, wasm, js):
            try:
                os.remove(p)
            except OSError:
                pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
