#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""run_helper_test.py -- execute the boot helper's transaction logic on the host.

The helper sources are AArch64/Android code, but their boot-session state
machine and privileged primitives only talk to the outside world through
`struct helper_ops` (see `sdk/src/helper/private/helper_ops.h`).  This runner
compiles the **production sources** plus `tests/test_helper_core.cpp` for
`wasm32`, links a no-libc module, and executes it in Node.  The test binds the
ops table to an in-memory filesystem, a recording shell runner, a fake dynamic
loader and a recording exec, i.e. every syscall the helper owns is injected.

What runs
  1. boot session state machine: flag '1'/'2'/'3', duplicate guard, protection
     gate, completion and work receipts;
  2. the guarded boot order: lock, credentials, policy backend, su delivery,
     property cleanup, commit;
  3. `maplesu_helper_su_write`: delivery, stale-copy revoke, validation,
     closed-surface-on-failure;
  4. `maplesu_helper_su_exec`: delivered-copy resolution, PATH prefixing,
     rejection of unauthorized/closed deliveries.

Usage
    py runtime/maplesu-sdk/sdk/tests/run_helper_test.py
    py runtime/maplesu-sdk/sdk/tests/run_helper_test.py --keep

Exit codes: 0 all checks passed, 1 a check failed, 2 the host cannot run the
test (no clang/ld/node) -- never a silent pass.
"""
from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
SDK = HERE.parent
TEST_SOURCE = HERE / "test_helper_core.cpp"
INCLUDE = SDK / "src" / "helper"
OUT_DIR = SDK / "build" / "tests"
NDK_BIN = Path("D:/Maple_Env/Android/Sdk/ndk/26.1.10909125/toolchains/llvm/prebuilt/"
               "windows-x86_64/bin")
NODE_CANDIDATES = [
    os.environ.get("MAPLESU_NODE", ""),
    str(Path.home() / ".dsh" / "dsh-runtimes" / "dsh-primary-runtime" / "dependencies"
        / "node" / "bin" / "node.exe"),
    "node",
]

JS_DRIVER = r"""
const fs = require('fs');
const path = process.argv[2];
const bytes = fs.readFileSync(path);
let instance = null;
const output = [];
const imports = {
  env: {
    memcpy(destination, source, length) {
      const memory = new Uint8Array(instance.exports.memory.buffer);
      memory.copyWithin(destination, source, source + length);
      return destination;
    },
    test_report(pointer, length) {
      const memory = new Uint8Array(instance.exports.memory.buffer);
      output.push(Buffer.from(memory.slice(pointer, pointer + length)).toString('utf8'));
    },
  },
};
WebAssembly.instantiate(bytes, imports).then(({ instance: wired }) => {
  instance = wired;
  const code = instance.exports.test_main();
  process.stdout.write(output.join('\n'));
  if (output.length === 0) process.stdout.write('FAIL no test output was reported\n');
  process.exit(code === 0 ? 0 : 1);
}).catch((error) => {
  process.stderr.write('wasm instantiate failed: ' + error.message + '\n');
  process.exit(2);
});
"""


def find_node() -> str | None:
    for candidate in NODE_CANDIDATES:
        if not candidate:
            continue
        resolved = shutil.which(candidate) if os.sep not in candidate else candidate
        if resolved and Path(resolved).is_file():
            return resolved
    return None


def run(argv: list[str], timeout: int = 120) -> subprocess.CompletedProcess[str]:
    return subprocess.run(argv, capture_output=True, text=True, encoding="utf-8",
                          errors="replace", timeout=timeout, cwd=str(SDK))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--keep", action="store_true", help="keep the generated wasm module")
    parser.add_argument("--ndk", type=Path, default=NDK_BIN)
    args = parser.parse_args(argv)

    node = find_node()
    if not node:
        print("[helper-test] node not found (set MAPLESU_NODE)", file=sys.stderr)
        return 2
    clang = args.ndk / ("clang++.exe" if os.name == "nt" else "clang++")
    if not clang.is_file():
        print(f"[helper-test] clang++ not found: {clang}", file=sys.stderr)
        return 2

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    object_path = OUT_DIR / "test_helper_core.o"
    wasm_path = OUT_DIR / "test_helper_core.wasm"
    compile_argv = [
        str(clang), "--target=wasm32", "-std=c++20", "-O2", "-ffreestanding",
        "-fno-exceptions", "-fno-rtti", "-fno-builtin", "-nostdlibinc",
        "-Wall", "-Wextra", "-Werror", f"-I{INCLUDE}",
        "-Wno-unused-const-variable", "-Wno-unused-variable",
        "-c", str(TEST_SOURCE), "-o", str(object_path),
    ]
    compiled = run(compile_argv)
    if compiled.returncode != 0:
        print("[helper-test] compile failed:\n" + compiled.stdout + compiled.stderr,
              file=sys.stderr)
        return 2
    lld = args.ndk / ("ld.lld.exe" if os.name == "nt" else "ld.lld")
    if not lld.is_file():
        print(f"[helper-test] ld.lld not found: {lld}", file=sys.stderr)
        return 2
    link_argv = [
        str(lld), "-flavor", "wasm", "--no-entry", "--export=test_main",
        "--export=memory", "--allow-undefined",
        "--initial-memory=4194304", "--max-memory=67108864",
        str(object_path), "-o", str(wasm_path),
    ]
    linked = run(link_argv)
    if linked.returncode != 0:
        print("[helper-test] link failed:\n" + linked.stdout + linked.stderr, file=sys.stderr)
        return 2

    driver_path = OUT_DIR / "helper_test_driver.js"
    driver_path.write_text(JS_DRIVER, encoding="utf-8")
    executed = run([node, str(driver_path), str(wasm_path)], timeout=180)
    sys.stdout.write(executed.stdout)
    if executed.stderr.strip():
        sys.stderr.write(executed.stderr)
    if executed.returncode != 0:
        print(f"[helper-test] FAILED (exit {executed.returncode})", file=sys.stderr)
        return 1
    passes = executed.stdout.count("PASS ")
    fails = executed.stdout.count("FAIL ")
    print(f"[helper-test] passed {passes} checks, failed {fails}")
    if not args.keep:
        object_path.unlink(missing_ok=True)
        wasm_path.unlink(missing_ok=True)
        driver_path.unlink(missing_ok=True)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
