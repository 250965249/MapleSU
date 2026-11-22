#!/usr/bin/env python3
"""Compile the real m023 TU and exercise Key/v2 management with a transport seam."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[5]
IMAGE = "sha256:272ada1e61c525116032246df2a790d1ccec1804b7a9e0b09203c5e650dcb78e"
CASES = ["roundtrip", "execute", "release", "bounds", "open-unknown", "exec-unknown",
         "negative", "exec-effect-error", "release-error", "close-error", "key-change",
         "fork", "old-v2", "bad-unsupported", "bad-completion", "threads", "allocation-failure",
         "write-error-cleanup", "exec-error-cleanup", "write-unknown", "close-unknown",
         "closed-address", "return-bits", "old-no-v2", "cross-thread", "real-fork",
         "credential-success", "credential-error", "credential-identity", "reused-address",
         "end-write-error", "end-alloc-error", "end-exec-error"]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--sanitize", action="store_true")
    parser.add_argument("--case", choices=CASES)
    args = parser.parse_args()
    out = args.out.resolve()
    out.mkdir(parents=True, exist_ok=True)
    (out / "kernel_module_kit_umbrella.h").write_text(
        '#pragma once\n#include "module_err_def.h"\n', encoding="utf-8")
    (out / "module_base_kernel_mem.h").write_text(
        '#pragma once\nnamespace kernel_module { uint32_t get_page_size(); }\n', encoding="utf-8")
    docker = ["docker", "run", "--rm", "--pull", "never", "--network", "none", "--read-only",
              "--tmpfs", "/tmp:rw,size=32m", "-e", "ASAN_OPTIONS=detect_leaks=1",
              "-e", "UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1",
              "--mount", f"type=bind,source={ROOT},target=/repo,readonly",
              "--mount", f"type=bind,source={out},target=/work", "-w", "/work", IMAGE]
    sources = [HERE / "test_key_management.cpp",
               ROOT / "runtime/maplesu-sdk/sdk/src/kernel_request/module_base_kernel_request.cpp",
               ROOT / "runtime/maplesu-sdk/sdk/src/module/module_current_identity.cpp"]
    inputs = [Path(__file__).resolve(), *sources,
              ROOT / "runtime/maplesu-sdk/sdk/include/maplesu_request_private.h",
              ROOT / "runtime/ultra/authorization/request_protocol.h"]
    before = {path.relative_to(ROOT).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest() for path in inputs}
    compile_command = [*docker, "g++", "-std=c++20", "-O1", "-g", "-pthread",
                       *(["-fsanitize=address,undefined", "-fno-omit-frame-pointer", "-fno-pie", "-no-pie"]
                         if args.sanitize else []), "-I/work", "-I/repo/runtime/maplesu-sdk/sdk/include",
                       "-I/repo/runtime/maplesu-sdk/include",
                       *["/repo/" + path.relative_to(ROOT).as_posix() for path in sources],
                       "-Wl,--wrap=syscall,--wrap=getpid,--wrap=getuid,--wrap=geteuid,--wrap=getresuid,--wrap=getresgid,"
                       "--wrap=__get_current_module_root_key_hd04aBTnbSZlTRP7S4mQpIeVvr2ssGjW,--wrap=_Znwm",
                       "-o", "key-management-test"]
    results = []

    def run(name, command):
        completed = subprocess.run(list(map(str, command)), capture_output=True, text=True,
                                   encoding="utf-8", errors="replace")
        output = completed.stdout + completed.stderr
        (out / f"{name}.log").write_text(output, encoding="utf-8")
        print(output, end="", flush=True)
        results.append({"name": name, "argv": list(map(str, command)), "exit": completed.returncode})
        return completed.returncode == 0

    success = run("compile", compile_command)
    if success:
        for case in ([args.case] if args.case else CASES):
            success = run(case, [*docker, "./key-management-test", case]) and success
    unchanged = all(hashlib.sha256((ROOT / path).read_bytes()).hexdigest() == digest for path, digest in before.items())
    success = success and unchanged
    (out / "results.json").write_text(json.dumps({"passed": success, "sanitized": args.sanitize,
        "scope": "actual m023 client TU; captured syscall provider, not device execution",
        "sources": before, "sourcesUnchanged": unchanged,
        "results": results}, indent=2) + "\n", encoding="utf-8")
    return 0 if success else 1


if __name__ == "__main__":
    sys.exit(main())
