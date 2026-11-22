#!/usr/bin/env python3
"""Test m034's real AsmJit generation and shared affinity policy on the host.

The OS header and SDK umbrella are test seams; the production m034 TU, policy,
AsmJit and m025 frame source slices remain real. No kernel code is executed.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import struct

from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM

SDK = Path(__file__).resolve().parents[1]
REPO = SDK.parents[2]


def run(argv, **kwargs):
    result = subprocess.run(list(map(str, argv)), capture_output=True, text=True,
                            encoding="utf-8", errors="replace", **kwargs)
    if result.returncode:
        raise RuntimeError(f"exit {result.returncode}: {argv}\n{result.stderr}")
    return result.stdout


def function(text, name):
    start = text.index("void " + name + "(")
    pos, depth = text.index("{", start), 1
    end = pos + 1
    while depth:
        depth += (text[end] == "{") - (text[end] == "}")
        end += 1
    return text[start:end]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--asmjit-lib", type=Path, required=True)
    parser.add_argument("--source", type=Path, default=SDK / "src/icache_sync/module_base_cpu_icache_sync.cpp")
    args = parser.parse_args()
    out = args.out.resolve(); out.mkdir(parents=True, exist_ok=True)
    shim = out / "include"; shim.mkdir(exist_ok=True)
    (shim / "kernel_module_kit_umbrella.h").write_text("""#pragma once
#include "aarch64_asm_helper.h"
#include "module_err_def.h"
namespace kernel_module {
void arm64_module_asm_func_start(asmjit::a64::Assembler*);
void arm64_module_asm_func_end(asmjit::a64::Assembler*);
KModErr execute_kernel_asm_func(const std::vector<uint8_t>&, uint64_t&);
}
""", encoding="utf-8")
    (shim / "sched.h").write_text("""#pragma once
#include <cstddef>
struct alignas(8) cpu_set_t { unsigned char bits[128]; };
inline int sched_getaffinity(int, size_t, cpu_set_t*) { return -1; }
inline int sched_setaffinity(int, size_t, const cpu_set_t*) { return -1; }
inline int sched_getcpu() { return -1; }
""", encoding="utf-8")
    executor = SDK / "src/module_base/module_base_kernel_func_executor.cpp"
    text = executor.read_text(encoding="utf-8-sig")
    start = function(text, "arm64_module_asm_func_start")
    end = function(text, "arm64_module_asm_func_end")
    finish = function(text, "standard_frame_end")
    source_slice = "\nnamespace kernel_module {\n" + finish + "\n" + start.replace("arm64_module_asm_func_start", "production_frame_start", 1) + "\n" + end.replace("arm64_module_asm_func_end", "production_frame_end", 1) + "\n}\n"
    frame = out / "production_frame.cpp"
    frame.write_text('#include "kernel_module_kit_umbrella.h"\n#include "private_module_base_kernel_func_executor.h"\n' + source_slice, encoding="utf-8")
    cxx = sorted((REPO / ".research/toolchains").glob("llvm-mingw-*/bin/x86_64-w64-mingw32-clang++.exe"))[-1]
    exe = out / "icache_probe.exe"
    command = [cxx, "-std=c++20", "-O1", "-DASMJIT_NO_X86", "-DASMJIT_NO_COMPILER", "-DASMJIT_NO_BUILDER", "-include", "algorithm", "-I" + str(shim), "-I" + str(SDK.parent / "include"), "-I" + str(SDK / "include"), "-I" + str(SDK / "src/icache_sync"), SDK / "tests/icache_probe.cpp", args.source, frame, args.asmjit_lib.resolve(), "-static", "-o", exe]
    run(command)
    policy_count, policy_failed = map(int, run([exe]).split())
    generated = []
    begin_flag = struct.pack('<IHHII', 0x3146534d, 1, 16, 1, 0)
    end_flag = struct.pack('<IHHII', 0x3146534d, 1, 16, 2, 0)
    oracle = bytes.fromhex("1f7508d59f3b03d5df3f03d5")
    for status in (0, -19990, -19995, 0x100000007):
        fields = run([exe, "generator", status]).strip().split()
        if len(fields) == 5:
            fields.append("")
        result, initial, starts, ends, executes, hex_bytes = fields
        code = bytes.fromhex(hex_bytes)
        begin_at, end_at = code.find(begin_flag), code.find(end_flag)
        body_offset = begin_at + len(begin_flag)
        body = code[body_offset:end_at - 4] if begin_at >= 0 and end_at >= body_offset else b""
        decoded = [(i.mnemonic, i.op_str) for i in Cs(CS_ARCH_ARM64, CS_MODE_ARM).disasm(body, 0)]
        passed = int(result) == status and int(initial) == 0 and (starts, ends, executes) == ("1", "1", "1") and body == oracle and code[:4] == bytes.fromhex("5f2403d5") and code[-4:] == bytes.fromhex("c0035fd6")
        generated.append({"input_status": status, "returned_status": int(result), "output_initial": int(initial), "frame_start_calls": int(starts), "frame_end_calls": int(ends), "execute_calls": int(executes), "bytes": len(code), "body_hex": body.hex(), "decoded_body": decoded, "passed": passed})
        (out / f"generated-{status}.bin").write_bytes(code)
    result = {"source": str(args.source.resolve()), "source_sha256": hashlib.sha256(args.source.read_bytes()).hexdigest(), "policy_header": str(SDK / "src/icache_sync/icache_policy.h"), "policy_sha256": hashlib.sha256((SDK / "src/icache_sync/icache_policy.h").read_bytes()).hexdigest(), "frame_source": str(executor), "frame_slice_sha256": hashlib.sha256(source_slice.encode()).hexdigest(), "command": list(map(str, command)), "policy_and_exception_cases": policy_count, "policy_and_exception_failed": policy_failed, "generator_cases": generated, "scope": "host source generation/control flow only; no SMP or kernel execution evidence"}
    (out / "results.json").write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"policy_cases": policy_count, "policy_failed": policy_failed, "generator_cases": len(generated), "generator_passed": sum(c["passed"] for c in generated)}, indent=2))
    return 0 if policy_failed == 0 and all(c["passed"] for c in generated) else 1


if __name__ == "__main__":
    raise SystemExit(main())
