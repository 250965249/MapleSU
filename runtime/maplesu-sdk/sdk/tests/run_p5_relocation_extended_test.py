#!/usr/bin/env python3
"""Run focused current-source relocation extensions and branch boundary checks.

Uses the production emitter, decoder and branch encoder. Unicorn executes the
original as the oracle; Capstone checks branch destinations independently.
"""
from pathlib import Path
from types import SimpleNamespace
import argparse
import hashlib
import json
import struct
import subprocess
import sys

from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM
from unicorn.arm64_const import UC_ARM64_REG_Q0
import run_relocation_test as oracle


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', required=True, type=Path)
    parser.add_argument('--asmjit-lib', required=True, type=Path)
    args = parser.parse_args()
    out = args.out.resolve()
    out.mkdir(parents=True, exist_ok=True)
    source = oracle.SDK / 'src/aarch64/aarch64_simulate_insn.cpp'
    decoder = oracle.SDK / 'src/aarch64/aarch64_decode_insn.cpp'
    exe = oracle.build(SimpleNamespace(asmjit_lib=args.asmjit_lib.resolve(),
        source=source, decoder_object=decoder), out)
    rows = []

    class CPU(oracle.CPU):
        def execute(self, *arguments):
            for index in range(32):
                self.uc.reg_write(UC_ARM64_REG_Q0 + index, ((index + 1) << 100) | 0xabcdef)
            result = super().execute(*arguments)
            return result + [self.uc.reg_read(UC_ARM64_REG_Q0 + index) for index in range(32)]

    cases = [('ldr-wzr', 0x1800081f), ('ldr-xzr', 0x5800081f),
        ('ldrsw-xzr', 0x9800081f), ('ldr-s', 0x1c000800),
        ('ldr-d', 0x5c000800), ('ldr-q', 0x9c000800),
        ('ldr-q31', 0x9c00081f), ('prfm', 0xd8000800)]
    cpu = CPU()
    for name, word in cases:
        for emitted_address in (oracle.RELOCATED, oracle.ORIGINAL + 0x1000):
            line = oracle.run([str(exe)], input=f'{word:x} {emitted_address:x} {oracle.ORIGINAL:x}\n').strip()
            step, code = line.split()
            emitted = bytes.fromhex(code)
            for value in (0, 1, 0x100000000, 0xdeadbeef12345678):
                expected = cpu.execute(struct.pack('<I', word), oracle.ORIGINAL, 0, value, 0x60000000)
                actual = cpu.execute(emitted, emitted_address, 0, value, 0x60000000)
                # The original oracle normalizes the default relocated fallthrough.
                if emitted_address != oracle.RELOCATED and actual[33] == emitted_address + len(emitted):
                    actual[33] = oracle.ORIGINAL + 4
                passed = expected == actual
                rows.append(dict(case=name, near=emitted_address != oracle.RELOCATED,
                    word=f'{word:08x}', value=value, passed=passed))
                assert passed, rows[-1]
    word = 0xd63f0020
    line = oracle.run([str(exe)], input=f'{word:x} {oracle.RELOCATED:x} {oracle.ORIGINAL:x}\n').strip()
    emitted = bytes.fromhex(line.split()[1])
    assert cpu.execute(struct.pack('<I', word), oracle.ORIGINAL, 1, 0x300100, 0x60000000) == cpu.execute(
        emitted, oracle.RELOCATED, 1, 0x300100, 0x60000000)
    rows.append(dict(case='blr-x1-original-lr', passed=True))
    for name, word, relocated, original in [
        ('branch-over-4GiB', 0x14000002, 0x100500000, 0x300000),
        ('branch-over-128MiB', 0x14000002, 0x100000, 0x9000000),
        ('blr-x30', 0xd63f03c0, 0x500000, 0x300000),
        ('svc-pc-visible', 0xd4000001, 0x500000, 0x300000),
        ('auth-blr', 0xd73f0801, 0x500000, 0x300000)]:
        result = subprocess.run([str(exe)], input=f'{word:x} {relocated:x} {original:x}\n',
            capture_output=True, text=True)
        assert result.returncode != 0, name
        rows.append(dict(case=name, passed=True, explicitUnsupported=True))
    cxx = sorted((oracle.REPO / '.research/toolchains').glob('llvm-mingw-*/bin/x86_64-w64-mingw32-clang++.exe'))[-1]
    branch = out / 'p5_branch_probe.exe'
    oracle.run([str(cxx), '-std=c++17', '-O1', str(oracle.HERE / 'p5_branch_probe.cpp'), '-static', '-o', str(branch)])
    edges = [(0x10000000, 0x17fffffc, True), (0x10000000, 0x18000000, False),
        (0x10000000, 0x08000000, True), (0x10000000, 0x07fffffc, False),
        (0x10000000, 0x10000000, True), (0x10000001, 0x10000000, False),
        (0x10000000, 0x10000001, False), (0x10000000, 0x110000000, False),
        (0x110000000, 0x10000000, False), (0, 0x07fffffc, True), (0, 0x08000000, False),
        (0xfffffffffffffff8, 0xfffffffffffffffc, True),
        (0xfffffffffffffffc, 0xfffffffff7fffffc, True),
        (0xfffffffffffffffc, 0, False), (0, 0xfffffffffffffffc, False)]
    outputs = oracle.run([str(branch)], input=''.join(f'{a:x} {b:x}\n' for a, b, _ in edges)).splitlines()
    assert len(outputs) == len(edges)
    capstone = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    capstone.detail = True
    for (origin, target, expected), line in zip(edges, outputs):
        accepted, word = line.split()
        accepted = accepted == '1'
        assert accepted == expected, (origin, target)
        if accepted:
            instruction = next(capstone.disasm(struct.pack('<I', int(word, 16)), origin))
            assert instruction.operands[0].imm & ((1 << 64) - 1) == target
        rows.append(dict(case='full-width-branch', origin=origin, target=target, passed=True))
    inputs = [source, decoder, oracle.SDK / 'src/aarch64/branch_encoding.h',
        Path(__file__), oracle.HERE / 'p5_branch_probe.cpp']
    report = dict(passed=True, tests=len(rows), cases=rows,
        inputs=[dict(path=str(p), sha256=hashlib.sha256(p.read_bytes()).hexdigest()) for p in inputs],
        scope='production emitted code in Unicorn/Capstone; no hardware PAC/BTI/CFI/GCS or kernel/SMP claim')
    (out / 'results.json').write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    print(json.dumps({k: report[k] for k in ('passed', 'tests', 'scope')}))
    return 0


if __name__ == '__main__':
    sys.exit(main())
