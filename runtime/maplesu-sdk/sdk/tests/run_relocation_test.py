#!/usr/bin/env python3
"""Compare production relocation bytes with original instructions in Unicorn.

Uses the real C++ decoder, emitter and vendored AsmJit. The only replacement
header is the unused SDK umbrella: no assembler or decoder stub is supplied.
Capstone independently decodes the emitted instructions; Unicorn executes both
paths and compares all X registers, SP, NZCV and the destination PC. It does not
duplicate the production branch-width decision in the test oracle.

Requires the repository llvm-mingw toolchain, capstone and unicorn. Builds only
the focused probe and its AsmJit dependency; never builds or replaces the SDK.
"""
from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
from pathlib import Path
import struct
import subprocess
import sys

from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM
from unicorn import Uc, UC_ARCH_ARM64, UC_MODE_ARM, UC_HOOK_CODE
from unicorn.arm64_const import (UC_ARM64_REG_X0, UC_ARM64_REG_X29,
    UC_ARM64_REG_X30, UC_ARM64_REG_SP, UC_ARM64_REG_PC, UC_ARM64_REG_NZCV)

HERE = Path(__file__).resolve().parent
SDK = HERE.parent
REPO = SDK.parents[2]
ORIGINAL, RELOCATED = 0x300000, 0x500000
REGS = [UC_ARM64_REG_X0 + i for i in range(29)] + [UC_ARM64_REG_X29, UC_ARM64_REG_X30]


def run(argv: list[str], **kwargs) -> str:
    result = subprocess.run(argv, capture_output=True, text=True,
                            encoding='utf-8', errors='replace', **kwargs)
    if result.returncode:
        raise RuntimeError(f"command exit {result.returncode}: {argv}\n{result.stderr}")
    return result.stdout


def build(args, out: Path) -> Path:
    candidates = sorted((REPO / '.research/toolchains').glob('llvm-mingw-*/bin'))
    if not candidates:
        raise RuntimeError('llvm-mingw toolchain missing')
    bindir = candidates[-1]
    cxx = bindir / 'x86_64-w64-mingw32-clang++.exe'
    vendor = SDK / 'third_party/asmjit/1.16.0/src'
    flags = ['-O1', '-std=c++17', '-DASMJIT_STATIC', '-DASMJIT_NO_X86',
             '-DASMJIT_NO_COMPILER', '-DASMJIT_NO_BUILDER', '-I' + str(vendor)]
    library = args.asmjit_lib
    if library is None:
        objdir = out / 'asmjit'
        objdir.mkdir(parents=True, exist_ok=True)
        sources = sorted((vendor / 'asmjit').rglob('*.cpp'))
        objects = [objdir / (source.relative_to(vendor).as_posix().replace('/', '_') + '.o')
                   for source in sources]
        def compile_one(pair):
            source, obj = pair
            run([str(cxx), *flags, '-c', str(source), '-o', str(obj)])
        with ThreadPoolExecutor(max_workers=4) as pool:
            list(pool.map(compile_one, zip(sources, objects)))
        library = out / 'asmjit.a'
        run([str(bindir / 'llvm-ar.exe'), 'rcs', str(library), *map(str, objects)])
    shim = out / 'include'
    shim.mkdir(exist_ok=True)
    (shim / 'kernel_module_kit_umbrella.h').write_text('#pragma once\n', encoding='utf-8')
    exe = out / 'relocation_probe.exe'
    decoder = args.decoder_object or SDK / 'src/aarch64/aarch64_decode_insn.cpp'
    run([str(cxx), *flags, '-include', 'algorithm', '-I' + str(shim), '-I' + str(SDK.parent / 'include'),
         str(HERE / 'relocation_probe.cpp'), str(args.source), str(decoder),
         str(library), '-static', '-o', str(exe)])
    return exe


def cases():
    result = []
    # The oracle is execution of these original encodings, not a copied width test.
    for name, base in [('cbz-w', 0x34000000), ('cbnz-w', 0x35000000),
                       ('cbz-x', 0xb4000000), ('cbnz-x', 0xb5000000)]:
        for reg in (0, 7, 30, 31):
            for offset in (8, -8, 0x7fffc, -0x80000):
                insn = base | (((offset // 4) & 0x7ffff) << 5) | reg
                for value in (0, 1, 0xffffffff, 0x100000000, 0x8000000000000000,
                              0x100000001):
                    result.append((name, insn, reg, value, 0xa0000000))
    extras = [
        ('b-forward', 0x14000002), ('b-backward', 0x17fffffe),
        ('bl-forward', 0x94000002), ('bl-backward', 0x97fffffe),
        ('b.eq', 0x54000040), ('b.ne', 0x54000041),
        ('tbz-low', 0x36000040), ('tbnz-low', 0x37000040),
        ('tbz-high', 0xb6400040), ('tbnz-high', 0xb7400040),
        ('tbz-wzr', 0x3600005f), ('tbnz-wzr', 0x3700005f),
        ('tbz-xzr', 0xb640005f), ('tbnz-xzr', 0xb740005f),
        ('adr-positive', 0x10000805), ('adr-negative', 0x10fff805),
        ('adrp-positive', 0xd0000005), ('adrp-negative', 0xf0ffffe5),
        ('adr-zr-positive', 0x1000081f), ('adr-zr-negative', 0x10fff81f),
        ('adrp-zr-positive', 0xd000001f), ('adrp-zr-negative', 0xf0ffffff),
        ('ldr-w-literal', 0x18000800), ('ldr-x-literal', 0x58000800),
        ('ldrsw-literal', 0x98000800),
    ]
    for name, insn in extras:
        for value in (0, 1, 1 << 40, 0x100000001):
            for flags in (0, 0x60000000):
                result.append((name, insn, 0, value, flags))
    return result


class CPU:
    def __init__(self):
        self.uc = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
        self.uc.mem_map(0x100000, 0x600000)
        self.lo, self.hi = 0, 0
        self.uc.hook_add(UC_HOOK_CODE, self.stop_outside)

    def stop_outside(self, uc, address, size, data):
        if not self.lo <= address < self.hi:
            uc.emu_stop()

    def execute(self, code, address, reg, value, flags):
        uc = self.uc
        uc.mem_write(address, code)
        uc.ctl_remove_cache(address, address + len(code))
        uc.mem_write(ORIGINAL + 0x100, bytes.fromhex('efcdab89674523f1'))
        for i, register in enumerate(REGS):
            uc.reg_write(register, ((i + 1) * 0x01020304050607) & ((1 << 64) - 1))
        if reg != 31:
            uc.reg_write(REGS[reg], value)
        uc.reg_write(UC_ARM64_REG_SP, 0x6ff000)
        uc.reg_write(UC_ARM64_REG_NZCV, flags)
        self.lo, self.hi = address, address + len(code)
        uc.emu_start(address, 0x700000, count=32)
        pc = uc.reg_read(UC_ARM64_REG_PC)
        if pc == RELOCATED + len(code):
            pc = ORIGINAL + 4
        return [uc.reg_read(r) for r in REGS] + [
            uc.reg_read(UC_ARM64_REG_SP), uc.reg_read(UC_ARM64_REG_NZCV), pc]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', required=True, type=Path)
    parser.add_argument('--source', type=Path,
        default=SDK / 'src/aarch64/aarch64_simulate_insn.cpp')
    parser.add_argument('--decoder-object', type=Path)
    parser.add_argument('--asmjit-lib', type=Path)
    parser.add_argument('--expect-failures', action='store_true')
    parser.add_argument('--baseline-registers', action='store_true',
        help='compare old objects on RT/RD 0..30 before their known ZR rejection')
    args = parser.parse_args()
    out = args.out.resolve()
    out.mkdir(parents=True, exist_ok=True)
    exe = build(args, out)
    tests = cases()
    if args.baseline_registers:
        tests = [case for case in tests if (case[1] & 31) != 31]
    unique = list(dict.fromkeys(case[1] for case in tests))
    request = ''.join(f'{word:x} {RELOCATED:x} {ORIGINAL:x}\n' for word in unique)
    lines = run([str(exe)], input=request).splitlines()
    if len(lines) != len(unique):
        raise AssertionError(f'probe returned {len(lines)}/{len(unique)} outputs')
    outputs = dict(zip(unique, lines))
    cpu, decoder = CPU(), Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    failures, records = [], []
    for name, word, reg, value, flags in tests:
        step, hexcode = outputs[word].split()
        original, emitted = struct.pack('<I', word), bytes.fromhex(hexcode)
        expected = cpu.execute(original, ORIGINAL, reg, value, flags)
        actual = cpu.execute(emitted, RELOCATED, reg, value, flags)
        ok = expected == actual
        row = dict(name=name, word=f'{word:08x}', reg=reg, value=f'{value:016x}',
                   nzcv=f'{flags:08x}', steppable=bool(int(step)), emitted=hexcode,
                   original=[f'{i.mnemonic} {i.op_str}' for i in decoder.disasm(original, ORIGINAL)],
                   relocated=[f'{i.mnemonic} {i.op_str}' for i in decoder.disasm(emitted, RELOCATED)],
                   expected_pc=f'{expected[-1]:x}', actual_pc=f'{actual[-1]:x}', passed=ok)
        if not ok:
            row['different_registers'] = [i for i in range(len(expected) - 1)
                                           if expected[i] != actual[i]]
            failures.append(row)
        records.append(row)
    zero_register = subprocess.run([str(exe)], input=f'5800081f {RELOCATED:x} {ORIGINAL:x}\n',
        capture_output=True, text=True, encoding='utf-8', errors='replace')
    report = dict(source=str(args.source.resolve()),
                  source_sha256=hashlib.sha256(args.source.read_bytes()).hexdigest(),
                  decoder_object=str(args.decoder_object) if args.decoder_object else None,
                  tests=len(tests), passed=len(tests)-len(failures), failed=len(failures),
                  failure_examples=failures[:8],
                  known_literal_zero_register_gap=dict(word='5800081f',
                      exit_code=zero_register.returncode, stderr=zero_register.stderr),
                  cases=records)
    (out / 'results.json').write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    print(json.dumps({k:v for k,v in report.items() if k not in ('cases','failure_examples')}))
    if args.expect_failures:
        return 0 if failures else 1
    return int(bool(failures))


if __name__ == '__main__':
    sys.exit(main())
