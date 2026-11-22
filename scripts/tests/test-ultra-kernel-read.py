"""Build the kernel-read wrapper offline and replay its generated ARM64 callbacks."""
import argparse
import json
from pathlib import Path
import struct
import subprocess

from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM
from unicorn import Uc, UC_ARCH_ARM64, UC_MODE_ARM, UC_HOOK_CODE
from unicorn import arm64_const as reg

p = argparse.ArgumentParser(description=__doc__)
p.add_argument('--ndk', required=True, type=Path)
p.add_argument('--build', required=True, type=Path)
p.add_argument('--frame', required=True, type=Path, help='Captured real SDK task-comm probe JSON')
p.add_argument('--baseline', type=Path, help='Replay report from the original boot command2; exits red')
a = p.parse_args()
root = Path(__file__).resolve().parents[2]
out = a.build.resolve()
out.mkdir(parents=True, exist_ok=True)
if a.baseline:
    report = json.loads(a.baseline.read_text(encoding='utf-8-sig'))
    fault = next(case for case in report['cases'] if not case['mapped'])
    assert fault['error'] and fault['fault']['pc'] == '0x170'
    print('FAIL original command2 dereferences the unmapped source at +0x170')
    raise SystemExit(1)

frame = bytes.fromhex(json.loads(a.frame.read_text(encoding='utf-8-sig'))['generatedCodeHex'])
decoder = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
decoded = {offset: next(decoder.disasm(frame[offset:offset + 4], offset))
           for offset in (0x30, 0x78, 0xbc, 0xc0)}
assert decoded[0x30].mnemonic == 'b' and decoded[0x78].mnemonic == 'b'
assert decoded[0xbc].mnemonic == 'mov' and decoded[0xc0].mnemonic == 'ldp'
(out / 'frame-start.bin').write_bytes(frame[:0x74])
tail = bytearray(frame[0x78:])
tail[0x44:0x48] = struct.pack('<I', 0xaa0003e0)  # End helper returns x0.
(out / 'frame-end.bin').write_bytes(tail)

tool = a.ndk / 'toolchains/llvm/prebuilt/windows-x86_64/bin/clang++.exe'
compiled = subprocess.run([str(tool), '--target=aarch64-linux-android31', '-std=c++17',
    '-fsyntax-only', '-Werror', '-Wno-packed-non-pod', '-I' + str(root / 'runtime/maplesu-sdk/include'),
    str(root / 'runtime/ultra/authorization/kernel_read.cpp')], capture_output=True, text=True)
assert compiled.returncode == 0, compiled.stdout + compiled.stderr

script = r'''set -eu
cd /case
C=/opt/ddk/clang/clang-r510928
S=/repo/patch-engine/upstream/3rdparty/asmjit2-src/src/asmjit
$C/bin/clang++ -std=c++17 -stdlib=libc++ -O0 -ffunction-sections -fdata-sections \
 -DASMJIT_STATIC -DASMJIT_NO_X86 -DASMJIT_NO_COMPILER -DASMJIT_NO_BUILDER -DASMJIT_NO_JIT \
 -I/repo/runtime/maplesu-sdk/include -I$S/.. \
 /repo/runtime/ultra/authorization/kernel_read.cpp /repo/runtime/tests/pro_kernel_read_test.cpp \
 $S/core/*.cpp $S/arm/*.cpp -Wl,--gc-sections -Wl,-rpath,$C/lib/x86_64-unknown-linux-gnu \
 -pthread -ldl -o kernel-read.test
for mode in good older missing raw-only fault cross-page-fault copy-fault execute-error bootstrap-fault bad-anchor; do
 ./kernel-read.test "$mode" frame-start.bin frame-end.bin
done
'''
run = subprocess.run(['docker', 'run', '--rm', '--network', 'none', '--mount',
    f'type=bind,source={root},target=/repo,readonly', '--mount',
    f'type=bind,source={out},target=/case', '--entrypoint', 'sh',
    'ghcr.io/ylarod/ddk-min:android15-6.6-20260828', '-c', script], capture_output=True, text=True)
(out / 'kernel-read.log').write_text(run.stdout + run.stderr, encoding='utf-8')
assert run.returncode == 0, run.stdout + run.stderr

CODE, STACK, REQUEST, CRED, STOP = 0x100000, 0x400000, 0x500000, 0x600000, 0x700000
SOURCE, METADATA = 0xffff800000500ff8, 0xffff800000700010
NOFAULT, COPY_USER = 0xffff800000900000, 0xffff800000901000
MASK = (1 << 64) - 1
cases = []
for line in run.stdout.splitlines():
    if not line.startswith('capture='):
        continue
    kind, index, mode, metadata_offset, metadata_size, code_hex = line[8:].split(',')
    metadata_offset, metadata_size = int(metadata_offset), int(metadata_size)
    index, code = int(index), bytes.fromhex(code_hex)
    # Replay each real callback with external kernel routines modeled at their ABI.
    for fault in ([False, True] if kind == 'bootstrap' else [False]):
        u = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
        for addr in (CODE, STACK, REQUEST, CRED, STOP, SOURCE & ~4095, METADATA & ~4095, NOFAULT):
            u.mem_map(addr, 0x10000 if addr < 0x8000000000000000 else 0x2000)
        u.mem_write(CODE, code)
        u.mem_write(SOURCE, bytes((i * 37 + 11) & 255 for i in range(600)))
        u.mem_write(METADATA, bytes(range(0x10, 0x44)))
        u.reg_write(reg.UC_ARM64_REG_SP, STACK + 0x8000)
        u.reg_write(reg.UC_ARM64_REG_X30, STOP)
        u.reg_write(reg.UC_ARM64_REG_X11, REQUEST)
        u.reg_write(reg.UC_ARM64_REG_X17, CRED + 0x10)
        original = {i: 0xabc000 + i for i in range(19, 30)}
        for i, value in original.items():
            u.reg_write(getattr(reg, f'UC_ARM64_REG_X{i}'), value)
        saved_par = 0x12345000
        u.reg_write(reg.UC_ARM64_REG_PAR_EL1, saved_par)
        state = {'nofault': 0, 'copy': 0, 'copied': b'', 'target': None, 'daif': 0x80}
        if kind == 'bootstrap' and fault:
            u.mem_unmap(METADATA & ~4095, 0x2000)
        if kind == 'read' and mode == 'fault':
            u.mem_unmap(SOURCE & ~4095, 0x2000)
        if kind == 'read' and mode == 'cross-page-fault':
            u.mem_unmap((SOURCE & ~4095) + 0x1000, 0x1000)

        def get(i): return u.reg_read(getattr(reg, f'UC_ARM64_REG_X{i}'))

        def returned(value):
            link = get(30)
            for i in range(1, 18):
                u.reg_write(getattr(reg, f'UC_ARM64_REG_X{i}'), 0xbad000 + i)
            u.reg_write(reg.UC_ARM64_REG_X0, value & MASK)
            u.reg_write(reg.UC_ARM64_REG_PC, link)

        def instruction(uc, pc, size, _):
            if pc == STOP:
                uc.emu_stop()
                return
            if pc == NOFAULT:
                state['nofault'] += 1
                dst, src, length = get(0), get(1), get(2)
                state['length'] = length
                assert 0 < length <= 256 and src == SOURCE + index * 256
                if mode == 'fault': returned(-14)
                elif mode == 'cross-page-fault':
                    uc.mem_write(dst, bytes(uc.mem_read(src, 8)))
                    returned(-14)
                else:
                    uc.mem_write(dst, bytes(uc.mem_read(src, length)))
                    returned(0)
                return
            if pc == COPY_USER:
                state['copy'] += 1
                target, src, length = get(0), get(1), get(2)
                assert length == state['length']
                state['target'] = target
                state['copied'] = bytes(uc.mem_read(src, length))
                returned(length - 1 if mode == 'copy-fault' else 0)
                return
            ins = next(decoder.disasm(bytes(uc.mem_read(pc, 4)), pc))
            if ins.mnemonic == 'mrs' and ins.op_str.endswith(', daif'):
                target = int(ins.op_str.split(',')[0][1:])
                uc.reg_write(getattr(reg, f'UC_ARM64_REG_X{target}'), state['daif'])
                uc.reg_write(reg.UC_ARM64_REG_PC, pc + 4)
            elif ins.mnemonic == 'msr' and ins.op_str.startswith('daifset,'):
                state['daif'] |= int(ins.op_str.split('#')[1], 0) << 6
                uc.reg_write(reg.UC_ARM64_REG_PC, pc + 4)
            elif ins.mnemonic == 'msr' and ins.op_str.startswith('daif,'):
                source = int(ins.op_str.split('x')[1])
                state['daif'] = get(source)
                uc.reg_write(reg.UC_ARM64_REG_PC, pc + 4)
            if ins.mnemonic == 'at':
                uc.reg_write(reg.UC_ARM64_REG_PAR_EL1, int(fault))
                uc.reg_write(reg.UC_ARM64_REG_PC, pc + 4)

        u.hook_add(UC_HOOK_CODE, instruction)
        u.emu_start(CODE, STOP + 4, count=5000)
        assert u.reg_read(reg.UC_ARM64_REG_PC) == STOP
        assert u.reg_read(reg.UC_ARM64_REG_SP) == STACK + 0x8000
        assert all(get(i) == value for i, value in original.items())
        reply = int.from_bytes(u.mem_read(CRED + 0x11, 6), 'little') | (
            int.from_bytes(u.mem_read(CRED + 0x28, 2), 'little') << 48)
        if kind == 'bootstrap':
            expected = 1 << 63 if fault else int.from_bytes(
                bytes(range(0x10 + metadata_offset, 0x10 + metadata_offset + metadata_size)), 'little')
            assert reply == expected, (kind, mode, index, fault, hex(reply))
            assert state['daif'] == 0x80
            assert u.reg_read(reg.UC_ARM64_REG_PAR_EL1) == saved_par
        else:
            failed = mode in ('fault', 'cross-page-fault', 'copy-fault')
            assert reply == ((-19987) & MASK if failed else 0), (mode, hex(reply))
            assert state['nofault'] == 1 and state['copy'] == (mode not in ('fault', 'cross-page-fault'))
            if state['copy']:
                assert state['copied'] == bytes((i * 37 + 11) & 255 for i in range(index * 256, index * 256 + state['length']))
        cases.append(dict(kind=kind, mode=mode, batch=index, unmapped=fault, passed=True))

report = dict(passed=True, deviceRequests=False, usesCapturedSdkFrame=True,
              actualGeneratedArm64=True, cases=cases)
(out / 'kernel-read.json').write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
print('\n'.join(line for line in run.stdout.splitlines() if line.startswith('PASS ')))
print(f'PASS generated ARM64 callbacks: {len(cases)} cases; no command2 requests')
