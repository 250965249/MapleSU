"""Replay the SDK's emitted credential comparison with one modeled allocation."""
import argparse
import json
from pathlib import Path
import struct
import subprocess

from unicorn import Uc, UC_ARCH_ARM64, UC_MODE_ARM, UC_HOOK_CODE
from unicorn import arm64_const as reg

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--ndk', required=True, type=Path)
parser.add_argument('--archive', required=True, type=Path)
parser.add_argument('--build', required=True, type=Path)
parser.add_argument('--adb', required=True, type=Path)
parser.add_argument('--serial', required=True)
args = parser.parse_args()
root = Path(__file__).resolve().parents[2]
args.build.mkdir(parents=True, exist_ok=True)
binary = args.build / 'credential-snapshot.test'
tool = args.ndk / 'toolchains/llvm/prebuilt/windows-x86_64/bin/clang++.exe'
wraps = ['_ZN13kernel_module27get_task_struct_comm_offsetERj',
         '_ZN13kernel_module29is_CONFIG_THREAD_INFO_IN_TASKEv',
         '_ZN13kernel_module23execute_kernel_asm_funcERKNSt6__ndk16vectorIhNS0_9allocatorIhEEEERm']
command = [tool, '--target=aarch64-linux-android31', '-std=c++17', '-O2', '-fPIE', '-pie',
           '-fno-rtti', '-ffunction-sections', '-fdata-sections', '-Wno-packed-non-pod',
           '-Wl,--gc-sections', '-static-libstdc++', '-I' + str(root / 'runtime/maplesu-sdk/include'),
           root / 'runtime/tests/pro_credential_snapshot_test.cpp', args.archive,
           '-ldl', '-llog', '-lz', '-o', binary] + ['-Wl,--wrap=' + name for name in wraps]
subprocess.run(list(map(str, command)), check=True, capture_output=True)
adb = [str(args.adb), '-s', args.serial]
remote = '/data/local/tmp/maplesu-credential-snapshot-fixture'
subprocess.run(adb + ['push', str(binary), remote], check=True, capture_output=True)
subprocess.run(adb + ['shell', 'chmod', '700', remote], check=True, capture_output=True)
checks, generated = [], None
for failure, reply in ((0, 2080), (0, 2088), (0, 0), (0, 4096), (-19969, 2080)):
    result = subprocess.run(adb + ['shell', remote, str(failure), str(reply)],
                            capture_output=True, encoding='utf-8', errors='replace', timeout=30)
    assert result.returncode == 0 and 'PASS ' in result.stdout, result.stdout + result.stderr
    code = bytes.fromhex(next(line[5:] for line in result.stdout.splitlines() if line.startswith('code=')))
    if generated is not None:
        assert generated == code
    generated = code
    checks.append(dict(failure=failure, reply=reply, verdict='passed'))

CODE, STACK, TASK, STOP, CRED = 0x100000, 0x400000, 0x500000, 0x600000, 0x700000
for values, expected in (((0, 0xabcd0000, 0xabcd0000), 2088),
                         ((0xabcd1000, 0xabcd1000, 0), 2080),
                         ((0xabcd1000, 0xabcd2000, 0xabcd3000), 0),
                         ((0, 0, 0), 0)):
    u = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
    for address in (CODE, STACK, TASK, STOP, CRED):
        u.mem_map(address, 0x10000)
    u.mem_write(CODE, generated)
    u.mem_write(TASK + 2104 - 24, struct.pack('<3Q', *values))
    u.reg_write(reg.UC_ARM64_REG_SP, STACK + 0x8000)
    u.reg_write(reg.UC_ARM64_REG_SP_EL0, TASK)
    u.reg_write(reg.UC_ARM64_REG_X30, STOP)
    # The real kernel request dispatcher supplies its reply credential slots.
    u.reg_write(reg.UC_ARM64_REG_X11, CRED)
    u.reg_write(reg.UC_ARM64_REG_X17, CRED + 0x44)
    u.hook_add(UC_HOOK_CODE, lambda uc, address, size, context: uc.emu_stop() if address == STOP else None)
    u.emu_start(CODE, STOP + 4, count=1000)
    assert u.reg_read(reg.UC_ARM64_REG_PC) == STOP
    assert u.reg_read(reg.UC_ARM64_REG_X0) == expected
    assert u.reg_read(reg.UC_ARM64_REG_SP) == STACK + 0x8000
    checks.append(dict(values=list(values), offset=expected, verdict='passed'))
(args.build / 'credential-snapshot.json').write_text(json.dumps(dict(passed=True, checks=checks,
    generatedCodeHex=generated.hex(), kernelRequestsSubmitted=False,
    boundary='Actual SDK offset probe and generated ARM64; modeled kernel execution'), indent=2) + '\n')
subprocess.run(adb + ['shell', 'rm', remote], check=True, capture_output=True)
print('PASS SDK credential snapshot: 5 native boundary cases and 4 real emitted ARM64 layouts')
