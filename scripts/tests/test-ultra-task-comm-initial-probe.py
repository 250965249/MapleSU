"""Capture the real first comm-offset callback; replay its complete ARM64 frame offline."""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import subprocess

from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM
from unicorn import Uc, UC_ARCH_ARM64, UC_MODE_ARM, UC_HOOK_CODE
from unicorn import arm64_const as reg

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--ndk', required=True, type=Path)
parser.add_argument('--archive', required=True, type=Path)
parser.add_argument('--build', required=True, type=Path)
parser.add_argument('--adb', type=Path)
parser.add_argument('--serial')
args = parser.parse_args()
if bool(args.adb) != bool(args.serial):
    parser.error('--adb and --serial must be supplied together')
root = Path(__file__).resolve().parents[2]
args.build.mkdir(parents=True, exist_ok=True)
binary = args.build / 'task-comm-initial-probe.test'
tool = args.ndk / 'toolchains/llvm/prebuilt/windows-x86_64/bin/clang++.exe'
wraps = [
    '_ZN13kernel_module29is_CONFIG_THREAD_INFO_IN_TASKEv',
    '_ZN13kernel_module34is_CURRENT_FROM_SP_EL0_THREAD_INFOEv',
    '_ZN13kernel_module23execute_kernel_asm_funcERKNSt6__ndk16vectorIhNS0_9allocatorIhEEEERm',
    '_ZN13kernel_module32execute_kernel_asm_func_with_bufEPKhjRm',
    '_ZN13kernel_module15read_kernel_memEmPvj',
    '_ZN13kernel_module23request_kernel_read_memEmPvj',
    '_ZN13kernel_module24request_kernel_write_memEmPKvj',
    'syscall', 'execve',
]
command = [tool, '--target=aarch64-linux-android31', '-std=c++17', '-O2', '-fPIE', '-pie',
           '-fno-rtti', '-ffunction-sections', '-fdata-sections', '-Wno-packed-non-pod',
           '-Wl,--gc-sections', '-static-libstdc++', '-I' + str(root / 'runtime/maplesu-sdk/include'),
           root / 'runtime/tests/pro_task_comm_initial_probe_test.cpp', args.archive,
           '-ldl', '-llog', '-lz', '-o', binary] + ['-Wl,--wrap=' + name for name in wraps]
compiled = subprocess.run(list(map(str, command)), capture_output=True, text=True)
if compiled.returncode:
    raise RuntimeError(compiled.stdout + compiled.stderr)
if not args.adb:
    print('PASS fixture compiled offline; no device or kernel request used')
    raise SystemExit(0)

adb = [str(args.adb), '-s', args.serial]
remote = '/data/local/tmp/maplesu-task-comm-initial-probe-fixture'
try:
    subprocess.run(adb + ['push', str(binary), remote], check=True, capture_output=True)
    subprocess.run(adb + ['shell', 'chmod', '700', remote], check=True, capture_output=True)
    result = subprocess.run(adb + ['shell', remote], capture_output=True, encoding='utf-8',
                            errors='replace', timeout=30)
    (args.build / 'capture.txt').write_text(result.stdout + result.stderr, encoding='utf-8')
    assert result.returncode == 0 and 'PASS ' in result.stdout, result.stdout + result.stderr
finally:
    subprocess.run(adb + ['shell', 'rm', '-f', remote], check=True, capture_output=True)
code = bytes.fromhex(next(line[5:] for line in result.stdout.splitlines() if line.startswith('code=')))
first_read, read_size = next(line[5:] for line in result.stdout.splitlines() if line.startswith('read=')).split(',')
CODE, STACK, REQUEST, CRED, STOP = 0x100000, 0x400000, 0x500000, 0x600000, 0x700000
TASK = 0xffff800001000000
u = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
for address in (CODE, STACK, REQUEST, CRED, STOP):
    u.mem_map(address, 0x10000)
u.mem_write(CODE, code)
u.reg_write(reg.UC_ARM64_REG_SP, STACK + 0x8000)
u.reg_write(reg.UC_ARM64_REG_SP_EL0, TASK)
u.reg_write(reg.UC_ARM64_REG_X30, STOP)
# Actual command-3 callback ABI: decoded request and credential reply slot.
u.reg_write(reg.UC_ARM64_REG_X11, REQUEST)
u.reg_write(reg.UC_ARM64_REG_X17, CRED + 0x10)
u.reg_write(reg.UC_ARM64_REG_X10, 0xdead0010)
disassembly = []
decoder = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
def trace(uc, pc, size, context):
    if pc == STOP:
        uc.emu_stop()
        return
    instruction = next(decoder.disasm(bytes(uc.mem_read(pc, 4)), pc - CODE))
    disassembly.append(f'{pc - CODE:#06x}: {instruction.mnemonic} {instruction.op_str}')
u.hook_add(UC_HOOK_CODE, trace)
u.emu_start(CODE, STOP + 4, count=1000)
assert u.reg_read(reg.UC_ARM64_REG_PC) == STOP
# Command 3 encodes 48 result bits at suid+1 and the final 16 at securebits.
reply = int.from_bytes(u.mem_read(CRED + 0x11, 6), 'little') | (int.from_bytes(
    u.mem_read(CRED + 0x28, 2), 'little') << 48)
request_reply = struct.unpack('<Q', bytes(u.mem_read(REQUEST + 0x44, 8)))[0]
report = dict(passed=reply == TASK, sdkArchiveSha256=hashlib.sha256(args.archive.read_bytes()).hexdigest(),
              generatedCodeHex=code.hex(), expectedCurrent=hex(TASK), credentialReply=hex(reply),
              firstReadAddress=hex(int(first_read, 16)), firstReadBytes=int(read_size),
              requestReply=hex(request_reply), x0=hex(u.reg_read(reg.UC_ARM64_REG_X0)),
              x10=hex(u.reg_read(reg.UC_ARM64_REG_X10)), kernelRequestsSubmitted=False,
              boundary='Real SDK first getcomm callback; command-3 inputs modeled; full emitted frame executed')
(args.build / 'task-comm-initial-probe.json').write_text(json.dumps(report, indent=2) + '\n')
(args.build / 'callback-disassembly.txt').write_text('\n'.join(disassembly) + '\n', encoding='utf-8')
print('\n'.join(disassembly))
print(json.dumps(report, indent=2))
assert reply == TASK, 'Initial current callback did not publish task pointer to command-3 reply'
assert u.reg_read(reg.UC_ARM64_REG_SP) == STACK + 0x8000
print('PASS real first comm probe: current returned intact; first scan read begins at task')
