"""Capture real SDK cred probes and replay UID callbacks after credential replacement."""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import subprocess

from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM
from unicorn import Uc, UC_ARCH_ARM64, UC_MODE_ARM, UC_HOOK_CODE, UC_HOOK_MEM_READ
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
binary = args.build / 'credprobe.test'
tool = args.ndk / 'toolchains/llvm/prebuilt/windows-x86_64/bin/clang++.exe'
wraps = [
    '_ZN13kernel_module29is_CONFIG_THREAD_INFO_IN_TASKEv',
    '_ZN13kernel_module34is_CURRENT_FROM_SP_EL0_THREAD_INFOEv',
    '_ZN13kernel_module27get_task_struct_cred_offsetERj',
    '_ZN13kernel_module20kallsyms_lookup_nameEPKcRNS_9SymbolHitENS_15SymbolMatchModeE',
    '_ZN13kernel_module23execute_kernel_asm_funcERKNSt6__ndk16vectorIhNS0_9allocatorIhEEEERm',
    '_ZN13kernel_module32execute_kernel_asm_func_with_bufEPKhjRm',
    '_ZN13kernel_module15read_kernel_memEmPvj',
    '_ZN13kernel_module23request_kernel_read_memEmPvj',
    '_ZN13kernel_module24request_kernel_write_memEmPKvj', 'syscall', 'execve',
]
command = [tool, '--target=aarch64-linux-android31', '-std=c++17', '-O2', '-fPIE', '-pie',
           '-fno-rtti', '-ffunction-sections', '-fdata-sections', '-Wno-packed-non-pod',
           '-Wl,--gc-sections', '-static-libstdc++', '-I' + str(root / 'runtime/maplesu-sdk/include'),
           root / 'runtime/tests/pro_cred_probe_initial_test.cpp', args.archive,
           '-ldl', '-llog', '-lz', '-o', binary] + ['-Wl,--wrap=' + name for name in wraps]
compiled = subprocess.run(list(map(str, command)), capture_output=True, text=True)
if compiled.returncode:
    raise RuntimeError(compiled.stdout + compiled.stderr)
if not args.adb:
    print('PASS fixture compiled offline; no device or kernel request used')
    raise SystemExit(0)
adb = [str(args.adb), '-s', args.serial]
remote = '/data/local/tmp/maplesu-cred-probe-initial-fixture'
captures = {}
try:
    subprocess.run(adb + ['push', str(binary), remote], check=True, capture_output=True)
    subprocess.run(adb + ['shell', 'chmod', '700', remote], check=True, capture_output=True)
    for probe in ('uid', 'euid', 'cap'):
        result = subprocess.run(adb + ['shell', remote, probe], capture_output=True,
                                encoding='utf-8', errors='replace', timeout=30)
        captures[probe] = result.stdout
        (args.build / (probe + '.txt')).write_text(result.stdout + result.stderr, encoding='utf-8')
        assert result.returncode == 0 and 'PASS ' in result.stdout, result.stdout + result.stderr
finally:
    subprocess.run(adb + ['shell', 'rm', '-f', remote], check=True, capture_output=True)

CODE, STACK, REQUEST, STOP = 0x100000, 0x400000, 0x500000, 0x700000
TASK, FIRST_CRED, NEXT_CRED = 0xffff800001000000, 0xffff800002000000, 0xffff800003000000
results = []
for probe in ('uid', 'euid'):
    code = bytes.fromhex(next(line[5:] for line in captures[probe].splitlines() if line.startswith('code=')))
    for cred in (FIRST_CRED, NEXT_CRED):
        u = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
        for address in (CODE, STACK, REQUEST, STOP, TASK, cred):
            u.mem_map(address, 0x10000)
        u.mem_write(CODE, code)
        u.mem_write(TASK + 0x588, struct.pack('<Q', cred))
        u.mem_write(cred + 4, struct.pack('<I', 2000))
        u.reg_write(reg.UC_ARM64_REG_SP, STACK + 0x8000)
        u.reg_write(reg.UC_ARM64_REG_SP_EL0, TASK)
        u.reg_write(reg.UC_ARM64_REG_X30, STOP)
        u.reg_write(reg.UC_ARM64_REG_X11, REQUEST)
        u.reg_write(reg.UC_ARM64_REG_X17, cred + 0x10)
        reads, trace = [], []
        decoder = Cs(CS_ARCH_ARM64, CS_MODE_ARM)

        def instruction(uc, pc, size, context):
            if pc == STOP:
                uc.emu_stop()
                return
            item = next(decoder.disasm(bytes(uc.mem_read(pc, 4)), pc - CODE))
            trace.append(f'{pc - CODE:#06x}: {item.mnemonic} {item.op_str}')

        def read(uc, access, address, size, value, context):
            if TASK <= address < TASK + 0x10000 or cred <= address < cred + 0x10000:
                reads.append((address, size))

        u.hook_add(UC_HOOK_CODE, instruction)
        u.hook_add(UC_HOOK_MEM_READ, read)
        u.emu_start(CODE, STOP + 4, count=1000)
        reply = int.from_bytes(u.mem_read(cred + 0x11, 6), 'little') | (
            int.from_bytes(u.mem_read(cred + 0x28, 2), 'little') << 48)
        assert u.reg_read(reg.UC_ARM64_REG_PC) == STOP and reply == 2000
        assert (TASK + 0x588, 8) in reads and (cred + 4, 4) in reads
        assert all(address < FIRST_CRED or cred <= address < cred + 0x10000 for address, _ in reads)
        results.append(dict(probe=probe, currentCred=hex(cred), returnedOriginalValue=reply,
                            kernelReads=[(hex(address), size) for address, size in reads]))
        (args.build / (probe + '-callback-disassembly.txt')).write_text('\n'.join(trace) + '\n', encoding='utf-8')
assert 'lookup=init_cred' in captures['cap'] and 'read=ffff800001000000,8' in captures['cap']
report = dict(passed=True, sdkArchiveSha256=hashlib.sha256(args.archive.read_bytes()).hexdigest(),
              kernelRequestsSubmitted=False, uidEuid=results,
              capProbe='first command2 read is resolved init_cred symbol, not current->cred',
              boundary='Real SDK first UID/EUID callback and first cap read; synthetic replacement cred per request')
(args.build / 'cred-probe-initial.json').write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
print(json.dumps(report, indent=2))
print('PASS UID/EUID reload current cred inside each callback; cap reads init_cred')
