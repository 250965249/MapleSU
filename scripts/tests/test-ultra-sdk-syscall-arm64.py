"""Replay the production SDK syscall wrapper with tagged ARM64 request pointers."""
import argparse
import hashlib
import io
import json
from pathlib import Path
import random
import struct
import subprocess
import sys

from elftools.elf.elffile import ELFFile
from unicorn import Uc, UC_ARCH_ARM64, UC_MODE_ARM, UC_HOOK_CODE
from unicorn import arm64_const as reg

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'tools'))
from native_toolchain import ndk_bin, ndk_home

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--ndk', type=Path)
parser.add_argument('--out', required=True, type=Path)
parser.add_argument('--unwrapped-baseline', action='store_true')
parser.add_argument('--bridge', type=Path, help='Also verify an actual linked production bridge')
args = parser.parse_args()
args.out.mkdir(parents=True, exist_ok=True)
source = ROOT / 'runtime/ultra/bridge/sdk_syscall.S'
suffix = '.exe' if sys.platform == 'win32' else ''
clang = ndk_bin(ndk_home(args.ndk)) / ('clang' + suffix)
entry = args.out / 'entry.S'
entry.write_text('''\
.text
.global fixture_entry
.type fixture_entry, %function
fixture_entry:
    b syscall
.size fixture_entry, .-fixture_entry
.section .note.GNU-stack,"",%progbits
''', encoding='utf-8')
libc = args.out / 'libc.S'
libc.write_text('''\
.text
.global syscall
.hidden syscall
.type syscall, %function
syscall:
    adrp x16, fixture_response
    add x16, x16, :lo12:fixture_response
    ldr x0, [x16]
    ldr w17, [x16, #8]
    cbz w17, 1f
    str w17, [x16, #12]
1:  ret
.size syscall, .-syscall
.data
.balign 8
.global fixture_response
.hidden fixture_response
fixture_response:
    .zero 16
.section .note.GNU-stack,"",%progbits
''', encoding='utf-8')
library = args.out / 'syscall-fixture.so'
command = [str(clang), '--target=aarch64-linux-android31', '-shared', '-nostdlib',
           '-Wl,--no-undefined', '-Wl,--build-id=none', str(entry), str(libc)]
if not args.unwrapped_baseline:
    command += [str(source), '-Wl,--wrap=syscall']
command += ['-o', str(library)]
compiled = subprocess.run(command, capture_output=True, text=True)
(args.out / 'compile.log').write_text(compiled.stdout + compiled.stderr, encoding='utf-8')
assert compiled.returncode == 0, compiled.stdout + compiled.stderr
blob = library.read_bytes()
elf = ELFFile(io.BytesIO(blob))
symbols = {s.name: s['st_value'] for s in elf.get_section_by_name('.symtab').iter_symbols()
           if isinstance(s['st_shndx'], int)}
if not args.unwrapped_baseline:
    assert '__wrap_syscall' in symbols
    assert '__wrap_syscall' not in {s.name for s in elf.get_section_by_name('.dynsym').iter_symbols()}

MASK = (1 << 64) - 1
USER_MASK = (1 << 56) - 1
REQUEST, STACK, STOP = 0x60000000, 0x70000000, 0x71000000
token = b'SDK-ECHO-221-TBI!'
cases = []
for tag in range(256):
    cases.append((221, (tag << 56) | REQUEST))
    cases.append((221, (tag << 56) | (1 << 55) | REQUEST))
for number in (0, 220, 222, MASK, (1 << 32) | 221, (1 << 63) | 221):
    for tag in (0, 1, 0x7f, 0x80, 0xb4, 0xfe, 0xff):
        for pointer in (REQUEST, (1 << 55) | REQUEST):
            cases.append((number, (tag << 56) | pointer))
for pointer in (0, 1, (1 << 47) - 1, 1 << 47, (1 << 55) - 1,
                1 << 55, (1 << 56) - 1, 0xffff800000001000, MASK):
    for tag in (0, 1, 0x80, 0xff):
        cases.append((221, (pointer & USER_MASK) | (tag << 56)))

results = []
random_source = random.Random(221)
initial = {i: random_source.getrandbits(64) for i in range(31)}
vectors = {i: random_source.getrandbits(128) for i in range(32)}
stack_bytes = random_source.randbytes(256)
responses = ((0, 0), (0x123456789abcdef, 0), (MASK, 14), (MASK, 38))
for base in (0x1000000, 0x5000000, 0x11000000):
    u = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
    high = max(s['p_vaddr'] + s['p_memsz'] for s in elf.iter_segments() if s['p_type'] == 'PT_LOAD')
    u.mem_map(base, (high + 4095) & ~4095)
    for segment in elf.iter_segments():
        if segment['p_type'] == 'PT_LOAD':
            u.mem_write(base + segment['p_vaddr'], segment.data())
    for address in (REQUEST, STACK, STOP):
        u.mem_map(address, 0x10000)
    u.mem_write(REQUEST, token)
    sp = STACK + 0x8000

    def capture(uc, address, size, _):
        if address == STOP:
            uc.emu_stop()
        elif address == base + symbols['syscall']:
            actual_pointer = uc.reg_read(reg.UC_ARM64_REG_X1)
            assert actual_pointer == expected_pointer, (
                f'number={number:#x} pointer={pointer:#x} forwarded={actual_pointer:#x} '
                f'expected={expected_pointer:#x}; tagged SDK request is not readable')
            for i, value in before.items():
                expected = expected_pointer if i == 1 else value
                assert uc.reg_read(getattr(reg, f'UC_ARM64_REG_X{i}')) == expected, (i, number, pointer)
            assert uc.reg_read(reg.UC_ARM64_REG_SP) == sp
            for i, value in vectors.items():
                assert uc.reg_read(getattr(reg, f'UC_ARM64_REG_Q{i}')) == value, i
            if number == 221 and expected_pointer == REQUEST:
                assert bytes(uc.mem_read(actual_pointer, len(token))) == token
            visited.append('syscall')

    u.hook_add(UC_HOOK_CODE, capture)
    for index, (number, pointer) in enumerate(cases):
        u.mem_write(sp - 128, stack_bytes)
        u.reg_write(reg.UC_ARM64_REG_SP, sp)
        expected_pointer = pointer & USER_MASK if number == 221 and not pointer & (1 << 55) else pointer
        before = initial.copy()
        before.update({0: number, 1: pointer, 30: STOP})
        for i, value in before.items():
            u.reg_write(getattr(reg, f'UC_ARM64_REG_X{i}'), value)
        for i, value in vectors.items():
            u.reg_write(getattr(reg, f'UC_ARM64_REG_Q{i}'), value)
        returned, set_errno = responses[index % len(responses)]
        response = base + symbols['fixture_response']
        u.mem_write(response, struct.pack('<QII', returned, set_errno, 117))
        visited = []

        u.emu_start(base + symbols['fixture_entry'], STOP + 4, count=32)
        assert visited == ['syscall']
        assert u.reg_read(reg.UC_ARM64_REG_PC) == STOP
        assert u.reg_read(reg.UC_ARM64_REG_X0) == returned
        assert struct.unpack('<I', bytes(u.mem_read(response + 12, 4)))[0] == (set_errno or 117)
        assert u.reg_read(reg.UC_ARM64_REG_SP) == sp
        assert bytes(u.mem_read(sp - 128, len(stack_bytes))) == stack_bytes
        for i in range(19, 31):
            assert u.reg_read(getattr(reg, f'UC_ARM64_REG_X{i}')) == before[i]
        results.append({'syscall': hex(number), 'pointer': hex(pointer), 'base': hex(base)})

bridge_check = None
if args.bridge:
    bridge_blob = args.bridge.read_bytes()
    bridge = ELFFile(io.BytesIO(bridge_blob))
    bridge_symbols = {s.name: s for s in bridge.get_section_by_name('.symtab').iter_symbols()
                      if isinstance(s['st_shndx'], int)}
    wrapper = bridge_symbols['__wrap_syscall']
    assert '__wrap_syscall' not in {s.name for s in bridge.get_section_by_name('.dynsym').iter_symbols()}
    dynsym = bridge.get_section_by_name('.dynsym')
    syscall_entries = [i for i, rel in enumerate(bridge.get_section_by_name('.rela.plt').iter_relocations())
                       if dynsym.get_symbol(rel['r_info_sym']).name == 'syscall']
    assert len(syscall_entries) == 1
    syscall_plt = bridge.get_section_by_name('.plt')['sh_addr'] + 32 + 16 * syscall_entries[0]
    text = bridge.get_section_by_name('.text')
    fixture_text = elf.get_section_by_name('.text')
    fixture_start = symbols['__wrap_syscall'] - fixture_text['sh_addr']
    wrapper_start = wrapper['st_value'] - text['sh_addr']
    wrapper_bytes = text.data()[wrapper_start:wrapper_start + wrapper['st_size']]
    fixture_size = next(s['st_size'] for s in elf.get_section_by_name('.symtab').iter_symbols()
                        if s.name == '__wrap_syscall')
    fixture_bytes = fixture_text.data()[fixture_start:fixture_start + fixture_size]
    assert len(wrapper_bytes) == len(fixture_bytes)
    assert wrapper_bytes[:-4] == fixture_bytes[:-4], 'production wrapper differs from emulated instructions'
    incoming, real_calls = [], []
    for offset, (word,) in enumerate(struct.iter_unpack('<I', text.data())):
        if word & 0x7c000000 != 0x14000000:
            continue
        pc = text['sh_addr'] + offset * 4
        immediate = word & 0x3ffffff
        if immediate & (1 << 25):
            immediate -= 1 << 26
        target = pc + immediate * 4
        if target == wrapper['st_value']:
            incoming.append(pc)
        if target == syscall_plt:
            real_calls.append(pc)
    assert incoming, 'production SDK calls did not reach the wrapper'
    assert real_calls == [wrapper['st_value'] + wrapper['st_size'] - 4], real_calls
    bridge_check = {'sha256': hashlib.sha256(bridge_blob).hexdigest(),
                    'wrappedCallSites': len(incoming), 'wrapperExported': False,
                    'wrapperInstructionsMatchEmulatedFixture': True,
                    'directLibcCallsOnlyFromWrapper': True}

report = {'passed': True, 'actualArm64Assembly': True, 'cases': len(results),
          'allTopByteTags': True, 'allArgumentRegistersPreserved': True,
          'kernelAddressesPreserved': True, 'tailReturnAndErrnoPreserved': True,
          'deviceAccess': False, 'fixtureSha256': hashlib.sha256(blob).hexdigest(),
          'sourceSha256': hashlib.sha256(source.read_bytes()).hexdigest(), 'bridge': bridge_check}
(args.out / 'result.json').write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
print(f'PASS ARM64 SDK syscall: {len(results)} cases; all tags; ABI/return/errno preserved')
if bridge_check:
    print(f'PASS production bridge: {bridge_check["wrappedCallSites"]} wrapped call sites; hidden wrapper')
