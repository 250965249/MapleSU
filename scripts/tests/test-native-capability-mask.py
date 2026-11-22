"""Compare the real SDK capability mask function with reference native AArch64 codegen."""
from pathlib import Path
import hashlib
import io
import json
import subprocess
import sys

from elftools.elf.elffile import ELFFile
from unicorn import Uc, UC_ARCH_ARM64, UC_MODE_ARM, UC_HOOK_CODE
from unicorn import arm64_const as R

ROOT = Path(__file__).resolve().parents[2]
OUT = ROOT / 'work/maplesu-selinux-20261116/implementation-capability'
OUT.mkdir(parents=True, exist_ok=True)
SOURCE = ROOT / 'runtime/maplesu-sdk/sdk/src/kernel_offsets/cred.cpp'
sys.path.insert(0, str(ROOT / 'runtime/maplesu-sdk/sdk/tools'))
from extract_payloads import parse_ar_members
from sdk_common import resolve_toolchain

archive = ROOT / 'runtime/maplesu-sdk/maintenance/baseline/libkernel_module_kit_static.a'
member = parse_ar_members(archive.read_bytes())[0]
assert member.name == 'cred.o'
assert hashlib.sha256(member.raw).hexdigest() == 'd0fe7618ffb9ebd66cea7249ead0d2cfcc8698be6b75818c4e4515b27ef70e45'
REFERENCE = OUT / 'original-cred.bc'
REFERENCE.write_bytes(member.raw)
CLANG = resolve_toolchain(None).tool('clang++')
SYMBOL = '_ZN13kernel_module19get_cap_ability_maxEv'
text = SOURCE.read_text(encoding='utf-8')
start = text.index('uint64_t get_cap_ability_max() {')
body = text[start:text.index('\n}', start) + 2]
(OUT / 'production.cpp').write_text('#include <cstdint>\n#include <cerrno>\n#include <sys/prctl.h>\nnamespace kernel_module {\n' + body + '\n}\n', encoding='utf-8')


def compile_object(source, output, extra=()):
    command = [str(CLANG), '--target=aarch64-linux-android21', '-Oz', '-c', *extra, str(source), '-o', str(output)]
    result = subprocess.run(command, capture_output=True, text=True, encoding='utf-8', errors='replace')
    if result.returncode:
        raise AssertionError(result.stderr)
    return command


commands = [compile_object(REFERENCE, OUT / 'reference.o', ('-x', 'ir')),
            compile_object(OUT / 'production.cpp', OUT / 'production.o')]


def load(path):
    elf = ELFFile(io.BytesIO(path.read_bytes()))
    symbol = elf.get_section_by_name('.symtab').get_symbol_by_name(SYMBOL)[0]
    section = elf.get_section(symbol['st_shndx'])
    offset, size = symbol['st_value'], symbol['st_size']
    calls = {}
    for relocations in elf.iter_sections():
        if relocations['sh_type'] != 'SHT_RELA' or relocations['sh_info'] != symbol['st_shndx']:
            continue
        symbols = elf.get_section(relocations['sh_link'])
        for reloc in relocations.iter_relocations():
            if offset <= reloc['r_offset'] < offset + size:
                assert reloc['r_info_type'] == 283, 'unexpected non-call relocation'
                calls[0x100000 + reloc['r_offset'] - offset] = symbols.get_symbol(reloc['r_info_sym']).name
    assert set(calls.values()) == {'prctl', '__errno'}
    return section.data()[offset:offset + size], calls


def execute(image, stop, result, error):
    code, calls = image
    uc = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
    uc.mem_map(0x100000, 0x10000)
    uc.mem_map(0x200000, 0x1000)
    uc.mem_map(0x300000, 0x10000)
    uc.mem_write(0x100000, code)
    uc.reg_write(R.UC_ARM64_REG_SP, 0x30fff0)
    uc.reg_write(R.UC_ARM64_REG_LR, 0x10fff0)
    queried = []

    def native(machine, address, size, user):
        name = calls.get(address)
        if name is None:
            return
        if name == 'prctl':
            assert machine.reg_read(R.UC_ARM64_REG_W0) == 23
            cap = machine.reg_read(R.UC_ARM64_REG_W1)
            queried.append(cap)
            rc, err = (result, error) if cap == stop else (-1, 22)
            machine.mem_write(0x200000, err.to_bytes(4, 'little'))
            machine.reg_write(R.UC_ARM64_REG_X0, rc & 0xffffffffffffffff)
        else:
            machine.reg_write(R.UC_ARM64_REG_X0, 0x200000)
        machine.reg_write(R.UC_ARM64_REG_PC, address + 4)

    uc.hook_add(UC_HOOK_CODE, native)
    uc.emu_start(0x100000, 0x10fff0, count=10000)
    assert uc.reg_read(R.UC_ARM64_REG_PC) == 0x10fff0, 'function did not return'
    return uc.reg_read(R.UC_ARM64_REG_X0), queried


reference, production = load(OUT / 'reference.o'), load(OUT / 'production.o')
cases = []
for cap in range(64):
    for result, error in ((0, 0), (1, 22), (-1, 1), (-1, 5)):
        expected = (1 << ((cap + 1) & 63)) - 1
        original = execute(reference, cap, result, error)
        actual = execute(production, cap, result, error)
        assert original == (expected, list(range(63, cap - 1, -1))), (cap, result, error, original)
        assert actual == original, (cap, result, error, actual, original)
        cases.append(dict(cap=cap, result=result, errno=error, mask=actual[0]))
assert execute(reference, -1, -1, 22) == execute(production, -1, -1, 22) == (0, list(range(63, -1, -1)))
cases.append(dict(allEINVAL=True, mask=0))
assert len(cases) == 257
report = dict(passed=True, cases=cases, count=len(cases), commands=commands,
              sourceSha256=hashlib.sha256(SOURCE.read_bytes()).hexdigest(),
              referenceSha256=hashlib.sha256(REFERENCE.read_bytes()).hexdigest(),
              cap63='0: original AArch64 variable LSL masks shift 64 to 0; defined reproduction, not a source-UB equivalence claim',
              deviceAccess=False)
(OUT / 'RESULT.json').write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
print('PASS 257 capability-mask cases: success, non-EINVAL failure, all EINVAL, and AArch64 cap 63')
