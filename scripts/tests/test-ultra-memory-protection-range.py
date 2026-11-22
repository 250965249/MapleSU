"""Replay the real AArch64 permission entry points at their executor boundary."""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import subprocess

from elftools.elf.elffile import ELFFile
from unicorn import Uc, UC_ARCH_ARM64, UC_MODE_ARM, UC_HOOK_CODE
from unicorn.arm64_const import (UC_ARM64_REG_X0, UC_ARM64_REG_X1, UC_ARM64_REG_X2,
                                UC_ARM64_REG_X30, UC_ARM64_REG_SP, UC_ARM64_REG_PC,
                                UC_ARM64_REG_TPIDR_EL0)

ENTRY = '_ZN13kernel_module25set_kernel_mem_protectionEmmNS_11KernMemProtE'
PAGE = '_ZN13kernel_module13get_page_sizeEv'
EXEC = '_ZL31exec_kernel_shellcode_no_resultNSt6__ndk18functionIF7KModErrPN6asmjit5v1_163a649AssemblerEEEE'
CHECKED = 'maplesu_exec_kernel_patch_checked'
DTOR = '_ZNSt6__ndk110__function12__value_funcIF7KModErrPN6asmjit5v1_163a649AssemblerEEED2B7v170000Ev'
MASK = (1 << 64) - 1


def replay(image, address, size, page, protection):
    emulator = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
    with image.open('rb') as stream:
        elf = ELFFile(stream)
        symbol_rows = list(elf.get_section_by_name('.symtab').iter_symbols())
        symbols = {s.name: s['st_value'] for s in symbol_rows}
        plt, relocations = elf.get_section_by_name('.plt'), elf.get_section_by_name('.rela.plt')
        imports = {}
        if plt is not None and relocations is not None:
            dynamic = elf.get_section_by_name('.dynsym')
            imports = {dynamic.get_symbol(relocation['r_info_sym']).name: plt['sh_addr'] + 32 + 16 * index
                       for index, relocation in enumerate(relocations.iter_relocations())}
        for segment in elf.iter_segments():
            if segment['p_type'] != 'PT_LOAD' or not segment['p_memsz']:
                continue
            lo = segment['p_vaddr'] & -4096
            hi = (segment['p_vaddr'] + segment['p_memsz'] + 4095) & -4096
            emulator.mem_map(lo, hi - lo)
            emulator.mem_write(segment['p_vaddr'], segment.data())
    stack, stop = 0x70000000, 0x71000000
    emulator.mem_map(stack, 0x10000)
    emulator.mem_map(stop, 4096)
    emulator.mem_map(stop + 4096, 4096)
    emulator.reg_write(UC_ARM64_REG_TPIDR_EL0, stop + 4096)
    emulator.reg_write(UC_ARM64_REG_SP, stack + 0xff00)
    emulator.reg_write(UC_ARM64_REG_X30, stop)
    emulator.reg_write(UC_ARM64_REG_X0, address)
    emulator.reg_write(UC_ARM64_REG_X1, size)
    emulator.reg_write(UC_ARM64_REG_X2, protection)
    calls = []
    def addresses(*names):
        return ({symbol['st_value'] for symbol in symbol_rows if symbol.name in names and symbol['st_value']} |
                {imports[name] for name in names if imports.get(name)})

    executors, page_queries, destructors = addresses(EXEC, CHECKED), addresses(PAGE), addresses(DTOR)

    def hook(uc, pc, length, _):
        if pc == stop:
            uc.emu_stop()
            return
        if pc in executors:
            function = uc.reg_read(UC_ARM64_REG_X0)
            closure = struct.unpack('<Q', uc.mem_read(function + 32, 8))[0]
            target, count = struct.unpack('<QQ', uc.mem_read(closure + 8, 16))
            calls.append(dict(address=target, pages=count))
            uc.reg_write(UC_ARM64_REG_X0, 0)
        elif pc in page_queries:
            uc.reg_write(UC_ARM64_REG_X0, page)
        elif pc not in destructors:
            return
        uc.reg_write(UC_ARM64_REG_PC, uc.reg_read(UC_ARM64_REG_X30))

    emulator.hook_add(UC_HOOK_CODE, hook)
    emulator.emu_start(symbols[ENTRY], stop + 4, count=20000)
    assert emulator.reg_read(UC_ARM64_REG_PC) == stop, 'Permission entry did not return'
    result = emulator.reg_read(UC_ARM64_REG_X0)
    return result if result < (1 << 63) else result - (1 << 64), calls


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--object', type=Path, required=True)
    parser.add_argument('--ndk', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    image = args.output.with_suffix('.elf')
    linker = args.ndk / 'toolchains/llvm/prebuilt/windows-x86_64/bin/ld.lld.exe'
    subprocess.run([str(linker), '--unresolved-symbols=ignore-all', '-e', ENTRY,
                    '-Ttext=0x100000', str(args.object), '-o', str(image)], check=True,
                   capture_output=True, text=True)
    cases = []
    base = 0xffffffe000000000
    for page in (4096, 16384, 65536):
        for offset, size in ((0, 1), (0, page), (1, page), (page - 1, 2),
                             (page - 1, page + 2), (page // 2, page // 2),
                             (page // 2, page // 2 + 1)):
            cases.append((f'p{page}-o{offset}-n{size}', base + offset, size, page, True))
        cases.extend([(f'p{page}-zero', base, 0, page, False),
                      (f'p{page}-address-wrap', MASK - 1, 3, page, False),
                      (f'p{page}-size-overflow', base + 1, MASK, page, False),
                      (f'p{page}-count-signed-overflow', 0xffff000000000000, (1 << 31) * page, page, False),
                      (f'p{page}-count-signed-max', 0xffff000000000000, ((1 << 31) - 1) * page, page, True),
                      (f'p{page}-last-address', MASK, 1, page, False),
                      (f'p{page}-aligned-end-wrap', MASK - page + 1, 1, page, False)])
    cases.extend([('zero-page', base, 1, 0, False),
                  ('unsupported-page', base, 1, 8192, False)])
    results = []
    for name, address, size, page, valid in cases:
        for protection in range(3):
            wanted = ([dict(address=address & -page, pages=((address % page) + size + page - 1) // page)]
                      * (2 if protection == 2 else 1)) if valid else []
            expected = 0 if valid else -20000
            try:
                status, calls = replay(image, address, size, page, protection)
                passed = status == expected and calls == wanted
                row = dict(name=name, protection=protection, passed=passed,
                           actualStatus=status, expectedStatus=expected,
                           actualCalls=calls, expectedCalls=wanted)
            except Exception as error:
                row = dict(name=name, protection=protection, passed=False, error=str(error))
            results.append(row)
    report = dict(passed=all(row['passed'] for row in results), cases=len(results),
                  failures=sum(not row['passed'] for row in results),
                  objectSha256=hashlib.sha256(args.object.read_bytes()).hexdigest(),
                  testScriptSha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                  realAarch64EntryExecuted=True, kernelCallbacksExecuted=False,
                  deviceAccess=False, results=results)
    args.output.write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    print(json.dumps({k: v for k, v in report.items() if k != 'results'}))
    raise SystemExit(0 if report['passed'] else 1)


if __name__ == '__main__':
    main()
