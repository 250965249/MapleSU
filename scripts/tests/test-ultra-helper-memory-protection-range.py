"""Replay real helper permission entries and inspect their executor closures."""
import argparse
import hashlib
import io
import json
from pathlib import Path
import struct

from elftools.elf.elffile import ELFFile
from unicorn import Uc, UC_ARCH_ARM64, UC_MODE_ARM, UC_HOOK_CODE
from unicorn import arm64_const as R
from unicorn.arm64_const import (UC_ARM64_REG_X0, UC_ARM64_REG_X1, UC_ARM64_REG_X2,
                                UC_ARM64_REG_X30, UC_ARM64_REG_SP, UC_ARM64_REG_PC)

MASK = (1 << 64) - 1
VTABLES = {0x1196a8: 'RO', 0x1196f0: 'RW', 0x119738: 'X'}


def replay(helper, address, size, page, protection, failure_at=None):
    uc = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
    image = ELFFile(io.BytesIO(helper.read_bytes()))
    for segment in image.iter_segments():
        if segment['p_type'] != 'PT_LOAD' or not segment['p_memsz']:
            continue
        lo = segment['p_vaddr'] & -4096
        hi = (segment['p_vaddr'] + segment['p_memsz'] + 4095) & -4096
        uc.mem_map(lo, hi - lo)
        uc.mem_write(segment['p_vaddr'], segment.data())
    stack, stop = 0x70000000, 0x71000000
    uc.mem_map(stack, 0x10000)
    uc.mem_map(stop, 4096)
    uc.reg_write(UC_ARM64_REG_SP, stack + 0xff00)
    uc.reg_write(UC_ARM64_REG_X30, stop)
    uc.reg_write(UC_ARM64_REG_X0, address)
    uc.reg_write(UC_ARM64_REG_X1, size)
    uc.reg_write(UC_ARM64_REG_X2, protection)
    for number in range(19, 30):
        uc.reg_write(getattr(R, f'UC_ARM64_REG_X{number}'), 0x9900 + number)
    calls = []

    def finish_call(result):
        link = uc.reg_read(UC_ARM64_REG_X30)
        for number in range(1, 18):
            uc.reg_write(getattr(R, f'UC_ARM64_REG_X{number}'), 0xbad000 + number)
        uc.reg_write(R.UC_ARM64_REG_NZCV, 0xf0000000)
        uc.reg_write(UC_ARM64_REG_X0, result & MASK)
        uc.reg_write(UC_ARM64_REG_PC, link)

    def hook(_uc, pc, _length, _data):
        if pc == stop:
            uc.emu_stop()
            return
        if pc == 0xc04c0:
            function = uc.reg_read(UC_ARM64_REG_X0)
            closure = struct.unpack('<Q', uc.mem_read(function + 32, 8))[0]
            vtable, target, count = struct.unpack('<QQQ', uc.mem_read(closure, 24))
            calls.append(dict(protection=VTABLES.get(vtable, hex(vtable)), address=target, pages=count))
            finish_call(-12345 if len(calls) == failure_at else 0)
        elif pc == 0xc0ac4:
            finish_call(page)
        elif pc == 0xc373c:
            finish_call(0)
        else:
            return

    uc.hook_add(UC_HOOK_CODE, hook)
    uc.emu_start(0xc0898, stop + 4, count=20000)
    assert uc.reg_read(UC_ARM64_REG_PC) == stop, 'Helper permission entry did not return'
    assert uc.reg_read(UC_ARM64_REG_SP) == stack + 0xff00, 'Caller stack was not restored'
    assert all(uc.reg_read(getattr(R, f'UC_ARM64_REG_X{number}')) == 0x9900 + number
               for number in range(19, 30)), 'Callee-saved registers were not restored'
    result = uc.reg_read(UC_ARM64_REG_X0)
    return result if result < (1 << 63) else result - (1 << 64), calls


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--helper', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
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
    cases.extend([('zero-page', base, 1, 0, False), ('unsupported-page', base, 1, 8192, False)])
    results = []
    for name, address, size, page, valid in cases:
        for protection in range(3):
            wanted = ([dict(protection=mode, address=address & -page,
                            pages=((address % page) + size + page - 1) // page)
                       for mode in (['RO', 'X'] if protection == 2 else [['RO'], ['RW']][protection])]
                      if valid else [])
            expected = 0 if valid else -20000
            try:
                status, calls = replay(args.helper, address, size, page, protection)
                row = dict(name=name, protection=protection, passed=status == expected and calls == wanted,
                           actualStatus=status, expectedStatus=expected, actualCalls=calls, expectedCalls=wanted)
            except Exception as error:
                row = dict(name=name, protection=protection, passed=False, error=str(error))
            results.append(row)
    for protection, failure_at in ((0, 1), (1, 1), (2, 1), (2, 2)):
        wanted = [dict(protection=mode, address=base, pages=2)
                  for mode in (['RO', 'X'][:failure_at] if protection == 2 else [['RO'], ['RW']][protection])]
        try:
            status, calls = replay(args.helper, base + 1, 4096, 4096, protection, failure_at)
            row = dict(name=f'executor-error-{failure_at}', protection=protection,
                       passed=status == -12345 and calls == wanted, actualStatus=status,
                       expectedStatus=-12345, actualCalls=calls, expectedCalls=wanted)
        except Exception as error:
            row = dict(name=f'executor-error-{failure_at}', protection=protection, passed=False, error=str(error))
        results.append(row)
    report = dict(passed=all(row['passed'] for row in results), cases=len(results),
                  failures=sum(not row['passed'] for row in results),
                  helperSha256=hashlib.sha256(args.helper.read_bytes()).hexdigest(),
                  testScriptSha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                  realAarch64EntryExecuted=True, kernelCallbacksExecuted=False, deviceAccess=False,
                  callerSavedRegistersClobbered=True, calleeSavedRegistersAndStackChecked=True,
                  results=results)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    print(json.dumps({key: value for key, value in report.items() if key != 'results'}))
    raise SystemExit(0 if report['passed'] else 1)


if __name__ == '__main__':
    main()
