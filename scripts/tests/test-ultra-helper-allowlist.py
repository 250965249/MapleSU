"""Replay the helper's real allowlist instructions with bounded memory APIs."""
import argparse
import hashlib
import io
import json
import struct
from pathlib import Path

from elftools.elf.elffile import ELFFile
from unicorn import Uc, UC_ARCH_ARM64, UC_HOOK_CODE, UC_MODE_ARM
from unicorn.arm64_const import UC_ARM64_REG_PC, UC_ARM64_REG_SP, UC_ARM64_REG_X0, UC_ARM64_REG_X1, UC_ARM64_REG_X2, UC_ARM64_REG_X22, UC_ARM64_REG_LR

ROOT = Path(__file__).resolve().parents[2]
CONTROL, OLD, RETIRED, NEW = 0x30000000, 0x30001000, 0x30002000, 0x30003000
BUFFER, STACK = 0x31000000, 0x32000000
MASK = (1 << 64) - 1


def replay(helper, scenario):
    data = helper.read_bytes()
    image = ELFFile(io.BytesIO(data))
    uc = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
    for segment in image.iter_segments():
        if segment['p_type'] != 'PT_LOAD':
            continue
        lo = segment['p_vaddr'] & ~4095
        hi = (segment['p_vaddr'] + segment['p_memsz'] + 4095) & ~4095
        uc.mem_map(lo, hi - lo)
        uc.mem_write(segment['p_vaddr'], segment.data())
    uc.mem_map(CONTROL, 0x10000)
    uc.mem_map(BUFFER, 0x10000)
    uc.mem_map(STACK, 0x10000)
    sp = STACK + 0x4000
    uc.reg_write(UC_ARM64_REG_SP, sp)
    uc.mem_write(CONTROL, struct.pack('<Q', OLD))
    uc.mem_write(OLD, struct.pack('<II', 10001, 0))
    uc.mem_write(RETIRED, struct.pack('<II', 10002, 0))
    uc.mem_write(BUFFER, struct.pack('<II', 10003, 0))
    state = dict(calls=[], freed=[], retired=RETIRED, snapshots=[], stopped=None, error=0)

    def read64(address):
        return struct.unpack('<Q', bytes(uc.mem_read(address, 8)))[0]

    def finish_call(address, result=0):
        state['calls'].append(hex(address))
        uc.reg_write(UC_ARM64_REG_X0, result & MASK)
        uc.reg_write(UC_ARM64_REG_PC, uc.reg_read(UC_ARM64_REG_LR))

    def hook(_uc, address, _size, _user):
        x0, x1, x2 = (uc.reg_read(r) for r in (UC_ARM64_REG_X0, UC_ARM64_REG_X1, UC_ARM64_REG_X2))
        if address in (0xf51a0, 0xf53fc, 0xf53f8, 0xf5f0c, 0xf5f04):
            state['stopped'] = hex(address)
            state['error'] = uc.reg_read(UC_ARM64_REG_X22)
            state['live'] = read64(CONTROL)
            uc.emu_stop()
            return
        if address == 0xf64e4:
            finish_call(address, state['retired'])
        elif address == 0xc0458:
            state['freed'].append(x0)
            finish_call(address)
        elif address == 0xf64c8:
            if scenario == 'retirement-write-error':
                finish_call(address, -101)
            else:
                state['retired'] = x0
                finish_call(address)
        elif address == 0xf64d8:
            finish_call(address, 0 if scenario == 'missing-control' else CONTROL)
        elif address == 0xc0560:
            uc.mem_write(x1, bytes(uc.mem_read(x0, x2)))
            finish_call(address, -102 if scenario == 'control-read-error' else 0)
        elif address == 0xc082c:
            state['snapshots'].append(dict(before=read64(x0), after=x1))
            uc.mem_write(x0, struct.pack('<Q', x1))
            finish_call(address, -103 if scenario == 'publish-error-after-store' else 0)
        elif address == 0xc0448:
            if scenario == 'allocation-error':
                finish_call(address, -104)
            else:
                uc.mem_write(x1, struct.pack('<Q', NEW))
                finish_call(address)
        elif address == 0xc0654:
            if scenario == 'write-error':
                finish_call(address, -105)
            else:
                uc.mem_write(x0, bytes(uc.mem_read(x1, x2)))
                finish_call(address)
        elif address == 0xb3414 or address == 0x113030:
            finish_call(address)

    uc.hook_add(UC_HOOK_CODE, hook)
    if scenario.startswith('empty') or scenario == 'missing-control':
        start = 0xf5eec
    elif scenario in ('allocation-error', 'write-error', 'publish-success', 'publish-error-after-store'):
        # Start after the unchanged vector construction. Its actual fields are
        # consumed by the helper's allocation, copy and publication instructions.
        uc.mem_write(sp + 0x2d8, struct.pack('<QQQ', BUFFER, BUFFER + 8, BUFFER + 8))
        uc.reg_write(UC_ARM64_REG_X0, CONTROL)
        from unicorn.arm64_const import UC_ARM64_REG_X21, UC_ARM64_REG_X8
        uc.reg_write(UC_ARM64_REG_X21, CONTROL)
        uc.reg_write(UC_ARM64_REG_X8, BUFFER)
        start = 0xf5e94
    else:
        start = 0xf5130
    uc.emu_start(start, 0, count=2000)
    assert state['stopped'], (scenario, hex(uc.reg_read(UC_ARM64_REG_PC)), state)
    state['live'] = read64(CONTROL)
    state['newBytes'] = bytes(uc.mem_read(NEW, 8)).hex()
    return state


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--helper', required=True, type=Path)
    parser.add_argument('--out', required=True, type=Path)
    parser.add_argument('--expect-legacy', action='store_true')
    args = parser.parse_args()
    scenarios = ['prepare', 'retirement-write-error', 'control-read-error', 'allocation-error',
                 'write-error', 'publish-success', 'publish-error-after-store', 'empty-list', 'missing-control']
    outcomes = {name: replay(args.helper, name) for name in scenarios}
    checks = {
        'publishedSnapshotsNeverFreed': not outcomes['prepare']['freed'],
        'preparationPreservesLivePointer': outcomes['prepare']['live'] == OLD,
        'retirementRecordCleared': outcomes['prepare']['retired'] == 0,
        'retirementWriteErrorPropagates': outcomes['retirement-write-error']['error'] == (-101 & MASK),
        'controlReadErrorPreservesLivePointer': outcomes['control-read-error']['live'] == OLD,
        'allocationErrorPreservesLivePointer': outcomes['allocation-error']['live'] == OLD,
        'writeErrorPreservesLivePointer': outcomes['write-error']['live'] == OLD,
        'completedTablePublished': outcomes['publish-success']['live'] == NEW and outcomes['publish-success']['newBytes'] == struct.pack('<II',10003,0).hex(),
        'publicationFailureDoesNotFreeCandidate': outcomes['publish-error-after-store']['live'] == NEW and not outcomes['publish-error-after-store']['freed'],
        'emptyListRevokes': outcomes['empty-list']['live'] == 0,
        'missingControlPropagates': outcomes['missing-control']['error'] == (-19921 & MASK),
    }
    report = dict(helperSha256=hashlib.sha256(args.helper.read_bytes()).hexdigest(), checks=checks,
                  passed=all(checks.values()), scenarios=outcomes,
                  scope='Real helper instructions; userspace and kernel APIs intercepted at existing ABI boundaries. This is an allowlist lifecycle replay, not an NX-panic reproduction.')
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(report, indent=2)+'\n', encoding='utf-8')
    if args.expect_legacy:
        assert not report['passed'] and not checks['publishedSnapshotsNeverFreed'] and not checks['preparationPreservesLivePointer']
        print('PASS legacy defect reproduced:', ', '.join(k for k,v in checks.items() if not v))
    else:
        assert report['passed'], checks
        print('PASS helper allowlist lifecycle:', len(checks), 'checks')


if __name__ == '__main__':
    main()
