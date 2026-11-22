"""Replay the real ARM64 bootstrap call site, thunk and original-loader continuation."""
import argparse
import io
import json
from pathlib import Path
from elftools.elf.elffile import ELFFile
from unicorn import Uc, UC_ARCH_ARM64, UC_MODE_ARM, UC_HOOK_CODE
from unicorn import arm64_const as reg

p = argparse.ArgumentParser(description=__doc__)
p.add_argument('--build', type=Path, required=True)
a = p.parse_args()
meta = json.loads((a.build / 'build.json').read_text())
blob = (a.build / 'embedded-bootstrap.elf').read_bytes()
elf = ELFFile(io.BytesIO(blob))
passed = []
for base in [0, 0x10000, 0x70000000]:
    for launcher_result in [0, 1, 2, 3, 4]:
        u = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
        u.mem_map(base, 0x140000)
        for s in elf.iter_segments():
            if s['p_type'] == 'PT_LOAD':
                u.mem_write(base + s['p_vaddr'], blob[s['p_offset']:s['p_offset'] + s['p_filesz']])
        stack = 0x400000
        u.mem_map(stack, 0x10000)
        u.reg_write(reg.UC_ARM64_REG_SP, stack + 0x8000)
        args = [0x123000 + i for i in range(9)]
        vectors = [(0x12340000 + i) << 64 | i for i in range(8)]
        for i in range(30): u.reg_write(getattr(reg, 'UC_ARM64_REG_X' + str(i)), args[i] if i < 9 else 0x9900 + i)
        for i, value in enumerate(vectors): u.reg_write(getattr(reg, 'UC_ARM64_REG_Q' + str(i)), value)
        calls = []
        def hook(uc, address, size, _):
            at = address - base
            if at == meta['launcher']:
                calls.append('identity')
                lr = uc.reg_read(reg.UC_ARM64_REG_X30)
                for i in range(19): uc.reg_write(getattr(reg, 'UC_ARM64_REG_X' + str(i)), launcher_result + i)
                for i in range(8): uc.reg_write(getattr(reg, 'UC_ARM64_REG_Q' + str(i)), 0)
                uc.reg_write(reg.UC_ARM64_REG_PC, lr)
            elif at == meta['originalModuleLoader']:
                calls.append('modules')
                assert [uc.reg_read(getattr(reg, 'UC_ARM64_REG_X' + str(i))) for i in range(9)] == args
                assert [uc.reg_read(getattr(reg, 'UC_ARM64_REG_Q' + str(i))) for i in range(8)] == vectors
                assert uc.reg_read(reg.UC_ARM64_REG_SP) == stack + 0x8000
                assert uc.reg_read(reg.UC_ARM64_REG_X30) == base + meta['hookSite'] + 4
                uc.reg_write(reg.UC_ARM64_REG_X0, 0x1234)
                uc.reg_write(reg.UC_ARM64_REG_PC, uc.reg_read(reg.UC_ARM64_REG_X30))
            elif at == meta['hookSite'] + 4:
                uc.emu_stop()
        u.hook_add(UC_HOOK_CODE, hook)
        u.emu_start(base + meta['hookSite'], base + 0x130000, count=200)
        assert calls == ['identity', 'modules']
        assert u.reg_read(reg.UC_ARM64_REG_X0) == 0x1234
        for i in range(19, 30): assert u.reg_read(getattr(reg, 'UC_ARM64_REG_X' + str(i))) == 0x9900 + i
        passed.append(dict(loadBase=base, launcherResult=launcher_result))
(a.build / 'entry-tests.json').write_text(json.dumps(dict(passed=True, cases=passed, deviceVerification=False), indent=2) + '\n')
print(f'PASS {len(passed)} ARM64 entry cases: registers, vectors, ASLR, errors and empty-module continuation')
