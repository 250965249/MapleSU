"""Execute the linked ARM64 query's reply-validation branch with ABI-level IPC fixtures."""
import argparse
import hashlib
import io
import json
import struct
from elftools.elf.elffile import ELFFile
from unicorn import Uc, UC_ARCH_ARM64, UC_MODE_ARM, UC_HOOK_CODE
from unicorn import arm64_const as r

p = argparse.ArgumentParser(description=__doc__)
p.add_argument('--library', required=True)
p.add_argument('--out', required=True)
a = p.parse_args()
blob = open(a.library, 'rb').read()
elf = ELFFile(io.BytesIO(blob))
symbol_rows = [s for s in elf.get_section_by_name('.symtab').iter_symbols()
               if isinstance(s['st_shndx'], int) and s['st_value']]
symbols = {s.name: s['st_value'] for s in symbol_rows}
getter = symbols['_ZN7maplesu3sdk29get_maplesu_environment_stateEPKc']
hooks = {
    '__wrap___set_current_module_root_key_hd04aBTnbSZlTRP7S4mQpIeVvr2ssGjW': 'key',
    '_ZN7maplesu3sdk14fork_base_infoC2Ev': 'construct',
    '_ZN7maplesu3sdk14fork_base_infoD2Ev': 'destroy',
    '_ZN7maplesu3sdk23fork_pipe_child_processERNS_14fork_pipe_infoE': 'fork',
    '_ZN7maplesu3sdk19read_int_from_childERKNS_14fork_pipe_infoERi': 'read',
    'maplesu_wait_environment_child': 'wait',
}
assert all(name in symbols for name in hooks)
# The archive contains several local constructors/destructors with the same name.
locations = {s['st_value']: hooks[s.name] for s in symbol_rows if s.name in hooks}
dyn = elf.get_section_by_name('.dynsym')
plt = elf.get_section_by_name('.plt')['sh_addr']
for i, relocation in enumerate(elf.get_section_by_name('.rela.plt').iter_relocations()):
    name = dyn.get_symbol(relocation['r_info_sym']).name
    if name in hooks: locations[plt + 32 + i * 16] = hooks[name]

cases = [
    dict(name='running', value=1, expected=1),
    dict(name='fault', value=2, expected=2),
    dict(name='unknown', value=3, expected=3),
    dict(name='not-installed', value=0, expected=0),
    dict(name='eof-after-running-bytes', value=1, read=False, expected=3),
    dict(name='eof-after-absence-bytes', value=0, read=False, expected=3),
    dict(name='child-exit-17', value=1, status=17 << 8, expected=3),
    dict(name='child-signal', value=1, status=9, expected=3),
    dict(name='invalid-child', value=1, child=0, wait=0, expected=3),
    dict(name='wait-error', value=1, wait=-1, expected=3),
    dict(name='wrong-child', value=1, wait=333, expected=3),
    dict(name='unexpected-enum', value=4, expected=3),
    dict(name='negative-enum', value=0xffffffff, expected=3),
]
results = []
for base in (0x1000000, 0x5000000, 0x11000000):
    for case in cases:
        u = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
        high = max(s['p_vaddr'] + s['p_memsz'] for s in elf.iter_segments() if s['p_type'] == 'PT_LOAD')
        u.mem_map(base, (high + 4095) & ~4095)
        for segment in elf.iter_segments():
            if segment['p_type'] == 'PT_LOAD': u.mem_write(base + segment['p_vaddr'], segment.data())
        stack, stop = 0x70000000, 0x71000000
        u.mem_map(stack, 0x20000)
        u.mem_map(stop, 4096)
        sp = stack + 0x10000
        u.reg_write(r.UC_ARM64_REG_SP, sp)
        u.reg_write(r.UC_ARM64_REG_X30, stop)
        u.reg_write(r.UC_ARM64_REG_X0, stack)
        preserved = {i: 0x11110000 + i for i in range(19, 30)}
        for i, value in preserved.items(): u.reg_write(getattr(r, f'UC_ARM64_REG_X{i}'), value)
        visited = []

        def hook(uc, address, size, _):
            if address == stop: uc.emu_stop(); return
            action = locations.get(address - base)
            if action is None: return
            visited.append(action)
            x0, x1 = [uc.reg_read(reg) for reg in (r.UC_ARM64_REG_X0, r.UC_ARM64_REG_X1)]
            value = 0
            if action in ('construct', 'fork'):
                child = case.get('child', 222) if action == 'fork' else 0
                uc.mem_write(x0, struct.pack('<iiiiii', -1, -1, 22, -1, 111, child))
            elif action == 'read':
                uc.mem_write(x1, struct.pack('<I', case['value']))
                value = int(case.get('read', True))
            elif action == 'wait':
                uc.mem_write(x1, struct.pack('<i', case.get('status', 0)))
                value = case.get('wait', case.get('child', 222))
            uc.reg_write(r.UC_ARM64_REG_X0, value & 0xffffffff)
            uc.reg_write(r.UC_ARM64_REG_PC, uc.reg_read(r.UC_ARM64_REG_X30))

        u.hook_add(UC_HOOK_CODE, hook)
        u.emu_start(base + getter, stop + 4, count=10000)
        actual = u.reg_read(r.UC_ARM64_REG_X0)
        assert u.reg_read(r.UC_ARM64_REG_PC) == stop
        assert actual == case['expected'], (case, actual, visited)
        assert u.reg_read(r.UC_ARM64_REG_SP) == sp
        assert all(u.reg_read(getattr(r, f'UC_ARM64_REG_X{i}')) == v for i, v in preserved.items())
        assert all(action in visited for action in ['key', 'construct', 'fork', 'read', 'wait', 'destroy'])
        results.append(dict(name=case['name'], aslrBase=hex(base), passed=True))
from pathlib import Path
Path(a.out).write_text(json.dumps(dict(passed=True, librarySha256=hashlib.sha256(blob).hexdigest(),
    actualLinkedArm64Instructions=True, syntheticIpc=True, calleeRegistersAndStackPreserved=True,
    deviceAcceptance=False, cases=results), indent=2) + '\n')
print(f'PASS linked ARM64 reply validation: {len(results)} cases; three ASLR bases; ABI preserved')
