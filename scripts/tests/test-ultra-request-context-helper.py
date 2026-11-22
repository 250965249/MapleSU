"""Replay shared credentials against the delivered ARM64 request instructions."""
import argparse
import hashlib
import io
import json
from pathlib import Path
import struct

from elftools.elf.elffile import ELFFile
from unicorn import Uc, UC_ARCH_ARM64, UC_MODE_ARM, UC_HOOK_CODE
from unicorn import arm64_const as reg

parser = argparse.ArgumentParser(description=__doc__)
source = parser.add_mutually_exclusive_group(required=True)
source.add_argument('--helper', type=Path)
source.add_argument('--sdk-elf', type=Path)
parser.add_argument('--out', type=Path, required=True)
args = parser.parse_args()
blob = (args.helper or args.sdk_elf).read_bytes()
elf = ELFFile(io.BytesIO(blob))
sdk = args.sdk_elf is not None
symbols = {s.name: s['st_value'] for s in elf.get_section_by_name('.symtab').iter_symbols()} if sdk else {}
dyn = elf.get_section_by_name('.dynsym')
plt = {dyn.get_symbol(r['r_info_sym']).name: elf.get_section_by_name('.plt')['sh_addr'] + 32 + 16 * i
       for i, r in enumerate(elf.get_section_by_name('.rela.plt').iter_relocations())}
entry = symbols['_ZN13kernel_moduleL19send_kernel_requestENS_13KernelCmdFlagEhmjjPm'] if sdk else 0xc4598
syscall = plt['syscall'] if sdk else 0x112fc0
get_suid = plt['getresuid'] if sdk else 0xc4560
get_sgid = plt['getresgid'] if sdk else 0xc457c
key_name = '__get_current_module_root_key_hd04aBTnbSZlTRP7S4mQpIeVvr2ssGjW'
key_entries = {table.get(name) for table in (symbols, plt)
               for name in (key_name, '__wrap_' + key_name)} if sdk else set()
BASE, STACK, OUTPUT, STOP = 0x10000, 0x4000000, 0x5000000, 0x6000000
MASK = (1 << 64) - 1
CAPS = struct.pack('<6I', 0x1234, 0x2345, 0x3456, 0x4567, 0x5678, 0x6789)
ADDRESSES = (0xffffff8001234000, 0xffffff8005678000)


class Request:
    def __init__(self, inherited, reply, fail=0, flag=48, address=0, size=4096, pages=1):
        self.cred, self.reply, self.fail = inherited, reply, fail
        self.calls, self.copied, self.paused, self.finished = [], 0, False, False
        self.heap = OUTPUT + 0x4000
        self.uc = u = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
        end = max(s['p_vaddr'] + s['p_memsz'] for s in elf.iter_segments() if s['p_type'] == 'PT_LOAD')
        u.mem_map(BASE, (end + 4095) & ~4095)
        for segment in elf.iter_segments():
            if segment['p_type'] == 'PT_LOAD':
                u.mem_write(BASE + segment['p_vaddr'], segment.data())
        for at in (STACK, OUTPUT, STOP):
            u.mem_map(at, 0x10000)
        u.mem_write(OUTPUT + 0x1000 if sdk else BASE + 0x11fa88, b'F' * 48 + b'\0')
        u.mem_write(OUTPUT, struct.pack('<Q', 0x1234))
        u.reg_write(reg.UC_ARM64_REG_SP, STACK + 0x8000)
        u.reg_write(reg.UC_ARM64_REG_X30, STOP)
        for i in range(19, 30):
            u.reg_write(getattr(reg, 'UC_ARM64_REG_X' + str(i)), 0x9900 + i)
        for i, value in enumerate((flag, 0, address, size, pages, OUTPUT)):
            u.reg_write(getattr(reg, 'UC_ARM64_REG_X' + str(i)), value)
        u.hook_add(UC_HOOK_CODE, self.hook)

    def returned(self, value):
        self.uc.reg_write(reg.UC_ARM64_REG_X0, value & MASK)
        self.uc.reg_write(reg.UC_ARM64_REG_PC, self.uc.reg_read(reg.UC_ARM64_REG_X30))

    def hook(self, u, address, size, context):
        at = address - BASE
        if address == STOP:
            self.finished = True
            u.emu_stop()
        elif at in key_entries:
            self.returned(OUTPUT + 0x1000)
        elif sdk and at in (plt.get('__strlen_chk'), plt.get('strlen'), plt.get('strnlen')):
            assert bytes(u.mem_read(u.reg_read(reg.UC_ARM64_REG_X0), 49)) == b'F' * 48 + b'\0'
            self.returned(48)
        elif sdk and at in (plt.get('malloc'), plt.get('_Znwm')):
            allocation = self.heap
            self.heap += (u.reg_read(reg.UC_ARM64_REG_X0) + 15) & ~15
            assert self.heap < OUTPUT + 0x10000
            self.returned(allocation)
        elif sdk and at == plt.get('memcpy'):
            destination = u.reg_read(reg.UC_ARM64_REG_X0)
            u.mem_write(destination, bytes(u.mem_read(u.reg_read(reg.UC_ARM64_REG_X1), u.reg_read(reg.UC_ARM64_REG_X2))))
            self.returned(destination)
        elif sdk and at == plt.get('memset'):
            destination = u.reg_read(reg.UC_ARM64_REG_X0)
            u.mem_write(destination, bytes([u.reg_read(reg.UC_ARM64_REG_X1) & 255]) * u.reg_read(reg.UC_ARM64_REG_X2))
            self.returned(destination)
        elif sdk and at in (plt.get('free'), plt.get('_ZdlPv')):
            self.returned(0)
        elif at == syscall:
            number = u.reg_read(reg.UC_ARM64_REG_X0)
            self.calls.append(number)
            if number in (90, 91):
                header, data = u.reg_read(reg.UC_ARM64_REG_X1), u.reg_read(reg.UC_ARM64_REG_X2)
                assert bytes(u.mem_read(header, 8)) == struct.pack('<II', 0x20080522, 0)
                if self.fail == number:
                    self.returned(-1)
                elif number == 90:
                    u.mem_write(data, CAPS)
                    self.returned(0)
                else:
                    assert bytes(u.mem_read(data, 24)) == CAPS
                    self.cred = dict(self.cred)
                    self.copied += 1
                    self.returned(0)
            else:
                assert number == 221
                data = bytes(u.mem_read(u.reg_read(reg.UC_ARM64_REG_X1), 85))
                assert data[:48] == b'F' * 48 and data[84] == 0
                request = bytes((a + b) & 255 for a, b in zip(data[48:66], data[66:84]))
                assert request[0] in (48, 51)
                self.cred['suid'], self.cred['sgid'] = self.reply & 0xffffffff, self.reply >> 32
                self.returned(-1)
                if not self.paused:
                    self.paused = True
                    u.emu_stop()
        elif at in (get_suid, get_sgid):
            value = self.cred['suid' if at == get_suid else 'sgid']
            if sdk:
                for i, word in enumerate((0, 0, value)):
                    u.mem_write(u.reg_read(getattr(reg, 'UC_ARM64_REG_X' + str(i))), struct.pack('<I', word))
                self.returned(0)
            else:
                self.returned(value)
        elif sdk and at in plt.values():
            raise AssertionError(('unexpected import', next(name for name, value in plt.items() if value == at)))

    def run(self):
        start = self.uc.reg_read(reg.UC_ARM64_REG_PC) if self.paused else BASE + entry
        self.uc.emu_start(start, STOP + 4, count=5000)

    def checked(self):
        assert self.finished, (hex(self.uc.reg_read(reg.UC_ARM64_REG_PC)), self.calls)
        assert self.uc.reg_read(reg.UC_ARM64_REG_SP) == STACK + 0x8000
        for i in range(19, 30):
            assert self.uc.reg_read(getattr(reg, 'UC_ARM64_REG_X' + str(i))) == 0x9900 + i
        return struct.unpack('<Q', bytes(self.uc.mem_read(OUTPUT, 8)))[0]


shared = dict(suid=10000, sgid=10000)
a, b = [Request(shared, reply) for reply in ADDRESSES]
a.run()  # Pause after A writes its kernel reply, before A reads it.
b.run()
b.run()
a.run()
observed = (a.checked(), b.checked())
if observed != ADDRESSES:
    raise AssertionError(f'ARM64 reply collision: {tuple(hex(x) for x in observed)}; expected {tuple(hex(x) for x in ADDRESSES)}')
assert shared == dict(suid=10000, sgid=10000) and a.copied == b.copied == 1
print('PASS ARM64 request: interleaved replies private; parent/fork-inherited credentials unchanged')
checks = 1
for failed_syscall in (90, 91):
    request = Request(shared, ADDRESSES[0], fail=failed_syscall)
    request.run()
    assert request.checked() == 0x1234 and 221 not in request.calls
    assert request.uc.reg_read(reg.UC_ARM64_REG_X0) > (1 << 63)
    checks += 1
print('PASS ARM64 request: failed credential copy stops before kernel submission')
for address, size, pages in (() if sdk else ((0, 4096, 1), (0x1234000, 0, 0), (0x1234000, 4096, 0))):
    request = Request(shared, ADDRESSES[0], flag=51, address=address, size=size, pages=pages)
    request.run()
    assert request.checked() == 0x1234 and 221 not in request.calls
    if not sdk:
        assert not request.calls
    checks += 1
for reply in (0x0000fffeffffb1e1, MASK - 19998, 0x123456789abcde00):
    request = Request(shared, reply, flag=51, address=0x1234000)
    request.run()
    request.run()
    assert request.checked() == reply
    expected = MASK - 19998 if reply in (0x0000fffeffffb1e1, MASK - 19998) else 0
    assert request.uc.reg_read(reg.UC_ARM64_REG_X0) == expected
    checks += 1
print('PASS ARM64 request: complete legacy/mapped execution errors retained')
args.out.parent.mkdir(parents=True, exist_ok=True)
args.out.write_text(json.dumps(dict(passed=True, checks=checks, actualArm64Instructions=True,
    deviceVerification=False, elfSha256=hashlib.sha256(blob).hexdigest(),
    source='linked SDK' if sdk else 'embedded helper',
    model='shared saved-ID credentials; copy on raw capset'), indent=2) + '\n')
