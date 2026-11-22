"""Replay the actual selectively patched helper instructions in Unicorn."""
import argparse
from pathlib import Path
import hashlib
import json
import struct
import io
from elftools.elf.elffile import ELFFile
from elftools.dwarf.callframe import FDE
from unicorn import Uc, UC_ARCH_ARM64, UC_MODE_ARM, UC_HOOK_CODE
from unicorn import arm64_const as reg

parser = argparse.ArgumentParser()
parser.add_argument('--helper', type=Path, required=True)
parser.add_argument('--kernel', type=Path)
parser.add_argument('--out', type=Path)
args = parser.parse_args()
code = args.helper.read_bytes()
elf = ELFFile(io.BytesIO(code))
request_fde = next(e for e in elf.get_dwarf_info().EH_CFI_entries() if isinstance(e, FDE)
                   and e['initial_location'] == 0xc4598)
STACK, OUTPUT, SENTINEL = 0x400000, 0x500000, 0x600000
MASK = (1 << 64)-1
results = []
unwind_checks = []

def kernel_reply(value):
    """Use the report kernel's real getresuid/getresgid conversion prefix."""
    if not args.kernel:
        return value
    raw = args.kernel.read_bytes()
    assert hashlib.sha256(raw).hexdigest() == '9551b5938e08fce421db569976aa366ddf65a56481906df27cabd7910dc03aac'
    k = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
    k.mem_map(0, 0x2400000)
    k.mem_write(0, raw)
    k.mem_map(0x4000000, 0x10000)
    k.reg_write(reg.UC_ARM64_REG_SP_EL0, 0x4000000)
    k.reg_write(reg.UC_ARM64_REG_X0, 0x4004000)
    k.mem_write(0x4000820, struct.pack('<Q', 0x4002000))
    halves = []
    for start, end, offset, word in [(0xcd178, 0xcd1b8, 16, value & 0xffffffff),
                                    (0xcd600, 0xcd640, 20, value >> 32)]:
        k.mem_write(0x4002000 + offset, struct.pack('<I', word))
        k.emu_start(start, end, count=50)
        halves.append(k.reg_read(reg.UC_ARM64_REG_W8))
    return halves[0] | (halves[1] << 32)
def machine():
    u = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
    end = max(s['p_vaddr'] + s['p_memsz'] for s in elf.iter_segments() if s['p_type'] == 'PT_LOAD')
    u.mem_map(0x10000, (end + 4095) & ~4095)
    for segment in elf.iter_segments():
        if segment['p_type'] == 'PT_LOAD':
            u.mem_write(0x10000 + segment['p_vaddr'], segment.data())
    for at in (STACK, OUTPUT, SENTINEL): u.mem_map(at, 0x10000)
    u.mem_write(0x10000 + 0x11fa88, b'F'*48 + b'\0')
    u.reg_write(reg.UC_ARM64_REG_SP, STACK + 0x8000)
    u.reg_write(reg.UC_ARM64_REG_X30, SENTINEL)
    for i in range(19, 30): u.reg_write(getattr(reg, 'UC_ARM64_REG_X'+str(i)), 0x9900+i)
    return u
def returned(u, value):
    u.reg_write(reg.UC_ARM64_REG_X0, value & MASK)
    u.reg_write(reg.UC_ARM64_REG_PC, u.reg_read(reg.UC_ARM64_REG_X30))

def check_unwind(u, at):
    row = [row for row in request_fde.get_decoded().table if row['pc'] <= at][-1]
    cfa = row['cfa']
    register = reg.UC_ARM64_REG_SP if cfa.reg == 31 else getattr(reg, 'UC_ARM64_REG_X'+str(cfa.reg))
    caller_sp = u.reg_read(register) + cfa.offset
    assert caller_sp == STACK+0x8000, 'request unwind CFA differs from caller SP'
    for i in [19, 20, 21, 22, 29, 30]:
        if i not in row:
            continue
        rule = row[i]
        assert rule.type == 'OFFSET'
        saved = struct.unpack('<Q', bytes(u.mem_read(caller_sp + rule.arg, 8)))[0]
        assert saved == (SENTINEL if i == 30 else 0x9900+i), ('request unwind saved register', i)
    unwind_checks.append(at)
for flag, reply, expected in [(51, MASK-19998, MASK-19998),
                              (51, 0x0000fffeffffb1e1, MASK-19998),
                              (51, 0x123456789abcde00, 0),
                              (51, 0x12345678ffffb1e1, 0),
                              (51, 0x0000fffeffffb1e0, 0),
                              (50, 0x0000fffeffffb1e1, 0), (53, 0, 0)]:
    reply = kernel_reply(reply)
    u = machine()
    for i, value in enumerate([flag, 0, 0x1234000, 4096, 1, OUTPUT]):
        u.reg_write(getattr(reg, 'UC_ARM64_REG_X'+str(i)), value)
    def hook(uc, address, size, _):
        at = address - 0x10000
        if address == SENTINEL: uc.emu_stop()
        elif at == 0xc459c: check_unwind(uc, at)
        elif at == 0x112fc0:
            number = uc.reg_read(reg.UC_ARM64_REG_X0)
            if number in (90, 91):
                header = uc.reg_read(reg.UC_ARM64_REG_X1)
                data = uc.reg_read(reg.UC_ARM64_REG_X2)
                assert bytes(uc.mem_read(header, 8)) == struct.pack('<II', 0x20080522, 0)
                caps = struct.pack('<6I', 0x1234, 0x2345, 0x3456, 0x4567, 0x5678, 0x6789)
                if number == 90:
                    uc.mem_write(data, caps)
                else:
                    assert bytes(uc.mem_read(data, 24)) == caps
                returned(uc, 0)
                return
            assert number == 221
            check_unwind(uc, uc.reg_read(reg.UC_ARM64_REG_X30)-0x10000-4)
            request = bytes(uc.mem_read(uc.reg_read(reg.UC_ARM64_REG_X1), 85))
            decoded = bytes((a+b)&255 for a,b in zip(request[48:66], request[66:84]))
            assert request[:48] == b'F'*48 and request[84] == 0
            assert decoded == struct.pack('<BBQII', flag, 0, 0x1234000, 4096, 1)
            returned(uc, -1)
        elif at == 0xc4560:
            check_unwind(uc, uc.reg_read(reg.UC_ARM64_REG_X30)-0x10000-4)
            returned(uc, reply & 0xffffffff)
        elif at == 0xc457c:
            check_unwind(uc, uc.reg_read(reg.UC_ARM64_REG_X30)-0x10000-4)
            returned(uc, reply >> 32)
    u.hook_add(UC_HOOK_CODE, hook)
    u.emu_start(0x10000+0xc4598, SENTINEL+4, count=1000)
    actual = u.reg_read(reg.UC_ARM64_REG_X0)
    results.append(dict(flag=flag, reply=hex(reply), expected=hex(expected), actual=hex(actual), passed=actual == expected))
    assert actual == expected, results[-1]
    assert struct.unpack('<Q', bytes(u.mem_read(OUTPUT, 8)))[0] == reply
    assert u.reg_read(reg.UC_ARM64_REG_SP) == STACK+0x8000
    for i in range(19, 30): assert u.reg_read(getattr(reg, 'UC_ARM64_REG_X'+str(i))) == 0x9900+i
    print('PASS helper request flag', flag, 'error' if expected == MASK-19998 else 'success')

# Invalid execution requests must stop before sending code to the kernel.
for address, size, pages in [(0, 4096, 1), (0x1234000, 0, 0), (0x1234000, 4096, 0)]:
    u = machine()
    for i, value in enumerate([51, 0, address, size, pages, OUTPUT]):
        u.reg_write(getattr(reg, 'UC_ARM64_REG_X'+str(i)), value)
    def invalid_hook(uc, at, size, _):
        if at == SENTINEL: uc.emu_stop()
        elif at == 0x10000 + 0x112fc0: raise AssertionError('invalid execution request reached syscall')
    u.hook_add(UC_HOOK_CODE, invalid_hook)
    u.emu_start(0x10000+0xc4598, SENTINEL+4, count=1000)
    assert u.reg_read(reg.UC_ARM64_REG_X0) == MASK-19998
    assert u.reg_read(reg.UC_ARM64_REG_SP) == STACK+0x8000
    for i in range(19, 30): assert u.reg_read(getattr(reg, 'UC_ARM64_REG_X'+str(i))) == 0x9900+i
    results.append(dict(name='invalid_execution', address=address, size=size, pages=pages, passed=True))
    print('PASS invalid execution request', address, size, pages)

# Execute the helper's original allocator/copy/exec wrapper including its patched
# failure branch. Calls into libc and kernel request transport are the boundaries.
for failure in ('copy', 'exec', 'none'):
    u = machine()
    u.reg_write(reg.UC_ARM64_REG_X0, OUTPUT+0x1000)
    u.reg_write(reg.UC_ARM64_REG_X1, 4)
    u.reg_write(reg.UC_ARM64_REG_X2, OUTPUT)
    calls = []
    def executor_hook(uc, address, size, _):
        at = address - 0x10000
        if address == SENTINEL: uc.emu_stop()
        elif at == 0xc4850:
            uc.mem_write(uc.reg_read(reg.UC_ARM64_REG_X1), struct.pack('<Q', 0x1234000))
            returned(uc, 0)
        elif at == 0xc46f4:
            calls.append('copy'); returned(uc, -20000 if failure == 'copy' else 0)
        elif at == 0xc4598:
            assert uc.reg_read(reg.UC_ARM64_REG_X0) == 53
            assert uc.reg_read(reg.UC_ARM64_REG_X2) == 0x1234000
            calls.append('release'); returned(uc, 0)
        elif at == 0xc47d4:
            calls.append('exec')
            uc.mem_write(uc.reg_read(reg.UC_ARM64_REG_X2), struct.pack('<Q', 0x123456789abcde00))
            returned(uc, -19999 if failure == 'exec' else 0)
    # Resolve prctl PLT from its dynamic relocation rather than a guessed address.
    from elftools.elf.elffile import ELFFile
    import io
    elf = ELFFile(io.BytesIO(code)); dyn = elf.get_section_by_name('.dynsym')
    rela = elf.get_section_by_name('.rela.plt'); plt = elf.get_section_by_name('.plt')
    prctl = next(plt['sh_addr']+32+i*16 for i,r in enumerate(rela.iter_relocations())
                 if dyn.get_symbol(r['r_info_sym']).name == 'prctl')
    def combined(uc, address, size, context):
        if address == 0x10000+prctl: returned(uc, 0x7654)
        else: executor_hook(uc, address, size, context)
    u.hook_add(UC_HOOK_CODE, combined)
    u.emu_start(0x10000+0xc5dd8, SENTINEL+4, count=500)
    assert u.reg_read(reg.UC_ARM64_REG_X0) == ({'copy':-20000,'exec':-19999,'none':0}[failure] & MASK)
    assert calls == (['copy','release'] if failure == 'copy' else ['copy','exec'])
    assert u.reg_read(reg.UC_ARM64_REG_SP) == STACK+0x8000
    results.append(dict(name='staging_'+failure, calls=calls, passed=True))
    print('PASS helper staging', failure)

if args.out:
    args.out.write_text(json.dumps(dict(cases=results, passed=all(c['passed'] for c in results),
        helperSha256=hashlib.sha256(code).hexdigest(), unwindChecks=len(unwind_checks),
        unwindLocations=sorted(set(unwind_checks)), deviceVerification=False), indent=2) + '\n')
