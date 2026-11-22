"""Replay helper -> real report kernel dispatch/executor -> real ID conversion -> helper.

Permission routines, allocations, copied code, and the final execve filesystem
lookup are modeled boundaries. This does not emulate hardware caches or a boot.
"""
import argparse
import hashlib
import json
from pathlib import Path
import struct
from unicorn import Uc, UC_ARCH_ARM64, UC_MODE_ARM, UC_HOOK_CODE
from unicorn import arm64_const as r

p = argparse.ArgumentParser(description=__doc__)
p.add_argument('--kernel', type=Path, required=True)
p.add_argument('--helper', type=Path, required=True)
p.add_argument('--symbols', type=Path, required=True)
p.add_argument('--receipt', type=Path, required=True)
p.add_argument('--out', type=Path, required=True)
a = p.parse_args()
kernel, helper = a.kernel.read_bytes(), a.helper.read_bytes()
assert hashlib.sha256(kernel).hexdigest() == '9551b5938e08fce421db569976aa366ddf65a56481906df27cabd7910dc03aac'
records = {x['role']: x for x in json.loads(a.receipt.read_text())['records']}
symbols = {line.split('\t')[2]: int(line.split('\t')[0], 16) for line in a.symbols.read_text().splitlines()}
BASE, DATA, STACK, BUFFER = 0x1000000, 0x5000000, 0x6000000, 0x7000000
TASK, CRED, REQUEST, FILENAME, PTREGS = DATA, DATA+0x2000, DATA+0x6000, DATA+0x7000, DATA+0x8000
SP, MASK = STACK+0x8000, (1<<64)-1
key_at = records['panic+0x0']['offset']
key = kernel[key_at:key_at+48]  # Opaque fixture; never output credentials.
restore = BASE + records['arm64_notify_die+0x0']['offset']
resume = BASE + symbols['do_execveat_common'] + 8


def kernel_flow(message, statuses=(0, 0, 0, 0), reply=0x123456789abcde00, euid=10000):
    u = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
    u.mem_map(BASE, (len(kernel)+4095)&~4095)
    u.mem_write(BASE, kernel)
    for at in DATA, STACK, BUFFER:
        u.mem_map(at, 0x10000)
    u.reg_write(r.UC_ARM64_REG_SP_EL0, TASK)
    u.mem_write(TASK+0x820, struct.pack('<Q', CRED))
    u.mem_write(CRED+24, struct.pack('<I', euid))
    u.mem_write(CRED+16, struct.pack('<Q', 0x1111222233334444))
    if message is not None:
        u.mem_write(REQUEST, message)
    u.mem_write(FILENAME, struct.pack('<Q', REQUEST))
    u.reg_write(r.UC_ARM64_REG_SP, SP)
    initial = {i: 0x999000+i for i in range(31)}
    initial[1] = MASK-13 if message is None else FILENAME
    for i, value in initial.items():
        u.reg_write(getattr(r, 'UC_ARM64_REG_X'+str(i)), value)
    calls = []
    boundaries = {BASE+symbols[name]: (kind, status) for name, kind, status in zip(
        ['set_memory_ro','set_memory_x','set_memory_nx','set_memory_rw'], ['ro','x','nx','rw'], statuses)}
    boundaries[BASE+symbols['module_memfree']] = ('free', 0)

    def hook(uc, address, size, _):
        if address == resume:
            uc.emu_stop()
        elif address in boundaries:
            kind, status = boundaries[address]
            calls.append(kind)
            assert uc.reg_read(r.UC_ARM64_REG_X0) == BUFFER
            if kind != 'free':
                assert uc.reg_read(r.UC_ARM64_REG_X1) == 1
            link = uc.reg_read(r.UC_ARM64_REG_X30)
            for i in range(19):
                uc.reg_write(getattr(r, 'UC_ARM64_REG_X'+str(i)), 0xdead000+i)
            uc.reg_write(r.UC_ARM64_REG_X0, status & 0xffffffff)
            uc.reg_write(r.UC_ARM64_REG_PC, link)
        elif address == BUFFER:
            calls.append('executed')
            assert uc.reg_read(r.UC_ARM64_REG_X17) == CRED+16
            uc.mem_write(CRED+16, struct.pack('<Q', reply))
            uc.reg_write(r.UC_ARM64_REG_PC, uc.reg_read(r.UC_ARM64_REG_X30))
        elif bytes(uc.mem_read(address, 4)) == bytes.fromhex('1f7508d5'):
            uc.reg_write(r.UC_ARM64_REG_PC, address+4)
    u.hook_add(UC_HOOK_CODE, hook)
    # PACIASP remains at the original entry. Start after it, with an opaque LR,
    # then verify the exact stack allocation and continuation of the real image.
    u.emu_start(BASE+symbols['do_execveat_common']+4, 0, count=3000)
    assert u.reg_read(r.UC_ARM64_REG_PC) == resume
    assert u.reg_read(r.UC_ARM64_REG_SP) == SP-0x70
    for i in [*range(8), *range(19,31)]:
        assert u.reg_read(getattr(r, 'UC_ARM64_REG_X'+str(i))) == initial[i], i
    raw_reply = struct.unpack('<Q', bytes(u.mem_read(CRED+16, 8)))[0]
    halves = []
    u.reg_write(r.UC_ARM64_REG_X0, PTREGS)
    for symbol, stop in [('__arm64_sys_getresuid',0xcd1b8), ('__arm64_sys_getresgid',0xcd640)]:
        u.emu_start(BASE+symbols[symbol], BASE+stop, count=50)
        halves.append(u.reg_read(r.UC_ARM64_REG_W8))
    return calls, raw_reply, halves[0] | (halves[1]<<32)


def sdk_flow(statuses, expected, address=BUFFER, size=4096, pages=1, reply=0x123456789abcde00):
    u = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
    u.mem_map(0x10000,0x130000)
    u.mem_write(0x10000, helper)
    for at in [0x400000,0x500000,0x600000]:
        u.mem_map(at,0x10000)
    u.mem_write(0x10000+0x11fa88,key+b'\0')
    u.reg_write(r.UC_ARM64_REG_SP,0x408000)
    u.reg_write(r.UC_ARM64_REG_X30,0x600000)
    for i in range(19,30):
        u.reg_write(getattr(r,'UC_ARM64_REG_X'+str(i)),0x9900+i)
    for i,value in enumerate([51,0,address,size,pages,0x500000]):
        u.reg_write(getattr(r,'UC_ARM64_REG_X'+str(i)),value)
    state = dict(kernelCalls=0, calls=[], raw=0, converted=0)

    def returned(uc,value):
        uc.reg_write(r.UC_ARM64_REG_X0,value&MASK)
        uc.reg_write(r.UC_ARM64_REG_PC,uc.reg_read(r.UC_ARM64_REG_X30))

    def hook(uc,at,size,_):
        offset=at-0x10000
        if at==0x600000: uc.emu_stop()
        elif offset==0x112fc0:
            message=bytes(uc.mem_read(uc.reg_read(r.UC_ARM64_REG_X1),85))
            assert b'\0' not in message[:-1] and message[84]==0
            state['kernelCalls']+=1
            state['calls'],state['raw'],state['converted']=kernel_flow(message,statuses,reply)
            returned(uc,-1)  # Original execve continues to its missing filename.
        elif offset==0xc4560: returned(uc,state['converted']&0xffffffff)
        elif offset==0xc457c: returned(uc,state['converted']>>32)
    u.hook_add(UC_HOOK_CODE,hook)
    u.emu_start(0x10000+0xc4598,0x600004,count=1000)
    status=u.reg_read(r.UC_ARM64_REG_X0)
    state.update(status=hex(status),expected=hex(expected&MASK),passed=status==(expected&MASK))
    assert u.reg_read(r.UC_ARM64_REG_SP)==0x408000
    for i in range(19,30):
        assert u.reg_read(getattr(r,'UC_ARM64_REG_X'+str(i)))==0x9900+i
    if state['kernelCalls']:
        assert struct.unpack('<Q',bytes(u.mem_read(0x500000,8)))[0]==state['converted']
    return state


cases=[]
for name,statuses,expected,calls in [
    ('success',(0,0,0,0),0,['ro','x','executed','nx','rw','free']),
    ('ro_failure',(-22,0,0,0),-19999,['ro','nx','rw','free']),
    ('x_failure',(0,-22,0,0),-19999,['ro','x','nx','rw','free']),
    ('nx_failure',(0,0,-22,0),-19999,['ro','x','executed','nx']),
    ('rw_failure',(0,0,0,-22),-19999,['ro','x','executed','nx','rw']),
]:
    result=sdk_flow(statuses,expected)
    result['passed']=result['passed'] and result['calls']==calls and result['kernelCalls']==1
    result['name']=name
    cases.append(result)
for name,address,size,pages in [('null',0,4096,1),('zero_length',BUFFER,0,0),('zero_pages',BUFFER,4096,0)]:
    try:
        result=sdk_flow((0,0,0,0),-19999,address,size,pages)
        result['passed']=result['passed'] and result['kernelCalls']==0
    except AssertionError:
        result=dict(passed=False, detail='invalid execution request reached kernel permission/execution boundary')
    result['name']=name
    cases.append(result)
for name,euid in [('ordinary_app',10000),('ordinary_root',0),('error_filename',10000)]:
    # Ordinary paths have a first-byte mismatch and must retain the original ABI.
    message=None if name=='error_filename' else b'/system/bin/sh\0'+bytes(80)
    calls,raw,converted=kernel_flow(message,euid=euid)
    cases.append(dict(name=name,passed=calls==[] and raw==0x1111222233334444))
report=dict(cases=cases,passed=all(c['passed'] for c in cases),
    kernelSha256=hashlib.sha256(kernel).hexdigest(),helperSha256=hashlib.sha256(helper).hexdigest(),
    deviceVerification=False, boundaries='permission routines, copied code, final execve lookup; PAC instruction not emulated')
a.out.write_text(json.dumps(report,indent=2)+'\n')
for c in cases: print(('PASS ' if c['passed'] else 'FAIL ')+c['name'])
raise SystemExit(0 if report['passed'] else 1)
