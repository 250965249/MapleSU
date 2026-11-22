"""Replay delivered SDK version functions and legacy module dispatch offline."""
import argparse
import io
import json
from pathlib import Path
import re
import struct
import subprocess

from elftools.elf.elffile import ELFFile
from unicorn import Uc, UC_ARCH_ARM64, UC_MODE_ARM, UC_HOOK_CODE
from unicorn import arm64_const as r
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))  # shared helpers live in scripts/
from verify_sdk_member_diff import parse_ar

parser = argparse.ArgumentParser()
parser.add_argument('--build', type=Path, required=True)
parser.add_argument('--baseline', type=Path, required=True)
parser.add_argument('--ndk', type=Path, required=True)
args = parser.parse_args()
tool = args.ndk / 'toolchains/llvm/prebuilt/windows-x86_64/bin'
build = args.build
archive = build / 'libkernel_module_kit_static.a'
data = archive.read_bytes()
members = parse_ar(str(archive))['members']
def member_bytes(ordinal):
    m = members[ordinal]
    return data[m['body_offset']:m['body_offset']+m['size']]
def run(name, *argv):
    subprocess.run([str(tool/(name+'.exe')), *map(str, argv)], check=True, capture_output=True)
def cstring(u, address):
    return bytes(u.mem_read(address, 256)).split(b'\0')[0]
def machine():
    u = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
    u.mem_map(0x400000, 0x10000)
    u.mem_map(0x600000, 0x10000)
    u.reg_write(r.UC_ARM64_REG_SP, 0x408000)
    u.reg_write(r.UC_ARM64_REG_X30, 0x600100)
    return u
def load(u, payload, base=0):
    elf = ELFFile(io.BytesIO(payload))
    loads = [s for s in elf.iter_segments() if s['p_type']=='PT_LOAD']
    lo = min(base+s['p_vaddr'] for s in loads)&~4095
    hi = (max(base+s['p_vaddr']+s['p_memsz'] for s in loads)+4095)&~4095
    u.mem_map(lo, hi-lo)
    for s in loads: u.mem_write(base+s['p_vaddr'], s.data())
    return elf
def returned(u, value):
    link = u.reg_read(r.UC_ARM64_REG_X30)
    for i in range(19): u.reg_write(getattr(r, 'UC_ARM64_REG_X'+str(i)), 0xdead0000+i)
    u.reg_write(r.UC_ARM64_REG_X0, value)
    u.reg_write(r.UC_ARM64_REG_PC, link)
def plt_address(elf, name):
    dyn = elf.get_section_by_name('.dynsym')
    return next(elf.get_section_by_name('.plt')['sh_addr']+32+i*16
        for i,rel in enumerate(elf.get_section_by_name('.rela.plt').iter_relocations())
        if dyn.get_symbol(rel['r_info_sym']).name==name)

helper = (build/'embedded-bootstrap.elf').read_bytes()
assert member_bytes(52).count(helper)==1, 'delivered archive/helper mismatch'
obj = build/'version-probe.o'
obj.write_bytes(member_bytes(53))
linked = build/'version-probe.elf'
symbol = '_ZN7maplesu3sdk15get_sdk_versionEv'
run('ld.lld', '--unresolved-symbols=ignore-all', '--defsym=sscanf=0x600000',
    '--entry='+symbol, obj, '-o', linked)
checks = []
error_probe = build/'error-name-probe.cpp'
error_probe.write_text('#include "module_err_def.h"\n'
    'static_assert(kmoderr_name_sv(KModErr::ERR_MAPLESU_ENV_NOT_INSTALL) == "ERR_MAPLESU_ENV_UNPREPARED");\n'
    'static_assert(kmoderr_name_sv(KModErr::OK) == "OK");\n')
run('clang++', '--target=aarch64-linux-android21', '-std=c++17', '-fsyntax-only',
    '-I', Path(__file__).resolve().parents[2]/'runtime/maplesu-sdk/include', error_probe)
for ordinal in (48, 50):
    original_ir = (build/('m%03d.original.ll'%ordinal)).read_text()
    original = None
    for match in re.finditer(r'\[(\d+) x i64\] \[(.*?)\]', original_ir):
        values = [int(x)&((1<<64)-1) for x in re.findall(r'i64 (-?\d+)', match[2])]
        payload = struct.pack('<'+'Q'*len(values), *values)
        if payload.startswith(b'\x7fELF'): original=payload; break
    assert original is not None
    patched = (build/('m%03d.embedded.elf'%ordinal)).read_bytes()
    before,after = ELFFile(io.BytesIO(original)),ELFFile(io.BytesIO(patched))
    for section in ('.text','.plt','.dynsym','.dynstr'):
        assert before.get_section_by_name(section).data()==after.get_section_by_name(section).data()
    assert b'MapleSU Default Module\0' not in patched and b'ERR_MAPLESU_ENV_NOT_INSTALL\0' not in patched
    assert member_bytes(ordinal).count(patched)==1
checks.append('embedded su/WebUI display cleaned; code and dynamic ABI unchanged')
for label, payload, entry, sscanf in [
    ('SDK', linked.read_bytes(), None, 0x600000),
    ('embedded helper', helper, 0xb3b8c, None),
]:
    u = machine()
    elf = load(u, payload)
    entry = entry or elf['e_entry']
    sscanf = sscanf or plt_address(elf, 'sscanf')
    calls = []
    def hook(uc, address, size, _):
        if address==0x600100: uc.emu_stop()
        elif address==sscanf:
            text = cstring(uc, uc.reg_read(r.UC_ARM64_REG_X0))
            assert text==b'5.1.0' and cstring(uc, uc.reg_read(r.UC_ARM64_REG_X1))==b'%u.%u.%u'
            calls.append(text.decode())
            for i,value in enumerate((5,1,0)):
                uc.mem_write(uc.reg_read(getattr(r,'UC_ARM64_REG_X'+str(i+2))), struct.pack('<I',value))
            returned(uc, 3)
    u.hook_add(UC_HOOK_CODE, hook)
    u.emu_start(entry, 0x600104, count=100)
    assert calls==['5.1.0'] and u.reg_read(r.UC_ARM64_REG_X0)==(1<<32|5) and u.reg_read(r.UC_ARM64_REG_X1)==0
    assert u.reg_read(r.UC_ARM64_REG_SP)==0x408000
    checks.append(label+' get_sdk_version() = 5.1.0')

# Build a legacy module exporting only the original module entry name. Execute
# the helper's real dlopen/dlsym/call sequence against that ELF, with dynamic
# loader operations modeled at their libc boundaries.
legacy = '\x5f\x5f\x73\x6b\x72\x6f\x6f\x74\x5f\x6d\x6f\x64\x75\x6c\x65\x5f\x6d\x61\x69\x6e\x5f\x31\x38\x66\x64\x66\x33\x39\x33\x38\x38\x35\x33\x36\x33\x37\x31\x32\x33\x34\x39\x65\x66\x33\x64\x65\x35\x34\x31\x31\x62\x64\x35'
source = build/'legacy-module.S'
source.write_text('.text\n.global '+legacy+'\n.type '+legacy+', %function\n'+legacy+':\n'
    ' cbz x0, 1f\n cbz x1, 1f\n mov w0, #42\n ret\n1: mov w0, #99\n ret\n')
module = build/'legacy-module.so'
run('clang', '--target=aarch64-linux-android21', '-nostdlib', '-shared', source, '-o', module)
u = machine()
elf = load(u, helper)
module_elf = load(u, module.read_bytes(), 0x800000)
entry = next(s['st_value']+0x800000 for s in module_elf.get_section_by_name('.dynsym').iter_symbols() if s.name==legacy)
sp = 0x408000
u.mem_write(sp+0x50, bytes([len(b'legacy-module.so')<<1])+b'legacy-module.so\0')
u.mem_write(sp+0x38, b'\0')
u.mem_write(sp+8, struct.pack('<Q',0x409000))
u.mem_write(0x409100,b'/fixture/module\0')
u.mem_write(0x11f938,b'F'*48+b'\0')
u.reg_write(r.UC_ARM64_REG_X19,0x409100)
calls=[]
def loader_hook(uc,address,size,_):
    if address==0xa6780: uc.emu_stop()
    elif address==plt_address(elf,'dlopen'):
        assert cstring(uc,uc.reg_read(r.UC_ARM64_REG_X0))==b'legacy-module.so'
        assert uc.reg_read(r.UC_ARM64_REG_X1)==2
        calls.append('dlopen'); returned(uc,0x1234)
    elif address==plt_address(elf,'dlsym'):
        assert uc.reg_read(r.UC_ARM64_REG_X0)==0x1234
        assert cstring(uc,uc.reg_read(r.UC_ARM64_REG_X1)).decode()==legacy
        calls.append('dlsym legacy entry'); returned(uc,entry)
    elif address==entry:
        assert cstring(uc,uc.reg_read(r.UC_ARM64_REG_X0))==b'F'*48
        assert cstring(uc,uc.reg_read(r.UC_ARM64_REG_X1))==b'/fixture/module'
        calls.append('module called')
    elif address==plt_address(elf,'dlclose'):
        assert uc.reg_read(r.UC_ARM64_REG_X0)==0x1234
        calls.append('dlclose'); returned(uc,0)
u.hook_add(UC_HOOK_CODE,loader_hook)
u.emu_start(0xa6718,0xa6784,count=200)
assert struct.unpack('<I',bytes(u.mem_read(0x409000,4)))[0]==42
assert calls==['dlopen','dlsym legacy entry','module called','dlclose']
checks.append('legacy ELF loaded and invoked with return value 42 (loader boundary modeled)')
old = parse_ar(str(args.baseline))['members']
for ordinal,label in [(47,'version storage name'),(54,'module descriptor tags'),(63,'install/uninstall callback names')]:
    assert old[ordinal]['sha256']==members[ordinal]['sha256']
    checks.append(label+' unchanged')
assert not any(b'MapleSU' in x for x in re.findall(rb'[ -~]{6,}',helper))
checks.append('helper display strings contain no MapleSU branding')
(build/'version-compatibility.json').write_text(json.dumps({'checks':checks,'moduleCalls':calls,
    'hardwareVerification':False},indent=2)+'\n')
for check in checks: print('PASS '+check)
