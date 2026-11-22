"""Derive a pinned helper candidate; preserve original frames and unwind tables."""
import argparse
import hashlib
import io
import json
from pathlib import Path
import struct
import subprocess
from elftools.elf.elffile import ELFFile

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / 'runtime/ultra/panic'
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--helper', type=Path, required=True, help='Exact r8 embedded helper')
parser.add_argument('--out', type=Path, required=True)
parser.add_argument('--ndk', type=Path, required=True)
args = parser.parse_args()
SOURCE = args.helper.resolve()
BUILD = args.out.resolve()
assert not SOURCE.is_relative_to(BUILD), 'Keep the baseline outside the output directory'
BUILD.mkdir(parents=True, exist_ok=True)
OUT = BUILD / 'cache-text'
OUT.mkdir(exist_ok=True)
TOOL = args.ndk / 'toolchains/llvm/prebuilt/windows-x86_64/bin' 
original = SOURCE.read_bytes()
assert hashlib.sha256(original).hexdigest() == '9917cd9fb9ba15b4169fc60285215e8b3efe02b96bdb52229c49339cf2a94089'
elf = ELFFile(io.BytesIO(original))
loads = [(i, s) for i, s in enumerate(elf.iter_segments()) if s['p_type'] == 'PT_LOAD']
index, tail = max(loads, key=lambda item: item[1]['p_vaddr'])
assert tail['p_flags'] == 5 and tail['p_offset'] + tail['p_filesz'] <= len(original)
start = (tail['p_vaddr'] + max(tail['p_memsz'], len(original)-tail['p_offset']) + 15) & ~15
patches = {
    0xc04d4: 'b maplesu_helper_text_identify',
    0xc04f0: 'bl maplesu_helper_text_generated',
    0xc04fc: 'bl maplesu_helper_text_epilogue',
    0xc0518: 'bl maplesu_helper_text_checked',
    0xc4c70: 'add x0, sp, #0\nbl maplesu_helper_icache_begin\ncbnz x0, original_icache_return\nb 0xc4c94',
    0xc4cf0: 'ldr x0, [sp, #0]\nbl maplesu_helper_icache_next\ncbnz x0, maplesu_helper_icache_next_exit',
    0xc4ea4: 'mov x0, x25\nb original_icache_finish',
    0xc4eb4: 'b 0xc4cf0',
    0xc4eec: 'b maplesu_helper_icache_exit',
    0xc4f78: 'b maplesu_helper_icache_unwind',
}
# Absolute branch operands in integrated assembler mean PC-relative immediates.
# Name all original targets so the linker, rather than the assembler, resolves them.
patches = {at: code.replace('b 0xc4c94', 'b original_icache_setup').replace('b 0xc4cf0', 'b original_icache_next')
           for at, code in patches.items()}
assembly = '\n'.join(f'.section .patch_{at:x},"ax"\n{code}\n' for at,code in patches.items())
(OUT / 'patches.S').write_text(assembly)
asm = (SRC / 'helper_icache.S').read_text(encoding='utf-8-sig') + (SRC / 'helper_text.S').read_text()
(OUT / 'thunks.S').write_text(asm)
def run(name, *args):
    r = subprocess.run([str(TOOL/(name+'.exe')), *map(str,args)], capture_output=True, text=True)
    if r.returncode: raise RuntimeError(r.stdout+r.stderr)
common = ['--target=aarch64-linux-android21','-Oz','-ffreestanding','-fno-builtin',
          '-fno-stack-protector','-fno-unwind-tables','-fno-asynchronous-unwind-tables','-fPIC','-Wall','-Wextra','-Werror','-c']
run('clang', *common, SRC/'helper_icache.c','-o',OUT/'policy.o')
run('clang', *common, OUT/'thunks.S','-o',OUT/'thunks.o')
run('clang', *common, OUT/'patches.S','-o',OUT/'patches.o')
sections = 'SECTIONS {\n'+''.join(f' .patch_{at:x} {hex(at)} : {{ *(.patch_{at:x}) }}\n' for at in patches)
sections += f' .extension {hex(start)} : {{ *(.text*) *(.rodata*) }}\n /DISCARD/ : {{ *(.comment) *(.note*) *(.eh_frame*) }}\n}}\n'
(OUT/'patch.ld').write_text(sections)
defs = {'original_icache_return':0xc4f28,'original_icache_finish':0xc4eec,
        'original_icache_setup':0xc4c94,'original_icache_next':0xc4cf0,
        'original_icache_resume_call':0xc4f7c,
        'original_text_vtable':0x119660,'original_noresult_init_call':0xc04d8,
        'original_noresult_end':0xc5648,'original_x0_operand':0x2e194,'original_result_end':0xc57a8}
# Reuse original dynamic imports; no new relocations or dynamic dependencies.
dyn=elf.get_section_by_name('.dynsym'); plt=elf.get_section_by_name('.plt')['sh_addr']
for i,rel in enumerate(elf.get_section_by_name('.rela.plt').iter_relocations()):
    defs[dyn.get_symbol(rel['r_info_sym']).name] = plt+32+16*i
run('ld.lld','-T',OUT/'patch.ld','--entry=maplesu_helper_icache_begin',
    *[f'--defsym={name}={hex(value)}' for name,value in defs.items()],
    OUT/'patches.o', OUT/'thunks.o', OUT/'policy.o','-o',OUT/'patch.elf')
linked=ELFFile(io.BytesIO((OUT/'patch.elf').read_bytes()))
assert not [s for s in linked.iter_sections() if s['sh_type'] in ('SHT_REL','SHT_RELA') and s['sh_size']]
result=bytearray(original)
changed=[]
for at in patches:
    section=linked.get_section_by_name(f'.patch_{at:x}'); data=section.data()
    assert section['sh_addr']==at
    assert len(data)=={0xc04d4:4,0xc04f0:4,0xc04fc:4,0xc0518:4,0xc4c70:16,0xc4cf0:12,0xc4ea4:8,0xc4eb4:4,0xc4eec:4,0xc4f78:4}[at]
    off=next(s['p_offset']+at-s['p_vaddr'] for _,s in loads if s['p_vaddr']<=at<s['p_vaddr']+s['p_filesz'])
    changed.append({'address':hex(at),'offset':off,'before':original[off:off+len(data)].hex(),'after':data.hex()})
    result[off:off+len(data)]=data
extension=linked.get_section_by_name('.extension').data()
file_at=tail['p_offset']+start-tail['p_vaddr']
assert file_at>=len(result)
result.extend(bytes(file_at-len(result))); result.extend(extension)
result.extend(bytes((-len(result))%8))
size=len(result)-tail['p_offset']
ph=elf['e_phoff']+index*elf['e_phentsize']
struct.pack_into('<QQ',result,ph+32,size,size)
build_at=elf.get_section_by_name('.note.gnu.build-id')['sh_offset']+16
result[build_at:build_at+20]=bytes(20)
normalized=bytearray(result); normalized[182886:182886+4096]=bytes(4096)
build_id=hashlib.sha1(normalized).digest()
result[build_at:build_at+20]=normalized[build_at:build_at+20]=build_id
candidate=OUT/'helper-panic-candidate.elf';candidate.write_bytes(result)
final=ELFFile(io.BytesIO(result))
for name in ['.eh_frame','.eh_frame_hdr','.gcc_except_table','.dynamic','.rela.dyn','.rela.plt','.dynsym']:
    assert elf.get_section_by_name(name).data()==final.get_section_by_name(name).data(), name
symbols={s.name:s['st_value'] for s in linked.get_section_by_name('.symtab').iter_symbols() if s.name.startswith('maplesu_')}
manifest={'sourceSha256':hashlib.sha256(original).hexdigest(),'helperSha256':hashlib.sha256(result).hexdigest(),
          'normalizedSha256':hashlib.sha256(normalized).hexdigest(),'buildId':build_id.hex(),
          'helperBytes':len(result),'extensionAddress':hex(start),'extensionOffset':file_at,'extensionBytes':len(extension),
          'patches':changed,'symbols':symbols,'unwindAndDynamicMetadataPreserved':True,
          'deviceVerification':False,'productionArchiveModified':False}
(OUT/'build.json').write_text(json.dumps(manifest,indent=2)+'\n')
cache_text_manifest = manifest

# Final publication integration: original frames and metadata remain intact.
"""Append checked hook publication with registered unwind records to the candidate."""
import argparse, hashlib, io, json, struct, subprocess
from pathlib import Path
from elftools.elf.elffile import ELFFile

OUT=BUILD/'hook'
OUT.mkdir(exist_ok=True)
original=candidate.read_bytes();assert hashlib.sha256(original).hexdigest()=='30c3b55b4b4cf4b37b49d35c7e91d72662ae13f37e5e3cc8f05488936303e58b'
e=ELFFile(io.BytesIO(original));loads=[(i,s) for i,s in enumerate(e.iter_segments()) if s['p_type']=='PT_LOAD']
rxid,rx=max(loads,key=lambda item:item[1]['p_vaddr'])
rwid,rw=max(((i,s) for i,s in loads if s['p_flags']==6),key=lambda item:item[1]['p_vaddr'])
start=(rx['p_vaddr']+len(original)-rx['p_offset']+15)&~15
bss=(rw['p_vaddr']+rw['p_memsz']+15)&~15
asm=(SRC/'helper_hook.S').read_text()
patches={0xce75c:'nop',0xcea50:'b maplesu_helper_hook_args',0xcea60:'bl maplesu_helper_publish_hook',0xcea68:'b original_hook_cleanup'}
(OUT/'args.S').write_text(asm)
(OUT/'patches.S').write_text('\n'.join(f'.section .patch_{at:x},"ax"\n{code}\n' for at,code in patches.items()))
def run(name,*args):
 r=subprocess.run([str(TOOL/(name+'.exe')),*map(str,args)],capture_output=True,text=True)
 if r.returncode:raise RuntimeError(r.stdout+r.stderr)
common=['--target=aarch64-linux-android21','-Oz','-fPIC','-fno-stack-protector','-c']
run('clang++',*common,'-mno-outline-atomics','-std=c++17','-fexceptions','-fno-rtti','-ffunction-sections','-fdata-sections','-Wall','-Wextra','-Werror','-I',ROOT/'runtime/maplesu-sdk/include',SRC/'helper_hook.cpp','-o',OUT/'policy.o')
for n in ['args','patches']:run('clang',*common,OUT/(n+'.S'),'-o',OUT/(n+'.o'))
ld='SECTIONS {\n'+''.join(f'.patch_{at:x} {hex(at)} : {{ *(.patch_{at:x}) }}\n' for at in patches)
ld+=f'.hook_bss {hex(bss)} (NOLOAD) : {{ *(.bss*) }}\n.extension {hex(start)} : {{ *(.text*) *(.rodata*) }}\n'
ld+=' .gcc_except_table : { *(.gcc_except_table*) }\n .eh_frame : { KEEP(*(.eh_frame)) }\n .eh_frame_hdr : { *(.eh_frame_hdr) }\n /DISCARD/ : { *(.data.DW.ref*) *(.comment) *(.note*) }\n}\n'
(OUT/'patch.ld').write_text(ld)
defs={'original_hook_publication_call':0xcea60,'original_hook_cleanup':0xce748,'original_read_kernel_mem':0xc0560,'original_write_kernel_mem':0xc0654,'_Znwm':0x9f184,'_ZdlPv':0x9f200,'__gxx_personality_v0':0x9f9b8,'DW.ref.__gxx_personality_v0':0x11cd28,'__cxa_begin_catch':0x9f294,'__cxa_end_catch':0x9f474,'_ZSt9terminatev':0x86e5c}
dyn=e.get_section_by_name('.dynsym');plt=e.get_section_by_name('.plt')['sh_addr']
for i,r in enumerate(e.get_section_by_name('.rela.plt').iter_relocations()):defs[dyn.get_symbol(r['r_info_sym']).name]=plt+32+16*i
run('ld.lld','-T',OUT/'patch.ld','--eh-frame-hdr','--entry=maplesu_helper_publish_hook',*[f'--defsym={n}={hex(v)}' for n,v in defs.items()],OUT/'patches.o',OUT/'args.o',OUT/'policy.o','-o',OUT/'patch.elf')
linked=ELFFile(io.BytesIO((OUT/'patch.elf').read_bytes()))
assert not [s.name for s in linked.iter_sections() if s['sh_type'] in ('SHT_REL','SHT_RELA') and s['sh_size']]
result=bytearray(original);changed=[]
for at in patches:
 data=linked.get_section_by_name(f'.patch_{at:x}').data();assert len(data)==4
 off=next(s['p_offset']+at-s['p_vaddr'] for _,s in loads if s['p_vaddr']<=at<s['p_vaddr']+s['p_filesz'])
 changed.append({'address':hex(at),'offset':off,'before':original[off:off+4].hex(),'after':data.hex()});result[off:off+4]=data
for s in linked.iter_sections():
 if not s['sh_flags']&2 or s['sh_type']=='SHT_NOBITS' or s.name.startswith('.patch_') or not s['sh_size']:continue
 assert s.name in ('.extension','.gcc_except_table','.eh_frame','.eh_frame_hdr'),s.name
 off=rx['p_offset']+s['sh_addr']-rx['p_vaddr'];assert off>=len(original)
 result.extend(bytes(max(0,off+s['sh_size']-len(result))));result[off:off+s['sh_size']]=s.data()
# A shared table searches both original FDEs and the new checked function's FDEs.
oldhdr=e.get_section_by_name('.eh_frame_hdr');newhdr=linked.get_section_by_name('.eh_frame_hdr')
def entries(data,address):
 assert data[:4]==bytes([1,0x1b,3,0x3b]);count=struct.unpack_from('<I',data,8)[0];assert len(data)==12+count*8
 return [(address+x,address+y) for x,y in struct.iter_unpack('<ii',data[12:])]
oldentries=entries(oldhdr.data(),oldhdr['sh_addr']);newentries=entries(newhdr.data(),newhdr['sh_addr']);allentries=sorted(oldentries+newentries)
assert len(set(x for x,y in allentries))==len(allentries)
hdrat=(rx['p_vaddr']+len(result)-rx['p_offset']+3)&~3
header=bytes([1,0x1b,3,0x3b])+struct.pack('<iI',e.get_section_by_name('.eh_frame')['sh_addr']-hdrat-4,len(allentries))
header+=b''.join(struct.pack('<ii',pc-hdrat,fde-hdrat) for pc,fde in allentries)
hdroff=rx['p_offset']+hdrat-rx['p_vaddr'];result.extend(bytes(hdroff-len(result)));result.extend(header);result.extend(bytes((-len(result))%8))
ph=e['e_phoff'];stride=e['e_phentsize']
size=len(result)-rx['p_offset'];struct.pack_into('<QQ',result,ph+rxid*stride+32,size,size)
newbss=linked.get_section_by_name('.hook_bss');endbss=newbss['sh_addr']+newbss['sh_size'];assert endbss<rx['p_vaddr']
struct.pack_into('<Q',result,ph+rwid*stride+40,endbss-rw['p_vaddr'])
ehid=next(i for i,s in enumerate(e.iter_segments()) if s['p_type']=='PT_GNU_EH_FRAME')
struct.pack_into('<QQQQQ',result,ph+ehid*stride+8,hdroff,hdrat,hdrat,len(header),len(header))
buildat=e.get_section_by_name('.note.gnu.build-id')['sh_offset']+16;result[buildat:buildat+20]=bytes(20)
normalized=bytearray(result);normalized[182886:182886+4096]=bytes(4096);bid=hashlib.sha1(normalized).digest();result[buildat:buildat+20]=normalized[buildat:buildat+20]=bid
final=ELFFile(io.BytesIO(result))
for n in ['.eh_frame','.eh_frame_hdr','.gcc_except_table','.dynamic','.rela.dyn','.rela.plt','.dynsym']:assert final.get_section_by_name(n).data()==e.get_section_by_name(n).data(),n
# Confirm the new CIE uses the original, runtime-relocated personality slot.
cies=[x for x in linked.get_dwarf_info().EH_CFI_entries() if type(x).__name__=='CIE']
assert any('personality' in x.augmentation_dict for x in cies)
(OUT/'helper-hook-candidate.elf').write_bytes(result)
syms={s.name:s['st_value'] for s in linked.get_section_by_name('.symtab').iter_symbols() if s.name.startswith('maplesu_')}
report={'sourceSha256':hashlib.sha256(original).hexdigest(),'helperSha256':hashlib.sha256(result).hexdigest(),'normalizedSha256':hashlib.sha256(normalized).hexdigest(),'buildId':bid.hex(),'helperBytes':len(result),'patches':changed,'symbols':syms,'bssAddress':hex(bss),'bssBytes':newbss['sh_size'],'unwindHeaderAddress':hex(hdrat),'originalFdeCount':len(oldentries),'addedFdeCount':len(newentries),'unwindAndDynamicMetadataPreserved':True,'deviceVerification':False,'productionArchiveModified':False}
(OUT/'build.json').write_text(json.dumps(report,indent=2)+'\n')

final_path = BUILD/'embedded-bootstrap.elf'
final_path.write_bytes(result)
manifest = dict(report, baselineHelperSha256=cache_text_manifest['sourceSha256'],
                cacheText=cache_text_manifest,
                patchKind='selective instruction and appended source patch; not a full TU rebuild',
                synchronizedRepairs=['cpu_affinity_and_cache_errors', 'kernel_text_w0', 'before_hook_publication'],
                limitations='Only the identified before-hook path is synchronized; hardware cache/TLB behavior requires device acceptance')
(BUILD/'build.json').write_text(json.dumps(manifest, indent=2)+'\n')
print(json.dumps({k: manifest[k] for k in ['helperSha256','normalizedSha256','buildId','helperBytes','synchronizedRepairs']},indent=2))
