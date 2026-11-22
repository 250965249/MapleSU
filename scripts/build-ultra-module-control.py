"""Add the SDK module-control extension and the matching installed-helper gate."""
import argparse,hashlib,io,json,re,struct,subprocess
from pathlib import Path
from elftools.elf.elffile import ELFFile
from verify_sdk_member_diff import parse_ar
p=argparse.ArgumentParser();p.add_argument('--archive',type=Path,required=True);p.add_argument('--bootstrap-ir',type=Path,required=True);p.add_argument('--out',type=Path,required=True);p.add_argument('--ndk',type=Path,required=True);a=p.parse_args()
root=Path(__file__).resolve().parents[1];out=a.out;out.mkdir(parents=True,exist_ok=True)
tool=a.ndk/'toolchains/llvm/prebuilt/windows-x86_64/bin'
def run(n,*args):
 r=subprocess.run([str(tool/(n+'.exe')),*map(str,args)],capture_output=True,text=True)
 if r.returncode:raise RuntimeError(r.stdout+r.stderr)
base=a.archive.read_bytes();assert hashlib.sha256(base).hexdigest()=='d1082fcc787037c308ff9acf88006de5936f56cabb23c4d1d7916443765825b3'
members=parse_ar(str(a.archive))['members']
def body(i):
 m=members[i];return base[m['body_offset']:m['body_offset']+m['size']]
obj=ELFFile(io.BytesIO(body(52)));helper=bytearray(obj.get_section_by_name('.data').data()[:1163328]);assert helper[:4]==b'\x7fELF'
elf=ELFFile(io.BytesIO(helper));align=lambda n:(n+0x3fff)&~0x3fff
file_at=align(len(helper));va=align(max(s['p_vaddr']+s['p_memsz'] for s in elf.iter_segments() if s['p_type']=='PT_LOAD'))
for filename in ['helper_module_gate.S','helper_module_gate.c']:
 run('clang','--target=aarch64-linux-android21','-Oz','-ffreestanding','-fno-stack-protector','-fPIC','-c',root/'runtime/ultra/modules'/filename,'-o',out/(filename+'.o'))
(out/'gate.ld').write_text('SECTIONS { . = '+hex(va)+'; .text : { *(.text*) } .rodata : { *(.rodata*) } /DISCARD/ : { *(.comment) *(.note*) *(.eh_frame*) } }')
run('ld.lld','-T',out/'gate.ld','--defsym=module_private_path=0xa6a9c','--defsym=helper_delete=0x9f200','--defsym=original_precheck_body=0xa6d6c','--entry=maplesu_module_gate',out/'helper_module_gate.S.o',out/'helper_module_gate.c.o','-o',out/'gate.elf')
run('llvm-objcopy','-O','binary',out/'gate.elf',out/'gate.bin');gate=(out/'gate.bin').read_bytes();assert len(gate)<4096
branch_at=0xa6d68;assert helper[branch_at:branch_at+4]==bytes.fromhex('ff0301d1')
branch=struct.pack('<I',0x14000000|(((va-branch_at)//4)&0x3ffffff));helper[branch_at:branch_at+4]=branch
# Preserve every existing LOAD and all stack/unwind metadata. PT_NOTE becomes the added RX LOAD;
# note sections remain available to file-based build-id tools.
index=next(i for i,s in enumerate(elf.iter_segments()) if s['p_type']=='PT_NOTE');phdr_at=elf['e_phoff']+index*elf['e_phentsize'];phdr=struct.pack('<IIQQQQQQ',1,5,file_at,va,va,len(gate),len(gate),0x4000);helper[phdr_at:phdr_at+56]=phdr
helper.extend(bytes(file_at-len(helper)));helper.extend(gate);helper.extend(bytes((-len(helper))%8))
note=elf.get_section_by_name('.note.gnu.build-id')['sh_offset']+16;helper[note:note+20]=bytes(20);normalized=bytearray(helper);normalized[182886:182886+4096]=bytes(4096);buildid=hashlib.sha1(normalized).digest();helper[note:note+20]=normalized[note:note+20]=buildid
(out/'embedded-bootstrap.elf').write_bytes(helper)
header='#pragma once\n'+f'#define MAPLESU_GATE_FILE_OFFSET {file_at}\n#define MAPLESU_GATE_BRANCH_OFFSET {branch_at}\n#define MAPLESU_GATE_PHDR_OFFSET {phdr_at}\n'
for name,data in [('bytes',gate),('branch',branch),('phdr',phdr)]:header+='static constexpr unsigned char maplesu_gate_'+name+'[] = {'+','.join(str(b) for b in data)+'};\n'
(out/'module_gate_identity.h').write_text(header)
rebuilt=[]
# Recovered IR carries the existing Panic request/staging repairs; only replace the embedded data/size.
ir=a.bootstrap_ir.read_text(encoding='utf-8-sig');match=re.search(r'\[145416 x i64\] \[(.*?)\]',ir);assert match
words=struct.unpack('<'+'q'*(len(helper)//8),helper)
resize=lambda text:text.replace('145416',str(len(words))).replace('1163328',str(len(helper)))
ir=resize(ir[:match.start()])+f'[{len(words)} x i64] ['+', '.join('i64 '+str(w) for w in words)+']'+resize(ir[match.end():])
wrapper='''\ndefine hidden void @maplesu_installed_helper_path(ptr %out) {
 call fastcc void @_ZN7maplesu3sdkL26get_autorun_bootstrap_pathEv(ptr sret(%"class.std::__ndk1::basic_string") align 8 %out)
 ret void
}
'''
ir+=wrapper
path=out/'m052.patched.ll';path.write_text(ir);dest=out/members[52]['name'];run('clang','--target=aarch64-linux-android21','-Oz','-fPIC','-c',path,'-o',dest);rebuilt.append(dest)
for i in [55,56]:
 src=out/f'm{i:03d}.bc';src.write_bytes(body(i));ll=src.with_suffix('.ll');run('clang','--target=aarch64-linux-android21','-S','-emit-llvm','-x','ir',src,'-o',ll);ir=ll.read_text()
 if i==55:
  ir+='''\ndefine hidden void @maplesu_system_directory(ptr %out) {
 call fastcc void @_ZN7maplesu3sdkL24get_system_file_dir_pathEv(ptr sret(%"class.std::__ndk1::basic_string") align 8 %out)
 ret void
}
'''
 else:
  old='@_ZN15default_modules11module_root16set_current_rootEb';assert old in ir;ir=ir.replace(old,'@maplesu_lock_module_root');ir=ir.replace('@_exit(', '@maplesu_module_worker_exit(')
 path=out/f'm{i:03d}.patched.ll';path.write_text(ir);dest=out/members[i]['name'];run('clang','--target=aarch64-linux-android21','-Oz','-fPIC','-c',path,'-o',dest);rebuilt.append(dest)
dest=out/'maplesu_module_control.o';run('clang++','--target=aarch64-linux-android21','-std=c++17','-Oz','-fPIC','-fexceptions','-ffunction-sections','-fdata-sections','-I',root/'runtime/maplesu-sdk/include','-I',out,'-c',root/'runtime/ultra/modules/module_control.cpp','-o',dest);rebuilt.append(dest)
archive=out/'libkernel_module_kit_static.a';assert archive.resolve()!=a.archive.resolve();archive.write_bytes(base);run('llvm-ar','rD',archive,*rebuilt);run('llvm-ar','sD',archive)
final=archive.read_bytes();member=parse_ar(str(archive))['members'][52];assert final[member['body_offset']:member['body_offset']+member['size']].count(helper)==1, 'Embedded helper must match byte-for-byte'
sha=lambda x:hashlib.sha256(x).hexdigest();meta={'sdkVersion':'5.1.0','archiveSha256':sha(archive.read_bytes()),'baselineArchiveSha256':sha(base),'helperSha256':sha(helper),'helperNormalizedSha256':sha(normalized),'helperBuildId':buildid.hex(),'helperBytes':len(helper),'gateFileOffset':file_at,'gateVirtualAddress':va,'gateBytes':len(gate),'bootstrapIrSha256':sha(a.bootstrap_ir.read_bytes()),'sourceSha256':sha((root/'runtime/ultra/modules/module_control.cpp').read_bytes()),'deviceVerification':False}
(out/'build.json').write_text(json.dumps(meta,indent=2)+'\n');print(json.dumps(meta,indent=2))
