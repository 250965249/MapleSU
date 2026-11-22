"""Replace only m052's helper/size and rebuild its paired module-control identity."""
from pathlib import Path
import hashlib,io,json,struct,subprocess,sys
from elftools.elf.elffile import ELFFile
import argparse
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'scripts'))
from verify_sdk_member_diff import parse_ar,compare_members
p=argparse.ArgumentParser(description=__doc__)
p.add_argument('--archive',type=Path,required=True)
p.add_argument('--helper',type=Path,required=True)
p.add_argument('--helper-manifest',type=Path,required=True)
p.add_argument('--out',type=Path,required=True)
p.add_argument('--ndk',type=Path,required=True)
args=p.parse_args()
TOOL=args.ndk/'toolchains/llvm/prebuilt/windows-x86_64/bin'
OUT=args.out.resolve();OUT.mkdir(parents=True,exist_ok=True)
source=args.archive.resolve()
assert not source.is_relative_to(OUT), 'Keep the baseline outside the output directory'
sha=lambda b:hashlib.sha256(b).hexdigest()
original=source.read_bytes();assert sha(original)=='92e800cef1063f129c7f50f136079e37421d9f61c4e6276b39a24f9bec7a5a96'
members=parse_ar(str(source))['members'];member=members[52];assert member['name']=='maplesu_autorun_bootstrap_install.o'
body=original[member['body_offset']:member['body_offset']+member['size']]
elf=ELFFile(io.BytesIO(body));oldhelper=elf.get_section_by_name('.data').data();newhelper=args.helper.read_bytes()
assert sha(oldhelper)=='9917cd9fb9ba15b4169fc60285215e8b3efe02b96bdb52229c49339cf2a94089'
metadata=json.loads(args.helper_manifest.read_text())
assert sha(newhelper)==metadata['helperSha256'] and len(newhelper)==metadata['helperBytes']
# Preserve the compiled installer, wrappers, C++ ABI, unwind metadata, and key slot scan.
# These are its allocation/copy/write sizes, identified from the pinned object's IDA references.
text=bytearray(elf.get_section_by_name('.text').data());changes=[]
for low,high,reg in [(0x374,0x37c,0),(0x3ac,0x3b8,2),(0x49c,0x4a4,2)]:
 for at,base,value in [(low,0x52800000,len(oldhelper)&65535),(high,0x72a00000,len(oldhelper)>>16)]:
  expected=base|(value<<5)|reg
  assert struct.unpack_from('<I',text,at)[0]==expected,(hex(at),'unexpected installer instruction')
  newvalue=(len(newhelper)&65535) if at==low else (len(newhelper)>>16)
  struct.pack_into('<I',text,at,base|(newvalue<<5)|reg)
  changes.append({'section':'.text','offset':hex(at),'oldSize':len(oldhelper),'newSize':len(newhelper)})
(OUT/'installer-text.bin').write_bytes(text);(OUT/'embedded-bootstrap.elf').write_bytes(newhelper)
input_obj=OUT/'m052-r8.o';input_obj.write_bytes(body);obj=OUT/member['name']
def run(name,*args):
 r=subprocess.run([str(TOOL/(name+'.exe')),*map(str,args)],capture_output=True,text=True)
 if r.returncode:raise RuntimeError(r.stdout+r.stderr)
run('llvm-objcopy','--update-section',f'.data={OUT/"embedded-bootstrap.elf"}','--update-section',f'.text={OUT/"installer-text.bin"}',input_obj,obj)
patched=bytearray(obj.read_bytes());newelf=ELFFile(io.BytesIO(patched));symbols=newelf.get_section_by_name('.symtab');symbol_changes=[]
for index,s in enumerate(symbols.iter_symbols()):
 if s.name=='_ZN7maplesu3sdkL27autorun_bootstrap_file_dataE':
  assert s['st_size']==len(oldhelper)
  struct.pack_into('<Q',patched,symbols['sh_offset']+index*symbols['sh_entsize']+16,len(newhelper));symbol_changes.append(s.name)
assert len(symbol_changes)==1;obj.write_bytes(patched);newelf=ELFFile(io.BytesIO(patched))
assert [(s.name,s['sh_type'],s['sh_flags']) for s in elf.iter_sections()]==[(s.name,s['sh_type'],s['sh_flags']) for s in newelf.iter_sections()]
for a,b in zip(elf.iter_sections(),newelf.iter_sections()):
 if a.name not in ('.data','.text','.symtab'):assert a.data()==b.data(),a.name
old_symbols=list(elf.get_section_by_name('.symtab').iter_symbols());new_symbols=list(newelf.get_section_by_name('.symtab').iter_symbols())
for a,b in zip(old_symbols,new_symbols):
 assert a.name==b.name
 for k in a.entry:assert a[k]==b[k] or (k=='st_size' and a.name in symbol_changes),(a.name,k)
# Keep the module gate's original bytes, with the new containing RX program header.
helper=ELFFile(io.BytesIO(newhelper));old=ELFFile(io.BytesIO(oldhelper));gateoff=1179648;branchat=0xa6d68
idx=next(i for i,s in enumerate(helper.iter_segments()) if s['p_type']=='PT_LOAD' and s['p_offset']==gateoff)
ph=helper['e_phoff']+idx*helper['e_phentsize']
assert newhelper[gateoff:gateoff+327]==oldhelper[gateoff:gateoff+327]
header='#pragma once\n'+f'#define MAPLESU_GATE_FILE_OFFSET {gateoff}\n#define MAPLESU_GATE_BRANCH_OFFSET {branchat}\n#define MAPLESU_GATE_PHDR_OFFSET {ph}\n'
for name,data in [('bytes',newhelper[gateoff:gateoff+327]),('branch',newhelper[branchat:branchat+4]),('phdr',newhelper[ph:ph+56])]:
 header+='static constexpr unsigned char maplesu_gate_'+name+'[] = {'+','.join(str(b) for b in data)+'};\n'
(OUT/'module_gate_identity.h').write_text(header)
control=OUT/'maplesu_module_control.o'
run('clang++','--target=aarch64-linux-android21','-std=c++17','-Oz','-fPIC','-fexceptions','-ffunction-sections','-fdata-sections','-I',ROOT/'runtime/maplesu-sdk/include','-I',OUT,'-c',ROOT/'runtime/ultra/modules/module_control.cpp','-o',control)
# Export/undefined-symbol contracts must stay identical for both modified members.
def contract(blob):
 e=ELFFile(io.BytesIO(blob));return sorted((s.name,s['st_info']['bind'],s['st_info']['type'],s['st_other']['visibility'],s['st_shndx']=='SHN_UNDEF') for s in e.get_section_by_name('.symtab').iter_symbols() if s['st_info']['bind']!='STB_LOCAL')
control_member=next(m for m in members if m['name']=='maplesu_module_control.o')
assert contract(body)==contract(bytes(patched))
assert contract(original[control_member['body_offset']:control_member['body_offset']+control_member['size']])==contract(control.read_bytes())
archive=OUT/'libkernel_module_kit_static.a';archive.write_bytes(original)
run('llvm-ar','rD',archive,obj,control);run('llvm-ar','sD',archive)
after=parse_ar(str(archive));diff=compare_members(parse_ar(str(source)),after)
assert [x['ord'] for x in diff['changed']]==[52,control_member['ord']] and not diff['added'] and not diff['removed'] and not diff['orderErrors'],diff
final=archive.read_bytes();m=after['members'][52];assert final[m['body_offset']:m['body_offset']+m['size']].count(newhelper)==1
report={'baselineArchiveSha256':sha(original),'archiveSha256':sha(final),'archiveBytes':len(final),'helper':json.loads(args.helper_manifest.read_text()),'installerSizeSites':changes,'abiPreserved':True,'moduleGateIdentityUpdated':True,'memberDiff':diff,'sourceSha256':sha((ROOT/'runtime/ultra/modules/module_control.cpp').read_bytes()),'deviceVerification':False}
(OUT/'build.json').write_text(json.dumps(report,indent=2)+'\n')
print(json.dumps({k:v for k,v in report.items() if k!='helper'},indent=2))
