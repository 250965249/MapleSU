"""Build the optional process-context policy sidecar against a measured image.

Uses the Root loader's image/BTF, native CFI and ELF parsers. Never substitutes
reference struct offsets for the target, deploys a module or changes a device.
"""
from __future__ import annotations
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import struct
import subprocess
import sys
import zlib

HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[1]
spec=importlib.util.spec_from_file_location('maplesu_root_builder',HERE/'build_root_module.py')
b=importlib.util.module_from_spec(spec);sys.modules[spec.name]=b;spec.loader.exec_module(b)
TARGETS=['sel_write_context','sel_write_access','selinux_setprocattr','sel_open_handle_status',
    'sel_read_handle_status','sel_mmap_handle_status','sk_filter_trim_cap','commit_creds','__skb_try_recv_datagram','copy_process',
    'selnl_notify_policyload','sel_write_load']
HELPERS=['set_memory_nx','set_memory_rw','set_memory_ro','set_memory_x','caches_clean_inval_pou',
    '__flush_icache_range','apply_alternatives_module','static_key_count','dynamic_scs_enabled','scs_patch','__pi_scs_patch','ksys_write']

def digest(path): return hashlib.sha256(Path(path).read_bytes()).hexdigest()

def nested_offset(btf,kind,member):
    hit=[m['byte'] for m in kind['members'] if m['name']==member]
    for field in kind['members']:
        if not field['name']:
            nested=btf.types[field['type']]
            if nested['kind'] in (b.BTF_STRUCT,b.BTF_UNION):
                try:hit.append(field['byte']+nested_offset(btf,nested,member))
                except ValueError:pass
    if len(set(hit))!=1: raise ValueError('missing/ambiguous BTF member: '+kind['name']+'.'+member)
    return hit[0]

def enum_value(btf,image,name,member):
    offset=btf.blob_offset
    _,_,_,hdr,typ_off,typ_len,str_off,str_len=struct.unpack_from('<HBBIIIII',image,offset)
    types=image[offset+hdr+typ_off:offset+hdr+typ_off+typ_len]
    cursor=0
    for t in btf.types[1:]:
        cursor+=12
        if t['name']==name and t['kind']==6:
            values=[]
            for i in range(t['vlen']):
                key,val=struct.unpack_from('<Ii',types,cursor+i*8)
                if btf._name(key)==member:values.append(val)
            if len(values)!=1:raise ValueError('missing BTF enum: '+name+'.'+member)
            return values[0]
        if t['kind'] in (b.BTF_STRUCT,b.BTF_UNION):cursor+=t['vlen']*12
        elif t['kind'] in b.BTF_SKIP:cursor+=b.BTF_SKIP[t['kind']](t['vlen'])
    raise ValueError('missing BTF enum: '+name)

def ioctl_cfi(image,symbols):
    name='proc_reg_unlocked_ioctl';at=symbols.address(name)
    if at is None:raise ValueError('native proc ioctl dispatch missing')
    ids={s['typeId'] for s in b.kcfi_type_ids(image[at:symbols.next_address(at,4096)])}
    if len(ids)!=1:raise ValueError('native proc ioctl CFI is ambiguous: '+repr(ids))
    return ids.pop()

def layout_header(image,contract,symbols,bundles):
    btf=b.Btf(image)
    probe=btf.struct('kprobe');proc=btf.struct('proc_ops');regs=btf.struct('pt_regs')
    members={m['name']:m['byte'] for m in probe['members']}
    if probe['size']!=contract['kprobe']['size']:raise ValueError('contract/image kprobe layout drift')
    for name,key in [('addr','addrOffset'),('symbol_name','symbolNameOffset')]:
        if members[name]!=contract['kprobe'][key]:raise ValueError('contract/image member drift: '+name)
    module=btf.struct('module');module_fields={m['name']:m['byte'] for m in module['members']}
    for name,key in [('name','nameOffset'),('init','initOffset'),('exit','exitOffset')]:
        if module_fields[name]!=contract['thisModule'][key]:raise ValueError('contract/image module drift: '+name)
    if module['size']!=contract['thisModule']['size']:raise ValueError('contract/image module size drift')
    start=image.find(b'IKCFG_ST');end=image.find(b'IKCFG_ED',start+8)
    if start<0 or end<0:raise ValueError('image kernel config missing')
    config=zlib.decompress(image[start+8:end],16+zlib.MAX_WBITS).decode()
    # The existing image reader returns config text; pages are not inferred from a release name.
    if isinstance(config,tuple):config=config[0]
    if isinstance(config,dict):config='\n'.join(k+'='+str(v) for k,v in config.items())
    if isinstance(config,bytes):config=config.decode()
    pages=[size for label,size in [('4K',4096),('16K',16384),('64K',65536)]
        if 'CONFIG_ARM64_'+label+'_PAGES=y' in config]
    if len(pages)!=1:raise ValueError('ambiguous/missing running image page size')
    names=set(TARGETS+HELPERS)
    metadata=json.loads(bundles.read_text())
    for bundle in metadata['bundles']:names.update(bundle['payload']['imports'])
    facts={'MSU_PH_PAGE_BYTES':pages[0],'MSU_PH_KPROBE_SIZE':probe['size'],
        'MSU_PH_KP_ADDR':members['addr'],'MSU_PH_KP_NAME':members['symbol_name'],
        'MSU_PH_KP_PRE':members['pre_handler'],'MSU_PH_REGS_PC':nested_offset(btf,regs,'pc'),
        'MSU_PH_PROC_OPS_SIZE':proc['size'],'MSU_PH_PROC_IOCTL':nested_offset(btf,proc,'proc_ioctl')}
    if symbols.address('module_alloc') is None:
        facts['MSU_PH_EXECMEM_MODULE_TEXT']=enum_value(btf,image,'execmem_type','EXECMEM_MODULE_TEXT')
    else:facts['MSU_PH_EXECMEM_MODULE_TEXT']=0 # not used by this image
    if facts['MSU_PH_REGS_PC']!=256:raise ValueError('AArch64 register ABI needs a new audit')
    lines=['/* Generated from the selected image; do not edit. */']
    lines += ['#define '+key+' '+str(value) for key,value in facts.items()]
    lines += ['#define MSU_PH_ALLOWED_SYMBOLS '+','.join(json.dumps(n) for n in sorted(names))]
    return '\n'.join(lines)+'\n',facts

def image_build_id(image,symbols):
    start,end=symbols.address('__start_notes'),symbols.address('__stop_notes')
    if start is None or end is None or not 0 <= start < end <= len(image):
        raise ValueError('measured Image notes missing')
    identities=[]
    while start+12<=end:
        names,desc,kind=struct.unpack_from('<III',image,start);start+=12
        name=image[start:start+names];start+=(names+3)&~3
        if start+desc>end:raise ValueError('truncated Image note')
        value=image[start:start+desc];start+=(desc+3)&~3
        if kind==3 and name==b'GNU\0':identities.append(value.hex())
    if len(set(identities))!=1:raise ValueError('ambiguous Image build ID')
    return identities[0]

def glue(contract,build_id):
    t=contract['thisModule'];name='maplesu_policy_hook'
    if not (t['nameOffset']+len(name)+1<t['initOffset']<t['exitOffset']<t['size']):
        raise ValueError('module metadata ranges overlap')
    return f'''.section .gnu.linkonce.this_module,"aw",%progbits
.balign 64
.global __this_module
__this_module:
.zero {t['nameOffset']}
.asciz "{name}"
.zero {t['initOffset']} - (. - __this_module)
.quad init_module
.zero {t['exitOffset']} - (. - __this_module)
.quad cleanup_module
.zero {t['size']} - (. - __this_module)
.section .modinfo,"a",%progbits
.asciz "license=GPL"
.asciz "name={name}"
.asciz "description=MapleSU temporary policy view backend"
.asciz "depends="
.asciz "maplesu_policy_hook_abi=2"
.asciz "maplesu_image_build_id={build_id}"
.asciz "vermagic={contract['vermagic']}"
.section .plt,"ax",%progbits
.byte 0
.section .init.plt,"ax",%progbits
.byte 0
.section .text.ftrace_trampoline,"ax",%progbits
.byte 0
.section __versions,"a",%progbits
.balign 8
.quad 0
.zero 56
.section .note.GNU-stack,"",%progbits
'''

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--contract',required=True,type=Path)
    p.add_argument('--out',required=True,type=Path)
    p.add_argument('--ndk',type=Path,default=b.DEFAULT_NDK)
    p.add_argument('--bundles',type=Path,default=ROOT/'work/ultra-policy-dynamic-abi-20261110/policy-bundles.json')
    args=p.parse_args();args.out.mkdir(parents=True,exist_ok=True)
    c=b.load_contract(args.contract);image_path=ROOT/c['imagePath'];image=image_path.read_bytes()
    if digest(image_path)!=c['imageSha256']:raise ValueError('selected image digest drift')
    if b.legacy_cfi.enabled(c):raise ValueError('legacy CFI sidecar qualification is not yet implemented; no KCFI substitution')
    symbols=b.SymbolTable(ROOT/c['symbolsPath'])
    header,facts=layout_header(image,c,symbols,args.bundles)
    (args.out/'policy_hook_layout.h').write_text(header)
    build_id=image_build_id(image,symbols)
    (args.out/'module_glue.S').write_text(glue(c,build_id))
    clang=b.find_tool(args.ndk,'clang');ld=b.find_tool(args.ndk,'ld.lld');runner=b.Runner()
    flags=[f for f in b.CLANG_FLAGS if not f.startswith('-mbranch-protection')]+['-mbranch-protection=standard','-I'+str(args.out)]
    objects=[]
    sources=[HERE/'module/maplesu_policy_hook.c',HERE/'module/policy_hook_dispatch.c',HERE/'module/policy_hook_original.S',args.out/'module_glue.S']
    for source in sources:
        out=args.out/(source.stem+'.o')
        runner([clang,*(flags if source.suffix=='.c' else b.ASM_FLAGS),source,'-o',out]);objects.append(out)
    module=args.out/'maplesu_policy_hook.ko';runner([ld,'-r','-o',module,*objects])
    dispatch=b.derive_kprobe_handler_ids(image,symbols,c)
    pre=int(dispatch['dispatch']['preHandler']['typeId'],16);ioctl=ioctl_cfi(image,symbols)
    b.patch_kcfi_prefixes(module,image_path,c,print,{'msu_policy_pre':pre,'msu_policy_ioctl':ioctl})
    elf=b.Elf(module)
    if set(elf.imports())!={'register_kprobe','unregister_kprobe'}:raise ValueError('unexpected module import set: '+repr(elf.imports()))
    callbacks={'msu_policy_pre':pre,'msu_policy_ioctl':ioctl}
    for name,expected in callbacks.items():
        symbol=elf.symbol(name);at=elf.symbol_file_offset(symbol)
        if b.read_uint32(elf.raw,at-4)!=expected:raise ValueError('callback CFI readback failed: '+name)
        if elf.symbol_section(symbol)['name'].startswith('.init'):raise ValueError('resident callback is init-only')
    for section in elf.sections:
        if section['flags'] & b.SHF_EXECINSTR:
            data=elf.section_bytes(section)
            if any(b.decode_brk(b.read_uint32(data,i)) is not None for i in range(0,len(data)-3,4)):
                raise ValueError('trap in sidecar text')
    receipt={'passed':True,'scope':'image-derived sidecar ELF/CFI build only; not installed or activated',
        'kernelRelease':c['kernelRelease'],'buildId':build_id,'controlAbi':2,'imageSha256':digest(image_path),'facts':facts,
        'callbacks':{k:hex(v) for k,v in callbacks.items()},'module':{'path':str(module),'sha256':digest(module),'bytes':module.stat().st_size},
        'commands':runner.commands,'sourceSha256':{str(s.relative_to(ROOT)):digest(s) for s in [*sources,HERE/'policy_hook_abi.h',HERE/'module/policy_hook_dispatch.h',Path(__file__)] if s.is_relative_to(ROOT)},
        'deviceAccess':False,'installed':False,'fullPolicyHidingAcceptance':False}
    (args.out/'build.json').write_text(json.dumps(receipt,indent=2)+'\n')
    print(json.dumps({k:v for k,v in receipt.items() if k not in ['commands','sourceSha256']},indent=2))
if __name__=='__main__':main()
