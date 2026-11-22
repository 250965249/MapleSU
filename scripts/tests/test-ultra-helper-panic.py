"""Execute actual helper instructions and its AsmJit generator in Unicorn."""
import argparse, hashlib, io, json, struct, re
from pathlib import Path
from elftools.elf.elffile import ELFFile
from unicorn import Uc, UC_ARCH_ARM64, UC_MODE_ARM, UC_HOOK_CODE, UC_HOOK_MEM_INVALID
from unicorn import arm64_const as R

p=argparse.ArgumentParser();p.add_argument('--helper',type=Path,required=True);p.add_argument('--out',type=Path,required=True);p.add_argument('--suite',choices=['icache','text'],default='icache')
a=p.parse_args();blob=a.helper.read_bytes();elf=ELFFile(io.BytesIO(blob))
BASE,STACK,DATA,STOP,HEAP=0x1000000,0x4000000,0x5000000,0x6000000,0x7000000
MASK=(1<<64)-1
dyn=elf.get_section_by_name('.dynsym');plt=elf.get_section_by_name('.plt')['sh_addr']
imports={BASE+plt+32+16*i:dyn.get_symbol(r['r_info_sym']).name for i,r in enumerate(elf.get_section_by_name('.rela.plt').iter_relocations())}
by_name={n:at for at,n in imports.items()}
def packmask(cpus):
    b=bytearray(128)
    for n in cpus:b[n//8]|=1<<(n%8)
    return bytes(b)
def signed(v):return v if v<1<<63 else v-(1<<64)

def run(config):
    u=Uc(UC_ARCH_ARM64,UC_MODE_ARM);pages=set()
    for seg in elf.iter_segments():
        if seg['p_type']!='PT_LOAD':continue
        start=(BASE+seg['p_vaddr'])&~4095;end=(BASE+seg['p_vaddr']+seg['p_memsz']+4095)&~4095
        for at in range(start,end,4096):
            if at not in pages:u.mem_map(at,4096);pages.add(at)
        u.mem_write(BASE+seg['p_vaddr'],seg.data())
    for name in ('.rela.dyn','.rela.plt'):
        for rel in elf.get_section_by_name(name).iter_relocations():
            kind=rel['r_info_type'];symbol=dyn.get_symbol(rel['r_info_sym']);add=rel['r_addend']
            if kind==1027:value=BASE+add
            elif kind in (257,1025,1026):
                value=(BASE+symbol['st_value']+add if symbol['st_shndx']!='SHN_UNDEF' else by_name.get(symbol.name,DATA+0x8000)+add)
            else:raise AssertionError(('relocation',kind))
            u.mem_write(BASE+rel['r_offset'],struct.pack('<Q',value&MASK))
    for at in (STACK,DATA,STOP):u.mem_map(at,0x10000)
    u.mem_map(HEAP,0x1000000)
    u.mem_write(DATA,struct.pack('<I',22));u.mem_write(DATA+16,b'fixture\0')
    entry=config.get('entry','icache')
    if entry=='text':
        for reg,value in [(0,0xffff000000001000),(1,DATA+0x1000),(2,4),(3,2)]:
            u.reg_write(getattr(R,f'UC_ARM64_REG_X{reg}'),value)
        u.mem_write(DATA+0x1000,bytes.fromhex('1f2003d5'))
    sp=STACK+0xf000;u.reg_write(R.UC_ARM64_REG_SP,sp);u.reg_write(R.UC_ARM64_REG_X30,STOP)
    for i in range(19,30):u.reg_write(getattr(R,f'UC_ARM64_REG_X{i}'),0x9900+i)
    state={'mask':packmask(config.get('saved',[0,1,3,7])),'cpu':0,'heap':HEAP,'gets':0,'sets':[],
           'execs':[],'binds':0,'allocations':{},'symbols':[],'freed':[],'read':False,'kernelBuffers':[],'transportCleanup':[],'controlRequests':[],'unwind':None,'alternateClosure':False}
    original=state['mask'];online=config.get('online','0-1\n').encode()
    def get(n):return u.reg_read(getattr(R,f'UC_ARM64_REG_X{n}'))
    def ret(v):
        link=get(30)
        for n in range(1,18):u.reg_write(getattr(R,f'UC_ARM64_REG_X{n}'),0xbad000+n)
        u.reg_write(R.UC_ARM64_REG_NZCV,0xf0000000)
        u.reg_write(R.UC_ARM64_REG_X0,v&MASK);u.reg_write(R.UC_ARM64_REG_PC,link)
    def alloc(size):
        at=state['heap'];state['heap']+=(max(size,1)+31)&~31;state['allocations'][at]=size
        return at
    def cstr(at):
        b=bytearray()
        for n in range(16384):
            ch=bytes(u.mem_read(at+n,1))
            if ch==b'\0':return bytes(b)
            b.extend(ch)
        raise AssertionError('unterminated fixture string')
    def hook(uc,address,size,_):
        if address==STOP:uc.emu_stop();return
        if config.get('alternate_vtable') and address==BASE+0xc04d4:
            target=struct.unpack('<Q',bytes(u.mem_read(get(0)+32,8)))[0]
            u.mem_write(DATA+0x3000,bytes(u.mem_read(BASE+0x119660,56)))
            u.mem_write(target,struct.pack('<Q',DATA+0x3000));state['alternateClosure']=True
        if config.get('exception_landingpad') and address==BASE+0xc4e88 and len(state['execs'])==1:
            u.reg_write(R.UC_ARM64_REG_X0,DATA+0x800)
            u.reg_write(R.UC_ARM64_REG_PC,BASE+0xc4f4c);return
        if address==BASE+0xa11e0 and config.get('exception_landingpad'):
            state['unwind']={'exception':hex(get(0)),'link':hex(get(30))}
            assert get(0)==DATA+0x800 and get(30)==BASE+0xc4f80
            uc.emu_stop();return
        # Kernel execution is the only SDK boundary mocked; its emitted bytecode
        # and the original generator/cleanup execute unchanged.
        if entry=='text' and address==BASE+0xb19c4:ret(0);return
        if entry=='text' and address==BASE+0xbac9c:
            name=cstr(get(0)).decode();state['symbols'].append(name)
            assert name=='aarch64_insn_patch_text',name
            u.mem_write(get(1),struct.pack('<Q',0xffff800001234000));ret(config.get('symbol_error',0));return
        if entry=='text' and address==BASE+0xc4598:
            state['controlRequests'].append(get(0))
            assert (get(0)==49 and 0xffff000000100018<=get(2)<0xffff00000010001c and get(1)==0) or (get(0)==52 and get(2)==0)
            ret(0);return
        if address==BASE+0xc5dd8:
            if get(30)==BASE+0xc5d5c:
                state['transportCleanup'].append(bytes(u.mem_read(get(0),get(1))).hex())
                u.mem_write(get(2),struct.pack('<Q',0xffff000000100000));ret(0);return
            length=get(1);emitted=bytes(u.mem_read(get(0),length))
            state['execs'].append('text' if entry=='text' and not state['execs'] else state['cpu']);state['kernelBuffers'].append(emitted.hex())
            u.mem_write(get(2),struct.pack('<Q',config.get('kernel_result',0)&MASK))
            ret(config.get('execute_error',0));return
        name=imports.get(address)
        if name is None:return
        if name in ('malloc','calloc','realloc'):
            n=get(0)*get(1) if name=='calloc' else get(1) if name=='realloc' else get(0)
            if config.get('malloc_error') and n==260:ret(0);return
            at=alloc(n)
            if name=='realloc' and get(0):
                old=get(0);u.mem_write(at,bytes(u.mem_read(old,min(state['allocations'][old],n))))
            ret(at)
        elif name=='free':state['freed'].append(get(0));ret(0)
        elif name in ('memset','memcpy','memmove','__memcpy_chk'):
            target=get(0);n=get(2)
            u.mem_write(target,bytes([get(1)&255])*n if name=='memset' else bytes(u.mem_read(get(1),n)))
            ret(target)
        elif name=='memcmp':
            x,y=bytes(u.mem_read(get(0),get(2))),bytes(u.mem_read(get(1),get(2)));ret((x>y)-(x<y))
        elif name in ('strlen','__strlen_chk'):ret(len(cstr(get(0))))
        elif name in ('strcmp','strncmp'):
            x,y=cstr(get(0)),cstr(get(1))
            if name=='strncmp':x,y=x[:get(2)],y[:get(2)]
            ret((x>y)-(x<y))
        elif name=='sched_getaffinity':
            state['gets']+=1
            if (config.get('save_error') and state['gets']==1) or (config.get('restore_query_error') and state['gets']>1):ret(-1)
            else:
                value=state['mask']
                if config.get('readback_mismatch') and state['gets']>1:value=packmask([0])
                u.mem_write(get(2),value);ret(0)
        elif name=='sched_setaffinity':
            value=bytes(u.mem_read(get(2),get(1)));restoring=value==original
            state['sets'].append({'mask':value.hex(),'restore':restoring})
            cpus=[i for i in range(1024) if value[i//8]&(1<<(i%8))]
            if not restoring:state['binds']+=1
            fail=config.get('restore_error') if restoring else config.get('bind_error') or state['binds']==config.get('bind_error_at')
            if fail:ret(-1)
            else:state['mask']=value;state['cpu']=cpus[0];ret(0)
        elif name=='sched_getcpu':ret(-1 if config.get('getcpu_error') else state['cpu']+int(config.get('cpu_mismatch',False)))
        elif name=='sysconf':ret(config.get('cpu_count',2))
        elif name=='syscall':
            nr=get(0)
            if nr==56:
                assert cstr(get(2))==b'/sys/devices/system/cpu/online';ret(-1 if config.get('online_error') else 12)
            elif nr==63:
                if state['read']:ret(0)
                else:u.mem_write(get(2),online);state['read']=True;ret(len(online))
            elif nr==57:ret(0)
            else:raise AssertionError(('unexpected syscall',nr))
        elif name=='__vsnprintf_chk':
            fmt=cstr(get(4)).decode('utf-8')
            stack,gr,vr,go,vo=struct.unpack('<QQQii',bytes(u.mem_read(get(5),32)))
            def arg():
                nonlocal stack,go
                if go<0:at=gr+go;go+=8
                else:at=stack;stack+=8
                return struct.unpack('<Q',bytes(u.mem_read(at,8)))[0]
            def field(m):
                flags,width,precision,length,kind=m.groups()
                if kind=='%':return '%'
                n=arg()
                if kind=='s':value=cstr(n).decode('utf-8',errors='replace') if n else '(null)'
                elif kind=='c':value=chr(n&255)
                elif kind=='p':value=hex(n)
                else:
                    if length not in ('l','ll','z','j'):n&=0xffffffff
                    if kind in ('d','i'):
                        if length not in ('l','ll','z','j') and n&(1<<31):n-=1<<32
                        elif length in ('l','ll','z','j'):n=signed(n)
                        value=str(n)
                    elif kind=='u':value=str(n)
                    elif kind in ('x','X'):value=format(n,kind)
                    else:raise AssertionError(('format specifier',kind,fmt))
                if width:value=value.rjust(int(width),'0' if '0' in flags else ' ')
                return value
            rendered=re.sub(r'%([-+#0 ]*)([0-9]*)(?:\.([0-9]+))?(ll|l|z|j|h|hh)?([a-zA-Z%])',field,fmt).encode()
            cap=get(1)
            if cap:u.mem_write(get(0),rendered[:cap-1]+b'\0')
            ret(len(rendered))
        elif name in ('getresuid','getresgid'):
            for n in range(3):
                if get(n):u.mem_write(get(n),struct.pack('<I',0))
            ret(0)
        elif name=='__errno':ret(DATA)
        elif name in ('strerror',):ret(DATA+16)
        elif name in ('fprintf','printf','fflush','prctl','pthread_mutex_lock','pthread_mutex_unlock'):ret(0)
        else:raise AssertionError(('unexpected import',name,hex(get(30))))
    def invalid(uc, access, address, size, value, context):
        state['unmapped'] = (hex(address),size,hex(uc.reg_read(R.UC_ARM64_REG_SP)),hex(get(0)),hex(get(19)))
        return False
    u.hook_add(UC_HOOK_MEM_INVALID, invalid)
    u.hook_add(UC_HOOK_CODE,hook)
    try:u.emu_start(BASE+(0xc0654 if entry=='text' else 0xc4c50),STOP+4,count=5000000)
    except Exception as e:raise RuntimeError(f'PC={u.reg_read(R.UC_ARM64_REG_PC):x}, LR={get(30):x}, memory={state.get('unmapped')}: {e}') from e
    if config.get('exception_landingpad'):
        assert state['unwind'] is not None
        assert u.reg_read(R.UC_ARM64_REG_SP)==sp-0x100
    else:
        assert u.reg_read(R.UC_ARM64_REG_PC)==STOP,'instruction budget exceeded'
        assert u.reg_read(R.UC_ARM64_REG_SP)==sp
        for i in range(19,30):assert get(i)==0x9900+i,(i,get(i))
    result=signed(get(0));expected=config['expected']
    passed=result==expected and (state['mask']==original)==config.get('expect_restored',True) and state['execs']==config.get('expected_execs',[])
    return {'passed':passed,'result':result,'expected':expected,'affinityRestored':state['mask']==original,
            'executedCpus':state['execs'],'expectedCpus':config.get('expected_execs',[]),
            'affinityQueries':state['gets'],'affinitySets':state['sets'],'generatedCode':state['kernelBuffers'],'queriedSymbols':state['symbols'],'transportCleanup':state['transportCleanup'],'unwind':state['unwind'],'alternateClosure':state['alternateClosure'],'controlRequests':state['controlRequests'],
            'liveAllocations':len([x for x in state['allocations'] if x not in state['freed']])}

cases={
 'all_bindings_failed':{'bind_error':True,'expected':-19983},
 'sparse_online_success':{'online':'0,3,7\n','expected':0,'expected_execs':[0,3,7]},
 'executor_error':{'execute_error':-19008,'expected':-19008,'expected_execs':[0]},
 'snapshot_error':{'save_error':True,'expected':-19984},
 'online_read_error':{'online_error':True,'expected':-19984},
 'invalid_online_mask':{'online':'0-1024\n','expected':-19984},
 'cpu_mismatch':{'cpu_mismatch':True,'expected':-19983},
 'restore_error':{'restore_error':True,'expected':-19983,'expected_execs':[0,1],'expect_restored':False},
 'restore_readback_mismatch':{'readback_mismatch':True,'expected':-19983,'expected_execs':[0,1]},
 'executor_positive_one':{'execute_error':1,'expected':1,'expected_execs':[0]},
 'restore_query_error':{'restore_query_error':True,'expected':-19983,'expected_execs':[0,1]},
 'second_cpu_bind_failed':{'bind_error_at':2,'expected':-19983,'expected_execs':[0]},
 'highest_cpu':{'online':'1023\n','expected':0,'expected_execs':[1023]},
 'empty_online':{'online':'','expected':-19984},
 'state_allocation_failed':{'malloc_error':True,'expected':-19990},
 'exception_landingpad_cleanup':{'exception_landingpad':True,'expected':DATA+0x800,'expected_execs':[0]},
}
if a.suite=='text':
    cases={
     'patch_success':{'expected':0,'expected_execs':['text',0,1]},
     'patch_negative_w0':{'kernel_result':0xffffffea,'expected':-19990,'expected_execs':['text']},
     'patch_signed64':{'kernel_result':-22,'expected':-19990,'expected_execs':['text']},
     'patch_positive_w0':{'kernel_result':1,'expected':-19990,'expected_execs':['text']},
     'patch_only_w0_zero':{'kernel_result':0xabcdef0000000000,'expected':0,'expected_execs':['text',0,1]},
     'patch_transport_failed':{'execute_error':-19008,'expected':-19008,'expected_execs':['text']},
     'patch_symbol_failed':{'symbol_error':-19979,'expected':-19979},
     'other_noresult_closure_compatible':{'alternate_vtable':True,'kernel_result':1,'expected':0,'expected_execs':['text',0,1]},
    }
    cases={name:dict(config,entry='text',saved=[0]) for name,config in cases.items()}
results={}
for name,config in cases.items():
    
    try:result=run(config)
    except Exception as error:result={'passed':False,'result':None,'executedCpus':[],'harnessError':str(error)}
    results[name]=result;print('PASS' if result['passed'] else 'FAIL',name,result['result'],result['executedCpus'])
report={'helperSha256':hashlib.sha256(blob).hexdigest(),'cases':results,'allPassed':all(x['passed'] for x in results.values()),'kernelStabilityVerified':False}
a.out.write_text(json.dumps(report,indent=2)+'\n')
raise SystemExit(0 if report['allPassed'] else 1)
