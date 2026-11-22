"""Replay the real helper hook publication slice and original cleanup in AArch64."""
import argparse,hashlib,io,json,struct
from pathlib import Path
from elftools.elf.elffile import ELFFile
from unicorn import Uc,UC_ARCH_ARM64,UC_MODE_ARM,UC_HOOK_CODE
from unicorn import arm64_const as R
p=argparse.ArgumentParser();p.add_argument('--helper',type=Path,required=True);p.add_argument('--out',type=Path,required=True);p.add_argument('--baseline',action='store_true',help='Demonstrate original unsafe publication; exits nonzero');a=p.parse_args()
blob=a.helper.read_bytes();elf=ELFFile(io.BytesIO(blob))
BASE,STACK,DATA,STOP,HEAP=0x1000000,0x4000000,0x5000000,0x6000000,0x7000000
ENTRY,FLAG,HANDLER,TRAMP=0xffff000000001000,0xffff000000003000,0xffff000000005000,0xffff000000006000
ORIGINAL,BRANCH=0xd503201f,0x14001400
MASK=(1<<64)-1
imports={BASE+elf.get_section_by_name('.plt')['sh_addr']+32+16*i:elf.get_section_by_name('.dynsym').get_symbol(r['r_info_sym']).name for i,r in enumerate(elf.get_section_by_name('.rela.plt').iter_relocations())}
byname={n:at for at,n in imports.items()}
def run(steps,expected,final=ORIGINAL,flag=1,handle=False,null=False,gate=False,allocation=False):
 u=Uc(UC_ARCH_ARM64,UC_MODE_ARM);pages=set()
 for s in elf.iter_segments():
  if s['p_type']!='PT_LOAD':continue
  for at in range((BASE+s['p_vaddr'])&~4095,(BASE+s['p_vaddr']+s['p_memsz']+4095)&~4095,4096):
   if at not in pages:u.mem_map(at,4096);pages.add(at)
  u.mem_write(BASE+s['p_vaddr'],s.data())
 dyn=elf.get_section_by_name('.dynsym')
 for name in ['.rela.dyn','.rela.plt']:
  for r in elf.get_section_by_name(name).iter_relocations():
   s=dyn.get_symbol(r['r_info_sym']);kind=r['r_info_type']
   if kind==1027:value=BASE+r['r_addend']
   elif kind in (257,1025,1026):value=(BASE+s['st_value'] if s['st_shndx']!='SHN_UNDEF' else byname.get(s.name,DATA+0x8000))+r['r_addend']
   else:raise AssertionError(kind)
   u.mem_write(BASE+r['r_offset'],struct.pack('<Q',value&MASK))
 for at in [STACK,DATA,STOP,HEAP]:u.mem_map(at,0x10000)
 state={'code':ORIGINAL,'flag':0,'at':0,'heap':HEAP,'writes':[],'early':0,'freed':[],'allocations':[],'flagAllocated':False,'tls':{},'throwReturn':None,'callbacks':[],'exceptionRuntime':{}}
 sp=STACK+0xf000
 def get(i):return u.reg_read(getattr(R,f'UC_ARM64_REG_X{i}'))
 def ret(v):
  link=get(30)
  for i in range(1,18):u.reg_write(getattr(R,f'UC_ARM64_REG_X{i}'),0xbad000+i)
  u.reg_write(R.UC_ARM64_REG_NZCV,0xf0000000)
  u.reg_write(R.UC_ARM64_REG_X0,v&MASK);u.reg_write(R.UC_ARM64_REG_PC,link)
 def throw_exception():
  state['throwReturn']=get(30)
  u.reg_write(R.UC_ARM64_REG_X0,8);u.reg_write(R.UC_ARM64_REG_X30,STOP+0x100)
  u.reg_write(R.UC_ARM64_REG_PC,BASE+0x9f240)
 def cstr(at):
  b=bytearray()
  for i in range(16384):
   c=bytes(u.mem_read(at+i,1))
   if c==b'\0':return bytes(b)
   b.extend(c)
  raise AssertionError('unterminated string')
 def take(op):
  assert state['at']<len(steps),(op,state['at'],steps)
  action=steps[state['at']];state['at']+=1;assert action[0]==op,(action,op)
  state['throwNow']=len(action)>4 and action[4]
  return (list(action)+[0,True,None])[0:4] if len(action)==1 else [op,action[1],action[2] if len(action)>2 else True,action[3] if len(action)>3 else None]
 def alloc(n):
  at=state['heap'];state['heap']+=(n+15)&~15;state['allocations'].append(at);return at
 def hook(uc,pc,size,_):
  if pc-BASE in [0x9f240,0x9f364,0xa0fb0,0x9f9b8,0x9f294,0x9f474]:
   key=hex(pc-BASE);state['exceptionRuntime'][key]=state['exceptionRuntime'].get(key,0)+1
  if pc==STOP:uc.emu_stop();return
  if pc==STOP+0x100:
   exception=get(0);u.mem_write(exception,struct.pack('<Q',17))
   u.mem_write(DATA+0x7000,struct.pack('<QQ',0,DATA+0x7020));u.mem_write(DATA+0x7020,b'i\0')
   u.reg_write(R.UC_ARM64_REG_X1,DATA+0x7000);u.reg_write(R.UC_ARM64_REG_X2,0)
   u.reg_write(R.UC_ARM64_REG_X30,state['throwReturn']);u.reg_write(R.UC_ARM64_REG_PC,BASE+0x9f364);return
  if pc==STOP+0x200:
   link,iterate=state['callbacks'].pop();value=get(0) if iterate else 0;u.reg_write(R.UC_ARM64_REG_X30,link);ret(value);return
  if pc==BASE+0xce314:
   frame=get(29);current_sp=u.reg_read(R.UC_ARM64_REG_SP)
   for r,v in [(19,0 if null else DATA+0x1000),(20,ENTRY),(21,128)]:u.reg_write(getattr(R,f'UC_ARM64_REG_X{r}'),v)
   u.mem_write(frame-0x20,struct.pack('<QQQ',DATA+0x2000,DATA+0x2010,DATA+0x2010))
   u.mem_write(DATA+0x2000,struct.pack('<QII',ENTRY,ORIGINAL,0))
   u.mem_write(current_sp+0x80,struct.pack('<QQ',FLAG,HANDLER));u.mem_write(frame-0x88,struct.pack('<Q',TRAMP))
   u.reg_write(R.UC_ARM64_REG_X0,BRANCH)
   u.reg_write(R.UC_ARM64_REG_PC,BASE+(0xce758 if gate else 0xcea4c));return
  if gate and pc==BASE+0xce788:
   uc.emu_stop();return
  if pc==BASE+0xd2190:
   state['flagAllocated']=True;u.mem_write(get(0),struct.pack('<Q',FLAG));ret(0);return
  if pc==BASE+0xc07b0:
   assert get(0)==FLAG and get(1)==1 and get(2)==1;ret(0);return
  if pc==BASE+0xc0560:
   op,status,mutate,read=take('r')
   if state['throwNow']:throw_exception();return
   assert get(0)==ENTRY and get(2)==4
   if status==0:u.mem_write(get(1),struct.pack('<I',state['code'] if read is None else read))
   ret(status);return
  if pc==BASE+0xc0654:
   code=get(0)==ENTRY;op,status,mutate,_=take('w' if code else 'f')
   if code:
    assert get(2)==4 and get(3)==2
    value=struct.unpack('<I',bytes(u.mem_read(get(1),4)))[0];state['writes'].append(value)
    if mutate:
     state['code']=value
     if value==BRANCH and state['flag']==0:state['early']+=1
   else:
    assert get(0)==FLAG and get(2)==1 and get(3)==1
    if mutate:state['flag']=bytes(u.mem_read(get(1),1))[0]
   if state['throwNow']:throw_exception();return
   ret(status);return
  if pc==BASE+0x9f184:
   if allocation:throw_exception()
   else:ret(alloc(get(0)))
   return
  if pc==BASE+0x9f200:state['freed'].append(get(0));ret(0);return
  name=imports.get(pc)
  if name=='malloc':ret(alloc(get(0)))
  elif name=='posix_memalign':
   out=get(0);n=get(2);u.mem_write(out,struct.pack('<Q',alloc(n)));ret(0)
  elif name in ('strlen','__strlen_chk'):ret(len(cstr(get(0))))
  elif name in ('pthread_mutex_lock','pthread_mutex_unlock','pthread_rwlock_rdlock','pthread_rwlock_wrlock','pthread_rwlock_unlock'):ret(0)
  elif name in ('getpid','gettid'):ret(1234)
  elif name=='pthread_self':ret(DATA+0x9000)
  elif name=='pthread_getspecific':ret(state['tls'].get(get(0),0))
  elif name=='pthread_setspecific':state['tls'][get(0)]=get(1);ret(0)
  elif name=='pthread_key_create':u.mem_write(get(0),struct.pack('<I',1));ret(0)
  elif name=='pthread_once':
   at,fn=get(0),get(1)
   if bytes(u.mem_read(at,4))!=bytes(4):ret(0)
   else:
    u.mem_write(at,struct.pack('<I',2));state['callbacks'].append((get(30),False))
    u.reg_write(R.UC_ARM64_REG_X30,STOP+0x200);u.reg_write(R.UC_ARM64_REG_PC,fn)
  elif name=='dl_iterate_phdr':
   fn,context=get(0),get(1);info=DATA+0x8000
   u.mem_write(info,struct.pack('<QQQH',BASE,DATA+0x8050,BASE+elf['e_phoff'],elf['e_phnum'])+bytes(102))
   u.mem_write(DATA+0x8050,b'helper-fixture\0');state['callbacks'].append((get(30),True))
   for i,v in [(0,info),(1,64),(2,context),(30,STOP+0x200)]:u.reg_write(getattr(R,f'UC_ARM64_REG_X{i}'),v)
   u.reg_write(R.UC_ARM64_REG_PC,fn)
  elif name=='free':state['freed'].append(get(0));ret(0)
  elif name=='memcpy':target=get(0);u.mem_write(target,bytes(u.mem_read(get(1),get(2))));ret(target)
  elif name=='memset':target=get(0);u.mem_write(target,bytes([get(1)&255])*get(2));ret(target)
  elif name:raise AssertionError(('unexpected import',name,hex(get(30))))
 u.hook_add(UC_HOOK_CODE,hook)
 def invoke():
  u.reg_write(R.UC_ARM64_REG_SP,sp);u.reg_write(R.UC_ARM64_REG_X30,STOP)
  for i in range(19,30):u.reg_write(getattr(R,f'UC_ARM64_REG_X{i}'),0x9900+i)
  u.emu_start(BASE+0xce2f4,STOP+4,count=2000000)
 invoke()
 if gate:return {'passed':state['flagAllocated'] and state['at']==0,'flagAllocated':state['flagAllocated']}
 assert u.reg_read(R.UC_ARM64_REG_PC)==STOP,'instruction budget'
 assert u.reg_read(R.UC_ARM64_REG_SP)==sp
 for i in range(19,30):assert get(i)==0x9900+i,(i,hex(get(i)))
 result=get(0);result=result if result<1<<63 else result-(1<<64)
 if allocation or any(len(step)>4 and step[4] for step in steps):
  assert all(state['exceptionRuntime'].get(hex(at),0)>0 for at in [0x9f240,0x9f364,0xa0fb0,0x9f9b8,0x9f294,0x9f474]),state['exceptionRuntime']
 context=struct.unpack('<Q',bytes(u.mem_read(DATA+0x1000,8)))[0] if not null else 0
 context_ok=bool(context)==handle
 if context:
  raw=bytes(u.mem_read(context,48))
  fields=(struct.unpack_from('<Q',raw)[0],struct.unpack_from('<I',raw,8)[0],struct.unpack_from('<QQ',raw,16),raw[32],struct.unpack_from('<Q',raw,40)[0])
  context_ok=context_ok and fields==(ENTRY,ORIGINAL,(HANDLER,128),0 if flag else 1,FLAG)
 repeated=None
 if result==-19991:
  before=state['at'];invoke();repeated=get(0)-(1<<64)
  assert repeated==-19991 and state['at']==before
 return {'passed':result==expected and state['code']==final and state['flag']==flag and state['at']==len(steps) and state['early']==0 and context_ok,'result':result,'expected':expected,'entry':hex(state['code']),'flag':state['flag'],'steps':state['at'],'earlyCallbacks':state['early'],'exceptionRuntime':state['exceptionRuntime'],'contextValid':context_ok,'repeatStatus':repeated,'writes':list(map(hex,state['writes']))}
cases={
 'success':dict(steps=[['r'],['f'],['w'],['r'],['f']],expected=0,final=BRANCH,flag=0,handle=True),
 'no_handle_success':dict(steps=[['r'],['f'],['w'],['r'],['f']],expected=0,final=BRANCH,flag=0,null=True),
 'read_failed':dict(steps=[['r',-101]],expected=-101,flag=0),
 'unexpected_entry':dict(steps=[['r',0,True,0xd503245f]],expected=-19980,flag=0),
 'guard_failed':dict(steps=[['r'],['f',-102,False]],expected=-102,flag=0),
 'entry_error_before_store':dict(steps=[['r'],['f'],['w',-103,False],['f'],['w'],['r']],expected=-103),
 'entry_error_after_store':dict(steps=[['r'],['f'],['w',-104],['f'],['w'],['r']],expected=-104),
 'readback_error':dict(steps=[['r'],['f'],['w'],['r',-105],['f'],['w'],['r']],expected=-105),
 'readback_mismatch':dict(steps=[['r'],['f'],['w',0,False],['r'],['f'],['w'],['r']],expected=-19990),
 'activation_after_store_error':dict(steps=[['r'],['f'],['w'],['r'],['f',-106],['f'],['w'],['r']],expected=-106),
 'rollback_failed':dict(steps=[['r'],['f'],['w',-107],['f'],['w',-108,False],['r']],expected=-19991,final=BRANCH,handle=True),
 'rollback_cache_error':dict(steps=[['r'],['f'],['w',-107],['f'],['w',-108],['r']],expected=-19991,handle=True),
 'rollback_read_error':dict(steps=[['r'],['f'],['w',-107],['f'],['w'],['r',-109]],expected=-19991,handle=True),
 'rollback_mismatch':dict(steps=[['r'],['f'],['w',-107],['f'],['w',0,False],['r']],expected=-19991,final=BRANCH,handle=True),
 'active_pending':dict(steps=[['r'],['f'],['w'],['r'],['f',-106],['f',-110,False],['w',-108,False],['r']],expected=-19991,final=BRANCH,flag=0,handle=True),
 'no_handle_pending':dict(steps=[['r'],['f'],['w',-107],['f'],['w',-108,False],['r']],expected=-19991,final=BRANCH,null=True),
 'allocation_exception':dict(steps=[],expected=-19905,flag=0,allocation=True),
 'read_exception':dict(steps=[['r',0,True,None,True]],expected=-19990,flag=0),
 'entry_exception_after_store':dict(steps=[['r'],['f'],['w',0,True,None,True],['f'],['w'],['r']],expected=-19990),
 'rollback_exception':dict(steps=[['r'],['f'],['w',-107],['f'],['w',0,False,None,True]],expected=-19991,final=BRANCH,handle=True),
 'no_handle_reserves_flag':dict(steps=[],expected=0,gate=True,null=True),
}
if a.baseline:
 cases={
  'original_publish_has_no_bypass':dict(steps=[['w']],expected=0,final=BRANCH,flag=0,handle=True),
  'original_error_after_store_has_no_rollback':dict(steps=[['w',-104]],expected=-104,final=ORIGINAL,flag=1),
  'original_no_handle_has_no_flag':dict(steps=[],expected=0,gate=True,null=True),
 }
results={}
for n,c in cases.items():
 try:r=run(**c)
 except Exception as error:r={'passed':False,'error':str(error)}
 results[n]=r;print('PASS' if r['passed'] else 'FAIL',n,r)
report={'helperSha256':hashlib.sha256(blob).hexdigest(),'cases':results,'allPassed':all(r['passed'] for r in results.values()),'scope':'Actual final publication slice, original cleanup and C++/libunwind exception instructions; libc and kernel I/O boundaries mocked; no device execution'}
a.out.write_text(json.dumps(report,indent=2)+'\n');raise SystemExit(not report['allPassed'])
