from pathlib import Path
import json,struct,hashlib,random
from unicorn import Uc,UC_ARCH_ARM64,UC_MODE_ARM,UC_HOOK_CODE
from unicorn import arm64_const as R
P=Path(__file__).resolve().parent;code=(P/'stat-code.bin').read_bytes();template=(P/'template.txt').read_text().encode()+b'\0'
def reg(n):return getattr(R,f'UC_ARM64_REG_X{n}')
cases=[]
for uid in (0,1,10000,10123,99999,0x12345678,0xffffffff):
 for fail in (False,True):
  for seed in range(3):
   u=Uc(UC_ARCH_ARM64,UC_MODE_ARM);u.mem_map(0x10000,0x40000);u.mem_map(0x80000,0x10000);u.mem_write(0x10000,code)
   sp=0x88000;u.reg_write(R.UC_ARM64_REG_SP,sp);rng=random.Random(seed)
   values=[rng.getrandbits(64) for i in range(31)]
   for i,v in enumerate(values):u.reg_write(reg(i),v)
   u.reg_write(reg(10),0x20000);u.mem_write(0x20000,template)
   u.reg_write(reg(12),0x24000);u.reg_write(reg(30),0x4f000)
   u.mem_write(0x30020,struct.pack('<Q',0x31000));u.mem_write(0x3100c,struct.pack('<I',uid))
   calls=[]
   def hook(uc,pc,size,unused):
    ins=struct.unpack('<I',uc.mem_read(pc,4))[0]
    if pc==0x4f000:uc.emu_stop();return
    if ins==0xd4200020:
     dst=uc.reg_read(reg(10));src=uc.reg_read(reg(11));buf=bytearray()
     while True:
      c=bytes(uc.mem_read(src+len(buf),1));buf+=c
      if c==b'\0':break
     uc.mem_write(dst,bytes(buf));uc.reg_write(reg(0),dst);calls.append('strcpy');uc.reg_write(R.UC_ARM64_REG_PC,pc+4)
    elif ins==0xd4200040:
     size=uc.reg_read(reg(0));dst=uc.reg_read(reg(19));src=uc.reg_read(reg(10))
     assert dst==0x24000 and size==len(template)
     result=bytes(uc.mem_read(src,size));expected=template.replace(b'00000000',f'{uid:08x}'.encode());assert result==expected,(result,expected)
     if not fail:uc.mem_write(dst,result)
     uc.reg_write(reg(0),size if fail else 0);calls.append('copy_to_user');uc.reg_write(R.UC_ARM64_REG_PC,pc+4)
   u.hook_add(UC_HOOK_CODE,hook);u.emu_start(0x10000,0,count=1000)
   assert calls==['strcpy','copy_to_user'] and u.reg_read(R.UC_ARM64_REG_PC)==0x4f000
   assert u.reg_read(R.UC_ARM64_REG_SP)==sp
   for i in range(1,30):assert u.reg_read(reg(i))==({10:0x20000,12:0x24000}.get(i,values[i])),i
   assert u.reg_read(reg(0))==(len(template) if fail else 0)
   assert bytes(u.mem_read(0x20000,len(template)))==template
   cases.append({'uid':uid,'copyFailure':fail,'seed':seed,'passed':True})
report={'passed':True,'cases':cases,'count':len(cases),'sourceSha256':hashlib.sha256((P/'stat_uid_path.cpp').read_bytes()).hexdigest(),'codeSha256':hashlib.sha256(code).hexdigest(),'scope':'Actual candidate source and SDK AsmJit generate ARM64, executed in Unicorn; get_current, kstrcpy and copy_to_user are fixtures; original authorization branch unchanged. No device acceptance.'}
(P/'codegen-replay.json').write_text(json.dumps(report,indent=2)+'\n');print('PASS',len(cases),'actual emitted ARM64 stat UID path cases')
