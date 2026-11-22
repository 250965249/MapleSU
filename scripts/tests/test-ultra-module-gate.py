"""Execute the delivered helper's actual common precheck; model only libc/syscall I/O."""
import argparse,io,json,struct
from pathlib import Path
from elftools.elf.elffile import ELFFile
from unicorn import Uc,UC_ARCH_ARM64,UC_MODE_ARM,UC_HOOK_CODE,UC_HOOK_INTR
from unicorn import arm64_const as r
p=argparse.ArgumentParser();p.add_argument('--helper',type=Path,required=True);p.add_argument('--out',type=Path);a=p.parse_args()
data=a.helper.read_bytes();elf=ELFFile(io.BytesIO(data));checks=[]
dyn=elf.get_section_by_name('.dynsym')
fprintf=next(elf.get_section_by_name('.plt')['sh_addr']+32+i*16 for i,rel in enumerate(elf.get_section_by_name('.rela.plt').iter_relocations()) if dyn.get_symbol(rel['r_info_sym']).name=='fprintf')
state_cases = [('legacy',None,2,False),('disabled',b'0'+b'a'*36+b'\n',0,True),('enabled',b'1'+b'a'*36+b'\n',0,False),('truncated',b'1',0,True),('garbage',b'X'+b'a'*36+b'\n',0,True),('unreadable',None,13,True),('overlong',b'1'+b'a'*36+b'\nX',0,True)]
cases = [(label,content,error,skip,(5,0,5)) for label,content,error,skip in state_cases]
# Preserve numeric minimum-version compatibility across the supported legacy range.
for version,skip in [((4,0,5),False),((4,6,5),False),((5,0,5),False),((5,1,0),False),((5,1,1),True),((4,0,4),True)]:
 cases.append(('minimum-'+'.'.join(map(str,version)),None,2,skip,version))
for label,content,error,skip,minimum in cases:
 u=Uc(UC_ARCH_ARM64,UC_MODE_ARM)
 for seg in elf.iter_segments():
  if seg['p_type']=='PT_LOAD':
   lo=seg['p_vaddr']&~4095;end=(seg['p_vaddr']+seg['p_memsz']+4095)&~4095
   u.mem_map(lo,end-lo);u.mem_write(seg['p_vaddr'],seg.data())
 u.mem_map(0x400000,0x20000);u.reg_write(r.UC_ARM64_REG_SP,0x408000);u.reg_write(r.UC_ARM64_REG_X30,0x410000)
 desc=0x412000;u.mem_write(desc+7168,b'touch_boost_oplus_1021_000000000\0');u.mem_write(desc+9220,struct.pack('<III',*minimum));u.reg_write(r.UC_ARM64_REG_X0,desc)
 u.mem_write(0x11fa38,b'\1\1');u.mem_write(0x11fa40,struct.pack('<III',5,1,0));u.mem_write(0x11fa50,struct.pack('<III',4,0,5))
 saved={i:0xcafe0000+i for i in range(19,30)}
 for i,v in saved.items():u.reg_write(getattr(r,'UC_ARM64_REG_X'+str(i)),v)
 calls=[]
 def returned(value):
  lr=u.reg_read(r.UC_ARM64_REG_X30)
  for i in range(19):u.reg_write(getattr(r,'UC_ARM64_REG_X'+str(i)),0xbad000+i)
  u.reg_write(r.UC_ARM64_REG_X0,value);u.reg_write(r.UC_ARM64_REG_PC,lr)
 def hook(uc,address,size,_):
  if address==0x410000:u.emu_stop()
  elif address==0xa6a9c:
   assert bytes(u.mem_read(u.reg_read(r.UC_ARM64_REG_X0),33))==b'touch_boost_oplus_1021_000000000\0'
   u.mem_write(u.reg_read(r.UC_ARM64_REG_X8),bytes([len(b'/fixture/mod')*2])+b'/fixture/mod\0'+bytes(10));returned(0)
  elif address==0x9f200:returned(0)
  elif address==fprintf:returned(0) # Model diagnostic output only; retain the real version decision.
 def syscall(uc,number,_):
  nr=u.reg_read(r.UC_ARM64_REG_X8);x0=u.reg_read(r.UC_ARM64_REG_X0);x1=u.reg_read(r.UC_ARM64_REG_X1)
  if nr==56:
   path=bytes(u.mem_read(x1,64)).split(b'\0')[0];calls.append(path.decode())
   flags=u.reg_read(r.UC_ARM64_REG_X2)
   # Linux ARM64 overrides the generic DIRECTORY/NOFOLLOW values. Model the
   # actual ABI: the old generic flags accidentally requested O_DIRECT on a dir.
   if path==b'/fixture/mod':value=10 if flags==(0o40000|0o100000|0o2000000) else -22
   else:
    assert path==b'.maplesu-state'
    value=(11 if content is not None else -error) if flags==(0o4000|0o100000|0o2000000) else -22
  elif nr==63:
   assert x0==11;count=min(len(content),u.reg_read(r.UC_ARM64_REG_X2));u.mem_write(x1,content[:count]);value=count
  elif nr==57:value=0
  else:raise AssertionError(nr)
  u.reg_write(r.UC_ARM64_REG_X0,value & ((1<<64)-1))
 u.hook_add(UC_HOOK_CODE,hook);u.hook_add(UC_HOOK_INTR,syscall)
 u.emu_start(0xa6d68,0x410004,count=2000)
 value=u.reg_read(r.UC_ARM64_REG_X0)
 assert (value!=0)==skip,(label,'expected skip',skip,'actual',value,calls)
 assert u.reg_read(r.UC_ARM64_REG_SP)==0x408000
 assert all(u.reg_read(getattr(r,'UC_ARM64_REG_X'+str(i)))==v for i,v in saved.items())
 checks.append(label);print('PASS',label,'skipped='+str(skip))
if a.out:a.out.write_text(json.dumps({'checks':checks,'actualHelperPrecheck':True,'hardwareVerification':False},indent=2))
