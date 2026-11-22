"""Run the production status handshake and restoration with kernel boundaries replaced."""
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / 'jailbreak-providers/dirtyfrag/tests'))
from test_l3_arm import definition, host_compiler


class StatusViewTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        source = (ROOT / 'jailbreak-providers/root-loader/module/maplesu_selinux_hide.h').read_text()
        cls.tmp = tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls.tmp.cleanup)
        folder = Path(cls.tmp.name)
        header = r'''
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
typedef unsigned char u8;
typedef unsigned int u32;
typedef uintptr_t uptr;
typedef uint64_t u64;
#define MAPLESU_NOCFI
#define MAPLESU_ENOSYS 38
struct kprobe;
struct maplesu_pt_regs { u64 regs[31]; u64 sp,pc,pstate; };
struct pt_regs;
#include "selinux_hide_abi.h"
enum { MSU_STATUS_IDLE, MSU_STATUS_RESERVED, MSU_STATUS_PENDING,
       MSU_STATUS_APPLYING, MSU_STATUS_READY, MSU_STATUS_FAILED };
static u32 maplesu_status_available=1, maplesu_status_state, maplesu_status_enabled;
static int maplesu_status_result;
static u32 maplesu_status_captured, maplesu_status_delta;
static int maplesu_status_setup(void){return 0;}
static struct msu_selinux_hide maplesu_status_request;
static struct msu_selinux_anchors maplesu_status_anchors;
static struct msu_selinux_status live={1,6,1,1,1};
static struct msu_selinux_status *maplesu_status_live=&live;
static unsigned uid=10123, marked=1, locks, unlocks, pins;
static u8 state[128],*maplesu_selinux=state;
char __this_module[1];
static uptr maplesu_current_task(void){return 1;}
static int maplesu_root_subject(uptr task){(void)task;return uid==0&&marked;}
static long cp(void*to,const void*from,unsigned long n){memcpy(to,from,n);return 0;}
static long (*maplesu_copy_from_nofault)(void*,const void*,unsigned long)=cp;
static long (*maplesu_copy_to_nofault)(void*,const void*,unsigned long)=cp;
static void maplesu_status_mutex_lock(void*p){if(p!=state+24)abort();locks++;}
static void maplesu_status_mutex_unlock(void*p){if(p!=state+24)abort();unlocks++;}
static u8 maplesu_status_module_get(void*p){if(p!=__this_module)abort();pins++;return 1;}
static long maplesu_simple_read(void *buf,unsigned long count,void *pos,const void *in,unsigned long size){
 (void)pos;if(count>size)count=size;memcpy(buf,in,count);return count;
}
'''
        main = r'''
#define CHECK(condition) do { if(!(condition)){fprintf(stderr,"line=%d\n",__LINE__);return 1;} } while(0)
int main(int argc,char**argv){
 const char*c=argc>1?argv[1]:"success";
 struct msu_selinux_hide p={0};
 struct maplesu_pt_regs regs={0};regs.pc=0x5555;
 struct msu_selinux_status*inherited_mapping=maplesu_status_live;
 p.version=MSU_STATUS_VERSION;p.command=MSU_STATUS_INITIALIZE;p.requested=1;
 p.baseline=(struct msu_selinux_status){1,4,1,1,1};
 p.layout=(struct msu_selinux_layout){MSU_STATUS_RUNTIME_BTF,128,24,48,4096,0};
 if(!strcmp(c,"app-control")){
  maplesu_status_control((uptr)&p);CHECK(!p.acknowledged&&!pins);return 0;
 }
 uid=0;
 if(!strcmp(c,"unmarked-root")){
  marked=0;maplesu_status_control((uptr)&p);CHECK(!p.acknowledged&&!pins);return 0;
 }
 if(!strcmp(c,"odd"))p.baseline.sequence=3;
 if(!strcmp(c,"live-odd"))live.sequence=7;
 if(!strcmp(c,"policy-changed"))p.baseline.policyload=2;
 if(!strcmp(c,"deny-changed"))p.baseline.deny_unknown=0;
 if(!strcmp(c,"permissive"))live.enforcing=0;
 if(!strcmp(c,"future-baseline"))p.baseline.sequence=8;
 if(!strcmp(c,"disabled"))p.requested=0;
 struct msu_selinux_status original=live;
 maplesu_status_control((uptr)&p);
 CHECK(p.acknowledged==MSU_STATUS_ACK&&p.result==0&&p.available&&!p.initialized&&!p.effective);
 CHECK(pins==1&&!memcmp(&original,&live,20)&&!locks&&!unlocks);
 maplesu_status_control((uptr)&p);CHECK(p.result==-16&&pins==1);
 p.command=MSU_STATUS_QUERY;maplesu_status_control((uptr)&p);CHECK(!p.result&&!p.initialized);
 uid=10123;CHECK(maplesu_status_read_pre(NULL,(void*)&regs)==0&&regs.pc==0x5555);
 uid=0;CHECK(maplesu_status_read_pre(NULL,(void*)&regs)==1&&regs.pc==(uptr)&maplesu_status_read);
 unsigned char output[20];CHECK(maplesu_status_read(NULL,output,20,NULL)==20);
 CHECK(locks==1&&unlocks==1&&maplesu_status_live==inherited_mapping);
 maplesu_status_control((uptr)&p);
 if(!strcmp(c,"odd")||!strcmp(c,"policy-changed")||!strcmp(c,"permissive")||
    !strcmp(c,"live-odd")||!strcmp(c,"deny-changed")||!strcmp(c,"future-baseline")){
  CHECK(p.result==-22&&!p.initialized&&!p.effective&&!memcmp(&original,&live,20));return 0;
 }
 CHECK(p.result==0&&p.initialized&&p.effective==p.requested);
 CHECK(live.enforcing==1&&live.policyload==1&&live.deny_unknown==1);
 CHECK(live.sequence==(!strcmp(c,"disabled")?6:4));
 CHECK(!memcmp(output,&live,20)&&!memcmp(&p.before,&original,20));
 CHECK(inherited_mapping->sequence==live.sequence&&p.after.sequence==live.sequence);
 regs.pc=0x5555;CHECK(maplesu_status_read_pre(NULL,(void*)&regs)==0&&regs.pc==0x5555);
 live.sequence+=2;live.policyload=2;
 maplesu_status_read(NULL,output,20,NULL);
 CHECK(locks==1&&unlocks==1&&pins==1&&((struct msu_selinux_status*)output)->policyload==2);
 CHECK(inherited_mapping->sequence==live.sequence);
 p.command=MSU_STATUS_INITIALIZE;maplesu_status_control((uptr)&p);CHECK(p.result==-16&&pins==1);
 return 0;
}
'''
        (folder / 'selinux_hide_abi.h').write_bytes((ROOT / 'jailbreak-providers/root-loader/selinux_hide_abi.h').read_bytes())
        path = folder / 'status.c'
        functions = ('maplesu_status_read', 'maplesu_status_read_pre', 'maplesu_status_control')
        path.write_text(header + '\n'.join(definition(source,n) for n in functions) + main)
        cls.binary = folder / ('status.exe' if os.name == 'nt' else 'status')
        result = subprocess.run([str(host_compiler()), '-std=c11', str(path), '-o', str(cls.binary)], capture_output=True,text=True)
        if result.returncode: raise AssertionError(result.stderr)

    def test_dirty_counter_read_and_existing_mapping(self):
        subprocess.run([str(self.binary), 'success'],check=True)

    def test_invalid_baseline_is_never_applied(self):
        for case in ('odd','live-odd','policy-changed','deny-changed','permissive','future-baseline'):
            with self.subTest(case=case):subprocess.run([str(self.binary),case],check=True)

    def test_disable_and_control_identity(self):
        for case in ('disabled','app-control','unmarked-root'):
            with self.subTest(case=case):subprocess.run([str(self.binary),case],check=True)


if __name__ == '__main__': unittest.main()
