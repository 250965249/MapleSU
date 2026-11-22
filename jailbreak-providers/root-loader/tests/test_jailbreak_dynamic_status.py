"""Compile the production status backend; keep all kernel calls at explicit seams."""
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "jailbreak-providers/dirtyfrag/tests"))
from test_l3_arm import host_compiler

HARNESS = r"""
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
typedef unsigned char u8;
typedef unsigned int u32;
typedef uint64_t u64;
typedef uintptr_t uptr;
#define MAPLESU_NULL ((void*)0)
#define MAPLESU_NOCFI
#define MAPLESU_L3_STATUS_HIDE 1
#define MAPLESU_L3_PRE_KCFI_ID 0
#define MAPLESU_LEGACY_CFI 1
#define MAPLESU_ENOSYS 38
#define MAPLESU_TAG "test: "
struct kprobe;
struct pt_regs;
struct maplesu_pt_regs { u64 regs[31]; u64 sp,pc,pstate; };
struct maplesu_l3_probe {
 const char *symbol_name;
 int (*pre_handler)(struct kprobe *, struct pt_regs *);
};
static unsigned page_calls, maps, registrations, pins, locks, unlocks;
static unsigned uid=0, marked=1, wanted_lock=24, state_argument, cfi_calls;
static int fail_pin, fail_page, fail_map, missing_symbol, reentrant;
static long (*nested_read)(void*,void*,unsigned long,void*);
#define CHECK(x) do {if(!(x)){fprintf(stderr,"CHECK line=%d: %s\n",__LINE__,#x);exit(1);}}while(0)
void __cfi_check(u64 t,void*p,void*d){(void)t;(void)d;CHECK(p!=0);cfi_calls++;}
static unsigned char state[256], page[65536];
static void *maplesu_selinux=state;
char __this_module[1];
static uptr maplesu_current_task(void){return 1;}
static int maplesu_root_subject(uptr t){(void)t;return uid==0&&marked;}
static void _printk(const char*f,...){(void)f;}
static void* live_page(void){page_calls++;return fail_page?NULL:page;}
static void* live_page_state(void*p){CHECK(p==state);state_argument++;return live_page();}
static void* map_ram(void*a,unsigned n,int node){
 CHECK(*(uptr*)a==(uptr)page&&n==1&&node==-1);maps++;
 if(reentrant){unsigned char out[20];CHECK(nested_read(NULL,out,20,NULL)==-11);}
 return fail_map?NULL:page;
}
static void unmap_ram(void*a,unsigned n){(void)a;(void)n;}
static long cp(void*a,const void*b,unsigned long n){memcpy(a,b,n);return 0;}
static void lock_mutex(void*p){CHECK(p==state+wanted_lock);locks++;}
static void unlock_mutex(void*p){CHECK(p==state+wanted_lock);unlocks++;}
static u8 pin(void*p){CHECK(p==__this_module);pins++;return !fail_pin;}
static long simple_read(void*a,unsigned long n,void*p,const void*b,unsigned long sz){
 (void)p;if(n>sz)n=sz;memcpy(a,b,n);return (long)n;
}
static int register_kprobe(struct maplesu_l3_probe*p){(void)p;registrations++;return 0;}
static void unregister_kprobe(struct maplesu_l3_probe*p){(void)p;}
static uptr maplesu_sym(const char*n){
 if(!strcmp(n,"selinux_kernel_status_page"))return missing_symbol?0:(uptr)(state_argument?(void*)live_page_state:(void*)live_page);
 if(!strcmp(n,"vm_map_ram"))return (uptr)map_ram;
 if(!strcmp(n,"vm_unmap_ram"))return (uptr)unmap_ram;
 if(!strcmp(n,"simple_read_from_buffer"))return (uptr)simple_read;
 if(!strcmp(n,"copy_from_user_nofault")||!strcmp(n,"copy_to_user_nofault"))return (uptr)cp;
 if(!strcmp(n,"mutex_lock"))return (uptr)lock_mutex;
 if(!strcmp(n,"mutex_unlock"))return (uptr)unlock_mutex;
 if(!strcmp(n,"try_module_get"))return (uptr)pin;
 return 0;
}
#include "maplesu_selinux_hide.h"
int main(int argc,char**argv){
 const char*c=argc>1?argv[1]:"init";
 struct msu_selinux_hide p={0};struct maplesu_pt_regs regs={0};
 struct msu_selinux_status *live=(void*)page;
 *live=(struct msu_selinux_status){1,6,1,1,1};
 state_argument=!strcmp(c,"state-argument")||!strcmp(c,"anchored-layout")||!strcmp(c,"forged-anchor");missing_symbol=!strcmp(c,"missing-symbol");
 fail_pin=!strcmp(c,"pin-fail");fail_page=!strcmp(c,"page-fail");fail_map=!strcmp(c,"map-fail");
 reentrant=!strcmp(c,"concurrent-read");nested_read=maplesu_status_read;
 maplesu_status_init();
 CHECK(!page_calls&&!maps);if(!strcmp(c,"init"))return 0;
 p.version=MSU_STATUS_VERSION;p.command=MSU_STATUS_INITIALIZE;p.requested=1;
 p.layout=(struct msu_selinux_layout){MSU_STATUS_RUNTIME_BTF,256,24,48,4096,state_argument?1u:0u};
 p.baseline=(struct msu_selinux_status){1,4,1,1,1};
 if(!strcmp(c,"anchored-layout")||!strcmp(c,"forged-anchor")){
  const u32 code[]={0xd503233f,0xf800865e,0xa9bd7bfd,0xf9000bf5,0xa9024ff4,
      0x910003fd,0x91012013,0xaa0003f4,0xaa1303e0};
  maplesu_status_anchors.page_function=0x100000;
  maplesu_status_anchors.enforce_function=0x110000;
  maplesu_status_anchors.mutex_lock=0x120000;
  memcpy(maplesu_status_anchors.page_code,code,sizeof(code));
  memcpy(maplesu_status_anchors.enforce_code,code,sizeof(code));
  maplesu_status_anchors.page_code[9]=0x94000000|((0x120000-0x100000-36)/4);
  maplesu_status_anchors.enforce_code[9]=0x94000000|((0x120000-0x110000-36)/4);
  CHECK(msu_status_layout_from_anchors(&maplesu_status_anchors,4096,&p.layout));
  wanted_lock=72;
  if(!strcmp(c,"forged-anchor"))p.layout.status_lock=80;
 }
 if(!strcmp(c,"global-anchors")||!strcmp(c,"forged-anchor-abi")){
  maplesu_status_anchors.page_function=0x100000;
  maplesu_status_anchors.enforce_function=0x110000;
  maplesu_status_anchors.mutex_lock=0x120000;
  maplesu_status_anchors.state=0x200600;
  for(unsigned i=0;i<2;++i){
   u32 *code=i?maplesu_status_anchors.enforce_code:maplesu_status_anchors.page_code;
   uptr pc=i?0x110000:0x100000;u32 delta=(0x200000-pc)/4096;
   code[0]=0x90000013u|((delta&3)<<29)|((delta>>2)<<5);
   code[1]=0x91000273u|(0x600u<<10);code[2]=0x91006260u;
   code[3]=0x94000000u|((0x120000-pc-12)/4);
  }
  CHECK(msu_status_layout_from_anchors(&maplesu_status_anchors,4096,&p.layout));
  if(!strcmp(c,"forged-anchor-abi"))p.layout.status_page_abi=1;
 }
 if(!strcmp(c,"shifted-layout"))p.layout.status_lock=wanted_lock=72;
 if(!strcmp(c,"mutex40"))p.layout.mutex_size=40;
 if(!strcmp(c,"page16k"))p.layout.page_bytes=16384;
 if(!strcmp(c,"page64k"))p.layout.page_bytes=65536;
 if(!strcmp(c,"oversized-lock"))p.layout.status_lock=248;
 if(!strcmp(c,"unsupported-page"))p.layout.page_bytes=8192;
 if(!strcmp(c,"unsupported-abi"))p.layout.status_page_abi=2;
 if(!strcmp(c,"unknown-source"))p.layout.source=0;
 if(!strcmp(c,"old-version"))p.version=1;
 if(!strcmp(c,"app"))uid=10123;
 if(!strcmp(c,"unmarked-root"))marked=0;
 if(!strcmp(c,"disabled")||!strcmp(c,"toggle-from-off"))p.requested=0;
 if(!strcmp(c,"duck-counter"))p.baseline.sequence=2;
 if(!strcmp(c,"policy-changed"))live->policyload=2;
 int window_case=!strncmp(c,"repair-window",13), default_case=!strcmp(c,"missing-baseline")||!strcmp(c,"explicit-default");
 int invalid_window=!strcmp(c,"repair-window-invalid"), permissive_default=!strcmp(c,"permissive-default");
 if(window_case){
  *live=(struct msu_selinux_status){1,8,1,3,0};
  p.baseline=(struct msu_selinux_status){1,2,1,0,1};
#ifdef MSU_STATUS_BASELINE_WINDOW
  p.baseline_kind=MSU_STATUS_BASELINE_WINDOW;
  p.window_end=(struct msu_selinux_status){1,4,1,2,1};
  p.restore_from=0;p.restore_to=1;
  if(invalid_window)p.window_end.sequence=10;
  if(!strcmp(c,"repair-window-wrap")){
   p.baseline.sequence=0xfffffffcu;p.window_end.sequence=0;live->sequence=4;
  }
#endif
 }
 if(default_case){
  memset(&p.baseline,0,sizeof(p.baseline));
#ifdef MSU_STATUS_BASELINE_DEFAULT
  p.allow_default=1;
  if(!strcmp(c,"explicit-default")){p.baseline_kind=MSU_STATUS_BASELINE_DEFAULT;p.allow_default=0;}
#endif
 }
 if(permissive_default){
  live->enforcing=0;
#ifdef MSU_STATUS_BASELINE_DEFAULT
  p.allow_default=1;
#endif
 }
 maplesu_status_control((uptr)&p);
 CHECK(!page_calls&&!maps&&!locks&&!unlocks);
 if(!strcmp(c,"old-version")||!strcmp(c,"app")||!strcmp(c,"unmarked-root")){
  CHECK(!p.acknowledged&&!pins);return 0;
 }
 CHECK(p.acknowledged==MSU_STATUS_ACK);
 if(!strcmp(c,"oversized-lock")||!strcmp(c,"unsupported-page")||!strcmp(c,"unsupported-abi")||!strcmp(c,"unknown-source")||!strcmp(c,"forged-anchor")||!strcmp(c,"forged-anchor-abi")){
  CHECK(p.result==-22&&!pins&&maplesu_status_state==MSU_STATUS_IDLE);return 0;
 }
 if(fail_pin||missing_symbol){CHECK(p.result==-MAPLESU_ENOSYS&&maplesu_status_state==MSU_STATUS_IDLE);return 0;}
 CHECK(!p.result&&!p.initialized&&pins==1&&cfi_calls==1&&registrations==1);
 maplesu_status_control((uptr)&p);CHECK(p.result==-16&&pins==1);
 if(!strcmp(c,"pending-switch")) {
  p.command=MSU_STATUS_SET;p.requested=0;maplesu_status_control((uptr)&p);
  CHECK(p.result==-16&&maplesu_status_state==MSU_STATUS_PENDING);
  CHECK(maplesu_status_request.requested==1&&pins==1);p.requested=1;
 }
 regs.pc=0x5555;uid=10123;CHECK(!maplesu_status_read_pre(NULL,(void*)&regs)&&regs.pc==0x5555);
 uid=0;CHECK(maplesu_status_read_pre(NULL,(void*)&regs)&&regs.pc==(uptr)maplesu_status_read);
 unsigned char output[20];long rc=maplesu_status_read(NULL,output,20,NULL);
 p.command=MSU_STATUS_QUERY;maplesu_status_control((uptr)&p);
 CHECK(page_calls==1);
 if(fail_page||fail_map){CHECK(rc==-12&&p.result==-12&&!p.initialized&&!locks&&live->sequence==6);return 0;}
 CHECK(rc==20&&maps==1&&locks==1&&unlocks==1);
 if(invalid_window||permissive_default){
  CHECK(p.result==-22&&!p.initialized&&!p.effective&&live->sequence==(invalid_window?8u:6u));return 0;
 }
 if(window_case||default_case){
  int wrapped=!strcmp(c,"repair-window-wrap");
  CHECK(!p.result&&p.initialized&&p.effective);
  CHECK(live->sequence==(wrapped?0xfffffffeu:window_case?4u:0u));
  CHECK(live->policyload==(window_case?3u:1u)&&live->deny_unknown==(window_case?0u:1u));
  unsigned policy=live->policyload;
  live->sequence+=2;live->policyload++;
  unsigned sequence=live->sequence;
  p.command=MSU_STATUS_SET;p.requested=0;maplesu_status_control((uptr)&p);
  CHECK(maplesu_status_read(NULL,output,20,NULL)==20);
  p.command=MSU_STATUS_QUERY;maplesu_status_control((uptr)&p);
  CHECK(!p.result&&p.initialized&&!p.effective);
  CHECK(live->sequence==sequence+(wrapped?6u:window_case?4u:6u)&&live->policyload==policy+1);
  return 0;
 }
 if(!strcmp(c,"policy-changed")){CHECK(p.result==-22&&!p.initialized&&!p.effective&&live->sequence==6);return 0;}
 CHECK(!p.result&&p.initialized&&p.effective==p.requested);
 CHECK(live->sequence==(p.requested?p.baseline.sequence:6)&&live->enforcing==1&&live->policyload==1&&live->deny_unknown==1);
 CHECK(!memcmp(output,live,20)&&p.before.sequence==6&&p.after.sequence==live->sequence);
 CHECK(p.layout.status_lock==wanted_lock&&p.layout.page_bytes>=4096);
 if(!strcmp(c,"state-argument"))CHECK(state_argument==2);
 if(!strcmp(c,"same-value-switch")) {
  for(unsigned round=0;round<16;++round) {
   p.command=MSU_STATUS_SET;maplesu_status_control((uptr)&p);
   CHECK(!p.result&&p.initialized&&p.effective&&live->sequence==4);
   CHECK(locks==1&&unlocks==1&&pins==1&&maps==1&&page_calls==1);
   CHECK(!maplesu_status_read_pre(NULL,(void*)&regs));
  }
  return 0;
 }
 if(!strcmp(c,"failed-switch")) {
  live->version=2;p.command=MSU_STATUS_SET;p.requested=0;
  maplesu_status_control((uptr)&p);CHECK(!p.result&&!p.initialized);
  CHECK(maplesu_status_read(NULL,output,20,NULL)==20);
  p.command=MSU_STATUS_QUERY;maplesu_status_control((uptr)&p);
  CHECK(p.result==-22&&!p.initialized&&!p.effective&&live->sequence==4);
  CHECK(maplesu_status_enabled==1&&maplesu_status_delta==2);
  p.command=MSU_STATUS_SET;maplesu_status_control((uptr)&p);
  CHECK(p.result==-22&&maplesu_status_state==MSU_STATUS_FAILED&&pins==1);
  return 0;
 }
 if(!strncmp(c,"toggle",6)) {
  for(unsigned round=0;round<16;++round) {
   if(round==3&&!strcmp(c,"toggle-later-policy")) {live->sequence+=2;live->policyload=2;live->deny_unknown=0;}
   if(round==3&&!strcmp(c,"toggle-counter-wrap"))live->sequence=0xfffffffeu;
   unsigned next=!p.effective, sequence=live->sequence+(next?-2u:2u);
   unsigned policy=live->policyload,deny=live->deny_unknown;
   p.command=2; /* MSU_STATUS_SET: leave this runnable against the pre-fix ABI. */
   p.requested=next;maplesu_status_control((uptr)&p);
   CHECK(!p.result&&!p.initialized&&pins==1);
   CHECK(maplesu_status_read_pre(NULL,(void*)&regs));
   CHECK(maplesu_status_read(NULL,output,20,NULL)==20);
   p.command=MSU_STATUS_QUERY;maplesu_status_control((uptr)&p);
   CHECK(!p.result&&p.initialized&&p.effective==next&&live->sequence==sequence);
   CHECK(live->policyload==policy&&live->deny_unknown==deny&&live->enforcing==1);
   CHECK(maps==1&&page_calls==1&&pins==1&&!memcmp(output,live,20));
  }
  return 0;
 }
 regs.pc=0x5555;CHECK(!maplesu_status_read_pre(NULL,(void*)&regs)&&regs.pc==0x5555);
 live->sequence+=2;live->policyload=2;
 CHECK(maplesu_status_read(NULL,output,20,NULL)==20&&((struct msu_selinux_status*)output)->policyload==2);
 CHECK(locks==1&&pins==1&&page_calls==1);
 return 0;
}
"""

class DynamicStatusTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp=tempfile.TemporaryDirectory(prefix="msu-status-dynamic-")
        cls.addClassCleanup(cls.tmp.cleanup)
        folder=Path(cls.tmp.name);source=folder/"status.c"
        source.write_text(HARNESS,encoding="utf-8")
        cls.binary=folder/("status.exe" if os.name=="nt" else "status")
        result=subprocess.run([str(host_compiler()),"-std=c11","-I",str(ROOT/"jailbreak-providers/root-loader/module"),str(source),"-o",str(cls.binary)],capture_output=True,text=True)
        if result.returncode:raise AssertionError(result.stderr)

    def run_case(self,case):
        result=subprocess.run([str(self.binary),case],capture_output=True,text=True)
        self.assertEqual(result.returncode,0,result.stderr)

    def test_no_layout_dependent_kernel_call_before_runtime_verification(self):
        self.run_case("init")

    def test_same_payload_consumes_changed_offsets_sizes_and_call_abi(self):
        for case in ("success","shifted-layout","mutex40","state-argument","page16k","page64k","anchored-layout","global-anchors"):
            with self.subTest(case=case):self.run_case(case)

    def test_invalid_layout_does_not_call_kernel_helpers(self):
        for case in ("oversized-lock","unsupported-page","unsupported-abi","unknown-source","forged-anchor","forged-anchor-abi"):
            with self.subTest(case=case):self.run_case(case)

    def test_control_identity_protocol_and_failure_receipts(self):
        for case in ("app","unmarked-root","old-version","pin-fail","page-fail","map-fail","missing-symbol"):
            with self.subTest(case=case):self.run_case(case)

    def test_duck_counter_correction_preserves_policy_and_existing_mappings(self):
        self.run_case("duck-counter")

    def test_runtime_switch_preserves_future_events(self):
        for case in ("toggle","toggle-from-off","toggle-later-policy","toggle-counter-wrap"):
            with self.subTest(case=case):self.run_case(case)

    def test_live_switch_idempotence_busy_and_failure(self):
        for case in ("same-value-switch","pending-switch","failed-switch"):
            with self.subTest(case=case):self.run_case(case)

    def test_disabled_policy_reload_and_racing_reader(self):
        for case in ("disabled","policy-changed","concurrent-read"):
            with self.subTest(case=case):self.run_case(case)

    def test_root_repair_window_preserves_later_policy_events(self):
        for case in ("repair-window", "repair-window-wrap", "repair-window-invalid"):
            with self.subTest(case=case): self.run_case(case)

    def test_missing_app_snapshot_activates_a_labelled_default(self):
        for case in ("missing-baseline", "explicit-default", "permissive-default"):
            with self.subTest(case=case): self.run_case(case)

if __name__=="__main__":unittest.main()
