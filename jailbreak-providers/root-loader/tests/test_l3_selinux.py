"""Real C callback regression for stock carrier exit127 / SELinux fd use denial."""
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / 'jailbreak-providers/dirtyfrag/tests'))
from test_l3_arm import definition, host_compiler
sys.path.insert(0, str(ROOT / 'jailbreak-providers/root-loader'))
import build_root_module as builder
SOURCE = ROOT / 'jailbreak-providers/root-loader/module/maplesu_l3.c'

class RootSubjectTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = SOURCE.read_text(encoding='utf-8')
        cc = host_compiler()
        if cc is None:
            raise AssertionError('host compiler missing')
        cls.tmp = tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls.tmp.cleanup)
        base = Path(cls.tmp.name)
        cls.binary = base / ('subject.exe' if os.name == 'nt' else 'subject')
        header = r'''
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
typedef unsigned char u8;
typedef unsigned int u32;
typedef uint64_t u64;
typedef uintptr_t uptr;
#define MAPLESU_NULL ((void *)0)
#define MAPLESU_TASK_CRED_OFF 0
#define MAPLESU_CRED_UID_OFF 8
#define MAPLESU_CRED_EUID_OFF 12
#define MAPLESU_CRED_GROUPS_OFF 16
struct kprobe;
struct pt_regs;
struct maplesu_pt_regs { u64 regs[31]; u64 sp,pc,pstate; };
static u32 maplesu_ready;
static uptr maplesu_groups;
static uptr fake_task[1];
static uptr maplesu_current_task(void) { return (uptr)fake_task; }
'''
        main = r'''
int main(int argc,char **argv) {
 u8 cred[32]={0}; uptr groups=42; u32 uid=0,euid=0;
 struct maplesu_pt_regs frame,original;
 memset(&frame,0x35,sizeof(frame)); frame.regs[30]=0x1000;
 original=frame; maplesu_ready=1; maplesu_groups=groups;
 const char *c=argc>1?argv[1]:"root";
 if(!strcmp(c,"unarmed"))maplesu_ready=0;
 if(!strcmp(c,"app"))uid=euid=10155;
 if(!strcmp(c,"setuid"))euid=10155;
 if(!strcmp(c,"unmarked"))groups=43;
 if(!strcmp(c,"missing"))maplesu_groups=0;
 memcpy(cred+8,&uid,4);memcpy(cred+12,&euid,4);memcpy(cred+16,&groups,sizeof(groups));
 fake_task[0]=(uptr)cred;
 if(!strcmp(c,"nullcred"))fake_task[0]=0;
 int rc=maplesu_avc_pre(NULL,!strcmp(c,"nullframe")?NULL:(struct pt_regs *)&frame);
 int allowed=rc==1 && frame.regs[0]==0 && frame.pc==original.regs[30];
 if(rc==1) { frame.regs[0]=original.regs[0];frame.pc=original.pc; }
 printf("rc=%d allowed=%d preserved=%d\n",rc,allowed,!memcmp(&frame,&original,sizeof(frame)));
 return 0;
}
'''
        body = '\n'.join(definition(cls.source,n) for n in ('maplesu_root_subject','maplesu_avc_pre'))
        path=base/'subject.c';path.write_text(header+body+main,encoding='utf-8')
        result=subprocess.run([str(cc),'-std=c11',str(path),'-o',str(cls.binary)],capture_output=True,text=True)
        if result.returncode:raise AssertionError(result.stderr)

    def run_case(self,case):
        result=subprocess.run([str(self.binary),case],capture_output=True,text=True,check=True)
        return dict(p.split('=') for p in result.stdout.split())

    def test_marked_root_has_data_path_and_preserves_other_registers(self):
        self.assertEqual({'rc':'1','allowed':'1','preserved':'1'},self.run_case('root'))

    def test_unmarked_root_and_apps_keep_original_denial(self):
        for c in ('unarmed','app','setuid','unmarked','missing','nullcred','nullframe'):
            with self.subTest(c=c):
                self.assertEqual({'rc':'0','allowed':'0','preserved':'1'},self.run_case(c))

    def test_both_callbacks_are_checked_and_removed(self):
        s=self.source
        self.assertIn('maplesu_avc_probe.pre_handler = maplesu_avc_pre',definition(s,'init_module'))
        self.assertIn('unregister_kprobe(&maplesu_avc_probe)',definition(s,'cleanup_module'))
        self.assertIn('maplesu_set_groups((void *)cred, (void *)maplesu_groups)',definition(s,'init_module'))
        self.assertNotIn('maplesu_ready = 1',definition(s,'maplesu_avc_pre'))

class ImageFactsTest(unittest.TestCase):
    def test_marker_offsets_and_entry_are_measured(self):
        cp=ROOT/'jailbreak-providers/root-loader/contracts/6.6.89-android15-8-g7e1f3c083cc6-abogki467167594-4k.json'
        c=json.loads(cp.read_text());image=(ROOT/c['imagePath']).read_bytes()
        symbols=builder.SymbolTable(ROOT/c['symbolsPath'])
        facts=builder.derive_l3_subject_facts(image,symbols)
        expected = {'MAPLESU_TASK_CRED_OFF':2080,'MAPLESU_CRED_UID_OFF':8,
                    'MAPLESU_CRED_EUID_OFF':24,'MAPLESU_CRED_GROUPS_OFF':160,
                    'MAPLESU_GROUP_USAGE_OFF':0}
        self.assertEqual(expected,{key:facts['defines'][key] for key in expected})
        self.assertEqual('avc_denied',facts['symbol'])
        bad=bytearray(image);offset=symbols.address('avc_denied')
        bad[offset:offset+4]=bytes.fromhex('fd7bbfa9')
        with self.assertRaises(builder.GateFailure):
            builder.derive_l3_subject_facts(bytes(bad),symbols)

class ReusableCredTest(unittest.TestCase):
    def test_more_than_64_requests_keep_a_pool_reference(self):
        cc = host_compiler()
        self.assertIsNotNone(cc)
        body = definition(SOURCE.read_text(encoding="utf-8"), "maplesu_pool_take")
        with tempfile.TemporaryDirectory() as tmp:
            base=Path(tmp)
            for size in (4,8):
                header = """
#include <stdint.h>
typedef unsigned int u32;
typedef uint64_t u64;
typedef uintptr_t uptr;
#define MAPLESU_CRED_USAGE_OFF 0
#define MAPLESU_CRED_USAGE_SIZE %d
static u32 maplesu_pool_count=3, maplesu_pool_cursor;
static uptr maplesu_pool[64];
""" % size
                main = """
int main(void) {
 uint64_t refs[3]={1,1,1};
 for(int i=0;i<3;i++)maplesu_pool[i]=(uptr)&refs[i];
 for(int i=0;i<1024;i++){
  uptr p=maplesu_pool_take();
  if(!p || *(uint64_t *)p!=2)return 1;
  --*(uint64_t *)p;
 }
 if(maplesu_pool_count!=3 || refs[0]!=1 || refs[1]!=1 || refs[2]!=1)return 2;
 maplesu_pool_count=0;
 return maplesu_pool_take()!=0;
}
"""
                path=base/'pool.c';exe=base/('pool.exe' if os.name=='nt' else 'pool')
                path.write_text(header+body+main,encoding='utf-8')
                result=subprocess.run([str(cc),'-std=c11',str(path),'-o',str(exe)],capture_output=True,text=True)
                self.assertEqual(0,result.returncode,result.stderr)
                self.assertEqual(0,subprocess.run([str(exe)]).returncode)

if __name__=='__main__':unittest.main()
