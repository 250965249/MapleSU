"""The real SU gate must remove the execution child's inherited syscall filter.

Host harness only: does not prove publication or app execution on a device.
"""
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


class SeccompGateTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cc = host_compiler()
        if cc is None:
            raise AssertionError('host compiler missing')
        cls.tmp = tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls.tmp.cleanup)
        base = Path(cls.tmp.name)
        cls.binary = base / ('seccomp.exe' if os.name == 'nt' else 'seccomp')
        source_path = Path(os.environ.get('MAPLESU_L3_TEST_SOURCE',
                          ROOT / 'jailbreak-providers/root-loader/module/maplesu_l3.c'))
        source = source_path.read_text(encoding='utf-8')
        header = r"""
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
typedef unsigned char u8;
typedef unsigned int u32;
typedef uint64_t u64;
typedef uintptr_t uptr;
struct kprobe;
struct pt_regs;
struct maplesu_pt_regs { u64 regs[31]; u64 sp, pc, pstate; };
struct task { u64 flags; u32 mode, count; uptr filter, cred; };
struct cred { u32 uid, euid; uptr groups; };
#define MAPLESU_NULL ((void *)0)
#define MAPLESU_KERNEL_VA_MIN 1
#define MAPLESU_TASK_CRED_OFF offsetof(struct task,cred)
#define MAPLESU_CRED_UID_OFF offsetof(struct cred,uid)
#define MAPLESU_CRED_EUID_OFF offsetof(struct cred,euid)
#define MAPLESU_CRED_GROUPS_OFF offsetof(struct cred,groups)
#define MAPLESU_TASK_SECCOMP_MODE_OFF offsetof(struct task,mode)
#define MAPLESU_TASK_THREAD_FLAGS_OFF offsetof(struct task,flags)
#define MAPLESU_TIF_SECCOMP_MASK (1ULL << 11)
#define MAPLESU_TAG ""
#define MAPLESU_L3_OPTION 4u
#define MAPLESU_L3_OP_ARM 0u
#define MAPLESU_L3_OP_SU 1u
#define MAPLESU_L3_OWNER_MIN 10000u
#define MAPLESU_L3_OWNER_MAX 100000u
#define MAPLESU_EPERM 1
#define MAPLESU_ENOMEM 12
#define MSU_POLICY_HOOK_OP 101u
#define MSU_POLICY_HOOK_TAG_LO 1u
#define MSU_POLICY_HOOK_TAG_HI 2u
#define MSU_STATUS_OP 102u
#define MSU_STATUS_TAG_LO 3u
#define MSU_STATUS_TAG_HI 4u
#define MAPLESU_L3_MAGIC(a,b) (((u32)(a)|(u32)(b))!=0)
#define MAPLESU_L3_TOKEN(a,b) (((u64)(b)<<32)|((u64)(a)&0xffffffffu))
static u32 maplesu_armed=1,maplesu_ready=1,maplesu_owner_uid=10155;
static u32 maplesu_pool_count=64,maplesu_arm_denied,maplesu_su_denied;
static u64 maplesu_token=0x123456789abcdef0ULL;
static uptr maplesu_groups=42,pool_cred;
static struct task child;
static struct { u8 enforcing; } state;
static void *maplesu_status_control(uptr p) { (void)p; return NULL; }
static typeof(state) *maplesu_selinux=&state;
static uptr maplesu_current_task(void) { return (uptr)&child; }
static u32 maplesu_caller_uid(const struct maplesu_pt_regs *f) { (void)f; return ((struct cred *)child.cred)->uid; }
static uptr maplesu_pool_take(void) { return pool_cred; }
static void maplesu_handover(uptr p) { child.cred=p; }
static int maplesu_deny(u32 *s,u32 o,int e,u32 u) { (void)s;(void)o;(void)e;(void)u;return 0; }
static int _printk(const char *f,...) { (void)f;return 0; }
"""
        main = r"""
int main(int argc,char **argv) {
 const char *c=argc>1?argv[1]:"grant";
 struct cred app={10155,10155,7},root={0,0,42};
 struct maplesu_pt_regs args={0},frame={0},original;
 child=(struct task){(1ULL<<3)|(1ULL<<11)|(1ULL<<35),2,3,0x12340,(uptr)&app};
 pool_cred=(uptr)&root;
 args.regs[0]=MAPLESU_L3_OPTION;args.regs[1]=MAPLESU_L3_OP_SU;
 args.regs[2]=(u32)maplesu_token;args.regs[3]=(u32)(maplesu_token>>32);
 frame.regs[0]=(uptr)&args;original=frame;
 if(!strcmp(c,"unarmed"))maplesu_armed=0;
 if(!strcmp(c,"unready"))maplesu_ready=0;
 if(!strcmp(c,"token"))args.regs[2]^=1;
 if(!strcmp(c,"owner"))app.uid++;
 if(!strcmp(c,"empty"))pool_cred=0;
 if(!strcmp(c,"native"))args.regs[2]=args.regs[3]=0;
 if(!strcmp(c,"option"))args.regs[0]=5;
 int rc=maplesu_l3_pre(NULL,(struct pt_regs *)&frame);
 printf("root=%d mode=%u filtered=%d refs=%d preserved=%d rc=%d\n",
  child.cred==(uptr)&root,child.mode,!!(child.flags&(1ULL<<11)),
  child.count==3&&child.filter==0x12340,
  (child.flags&~(1ULL<<11))==((1ULL<<3)|(1ULL<<35))&&!memcmp(&frame,&original,sizeof(frame)),rc);
 return 0;
}
"""
        names = ('maplesu_root_subject', 'maplesu_root_seccomp_disable', 'maplesu_l3_pre')
        body = '\n'.join(part for name in names if (part := definition(source, name)) is not None)
        path = base / 'seccomp.c'
        path.write_text(header + body + main, encoding='utf-8')
        result = subprocess.run([str(cc), '-std=gnu11', str(path), '-o', str(cls.binary)], capture_output=True, text=True)
        if result.returncode:
            raise AssertionError(result.stderr)

    def run_case(self, case):
        result = subprocess.run([str(self.binary), case], capture_output=True, text=True, check=True)
        return dict(p.split('=') for p in result.stdout.split())

    def test_root_handover_also_removes_inherited_syscall_restriction(self):
        self.assertEqual({'root':'1','mode':'0','filtered':'0','refs':'1','preserved':'1','rc':'0'}, self.run_case('grant'))

    def test_denied_or_unrelated_calls_preserve_app_filter(self):
        expected = {'root':'0','mode':'2','filtered':'1','refs':'1','preserved':'1','rc':'0'}
        for case in ('unarmed','unready','token','owner','empty','native','option'):
            with self.subTest(case=case):
                self.assertEqual(expected, self.run_case(case))


class SeccompImageFactsTest(unittest.TestCase):
    def test_all_shipped_kmis_measure_mode_and_syscall_flag(self):
        contracts = ROOT / 'jailbreak-providers/root-loader/contracts'
        offsets = {'5.10':0x848,'5.15':0x860,'6.1':0x900,'6.6':0x8e8,'6.12':0x9c8,'6.18':0x9d0}
        for path in sorted(contracts.glob('*.json')):
            with self.subTest(contract=path.name):
                contract = json.loads(path.read_text())
                image = (ROOT / contract['imagePath']).read_bytes()
                symbols = builder.SymbolTable(ROOT / contract['symbolsPath'])
                facts = builder.derive_l3_seccomp_facts(image, symbols)
                family = '.'.join(contract['kernelRelease'].split('.')[:2])
                self.assertEqual({'MAPLESU_TASK_SECCOMP_MODE_OFF':offsets[family],
                                  'MAPLESU_TASK_THREAD_FLAGS_OFF':0,
                                  'MAPLESU_TIF_SECCOMP_MASK':1<<11}, facts['defines'])
                if family != '5.10':
                    btf = builder.Btf(image)
                    mode = btf.member(btf.struct('task_struct'), 'seccomp')['byte'] + btf.member(btf.struct('seccomp'), 'mode')['byte']
                    self.assertEqual(mode, facts['defines']['MAPLESU_TASK_SECCOMP_MODE_OFF'])
                bad = bytearray(image)
                branch = facts['traceBranch']
                bad[branch:branch+4] = bytes.fromhex('1f2003d5')
                with self.assertRaises(builder.GateFailure):
                    builder.derive_l3_seccomp_facts(bytes(bad), symbols)


if __name__ == '__main__':
    unittest.main()
