"""Run the actual optional listener; syscall/kprobe/credential calls are host fixtures."""
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "jailbreak-providers/dirtyfrag/tests"))
from test_l3_arm import host_compiler

HARNESS = r'''
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
typedef unsigned char u8;
typedef unsigned int u32;
typedef uint64_t u64;
typedef uintptr_t uptr;
#define MAPLESU_L3_POLICY_BRIDGE 1
#define MAPLESU_LEGACY_CFI 1
#define MAPLESU_L3_PRE_KCFI_ID 0x12345678
#define MAPLESU_NOCFI
#define MAPLESU_NULL ((void *)0)
#define MAPLESU_KERNEL_VA_MIN 4096
#define MAPLESU_TAG "test: "
#define CHECK(x) do { if (!(x)) { fprintf(stderr,"line=%d: %s\n",__LINE__,#x); exit(1); } } while(0)
struct kprobe;struct pt_regs;struct file;
struct maplesu_pt_regs { u64 regs[31],sp,pc,pstate; };
struct maplesu_l3_probe { uptr addr;const char *symbol_name;int (*pre_handler)(struct kprobe *,struct pt_regs *); };
static u32 entry[4]={0xd503233f},uid,euid,marked=1,in_probe,init_calls,pins,operations,removed;
static int pin_error,register_error,init_error,offset;
static int (*authorized)(void);
static uptr maplesu_current_task(void) { return 1; }
static int maplesu_root_subject(uptr task) { return task==1 && !uid && !euid && marked; }
static uptr maplesu_sym(const char *name) { CHECK(!strcmp(name,"__arm64_sys_prctl"));return (uptr)entry; }
static int register_kprobe(struct maplesu_l3_probe *p) {
    CHECK(!in_probe);p->addr=(uptr)entry+offset;return register_error;
}
static void unregister_kprobe(struct maplesu_l3_probe *p) { (void)p;removed++; }
static void _printk(const char *s,...) { (void)s; }
void __cfi_check(u64 type,void *target,void *diag) {
    CHECK(type==MAPLESU_L3_PRE_KCFI_ID && target && !diag);
}
int msu_policy_pre(struct kprobe *p,struct pt_regs *r) { (void)p;(void)r;return 0; }
int msu_policy_embedded_init(uptr (*lookup)(const char *),int (*subject)(void)) {
    CHECK(!in_probe && lookup==maplesu_sym);authorized=subject;init_calls++;return init_error;
}
int msu_policy_embedded_retain(void) { CHECK(in_probe && authorized());pins++;return pin_error; }
void msu_policy_embedded_cleanup(void) { CHECK(!in_probe); }
long msu_policy_ioctl(struct file *file,unsigned int request,unsigned long user) {
    CHECK(!in_probe && !file && request==0xc0f84d51u && user==1234 && authorized());operations++;return 17;
}
#include "maplesu_policy_control.h"
int main(int argc,char **argv) {
    const char *name=argc>1?argv[1]:"query";
    struct maplesu_pt_regs args={0},frame={0};
    if (!strcmp(name,"init-failure")) init_error=-2;
    if (!strcmp(name,"registration-failure")) register_error=-12;
    if (!strcmp(name,"bad-offset")) offset=4;
    if (!strcmp(name,"bti-offset")) { offset=4;entry[0]=0xd503245f; }
    maplesu_policy_init();
    CHECK(init_calls==1 && !operations && !pins);
    if(init_error || register_error || !strcmp(name,"bad-offset")) {
        CHECK(!maplesu_policy_available);return 0;
    }
    CHECK(maplesu_policy_available);
    args.regs[0]=4;args.regs[1]=MSU_POLICY_HOOK_OP;
    args.regs[2]=MSU_POLICY_HOOK_TAG_LO;args.regs[3]=MSU_POLICY_HOOK_TAG_HI;args.regs[4]=1234;
    frame.regs[0]=(uptr)&args;frame.regs[30]=0xabcdef;frame.sp=0x10000;frame.pc=0x1000;
    if (!strcmp(name,"uid")) uid=10000;
    if (!strcmp(name,"euid")) euid=10000;
    if (!strcmp(name,"unmarked")) marked=0;
    if (!strcmp(name,"native")) args.regs[1]=1;
    if (!strcmp(name,"wrong-tag")) args.regs[3]^=1;
    if (!strcmp(name,"pin-failure")) pin_error=-19;
    if (!strcmp(name,"invalid-frame")) frame.regs[0]=0;
    in_probe=1;
    int redirected=maplesu_policy_control_pre(NULL,(void *)&frame);
    in_probe=0;
    CHECK(!operations && frame.sp==0x10000 && frame.regs[30]==0xabcdef);
    if (!strcmp(name,"query") || !strcmp(name,"bti-offset")) {
        CHECK(redirected==1 && frame.pc==(uptr)maplesu_policy_control && pins==1);
        CHECK(maplesu_policy_control(&args)==17 && operations==1);
        marked=0;CHECK(maplesu_policy_control(&args)==-1 && operations==1);
    } else CHECK(!redirected && frame.pc==0x1000);
    maplesu_policy_cleanup();CHECK(removed==1 && !maplesu_policy_available);
    return 0;
}
'''


class ResidentPolicyControlTest(unittest.TestCase):
    def test_process_context_and_authenticated_entry(self):
        compiler = host_compiler()
        self.assertIsNotNone(compiler)
        with tempfile.TemporaryDirectory(prefix="maplesu-resident-policy-") as directory:
            source, executable = Path(directory) / "control.c", Path(directory) / "control.exe"
            source.write_text(HARNESS, encoding="utf-8")
            subprocess.run([compiler, "-std=c11", "-Wall", "-Wextra", "-Werror", "-I" + str(
                ROOT / "jailbreak-providers/root-loader/module"), source, "-o", executable], check=True)
            for case in ("query", "uid", "euid", "unmarked", "native", "wrong-tag", "invalid-frame",
                         "pin-failure", "registration-failure", "init-failure", "bad-offset", "bti-offset"):
                with self.subTest(case=case):
                    subprocess.run([executable, case], check=True, capture_output=True, text=True, timeout=10)


if __name__ == "__main__":
    unittest.main()
