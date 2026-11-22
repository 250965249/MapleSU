"""Regression for the real stock-device failure: final record open gets EACCES.

The C harness extracts the production writer and simulates restored enforcement:
path opens are denied, while the root worker owns a descriptor opened in its window.
"""
import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from test_l3_arm import definition, host_compiler

SOURCE = Path(__file__).resolve().parents[1] / "adapter" / "bootstrap.c"

class FinalRecordTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.text = SOURCE.read_text(encoding="utf-8")
        cc = host_compiler()
        if cc is None:
            raise unittest.SkipTest("host compiler missing")
        cls.scratch = tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls.scratch.cleanup)
        base = Path(cls.scratch.name)
        cls.binary = base / ("final.exe" if os.name == "nt" else "final")
        body = definition(cls.text, "attest_write_final")
        source = r'''
#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <errno.h>
#include <stdlib.h>
#define MAPLESU_HOOK_JSON_MAX 1536
#define MAPLESU_HOOK_ATTEST_SCHEMA "maplesu.hook.attest.v1"
#define MAPLESU_HOOK_DAEMON_DOC "fixture.json"
#define MAPLESU_L3_GATE_ARMED "ARMED"
#define MAPLESU_L3_GATE_UNAVAILABLE "UNAVAILABLE"
#define O_WRONLY 1
#define O_CREAT 2
#define O_TRUNC 4
#define O_CLOEXEC 8
#define SEEK_SET 0
struct attest_state { int record_fd; char su_token[17], su_reason[32], domain[96], boot_id[96], attempt[96], socket_path[128]; long starttime; };
static int opens, writes, success, short_write, truncate_denied;
static char captured[1536];
static int open(const char *p,int f,...) { ++opens; errno=EACCES; return -1; }
static int close(int fd) { return 0; }
static int fchmod(int fd,int mode) { return 0; }
static int ftruncate(int fd,long size) { if(truncate_denied) { errno=EACCES; return -1; } return fd==9 ? 0 : -1; }
static long lseek(int fd,long pos,int how) { return fd==9 ? 0 : -1; }
static int fsync(int fd) { return fd==9 ? 0 : -1; }
static int getpid(void) { return 42; }
static int getuid(void) { return 0; }
static long write(int fd,const void *body,size_t length) { if(fd!=9)return -1; ++writes; memcpy(captured,body,length); return short_write ? (long)length-1 : (long)length; }
static void log_line(const char *format,...) { if(strstr(format,"attest final enforcing=")) ++success; }
static void hook_l3_su_json(char *out,size_t size,const char *gate,const char *token,const char *reason) { snprintf(out,size,"\"suGate\":\"%s\"",gate); }
'''
        main = r'''
int main(int argc,char **argv) {
 struct attest_state state={0}; state.record_fd=9; strcpy(state.domain,"u:r:kernel:s0");
 strcpy(state.attempt,"attempt"); strcpy(state.boot_id,"boot");
 int enforcing=1;
 if(argc>1 && !strcmp(argv[1],"truncate-denied")) truncate_denied=1;
 if(argc>1 && !strcmp(argv[1],"missing")) state.record_fd=-1;
 if(argc>1 && !strcmp(argv[1],"short")) short_write=1;
 if(argc>1 && !strcmp(argv[1],"open-window")) enforcing=0;
 attest_write_final(&state,enforcing);
 printf("opens=%d writes=%d success=%d final=%d\n",opens,writes,success,strstr(captured,"\"enforcingFinal\":1")!=NULL);
 return 0;
}
'''
        path=base/"final.c"
        path.write_text(source+"\n"+body+"\n"+main,encoding="utf-8")
        built=subprocess.run([str(cc),"-std=c11",str(path),"-o",str(cls.binary)],capture_output=True,text=True)
        if built.returncode:
            raise AssertionError(built.stderr)

    def run_case(self,case=""):
        result=subprocess.run([str(self.binary),case],capture_output=True,text=True,check=True)
        return dict(pair.split("=") for pair in result.stdout.strip().split())

    def test_restored_worker_writes_using_inherited_descriptor(self):
        self.assertEqual({"opens":"0","writes":"1","success":"1","final":"1"},self.run_case())

    def test_restored_worker_does_not_need_inode_write_permission_again(self):
        self.assertEqual({"opens":"0","writes":"1","success":"1","final":"1"},
                         self.run_case("truncate-denied"))

    def test_missing_descriptor_never_reports_success(self):
        result=self.run_case("missing")
        self.assertEqual("0",result["opens"])
        self.assertEqual("0",result["writes"])
        self.assertEqual("0",result["success"])

    def test_short_write_never_reports_success(self):
        self.assertEqual("0",self.run_case("short")["success"])

    def test_open_window_never_publishes_final_success(self):
        self.assertEqual("0",self.run_case("open-window")["writes"])

    def test_helper_opens_before_fork_and_passes_both_descriptors(self):
        daemon=definition(self.text,"hook_daemon")
        self.assertLess(daemon.index("attest_prepare_descriptors("),daemon.index("fork()"))
        for variable in ("MAPLESU_ATTEST_ENV_RECORD_FD","MAPLESU_ATTEST_ENV_ENFORCE_FD"):
            self.assertIn(variable,daemon)
            self.assertIn(variable,definition(self.text,"attest_main"))