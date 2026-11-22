// Drive the real C++ adapter through the real proc ioctl control implementation.
// Only OS file discovery and native kernel primitives are supplied by fixtures.
#include "kernel_payload_hook.h"
#include <cassert>
#include <cerrno>
#include <cstdarg>
#include <cstdio>
#include <cstdlib>
#include <fcntl.h>
#include <cstring>
#include <stdexcept>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
using namespace maplesu::module_policy;
int policy_hook_loader(int,char**);
extern "C" {
int policy_test_transport_regression();
long policy_test_ioctl(void*);
void policy_test_fault(int);
void policy_test_native_result(long);
void policy_test_copy_fault(unsigned);
unsigned policy_test_write_calls();
}
extern "C" int __real_open(const char*,int,...);
extern "C" int __real_close(int);
extern "C" int __real_fstat(int,struct stat*);
extern "C" int __real_lstat(const char*,struct stat*);
static bool present=true, old_protocol=false;
static bool resident=false;
static unsigned resident_calls=0, lost_resident_reply=0;
static unsigned backend_accesses=0;
static unsigned notes_accesses=0;
extern "C" int __wrap_open(const char *path,int flags,...) {
    if (!strcmp(path,"/sys/kernel/notes")) { ++notes_accesses;errno=EACCES;return -1; }
    if (strcmp(path,MSU_POLICY_HOOK_PATH)) {
        va_list args;va_start(args,flags);int mode=(flags&O_CREAT)?va_arg(args,int):0;va_end(args);
        return __real_open(path,flags,mode);
    }
    ++backend_accesses;
    if (!present || resident) { errno=ENOENT;return -1; }
    return 9876;
}
extern "C" int __wrap_close(int fd) { return fd==9876?0:__real_close(fd); }
extern "C" int __wrap_fstat(int fd,struct stat *st) {
    if(fd!=9876) return __real_fstat(fd,st);
    *st={};st->st_mode=S_IFREG|0600;return 0;
}
extern "C" int __wrap_lstat(const char *path,struct stat *st) {
    if(strcmp(path,MSU_POLICY_HOOK_PATH)) return __real_lstat(path,st);
    ++backend_accesses;
    if (!present) { errno=ENOENT;return -1; }
    *st={};st->st_mode=S_IFREG|0600;return 0;
}
extern "C" int __wrap_ioctl(int fd,unsigned long command,...) {
    assert(fd==9876 && command==MSU_POLICY_HOOK_IOCTL);
    ++backend_accesses;
    va_list args;va_start(args,command);auto *r=va_arg(args,msu_policy_hook_request*);va_end(args);
    if (old_protocol) { r->version=1;return 0; }
    auto rc=policy_test_ioctl(r);
    if (rc<0) { errno=-rc;return -1; }
    return static_cast<int>(rc);
}
extern "C" int __wrap_prctl(int option,...) {
    ++resident_calls;
    va_list args;va_start(args,option);
    auto operation=va_arg(args,unsigned long),lo=va_arg(args,unsigned long),hi=va_arg(args,unsigned long);
    auto *r=va_arg(args,msu_policy_hook_request*);va_end(args);
    assert(option==4 && operation==3 && lo==0x504f4c59u && hi==0x4d535532u);
    if (!resident || !present) { errno=EINVAL;return -1; }
    if (old_protocol) { r->version=1;return 0; }
    auto rc=policy_test_ioctl(r);
    if (lost_resident_reply && r->command!=MSU_PH_QUERY) {
        --lost_resident_reply;errno=EINTR;return -1;
    }
    if (rc<0) { errno=-rc;return -1; }
    return static_cast<int>(rc);
}
namespace maplesu::module_policy {
unsigned prepare_policy_view_with(PolicyKernelIo&,bool,bool) {
    throw std::runtime_error("unexpected second allocation in resident recovery");
}
}
static State hidden() {
    State result;result.requested=Mode::Hide;result.effective=BootState{Mode::Hide,3,"00000000-0000-0000-0000-000000000001"};
    return result;
}
int main(int argc,char**) {
    resident=argc>1;
    assert(!policy_test_transport_regression());
    assert(hook_policy_backend_present());
    if (resident) {
        char tool[]="maplesu-policy",operation[]="hook-info";
        char *arguments[]={tool,operation};
        assert(!policy_hook_loader(2,arguments));
        assert(!notes_accesses && !backend_accesses);
        puts("PASS adapter: resident hook-info never opens kernel notes or the absent proc sidecar");
    }
    assert(prepare_hook_kernel_policy(Mode::Hide,false)==3);
    auto observed=observe_hook_policy_state(hidden(),true);
    assert(observed.effective && observed.effective->mode==Mode::Hide && !observed.hide_failed);
    puts("PASS adapter: actual proc ioctl resumes and confirms the resident backend");
    present=false;observed=observe_hook_policy_state(hidden(),true);
    assert(!observed.effective && observed.hide_failed);
    present=true;old_protocol=true;observed=observe_hook_policy_state(hidden(),true);
    assert(!observed.effective && observed.hide_failed);
    old_protocol=false;
    puts("PASS adapter: missing or old backend cannot leave stale effective Hide");
    // config reads also report SDK-owned state; the temporary backend may be absent.
    char directory[]="/tmp/maplesu-policy-owner-XXXXXX";
    assert(mkdtemp(directory));
    {
        Store sdk(open(directory,O_RDONLY|O_DIRECTORY|O_CLOEXEC));
        sdk.publish(*hidden().effective);
        auto boot=hidden().effective->boot_id;
        auto probes=backend_accesses,prctls=resident_calls;
        present=false;
        observed=observe_hook_policy_state(sdk.read(boot),sdk.owns_hook(boot));
        assert(observed.effective && observed.effective->mode==Mode::Hide && !observed.hide_failed);
        present=true;old_protocol=true;
        observed=observe_hook_policy_state(sdk.read(boot),sdk.owns_hook(boot));
        assert(observed.effective && observed.effective->capabilities==3 && !observed.hide_failed);
        assert(backend_accesses==probes);
        assert(resident_calls==prctls);
        old_protocol=false;
    }
    assert(!unlink((std::string(directory)+"/effective").c_str()));
    assert(!unlink((std::string(directory)+"/.lock").c_str()));
    assert(!rmdir(directory));
    puts("PASS adapter: SDK-owned status is independent of temporary backend availability");
    HookKernelIo io;
    char bytes[32]={};unsigned writes=policy_test_write_calls();
    policy_test_copy_fault(2);bool lost=false;
    try { io.write_policy(42,bytes,sizeof bytes); } catch(const std::runtime_error&) {lost=true;}
    assert(lost && policy_test_write_calls()==writes+1 && io.query().enabled);
    if (resident) {
        writes=policy_test_write_calls();lost_resident_reply=1;lost=false;
        try { io.write_policy(42,bytes,sizeof bytes); } catch(const std::runtime_error&) {lost=true;}
        assert(lost && !lost_resident_reply && policy_test_write_calls()==writes+1);
        puts("PASS adapter: interrupted resident write is never replayed through proc or another Root");
    }
    puts("PASS adapter: lost write acknowledgement reports uncertainty without replaying the native write");
    pid_t child=fork();assert(child>=0);
    if(!child) {
        policy_test_fault(-ENOMEM);auto state=observe_hook_policy_state(hidden(),true);
        assert(!state.effective && state.hide_failed);
        assert(prepare_hook_kernel_policy(Mode::Load,false)==1);
        state=observe_hook_policy_state(hidden(),true);
        assert(state.effective && state.effective->mode==Mode::Load && state.hide_failed);
        assert(io.write_policy(42,bytes,sizeof bytes)==sizeof bytes);
        _exit(0);
    }
    int status=0;assert(waitpid(child,&status,0)==child && WIFEXITED(status) && !WEXITSTATUS(status));
    puts("PASS adapter: failed restoration stays unconfirmed, retry restores Load, evidence failure never invalidates a committed write");
    policy_test_native_result(-ENOSPC);errno=0;
    assert(io.write_policy(42,bytes,sizeof bytes)==-1 && errno==ENOSPC);
    policy_test_native_result(32);
    assert(prepare_hook_kernel_policy(Mode::Block,false)==1);
    assert(!io.query().enabled && !io.query().installed);
    puts("PASS adapter: native errno is preserved and disable readback leaves no probes");
}
