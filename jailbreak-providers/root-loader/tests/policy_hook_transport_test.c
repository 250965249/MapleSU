/* SPDX-License-Identifier: GPL-3.0-only */
/* Linux primitives form the fixture boundary. Drive the proc ioctl ABI exactly
 * as a root client does, including executable publication and failed copies. */
#define _GNU_SOURCE
#include <assert.h>
#include <errno.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <unistd.h>
#include "../policy_hook_abi.h"
#include "../module/policy_hook_dispatch.h"

typedef unsigned long long u64;
extern int init_module(void);
extern void cleanup_module(void);
struct file;
static long (*control)(struct file *, unsigned int, unsigned long);
#ifdef MAPLESU_POLICY_HOOK_EMBEDDED
extern int msu_policy_embedded_init(unsigned long (*)(const char *), int (*)(void));
extern int msu_policy_embedded_retain(void);
extern void msu_policy_embedded_cleanup(void);
extern long msu_policy_ioctl(struct file *, unsigned int, unsigned long);
#endif
char __this_module[16], msu_policy_original_return[4];
static unsigned uid, euid, registrations, unregistrations, fail_registration, module_refs;
static unsigned marked=1;
static unsigned prepare_calls, transition_calls, transition_enabled, copy_fail, allocations;
static void *registered[MSU_POLICY_HOOK_COUNT];
static int call_result, fault_on_enable;
static unsigned write_calls, writer_active, writer_marks;
static long native_result = 32;
static void *allocated;
static size_t allocated_bytes;
static pthread_mutex_t mutex=PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t condition=PTHREAD_COND_INITIALIZER;
static int pause_prepare, prepare_started;
static void *lookup(const char *);
#ifdef MAPLESU_POLICY_HOOK_EMBEDDED
static unsigned long embedded_lookup(const char *name) { return (unsigned long)lookup(name); }
static int embedded_subject(void) { return marked; }
int init_module(void) {
    control=msu_policy_ioctl;
    return msu_policy_embedded_init(embedded_lookup,embedded_subject);
}
void cleanup_module(void) { msu_policy_embedded_cleanup(); }
#endif
static long fake_uid(const void *x) { (void)x; return uid; }
static long fake_euid(const void *x) { (void)x; return euid; }
static long fake_copy(void *to,const void *from,unsigned long size)
{
    if (!to || !from || (copy_fail && !--copy_fail)) { copy_fail=0; return -EFAULT; }
    memcpy(to,from,size); return 0;
}
static void *fake_alloc(unsigned long size)
{
    ++allocations;
    allocated=mmap(NULL,size,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
    assert(allocated!=MAP_FAILED); allocated_bytes=size; return allocated;
}
static void fake_free(void *p) { assert(!munmap(p,allocated_bytes)); allocated=NULL; }
static int fake_nx(unsigned long at,int pages) { return mprotect((void *)at,pages*4096,PROT_READ|PROT_WRITE); }
static int fake_ro(unsigned long at,int pages) { return mprotect((void *)at,pages*4096,PROT_READ); }
static int fake_rw(unsigned long at,int pages) { return mprotect((void *)at,pages*4096,PROT_READ|PROT_WRITE); }
static int fake_x(unsigned long at,int pages) { return mprotect((void *)at,pages*4096,PROT_READ|PROT_EXEC); }
static unsigned char fake_get(void *m) { assert(m==__this_module); ++module_refs; return 1; }
static void *fake_proc(const char *name,unsigned short mode,void *parent,const void *ops,void *data)
{
    assert(!strcmp(name,"maplesu_policy_hook") && mode==0600 && !parent && !data);
    control=*(void *const *)((const char *)ops+48); return (void *)1;
}
static void fake_remove(void *p) { assert(p==(void *)1); control=NULL; }
static u64 target(u64 a,u64 b,u64 c,u64 d,u64 e,u64 f)
{ (void)a;(void)b;(void)c;(void)d;(void)e;(void)f; return 77; }
int register_kprobe(void *probe)
{
    void **p=probe;
    if (p[6]) { assert(!strcmp(p[6],"kallsyms_lookup_name")); p[5]=(void *)lookup; return 0; }
    if (fail_registration && ++registrations==fail_registration) return -ENOMEM;
    if (!fail_registration) ++registrations;
    for (unsigned i=0;i<MSU_POLICY_HOOK_COUNT;++i) if (!registered[i]) { registered[i]=probe; return 0; }
    assert(0); return -1;
}
void unregister_kprobe(void *probe)
{
    void **p=probe;
    if (p[6]) return;
    ++unregistrations;
    for (unsigned i=0;i<MSU_POLICY_HOOK_COUNT;++i) if (registered[i]==probe) {registered[i]=NULL; return;}
    assert(0);
}
static int prepare(void)
{
    ++prepare_calls;
    pthread_mutex_lock(&mutex); prepare_started=1; pthread_cond_broadcast(&condition);
    while (pause_prepare) pthread_cond_wait(&condition,&mutex);
    pthread_mutex_unlock(&mutex); return call_result;
}
static int transition(unsigned enabled) {
    ++transition_calls; transition_enabled=enabled;
    if (enabled && fault_on_enable) msu_policy_backend_note_error(-EIO);
    return call_result;
}
static int mark_writer(unsigned phase) { assert(phase<=1 && writer_active==phase);writer_active=!phase;++writer_marks;return 0; }
static long fake_write(unsigned fd,const void *data,unsigned long count)
{ assert(fd==42 && data && count==32 && writer_active);++write_calls;return native_result; }
static u64 predicate(u64 op,u64 first,u64 second,u64 d,u64 e,u64 f)
{ (void)op;(void)first;(void)second;(void)d;(void)e;(void)f;return 1; }
u64 msu_policy_call_original(u64 fn,const u64 a[6])
{ return ((u64(*)(u64,u64,u64,u64,u64,u64))(uintptr_t)fn)(a[0],a[1],a[2],a[3],a[4],a[5]); }
static void *lookup(const char *name)
{
#define NAME(n,f) if (!strcmp(name,n)) return (void *)f
    NAME("__arm64_sys_getuid",fake_uid); NAME("__arm64_sys_geteuid",fake_euid);
    NAME("copy_from_user_nofault",fake_copy); NAME("copy_to_user_nofault",fake_copy);
    NAME("module_alloc",fake_alloc); NAME("module_memfree",fake_free);
    NAME("set_memory_nx",fake_nx); NAME("set_memory_rw",fake_rw);
    NAME("set_memory_ro",fake_ro); NAME("set_memory_x",fake_x);
    NAME("try_module_get",fake_get); NAME("proc_create_data",fake_proc); NAME("proc_remove",fake_remove);
    NAME("ksys_write",fake_write);
    if (!strncmp(name,"sel_",4) || !strcmp(name,"selinux_setprocattr") ||
        !strcmp(name,"sk_filter_trim_cap") || !strcmp(name,"commit_creds") ||
        !strcmp(name,"__skb_try_recv_datagram") || !strcmp(name,"copy_process") ||
        !strcmp(name,"selnl_notify_policyload")) return (void *)target;
    return NULL;
#undef NAME
}
static struct msu_policy_hook_request request(unsigned command)
{
    struct msu_policy_hook_request r={0}; r.version=MSU_POLICY_HOOK_VERSION; r.command=command; return r;
}
static int invoke(struct msu_policy_hook_request *r)
{ assert(control); long rc=control(NULL,MSU_POLICY_HOOK_IOCTL,(unsigned long)r); return rc ? (int)rc : r->status; }
static u64 symbol(const char *name)
{ struct msu_policy_hook_request r=request(MSU_PH_LOOKUP); strcpy(r.name,name); assert(!invoke(&r)); return r.result; }
static int protect(const char *name,u64 address,u64 pages)
{ struct msu_policy_hook_request r=request(MSU_PH_CALL); r.address=symbol(name); r.bytes=2; r.args[0]=address;r.args[1]=pages; return invoke(&r); }
static void stub(unsigned char *at,void *to)
{
    /* Host-only native ABI veneer; never included in a device artifact. */
    const unsigned char begin[]={0x48,0xb8}, end[]={0xff,0xe0};
    memcpy(at,begin,2); memcpy(at+2,&to,8); memcpy(at+10,end,2);
}
static void *prepare_thread(void *packet) { assert(!invoke(packet)); return NULL; }
int main(void)
{
    _Static_assert(sizeof(struct msu_policy_hook_request)==248,"fixed ioctl ABI");
    assert(init_module()==0);
    struct msu_policy_hook_request r=request(MSU_PH_QUERY);
    uid=10001; assert(invoke(&r)==-EPERM); uid=0; euid=10001; assert(invoke(&r)==-EPERM);euid=0;
#ifdef MAPLESU_POLICY_HOOK_EMBEDDED
    marked=0;assert(invoke(&r)==-EPERM);marked=1;
    assert(!msu_policy_embedded_retain());
    assert(!invoke(&r) && !r.pinned);
#else
    (void)marked;
#endif
    assert(!invoke(&r) && !r.prepared && !r.enabled && !r.installed);
    puts("PASS: live UID and EUID authorization; unused backend reports inactive");
    r.version=9; assert(invoke(&r)==-EINVAL); r=request(MSU_PH_QUERY); r.flags=1;assert(invoke(&r)==-EINVAL);
    r=request(MSU_PH_LOOKUP); strcpy(r.name,"arbitrary_kernel_write"); assert(invoke(&r)==-ENOENT);
    puts("PASS: unknown ABI and unlisted symbols never execute");
    r=request(MSU_PH_ALLOCATE);r.bytes=16384;assert(!invoke(&r)); u64 base=r.result;
    r=request(MSU_PH_ALLOCATE);r.bytes=4096;assert(invoke(&r)==-EALREADY);
    r=request(MSU_PH_WRITE);r.address=base+16384-4;r.bytes=8;r.data=(unsigned long)&base;
    assert(invoke(&r)==-EINVAL); r.address=UINT64_MAX-1;r.bytes=8;assert(invoke(&r)==-EINVAL);
    assert(protect("set_memory_rw",(u64)(uintptr_t)target,1)==-EINVAL);
    assert(protect("set_memory_ro",base-4096,1)==-EINVAL);
    assert(protect("set_memory_rw",base+16384,1)==-EINVAL);
    assert(protect("set_memory_ro",UINT64_MAX-4095,1)==-EINVAL);
    puts("PASS: allocation is bounded, not repeated, and overflowing writes are rejected");
    unsigned char code[384]={0}; stub(code,(void *)prepare);stub(code+64,(void *)transition);
    stub(code+128,(void *)predicate);stub(code+192,(void *)target);
    stub(code+256,(void *)mark_writer);
    r=request(MSU_PH_WRITE);r.address=base;r.bytes=sizeof code;r.data=(unsigned long)code;assert(!invoke(&r));
    unsigned char readback[384]; r.command=MSU_PH_READ;r.data=(unsigned long)readback;assert(!invoke(&r));
    assert(!memcmp(code,readback,sizeof code));
    assert(protect("set_memory_x",base,1)==-EPERM);
    assert(!protect("set_memory_ro",base,1) && !protect("set_memory_x",base,1));
    r.command=MSU_PH_WRITE;r.data=(unsigned long)code;assert(invoke(&r)==-EINVAL);
    assert(protect("set_memory_rw",base,1)==-EPERM);
    puts("PASS: payload readback is exact; writes to executable pages and W+X are blocked");
    const char *names[]={"sel_write_context","sel_write_access","selinux_setprocattr","sel_open_handle_status",
        "sel_read_handle_status","sel_mmap_handle_status","sk_filter_trim_cap","commit_creds","__skb_try_recv_datagram","copy_process",
        "selnl_notify_policyload","sel_write_load"};
    struct msu_policy_hook_dispatch bindings[MSU_POLICY_HOOK_COUNT];
    u64 addresses[MSU_POLICY_HOOK_COUNT];
    for(unsigned i=0;i<MSU_POLICY_HOOK_COUNT;++i) {
        addresses[i]=symbol(names[i]);
        bindings[i]=(struct msu_policy_hook_dispatch){addresses[i],base+128,base+192,base+4096,i,0};
    }
    r=request(MSU_PH_BIND);r.address=base;r.predicate=base+128;r.handler=base+64;
    r.activation=base+4096;r.bytes=sizeof bindings;r.data=(unsigned long)bindings;
    r.args[0]=base+256;
    assert(!invoke(&r));
    bindings[2].handler=base+8192;
    assert(invoke(&r)==-EINVAL);bindings[2].handler=base+192;
    puts("PASS: the complete resident entry contract is bound before preparation and rejects non-executable entries");
    pid_t releasing=fork();assert(releasing>=0);
    if(!releasing) {
        struct msu_policy_hook_request released=request(MSU_PH_RELEASE);released.address=base;
        assert(!invoke(&released));released=request(MSU_PH_QUERY);
        assert(!invoke(&released)&&!released.address&&!released.handler&&!released.predicate&&!released.result);
        _exit(0);
    }
    int release_status=0;assert(waitpid(releasing,&release_status,0)==releasing);
    assert(WIFEXITED(release_status)&&WEXITSTATUS(release_status)==0);
    puts("PASS: releasing an unprepared image clears every resident pointer before the next query");
    r=request(MSU_PH_CALL);r.address=base;r.bytes=0;pause_prepare=1;
    pthread_t worker;assert(!pthread_create(&worker,NULL,prepare_thread,&r));
    pthread_mutex_lock(&mutex);while(!prepare_started)pthread_cond_wait(&condition,&mutex);pthread_mutex_unlock(&mutex);
    struct msu_policy_hook_request q=request(MSU_PH_QUERY);assert(invoke(&q)==-EBUSY);
    pthread_mutex_lock(&mutex);pause_prepare=0;pthread_cond_broadcast(&condition);pthread_mutex_unlock(&mutex);
    pthread_join(worker,NULL);assert(r.prepared && r.pinned && prepare_calls==1 && module_refs==1);
    puts("PASS: preparation is process-context, pinned, and overlapping control returns busy");
    fail_registration=3;registrations=0;
    for(unsigned i=0;i<3;++i){r=request(MSU_PH_INSTALL);r.address=addresses[i];r.operation=i;r.predicate=base+128;
        r.handler=base+192;r.activation=base+4096;int rc=invoke(&r);assert(rc==(i==2?-ENOMEM:0));}
    assert(!r.installed && !r.enabled && unregistrations==2);
    puts("PASS: failed partial registration detaches all earlier probes and remains inactive");
    fail_registration=0;registrations=0;
    for(unsigned i=0;i<MSU_POLICY_HOOK_COUNT;++i){r=request(MSU_PH_INSTALL);r.address=addresses[i];r.operation=i;r.predicate=base+128;
        r.handler=base+192;r.activation=base+4096;assert(!invoke(&r));}
    r=request(MSU_PH_ACTIVATE);r.address=base+4096;r.result=1;r.handler=base+128;
    assert(invoke(&r)==-EINVAL && !r.enabled && !transition_calls);
    r.handler=base+64;assert(!invoke(&r) && r.enabled && r.installed==MSU_POLICY_HOOK_COUNT && transition_enabled==1 && transition_calls==1);
    puts("PASS: activation requires every query and fork hook and successful real transition callback");
    r=request(MSU_PH_POLICY_WRITE);r.args[0]=42;r.data=(unsigned long)code;r.bytes=32;
    assert(!invoke(&r) && r.result==32 && write_calls==1 && writer_marks==2 && !writer_active);
    native_result=-ENOSPC;
    r=request(MSU_PH_POLICY_WRITE);r.args[0]=42;r.data=(unsigned long)code;r.bytes=32;
    assert(!invoke(&r) && (long)r.result==-ENOSPC && write_calls==2 && writer_marks==4 && !writer_active);
    native_result=32;
    puts("PASS: module policy writes are synchronously marked; native errors and single-write semantics are preserved");
    pid_t degraded=fork();assert(degraded>=0);
    if(!degraded) {
        msu_policy_backend_note_error(-ENOMEM);
        struct msu_policy_hook_request pending=request(MSU_PH_QUERY);
        assert(!invoke(&pending) && !pending.enabled && (long)pending.args[1]==-ENOMEM && (long)pending.args[2]==-EINPROGRESS);
        msu_policy_backend_reconcile();
        struct msu_policy_hook_request observed=request(MSU_PH_QUERY);
        assert(!invoke(&observed) && !observed.enabled && (long)observed.args[1]==-ENOMEM && !observed.args[2]);
        observed=request(MSU_PH_ACTIVATE);observed.result=1;assert(invoke(&observed)==-ENOMEM);
        observed=request(MSU_PH_POLICY_WRITE);observed.args[0]=42;observed.data=(unsigned long)code;observed.bytes=32;
        assert(!invoke(&observed) && observed.result==32 && !writer_active);
        _exit(0);
    }
    int degraded_status=0;assert(waitpid(degraded,&degraded_status,0)==degraded && WIFEXITED(degraded_status) && !WEXITSTATUS(degraded_status));
    puts("PASS: runtime failure restores native mappings and remains visible without blocking subsequent module writes");
    unsigned long frame[34]={0};frame[30]=(unsigned long)msu_policy_original_return;
    int(*pre)(void *,void *)=*(void **)((char *)registered[0]+64);
    assert(pre(registered[0],frame)==0 && !frame[32]);
    frame[30]=0x1234;assert(pre(registered[0],frame)==1 && frame[32] && frame[30]==0x1234);
    puts("PASS: only the original-call return label bypasses redirection; native frame is preserved");
    copy_fail=1;r=request(MSU_PH_QUERY);assert(invoke(&r)==-EFAULT);assert(!invoke(&r) && r.enabled);
    puts("PASS: a user-copy fault is recoverable through the public query");
    r=request(MSU_PH_ACTIVATE);r.address=base+4096;r.handler=base+64;r.result=0;
    assert(!invoke(&r) && !r.enabled && !r.installed && transition_enabled==0 && transition_calls==2);
    puts("PASS: disabling reconciles mappings before detaching; ordinary path has no installed probes");
    /* A new client has no payload addresses or transition callback in memory.
     * Recover only from the resident public ABI, without allocating again. */
    q=request(MSU_PH_QUERY);assert(!invoke(&q));
    assert(q.prepared && !q.enabled && !q.installed);
    assert(q.address==base+4096 && q.handler==base+64);
    r=request(MSU_PH_ACTIVATE);r.result=1;
    assert(!invoke(&r) && r.enabled && r.installed==MSU_POLICY_HOOK_COUNT && allocations==1);
    assert(prepare_calls==1 && module_refs==1 && transition_calls==3);
    puts("PASS: a new client re-enables the resident snapshot without allocation or preparation replay");
    r=request(MSU_PH_ACTIVATE);r.result=0;
    assert(!invoke(&r) && !r.enabled && !r.installed);
    fail_registration=4;registrations=0;
    r=request(MSU_PH_ACTIVATE);r.result=1;
    assert(invoke(&r)==-ENOMEM && !r.enabled && !r.installed);
    assert(transition_calls==4);
    fail_registration=0;registrations=0;
    assert(!invoke(&r) && r.enabled && r.installed==MSU_POLICY_HOOK_COUNT && transition_calls==5);
    puts("PASS: re-registration failure is inactive, fully detached, and retryable");
    call_result=-ENOMEM;r=request(MSU_PH_ACTIVATE);r.result=0;
    assert(invoke(&r)==-ENOMEM && !r.enabled && r.installed==MSU_POLICY_HOOK_COUNT);
    call_result=0;assert(!invoke(&r) && !r.installed && !r.enabled);
    puts("PASS: failed reconciliation keeps resident descriptors until a successful recovery");
    pid_t raced=fork();assert(raced>=0);
    if(!raced) {
        struct msu_policy_hook_request disabled=request(MSU_PH_CANCEL);assert(!invoke(&disabled));
        fault_on_enable=1;
        struct msu_policy_hook_request enabling=request(MSU_PH_ACTIVATE);enabling.result=1;
        assert(invoke(&enabling)==-EIO && !enabling.enabled && !enabling.installed && !transition_enabled);
        struct msu_policy_hook_request after=request(MSU_PH_QUERY);
        assert(!invoke(&after) && (long)after.args[1]==-EIO && !after.args[2]);
        _exit(0);
    }
    int raced_status=0;assert(waitpid(raced,&raced_status,0)==raced && WIFEXITED(raced_status) && !WEXITSTATUS(raced_status));
    puts("PASS: runtime failure during activation never republishes enabled and restores mappings before detaching");
    r=request(MSU_PH_ACTIVATE);r.result=1;copy_fail=2;
    assert(invoke(&r)==-EFAULT);
    q=request(MSU_PH_QUERY);assert(!invoke(&q)&&q.enabled&&q.installed==MSU_POLICY_HOOK_COUNT);
    assert(allocations==1&&prepare_calls==1);
    r=request(MSU_PH_CANCEL);assert(!invoke(&r)&&r.command==MSU_PH_CANCEL&&!r.enabled&&!r.installed);
    assert(!invoke(&r)&&!r.enabled&&!r.installed);
    puts("PASS: a lost activation acknowledgement is recovered by query and cancellation is idempotent");
    return 0;
}

#ifdef MAPLESU_POLICY_HOOK_TRANSPORT_LIBRARY
long policy_test_ioctl(void *r) { return control(NULL,MSU_POLICY_HOOK_IOCTL,(unsigned long)r); }
void policy_test_fault(int restore) { msu_policy_backend_note_error(-ENOMEM);call_result=restore;msu_policy_backend_reconcile();call_result=0; }
void policy_test_native_result(long value) { native_result=value; }
void policy_test_copy_fault(unsigned nth) { copy_fail=nth; }
unsigned policy_test_write_calls(void) { return write_calls; }
#endif
