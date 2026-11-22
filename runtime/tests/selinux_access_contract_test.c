/* Execute the production access handler with kernel permission/SID/AV seams. */
#include <assert.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
typedef uint32_t u32;
typedef uint16_t u16;
struct file { unsigned unused; };
struct av_decision { u32 allowed, auditallow, auditdeny, seqno, flags; };
#define GFP_KERNEL 0
#define SECINITSID_SECURITY 2
#define SECCLASS_SECURITY 1
#define SECURITY__COMPUTE_AV 4
#define SIMPLE_TRANSACTION_LIMIT 4096
#define scnprintf snprintf
#define kfree free
static unsigned generation, fail_allocation, allocations, computations;
static int permission_error, context_error;
static void *kzalloc(size_t size, int flags)
{
    (void)flags;
    return ++allocations==fail_allocation ? NULL : calloc(1,size);
}
static u32 pv_current_sid(void) { return 7; }
static int maplesu_avc_has_perm(u32 sid, u32 target, u16 cls, u32 permission, void *audit)
{
    assert(sid==7 && target==2 && cls==1 && permission==4 && !audit);
    return permission_error;
}
static int maplesu_context_to_sid(const char *text, u32 length, u32 *sid, u32 *live, int *rc)
{
    assert(length==strlen(text) && !live && !rc);
    *sid=!strcmp(text,"source") ? 11 : 12;
    return context_error;
}
static void compute_view_av(u32 source, u32 target, u16 cls, struct av_decision *av)
{
    assert(source==11 && target==12 && cls==3);
    ++computations;
    *av=(struct av_decision){0x1234,0x5678,0xabcd,generation,1};
}
#include "selinux_access_under_test.inc"

static ssize_t transaction(char *buffer)
{
    strcpy(buffer,"source target 3");
    allocations=0;
    return view_access(NULL,buffer,strlen(buffer));
}

int main(void)
{
    char buffer[SIMPLE_TRANSACTION_LIMIT];
    const u32 generations[]={0,1,4,40,UINT32_MAX};
    for (unsigned i=0;i<sizeof(generations)/sizeof(generations[0]);++i) {
        generation=generations[i];
        ssize_t length=transaction(buffer);
        assert(length>0 && (size_t)length==strlen(buffer));
        assert(!strcmp(buffer,"1234 ffffffff 5678 abcd 1 1"));
    }
    assert(computations==5);
    permission_error=-EACCES;
    assert(transaction(buffer)==-EACCES && !allocations && computations==5);
    permission_error=0;
    for (fail_allocation=1;fail_allocation<=2;++fail_allocation)
        assert(transaction(buffer)==-ENOMEM && computations==5);
    fail_allocation=0;context_error=-EINVAL;
    assert(transaction(buffer)==-EINVAL && computations==5);
    context_error=0;strcpy(buffer,"source");
    assert(view_access(NULL,buffer,strlen(buffer))==-EINVAL && computations==5);
    puts("PASS production access handler: seqno=1, AV fields preserved, permission/allocation/parse failures");
    return 0;
}
