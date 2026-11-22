#include "policy_view_internal.h"
#include <stdio.h>

bool fixture_mutate_mls;
struct maplesu_policy_view maplesu_view;
__typeof__(selinux_state) selinux_state;
static struct user_datum u={1},lu={7};
static struct role_datum r={2},lr={9};
static struct type_datum t={3,false},lt={23,false},nt={47,false};
static struct sidtab baseline={1},runtime={2};
static struct selinux_policy saved,live,next;
static unsigned allocations,unlocks,locks,base_calls,live_calls,stales,tests;
static int base_error,live_error;
static bool fail_alloc,replace_on_unlock;
int maplesu_type_is_original(struct policydb *p,u32 generation,u32 type) {
    (void)p;(void)generation;(void)type;
    return -1;
}
void *kmemdup_nul(const char *text,u32 size,int flags) {
    (void)flags;
    assert(locks==0);
    ++allocations;
    if (fail_alloc) return NULL;
    char *result=malloc((size_t)size+1);
    assert(result);
    memcpy(result,text,size);result[size]=0;
    return result;
}
void kfree(void *p) { assert(locks==0);free(p); }
void fixture_rcu_lock(void) { assert(locks==0);++locks; }
void fixture_rcu_unlock(void) {
    assert(locks==1);--locks;++unlocks;
    if (replace_on_unlock) { selinux_state.policy=&next;replace_on_unlock=false; }
}
int sidtab_context_to_sid(struct sidtab *sidtab,struct context *ctx,u32 *sid) {
    assert(locks==1);
    if (sidtab==&baseline) {
        ++base_calls;
        assert(ctx->type==3);
        if (base_error) return base_error;
    } else {
        assert(sidtab==&runtime);
        ++live_calls;
        assert(ctx->type==selinux_state.policy->policydb.expected_type);
        if (stales) { --stales;return -ESTALE; }
        if (live_error) return live_error;
    }
    *sid=sidtab->identity*1000+ctx->type;
    return 0;
}
static void reset(void) {
    allocations=unlocks=locks=base_calls=live_calls=stales=0;
    base_error=live_error=0;fail_alloc=replace_on_unlock=fixture_mutate_mls=false;
    saved=(struct selinux_policy){&baseline,{{"u",&u},{"r",&r},{"app",&t},1,2,3,true},3};
    live=(struct selinux_policy){&runtime,{{"u",&lu},{"r",&lr},{"app",&lt},7,9,23,true},4};
    next=live;next.latest_granting=5;next.policydb.p_types.datum=&nt;next.policydb.expected_type=47;
    maplesu_view.policy=&saved;selinux_state.policy=&live;
}
static void check(const char *input,int expected,int live_expected,unsigned tries,u32 mapped) {
    char immutable[80];strcpy(immutable,input);
    u32 sid=99,live_sid=99;int live_rc=99;
    int rc=maplesu_context_to_sid(immutable,(u32)strlen(immutable),&sid,&live_sid,&live_rc);
    assert(rc==expected && live_rc==live_expected);
    assert(locks==0 && live_calls==tries && allocations==1);
    assert(!strcmp(immutable,input));
    assert(live_sid==mapped);
    if (rc==0) assert(sid==1003);
    ++tests;
}
int main(void) {
    reset();check("u:r:app:s0",0,0,1,2023);
    reset();fixture_mutate_mls=true;check("u:r:app:s0",0,0,1,2023);
    reset();replace_on_unlock=true;stales=1;
    check("u:r:app:s0",0,0,2,2047);assert(unlocks==2);
    reset();stales=3;check("u:r:app:s0",0,0,4,2023);assert(unlocks==4);
    reset();stales=4;check("u:r:app:s0",0,-ESTALE,4,0);assert(unlocks==4);
    reset();live_error=-ENOMEM;check("u:r:app:s0",0,-ENOMEM,1,0);
    reset();base_error=-ENOMEM;check("u:r:app:s0",-ENOMEM,-ENOMEM,0,0);
    reset();live.policydb.p_types.name=NULL;check("u:r:app:s0",0,-EINVAL,0,0);
    reset();saved.policydb.p_types.name=NULL;check("u:r:app:s0",-EINVAL,-EINVAL,0,0);
    reset();live.policydb.expected_type=3;check("u:r:app:s0",0,-EINVAL,0,0);
    reset();selinux_state.policy=NULL;check("u:r:app:s0",-EAGAIN,-EAGAIN,0,0);
    reset();check("u:r:app:s1",-EINVAL,-EINVAL,0,0);
    reset();check("broken",-EINVAL,-EINVAL,0,0);
    reset();{
        u32 sid=9,lsid=9;int lrc=9;
        assert(maplesu_context_to_sid("",0,&sid,&lsid,&lrc)==-EINVAL && !allocations);++tests;
    }
    reset();fail_alloc=true;{
        u32 sid=9,lsid=9;int lrc=9;
        assert(maplesu_context_to_sid("u:r:app:s0",10,&sid,&lsid,&lrc)==-ENOMEM);
        assert(allocations==1 && unlocks==0);++tests;
    }
    printf("PASS %u KSU-derived SID synchronization cases (reload, retry bounds, separate IDs, allocation and error paths)\n",tests);
}
