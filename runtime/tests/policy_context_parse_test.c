#include "policy_view_internal.h"
#include <stdio.h>

static unsigned tests;
bool fixture_mutate_mls;
int maplesu_type_is_original(struct policydb *p,u32 generation,u32 type) {
    (void)p; (void)generation; (void)type;
    return -1; // Exercise the real KSU fallback used after independent reloads.
}
static struct user_datum u={1}, lu={7};
static struct role_datum r={2}, lr={9};
static struct type_datum t={3,false}, lt={23,false};
static struct policydb base,live;
static void reset(void) {
    base=(struct policydb){{"u",&u},{"r",&r},{"app",&t},1,2,3,true};
    live=(struct policydb){{"u",&lu},{"r",&lr},{"app",&lt},7,9,23,true};
    t.attribute=lt.attribute=false;
    fixture_mutate_mls=false;
}
static void check(const char *input,int rc,int lrc) {
    struct sidtab a={0},b={0};
    struct context c,lc;
    int actual_lrc=1;
    char text[80],ltext[80];
    assert(strlen(input)<sizeof(text));
    strcpy(text,input);strcpy(ltext,input);
    assert(maplesu_context_parse(&base,&live,&a,&b,text,ltext,(u32)strlen(input),&c,&lc,3,0,&actual_lrc)==rc);
    assert(actual_lrc==lrc);
    if (!rc) assert(c.user==1 && c.role==2 && c.type==3 && c.category==1);
    else assert(c.user==0 && c.role==0 && c.type==0 && c.category==0);
    if (!lrc) assert(lc.user==7 && lc.role==9 && lc.type==23 && lc.category==1);
    else assert(lc.user==0 && lc.role==0 && lc.type==0 && lc.category==0);
    context_destroy(&c);context_destroy(&lc);
    ++tests;
}
int main(void) {
    reset();check("u:r:app:s0",0,0);
    reset();live.expected_user=1;live.expected_role=2;live.expected_type=3;
    check("u:r:app:s0",0,-EINVAL); // Never validate live using the baseline IDs.
    reset();live.p_users.name=NULL;check("u:r:app:s0",0,-EINVAL);
    reset();live.p_roles.name=NULL;check("u:r:app:s0",0,-EINVAL);
    reset();live.p_types.name=NULL;check("u:r:app:s0",0,-EINVAL);
    reset();lt.attribute=true;check("u:r:app:s0",0,-EINVAL);
    reset();live.valid_mls=false;check("u:r:app:s0",0,-EINVAL);
    reset();base.valid_mls=false;check("u:r:app:s0",-EINVAL,-EINVAL);
    reset();base.expected_type=99;check("u:r:app:s0",-EINVAL,-EINVAL);
    reset();t.attribute=true;check("u:r:app:s0",-EINVAL,-EINVAL);
    reset();base.p_users.name=NULL;check("u:r:app:s0",-EINVAL,-EINVAL);
    reset();check("u:r:added:s0",-EINVAL,-EINVAL);
    reset();check("u:r:app",-EINVAL,-EINVAL);
    reset();check("u:r:app:s1",-EINVAL,-EINVAL);
    reset();check("malformed",-EINVAL,-EINVAL);
    reset();fixture_mutate_mls=true;check("u:r:app:s0",0,0);
    printf("PASS %u KSU-derived context parser cases (independent IDs, MLS, invalid and missing symbols)\n",tests);
}
