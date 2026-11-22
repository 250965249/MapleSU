/* Public dispatch ABI tests: native calls, argument forwarding and bounded recv.
 * Kernel primitives are the fixture boundary; no private helper is asserted. */
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include "../module/policy_hook_dispatch.h"

static unsigned calls, predicates, handlers, selected = 1, discard, observed_op, guard_calls;
static unsigned long long seen[6], returned = 73;
static int backend_error;
static unsigned reconciliations;
void msu_policy_backend_note_error(int error) { backend_error=error; }
void msu_policy_backend_reconcile(void) { ++reconciliations; }
static unsigned long long original(unsigned long long a, unsigned long long b,
    unsigned long long c, unsigned long long d, unsigned long long e, unsigned long long f)
{
    unsigned long long args[] = {a,b,c,d,e,f};
    memcpy(seen, args, sizeof seen); ++calls; return returned;
}
unsigned long long msu_policy_call_original(unsigned long long fn,
    const unsigned long long args[6])
{
    assert(fn == (unsigned long long)(unsigned long)&original);
    return original(args[0],args[1],args[2],args[3],args[4],args[5]);
}
static unsigned long long predicate(unsigned long long op, unsigned long long a,
    unsigned long long b, unsigned long long c, unsigned long long d, unsigned long long e)
{
    (void)c;(void)d;(void)e; ++predicates; observed_op = (unsigned)op;
    seen[0] = a; seen[1] = b; return selected;
}
static unsigned long long handler(unsigned long long a, unsigned long long b,
    unsigned long long c, unsigned long long d, unsigned long long e, unsigned long long f)
{
    unsigned long long args[] = {a,b,c,d,e,f};
    memcpy(seen, args, sizeof seen); ++handlers;
    if (observed_op == 7) assert(calls == 1);
    return observed_op == 8 ? (handlers <= discard ? 0 : b) : 91;
}
static void reset(void) { calls=predicates=handlers=discard=observed_op=0; selected=1; returned=73; }
static unsigned long long guard(unsigned long long phase,unsigned long long b,unsigned long long c,
    unsigned long long d,unsigned long long e,unsigned long long f)
{
    (void)b;(void)c;(void)d;(void)e;(void)f;
    assert(phase==guard_calls && calls==phase);++guard_calls;return 0;
}
int main(void)
{
    unsigned int active = 0;
    unsigned long long args[] = {11,22,33,44,55,66};
    struct msu_policy_hook_dispatch h = {(unsigned long)&original,
        (unsigned long)&predicate,(unsigned long)&handler,(unsigned long)&active,0,1};
    assert(msu_policy_dispatch(&h,args)==73 && calls==1 && predicates==0 && handlers==0);
    assert(!memcmp(args,seen,sizeof args));
    puts("PASS: inactive Hook executes native function exactly once with all arguments");
    reset(); active=1; selected=0;
    assert(msu_policy_dispatch(&h,args)==73 && calls==1 && handlers==0);
    puts("PASS: unselected reader retains native result and arguments");
    reset();
    assert(msu_policy_dispatch(&h,args)==91 && calls==0 && handlers==1);
    assert(!memcmp(args,seen,sizeof args));
    puts("PASS: selected query reaches payload with native arguments");
    reset(); h.operation=7;
    assert(msu_policy_dispatch(&h,args)==73 && calls==1 && handlers==1);
    puts("PASS: credentials commit once, before mapping callback, native result preserved");
    reset(); h.operation=8; discard=2;
    int error=0; args[4]=(unsigned long)&error;
    assert(msu_policy_dispatch(&h,args)==73 && calls==3 && handlers==3 && !error);
    puts("PASS: hidden datagrams drain before visible message without outer receive replay");
    reset(); discard=9;
    assert(msu_policy_dispatch(&h,args)==0 && calls==8 && handlers==8 && error==-11);
    puts("PASS: hidden receive drain is bounded and returns native EAGAIN");
    reset(); returned=0;
    assert(msu_policy_dispatch(&h,args)==0 && calls==1 && handlers==0);
    puts("PASS: native empty/error dequeue is not retried or overwritten");
    reset();h.operation=9;h.handler=(unsigned long)&guard;active=0;
    assert(msu_policy_dispatch(&h,args)==73 && calls==1 && !predicates && guard_calls==2);
    puts("PASS: fork is bracketed exactly once while query activation is changing");
    reset();guard_calls=0;active=1;h.operation=11;
    assert(msu_policy_dispatch(&h,args)==73 && calls==1 && !predicates && guard_calls==2 && reconciliations==1 && !backend_error);
    puts("PASS: reload brackets the native write once and reconciles only after releasing the payload epoch");
    reset();h.operation=10;h.handler=(unsigned long)&handler;
    assert(msu_policy_dispatch(&h,args)==73 && calls==1 && handlers==1 && backend_error==91);
    puts("PASS: notification observer preserves native delivery even if epoch tracking fails");
    return 0;
}
