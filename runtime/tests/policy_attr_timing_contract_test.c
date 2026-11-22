#include "policy_view_internal.h"
#include <stdio.h>

bool fixture_mutate_mls;
struct fixture_counts fixture_counts;
struct maplesu_policy_view maplesu_view;
__typeof__(selinux_state) selinux_state;
static struct user_datum user = {1}, other_user = {7};
static struct role_datum role = {2}, other_role = {9};
static struct type_datum type = {3, false}, other_type = {23, false};
static struct sidtab backup_sidtab = {1}, live_sidtab = {2};
static struct selinux_policy backup, live, next;
static struct cred caller_cred;
static struct task_struct caller = {&caller_cred};
struct task_struct *current = &caller;
static struct policydb *captured;
static u32 captured_generation;
static unsigned original_limit, rcu_depth, epoch_depth, stale_count, tests;
static int avc_error, backup_error, live_error;
static bool fail_alloc, reload_on_unlock;

u32 current_sid(void) { return caller_cred.security.sid; }
struct task_security_struct *selinux_cred(const struct cred *cred) {
    return (struct task_security_struct *)&cred->security;
}
const struct cred *__task_cred(const struct task_struct *task) { return task->cred; }
struct task_struct *ptrace_parent(struct task_struct *task) { (void)task; return NULL; }
int current_is_single_threaded(void) { return 1; }
int fixture_bounded_transition(u32 from, u32 to) { (void)from; (void)to; return 0; }
int fixture_avc_has_perm(u32 from, u32 to, unsigned cls, unsigned access, void *audit) {
    (void)from; (void)to; (void)cls; (void)access; (void)audit;
    ++fixture_counts.avc;
    return avc_error;
}
struct cred *prepare_creds(void) {
    struct cred *fresh = malloc(sizeof(*fresh));
    assert(fresh);
    *fresh = caller_cred;
    ++fixture_counts.prepare;
    return fresh;
}
void abort_creds(struct cred *cred) { ++fixture_counts.abort; free(cred); }
int commit_creds(struct cred *cred) {
    ++fixture_counts.commit;
    caller_cred = *cred;
    free(cred);
    return 0;
}
void maplesu_policy_query_begin(void) { assert(!epoch_depth); ++epoch_depth; }
void maplesu_policy_query_end(void) { assert(epoch_depth == 1); --epoch_depth; }
void *kmemdup_nul(const char *text, u32 length, int flags) {
    char *copy;
    (void)flags;
    assert(!rcu_depth);
    ++fixture_counts.allocations;
    if (fail_alloc) return NULL;
    copy = malloc((size_t)length + 1);
    assert(copy);
    memcpy(copy, text, length);
    copy[length] = '\0';
    return copy;
}
void kfree(void *memory) { assert(!rcu_depth); free(memory); }
void fixture_rcu_lock(void) { assert(!rcu_depth); ++rcu_depth; }
void fixture_rcu_unlock(void) {
    assert(rcu_depth == 1);
    --rcu_depth;
    if (reload_on_unlock) {
        selinux_state.policy = &next;
        reload_on_unlock = false;
    }
}
int maplesu_type_is_original(struct policydb *policy, u32 generation, u32 value) {
    if (policy != captured || generation != captured_generation || !generation || !original_limit)
        return -1;
    return value && value <= original_limit ? 1 : 0;
}
int sidtab_context_to_sid(struct sidtab *table, struct context *context, u32 *sid) {
    assert(rcu_depth == 1);
    if (table == &backup_sidtab) {
        ++fixture_counts.base_sid;
        assert(context->user == 1 && context->role == 2 && context->type == 3);
        if (backup_error) return backup_error;
    } else {
        assert(table == &live_sidtab);
        ++fixture_counts.live_sid;
        assert(context->user == selinux_state.policy->policydb.expected_user);
        assert(context->role == selinux_state.policy->policydb.expected_role);
        assert(context->type == selinux_state.policy->policydb.expected_type);
        if (stale_count) { --stale_count; return -ESTALE; }
        if (live_error) return live_error;
    }
    *sid = table->identity * 1000 + context->type;
    return 0;
}
static void reset(void) {
    assert(!rcu_depth && !epoch_depth);
    memset(&fixture_counts, 0, sizeof(fixture_counts));
    backup = (struct selinux_policy){&backup_sidtab,
        {{"u", &user}, {"r", &role}, {"app", &type}, 1, 2, 3, true}, 3};
    live = backup;
    live.sidtab = &live_sidtab;
    live.latest_granting = 4;
    next = live;
    next.latest_granting = 5;
    next.policydb = (struct policydb){{"u", &other_user}, {"r", &other_role},
        {"app", &other_type}, 7, 9, 23, true};
    captured = &live.policydb;
    captured_generation = live.latest_granting;
    original_limit = 3;
    maplesu_view.policy = &backup;
    selinux_state.policy = &live;
    caller_cred.security.sid = 100;
    avc_error = backup_error = live_error = 0;
    stale_count = 0;
    fail_alloc = reload_on_unlock = fixture_mutate_mls = false;
    type.attribute = other_type.attribute = false;
}
static void check(const char *name, const char *input, int expected,
                  unsigned expected_lookups, unsigned allocations,
                  unsigned prepares, unsigned aborts) {
    char value[256];
    assert(strlen(input) < sizeof(value));
    strcpy(value, input);
    int rc = maplesu_policy_view_setprocattr("current", value, strlen(value));
    printf("CASE %s rc=%d lookups=%u mls=%u allocations=%u baseSid=%u liveSid=%u prepare=%u abort=%u commit=%u\n",
        name, rc, fixture_counts.lookups, fixture_counts.mls, fixture_counts.allocations,
        fixture_counts.base_sid, fixture_counts.live_sid, fixture_counts.prepare,
        fixture_counts.abort, fixture_counts.commit);
    assert(rc == expected && !epoch_depth && !rcu_depth);
    assert(fixture_counts.lookups == expected_lookups);
    assert(fixture_counts.allocations == allocations);
    assert(fixture_counts.prepare == prepares && fixture_counts.abort == aborts);
    ++tests;
}
int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    reset(); avc_error = -EACCES;
    check("ordinary-self", "u:r:app:s0", -EACCES, 0, 0, 0, 0);
    assert(fixture_counts.avc == 1 && !fixture_counts.commit);
    reset(); avc_error = -EACCES;
    check("ordinary-newline", "\n:r:app:s0", -EACCES, 0, 0, 0, 0);
    assert(fixture_counts.avc == 1 && !fixture_counts.commit);

#ifdef FIXTURE_BASELINE
    reset(); check("zygote-invalid-type", "u:r:missing:s0", -EINVAL, 5, 1, 0, 0);
    reset(); check("invalid-user", "absent:r:missing:s0", -EINVAL, 5, 1, 0, 0);
    reset(); check("invalid-role", "u:absent:missing:s0", -EINVAL, 5, 1, 0, 0);
    reset(); check("valid-context", "u:r:app:s0", 10, 5, 1, 1, 0);
    assert(fixture_counts.mls == 2);
#else
    reset(); check("zygote-invalid-type", "u:r:missing:s0", -EINVAL, 3, 1, 0, 0);
    reset(); check("invalid-user", "absent:r:missing:s0", -EINVAL, 1, 1, 0, 0);
    reset(); check("invalid-role", "u:absent:missing:s0", -EINVAL, 2, 1, 0, 0);
    reset(); check("valid-context", "u:r:app:s0", 10, 3, 1, 1, 0);
    assert(fixture_counts.mls == 1);
#endif
    assert(fixture_counts.base_sid == 1 && fixture_counts.live_sid == 1);
    assert(fixture_counts.commit == 1 && caller_cred.security.sid == 2003);
    reset(); check("zygote-newline", "\n:r:missing:s0", -EINVAL, 0, 0, 1, 1);
    assert(!fixture_counts.commit);

#ifndef FIXTURE_BASELINE
    reset(); fixture_mutate_mls = true;
    check("mutating-mls", "u:r:app:s0", 10, 3, 1, 1, 0);
    reset(); type.attribute = true;
    check("attribute-not-type", "u:r:app:s0", -EINVAL, 3, 1, 0, 0);
    reset(); check("malformed", "broken", -EINVAL, 0, 1, 0, 0);
    reset(); check("invalid-mls", "u:r:app:s1", -EINVAL, 3, 1, 0, 0);
    reset(); live.policydb.expected_type = 99;
    check("live-invalid", "u:r:app:s0", -EINVAL, 3, 1, 0, 0);
    reset(); original_limit = 0;
    check("unqualified-type-fallback", "u:r:app:s0", 10, 9, 2, 1, 0);
    assert(fixture_counts.mls == 2);
    reset(); original_limit = 2;
    check("non-original-type-fallback", "u:r:app:s0", -EINVAL, 8, 2, 0, 0);
    reset(); live = next;
    check("generation-and-ids-fallback", "u:r:app:s0", 10, 9, 2, 1, 0);
    assert(fixture_counts.mls == 2 && caller_cred.security.sid == 2023);
    reset(); captured = &next.policydb;
    check("table-fallback", "u:r:app:s0", 10, 9, 2, 1, 0);
    reset(); stale_count = 3;
    check("stale-three", "u:r:app:s0", 10, 12, 1, 1, 0);
    assert(fixture_counts.live_sid == 4 && fixture_counts.base_sid == 4);
    reset(); stale_count = 4;
    check("stale-bound", "u:r:app:s0", -ESTALE, 12, 1, 0, 0);
    assert(fixture_counts.live_sid == 4 && fixture_counts.base_sid == 4);
    reset(); stale_count = 1; reload_on_unlock = true;
    check("reload-with-different-ids", "u:r:app:s0", 10, 12, 2, 1, 0);
    assert(caller_cred.security.sid == 2023);
    reset(); backup_error = -ENOMEM;
    check("backup-sid-error", "u:r:app:s0", -ENOMEM, 3, 1, 0, 0);
    assert(fixture_counts.base_sid == 1 && !fixture_counts.live_sid);
    reset(); live_error = -ENOMEM;
    check("live-sid-error", "u:r:app:s0", -ENOMEM, 3, 1, 0, 0);
    reset(); live_error = -EAGAIN;
    check("live-eagain-is-not-fallback", "u:r:app:s0", -EAGAIN, 3, 1, 0, 0);
    reset(); selinux_state.policy = NULL;
    check("missing-live", "u:r:app:s0", -EAGAIN, 0, 1, 0, 0);
    reset(); fail_alloc = true;
    check("allocation-failed", "u:r:app:s0", -ENOMEM, 0, 1, 0, 0);
#endif
    printf("PASS %u actual setprocattr source cases; counts prove work, not device latency\n", tests);
    return 0;
}
