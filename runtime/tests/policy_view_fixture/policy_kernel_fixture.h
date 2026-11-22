#ifndef MAPLESU_POLICY_KERNEL_FIXTURE_H
#define MAPLESU_POLICY_KERNEL_FIXTURE_H
#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
typedef uint32_t u32;
#define GFP_KERNEL 0
#define SECSID_NULL 0
struct context { u32 user, role, type, category; };
struct user_datum { u32 value; };
struct role_datum { u32 value; };
struct type_datum { u32 value; bool attribute; };
struct symtab { const char *name; void *datum; };
struct policydb {
    struct symtab p_users, p_roles, p_types;
    u32 expected_user, expected_role, expected_type;
    bool valid_mls;
};
struct sidtab { unsigned identity; };
struct selinux_policy { struct sidtab *sidtab; struct policydb policydb; u32 latest_granting; };
struct maplesu_policy_view { struct selinux_policy *policy; };
extern struct maplesu_policy_view maplesu_view;
extern struct { struct selinux_policy *policy; } selinux_state;
void *kmemdup_nul(const char *,u32,int);
void kfree(void *);
void fixture_rcu_lock(void);
void fixture_rcu_unlock(void);
#define rcu_read_lock() fixture_rcu_lock()
#define rcu_read_unlock() fixture_rcu_unlock()
#define rcu_dereference(x) (x)
int sidtab_context_to_sid(struct sidtab *,struct context *,u32 *);
int maplesu_context_to_sid(const char *,u32,u32 *,u32 *,int *);
int maplesu_context_to_sid_live(const char *,u32,u32 *);
int maplesu_policy_view_setprocattr(const char *,void *,size_t);
extern bool fixture_mutate_mls;
#ifdef MAPLESU_POLICY_ATTR_CONTRACT_TEST
struct fixture_counts {
    unsigned lookups, mls, allocations, base_sid, live_sid, prepare, abort, commit, avc;
};
extern struct fixture_counts fixture_counts;
struct task_security_struct { u32 sid; };
#define maplesu_cred_security task_security_struct
struct cred { struct task_security_struct security; };
struct task_struct { struct cred *cred; };
extern struct task_struct *current;
#define SECCLASS_PROCESS 2
#define PROCESS__SETCURRENT 1
#define PROCESS__DYNTRANSITION 2
#define PROCESS__PTRACE 4
#define maplesu_avc_has_perm fixture_avc_has_perm
#define maplesu_bounded_transition fixture_bounded_transition
u32 current_sid(void);
struct task_security_struct *selinux_cred(const struct cred *);
const struct cred *__task_cred(const struct task_struct *);
struct task_struct *ptrace_parent(struct task_struct *);
int fixture_avc_has_perm(u32,u32,unsigned,unsigned,void *);
int fixture_bounded_transition(u32,u32);
struct cred *prepare_creds(void);
void abort_creds(struct cred *);
int commit_creds(struct cred *);
int current_is_single_threaded(void);
#endif
static inline void context_init(struct context *c) { memset(c, 0, sizeof(*c)); }
static inline void context_destroy(struct context *c) { memset(c, 0, sizeof(*c)); }
static inline void *symtab_search(struct symtab *s, const char *name) {
#ifdef MAPLESU_POLICY_ATTR_CONTRACT_TEST
    ++fixture_counts.lookups;
#endif
    return s->name && !strcmp(s->name,name) ? s->datum : NULL;
}
static inline int mls_context_to_sid(struct policydb *p, char oldc, char *text,
                                    struct context *c, struct sidtab *sidtab, u32 def_sid) {
    (void)sidtab; (void)def_sid;
#ifdef MAPLESU_POLICY_ATTR_CONTRACT_TEST
    ++fixture_counts.mls;
#endif
    if (!p->valid_mls || oldc != ':' || strcmp(text,"s0")) return -EINVAL;
    c->category=1;
    if (fixture_mutate_mls) text[0]='X';
    return 0;
}
static inline bool policydb_context_isvalid(struct policydb *p, struct context *c) {
    return c->user==p->expected_user && c->role==p->expected_role &&
           c->type==p->expected_type && c->category==1;
}
#endif
