/* Host-only objects for executing the production accessors with relocated
 * fields. Kernel operations are not simulated as successful device evidence. */
#include <stdint.h>
#include <stddef.h>
#include <string.h>
typedef uint32_t u32;
typedef uint64_t u64;
typedef struct { u32 val; } kuid_t;
struct cred { kuid_t uid; void *security; };
struct fixture_security { u32 sid; };
#define maplesu_cred_security fixture_security
struct context { u32 ignored; };
struct sidtab { u32 ignored; };
struct sidtab_entry { struct context context; };
struct task_struct { unsigned int ptrace; struct task_struct *parent; const struct cred *cred, *real_cred; };
static struct task_struct *current;
struct lsm_blob_sizes { int lbs_cred; unsigned char storage[65536]; };
static struct lsm_blob_sizes selinux_blob_sizes;
static struct sidtab_entry *selected_entry;
static inline struct sidtab_entry *sidtab_search_entry(struct sidtab *tab, u32 sid)
{ (void)tab; (void)sid; return selected_entry; }
#define rcu_dereference_protected(value, condition) (value)
#define rcu_dereference(value) (value)
#define READ_ONCE(value) __atomic_load_n(&(value), __ATOMIC_RELAXED)
#include "policy_dynamic_layout.h"
struct maplesu_policy_layout_table maplesu_policy_layout;
void dynamic_access_bind(const struct maplesu_policy_layout_table *table)
{ maplesu_policy_layout = *table; }
u32 dynamic_access_uid(void *task)
{ current = task; return pv_current_uid().val; }
u32 dynamic_access_sid(void *task, int security_offset)
{
    current = task;
    PV_FIELD(&selinux_blob_sizes, lsm_blob_sizes, lbs_cred) = security_offset;
    return pv_current_sid();
}
void dynamic_access_set_uid(void *cred, u32 value)
{ PV_FIELD((struct cred *)cred, cred, uid).val = value; }
void *dynamic_access_parent(void *task)
{ return pv_ptrace_parent(task); }
void *dynamic_access_context(void *entry)
{ selected_entry = entry; return pv_sidtab_search(NULL, 0); }

u32 dynamic_access_policy_flag(const void *policy)
{ return PV_BITS(policy, policydb, allow_unknown); }
