// SPDX-License-Identifier: GPL-3.0-only
/* Context/access serialization follows KernelSU selinux_hide.c. */
#include "policy_view_internal.h"


static int context_struct_to_string(struct policydb *p, struct context *context, char **scontext, u32 *scontext_len)
{
    char *scontextp;

    if (scontext)
        *scontext = NULL;
    *scontext_len = 0;

    if (context->len) {
        *scontext_len = context->len;
        if (scontext) {
            *scontext = kstrdup(context->str, GFP_ATOMIC);
            if (!(*scontext))
                return -ENOMEM;
        }
        return 0;
    }

    /* Compute the size of the context. */
    *scontext_len += strlen(pv_sym_name(p, SYM_USERS, context->user - 1)) + 1;
    *scontext_len += strlen(pv_sym_name(p, SYM_ROLES, context->role - 1)) + 1;
    *scontext_len += strlen(pv_sym_name(p, SYM_TYPES, context->type - 1)) + 1;
    *scontext_len += mls_compute_context_len(p, context);

    if (!scontext)
        return 0;

    /* Allocate space for the context; caller must free this space. */
    scontextp = kmalloc(*scontext_len, GFP_ATOMIC);
    if (!scontextp)
        return -ENOMEM;
    *scontext = scontextp;

    /*
     * Copy the user name, role name and type name into the context.
     */
    scontextp += sprintf(scontextp, "%s:%s:%s", pv_sym_name(p, SYM_USERS, context->user - 1),
                         pv_sym_name(p, SYM_ROLES, context->role - 1), pv_sym_name(p, SYM_TYPES, context->type - 1));

    mls_sid_to_context(p, context, &scontextp);

    *scontextp = 0;

    return 0;
}

static int sidtab_entry_to_string(struct policydb *p, struct sidtab *sidtab, struct sidtab_entry *entry,
                                  char **scontext, u32 *scontext_len)
{
    int rc = sidtab_sid2str_get(sidtab, entry, scontext, scontext_len);

    if (rc != -ENOENT)
        return rc;

    rc = context_struct_to_string(p, &PV_FIELD(entry, sidtab_entry, context), scontext, scontext_len);
    if (!rc && scontext)
        sidtab_sid2str_put(sidtab, entry, *scontext, *scontext_len);
    return rc;
}

int maplesu_sid_to_context(u32 sid, char **scontext,
                                               u32 *scontext_len)
{
    struct policydb *policydb;
    struct sidtab *sidtab;
    struct sidtab_entry *entry;
    int rc = 0;

    if (scontext)
        *scontext = NULL;
    *scontext_len = 0;

    // removed: if (!selinux_initialized())
    // removed: rcu lock
    policydb = &PV_FIELD(maplesu_view.policy, selinux_policy, policydb);
    sidtab = PV_FIELD(maplesu_view.policy, selinux_policy, sidtab);

    // removed: force
    entry = sidtab_search_entry(sidtab, sid);
    if (!entry) {
        pr_err("SELinux: %s:  unrecognized SID %d\n", __func__, sid);
        rc = -EINVAL;
        goto out_unlock;
    }
    // removed: only_invalid

    rc = sidtab_entry_to_string(policydb, sidtab, entry, scontext, scontext_len);

out_unlock:
    return rc;
}

static void compute_view_av(u32 ssid, u32 tsid, u16 tclass, struct av_decision *avd)
{
    struct selinux_policy *p = maplesu_view.policy;
    struct context *source, *target;
    memset(avd, 0, sizeof(*avd));
    avd->auditdeny = 0xffffffff;
    avd->seqno = PV_FIELD(p, selinux_policy, latest_granting);
    source = pv_sidtab_search(PV_FIELD(p, selinux_policy, sidtab), ssid);
    target = pv_sidtab_search(PV_FIELD(p, selinux_policy, sidtab), tsid);
    if (!source || !target)
        return;
    if (ebitmap_get_bit(&PV_FIELD(&PV_FIELD(p, selinux_policy, policydb), policydb, permissive_map), source->type))
        avd->flags |= AVD_FLAGS_PERMISSIVE;
    if (!tclass) {
        if (PV_BITS(&PV_FIELD(p, selinux_policy, policydb), policydb, allow_unknown))
            avd->allowed = 0xffffffff;
        return;
    }
    /* KSU's fallback also covers kernels that inline or rename the native AV
     * helper. Do not call a compiler-specialized private symbol by guesswork. */
    maplesu_compute_policy_av(&PV_FIELD(p, selinux_policy, policydb), source, target, tclass, avd, NULL);
}

static ssize_t view_context(struct file *file, char *buf, size_t size)
{
    char *canon = NULL;
    u32 sid, len;
    ssize_t length;
    (void)file;

    length =
        maplesu_avc_has_perm(pv_current_sid(), SECINITSID_SECURITY, SECCLASS_SECURITY, SECURITY__CHECK_CONTEXT, NULL);
    if (length)
        goto out;
    length = maplesu_context_to_sid(buf, size, &sid, NULL, NULL);
    if (length) {
        goto out;
    }

    length = maplesu_sid_to_context(sid, &canon, &len);
    if (length)
        goto out;

    length = -ERANGE;
    if (len > SIMPLE_TRANSACTION_LIMIT) {
        pr_err("SELinux: %s:  context size (%u) exceeds "
               "payload max\n",
               __func__, len);
        goto out;
    }

    memcpy(buf, canon, len);
    length = len;
out:
    kfree(canon);
    return length;
}

static ssize_t view_access(struct file *file, char *buf, size_t size)
{
    char *scon = NULL, *tcon = NULL;
    u32 ssid, tsid, sconlen, tconlen;
    u16 tclass;
    struct av_decision avd;
    ssize_t length;
    (void)file;

    length = maplesu_avc_has_perm(pv_current_sid(), SECINITSID_SECURITY, SECCLASS_SECURITY, SECURITY__COMPUTE_AV, NULL);
    if (length)
        goto out;

    length = -ENOMEM;
    scon = kzalloc(size + 1, GFP_KERNEL);
    if (!scon)
        goto out;

    length = -ENOMEM;
    tcon = kzalloc(size + 1, GFP_KERNEL);
    if (!tcon)
        goto out;

    length = -EINVAL;
    if (sscanf(buf, "%s %s %hu", scon, tcon, &tclass) != 3)
        goto out;

    sconlen = strlen(scon);
    tconlen = strlen(tcon);

    length =
        maplesu_context_to_sid(scon, sconlen, &ssid, NULL, NULL);
    if (length) {
        goto out;
    }

    length =
        maplesu_context_to_sid(tcon, tconlen, &tsid, NULL, NULL);
    if (length) {
        goto out;
    }

    compute_view_av(ssid, tsid, tclass, &avd);

    /* KSU's hidden access ABI uses 1 independently of the status page's
     * first-open policyload sentinel. Keep the actual permission decision. */
    avd.seqno = 1;
    length = scnprintf(buf, SIMPLE_TRANSACTION_LIMIT, "%x %x %x %x %u %x", avd.allowed, 0xffffffff, avd.auditallow,
                       avd.auditdeny, avd.seqno, avd.flags);
out:
    kfree(tcon);
    kfree(scon);
    return length;
}

ssize_t maplesu_policy_view_context(struct file *file, char *buf, size_t size)
{
    ssize_t result;

    maplesu_policy_query_begin();
    result = view_context(file, buf, size);
    maplesu_policy_query_end();
    return result;
}

ssize_t maplesu_policy_view_access(struct file *file, char *buf, size_t size)
{
    ssize_t result;

    maplesu_policy_query_begin();
    result = view_access(file, buf, size);
    maplesu_policy_query_end();
    return result;
}
