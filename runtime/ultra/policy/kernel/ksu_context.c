// SPDX-License-Identifier: GPL-3.0-only
/* Derived from KernelSU 730f644615969cfd4a84b45d7f62a667b7b95a50,
 * kernel/feature/selinux_hide.c. See KSU-PROVENANCE.json. */
#include "policy_view_internal.h"

int maplesu_context_parse(struct policydb *pol, struct policydb *orig_pol, struct sidtab *sidtabp,
                                    struct sidtab *orig_sidtabp, char *scontext, const char *source, u32 source_len,
                                    struct context *ctx, struct context *orig_ctx, u32 policy_generation, u32 def_sid,
                                    int *orig_rc_p)
{
    struct role_datum *role, *orig_role;
    struct type_datum *typdatum, *orig_typdatum;
    struct user_datum *usrdatum, *orig_usrdatum;
    char *scontextp, *p, oldc;
    bool orig_valid = true;
    bool live_valid = true;
    int rc = -EINVAL, orig_rc = -EINVAL;
    int type_is_original;

    context_init(ctx);
    context_init(orig_ctx);

    // split fields once
    // look up both policies
    scontextp = scontext;

    /* Extract the user. */
    p = scontextp;
    while (*p && *p != ':')
        p++;

    if (*p == 0)
        goto out;

    *p++ = 0;

    usrdatum = symtab_search(&PV_SYMTAB(pol, p_users, SYM_USERS), scontextp);
    if (!usrdatum)
        goto out;
    ctx->user = usrdatum->value;
    orig_usrdatum = symtab_search(&PV_SYMTAB(orig_pol, p_users, SYM_USERS), scontextp);
    if (orig_usrdatum)
        orig_ctx->user = orig_usrdatum->value;
    else
        orig_valid = false;

    /* Extract role. */
    scontextp = p;
    while (*p && *p != ':')
        p++;

    if (*p == 0)
        goto out;

    *p++ = 0;

    role = symtab_search(&PV_SYMTAB(pol, p_roles, SYM_ROLES), scontextp);
    if (!role)
        goto out;
    ctx->role = role->value;
    orig_role = symtab_search(&PV_SYMTAB(orig_pol, p_roles, SYM_ROLES), scontextp);
    if (orig_role)
        orig_ctx->role = orig_role->value;
    else
        orig_valid = false;

    /* Extract type. */
    scontextp = p;
    while (*p && *p != ':')
        p++;
    oldc = *p;
    *p++ = 0;

    typdatum = symtab_search(&PV_SYMTAB(pol, p_types, SYM_TYPES), scontextp);
    if (!typdatum || typdatum->attribute) {
        live_valid = false;
    } else {
        ctx->type = typdatum->value;
        // Type values stay stable when KSU copies the live policy
        type_is_original = maplesu_type_is_original(orig_pol, policy_generation, typdatum->value);
        if (type_is_original < 0) {
            orig_typdatum = symtab_search(&PV_SYMTAB(orig_pol, p_types, SYM_TYPES), scontextp);
            if (orig_typdatum && !orig_typdatum->attribute)
                orig_ctx->type = orig_typdatum->value;
            else
                orig_valid = false;
        } else if (type_is_original) {
            orig_ctx->type = typdatum->value;
        } else {
            orig_valid = false;
        }
    }

    if (!live_valid)
        goto out;

    rc = mls_context_to_sid(pol, oldc, p, ctx, sidtabp, def_sid);
    if (orig_valid) {
        if (oldc) {
            size_t offset = p - scontext;

            // restore MLS suffix for live policy
            memcpy(p, source + offset, source_len - offset);
            p[source_len - offset] = '\0';
        }
        // validate live context with live policy
        orig_rc = mls_context_to_sid(orig_pol, oldc, p, orig_ctx, orig_sidtabp, def_sid);
        if (!orig_rc && !policydb_context_isvalid(orig_pol, orig_ctx))
            orig_rc = -EINVAL;
    }

    if (!rc && !policydb_context_isvalid(pol, ctx))
        rc = -EINVAL;
out:
    if (rc) {
        context_destroy(ctx);
        // ignore live result if backup fails
        orig_rc = -EINVAL;
    }
    if (rc || orig_rc)
        context_destroy(orig_ctx);
    *orig_rc_p = orig_rc;
    return rc;
}

int maplesu_context_parse_live(struct policydb *pol, struct policydb *live_pol,
                               struct sidtab *sidtab, char *text,
                               struct context *ctx, u32 generation)
{
    struct user_datum *user;
    struct role_datum *role;
    struct type_datum *type;
    char *field = text, *p = text, oldc;
    int rc = -EINVAL;

    context_init(ctx);
    while (*p && *p != ':')
        ++p;
    if (!*p)
        goto out;
    *p++ = '\0';
    user = symtab_search(&PV_SYMTAB(pol, p_users, SYM_USERS), field);
    if (!user)
        goto out;
    ctx->user = user->value;

    field = p;
    while (*p && *p != ':')
        ++p;
    if (!*p)
        goto out;
    *p++ = '\0';
    role = symtab_search(&PV_SYMTAB(pol, p_roles, SYM_ROLES), field);
    if (!role)
        goto out;
    ctx->role = role->value;

    field = p;
    while (*p && *p != ':')
        ++p;
    oldc = *p;
    *p++ = '\0';
    type = symtab_search(&PV_SYMTAB(pol, p_types, SYM_TYPES), field);
    if (!type || type->attribute)
        goto out;
    /* Only the unchanged captured table/generation shares numeric IDs. */
    if (maplesu_type_is_original(live_pol, generation, type->value) <= 0) {
        rc = -EAGAIN;
        goto out;
    }
    ctx->type = type->value;
    rc = mls_context_to_sid(pol, oldc, p, ctx, sidtab, SECSID_NULL);
    if (rc)
        goto out;
    if (!policydb_context_isvalid(pol, ctx) || !policydb_context_isvalid(live_pol, ctx))
        rc = -EINVAL;
out:
    if (rc)
        context_destroy(ctx);
    return rc;
}

