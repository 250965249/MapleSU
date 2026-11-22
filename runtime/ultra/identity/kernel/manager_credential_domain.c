// SPDX-License-Identifier: GPL-3.0-only
#include <linux/errno.h>
#include <linux/string.h>
#include <linux/stddef.h>
#include <linux/version.h>
#include "manager_credential_domain.h"
#include "manager_credential_profile.h"

#if MSU_MANAGEMENT_PROFILE_DOMAIN_VERIFIED && defined(CONFIG_SECURITY_SELINUX)
#include <linux/cred.h>
#include <linux/security.h>
#include "objsec.h"

/* The actual native accessor supplies the object type. Qualification binds
 * this target's declaration, blob allocation and resolver/KCFI identity. */
typedef typeof(*selinux_cred((const struct cred *)0)) msu_domain_native_security;
_Static_assert(__builtin_types_compatible_p(typeof(&security_secctx_to_secid),
    int (*)(const char *, u32, u32 *)), "native context resolver type");
_Static_assert(__builtin_types_compatible_p(typeof(selinux_blob_sizes),
    struct lsm_blob_sizes), "native LSM blob size object type");
_Static_assert(__builtin_types_compatible_p(typeof(((msu_domain_native_security *)0)->sid),
    u32), "native credential SID type");
_Static_assert(__builtin_types_compatible_p(typeof(((msu_domain_native_security *)0)->create_sid),
    u32), "native credential creation SID type");
_Static_assert(__builtin_types_compatible_p(typeof(((msu_domain_native_security *)0)->keycreate_sid),
    u32), "native credential key creation SID type");
_Static_assert(__builtin_types_compatible_p(typeof(((msu_domain_native_security *)0)->sockcreate_sid),
    u32), "native credential socket creation SID type");
#endif

#define MSU_DOMAIN_TYPE(type) sizeof(type), __alignof__(type)
#define MSU_DOMAIN_FIELD(type, field) offsetof(type, field), sizeof(((type *)0)->field)
const unsigned int msu_credential_domain_compiled_layout[MSU_CREDENTIAL_DOMAIN_LAYOUT_WORDS]
    __attribute__((section(".msu.credential_domain.layout"))) = {
    1, LINUX_VERSION_CODE, MSU_MANAGEMENT_PROFILE_DOMAIN_VERIFIED,
#ifdef CONFIG_SECURITY_SELINUX
    1,
#else
    0,
#endif
#if MSU_MANAGEMENT_PROFILE_DOMAIN_VERIFIED && defined(CONFIG_SECURITY_SELINUX)
    MSU_DOMAIN_TYPE(struct cred), MSU_DOMAIN_FIELD(struct cred, security),
    MSU_DOMAIN_TYPE(msu_domain_native_security),
    MSU_DOMAIN_FIELD(msu_domain_native_security, osid),
    MSU_DOMAIN_FIELD(msu_domain_native_security, sid),
    MSU_DOMAIN_FIELD(msu_domain_native_security, exec_sid),
    MSU_DOMAIN_FIELD(msu_domain_native_security, create_sid),
    MSU_DOMAIN_FIELD(msu_domain_native_security, keycreate_sid),
    MSU_DOMAIN_FIELD(msu_domain_native_security, sockcreate_sid),
    MSU_DOMAIN_TYPE(struct lsm_blob_sizes), MSU_DOMAIN_FIELD(struct lsm_blob_sizes, lbs_cred),
#else
    ~0U, 0, ~0U, 0, ~0U, 0, ~0U, 0, ~0U, 0, ~0U, 0,
    ~0U, 0, ~0U, 0, ~0U, 0, ~0U, 0, ~0U, 0,
#endif
};
#undef MSU_DOMAIN_TYPE
#undef MSU_DOMAIN_FIELD

int msu_credential_domain_supported(void)
{
#if MSU_MANAGEMENT_PROFILE_DOMAIN_VERIFIED && defined(CONFIG_SECURITY_SELINUX)
    return 0;
#else
    return -EOPNOTSUPP;
#endif
}

int msu_credential_domain_prepare(struct cred *prepared, const char *domain, u32 length)
{
    if (!prepared || !domain || length >= MSU_CRED_PROFILE_DOMAIN_BYTES ||
        domain[length] || memchr(domain, 0, length)) return -EINVAL;
    if (!length) return 0;
#if MSU_MANAGEMENT_PROFILE_DOMAIN_VERIFIED && defined(CONFIG_SECURITY_SELINUX)
    {
        msu_domain_native_security *security;
        u32 sid = 0;
        int error;
        if (prepared == current_cred() || prepared == current_real_cred()) return -EPERM;
        if (!prepared->security || prepared->security == current_cred()->security ||
            prepared->security == current_real_cred()->security) return -EINVAL;
        security = selinux_cred(prepared);
        if (!security) return -EINVAL;
        error = security_secctx_to_secid(domain, length, &sid);
        if (error) return error;
        if (!sid) return -EINVAL;
        /* Match selected KSU setup_selinux: retain osid and exec_sid. The
         * private prepared blob is committed only by the shared cred core. */
        security->sid = sid;
        security->create_sid = 0;
        security->keycreate_sid = 0;
        security->sockcreate_sid = 0;
        return 0;
    }
#else
    return -EOPNOTSUPP;
#endif
}
