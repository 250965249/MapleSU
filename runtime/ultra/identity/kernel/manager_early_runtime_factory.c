// SPDX-License-Identifier: GPL-3.0-only
#include <linux/errno.h>
#include <linux/mutex.h>
#include <linux/string.h>
#include "manager_early_runtime_factory.h"
#include "manager_installation_state.h"
#include "manager_deployment_namespace.h"
#include "manager_early_oem.h"
#include "manager_early_root.h"
#include "manager_early_root_backend.h"
#include "manager_early_selinux.h"
#include "manager_early_selinux_backend.h"

static DEFINE_MUTEX(msu_early_runtime_lock);
static struct {
    unsigned long (*lookup)(const char *);
    int (*resolve_cfi)(const char *, const void *, unsigned long *);
    maplesu_host_instance host;
    struct msu_deployment_namespace_record deployment;
    struct msu_early_root_provider root;
    unsigned char generation[16];
    int bind_error[3], domain_error[3];
    bool bound, generation_live, closed, attempted[3];
} early;

static bool same_host(const maplesu_host_instance *a, const maplesu_host_instance *b)
{
    return a->low == b->low && a->high == b->high;
}

int msu_early_runtime_target_bind(unsigned long (*lookup)(const char *),
    int (*resolve_cfi)(const char *, const void *, unsigned long *))
{
    int error = 0;
    if (!lookup || !resolve_cfi) return -EINVAL;
    mutex_lock(&msu_early_runtime_lock);
    if (early.bound) {
        error = early.lookup == lookup && early.resolve_cfi == resolve_cfi ? 0 : -ESTALE;
        goto out;
    }
    early.lookup = lookup;
    early.resolve_cfi = resolve_cfi;
    early.bind_error[0] = msu_early_oem_target_bind(lookup, resolve_cfi);
    early.bind_error[1] = msu_early_root_backend_target_bind(lookup, resolve_cfi);
    early.bind_error[2] = msu_early_selinux_backend_bind(lookup, resolve_cfi);
    early.bound = true;
    /* An unsupported fixed business target never becomes a new SU prerequisite.
     * Its original qualification error is returned only to that domain request. */
out:
    mutex_unlock(&msu_early_runtime_lock);
    return error;
}

/* The installation's existing revoke path retires the same fixed registry.
 * This factory also closes partially constructed, not-yet-registered domains. */
static int retire_generation(void)
{
    u32 effects = 0, local = 0;
    int error, next;
    if (!early.generation_live) return 0;
    error = msu_early_fixed_provider_revoke(&early.host, early.generation, &effects);
    if (error) return error;
    if (early.attempted[0]) {
        next = msu_early_oem_close(&local);
        if (!next && !msu_early_oem_discarded()) next = -EINPROGRESS;
        if (!error) error = next;
    }
    if (early.attempted[1] && early.root.initialized) {
        next = msu_early_root_provider_close(&early.root, &local);
        if (!next) next = msu_early_root_provider_discarded(&early.root);
        if (!error) error = next;
    }
    if (early.attempted[2]) {
        next = msu_early_selinux_close();
        if (!next) next = msu_early_selinux_discarded();
        if (!error) error = next;
    }
    if (!error) {
        memset(early.attempted, 0, sizeof(early.attempted));
        memset(early.domain_error, 0, sizeof(early.domain_error));
        memzero_explicit(early.generation, sizeof(early.generation));
        early.generation_live = false;
    }
    return error;
}

static int installation_current(const maplesu_host_instance *host,
    maplesu_installation_state_v3 *installation)
{
    int error = msu_installation_read(installation);
    if (error) return error;
    if (!installation->record.active || installation->flags ||
        !same_host(host, &installation->host) ||
        !memchr_inv(installation->record.generation, 0, 16)) return -ESTALE;
    return 0;
}

int msu_early_runtime_activate(const maplesu_host_instance *host, u32 operation)
{
    maplesu_installation_state_v3 installation, final;
    struct msu_early_root_ops ops = {0};
    u32 domain;
    int error;
    if (!host || !(host->low | host->high) || operation < MSU_EARLY_FIXED_OEM_MTK ||
        operation > MSU_EARLY_FIXED_SELINUX_WRITE_SEQUENCE) return -EINVAL;
    domain = operation <= MSU_EARLY_FIXED_OEM_OPLUS_INTE ? 0 :
        operation == MSU_EARLY_FIXED_ROOT_ENV ? 1 : 2;
    mutex_lock(&msu_early_runtime_lock);
    if (!early.bound) { error = -EOPNOTSUPP; goto out; }
    if (early.closed) { error = -ESTALE; goto out; }
    error = installation_current(host, &installation);
    if (error) goto out;
    if (early.generation_live && (!same_host(host, &early.host) ||
        memcmp(early.generation, installation.record.generation, 16))) {
        error = retire_generation();
        if (error) goto out;
    }
    if (!early.generation_live) {
        early.host = *host;
        early.deployment = (struct msu_deployment_namespace_record){
            .magic = MSU_DEPLOYMENT_NAMESPACE_MAGIC,
            .schema = MSU_DEPLOYMENT_NAMESPACE_SCHEMA,
            .bytes = sizeof(early.deployment),
        };
        memcpy(early.deployment.name, installation.name, 16);
        if (!msu_deployment_namespace_valid(&early.deployment)) { error = -ESTALE; goto out; }
        memcpy(early.generation, installation.record.generation, 16);
        early.generation_live = true;
    }
    error = early.bind_error[domain];
    if (error) goto out;
    if (early.attempted[domain]) { error = early.domain_error[domain]; goto validate; }
    switch (domain) {
    case 0:
        early.attempted[domain] = true;
        error = msu_early_oem_init(host, &early.deployment, early.generation);
        break;
    case 1:
        error = msu_early_root_backend_create(host, &early.deployment, early.generation, &ops);
        if (error) break;
        early.attempted[domain] = true;
        error = msu_early_root_provider_init(&early.root, host, &early.deployment,
            early.generation, &ops);
        break;
    default:
        error = msu_early_selinux_backend_init(host, &early.deployment, early.generation);
        if (error) break;
        early.attempted[domain] = true;
        error = msu_early_selinux_init(host, &early.deployment);
        break;
    }
    early.domain_error[domain] = error;
validate:
    if (error) goto out;
    /* Registration itself changes no target. If installation revoke won before
     * registration, the second held read sees that change and retires this late
     * registration before command31 is allowed to invoke any provider. */
    error = installation_current(host, &final);
    if (!error && (memcmp(final.record.generation, early.generation, 16) ||
        memcmp(final.name, early.deployment.name, 16))) error = -ESTALE;
    if (error) {
        int cleanup = retire_generation();
        if (cleanup) early.domain_error[domain] = cleanup;
    }
out:
    mutex_unlock(&msu_early_runtime_lock);
    return error;
}

int msu_early_runtime_close(void)
{
    int error;
    mutex_lock(&msu_early_runtime_lock);
    early.closed = true;
    error = retire_generation();
    mutex_unlock(&msu_early_runtime_lock);
    return error;
}

int msu_early_runtime_discarded(void)
{
    int error;
    mutex_lock(&msu_early_runtime_lock);
    error = early.generation_live ? -EINPROGRESS : 0;
    mutex_unlock(&msu_early_runtime_lock);
    return error;
}
