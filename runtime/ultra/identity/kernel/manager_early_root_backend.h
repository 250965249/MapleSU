// SPDX-License-Identifier: GPL-3.0-only
#ifndef MAPLESU_MANAGER_EARLY_ROOT_BACKEND_H
#define MAPLESU_MANAGER_EARLY_ROOT_BACKEND_H
#include "manager_early_root.h"
/* Boot captures native resolvers only. Construction neither publishes text
 * nor changes credentials; command 31 is the existing authenticated caller. */
int msu_early_root_backend_target_bind(unsigned long (*lookup)(const char *),
    int (*resolve_cfi)(const char *, const void *, unsigned long *));
int msu_early_root_backend_create(const maplesu_host_instance *host,
    const struct msu_deployment_namespace_record *deployment,
    const unsigned char generation[16], struct msu_early_root_ops *ops);
#endif
