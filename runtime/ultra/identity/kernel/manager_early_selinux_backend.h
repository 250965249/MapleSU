// SPDX-License-Identifier: GPL-3.0-only
#ifndef MAPLESU_MANAGER_EARLY_SELINUX_BACKEND_H
#define MAPLESU_MANAGER_EARLY_SELINUX_BACKEND_H
#include "manager_early_selinux.h"

/* Boot qualification reads only fixed symbols and their native lock anchors.
 * The installation generation is captured later, after helper authentication. */
int msu_early_selinux_backend_bind(unsigned long (*lookup)(const char *),
    int (*resolve_cfi)(const char *, const void *, unsigned long *));
int msu_early_selinux_backend_init(const maplesu_host_instance *host,
    const struct msu_deployment_namespace_record *deployment,
    const unsigned char generation[16]);
int msu_early_selinux_backend_discarded(void);
#endif
