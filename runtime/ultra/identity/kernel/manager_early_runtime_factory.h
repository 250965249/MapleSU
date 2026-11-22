// SPDX-License-Identifier: GPL-3.0-only
#ifndef MAPLESU_MANAGER_EARLY_RUNTIME_FACTORY_H
#define MAPLESU_MANAGER_EARLY_RUNTIME_FACTORY_H
#include <linux/types.h>
#include "request_protocol.h"
/* Boot captures only fixed native resolvers. No text, status or app state changes. */
int msu_early_runtime_target_bind(unsigned long (*lookup)(const char *),
    int (*resolve_cfi)(const char *, const void *, unsigned long *));
/* Called only after the existing helper session has authenticated its lease. */
int msu_early_runtime_activate(const maplesu_host_instance *host, u32 operation);
/* Host discard closes admission before management/service table teardown. */
int msu_early_runtime_close(void);
int msu_early_runtime_discarded(void);
#endif
