/* SPDX-License-Identifier: GPL-3.0-only */
#ifndef MAPLESU_INIT_BRIDGE_NATIVE_LOOKUP_H
#define MAPLESU_INIT_BRIDGE_NATIVE_LOOKUP_H

/* Module initialization, before any SDK/service exposure. No user address or
 * symbol address is accepted. A failed qualification leaves lookup closed. */
int msu_init_bridge_lookup_init(void);
unsigned long msu_init_bridge_lookup(const char *name);
int msu_init_bridge_resolve_cfi(const char *name, const void *prototype,
    unsigned long *address);
#endif
