/* SPDX-License-Identifier: GPL-3.0-only */
#ifndef MAPLESU_ULTRA_PREINIT_H
#define MAPLESU_ULTRA_PREINIT_H
#include <linux/types.h>
int msu_preinit_start(void);
void msu_preinit_release(void);
bool msu_preinit_execve(const void *args, long (*original)(const void *), long *result);
#endif
