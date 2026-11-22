/* SPDX-License-Identifier: GPL-3.0-only */
#ifndef MAPLESU_INIT_BRIDGE_NATIVE_CFI_H
#define MAPLESU_INIT_BRIDGE_NATIVE_CFI_H

#ifndef __has_feature
#define __has_feature(name) 0
#endif
/* Kbuild passes the actual C compiler's feature state to assembly, whose
 * normal flags do not contain the C sanitizer options. */
#if defined(__ASSEMBLY__)
#ifndef MSU_INIT_BRIDGE_CC_HAS_KCFI
#error "Native CFI assembly requires the actual C compiler feature state"
#endif
#elif __has_feature(kcfi)
#define MSU_INIT_BRIDGE_CC_HAS_KCFI 1
#else
#define MSU_INIT_BRIDGE_CC_HAS_KCFI 0
#endif

/* Older KCFI kernels can expose CONFIG_CFI_CLANG without CFI_TRAPS. Keep the
 * established legacy fallback; compiler feature names other than kcfi are
 * not assumed. Never treat a protected legacy target as no-CFI. */
#if MSU_INIT_BRIDGE_CC_HAS_KCFI || defined(CONFIG_CFI) || \
    (defined(CONFIG_CFI_CLANG) && defined(CONFIG_ARCH_USES_CFI_TRAPS))
#define MSU_INIT_BRIDGE_CFI_KCFI 1
#define MSU_INIT_BRIDGE_CFI_LEGACY 0
#define MSU_INIT_BRIDGE_CFI_NONE 0
#elif defined(CONFIG_CFI_CLANG)
#define MSU_INIT_BRIDGE_CFI_KCFI 0
#define MSU_INIT_BRIDGE_CFI_LEGACY 1
#define MSU_INIT_BRIDGE_CFI_NONE 0
#elif defined(CONFIG_KCFI)
#error "Unqualified target KCFI configuration: native CFI contract required"
#else
#define MSU_INIT_BRIDGE_CFI_KCFI 0
#define MSU_INIT_BRIDGE_CFI_LEGACY 0
#define MSU_INIT_BRIDGE_CFI_NONE 1
#endif

#if MSU_INIT_BRIDGE_CFI_KCFI && !defined(__ASSEMBLY__)
#include <linux/cfi.h>
#endif
#endif
