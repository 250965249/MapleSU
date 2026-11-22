// SPDX-License-Identifier: GPL-3.0-only
#pragma once
#include <stdint.h>

/* Private factory output, never a reinterpretation of the legacy control word.
 * P2 publishes this immutable binding only after qualifying the native entry,
 * context, host/controller and runtime gate closure. Context and entry remain
 * boot-live through the branch-before-enter window and final gate retirement.
 * A scalar address/descriptor supplied by a Manager is not a factory binding. */
struct msu_su_native_reader_binding {
    uint32_t schema;
    uint32_t bytes;
    uint64_t entry;
    uint64_t context;
    uint64_t host_low;
    uint64_t host_high;
    uint64_t controller;
};
#define MSU_SU_NATIVE_READER_SCHEMA 1U
#ifdef __cplusplus
static_assert(sizeof(msu_su_native_reader_binding) == 48);
#endif

/* Native entry ABI: u64 entry(const void *context). Exactly 1 permits discovery;
 * zero includes denial, unavailable source, stale controller and unsupported
 * context. It never grants credentials. The emitter preserves its caller's ABI
 * and x0-x18/LR as required by the actual hook; CFI type comes from this entry.
 * Execution separately holds a kernel lease through the unique cred core's
 * final return. A discovery result is never reused as an execution ticket. */
