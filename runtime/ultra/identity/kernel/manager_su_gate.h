// SPDX-License-Identifier: GPL-3.0-only
#ifndef MAPLESU_MANAGER_SU_GATE_H
#define MAPLESU_MANAGER_SU_GATE_H
#include <linux/types.h>
#include "request_protocol.h"
#define MSU_SU_GATE_BYTES 1024U
#define MSU_SU_PAYLOAD_BYTES 64U
/* Fixed native no-FP callback frame. All GPRs, original LR and NZCV survive
 * enter/leave; a payload may change only the actual intercepted arguments. */
struct msu_su_gate_frame { u64 x[31], nzcv; };
_Static_assert(sizeof(struct msu_su_gate_frame) == 256, "SU gate frame");
int msu_su_gate_build(u32 *output, u32 capacity, u64 address,
    const maplesu_publication_control_v3 *control, u32 instruction,
    u32 executed_prefix, u32 *written);
int msu_su_payload_build(u32 *output, u32 capacity, u64 callback, u64 context);
bool msu_su_gate_instruction(u32 instruction);
#endif
