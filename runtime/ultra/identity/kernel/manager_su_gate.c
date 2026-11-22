// SPDX-License-Identifier: GPL-3.0-only
#include <linux/errno.h>
#include <linux/string.h>
#include "manager_su_gate.h"

struct msu_su_encoder { u32 *words, capacity, count; int error; };
static void emit(struct msu_su_encoder *e, u32 word)
{
    if (e->error) return;
    if (e->count == e->capacity) { e->error = -E2BIG; return; }
    e->words[e->count++] = word;
}
/* Same MODULE movz/movk materialisation, using fixed four-word slots so every
 * runtime address is explicit and bounded; no user instruction enters here. */
static void address(struct msu_su_encoder *e, u32 reg, u64 value)
{
    u32 shift;
    for (shift = 0; shift < 4; ++shift)
        emit(e, (shift ? 0xf2800000U : 0xd2800000U) |
            (shift << 21) | (((value >> (shift * 16)) & 0xffffU) << 5) | reg);
}
static void save(struct msu_su_encoder *e)
{
    u32 r;
    emit(e, 0xd10403ffU); /* sub sp,sp,#256 */
    for (r = 0; r < 30; r += 2)
        emit(e, 0xa9000000U | ((r & 0x7fU) << 15) | ((r + 1) << 10) | (31U << 5) | r);
    emit(e, 0xf9007bfeU); /* str x30,[sp,#240] */
    emit(e, 0xd53b4209U); /* mrs x9,nzcv */
    emit(e, 0xf9007fe9U); /* str x9,[sp,#248] */
}
static void restore(struct msu_su_encoder *e)
{
    u32 r;
    emit(e, 0xf9407fe9U); /* ldr x9,[sp,#248] */
    emit(e, 0xd51b4209U); /* msr nzcv,x9 */
    for (r = 0; r < 30; r += 2)
        emit(e, 0xa9400000U | ((r & 0x7fU) << 15) | ((r + 1) << 10) | (31U << 5) | r);
    emit(e, 0xf9407bfeU);
    emit(e, 0x910403ffU); /* add sp,sp,#256 */
}
static bool branch(u64 from, u64 to, u32 *word)
{
    s64 delta;
    if ((from | to) & 3U) return false;
    if (to >= from) {
        if (to - from > 0x7fffffcULL) return false;
        delta = to - from;
    } else {
        if (from - to > 0x8000000ULL) return false;
        delta = -(s64)(from - to);
    }
    *word = 0x14000000U | (((u64)(delta / 4)) & 0x3ffffffU);
    return true;
}
bool msu_su_gate_instruction(u32 word)
{
    /* Position-independent prologue subset only. The existing MODULE emitter
     * has wider relocation; this native producer rejects the other shapes. */
    return word == 0xd503201fU ||
        (word & 0x1f000000U) == 0x11000000U || /* ADD/SUB immediate */
        (word & 0x3e000000U) == 0x28000000U || /* integer pair load/store */
        (word & 0x3b000000U) == 0x39000000U || /* integer load/store immediate */
        (word & 0x3b000000U) == 0x38000000U || /* integer pre/post-index, SCS prologue */
        (word & 0x7fe0ffe0U) == 0x2a0003e0U || /* MOV register */
        word == 0xd503233fU || word == 0xd503237fU ||
        word == 0xd503231fU || word == 0xd503235fU; /* PAC prologue */
}
static u32 authenticate(u32 prefix)
{
    switch (prefix) {
    case 0xd503231fU: case 0xd503239fU: return 0xd503239fU;
    case 0xd503233fU: case 0xd50323bfU: return 0xd50323bfU;
    case 0xd503235fU: case 0xd50323dfU: return 0xd50323dfU;
    case 0xd503237fU: case 0xd50323ffU: return 0xd50323ffU;
    default: return 0;
    }
}
int msu_su_gate_build(u32 *output, u32 capacity, u64 base,
    const maplesu_publication_control_v3 *control, u32 instruction,
    u32 prefix, u32 *written)
{
    struct msu_su_encoder e = { output, capacity / 4, 0, 0 };
    u32 denied, early, normal, exit, word, auth;
    if (!written) return -EINVAL;
    *written = 0;
    if (!output || !control || capacity < MSU_SU_GATE_BYTES || (base & 3U) ||
        base > ~0ULL - MSU_SU_GATE_BYTES || !control->publication_id ||
        control->schema != 1 || control->length != sizeof(*control) || control->reserved ||
        !control->enter_function || !control->leave_function || !control->payload_entry ||
        ((control->enter_function | control->leave_function | control->payload_entry) & 3U) ||
        control->entry_address > ~0ULL - 4 || control->resume_address != control->entry_address + 4 ||
        !msu_su_gate_instruction(instruction)) return -EOPNOTSUPP;
    memset(output, 0, capacity);
    save(&e);
    address(&e, 0, control->publication_id);
    address(&e, 16, control->enter_function);
    emit(&e, 0xd63f0200U); /* blr x16, returns pinned payload or zero */
    denied = e.count; emit(&e, 0); /* cbz x0,normal */
    emit(&e, 0xaa0003f0U); /* mov x16,x0 */
    emit(&e, 0x910003e0U); /* x0 is the actual saved frame */
    emit(&e, 0xd63f0200U);
    emit(&e, 0xaa0003f3U); /* x19 is callee-saved across leave */
    address(&e, 0, control->publication_id);
    address(&e, 16, control->leave_function);
    emit(&e, 0xd63f0200U);
    early = e.count; emit(&e, 0); /* cbnz x19,early-return */
    normal = e.count;
    restore(&e);
    emit(&e, instruction);
    if (!branch(base + (u64)e.count * 4, control->resume_address, &word)) return -ERANGE;
    emit(&e, word);
    exit = e.count;
    restore(&e);
    auth = authenticate(prefix);
    if (auth) emit(&e, auth);
    emit(&e, 0xd65f03c0U);
    if (e.error) return e.error;
    output[denied] = 0xb4000000U | ((normal - denied) << 5);
    output[early] = 0xb5000013U | ((exit - early) << 5);
    *written = e.count * 4;
    return 0;
}
int msu_su_payload_build(u32 *output, u32 capacity, u64 callback, u64 context)
{
    struct msu_su_encoder e = { output, capacity / 4, 0, 0 };
    if (!output || capacity < MSU_SU_PAYLOAD_BYTES || !callback || (callback & 3U) || !context)
        return -EINVAL;
    memset(output, 0, capacity);
    emit(&e, 0xd503245fU); /* BTI C */
    address(&e, 1, context);
    address(&e, 16, callback);
    emit(&e, 0xd61f0200U); /* tail call preserves return into permanent gate */
    return e.error;
}
