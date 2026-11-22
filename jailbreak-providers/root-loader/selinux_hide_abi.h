/* SPDX-License-Identifier: GPL-3.0-only */
#ifndef MAPLESU_JAILBREAK_SELINUX_HIDE_ABI_H
#define MAPLESU_JAILBREAK_SELINUX_HIDE_ABI_H

/* This control operation grants no credentials. Only an already marked root
 * subject may query or initialize it. The two words are protocol tags, not keys. */
#define MSU_STATUS_OP 2u
#define MSU_STATUS_TAG_LO 0x53554c53u
#define MSU_STATUS_TAG_HI 0x31574956u
#define MSU_STATUS_QUERY 0u
#define MSU_STATUS_INITIALIZE 1u
#define MSU_STATUS_SET 2u
#define MSU_STATUS_AVAILABLE 1u
#define MSU_STATUS_CAN_SET 2u
#define MSU_STATUS_ACK 0x41434b34u
#define MSU_STATUS_VERSION 4u
#define MSU_STATUS_BASELINE_SNAPSHOT 0u
#define MSU_STATUS_BASELINE_WINDOW 1u
#define MSU_STATUS_BASELINE_DEFAULT 2u
#define MSU_STATUS_RUNTIME_BTF 1u
#define MSU_STATUS_RUNTIME_ANCHORS 2u
#define MSU_STATUS_ANCHOR_WORDS 16u

struct msu_selinux_status {
    unsigned int version, sequence, enforcing, policyload, deny_unknown;
};

struct msu_selinux_window_file {
    struct msu_selinux_status start, end;
    unsigned int restore_from, restore_to;
};

/* Resolved before requesting initialization; consumed by the same kernel payload
 * on every layout. Function ABI 0 takes no arguments, ABI 1 takes selinux_state. */
struct msu_selinux_layout {
    unsigned int source, state_size, status_lock, mutex_size, page_bytes, status_page_abi;
};

struct msu_selinux_anchors {
    unsigned long long page_function, enforce_function, mutex_lock, state;
    unsigned int page_code[MSU_STATUS_ANCHOR_WORDS], enforce_code[MSU_STATUS_ANCHOR_WORDS];
};

/* A narrow no-BTF fallback, not arbitrary instruction rewriting. Track either
 * the native state argument or an ADRP/ADR-derived global to mutex_lock. The
 * module supplies its resolved selinux_state address; user code chooses none. */
static inline int msu_status_lock_anchor(const unsigned int *code,
    unsigned long long address, unsigned long long mutex, unsigned long long state,
    unsigned int *offset, unsigned int *state_argument)
{
    unsigned long long value[31];
    unsigned int known[31], i;
    for (i = 0; i < 31; ++i) { known[i] = 0; value[i] = 0; }
    known[0] = 1; /* Symbolic state argument; 2 means a concrete PC-relative VA. */
    for (i = 0; i < MSU_STATUS_ANCHOR_WORDS; ++i) {
        unsigned int word = code[i], rd = word & 31u, rn = (word >> 5) & 31u;
        if ((word & 0xfc000000u) == 0x94000000u) {
            long long relative = (long long)(word & 0x3ffffffu);
            unsigned long long lock;
            if (relative & 0x2000000) relative -= 0x4000000;
            if (address + i * 4 + relative * 4 != mutex) return 0;
            if (known[0] == 1) lock = value[0];
            else if (known[0] == 2 && state && value[0] >= state) lock = value[0] - state;
            else return 0;
            if (lock < 8 || lock > 65536 || (lock & 7)) return 0;
            *offset = (unsigned int)lock;
            *state_argument = known[0] == 1;
            return 1;
        }
        if (((word & 0x9f000000u) == 0x90000000u ||
             (word & 0x9f000000u) == 0x10000000u) && rd < 31) {
            long long relative = ((word >> 29) & 3u) | ((long long)((word >> 5) & 0x7ffffu) << 2);
            if (relative & 0x100000) relative -= 0x200000;
            value[rd] = (word & 0x80000000u) ?
                ((address + i * 4) & ~4095ULL) + relative * 4096 : address + i * 4 + relative;
            known[rd] = 2;
        } else if ((word & 0xff000000u) == 0x91000000u && rd < 31) {
            unsigned int shift = (word >> 22) & 1u;
            known[rd] = rn < 31 ? known[rn] : 0;
            value[rd] = (rn < 31 ? value[rn] : 0) + (((word >> 10) & 4095u) << (shift ? 12 : 0));
        } else if ((word & 0x7fe0ffe0u) == 0x2a0003e0u && rd < 31) {
            unsigned int rm = (word >> 16) & 31u;
            known[rd] = (word >> 31) && rm < 31 ? known[rm] : 0;
            value[rd] = rm < 31 ? value[rm] : 0;
        } else if (word == 0xd503233fu || word == 0xd503237fu ||
                   word == 0xd503245fu || word == 0xd503201fu || word == 0xf800865eu) {
            /* PAC/BTI, ftrace NOP and shadow-call-stack prologue. */
        } else if (rn == 31 && !(word & (1u << 22)) &&
                   ((word & 0x3b000000u) == 0x29000000u ||
                    (word & 0x3b000000u) == 0x39000000u)) {
            /* Integer register saves to the stack do not change tracked GPRs. */
        } else if ((word & 0xff0003ffu) == 0xd10003ffu ||
                   (word & 0xff0003ffu) == 0x910003ffu) {
            /* SUB/ADD SP,SP only changes the stack pointer. */
        } else return 0;
    }
    return 0;
}

static inline int msu_status_layout_from_anchors(const struct msu_selinux_anchors *anchors,
    unsigned int page_bytes, struct msu_selinux_layout *layout)
{
    unsigned int page_lock, enforce_lock, page_argument, enforce_argument;
    if (!anchors->page_function || !anchors->enforce_function || !anchors->mutex_lock ||
        !msu_status_lock_anchor(anchors->page_code, anchors->page_function, anchors->mutex_lock, anchors->state, &page_lock, &page_argument) ||
        !msu_status_lock_anchor(anchors->enforce_code, anchors->enforce_function, anchors->mutex_lock, anchors->state, &enforce_lock, &enforce_argument) ||
        page_lock != enforce_lock) return 0;
    layout->source = MSU_STATUS_RUNTIME_ANCHORS;
    /* These sizes are not known without type metadata, and not used to
     * allocate/copy objects. Do not invent them from a reference kernel. */
    layout->state_size = layout->mutex_size = 0;
    layout->status_lock = page_lock;
    layout->page_bytes = page_bytes;
    layout->status_page_abi = page_argument;
    return 1;
}

static inline int msu_status_layout_valid(const struct msu_selinux_layout *layout)
{
    if ((layout->page_bytes != 4096 && layout->page_bytes != 16384 && layout->page_bytes != 65536) ||
        (layout->status_lock & 7u) || layout->status_page_abi > 1) return 0;
    if (layout->source == MSU_STATUS_RUNTIME_ANCHORS)
        return !layout->state_size && !layout->mutex_size &&
            layout->status_lock >= 8 && layout->status_lock <= 65536;
    return layout->source == MSU_STATUS_RUNTIME_BTF &&
        layout->state_size >= 16 && layout->state_size <= 65536 &&
        layout->mutex_size >= 8 && layout->mutex_size <= 1024 && !(layout->mutex_size & 7u) &&
        layout->status_lock <= layout->state_size &&
        layout->mutex_size <= layout->state_size - layout->status_lock;
}

struct msu_selinux_hide {
    unsigned int version, command, requested, acknowledged;
    int result;
    unsigned int available, initialized, effective;
    struct msu_selinux_layout layout;
    struct msu_selinux_status baseline, before, after;
    struct msu_selinux_anchors anchors;
    unsigned int baseline_kind, allow_default, restore_from, restore_to;
    struct msu_selinux_status window_end;
};

static inline int msu_status_stock_valid(const struct msu_selinux_status *status)
{
    return status->version == 1 && !(status->sequence & 1u) &&
        status->enforcing == 1 && status->deny_unknown <= 1;
}

/* A raw snapshot proves no policy transactions. A rooted repair window also
 * records its end, so unrelated later events are not mistaken for jailbreak
 * history. Unsigned differences allow a single counter wrap, not stale history. */
static inline int msu_status_baseline_valid(const struct msu_selinux_status *baseline,
                                           const struct msu_selinux_status *live)
{
    return msu_status_stock_valid(baseline) && msu_status_stock_valid(live) &&
        baseline->sequence <= live->sequence &&
        baseline->policyload == live->policyload && baseline->deny_unknown == live->deny_unknown;
}

static inline int msu_status_window_delta(const struct msu_selinux_hide *request,
    const struct msu_selinux_status *live, unsigned int *delta)
{
    const struct msu_selinux_status *start = &request->baseline, *end = &request->window_end;
    unsigned int restore = request->restore_from != request->restore_to ? 2u : 0u;
    unsigned int repair = end->sequence - start->sequence, later = live->sequence - end->sequence;
    if (!msu_status_stock_valid(start) || !msu_status_stock_valid(end) ||
        !msu_status_stock_valid(live) || request->restore_from > 1 || request->restore_to != 1 ||
        start->deny_unknown != end->deny_unknown || repair >= 0x80000000u - restore ||
        end->policyload - start->policyload >= 0x80000000u ||
        later < restore || later >= 0x80000000u || live->policyload - end->policyload >= 0x80000000u ||
        (later == restore && (live->policyload != end->policyload || live->deny_unknown != end->deny_unknown)))
        return 0;
    *delta = repair + restore;
    return 1;
}

#endif
