/*
 * Hop plan + one-attempt state machine. Pure logic: no I/O, no device calls.
 *
 * Two layers live here on purpose:
 *
 *   1. A plan is the ordered, immutable description of the hops the design
 *      fixes (H-0..H-7), each with its verification kind and bounded retry
 *      budget. A plan carries no device values and executes nothing.
 *
 *   2. A machine is the run-time contract around one attempt: explicit method,
 *      explicit backend, an exclusively created one-shot carrier, and at most
 *      one attempt per boot. It refuses to reach success unless a restore step
 *      was verified first (C5/D-8), and it routes every failure that may have
 *      touched the kernel window into the restore state instead of "clean up
 *      later".
 *
 * Device binding is deliberately absent. `struct msk_ops` is the seam a later
 * phase fills with real syscalls; P0 only validates that a binding is complete,
 * and nothing in this directory calls one (G-P0-2/G-P0-5 make that structural).
 */
#ifndef MSK_PLAN_H
#define MSK_PLAN_H

#include <stddef.h>
#include <stdint.h>

#include "msk_spec.h"

#ifdef __cplusplus
extern "C" {
#endif

#define MSK_PLAN_VERSION 1u
#define MSK_PLAN_STEPS 9u
#define MSK_PLAN_DIGEST_BYTES 32u

/*
 * Hops of the design's hop table (H-0, H-2..H-5) plus the restore hop that the
 * design folded into H-3. Restore is promoted to its own ordered hop because
 * C5/D-8 require it to be verified by reading the value back, not merely
 * planned; removing it must be impossible rather than "remembered".
 */
enum msk_hop {
	MSK_HOP_ELIGIBILITY = 0, /* H-0: exact target, explicit method/backend */
	MSK_HOP_PRIMITIVE = 1,   /* H-2: provider stages W1/W2/W3              */
	MSK_HOP_SELINUX = 2,     /* H-3: enforcing observation                 */
	MSK_HOP_CRED = 3,        /* H-4a: child cred + uid verification         */
	MSK_HOP_SECCOMP = 4,     /* H-4b: filter clear + load probe             */
	MSK_HOP_RESTORE = 5,     /* C5/D-8: restore body + readback evidence    */
	MSK_HOP_HANDOVER = 6,    /* H-4c: single-shot dispatch to the consumer  */
	MSK_HOP_READY = 7,       /* H-5: kernel-produced token                  */
	MSK_HOP_COUNT = 8
};

/*
 * How a hop is judged. There is no "it did not crash" verdict: every step must
 * name a predicate, and msk_plan_validate() rejects a plan containing NONE.
 */
enum msk_verify {
	MSK_VERIFY_NONE = 0,
	MSK_VERIFY_PRECONDITION = 1,          /* eligibility / dispatch gates     */
	MSK_VERIFY_PROVIDER_FRAME = 2,        /* provider status frame r<rc>:...  */
	MSK_VERIFY_ENFORCE_NODE_READBACK = 3, /* read the enforcing node back      */
	MSK_VERIFY_CHILD_UID = 4,             /* child reports uid 0              */
	MSK_VERIFY_SECCOMP_MODE = 5,          /* child reports no filter          */
	MSK_VERIFY_LOAD_PROBE = 6,            /* module-load probe errno only     */
	MSK_VERIFY_RESTORE_READBACK = 7,      /* restore values read back         */
	MSK_VERIFY_MAGIC_ROUNDTRIP = 8,       /* kernel-produced token            */
	MSK_VERIFY_COUNT = 9
};

struct msk_step {
	uint8_t hop;
	uint8_t verify;
	uint8_t mandatory;
	uint8_t reserved;
	uint32_t max_rounds; /* bounded; never "retry until it works" */
	uint32_t settle_us;  /* pause between bounded rounds          */
};

/* Plan flags that encode the invariants rather than leaving them to prose. */
enum msk_plan_flag {
	MSK_PLAN_F_ONE_ATTEMPT_PER_BOOT = 1u << 0,
	MSK_PLAN_F_CARRIER_ONE_SHOT = 1u << 1,
	MSK_PLAN_F_RESTORE_MANDATORY = 1u << 2,
	MSK_PLAN_F_READY_KERNEL_TOKEN = 1u << 3,
	MSK_PLAN_F_ALL = 0x0000000Fu
};

struct msk_plan {
	uint32_t version;
	uint32_t flags;
	size_t count;
	struct msk_step steps[MSK_PLAN_STEPS];
	uint8_t spec_digest[MSK_SPEC_DIGEST_BYTES];
	uint8_t plan_digest[MSK_PLAN_DIGEST_BYTES];
};

enum msk_plan_status {
	MSK_PLAN_OK = 0,
	MSK_PLAN_EINVAL = -40,
	MSK_PLAN_INCOMPLETE = -41, /* binding cannot describe every hop      */
	MSK_PLAN_TAMPERED = -42,   /* structure differs from the fixed table  */
	MSK_PLAN_EBINDING = -43    /* binding fails msk_spec_validate         */
};

/*
 * Compile a validated binding into the fixed plan and digest it. Refuses an
 * invalid binding (MSK_PLAN_EBINDING) or a missing release (MSK_PLAN_INCOMPLETE).
 * Never emits a step with MSK_VERIFY_NONE.
 */
int msk_plan_build(const struct msk_binding *binding, struct msk_plan *out);

/*
 * Structural check against the fixed table, including digest recomputation and
 * the presence of the mandatory restore step. The renderer calls this before
 * emitting a single byte, so a caller cannot hand it a plan that skips restore.
 */
int msk_plan_validate(const struct msk_plan *plan);

const struct msk_step *msk_plan_step(const struct msk_plan *plan, size_t index);

/*
 * Design H-2/P3: the fake page's bit 16 decides whether the 8-byte store would
 * also clear selinux_state.initialized. Returns 1 when the low word is
 * acceptable, 0 when it must be refused before any kernel step. This is a pure
 * predicate over the caller's chosen page address, not a device action.
 */
int msk_plan_page_layout_accepts(uint32_t page_low32);

/* ------------------------------------------------------------------ */
/* One attempt: explicit inputs and the state machine                  */
/* ------------------------------------------------------------------ */

struct msk_attempt {
	uint64_t boot_token;      /* opaque per-boot value; 0 is invalid        */
	const char *method;       /* exactly "ghostlock"                        */
	const char *backend;      /* exactly "hook" (design D-6 third value)    */
	uint32_t one_shot_marker; /* exactly 1: carrier created exclusively     */
};

/*
 * States name the last verified milestone (not "work in progress"). After
 * MSK_STATE_SECCOMP both seccomp verdicts are consumed: the filter verdict
 * (MSK_EV_SECCOMP_OK) moved the machine in, and the load-probe verdict
 * (MSK_EV_LOAD_PROBE_OK/FAIL) moves it to restore.
 */
enum msk_state {
	MSK_STATE_IDLE = 0,
	MSK_STATE_ELIGIBLE,
	MSK_STATE_PRIMITIVE,
	MSK_STATE_SELINUX,
	MSK_STATE_CRED,
	MSK_STATE_SECCOMP,
	MSK_STATE_RESTORE,
	MSK_STATE_HANDOVER,
	MSK_STATE_DONE,
	MSK_STATE_ABORTED,
	MSK_STATE_COUNT
};

enum msk_event {
	MSK_EV_PRIMITIVE_OK = 0,
	MSK_EV_PRIMITIVE_FAIL,
	MSK_EV_SELINUX_OK,
	MSK_EV_SELINUX_FAIL,
	MSK_EV_CRED_OK,
	MSK_EV_CRED_FAIL,
	MSK_EV_SECCOMP_OK,
	MSK_EV_SECCOMP_FAIL,
	MSK_EV_LOAD_PROBE_OK,
	MSK_EV_LOAD_PROBE_FAIL,
	MSK_EV_RESTORE_OK,
	MSK_EV_RESTORE_FAIL,
	MSK_EV_HANDOVER_OK,
	MSK_EV_HANDOVER_FAIL,
	MSK_EV_READY_OK,
	MSK_EV_READY_FAIL,
	MSK_EV_COUNT
};

enum msk_machine_status {
	MSK_SM_OK = 0,
	MSK_SM_EINVAL = -60,
	MSK_SM_ESTATE = -61,    /* event not valid in this state             */
	MSK_SM_EREENTRY = -62,  /* second attempt for the same boot          */
	MSK_SM_EMETHOD = -63,   /* method is not the explicit one            */
	MSK_SM_EBACKEND = -64,  /* backend is not the explicit one            */
	MSK_SM_EMARKER = -65,   /* one-shot carrier marker is not exactly 1  */
	MSK_SM_EREADY = -66,    /* token is not a kernel-shaped readiness one */
	MSK_SM_EBOOT = -67,     /* boot token mismatch                        */
	MSK_SM_ETERMINAL = -68, /* machine already finished                   */
	MSK_SM_ENOATTEMPT = -69 /* no armed attempt                           */
};

struct msk_machine {
	enum msk_state state;
	enum msk_failure failure;
	uint64_t boot_token;
	uint32_t armed;
	uint32_t attempt_used;
	uint32_t flags;
	uint32_t ready_magic;
};

/* Machine flags (observable evidence; not caller-settable). */
enum msk_machine_flag {
	MSK_SM_F_SELINUX_TOUCHED = 1u << 0, /* W1 reached its verified state  */
	MSK_SM_F_RESTORE_VERIFIED = 1u << 1,/* restore evidence read back     */
	MSK_SM_F_HANDOVER_DONE = 1u << 2,    /* consumer dispatch accepted     */
	MSK_SM_F_READY_VERIFIED = 1u << 3,   /* kernel token verified          */
	MSK_SM_F_RESTORE_FAILED = 1u << 4,   /* restore ran and did not verify */
	MSK_SM_F_RESTORE_ROLLBACK = 1u << 5  /* restore entered from failure   */
};

void msk_machine_init(struct msk_machine *machine);

/*
 * Arm one attempt. Refusals:
 *   - method != "ghostlock"   => MSK_SM_EMETHOD
 *   - backend != "hook"       => MSK_SM_EBACKEND
 *   - one_shot_marker != 1    => MSK_SM_EMARKER
 *   - boot token 0 / NULL     => MSK_SM_EINVAL
 *   - already armed this boot => MSK_SM_EREENTRY
 *   - armed under another boot without a reset => MSK_SM_EBOOT
 */
int msk_machine_arm(struct msk_machine *machine,
		    const struct msk_attempt *attempt);

/*
 * Start a new boot after a terminal attempt. Only a terminal machine may be
 * reset, and only to a different boot token: the same boot can never be reused
 * (C9), even after a failure.
 */
int msk_machine_reset(struct msk_machine *machine, uint64_t new_boot_token);

/*
 * Advance one event. `event_boot_token` binds READY_OK to this attempt's boot;
 * `event_magic` must be the magic the caller already accepted with
 * msk_ready_parse() (this layer re-checks non-zero and boot binding only, to
 * keep userspace from minting a token: the parser is accept-only).
 */
int msk_machine_step(struct msk_machine *machine, enum msk_event event,
		     uint64_t event_boot_token, uint32_t event_magic);

const char *msk_state_name(enum msk_state state);
const char *msk_event_name(enum msk_event event);
int msk_machine_succeeded(const struct msk_machine *machine);

/*
 * Highest effect the machine has proven: NONE, KERNEL_WINDOW (W1 verified),
 * HANDED_OVER (consumer dispatched), READY (terminal success). This is the
 * D-2-shaped "did anything happen" answer, derived from evidence flags rather
 * than from the caller's optimism.
 */
enum msk_effect msk_machine_effect(const struct msk_machine *machine);
enum msk_failure msk_machine_failure(const struct msk_machine *machine);

/* ------------------------------------------------------------------ */
/* Device seam (P1/P2 fills this in; P0 only checks completeness)      */
/* ------------------------------------------------------------------ */

struct msk_ops {
	void *context;
	int (*read_enforce)(void *context, int32_t *observed);
	int (*read_checkreqprot)(void *context, int32_t *observed);
	int (*dispatch_consumer)(void *context, const char *script_path);
	int (*read_ready_token)(void *context, char *line, size_t capacity,
				size_t *used);
};

/*
 * MSK_OK when every callback is present, MSK_ENOTIMPL otherwise. P0 has no
 * binding and no call site; the point of this function is that "is this layer
 * allowed to act?" is answerable without any device access.
 */
int msk_ops_ready(const struct msk_ops *ops);

#ifdef __cplusplus
}
#endif
#endif /* MSK_PLAN_H */
