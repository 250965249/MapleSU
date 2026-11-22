/*
 * Plan compilation and the one-attempt state machine.
 *
 * Invariants are encoded as refusals, not as comments:
 *   - the plan table is fixed and digested; a mutated plan is TAMPERED;
 *   - restore is a mandatory step that sits before handover in the plan;
 *   - the machine can only reach DONE through a verified restore event;
 *   - every failure that may have touched the kernel window enters RESTORE;
 *   - one boot token can arm exactly one attempt, ever;
 *   - method/backend/marker are explicit and exactly one value each.
 *
 * No I/O, no device call, no allocation. ASCII-only.
 */
#include "msk_digest.h"
#include "msk_plan.h"

/* Fixed plan table. Comments record where each budget comes from. */
static const struct msk_step MSK_STEP_TABLE[MSK_PLAN_STEPS] = {
	/* H-0: admission is decided before any kernel action. */
	{ (uint8_t)MSK_HOP_ELIGIBILITY, (uint8_t)MSK_VERIFY_PRECONDITION, 1u, 0u,
	  1u, 0u },
	/* H-2: external provider stages; its own status frame is the verdict. */
	{ (uint8_t)MSK_HOP_PRIMITIVE, (uint8_t)MSK_VERIFY_PROVIDER_FRAME, 1u, 0u,
	  1u, 0u },
	/* H-3: 15 rounds with a 100 ms settle (design H-3). */
	{ (uint8_t)MSK_HOP_SELINUX, (uint8_t)MSK_VERIFY_ENFORCE_NODE_READBACK, 1u,
	  0u, 15u, 100000u },
	/* H-4a: 15 rounds with a 100 ms settle (design H-4). */
	{ (uint8_t)MSK_HOP_CRED, (uint8_t)MSK_VERIFY_CHILD_UID, 1u, 0u, 15u,
	  100000u },
	/* H-4b: three chains of six attempts (design H-4 W3). */
	{ (uint8_t)MSK_HOP_SECCOMP, (uint8_t)MSK_VERIFY_SECCOMP_MODE, 1u, 0u, 18u,
	  1000u },
	/* H-4b probe: errno-only precondition for the stage-2 load (design #11). */
	{ (uint8_t)MSK_HOP_SECCOMP, (uint8_t)MSK_VERIFY_LOAD_PROBE, 1u, 0u, 1u,
	  0u },
	/* C5/D-8: restore evidence must be read back before any handover. */
	{ (uint8_t)MSK_HOP_RESTORE, (uint8_t)MSK_VERIFY_RESTORE_READBACK, 1u, 0u,
	  1u, 0u },
	/* H-4c: one dispatch to the consumer, then no more kernel actions. */
	{ (uint8_t)MSK_HOP_HANDOVER, (uint8_t)MSK_VERIFY_PRECONDITION, 1u, 0u, 1u,
	  0u },
	/* H-5: 3 s window sampled every 100 ms (design H-5). */
	{ (uint8_t)MSK_HOP_READY, (uint8_t)MSK_VERIFY_MAGIC_ROUNDTRIP, 1u, 0u, 30u,
	  100000u }
};

static const char MSK_PLAN_DOMAIN[] = "MSK1-PLAN/v1";

static void msk_zero(void *destination, size_t length)
{
	unsigned char *bytes = (unsigned char *)destination;
	size_t index;

	for (index = 0; index < length; ++index)
		bytes[index] = 0;
}

static int msk_text_equals(const char *text, const char *expected)
{
	size_t index = 0;

	if (text == 0 || expected == 0)
		return 0;
	while (expected[index] != '\0') {
		if (text[index] != expected[index])
			return 0;
		++index;
	}
	return text[index] == '\0';
}

static int msk_step_equals(const struct msk_step *left,
			   const struct msk_step *right)
{
	return left->hop == right->hop && left->verify == right->verify &&
	       left->mandatory == right->mandatory &&
	       left->max_rounds == right->max_rounds &&
	       left->settle_us == right->settle_us;
}

static void msk_update_u32(struct msk_sha256 *context, uint32_t value)
{
	uint8_t bytes[4];

	bytes[0] = (uint8_t)value;
	bytes[1] = (uint8_t)(value >> 8);
	bytes[2] = (uint8_t)(value >> 16);
	bytes[3] = (uint8_t)(value >> 24);
	msk_sha256_update(context, bytes, sizeof(bytes));
}

static void msk_compute_plan_digest(const struct msk_plan *plan,
				    uint8_t out[MSK_PLAN_DIGEST_BYTES])
{
	struct msk_sha256 context;
	size_t index;

	msk_sha256_init(&context);
	msk_sha256_update(&context, MSK_PLAN_DOMAIN, sizeof(MSK_PLAN_DOMAIN) - 1U);
	msk_update_u32(&context, plan->version);
	msk_update_u32(&context, plan->flags);
	msk_sha256_update(&context, plan->spec_digest, MSK_SPEC_DIGEST_BYTES);
	for (index = 0; index < MSK_PLAN_STEPS; ++index) {
		const struct msk_step *step = &plan->steps[index];
		uint8_t head[4];

		head[0] = step->hop;
		head[1] = step->verify;
		head[2] = step->mandatory;
		head[3] = step->reserved;
		msk_sha256_update(&context, head, sizeof(head));
		msk_update_u32(&context, step->max_rounds);
		msk_update_u32(&context, step->settle_us);
	}
	msk_sha256_final(&context, out);
}

int msk_plan_build(const struct msk_binding *binding, struct msk_plan *out)
{
	size_t index;

	if (binding == 0 || out == 0)
		return MSK_PLAN_EINVAL;
	if (binding->release[0] == '\0')
		return MSK_PLAN_INCOMPLETE;
	if (msk_spec_validate(binding) != MSK_OK)
		return MSK_PLAN_EBINDING;

	msk_zero(out, sizeof(*out));
	out->version = MSK_PLAN_VERSION;
	out->flags = (uint32_t)MSK_PLAN_F_ALL;
	out->count = MSK_PLAN_STEPS;
	for (index = 0; index < MSK_PLAN_STEPS; ++index)
		out->steps[index] = MSK_STEP_TABLE[index];
	if (msk_spec_digest(binding, out->spec_digest) != MSK_OK)
		return MSK_PLAN_EBINDING;
	msk_compute_plan_digest(out, out->plan_digest);
	return MSK_PLAN_OK;
}

int msk_plan_validate(const struct msk_plan *plan)
{
	uint8_t digest[MSK_PLAN_DIGEST_BYTES];
	size_t index;
	int saw_restore = 0;

	if (plan == 0)
		return MSK_PLAN_EINVAL;
	if (plan->version != MSK_PLAN_VERSION)
		return MSK_PLAN_TAMPERED;
	if (plan->flags != (uint32_t)MSK_PLAN_F_ALL)
		return MSK_PLAN_TAMPERED;
	if (plan->count != MSK_PLAN_STEPS)
		return MSK_PLAN_TAMPERED;

	for (index = 0; index < MSK_PLAN_STEPS; ++index) {
		if (!msk_step_equals(&plan->steps[index], &MSK_STEP_TABLE[index]))
			return MSK_PLAN_TAMPERED;
		if (plan->steps[index].verify == (uint8_t)MSK_VERIFY_NONE)
			return MSK_PLAN_TAMPERED;
		if (plan->steps[index].mandatory != 1u)
			return MSK_PLAN_TAMPERED;
		if (plan->steps[index].hop == (uint8_t)MSK_HOP_RESTORE &&
		    plan->steps[index].verify ==
			    (uint8_t)MSK_VERIFY_RESTORE_READBACK)
			saw_restore = 1;
	}
	if (!saw_restore)
		return MSK_PLAN_TAMPERED;

	{
		int any = 0;

		for (index = 0; index < MSK_SPEC_DIGEST_BYTES; ++index)
			any = any || plan->spec_digest[index] != 0;
		if (!any)
			return MSK_PLAN_TAMPERED;
	}

	msk_compute_plan_digest(plan, digest);
	for (index = 0; index < MSK_PLAN_DIGEST_BYTES; ++index) {
		if (digest[index] != plan->plan_digest[index])
			return MSK_PLAN_TAMPERED;
	}
	return MSK_PLAN_OK;
}

const struct msk_step *msk_plan_step(const struct msk_plan *plan, size_t index)
{
	if (plan == 0 || index >= plan->count || index >= MSK_PLAN_STEPS)
		return 0;
	return &plan->steps[index];
}

int msk_plan_page_layout_accepts(uint32_t page_low32)
{
	/*
	 * The store writes an 8-byte, page-aligned pointer. Byte 2 of that value
	 * is bit 16 of the page address; when it is even the write also clears
	 * selinux_state.initialized, which silently breaks SID lookups. Our
	 * upstream rejects that page; the plan refuses it before any step runs.
	 */
	return (page_low32 & 0x00010000u) != 0 ? 1 : 0;
}

/* ------------------------------------------------------------------ */
/* One-attempt state machine                                           */
/* ------------------------------------------------------------------ */

void msk_machine_init(struct msk_machine *machine)
{
	if (machine == 0)
		return;
	msk_zero(machine, sizeof(*machine));
	machine->state = MSK_STATE_IDLE;
	machine->failure = MSK_FAILURE_NONE;
}

static int msk_machine_is_terminal(const struct msk_machine *machine)
{
	return machine->state == MSK_STATE_DONE ||
	       machine->state == MSK_STATE_ABORTED;
}

int msk_machine_arm(struct msk_machine *machine,
		    const struct msk_attempt *attempt)
{
	if (machine == 0 || attempt == 0)
		return MSK_SM_EINVAL;
	if (attempt->boot_token == 0 || attempt->method == 0 ||
	    attempt->backend == 0)
		return MSK_SM_EINVAL;
	if (!msk_text_equals(attempt->method, "ghostlock"))
		return MSK_SM_EMETHOD;
	if (!msk_text_equals(attempt->backend, "hook"))
		return MSK_SM_EBACKEND;
	if (attempt->one_shot_marker != 1u)
		return MSK_SM_EMARKER;

	if (msk_machine_is_terminal(machine)) {
		if (attempt->boot_token == machine->boot_token)
			return MSK_SM_EREENTRY;
		return MSK_SM_ETERMINAL;
	}
	if (machine->state != MSK_STATE_IDLE) {
		if (attempt->boot_token == machine->boot_token)
			return MSK_SM_EREENTRY;
		return MSK_SM_EBOOT;
	}
	if (machine->attempt_used != 0u)
		return MSK_SM_EREENTRY;
	if (machine->boot_token != 0 &&
	    attempt->boot_token != machine->boot_token)
		return MSK_SM_EBOOT;

	machine->boot_token = attempt->boot_token;
	machine->armed = 1u;
	machine->attempt_used = 1u;
	machine->state = MSK_STATE_ELIGIBLE;
	machine->failure = MSK_FAILURE_NONE;
	machine->flags = 0u;
	machine->ready_magic = 0u;
	return MSK_SM_OK;
}

int msk_machine_reset(struct msk_machine *machine, uint64_t new_boot_token)
{
	if (machine == 0 || new_boot_token == 0)
		return MSK_SM_EINVAL;
	if (!msk_machine_is_terminal(machine))
		return MSK_SM_ETERMINAL;
	if (new_boot_token == machine->boot_token)
		return MSK_SM_EREENTRY;

	machine->boot_token = new_boot_token;
	machine->state = MSK_STATE_IDLE;
	machine->failure = MSK_FAILURE_NONE;
	machine->armed = 0u;
	machine->attempt_used = 0u;
	machine->flags = 0u;
	machine->ready_magic = 0u;
	return MSK_SM_OK;
}

static int msk_machine_fail_to_restore(struct msk_machine *machine,
				       enum msk_failure failure)
{
	if (machine->failure == MSK_FAILURE_NONE)
		machine->failure = failure;
	machine->flags |= (uint32_t)MSK_SM_F_RESTORE_ROLLBACK;
	machine->state = MSK_STATE_RESTORE;
	return MSK_SM_OK;
}

static int msk_machine_abort(struct msk_machine *machine,
			     enum msk_failure failure)
{
	if (machine->failure == MSK_FAILURE_NONE)
		machine->failure = failure;
	machine->state = MSK_STATE_ABORTED;
	return MSK_SM_OK;
}

int msk_machine_step(struct msk_machine *machine, enum msk_event event,
		     uint64_t event_boot_token, uint32_t event_magic)
{
	if (machine == 0)
		return MSK_SM_EINVAL;
	if (machine->armed == 0u)
		return MSK_SM_ENOATTEMPT;
	if (msk_machine_is_terminal(machine))
		return MSK_SM_ETERMINAL;

	switch (machine->state) {
	case MSK_STATE_ELIGIBLE:
		if (event == MSK_EV_PRIMITIVE_OK) {
			machine->state = MSK_STATE_PRIMITIVE;
			return MSK_SM_OK;
		}
		if (event == MSK_EV_PRIMITIVE_FAIL)
			return msk_machine_fail_to_restore(machine,
							   MSK_FAILURE_PROVIDER);
		return MSK_SM_ESTATE;

	case MSK_STATE_PRIMITIVE:
		if (event == MSK_EV_SELINUX_OK) {
			machine->flags |= (uint32_t)MSK_SM_F_SELINUX_TOUCHED;
			machine->state = MSK_STATE_SELINUX;
			return MSK_SM_OK;
		}
		if (event == MSK_EV_SELINUX_FAIL)
			return msk_machine_fail_to_restore(machine,
							   MSK_FAILURE_SELINUX);
		return MSK_SM_ESTATE;

	case MSK_STATE_SELINUX:
		if (event == MSK_EV_CRED_OK) {
			machine->state = MSK_STATE_CRED;
			return MSK_SM_OK;
		}
		if (event == MSK_EV_CRED_FAIL)
			return msk_machine_fail_to_restore(machine,
							   MSK_FAILURE_CRED);
		return MSK_SM_ESTATE;

	case MSK_STATE_CRED:
		if (event == MSK_EV_SECCOMP_OK) {
			machine->state = MSK_STATE_SECCOMP;
			return MSK_SM_OK;
		}
		if (event == MSK_EV_SECCOMP_FAIL)
			return msk_machine_fail_to_restore(machine,
							   MSK_FAILURE_SECCOMP);
		return MSK_SM_ESTATE;

	case MSK_STATE_SECCOMP:
		if (event == MSK_EV_LOAD_PROBE_OK) {
			/* Planned path: restore is now mandatory and next. */
			machine->state = MSK_STATE_RESTORE;
			return MSK_SM_OK;
		}
		if (event == MSK_EV_LOAD_PROBE_FAIL)
			return msk_machine_fail_to_restore(machine,
							   MSK_FAILURE_LOAD_PROBE);
		return MSK_SM_ESTATE;

	case MSK_STATE_RESTORE:
		if (event == MSK_EV_RESTORE_OK) {
			machine->flags |= (uint32_t)MSK_SM_F_RESTORE_VERIFIED;
			/* A rollback ends here; a planned restore goes to handover. */
			if ((machine->flags & (uint32_t)MSK_SM_F_RESTORE_ROLLBACK) != 0)
				return msk_machine_abort(machine,
							 machine->failure);
			machine->state = MSK_STATE_HANDOVER;
			return MSK_SM_OK;
		}
		if (event == MSK_EV_RESTORE_FAIL) {
			machine->flags |= (uint32_t)MSK_SM_F_RESTORE_FAILED;
			return msk_machine_abort(machine,
						 MSK_FAILURE_RESTORE_FAILED);
		}
		return MSK_SM_ESTATE;

	case MSK_STATE_HANDOVER:
		if (event == MSK_EV_HANDOVER_OK) {
			machine->flags |= (uint32_t)MSK_SM_F_HANDOVER_DONE;
			/* Same state name: handover verified, readiness pending. */
			return MSK_SM_OK;
		}
		if (event == MSK_EV_HANDOVER_FAIL)
			return msk_machine_abort(machine, MSK_FAILURE_HANDOVER);
		if (event == MSK_EV_READY_OK) {
			if (machine->flags & (uint32_t)MSK_SM_F_HANDOVER_DONE) {
				if (event_magic == 0u)
					return msk_machine_abort(
						machine,
						MSK_FAILURE_READY_WRONG_MAGIC);
				if (event_boot_token != machine->boot_token)
					return msk_machine_abort(
						machine,
						MSK_FAILURE_READY_WRONG_BOOT);
				machine->ready_magic = event_magic;
				machine->flags |= (uint32_t)MSK_SM_F_READY_VERIFIED;
				machine->state = MSK_STATE_DONE;
				return MSK_SM_OK;
			}
			return MSK_SM_ESTATE;
		}
		if (event == MSK_EV_READY_FAIL)
			return msk_machine_abort(machine, MSK_FAILURE_READY_ABSENT);
		return MSK_SM_ESTATE;

	default:
		return MSK_SM_ESTATE;
	}
}

const char *msk_state_name(enum msk_state state)
{
	switch (state) {
	case MSK_STATE_IDLE:
		return "idle";
	case MSK_STATE_ELIGIBLE:
		return "eligible";
	case MSK_STATE_PRIMITIVE:
		return "primitive";
	case MSK_STATE_SELINUX:
		return "selinux";
	case MSK_STATE_CRED:
		return "cred";
	case MSK_STATE_SECCOMP:
		return "seccomp";
	case MSK_STATE_RESTORE:
		return "restore";
	case MSK_STATE_HANDOVER:
		return "handover";
	case MSK_STATE_DONE:
		return "done";
	case MSK_STATE_ABORTED:
		return "aborted";
	default:
		return "unknown";
	}
}

const char *msk_event_name(enum msk_event event)
{
	switch (event) {
	case MSK_EV_PRIMITIVE_OK:
		return "primitive_ok";
	case MSK_EV_PRIMITIVE_FAIL:
		return "primitive_fail";
	case MSK_EV_SELINUX_OK:
		return "selinux_ok";
	case MSK_EV_SELINUX_FAIL:
		return "selinux_fail";
	case MSK_EV_CRED_OK:
		return "cred_ok";
	case MSK_EV_CRED_FAIL:
		return "cred_fail";
	case MSK_EV_SECCOMP_OK:
		return "seccomp_ok";
	case MSK_EV_SECCOMP_FAIL:
		return "seccomp_fail";
	case MSK_EV_LOAD_PROBE_OK:
		return "load_probe_ok";
	case MSK_EV_LOAD_PROBE_FAIL:
		return "load_probe_fail";
	case MSK_EV_RESTORE_OK:
		return "restore_ok";
	case MSK_EV_RESTORE_FAIL:
		return "restore_fail";
	case MSK_EV_HANDOVER_OK:
		return "handover_ok";
	case MSK_EV_HANDOVER_FAIL:
		return "handover_fail";
	case MSK_EV_READY_OK:
		return "ready_ok";
	case MSK_EV_READY_FAIL:
		return "ready_fail";
	default:
		return "unknown";
	}
}

int msk_machine_succeeded(const struct msk_machine *machine)
{
	return machine != 0 && machine->state == MSK_STATE_DONE;
}

enum msk_effect msk_machine_effect(const struct msk_machine *machine)
{
	enum msk_effect from_failure;

	if (machine == 0)
		return MSK_EFFECT_NONE;
	if (machine->state == MSK_STATE_DONE &&
	    (machine->flags & (uint32_t)MSK_SM_F_READY_VERIFIED) != 0)
		return MSK_EFFECT_READY;
	if ((machine->flags & (uint32_t)MSK_SM_F_HANDOVER_DONE) != 0)
		return MSK_EFFECT_HANDED_OVER;
	if ((machine->flags & (uint32_t)MSK_SM_F_SELINUX_TOUCHED) != 0)
		return MSK_EFFECT_KERNEL_WINDOW;
	from_failure = msk_failure_effect(machine->failure);
	if (from_failure != MSK_EFFECT_NONE)
		return from_failure;
	return MSK_EFFECT_NONE;
}

enum msk_failure msk_machine_failure(const struct msk_machine *machine)
{
	if (machine == 0)
		return MSK_FAILURE_NONE;
	return machine->failure;
}

int msk_ops_ready(const struct msk_ops *ops)
{
	if (ops == 0)
		return MSK_ENOTIMPL;
	if (ops->read_enforce == 0 || ops->read_checkreqprot == 0 ||
	    ops->dispatch_consumer == 0 || ops->read_ready_token == 0)
		return MSK_ENOTIMPL;
	return MSK_OK;
}
