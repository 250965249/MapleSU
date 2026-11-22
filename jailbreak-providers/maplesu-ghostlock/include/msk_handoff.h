/*
 * Handover bytes + readiness token contract. Pure: renders text, parses text.
 *
 * The renderer produces the exact bytes of the script that a later phase may
 * write to a one-shot carrier, but it never writes a file and never starts a
 * process. The write (exclusive create) and the dispatch belong to
 * jailbreak-providers/ghostlock/adapter/handoff.cpp, which already owns that
 * responsibility and its TR gate.
 *
 * Restore is a hard precondition of handover here, not a courtesy:
 *   - the plan must carry the mandatory restore step (msk_plan_validate);
 *   - the restore body must declare, in order, the stages that prove a
 *     baseline was captured, policy was repaired, enforcing was written and
 *     read back;
 *   - the emitted script refuses to hand over when the readback is missing or
 *     does not equal the expected enforcing value (exit before exec).
 * The reference implementation does none of this (it leaves SELinux permissive
 * and prints a note); this layer deliberately cannot express that behaviour.
 *
 * Readiness: accept-only. There is intentionally no formatter in this API,
 * because a userspace formatter would let software mint its own success token
 * (design R-9/C10). The magic value is ours, not the reference value.
 */
#ifndef MSK_HANDOFF_H
#define MSK_HANDOFF_H

#include <stddef.h>
#include <stdint.h>

#include "msk_plan.h"

#ifdef __cplusplus
extern "C" {
#endif

#define MSK_HANDOFF_BODY_MAX 8192u
#define MSK_HANDOFF_SCRIPT_MAX 16384u
#define MSK_HANDOFF_PATH_MAX 512u
#define MSK_HANDOFF_ARG_MAX 512u
#define MSK_HANDOFF_ARGC_MAX 32u
#define MSK_ATTEMPT_ID_MAX 64u
#define MSK_HANDOFF_MARKER_COUNT 6u

enum msk_handoff_status {
	MSK_HANDOFF_OK = 0,
	MSK_HANDOFF_EINVAL = -80,
	MSK_HANDOFF_EPLAN = -81,          /* plan missing/tampered/incomplete  */
	MSK_HANDOFF_ESTRING = -82,        /* path/id/arg fails its grammar      */
	MSK_HANDOFF_ERESTORE_WEAK = -83,  /* body does not prove the stages     */
	MSK_HANDOFF_ECONSUMER = -84       /* consumer argv contract violated    */
};

struct msk_handoff_input {
	const char *interpreter;   /* absolute shell path for the #! line      */
	const char *home_dir;      /* absolute per-attempt home                */
	const char *attempt_id;    /* [A-Za-z0-9._-]{1,64}                     */
	const char *consumer_path; /* absolute                                 */
	const char *const *consumer_argv; /* consumer_argc entries, borrowed    */
	size_t consumer_argc;      /* 0..MSK_HANDOFF_ARGC_MAX                  */
	const char *restore_body;  /* shell text; see the marker contract      */
	size_t restore_body_length;
	int32_t baseline_enforcing;     /* -2 absent, -1 unreadable, 0/1 observed */
	int32_t baseline_checkreqprot;  /* same encoding                          */
	char origin;               /* 'o' observed / 'd' documented baseline   */
};

/*
 * Render the script.
 *
 * `*used` receives the byte length of the script excluding the terminating NUL.
 * Success requires capacity >= used + 1. On MSK_EOVERFLOW nothing is written,
 * buffer[0] is set to NUL when capacity > 0, and `*used` receives the required
 * capacity (script bytes + 1) so the caller can allocate exactly once.
 *
 * The restore body marker contract (exact lines, this order):
 *     # MSK-RESTORE:begin
 *     # MSK-RESTORE:baseline
 *     # MSK-RESTORE:policy
 *     # MSK-RESTORE:enforce
 *     # MSK-RESTORE:readback
 *     # MSK-RESTORE:end
 * The readback stage must print exactly one line to stdout: "<enforcing>:<checkreqprot>",
 * each field one of 0, 1, 2, u. Diagnostics stay on stderr; stdout is the
 * evidence channel. This is the C5/D-8 shape: a run is not a restoration.
 */
int msk_handoff_render(const struct msk_plan *plan,
		       const struct msk_handoff_input *input,
		       char *buffer, size_t capacity, size_t *used);

/*
 * Readiness token grammar:
 *     "MSK-READY/1 " <magic:16 hex> " " <boot_tag:16 hex> [ "\n" | "\r\n" ]
 * The magic is MSK_READY_MAGIC (a value this project owns; the reference
 * implementation's value is not used). The boot tag must equal the attempt's
 * boot token, so a token captured from another boot cannot be replayed.
 */
#define MSK_READY_PREFIX "MSK-READY/1 "
#define MSK_READY_HEX_DIGITS 16u
#define MSK_READY_MAGIC 0x4D534B52u /* "MSKR"; kernel-side constant, ours */
#define MSK_READY_LINE_MAX 48u

enum msk_ready_status {
	MSK_READY_OK = 0,
	MSK_READY_ABSENT = -90,       /* no token line at all                */
	MSK_READY_MALFORMED = -91,    /* token-like line with a broken shape */
	MSK_READY_WRONG_MAGIC = -92,  /* stale or software-minted magic      */
	MSK_READY_WRONG_BOOT = -93    /* token belongs to another boot       */
};

int msk_ready_parse(const char *line, size_t length,
		    uint64_t expected_boot_tag, uint32_t *out_magic);

/* Map any layer's status code onto the shared failure taxonomy. */
enum msk_failure msk_failure_from_status(int status);

#ifdef __cplusplus
}
#endif
#endif /* MSK_HANDOFF_H */
