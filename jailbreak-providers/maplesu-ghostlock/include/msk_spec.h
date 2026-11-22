/*
 * MSK1 - the spec carrier for one exact kernel release.
 *
 * This is MapleSU's own schema (design section 5 P0.2), not the reference
 * implementation's wide layout table: 13 required keys, no compile-time
 * defaults, no optional keys, no numeric fallback of any kind. A key that is
 * missing, duplicated, unknown or out of its documented bound refuses the whole
 * binding, so a partially parsed spec can never be mistaken for a usable one.
 *
 * Everything here is pure: no file, no sysfs, no process, no allocation. The
 * caller decides where the text came from; this layer only decides whether it
 * is an acceptable binding, and digests it when it is.
 *
 * Failure model (design section 5 P0): a wrong release or a malformed spec is refused
 * BEFORE any kernel-side action, so it maps to effect NONE below.
 *
 * ASCII-only source; the Linux release string is bytes, not a locale string.
 */
#ifndef MSK_SPEC_H
#define MSK_SPEC_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define MSK_SPEC_VERSION 1u
#define MSK_RELEASE_MAX 128u
#define MSK_SPEC_KEY_MAX 32u
#define MSK_SPEC_KEY_COUNT 13u
#define MSK_SPEC_DIGEST_BYTES 32u

/* Bounds that are part of the carrier contract, not of any device value. */
#define MSK_SPEC_MAX_BYTES 4096u
#define MSK_SPEC_MAX_LINE 256u
#define MSK_SPEC_IMAGE_LIMIT (64ULL * 1024ULL * 1024ULL)
#define MSK_SPEC_TASK_LIMIT 4096ULL

/*
 * Status codes. Negative is failure; zero is success. Values are part of the
 * P0 interface and are append-only: adding a code is fine, renumbering is not.
 */
enum msk_status {
	MSK_OK = 0,
	MSK_EINVAL = -1,       /* NULL, empty value, not key=value, bad digit    */
	MSK_EINCOMPLETE = -2,  /* at least one required key absent               */
	MSK_EUNSUPPORTED = -3, /* release (or version) not accepted              */
	MSK_ERANGE = -4,       /* value outside its documented bound             */
	MSK_EOVERFLOW = -5,    /* output buffer too small (render/digest text)   */
	MSK_EUNKNOWNKEY = -6,  /* key not in the MSK1 schema                     */
	MSK_EDUPLICATE = -7,   /* key appeared more than once                    */
	MSK_ETOOLARGE = -8,    /* input, line, or field exceeds its size bound   */
	MSK_EBADVERSION = -9,  /* version key present but not MSK_SPEC_VERSION   */
	MSK_ERELATION = -10,   /* two keys contradict a documented relation      */
	MSK_ENOTIMPL = -11     /* device binding absent (P1/P2); P0 never calls  */
};

/* Sentinel for "no schema key" in diagnostics. */
#define MSK_SPEC_KEY_NONE 0xFFFFFFFFu

/*
 * Optional parse diagnostics. Pointers are not stored; key identity is an index
 * into the schema (see msk_spec_key_name), so the caller can format its own
 * message without borrowing this layer's storage.
 */
struct msk_spec_diag {
	uint32_t line;          /* 1-based line of the failure; 0 = whole input  */
	uint32_t offset;        /* byte offset of the failing token              */
	uint32_t key_length;    /* length of the key token at offset             */
	uint32_t key_index;     /* schema index, or MSK_SPEC_KEY_NONE            */
	uint64_t missing_mask;  /* bit i = schema key i is missing               */
	uint64_t duplicate_mask;/* bit i = schema key i appeared more than once  */
};

/*
 * One binding == one exact `uname -r`. All offsets are image-relative or
 * struct-relative; the address derivation belongs to the plan layer.
 */
struct msk_binding {
	uint32_t version;
	char release[MSK_RELEASE_MAX];   /* exact release, NUL-terminated        */
	uint64_t kernel_phys_load;       /* runtime physical load of the image   */
	uint64_t kernel_phys_offset;     /* reference physical load (slide base) */
	uint64_t page_offset;            /* direct-map/page-offset alias base    */
	uint64_t selinux_enforcing_off;  /* image offset of the enforcing byte   */
	uint64_t init_cred_off;          /* image offset of init_cred            */
	uint64_t task_real_cred_off;     /* task_struct: real_cred pointer       */
	uint64_t task_cred_off;          /* task_struct: cred pointer            */
	uint64_t task_seccomp_off;       /* task_struct: seccomp.mode            */
	uint64_t task_comm_off;          /* task_struct: comm[]                  */
	int32_t waiter_shift;            /* pselect waiter word shift            */
	uint32_t kernelsnitch_collisions;/* spray collision budget               */
};

/*
 * Parse MSK1 text into a binding. The output is written only on success: on
 * every failure path `*out` is left exactly as the caller passed it, so a stale
 * or partially filled binding cannot leak into a plan.
 *
 * Text grammar, deliberately tiny:
 *   - one `key=value` per line; LF terminators; one trailing CR per line is
 *     stripped (a CRLF-written spec must not silently break release matching);
 *   - a line whose first byte is `#` is a comment; blank lines are ignored;
 *   - no inline comments, no quoting, no hex, no sign except a leading `-` for
 *     signed keys, no leading/trailing whitespace in the value;
 *   - unknown key => MSK_EUNKNOWNKEY (never ignored).
 */
int msk_spec_parse(const char *text, size_t length, struct msk_binding *out);
int msk_spec_parse_ex(const char *text, size_t length, struct msk_binding *out,
		      struct msk_spec_diag *diag);

/*
 * Validate bounds and relations of an already parsed binding. This is the same
 * check the parser applies last; it is public so a caller that assembles a
 * binding from a contract file still gets the identical refusal.
 */
int msk_spec_validate(const struct msk_binding *binding);

/*
 * Eligibility: the spec must name the running release byte-for-byte. No major
 * version matching, no suffix matching, no "close enough" (design H-1).
 * Returns MSK_OK or MSK_EUNSUPPORTED.
 */
int msk_spec_accept_release(const struct msk_binding *binding,
			    const char *running_release);

/*
 * Content digest over the canonical form documented in README.md:
 *   "MSK1-BINDING/v1" || u32le version || u16le release_length || release
 *   || nine u64le fields (phys_load, phys_offset, page_offset,
 *      selinux_enforcing_off, init_cred_off, task_real_cred_off,
 *      task_cred_off, task_seccomp_off, task_comm_off)
 *   || i32le waiter_shift || u32le kernelsnitch_collisions
 * It is a content digest, never an authenticator (no key material).
 */
int msk_spec_digest(const struct msk_binding *binding,
		    uint8_t out[MSK_SPEC_DIGEST_BYTES]);

/* Schema as data: enumeration is stable and matches the canonical order. */
size_t msk_spec_key_count(void);
const char *msk_spec_key_name(size_t index);
int msk_spec_key_required(size_t index);

/* Digest of the schema itself (names, order, requiredness, kinds, bounds). */
int msk_spec_schema_digest(uint8_t out[MSK_SPEC_DIGEST_BYTES]);

/*
 * Failure taxonomy shared by every layer (design D-2 shape: "did anything
 * happen?" must be answerable from the failure alone).
 */
enum msk_failure {
	MSK_FAILURE_NONE = 0,
	MSK_FAILURE_SPEC_UNSUPPORTED,
	MSK_FAILURE_SPEC_INVALID,
	MSK_FAILURE_ELIGIBILITY,
	MSK_FAILURE_PROVIDER,
	MSK_FAILURE_SELINUX,
	MSK_FAILURE_CRED,
	MSK_FAILURE_SECCOMP,
	MSK_FAILURE_LOAD_PROBE,
	MSK_FAILURE_RESTORE_WEAK,
	MSK_FAILURE_RESTORE_FAILED,
	MSK_FAILURE_HANDOVER,
	MSK_FAILURE_READY_ABSENT,
	MSK_FAILURE_READY_MALFORMED,
	MSK_FAILURE_READY_WRONG_MAGIC,
	MSK_FAILURE_READY_WRONG_BOOT,
	MSK_FAILURE_NO_OPS,
	MSK_FAILURE_COUNT
};

/*
 * What a failure proves may have happened:
 *   NONE           nothing acted on the kernel (safe to re-decide, still bound
 *                  by the one-attempt-per-boot rule);
 *   KERNEL_WINDOW  the kernel window may have been touched; restore applies and
 *                  a retry needs a new boot (C9);
 *   HANDED_OVER    the consumer was started; a retry needs a new boot;
 *   READY          terminal success (only reachable through the machine).
 */
enum msk_effect {
	MSK_EFFECT_NONE = 0,
	MSK_EFFECT_KERNEL_WINDOW,
	MSK_EFFECT_HANDED_OVER,
	MSK_EFFECT_READY
};

const char *msk_failure_name(enum msk_failure failure);
enum msk_effect msk_failure_effect(enum msk_failure failure);
int msk_failure_needs_restore(enum msk_failure failure);

#ifdef __cplusplus
}
#endif
#endif /* MSK_SPEC_H */
