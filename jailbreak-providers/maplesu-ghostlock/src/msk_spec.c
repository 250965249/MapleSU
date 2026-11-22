/*
 * MSK1 spec carrier: strict parse, strict validate, content digest.
 *
 * Pure translation unit: no headers beyond <stddef.h>/<stdint.h>, no libc, no
 * allocation, no I/O. The schema is data (MSK_SCHEMA) and the parser is one
 * generic loop over it, so an added key is an added table row rather than a
 * branch somebody can forget to validate.
 */
#include "msk_digest.h"
#include "msk_spec.h"

enum msk_field {
	MSK_FIELD_VERSION = 0,
	MSK_FIELD_RELEASE,
	MSK_FIELD_PHYS_LOAD,
	MSK_FIELD_PHYS_OFFSET,
	MSK_FIELD_PAGE_OFFSET,
	MSK_FIELD_SELINUX,
	MSK_FIELD_INIT_CRED,
	MSK_FIELD_REAL_CRED,
	MSK_FIELD_CRED,
	MSK_FIELD_SECCOMP,
	MSK_FIELD_COMM,
	MSK_FIELD_WAITER,
	MSK_FIELD_COLLISIONS,
	MSK_FIELD_COUNT
};

enum msk_kind {
	MSK_KIND_TEXT = 0,
	MSK_KIND_U64 = 1,
	MSK_KIND_I32 = 2
};

struct msk_key_def {
	const char *name;
	uint16_t name_length;
	uint8_t required;
	uint8_t kind;
	uint64_t lower;
	uint64_t upper;
	uint8_t field;
};

/*
 * Schema order is the canonical order: it is the order in which missing bits are
 * reported, the order of msk_spec_key_name(), and the order of the schema
 * digest. Field numbers are intentionally identical to indices; the test suite
 * asserts it so a future insert cannot silently desynchronise diagnostics.
 */
static const struct msk_key_def MSK_SCHEMA[MSK_SPEC_KEY_COUNT] = {
	{ "msk_spec_version", 16u, 1u, MSK_KIND_U64, 1u, 1u,
	  (uint8_t)MSK_FIELD_VERSION },
	{ "release", 7u, 1u, MSK_KIND_TEXT, 1u, MSK_RELEASE_MAX - 1u,
	  (uint8_t)MSK_FIELD_RELEASE },
	{ "kernel_phys_load", 16u, 1u, MSK_KIND_U64, 1u, 0xFFFFFFFFFFFFFFFFULL,
	  (uint8_t)MSK_FIELD_PHYS_LOAD },
	{ "kernel_phys_offset", 18u, 1u, MSK_KIND_U64, 1u, 0xFFFFFFFFFFFFFFFFULL,
	  (uint8_t)MSK_FIELD_PHYS_OFFSET },
	{ "page_offset", 11u, 1u, MSK_KIND_U64, 1u, 0xFFFFFFFFFFFFFFFFULL,
	  (uint8_t)MSK_FIELD_PAGE_OFFSET },
	{ "selinux_enforcing_off", 21u, 1u, MSK_KIND_U64, 0u,
	  MSK_SPEC_IMAGE_LIMIT - 1u, (uint8_t)MSK_FIELD_SELINUX },
	{ "init_cred_off", 13u, 1u, MSK_KIND_U64, 0u, MSK_SPEC_IMAGE_LIMIT - 1u,
	  (uint8_t)MSK_FIELD_INIT_CRED },
	{ "task_real_cred_off", 18u, 1u, MSK_KIND_U64, 1u,
	  MSK_SPEC_TASK_LIMIT - 1u, (uint8_t)MSK_FIELD_REAL_CRED },
	{ "task_cred_off", 13u, 1u, MSK_KIND_U64, 1u, MSK_SPEC_TASK_LIMIT - 1u,
	  (uint8_t)MSK_FIELD_CRED },
	{ "task_seccomp_off", 16u, 1u, MSK_KIND_U64, 1u,
	  MSK_SPEC_TASK_LIMIT - 1u, (uint8_t)MSK_FIELD_SECCOMP },
	{ "task_comm_off", 13u, 1u, MSK_KIND_U64, 1u, MSK_SPEC_TASK_LIMIT - 1u,
	  (uint8_t)MSK_FIELD_COMM },
	{ "waiter_shift", 12u, 1u, MSK_KIND_I32,
	  (uint64_t)(int64_t)-8, (uint64_t)(int64_t)8, (uint8_t)MSK_FIELD_WAITER },
	{ "kernelsnitch_collisions", 23u, 1u, MSK_KIND_U64, 0u, 64u,
	  (uint8_t)MSK_FIELD_COLLISIONS }
};

#define MSK_ALL_KEYS ((1ULL << MSK_SPEC_KEY_COUNT) - 1ULL)

static void msk_zero(void *destination, size_t length)
{
	unsigned char *bytes = (unsigned char *)destination;
	size_t index;

	for (index = 0; index < length; ++index)
		bytes[index] = 0;
}

static void msk_copy(void *destination, const void *source, size_t length)
{
	unsigned char *out = (unsigned char *)destination;
	const unsigned char *in = (const unsigned char *)source;
	size_t index;

	for (index = 0; index < length; ++index)
		out[index] = in[index];
}

static int msk_bytes_equal(const char *left, const char *right, size_t length)
{
	size_t index;

	for (index = 0; index < length; ++index) {
		if (left[index] != right[index])
			return 0;
	}
	return 1;
}

/* NUL-terminated length with a hard limit; returns 0 when no NUL in range. */
static int msk_bounded_length(const char *text, size_t limit, size_t *out)
{
	size_t index;

	if (text == 0 || out == 0)
		return 0;
	for (index = 0; index < limit; ++index) {
		if (text[index] == '\0') {
			*out = index;
			return 1;
		}
	}
	return 0;
}

static void msk_diag_reset(struct msk_spec_diag *diag)
{
	if (diag == 0)
		return;
	msk_zero(diag, sizeof(*diag));
	diag->key_index = MSK_SPEC_KEY_NONE;
}

static void msk_diag_key(struct msk_spec_diag *diag, uint32_t line,
			 uint32_t offset, uint32_t key_length, uint32_t key_index)
{
	if (diag == 0)
		return;
	diag->line = line;
	diag->offset = offset;
	diag->key_length = key_length;
	diag->key_index = key_index;
}

/* Unsigned decimal only: no sign, no prefix, no spaces, overflow checked. */
static int msk_parse_u64(const char *text, size_t length, uint64_t *out)
{
	uint64_t value = 0;
	size_t index;

	if (length == 0)
		return MSK_EINVAL;
	for (index = 0; index < length; ++index) {
		unsigned int digit;

		if (text[index] < '0' || text[index] > '9')
			return MSK_EINVAL;
		digit = (unsigned int)(text[index] - '0');
		if (value > (UINT64_MAX - digit) / 10U)
			return MSK_ERANGE;
		value = value * 10U + digit;
	}
	*out = value;
	return MSK_OK;
}

/* Signed decimal for the one signed key; magnitude bounded before negation. */
static int msk_parse_i32(const char *text, size_t length, int64_t *out)
{
	uint64_t magnitude = 0;
	int negative = 0;
	int status;

	if (length > 0 && text[0] == '-') {
		negative = 1;
		++text;
		--length;
	}
	status = msk_parse_u64(text, length, &magnitude);
	if (status != MSK_OK)
		return status;
	if (magnitude > 2147483647ULL)
		return MSK_ERANGE;
	*out = negative ? -(int64_t)magnitude : (int64_t)magnitude;
	return MSK_OK;
}

static int msk_store_release(const char *value, size_t length,
			     struct msk_binding *binding)
{
	size_t index;

	if (length == 0)
		return MSK_EINVAL;
	if (length >= MSK_RELEASE_MAX)
		return MSK_ERANGE;
	for (index = 0; index < length; ++index) {
		unsigned char byte = (unsigned char)value[index];

		/* printable, no space, no comment marker, no control bytes */
		if (byte < 0x21U || byte > 0x7EU || byte == '#')
			return MSK_EINVAL;
	}
	msk_copy(binding->release, value, length);
	binding->release[length] = '\0';
	return MSK_OK;
}

static int msk_apply_u64(const struct msk_key_def *def, uint64_t value,
			 struct msk_binding *binding)
{
	switch ((enum msk_field)def->field) {
	case MSK_FIELD_VERSION:
		if (value != MSK_SPEC_VERSION)
			return MSK_EBADVERSION;
		binding->version = (uint32_t)value;
		return MSK_OK;
	case MSK_FIELD_PHYS_LOAD:
		binding->kernel_phys_load = value;
		return MSK_OK;
	case MSK_FIELD_PHYS_OFFSET:
		binding->kernel_phys_offset = value;
		return MSK_OK;
	case MSK_FIELD_PAGE_OFFSET:
		binding->page_offset = value;
		return MSK_OK;
	case MSK_FIELD_SELINUX:
		binding->selinux_enforcing_off = value;
		return MSK_OK;
	case MSK_FIELD_INIT_CRED:
		binding->init_cred_off = value;
		return MSK_OK;
	case MSK_FIELD_REAL_CRED:
		binding->task_real_cred_off = value;
		return MSK_OK;
	case MSK_FIELD_CRED:
		binding->task_cred_off = value;
		return MSK_OK;
	case MSK_FIELD_SECCOMP:
		binding->task_seccomp_off = value;
		return MSK_OK;
	case MSK_FIELD_COMM:
		binding->task_comm_off = value;
		return MSK_OK;
	case MSK_FIELD_COLLISIONS:
		binding->kernelsnitch_collisions = (uint32_t)value;
		return MSK_OK;
	default:
		return MSK_EINVAL;
	}
}

static int msk_apply(const struct msk_key_def *def, const char *value,
		     size_t length, struct msk_binding *binding)
{
	uint64_t number = 0;
	int64_t signed_number = 0;
	int status;

	switch ((enum msk_kind)def->kind) {
	case MSK_KIND_TEXT:
		return msk_store_release(value, length, binding);
	case MSK_KIND_U64:
		status = msk_parse_u64(value, length, &number);
		if (status != MSK_OK)
			return status;
		if ((enum msk_field)def->field == MSK_FIELD_VERSION) {
			if (number != MSK_SPEC_VERSION)
				return MSK_EBADVERSION;
		}
		if (number < def->lower || number > def->upper)
			return MSK_ERANGE;
		return msk_apply_u64(def, number, binding);
	case MSK_KIND_I32:
		status = msk_parse_i32(value, length, &signed_number);
		if (status != MSK_OK)
			return status;
		if (signed_number < (int64_t)def->lower ||
		    signed_number > (int64_t)def->upper)
			return MSK_ERANGE;
		binding->waiter_shift = (int32_t)signed_number;
		return MSK_OK;
	default:
		return MSK_EINVAL;
	}
}

static int msk_validate_ex(const struct msk_binding *binding,
			   struct msk_spec_diag *diag)
{
	size_t release_length = 0;
	size_t index;

	if (binding == 0)
		return MSK_EINVAL;

	if (binding->version != MSK_SPEC_VERSION) {
		msk_diag_key(diag, 0, 0, 0, (uint32_t)MSK_FIELD_VERSION);
		return MSK_EBADVERSION;
	}

	if (!msk_bounded_length(binding->release, MSK_RELEASE_MAX, &release_length)) {
		msk_diag_key(diag, 0, 0, 0, (uint32_t)MSK_FIELD_RELEASE);
		return MSK_EINVAL;
	}
	if (release_length == 0) {
		msk_diag_key(diag, 0, 0, 0, (uint32_t)MSK_FIELD_RELEASE);
		return MSK_EINCOMPLETE;
	}
	for (index = 0; index < release_length; ++index) {
		unsigned char byte = (unsigned char)binding->release[index];

		if (byte < 0x21U || byte > 0x7EU || byte == '#') {
			msk_diag_key(diag, 0, 0, 0, (uint32_t)MSK_FIELD_RELEASE);
			return MSK_EINVAL;
		}
	}

	/* The image is loaded page-aligned; the reference load is too. */
	if (binding->kernel_phys_load == 0 ||
	    (binding->kernel_phys_load & 0xFFFULL) != 0) {
		msk_diag_key(diag, 0, 0, 0, (uint32_t)MSK_FIELD_PHYS_LOAD);
		return MSK_ERANGE;
	}
	if (binding->kernel_phys_offset == 0 ||
	    (binding->kernel_phys_offset & 0xFFFULL) != 0) {
		msk_diag_key(diag, 0, 0, 0, (uint32_t)MSK_FIELD_PHYS_OFFSET);
		return MSK_ERANGE;
	}
	/* page_offset is a base the address derivation ORs into: low bits zero. */
	if (binding->page_offset == 0 ||
	    (binding->page_offset & 0xFFFFULL) != 0) {
		msk_diag_key(diag, 0, 0, 0, (uint32_t)MSK_FIELD_PAGE_OFFSET);
		return MSK_ERANGE;
	}
	if (binding->selinux_enforcing_off >= MSK_SPEC_IMAGE_LIMIT) {
		msk_diag_key(diag, 0, 0, 0, (uint32_t)MSK_FIELD_SELINUX);
		return MSK_ERANGE;
	}
	if (binding->init_cred_off >= MSK_SPEC_IMAGE_LIMIT) {
		msk_diag_key(diag, 0, 0, 0, (uint32_t)MSK_FIELD_INIT_CRED);
		return MSK_ERANGE;
	}
	if (binding->task_real_cred_off == 0 ||
	    (binding->task_real_cred_off & 7ULL) != 0 ||
	    binding->task_real_cred_off >= MSK_SPEC_TASK_LIMIT) {
		msk_diag_key(diag, 0, 0, 0, (uint32_t)MSK_FIELD_REAL_CRED);
		return MSK_ERANGE;
	}
	/* W2 covers the adjacent real_cred/cred pointer pair in one store. */
	if (binding->task_cred_off != binding->task_real_cred_off + 8ULL) {
		msk_diag_key(diag, 0, 0, 0, (uint32_t)MSK_FIELD_CRED);
		return MSK_ERELATION;
	}
	if (binding->task_seccomp_off == 0 ||
	    (binding->task_seccomp_off & 3ULL) != 0 ||
	    binding->task_seccomp_off >= MSK_SPEC_TASK_LIMIT) {
		msk_diag_key(diag, 0, 0, 0, (uint32_t)MSK_FIELD_SECCOMP);
		return MSK_ERANGE;
	}
	if (binding->task_comm_off == 0 ||
	    binding->task_comm_off >= MSK_SPEC_TASK_LIMIT) {
		msk_diag_key(diag, 0, 0, 0, (uint32_t)MSK_FIELD_COMM);
		return MSK_ERANGE;
	}
	if (binding->waiter_shift < -8 || binding->waiter_shift > 8) {
		msk_diag_key(diag, 0, 0, 0, (uint32_t)MSK_FIELD_WAITER);
		return MSK_ERANGE;
	}
	if (binding->kernelsnitch_collisions > 64U) {
		msk_diag_key(diag, 0, 0, 0, (uint32_t)MSK_FIELD_COLLISIONS);
		return MSK_ERANGE;
	}
	return MSK_OK;
}

int msk_spec_validate(const struct msk_binding *binding)
{
	return msk_validate_ex(binding, 0);
}

int msk_spec_parse_ex(const char *text, size_t length, struct msk_binding *out,
		      struct msk_spec_diag *diag)
{
	struct msk_binding scratch;
	uint64_t seen = 0;
	size_t offset = 0;
	uint32_t line = 0;
	int status;

	msk_diag_reset(diag);
	if (text == 0 || out == 0)
		return MSK_EINVAL;

	if (length > MSK_SPEC_MAX_BYTES) {
		if (diag != 0)
			diag->line = 0;
		return MSK_ETOOLARGE;
	}

	msk_zero(&scratch, sizeof(scratch));

	while (offset < length) {
		size_t line_start = offset;
		size_t line_end = offset;
		size_t key_end;
		size_t value_start;
		size_t value_length;
		const struct msk_key_def *def = 0;
		size_t key_index;

		++line;
		while (line_end < length && text[line_end] != '\n')
			++line_end;
		offset = line_end + 1;

		if (line_end - line_start > MSK_SPEC_MAX_LINE) {
			msk_diag_key(diag, line, (uint32_t)line_start, 0,
				     MSK_SPEC_KEY_NONE);
			return MSK_ETOOLARGE;
		}
		if (line_end > line_start && text[line_end - 1] == '\r')
			--line_end;
		if (line_end == line_start)
			continue;
		if (text[line_start] == '#')
			continue;

		key_end = line_start;
		while (key_end < line_end && text[key_end] != '=')
			++key_end;
		if (key_end == line_end) {
			msk_diag_key(diag, line, (uint32_t)line_start,
				     (uint32_t)(line_end - line_start),
				     MSK_SPEC_KEY_NONE);
			return MSK_EINVAL;
		}
		value_start = key_end + 1;
		value_length = line_end - value_start;

		if (key_end == line_start || key_end - line_start > MSK_SPEC_KEY_MAX ||
		    value_length == 0) {
			msk_diag_key(diag, line, (uint32_t)line_start,
				     (uint32_t)(key_end - line_start),
				     MSK_SPEC_KEY_NONE);
			return MSK_EINVAL;
		}

		for (key_index = 0; key_index < MSK_SPEC_KEY_COUNT; ++key_index) {
			if (MSK_SCHEMA[key_index].name_length !=
			    (uint16_t)(key_end - line_start))
				continue;
			if (!msk_bytes_equal(text + line_start,
					     MSK_SCHEMA[key_index].name,
					     key_end - line_start))
				continue;
			def = &MSK_SCHEMA[key_index];
			break;
		}
		if (def == 0) {
			msk_diag_key(diag, line, (uint32_t)line_start,
				     (uint32_t)(key_end - line_start),
				     MSK_SPEC_KEY_NONE);
			return MSK_EUNKNOWNKEY;
		}

		if ((seen & (1ULL << def->field)) != 0) {
			if (diag != 0)
				diag->duplicate_mask |= 1ULL << def->field;
			msk_diag_key(diag, line, (uint32_t)line_start,
				     def->name_length, def->field);
			return MSK_EDUPLICATE;
		}

		status = msk_apply(def, text + value_start, value_length,
				   &scratch);
		if (status != MSK_OK) {
			msk_diag_key(diag, line, (uint32_t)line_start,
				     def->name_length, def->field);
			return status;
		}
		seen |= 1ULL << def->field;
	}

	if (seen != MSK_ALL_KEYS) {
		if (diag != 0) {
			diag->missing_mask = MSK_ALL_KEYS & ~seen;
			diag->line = 0;
		}
		return MSK_EINCOMPLETE;
	}

	status = msk_validate_ex(&scratch, diag);
	if (status != MSK_OK)
		return status;

	*out = scratch;
	return MSK_OK;
}

int msk_spec_parse(const char *text, size_t length, struct msk_binding *out)
{
	return msk_spec_parse_ex(text, length, out, 0);
}

int msk_spec_accept_release(const struct msk_binding *binding,
			    const char *running_release)
{
	size_t binding_length = 0;
	size_t running_length = 0;

	if (binding == 0 || running_release == 0)
		return MSK_EINVAL;
	if (!msk_bounded_length(binding->release, MSK_RELEASE_MAX,
				&binding_length))
		return MSK_EINVAL;
	if (!msk_bounded_length(running_release, MSK_RELEASE_MAX,
				&running_length))
		return MSK_EINVAL;
	if (binding_length != running_length)
		return MSK_EUNSUPPORTED;
	if (binding_length == 0)
		return MSK_EUNSUPPORTED;
	if (!msk_bytes_equal(binding->release, running_release, binding_length))
		return MSK_EUNSUPPORTED;
	return MSK_OK;
}

static void msk_update_u16(struct msk_sha256 *context, uint16_t value)
{
	uint8_t bytes[2];

	bytes[0] = (uint8_t)value;
	bytes[1] = (uint8_t)(value >> 8);
	msk_sha256_update(context, bytes, sizeof(bytes));
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

static void msk_update_u64(struct msk_sha256 *context, uint64_t value)
{
	uint8_t bytes[8];
	size_t index;

	for (index = 0; index < 8; ++index)
		bytes[index] = (uint8_t)(value >> (index * 8U));
	msk_sha256_update(context, bytes, sizeof(bytes));
}

static const char MSK_BINDING_DOMAIN[] = "MSK1-BINDING/v1";
static const char MSK_SCHEMA_DOMAIN[] = "MSK1-SCHEMA/v1";

int msk_spec_digest(const struct msk_binding *binding,
		    uint8_t out[MSK_SPEC_DIGEST_BYTES])
{
	struct msk_sha256 context;
	size_t release_length = 0;

	if (binding == 0 || out == 0)
		return MSK_EINVAL;
	if (!msk_bounded_length(binding->release, MSK_RELEASE_MAX,
				&release_length))
		return MSK_EINVAL;

	msk_sha256_init(&context);
	msk_sha256_update(&context, MSK_BINDING_DOMAIN,
			  sizeof(MSK_BINDING_DOMAIN) - 1U);
	msk_update_u32(&context, binding->version);
	msk_update_u16(&context, (uint16_t)release_length);
	msk_sha256_update(&context, binding->release, release_length);
	msk_update_u64(&context, binding->kernel_phys_load);
	msk_update_u64(&context, binding->kernel_phys_offset);
	msk_update_u64(&context, binding->page_offset);
	msk_update_u64(&context, binding->selinux_enforcing_off);
	msk_update_u64(&context, binding->init_cred_off);
	msk_update_u64(&context, binding->task_real_cred_off);
	msk_update_u64(&context, binding->task_cred_off);
	msk_update_u64(&context, binding->task_seccomp_off);
	msk_update_u64(&context, binding->task_comm_off);
	msk_update_u32(&context, (uint32_t)binding->waiter_shift);
	msk_update_u32(&context, binding->kernelsnitch_collisions);
	msk_sha256_final(&context, out);
	return MSK_OK;
}

size_t msk_spec_key_count(void)
{
	return MSK_SPEC_KEY_COUNT;
}

const char *msk_spec_key_name(size_t index)
{
	if (index >= MSK_SPEC_KEY_COUNT)
		return 0;
	return MSK_SCHEMA[index].name;
}

int msk_spec_key_required(size_t index)
{
	if (index >= MSK_SPEC_KEY_COUNT)
		return -1;
	return MSK_SCHEMA[index].required != 0 ? 1 : 0;
}

int msk_spec_schema_digest(uint8_t out[MSK_SPEC_DIGEST_BYTES])
{
	struct msk_sha256 context;
	size_t index;

	if (out == 0)
		return MSK_EINVAL;

	msk_sha256_init(&context);
	msk_sha256_update(&context, MSK_SCHEMA_DOMAIN,
			  sizeof(MSK_SCHEMA_DOMAIN) - 1U);
	for (index = 0; index < MSK_SPEC_KEY_COUNT; ++index) {
		const struct msk_key_def *def = &MSK_SCHEMA[index];

		msk_update_u16(&context, def->name_length);
		msk_sha256_update(&context, def->name, def->name_length);
		msk_sha256_update(&context, &def->required, 1U);
		msk_sha256_update(&context, &def->kind, 1U);
		msk_update_u64(&context, def->lower);
		msk_update_u64(&context, def->upper);
	}
	msk_sha256_final(&context, out);
	return MSK_OK;
}

const char *msk_failure_name(enum msk_failure failure)
{
	switch (failure) {
	case MSK_FAILURE_NONE:
		return "none";
	case MSK_FAILURE_SPEC_UNSUPPORTED:
		return "spec_unsupported";
	case MSK_FAILURE_SPEC_INVALID:
		return "spec_invalid";
	case MSK_FAILURE_ELIGIBILITY:
		return "eligibility";
	case MSK_FAILURE_PROVIDER:
		return "provider";
	case MSK_FAILURE_SELINUX:
		return "selinux";
	case MSK_FAILURE_CRED:
		return "cred";
	case MSK_FAILURE_SECCOMP:
		return "seccomp";
	case MSK_FAILURE_LOAD_PROBE:
		return "load_probe";
	case MSK_FAILURE_RESTORE_WEAK:
		return "restore_weak";
	case MSK_FAILURE_RESTORE_FAILED:
		return "restore_failed";
	case MSK_FAILURE_HANDOVER:
		return "handover";
	case MSK_FAILURE_READY_ABSENT:
		return "ready_absent";
	case MSK_FAILURE_READY_MALFORMED:
		return "ready_malformed";
	case MSK_FAILURE_READY_WRONG_MAGIC:
		return "ready_wrong_magic";
	case MSK_FAILURE_READY_WRONG_BOOT:
		return "ready_wrong_boot";
	case MSK_FAILURE_NO_OPS:
		return "no_ops";
	default:
		return "unknown";
	}
}

enum msk_effect msk_failure_effect(enum msk_failure failure)
{
	switch (failure) {
	case MSK_FAILURE_PROVIDER:
	case MSK_FAILURE_SELINUX:
	case MSK_FAILURE_CRED:
	case MSK_FAILURE_SECCOMP:
	case MSK_FAILURE_LOAD_PROBE:
	case MSK_FAILURE_RESTORE_FAILED:
	case MSK_FAILURE_READY_ABSENT:
	case MSK_FAILURE_READY_MALFORMED:
	case MSK_FAILURE_READY_WRONG_MAGIC:
	case MSK_FAILURE_READY_WRONG_BOOT:
		return MSK_EFFECT_KERNEL_WINDOW;
	default:
		return MSK_EFFECT_NONE;
	}
}

int msk_failure_needs_restore(enum msk_failure failure)
{
	return msk_failure_effect(failure) == MSK_EFFECT_KERNEL_WINDOW ? 1 : 0;
}
