/*
 * Handover script rendering + readiness token parsing. Pure text.
 *
 * Nothing here opens, writes, spawns or signals. The only products are bytes
 * (a script that a later phase may write exclusively) and a verdict on a token
 * line the kernel is supposed to have produced.
 */
#include "msk_handoff.h"

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

static int msk_bytes_equal(const void *left, const void *right, size_t length)
{
	const unsigned char *a = (const unsigned char *)left;
	const unsigned char *b = (const unsigned char *)right;
	size_t index;

	for (index = 0; index < length; ++index) {
		if (a[index] != b[index])
			return 0;
	}
	return 1;
}

static int msk_text_length(const char *text, size_t limit, size_t *out)
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

static int msk_is_printable(unsigned char byte)
{
	return byte >= 0x20U && byte <= 0x7EU;
}

/* Absolute POSIX-ish path, printable, no empty component, no "..". */
static int msk_valid_path(const char *path)
{
	size_t length = 0;
	size_t index;
	size_t component_start;

	if (!msk_text_length(path, MSK_HANDOFF_PATH_MAX, &length))
		return 0;
	if (length < 2 || path[0] != '/' || path[length - 1] == '/')
		return 0;
	for (index = 0; index < length; ++index) {
		if (!msk_is_printable((unsigned char)path[index]))
			return 0;
	}
	component_start = 1;
	for (index = 1; index <= length; ++index) {
		if (index == length || path[index] == '/') {
			size_t component_length = index - component_start;

			if (component_length == 0)
				return 0;
			if (component_length == 2 && path[component_start] == '.' &&
			    path[component_start + 1] == '.')
				return 0;
			component_start = index + 1;
		}
	}
	return 1;
}

static int msk_valid_attempt_id(const char *identifier)
{
	size_t length = 0;
	size_t index;

	if (!msk_text_length(identifier, MSK_ATTEMPT_ID_MAX + 1U, &length))
		return 0;
	if (length == 0 || length > MSK_ATTEMPT_ID_MAX)
		return 0;
	for (index = 0; index < length; ++index) {
		unsigned char byte = (unsigned char)identifier[index];

		if ((byte >= '0' && byte <= '9') || (byte >= 'A' && byte <= 'Z') ||
		    (byte >= 'a' && byte <= 'z') || byte == '.' || byte == '_' ||
		    byte == '-')
			continue;
		return 0;
	}
	return 1;
}

static int msk_valid_argument(const char *argument)
{
	size_t length = 0;
	size_t index;

	if (!msk_text_length(argument, MSK_HANDOFF_ARG_MAX + 1U, &length))
		return 0;
	if (length == 0 || length > MSK_HANDOFF_ARG_MAX)
		return 0;
	for (index = 0; index < length; ++index) {
		if (!msk_is_printable((unsigned char)argument[index]))
			return 0;
	}
	return 1;
}

static int msk_valid_body_bytes(const char *body, size_t length)
{
	size_t index;

	if (body == 0 || length == 0 || length > MSK_HANDOFF_BODY_MAX)
		return 0;
	for (index = 0; index < length; ++index) {
		unsigned char byte = (unsigned char)body[index];

		if (byte == '\n' || byte == '\t' || msk_is_printable(byte))
			continue;
		return 0;
	}
	return 1;
}

struct msk_marker {
	const char *text;
	size_t length;
};

static const struct msk_marker MSK_MARKERS[MSK_HANDOFF_MARKER_COUNT] = {
	{ "# MSK-RESTORE:begin", sizeof("# MSK-RESTORE:begin") - 1U },
	{ "# MSK-RESTORE:baseline", sizeof("# MSK-RESTORE:baseline") - 1U },
	{ "# MSK-RESTORE:policy", sizeof("# MSK-RESTORE:policy") - 1U },
	{ "# MSK-RESTORE:enforce", sizeof("# MSK-RESTORE:enforce") - 1U },
	{ "# MSK-RESTORE:readback", sizeof("# MSK-RESTORE:readback") - 1U },
	{ "# MSK-RESTORE:end", sizeof("# MSK-RESTORE:end") - 1U }
};

/*
 * The body must declare every restore stage exactly once and in order. This is
 * a textual shape check, not a proof of the body's behaviour; the runtime
 * proof is the readback line the emitted script demands before handover.
 */
static int msk_body_declares_restore(const char *body, size_t length)
{
	size_t start = 0;
	size_t expected = 0;

	while (start < length) {
		size_t end = start;
		size_t marker;

		while (end < length && body[end] != '\n')
			++end;
		for (marker = 0; marker < MSK_HANDOFF_MARKER_COUNT; ++marker) {
			if (end - start != MSK_MARKERS[marker].length)
				continue;
			if (!msk_bytes_equal(body + start, MSK_MARKERS[marker].text,
					     MSK_MARKERS[marker].length))
				continue;
			if (marker != expected)
				return 0;
			++expected;
			break;
		}
		start = end + 1;
	}
	return expected == MSK_HANDOFF_MARKER_COUNT ? 1 : 0;
}

static int msk_valid_baseline(int32_t value)
{
	return value >= -2 && value <= 1;
}

struct msk_writer {
	char *buffer;
	size_t capacity;
	size_t used;
	int overflow;
};

static void msk_write(struct msk_writer *writer, const char *bytes, size_t length)
{
	if (writer->buffer != 0 && writer->overflow == 0) {
		if (writer->used + length <= writer->capacity)
			msk_copy(writer->buffer + writer->used, bytes, length);
		else
			writer->overflow = 1;
	}
	writer->used += length;
}

static void msk_write_u32(struct msk_writer *writer, uint32_t value)
{
	char digits[10];
	size_t count = 0;

	if (value == 0) {
		msk_write(writer, "0", 1);
		return;
	}
	while (value > 0) {
		digits[count++] = (char)('0' + (value % 10U));
		value /= 10U;
	}
	while (count > 0) {
		char digit = digits[--count];

		msk_write(writer, &digit, 1);
	}
}

static void msk_write_i32(struct msk_writer *writer, int32_t value)
{
	if (value < 0) {
		msk_write(writer, "-", 1);
		msk_write_u32(writer, (uint32_t)(-value));
		return;
	}
	msk_write_u32(writer, (uint32_t)value);
}

static void msk_write_hex16(struct msk_writer *writer, const uint8_t *bytes)
{
	static const char digits[] = "0123456789abcdef";
	size_t index;

	for (index = 0; index < 8; ++index) {
		char pair[2];

		pair[0] = digits[(bytes[index] >> 4) & 0x0FU];
		pair[1] = digits[bytes[index] & 0x0FU];
		msk_write(writer, pair, 2);
	}
}

static void msk_write_quoted(struct msk_writer *writer, const char *text,
			    size_t length)
{
	size_t index;

	msk_write(writer, "'", 1);
	for (index = 0; index < length; ++index) {
		if (text[index] == '\'')
			msk_write(writer, "'\\''", 4);
		else
			msk_write(writer, &text[index], 1);
	}
	msk_write(writer, "'", 1);
}

/*
 * Literal-with-length helper: the length of a string literal is computed by the
 * compiler, never by hand. A hand-counted length once read past the literal.
 */
#define MSK_LIT(text) (text), (sizeof(text) - 1U)

static void msk_render(struct msk_writer *writer,
		       const struct msk_plan *plan,
		       const struct msk_handoff_input *input)
{
	size_t index;
	size_t length = 0;
	uint32_t expected_enforce =
		(input->baseline_enforcing == 0 || input->baseline_enforcing == 1)
			? (uint32_t)input->baseline_enforcing
			: 1U;

	msk_text_length(input->interpreter, MSK_HANDOFF_PATH_MAX, &length);
	msk_write(writer, MSK_LIT("#!"));
	msk_write(writer, input->interpreter, length);
	msk_write(writer, MSK_LIT("\n"));

	msk_write(writer, MSK_LIT("# msk-handoff v1 attempt="));
	msk_text_length(input->attempt_id, MSK_ATTEMPT_ID_MAX + 1U, &length);
	msk_write(writer, input->attempt_id, length);
	msk_write(writer, MSK_LIT(" plan="));
	msk_write_hex16(writer, plan->plan_digest);
	msk_write(writer, MSK_LIT(" spec="));
	msk_write_hex16(writer, plan->spec_digest);
	msk_write(writer, MSK_LIT("\n"));
	msk_write(writer, MSK_LIT("# P0 contract bytes only: the caller creates "
				  "the carrier exclusively and runs it once.\n"));

	msk_write(writer, MSK_LIT("HOME_DIR="));
	msk_text_length(input->home_dir, MSK_HANDOFF_PATH_MAX, &length);
	msk_write_quoted(writer, input->home_dir, length);
	msk_write(writer, MSK_LIT("\n"));

	msk_write(writer, MSK_LIT("BASELINE_ENFORCING="));
	msk_write_i32(writer, input->baseline_enforcing);
	msk_write(writer, MSK_LIT("\n"));

	msk_write(writer, MSK_LIT("BASELINE_CHECKREQPROT="));
	msk_write_i32(writer, input->baseline_checkreqprot);
	msk_write(writer, MSK_LIT("\n"));

	msk_write(writer, MSK_LIT("EXPECT_ENFORCE="));
	msk_write_u32(writer, expected_enforce);
	msk_write(writer, MSK_LIT("\n"));

	msk_write(writer, MSK_LIT("RESTORE_OUT=\"$(\n"));
	msk_write(writer, input->restore_body, input->restore_body_length);
	msk_write(writer, MSK_LIT("\n)\n"));
	msk_write(writer, MSK_LIT("RESTORE_RC=$?\n"));
	msk_write(writer, MSK_LIT("ENF=${RESTORE_OUT%%:*}\n"));
	msk_write(writer, MSK_LIT("CRP=${RESTORE_OUT#*:}\n"));
	msk_write(writer, MSK_LIT("READBACK_OK=0\n"));
	msk_write(writer, MSK_LIT("case \"$ENF:$CRP\" in\n"));
	msk_write(writer, MSK_LIT("  [012u]:[012u]) READBACK_OK=1 ;;\n"));
	msk_write(writer, MSK_LIT("esac\n"));
	msk_write(writer,
		  MSK_LIT("[ \"$ENF\" = \"$EXPECT_ENFORCE\" ] || READBACK_OK=0\n"));
	msk_write(writer,
		  MSK_LIT("[ \"$READBACK_OK\" -eq 1 ] || RESTORE_RC=79\n"));
	msk_write(writer, MSK_LIT("FRAME=\"r${RESTORE_RC}:${ENF:-u}:${CRP:-u}:"));
	msk_write(writer, &input->origin, 1);
	msk_write(writer, MSK_LIT("\"\n"));
	msk_write(writer, MSK_LIT("printf '%s\\n' \"$FRAME\"\n"));
	msk_write(writer, MSK_LIT("[ \"$RESTORE_RC\" -eq 0 ] || exit 80\n"));
	msk_write(writer, MSK_LIT("exec "));
	msk_text_length(input->consumer_path, MSK_HANDOFF_PATH_MAX, &length);
	msk_write_quoted(writer, input->consumer_path, length);
	for (index = 0; index < input->consumer_argc; ++index) {
		msk_text_length(input->consumer_argv[index],
				MSK_HANDOFF_ARG_MAX + 1U, &length);
		msk_write(writer, MSK_LIT(" "));
		msk_write_quoted(writer, input->consumer_argv[index], length);
	}
	msk_write(writer, MSK_LIT(" \"$FRAME\"\n"));
}

static int msk_validate_input(const struct msk_plan *plan,
			      const struct msk_handoff_input *input)
{
	size_t index;

	if (plan == 0 || input == 0)
		return MSK_HANDOFF_EINVAL;
	if (msk_plan_validate(plan) != MSK_PLAN_OK)
		return MSK_HANDOFF_EPLAN;
	if (!msk_valid_path(input->interpreter) || !msk_valid_path(input->home_dir))
		return MSK_HANDOFF_ESTRING;
	if (!msk_valid_attempt_id(input->attempt_id))
		return MSK_HANDOFF_ESTRING;
	if (!msk_valid_path(input->consumer_path))
		return MSK_HANDOFF_ESTRING;

	if (input->consumer_argc > MSK_HANDOFF_ARGC_MAX)
		return MSK_HANDOFF_ECONSUMER;
	if (input->consumer_argc > 0 && input->consumer_argv == 0)
		return MSK_HANDOFF_ECONSUMER;
	for (index = 0; index < input->consumer_argc; ++index) {
		if (!msk_valid_argument(input->consumer_argv[index]))
			return MSK_HANDOFF_ECONSUMER;
	}

	if (!msk_valid_baseline(input->baseline_enforcing) ||
	    !msk_valid_baseline(input->baseline_checkreqprot))
		return MSK_HANDOFF_EINVAL;
	if (input->origin != 'o' && input->origin != 'd')
		return MSK_HANDOFF_EINVAL;
	/* 'o' claims an observed enforcing baseline: it must be 0 or 1. */
	if (input->origin == 'o' && input->baseline_enforcing != 0 &&
	    input->baseline_enforcing != 1)
		return MSK_HANDOFF_EINVAL;

	if (!msk_valid_body_bytes(input->restore_body,
				  input->restore_body_length))
		return MSK_HANDOFF_EINVAL;
	if (!msk_body_declares_restore(input->restore_body,
				       input->restore_body_length))
		return MSK_HANDOFF_ERESTORE_WEAK;
	return MSK_HANDOFF_OK;
}

int msk_handoff_render(const struct msk_plan *plan,
		       const struct msk_handoff_input *input,
		       char *buffer, size_t capacity, size_t *used)
{
	struct msk_writer dry;
	struct msk_writer real;
	size_t required;
	int status;

	if (used == 0)
		return MSK_HANDOFF_EINVAL;
	*used = 0;
	if (buffer != 0 && capacity > 0)
		buffer[0] = '\0';
	if (buffer == 0)
		return MSK_HANDOFF_EINVAL;

	status = msk_validate_input(plan, input);
	if (status != MSK_HANDOFF_OK)
		return status;

	msk_zero(&dry, sizeof(dry));
	msk_render(&dry, plan, input);
	if (dry.used + 1U > MSK_HANDOFF_SCRIPT_MAX) {
		*used = dry.used + 1U;
		return MSK_ETOOLARGE;
	}
	required = dry.used + 1U;
	if (capacity < required) {
		*used = required;
		return MSK_EOVERFLOW;
	}

	msk_zero(&real, sizeof(real));
	real.buffer = buffer;
	real.capacity = capacity - 1U;
	msk_render(&real, plan, input);
	buffer[real.used] = '\0';
	*used = real.used;
	return MSK_HANDOFF_OK;
}

static int msk_parse_hex16(const char *text, uint64_t *out)
{
	uint64_t value = 0;
	size_t index;

	for (index = 0; index < MSK_READY_HEX_DIGITS; ++index) {
		unsigned char byte = (unsigned char)text[index];
		unsigned int digit;

		if (byte >= '0' && byte <= '9')
			digit = (unsigned int)(byte - '0');
		else if (byte >= 'a' && byte <= 'f')
			digit = (unsigned int)(byte - 'a') + 10U;
		else if (byte >= 'A' && byte <= 'F')
			digit = (unsigned int)(byte - 'A') + 10U;
		else
			return 0;
		value = (value << 4) | digit;
	}
	*out = value;
	return 1;
}

static int msk_looks_like_token(const char *line, size_t length)
{
	static const char marker[] = "MSK-READY/";
	const size_t marker_length = sizeof(marker) - 1U;

	if (length < marker_length)
		return 0;
	return msk_bytes_equal(line, marker, marker_length);
}

int msk_ready_parse(const char *line, size_t length,
		    uint64_t expected_boot_tag, uint32_t *out_magic)
{
	const size_t prefix_length = sizeof(MSK_READY_PREFIX) - 1U;
	uint64_t magic = 0;
	uint64_t boot_tag = 0;

	if (line == 0 || out_magic == 0)
		return MSK_EINVAL;

	if (length > 0 && line[length - 1] == '\n')
		--length;
	if (length > 0 && line[length - 1] == '\r')
		--length;
	if (length == 0)
		return MSK_READY_ABSENT;
	if (length > MSK_READY_LINE_MAX)
		return MSK_READY_MALFORMED;
	if (length < prefix_length ||
	    !msk_bytes_equal(line, MSK_READY_PREFIX, prefix_length))
		return msk_looks_like_token(line, length) ? MSK_READY_MALFORMED
							  : MSK_READY_ABSENT;

	if (length != prefix_length + MSK_READY_HEX_DIGITS + 1U +
			       MSK_READY_HEX_DIGITS)
		return MSK_READY_MALFORMED;
	if (line[prefix_length + MSK_READY_HEX_DIGITS] != ' ')
		return MSK_READY_MALFORMED;
	if (!msk_parse_hex16(line + prefix_length, &magic))
		return MSK_READY_MALFORMED;
	if (!msk_parse_hex16(line + prefix_length + MSK_READY_HEX_DIGITS + 1U,
			     &boot_tag))
		return MSK_READY_MALFORMED;

	if (magic > 0xFFFFFFFFULL || (uint32_t)magic != MSK_READY_MAGIC)
		return MSK_READY_WRONG_MAGIC;
	if (boot_tag != expected_boot_tag)
		return MSK_READY_WRONG_BOOT;

	*out_magic = (uint32_t)magic;
	return MSK_READY_OK;
}

enum msk_failure msk_failure_from_status(int status)
{
	switch (status) {
	case MSK_OK:
		return MSK_FAILURE_NONE;
	case MSK_EUNSUPPORTED:
	case MSK_EBADVERSION:
		return MSK_FAILURE_SPEC_UNSUPPORTED;
	case MSK_EINVAL:
	case MSK_EINCOMPLETE:
	case MSK_ERANGE:
	case MSK_EUNKNOWNKEY:
	case MSK_EDUPLICATE:
	case MSK_ETOOLARGE:
	case MSK_ERELATION:
		return MSK_FAILURE_SPEC_INVALID;
	case MSK_ENOTIMPL:
		return MSK_FAILURE_NO_OPS;
	case MSK_PLAN_INCOMPLETE:
	case MSK_PLAN_EBINDING:
		return MSK_FAILURE_SPEC_INVALID;
	case MSK_PLAN_TAMPERED:
		return MSK_FAILURE_HANDOVER;
	case MSK_SM_EREADY:
		return MSK_FAILURE_READY_WRONG_MAGIC;
	case MSK_SM_EMETHOD:
	case MSK_SM_EBACKEND:
	case MSK_SM_EMARKER:
	case MSK_SM_EREENTRY:
	case MSK_SM_EBOOT:
	case MSK_SM_ETERMINAL:
	case MSK_SM_ESTATE:
	case MSK_SM_ENOATTEMPT:
		return MSK_FAILURE_ELIGIBILITY;
	case MSK_HANDOFF_ERESTORE_WEAK:
		return MSK_FAILURE_RESTORE_WEAK;
	case MSK_HANDOFF_EPLAN:
		return MSK_FAILURE_HANDOVER;
	case MSK_HANDOFF_ESTRING:
	case MSK_HANDOFF_ECONSUMER:
	case MSK_HANDOFF_EINVAL:
		return MSK_FAILURE_HANDOVER;
	case MSK_READY_ABSENT:
		return MSK_FAILURE_READY_ABSENT;
	case MSK_READY_MALFORMED:
		return MSK_FAILURE_READY_MALFORMED;
	case MSK_READY_WRONG_MAGIC:
		return MSK_FAILURE_READY_WRONG_MAGIC;
	case MSK_READY_WRONG_BOOT:
		return MSK_FAILURE_READY_WRONG_BOOT;
	case MSK_EOVERFLOW:
		return MSK_FAILURE_HANDOVER;
	default:
		return MSK_FAILURE_NONE;
	}
}
