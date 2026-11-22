/*
 * Host unit tests for the P0 contract layer.
 *
 * This is test-only code: it may include hosted headers and print. It never
 * touches a device, a kernel, a module or a process. Build and run through
 * gates/run_gates.py (G-P0-3) or tests/test_msk_host.py.
 *
 * Output: one "PASS <case>" / "FAIL <case>" line per assertion, then
 * "TOTAL <n> FAILED <m>". Exit 0 iff m == 0.
 */
#include <stddef.h>
#include <stdio.h>
#include <string.h>

#if defined(_WIN32)
#include <fcntl.h>
#include <io.h>
#endif

#include "msk_digest.h"
#include "msk_handoff.h"
#include "msk_plan.h"
#include "msk_spec.h"

static int g_total;
static int g_failed;

static void check_impl(int condition, const char *name)
{
	++g_total;
	if (condition) {
		printf("PASS %s\n", name);
		return;
	}
	++g_failed;
	printf("FAIL %s\n", name);
}

#define CHECK(condition, name) check_impl((condition) ? 1 : 0, (name))

static void check_status(const char *name, int actual, int expected)
{
	++g_total;
	if (actual == expected) {
		printf("PASS %s\n", name);
		return;
	}
	++g_failed;
	printf("FAIL %s (status %d, expected %d)\n", name, actual, expected);
}

static void check_u64(const char *name, unsigned long long actual,
		      unsigned long long expected)
{
	++g_total;
	if (actual == expected) {
		printf("PASS %s\n", name);
		return;
	}
	++g_failed;
	printf("FAIL %s (%llu != %llu)\n", name, actual, expected);
}

static int hex_equals(const uint8_t *bytes, size_t length, const char *hex)
{
	static const char digits[] = "0123456789abcdef";
	size_t index;

	for (index = 0; index < length; ++index) {
		if (hex[index * 2U] != digits[(bytes[index] >> 4) & 0x0FU])
			return 0;
		if (hex[index * 2U + 1U] != digits[bytes[index] & 0x0FU])
			return 0;
	}
	return hex[length * 2U] == '\0';
}

static void print_hex(const uint8_t *bytes, size_t length)
{
	size_t index;

	for (index = 0; index < length; ++index)
		printf("%02x", bytes[index]);
}

/*
 * Synthetic fixture. Every number here is invented for the test; none is a
 * device value, and none is copied from any reference implementation.
 * page_offset is 0xffffff8000000000; task_cred_off is real_cred_off + 8.
 */
static const char MSK_GOLDEN_SPEC[] =
	"msk_spec_version=1\n"
	"release=6.6.89-android15-8-g1234567890ab\n"
	"kernel_phys_load=2818572288\n"
	"kernel_phys_offset=2147483648\n"
	"page_offset=18446744071562067968\n"
	"selinux_enforcing_off=4194304\n"
	"init_cred_off=8388608\n"
	"task_real_cred_off=2104\n"
	"task_cred_off=2112\n"
	"task_seccomp_off=2216\n"
	"task_comm_off=1840\n"
	"waiter_shift=2\n"
	"kernelsnitch_collisions=7\n";

static const char MSK_GOLDEN_RELEASE[] = "6.6.89-android15-8-g1234567890ab";

/* ---------------------------------------------------------------- */

static void section_digest(void)
{
	static const uint8_t expected_empty[32] = {
		0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14,
		0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
		0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c,
		0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55
	};
	uint8_t digest[MSK_DIGEST_BYTES];
	uint8_t again[MSK_DIGEST_BYTES];
	char million[1000];
	size_t index;

	msk_sha256("", 0, digest);
	CHECK(memcmp(digest, expected_empty, 32) == 0, "sha256/empty");
	msk_sha256("abc", 3, digest);
	CHECK(hex_equals(digest, 32,
			 "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"),
	      "sha256/abc");
	msk_sha256("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", 56,
		   digest);
	CHECK(hex_equals(digest, 32,
			 "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"),
	      "sha256/two-block");
	for (index = 0; index < sizeof(million); ++index)
		million[index] = 'a';
	{
		struct msk_sha256 context;

		msk_sha256_init(&context);
		for (index = 0; index < 1000; ++index)
			msk_sha256_update(&context, million, sizeof(million));
		msk_sha256_final(&context, digest);
	}
	CHECK(hex_equals(digest, 32,
			 "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"),
	      "sha256/million-a");
	msk_sha256("abc", 3, again);
	CHECK(hex_equals(again, 32,
			 "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"),
	      "sha256/repeat");
}

static void section_schema(void)
{
	static const char *const expected[13] = {
		"msk_spec_version", "release", "kernel_phys_load",
		"kernel_phys_offset", "page_offset", "selinux_enforcing_off",
		"init_cred_off", "task_real_cred_off", "task_cred_off",
		"task_seccomp_off", "task_comm_off", "waiter_shift",
		"kernelsnitch_collisions"
	};
	uint8_t first[MSK_SPEC_DIGEST_BYTES];
	uint8_t second[MSK_SPEC_DIGEST_BYTES];
	size_t index;

	check_u64("schema/key-count", msk_spec_key_count(), 13u);
	CHECK(msk_spec_key_count() == MSK_SPEC_KEY_COUNT, "schema/count-macro");
	for (index = 0; index < 13; ++index) {
		int same = msk_spec_key_name(index) != NULL &&
			   strcmp(msk_spec_key_name(index), expected[index]) == 0;

		CHECK(same, expected[index]);
		if (!same)
			printf("  actual key %u: %s\n", (unsigned)index,
			       msk_spec_key_name(index) ? msk_spec_key_name(index)
							: "(null)");
		CHECK(msk_spec_key_required(index) == 1, "schema/required");
	}
	CHECK(msk_spec_key_name(13) == NULL, "schema/name-out-of-range");
	CHECK(msk_spec_key_required(13) == -1, "schema/required-out-of-range");
	msk_spec_schema_digest(first);
	msk_spec_schema_digest(second);
	CHECK(memcmp(first, second, MSK_SPEC_DIGEST_BYTES) == 0,
	      "schema/digest-stable");
	CHECK(!hex_equals(first, 32,
			  "0000000000000000000000000000000000000000000000000000000000000000"),
	      "schema/digest-nonzero");
	CHECK(msk_spec_schema_digest(NULL) == MSK_EINVAL, "schema/digest-null");
}

static size_t append(char *buffer, size_t used, const char *text)
{
	size_t length = strlen(text);

	memcpy(buffer + used, text, length);
	return used + length;
}

static size_t remove_key_line(const char *key, char *out)
{
	size_t used = 0;
	size_t key_length = strlen(key);
	const char *cursor = MSK_GOLDEN_SPEC;

	while (*cursor != '\0') {
		const char *newline = strchr(cursor, '\n');
		size_t length = newline != NULL ? (size_t)(newline - cursor) + 1U
						: strlen(cursor);
		int match = strncmp(cursor, key, key_length) == 0 &&
			    cursor[key_length] == '=';

		if (!match) {
			memcpy(out + used, cursor, length);
			used += length;
		}
		cursor += length;
	}
	out[used] = '\0';
	return used;
}

static void crlf_copy(char *out, size_t *used)
{
	const char *cursor = MSK_GOLDEN_SPEC;

	*used = 0;
	while (*cursor != '\0') {
		if (*cursor == '\n') {
			out[(*used)++] = '\r';
			out[(*used)++] = '\n';
		} else {
			out[(*used)++] = *cursor;
		}
		++cursor;
	}
	out[*used] = '\0';
}

static void parse_golden(struct msk_binding *binding)
{
	int status = msk_spec_parse(MSK_GOLDEN_SPEC, strlen(MSK_GOLDEN_SPEC),
				    binding);

	check_status("parse/golden-status", status, MSK_OK);
}

static void section_parse(void)
{
	struct msk_binding binding;
	struct msk_binding untouched;
	struct msk_binding second;
	struct msk_spec_diag diag;
	char buffer[8192];
	char big[5000];
	size_t used;
	size_t index;
	int status;

	memset(&binding, 0, sizeof(binding));
	parse_golden(&binding);
	check_u64("parse/version", binding.version, 1u);
	CHECK(strcmp(binding.release, MSK_GOLDEN_RELEASE) == 0,
	      "parse/release");
	check_u64("parse/phys-load", binding.kernel_phys_load, 2818572288ULL);
	check_u64("parse/phys-offset", binding.kernel_phys_offset, 2147483648ULL);
	check_u64("parse/page-offset", binding.page_offset, 18446744071562067968ULL);
	check_u64("parse/selinux-off", binding.selinux_enforcing_off, 4194304ULL);
	check_u64("parse/init-cred-off", binding.init_cred_off, 8388608ULL);
	check_u64("parse/real-cred-off", binding.task_real_cred_off, 2104ULL);
	check_u64("parse/cred-off", binding.task_cred_off, 2112ULL);
	check_u64("parse/seccomp-off", binding.task_seccomp_off, 2216ULL);
	check_u64("parse/comm-off", binding.task_comm_off, 1840ULL);
	check_u64("parse/waiter", (unsigned long long)(long long)binding.waiter_shift,
		  2ULL);
	check_u64("parse/collisions", binding.kernelsnitch_collisions, 7u);
	check_status("parse/validate", msk_spec_validate(&binding), MSK_OK);
	check_status("parse/accept-exact",
		     msk_spec_accept_release(&binding, MSK_GOLDEN_RELEASE), MSK_OK);
	check_status("parse/accept-suffix",
		     msk_spec_accept_release(&binding,
					     "6.6.89-android15-8-g1234567890ab-x"),
		     MSK_EUNSUPPORTED);
	check_status("parse/accept-major-only",
		     msk_spec_accept_release(&binding, "6.6.89"), MSK_EUNSUPPORTED);
	check_status("parse/accept-empty",
		     msk_spec_accept_release(&binding, ""), MSK_EUNSUPPORTED);
	check_status("parse/accept-null",
		     msk_spec_accept_release(&binding, NULL), MSK_EINVAL);
	{
		char no_nul[MSK_RELEASE_MAX + 2];

		memset(no_nul, 'x', sizeof(no_nul));
		check_status("parse/accept-unterminated",
			     msk_spec_accept_release(&binding, no_nul), MSK_EINVAL);
	}

	/* CRLF input must parse identically (DEV-98 class of failure). */
	crlf_copy(buffer, &used);
	status = msk_spec_parse(buffer, used, &second);
	check_status("parse/crlf", status, MSK_OK);
	CHECK(status == MSK_OK && second.task_cred_off == 2112ULL,
	      "parse/crlf-fields");

	/* Comments and blank lines are ignored, not defaults. */
	used = 0;
	used = append(buffer, used, "# a comment\n\n");
	used = append(buffer, used, MSK_GOLDEN_SPEC);
	used = append(buffer, used, "# trailing comment\n");
	check_status("parse/comments", msk_spec_parse(buffer, used, &second),
		     MSK_OK);

	/* Missing key: one at a time, exact bit and untouched output. */
	for (index = 0; index < 13; ++index) {
		struct msk_spec_diag local;
		char name[128];

		used = remove_key_line(msk_spec_key_name(index), buffer);
		memset(&untouched, 0xAA, sizeof(untouched));
		memset(&local, 0, sizeof(local));
		status = msk_spec_parse_ex(buffer, used, &untouched, &local);
		snprintf(name, sizeof(name), "parse/missing/%s",
			 msk_spec_key_name(index));
		check_status(name, status, MSK_EINCOMPLETE);
		check_u64("parse/missing-mask", local.missing_mask,
			  1ULL << index);
	}

	/* Unknown key is refused, including reference-layout key names. */
	used = 0;
	used = append(buffer, used, MSK_GOLDEN_SPEC);
	used = append(buffer, used, "FAKE" "_WAITER_A=1\n");
	memset(&diag, 0, sizeof(diag));
	status = msk_spec_parse_ex(buffer, used, &second, &diag);
	check_status("parse/unknown", status, MSK_EUNKNOWNKEY);
	CHECK(diag.key_index == MSK_SPEC_KEY_NONE, "parse/unknown-key-index");
	{
		static const char *const reference_keys[] = {
			"FAKE" "_WAITER_A=1\n",
			"COMPACT" "_WAITER=1\n",
			"LOCK" "_OFF=1\n",
			"MM_STRUCT" "_SZ=1\n",
			"FAKE" "_TASK_OFF=1\n",
			"KERNELSNITCH_IDENTITY_START=1\n"
		};

		for (index = 0;
		     index < sizeof(reference_keys) / sizeof(reference_keys[0]);
		     ++index) {
			used = 0;
			used = append(buffer, used, MSK_GOLDEN_SPEC);
			used = append(buffer, used, reference_keys[index]);
			check_status("parse/reacts-to-reference-layout",
				     msk_spec_parse(buffer, used, &second),
				     MSK_EUNKNOWNKEY);
		}
	}

	/* Duplicate key. */
	used = 0;
	used = append(buffer, used, MSK_GOLDEN_SPEC);
	used = append(buffer, used, "waiter_shift=3\n");
	memset(&diag, 0, sizeof(diag));
	status = msk_spec_parse_ex(buffer, used, &second, &diag);
	check_status("parse/duplicate", status, MSK_EDUPLICATE);
	check_u64("parse/duplicate-mask", diag.duplicate_mask, 1ULL << 11);

	/* Bad line shapes. */
	check_status("parse/no-equals",
		     msk_spec_parse("release\n", 8, &second), MSK_EINVAL);
	check_status("parse/empty-key",
		     msk_spec_parse("=1\n", 3, &second), MSK_EINVAL);
	check_status("parse/empty-value",
		     msk_spec_parse("release=\n", 9, &second), MSK_EINVAL);
	used = remove_key_line("waiter_shift", buffer);
	used = append(buffer, used, "waiter_shift=2 # comment\n");
	check_status("parse/inline-comment", msk_spec_parse(buffer, used, &second),
		     MSK_EINVAL);

	/* Numeric grammar is decimal-only and whitespace-hostile. */
	{
		static const char *const bad_values[] = {
			"0x10", "+5", " 5", "5 ", "5x", ""
		};

		for (index = 0;
		     index < sizeof(bad_values) / sizeof(bad_values[0]);
		     ++index) {
			used = remove_key_line("waiter_shift", buffer);
			used = append(buffer, used, "waiter_shift=");
			used = append(buffer, used, bad_values[index]);
			used = append(buffer, used, "\n");
			check_status("parse/bad-number",
				     msk_spec_parse(buffer, used, &second),
				     MSK_EINVAL);
		}
	}

	/* Out-of-range and relation failures. */
	used = remove_key_line("kernel_phys_load", buffer);
	used = append(buffer, used, "kernel_phys_load=18446744073709551616\n");
	check_status("parse/overflow", msk_spec_parse(buffer, used, &second),
		     MSK_ERANGE);

	used = remove_key_line("msk_spec_version", buffer);
	used = append(buffer, used, "msk_spec_version=2\n");
	check_status("parse/bad-version", msk_spec_parse(buffer, used, &second),
		     MSK_EBADVERSION);

	used = remove_key_line("task_cred_off", buffer);
	used = append(buffer, used, "task_cred_off=2120\n");
	check_status("parse/cred-relation", msk_spec_parse(buffer, used, &second),
		     MSK_ERELATION);

	{
		struct {
			const char *line;
			const char *name;
		} ranges[] = {
			{ "page_offset=4096\n", "parse/range-page" },
			{ "kernel_phys_load=2818572289\n", "parse/range-phys" },
			{ "selinux_enforcing_off=67108864\n", "parse/range-image" },
			{ "waiter_shift=9\n", "parse/range-waiter-high" },
			{ "waiter_shift=-9\n", "parse/range-waiter-low" },
			{ "kernelsnitch_collisions=65\n", "parse/range-collisions" },
			{ "task_seccomp_off=12345678\n", "parse/range-task" }
		};

		for (index = 0; index < sizeof(ranges) / sizeof(ranges[0]);
		     ++index) {
			const char *line = ranges[index].line;
			const char *equals = strchr(line, '=');
			size_t key_length = (size_t)(equals - line);
			char key[64];

			memcpy(key, line, key_length);
			key[key_length] = '\0';
			used = remove_key_line(key, buffer);
			used = append(buffer, used, line);
			check_status(ranges[index].name,
				     msk_spec_parse(buffer, used, &second),
				     MSK_ERANGE);
		}
	}

	/* Release grammar. */
	{
		char long_release[MSK_RELEASE_MAX + 16];

		used = remove_key_line("release", buffer);
		used = append(buffer, used, "release=");
		memset(long_release, 'r', sizeof(long_release));
		long_release[sizeof(long_release) - 1] = '\0';
		used = append(buffer, used, long_release);
		used = append(buffer, used, "\n");
		check_status("parse/release-too-long",
			     msk_spec_parse(buffer, used, &second), MSK_ERANGE);
	}
	used = remove_key_line("release", buffer);
	used = append(buffer, used, "release=bad release\n");
	check_status("parse/release-space", msk_spec_parse(buffer, used, &second),
		     MSK_EINVAL);

	/* Size bounds and empty input. */
	check_status("parse/empty-input", msk_spec_parse("", 0, &second),
		     MSK_EINCOMPLETE);
	memset(&diag, 0, sizeof(diag));
	check_status("parse/empty-input-diag",
		     msk_spec_parse_ex("", 0, &second, &diag), MSK_EINCOMPLETE);
	check_u64("parse/empty-input-mask", diag.missing_mask, 0x1FFFu);
	check_status("parse/null-text", msk_spec_parse(NULL, 1, &second),
		     MSK_EINVAL);
	check_status("parse/null-out", msk_spec_parse(MSK_GOLDEN_SPEC, 1, NULL),
		     MSK_EINVAL);
	memset(big, 'x', sizeof(big));
	check_status("parse/too-big", msk_spec_parse(big, sizeof(big), &second),
		     MSK_ETOOLARGE);
	memset(buffer, 'a', 300);
	buffer[300] = '\n';
	check_status("parse/line-too-long", msk_spec_parse(buffer, 301, &second),
		     MSK_ETOOLARGE);
	buffer[299] = '=';
	check_status("parse/line-too-long-key",
		     msk_spec_parse(buffer, 301, &second), MSK_ETOOLARGE);

	/* Diagnostics point at the offending line. */
	used = 0;
	used = append(buffer, used, "# header\n");
	used = append(buffer, used, "unknown_key=1\n");
	memset(&diag, 0, sizeof(diag));
	status = msk_spec_parse_ex(buffer, used, &second, &diag);
	check_status("parse/diag-status", status, MSK_EUNKNOWNKEY);
	check_u64("parse/diag-line", diag.line, 2u);
	check_u64("parse/diag-key-length", diag.key_length, 11u);
	CHECK(diag.offset > 0, "parse/diag-offset");

	/* A failed parse never writes the output binding. */
	{
		struct msk_binding probe;

		memset(&probe, 0x5A, sizeof(probe));
		status = msk_spec_parse("release=nope\n", 13, &probe);
		CHECK(status == MSK_EINCOMPLETE, "parse/failure-status");
		{
			unsigned char *bytes = (unsigned char *)&probe;
			int untouched = 1;

			for (index = 0; index < sizeof(probe); ++index)
				untouched = untouched && bytes[index] == 0x5A;
			CHECK(untouched, "parse/failure-out-untouched");
		}
	}

	/* Reference implementation's wide table is not our schema. */
	check_status("parse/reference-table-rejected",
		     msk_spec_parse("KIMAGE_TEXT_BASE=1\n",
				    strlen("KIMAGE_TEXT_BASE=1\n"), &second),
		     MSK_EUNKNOWNKEY);
}

static void section_binding_digest(void)
{
	struct msk_binding binding;
	struct msk_binding changed;
	uint8_t first[MSK_SPEC_DIGEST_BYTES];
	uint8_t second[MSK_SPEC_DIGEST_BYTES];
	int field;

	parse_golden(&binding);
	check_status("digest/status",
		     msk_spec_digest(&binding, first), MSK_OK);
	msk_spec_digest(&binding, second);
	CHECK(memcmp(first, second, 32) == 0, "digest/stable");
	CHECK(!hex_equals(first, 32,
			  "0000000000000000000000000000000000000000000000000000000000000000"),
	      "digest/nonzero");
	check_status("digest/null", msk_spec_digest(NULL, second), MSK_EINVAL);
	check_status("digest/null-out", msk_spec_digest(&binding, NULL),
		     MSK_EINVAL);

	for (field = 0; field < 10; ++field) {
		changed = binding;
		switch (field) {
		case 0:
			changed.kernel_phys_load += 4096;
			break;
		case 1:
			changed.kernel_phys_offset += 4096;
			break;
		case 2:
			changed.page_offset += 0x10000ULL;
			break;
		case 3:
			changed.selinux_enforcing_off += 4;
			break;
		case 4:
			changed.init_cred_off += 8;
			break;
		case 5:
			changed.task_real_cred_off -= 8;
			changed.task_cred_off -= 8;
			break;
		case 6:
			changed.task_cred_off += 8;
			break;
		case 7:
			changed.task_seccomp_off += 4;
			break;
		case 8:
			changed.task_comm_off += 4;
			break;
		default:
			changed.waiter_shift += 1;
			break;
		}
		msk_spec_digest(&changed, second);
		CHECK(memcmp(first, second, 32) != 0, "digest/sensitive");
	}
	changed = binding;
	changed.release[0] = '7';
	msk_spec_digest(&changed, second);
	CHECK(memcmp(first, second, 32) != 0, "digest/release-sensitive");
}

static const struct {
	uint8_t hop;
	uint8_t verify;
	uint32_t rounds;
	uint32_t settle;
} MSK_EXPECTED_STEPS[MSK_PLAN_STEPS] = {
	{ (uint8_t)MSK_HOP_ELIGIBILITY, (uint8_t)MSK_VERIFY_PRECONDITION, 1u, 0u },
	{ (uint8_t)MSK_HOP_PRIMITIVE, (uint8_t)MSK_VERIFY_PROVIDER_FRAME, 1u, 0u },
	{ (uint8_t)MSK_HOP_SELINUX, (uint8_t)MSK_VERIFY_ENFORCE_NODE_READBACK, 15u,
	  100000u },
	{ (uint8_t)MSK_HOP_CRED, (uint8_t)MSK_VERIFY_CHILD_UID, 15u, 100000u },
	{ (uint8_t)MSK_HOP_SECCOMP, (uint8_t)MSK_VERIFY_SECCOMP_MODE, 18u, 1000u },
	{ (uint8_t)MSK_HOP_SECCOMP, (uint8_t)MSK_VERIFY_LOAD_PROBE, 1u, 0u },
	{ (uint8_t)MSK_HOP_RESTORE, (uint8_t)MSK_VERIFY_RESTORE_READBACK, 1u, 0u },
	{ (uint8_t)MSK_HOP_HANDOVER, (uint8_t)MSK_VERIFY_PRECONDITION, 1u, 0u },
	{ (uint8_t)MSK_HOP_READY, (uint8_t)MSK_VERIFY_MAGIC_ROUNDTRIP, 30u,
	  100000u }
};

static void section_plan(void)
{
	struct msk_binding binding;
	struct msk_binding invalid;
	struct msk_plan plan;
	struct msk_plan tampered;
	uint8_t spec_digest[MSK_SPEC_DIGEST_BYTES];
	size_t index;

	parse_golden(&binding);
	memset(&plan, 0, sizeof(plan));
	check_status("plan/build", msk_plan_build(&binding, &plan), MSK_PLAN_OK);
	check_u64("plan/count", plan.count, MSK_PLAN_STEPS);
	check_u64("plan/version", plan.version, MSK_PLAN_VERSION);
	check_u64("plan/flags", plan.flags, MSK_PLAN_F_ALL);
	check_status("plan/validate", msk_plan_validate(&plan), MSK_PLAN_OK);
	msk_spec_digest(&binding, spec_digest);
	CHECK(memcmp(plan.spec_digest, spec_digest, 32) == 0,
	      "plan/spec-digest");
	for (index = 0; index < MSK_PLAN_STEPS; ++index) {
		const struct msk_step *step = msk_plan_step(&plan, index);

		CHECK(step != NULL, "plan/step-visible");
		if (step == NULL)
			continue;
		check_u64("plan/step-hop", step->hop, MSK_EXPECTED_STEPS[index].hop);
		check_u64("plan/step-verify", step->verify,
			  MSK_EXPECTED_STEPS[index].verify);
		check_u64("plan/step-rounds", step->max_rounds,
			  MSK_EXPECTED_STEPS[index].rounds);
		check_u64("plan/step-settle", step->settle_us,
			  MSK_EXPECTED_STEPS[index].settle);
		check_u64("plan/step-mandatory", step->mandatory, 1u);
		CHECK(step->verify != MSK_VERIFY_NONE, "plan/step-has-verdict");
	}
	CHECK(msk_plan_step(&plan, MSK_PLAN_STEPS) == NULL,
	      "plan/step-out-of-range");
	check_status("plan/null-binding", msk_plan_build(NULL, &plan),
		     MSK_PLAN_EINVAL);
	check_status("plan/null-out", msk_plan_build(&binding, NULL),
		     MSK_PLAN_EINVAL);

	memset(&invalid, 0, sizeof(invalid));
	invalid.version = MSK_SPEC_VERSION;
	strcpy(invalid.release, MSK_GOLDEN_RELEASE);
	invalid.kernel_phys_load = 2818572288ULL;
	check_status("plan/incomplete-binding",
		     msk_plan_build(&invalid, &plan), MSK_PLAN_EBINDING);

	invalid = binding;
	invalid.release[0] = '\0';
	check_status("plan/empty-release", msk_plan_build(&invalid, &plan),
		     MSK_PLAN_INCOMPLETE);

	/* Any structural drift is detected before a byte is rendered. */
	msk_plan_build(&binding, &plan);

	tampered = plan;
	tampered.steps[6].verify = (uint8_t)MSK_VERIFY_NONE;
	check_status("plan/tamper-restore-verify", msk_plan_validate(&tampered),
		     MSK_PLAN_TAMPERED);

	tampered = plan;
	tampered.steps[6].verify = (uint8_t)MSK_VERIFY_CHILD_UID;
	check_status("plan/tamper-restore-value", msk_plan_validate(&tampered),
		     MSK_PLAN_TAMPERED);

	tampered = plan;
	tampered.flags &= ~(uint32_t)MSK_PLAN_F_RESTORE_MANDATORY;
	check_status("plan/tamper-flags", msk_plan_validate(&tampered),
		     MSK_PLAN_TAMPERED);

	tampered = plan;
	tampered.count = 8;
	check_status("plan/tamper-count", msk_plan_validate(&tampered),
		     MSK_PLAN_TAMPERED);

	tampered = plan;
	tampered.plan_digest[0] ^= 0x01U;
	check_status("plan/tamper-digest", msk_plan_validate(&tampered),
		     MSK_PLAN_TAMPERED);

	tampered = plan;
	memset(tampered.spec_digest, 0, sizeof(tampered.spec_digest));
	check_status("plan/tamper-spec-digest", msk_plan_validate(&tampered),
		     MSK_PLAN_TAMPERED);

	check_status("plan/validate-null", msk_plan_validate(NULL),
		     MSK_PLAN_EINVAL);

	/* H-2/P3 page rule: bit 16 must be set, or initialized would be cleared. */
	check_u64("plan/page-bit16-set", msk_plan_page_layout_accepts(0x00010000u),
		  1u);
	check_u64("plan/page-bit16-clear", msk_plan_page_layout_accepts(0u), 0u);
	check_u64("plan/page-bit17", msk_plan_page_layout_accepts(0x00020000u), 0u);
	check_u64("plan/page-both", msk_plan_page_layout_accepts(0x00030000u), 1u);
	check_u64("plan/page-bit16-with-low",
		  msk_plan_page_layout_accepts(0x0001ABCDu), 1u);
}

static void arm_attempt(struct msk_machine *machine, uint64_t boot)
{
	struct msk_attempt attempt;

	memset(&attempt, 0, sizeof(attempt));
	attempt.boot_token = boot;
	attempt.method = "ghostlock";
	attempt.backend = "hook";
	attempt.one_shot_marker = 1u;
	check_status("machine/arm", msk_machine_arm(machine, &attempt),
		     MSK_SM_OK);
}

static void run_to_handover(struct msk_machine *machine, uint64_t boot)
{
	arm_attempt(machine, boot);
	check_status("machine/primitive",
		     msk_machine_step(machine, MSK_EV_PRIMITIVE_OK, boot, 0),
		     MSK_SM_OK);
	check_status("machine/selinux",
		     msk_machine_step(machine, MSK_EV_SELINUX_OK, boot, 0),
		     MSK_SM_OK);
	check_status("machine/cred",
		     msk_machine_step(machine, MSK_EV_CRED_OK, boot, 0), MSK_SM_OK);
	check_status("machine/seccomp",
		     msk_machine_step(machine, MSK_EV_SECCOMP_OK, boot, 0),
		     MSK_SM_OK);
	check_status("machine/load-probe",
		     msk_machine_step(machine, MSK_EV_LOAD_PROBE_OK, boot, 0),
		     MSK_SM_OK);
	check_status("machine/restore",
		     msk_machine_step(machine, MSK_EV_RESTORE_OK, boot, 0),
		     MSK_SM_OK);
	check_status("machine/handover",
		     msk_machine_step(machine, MSK_EV_HANDOVER_OK, boot, 0),
		     MSK_SM_OK);
}

static void section_machine(void)
{
	struct msk_machine machine;
	struct msk_machine other;
	struct msk_attempt attempt;
	const uint64_t boot = 0x1122334455667788ULL;
	const uint32_t magic = MSK_READY_MAGIC;

	msk_machine_init(&machine);
	check_u64("machine/initial-state", machine.state, MSK_STATE_IDLE);
	check_u64("machine/initial-effect", msk_machine_effect(&machine),
		  MSK_EFFECT_NONE);
	check_u64("machine/initial-failure", msk_machine_failure(&machine),
		  MSK_FAILURE_NONE);
	CHECK(!msk_machine_succeeded(&machine), "machine/not-succeeded");
	check_status("machine/step-before-arm",
		     msk_machine_step(&machine, MSK_EV_PRIMITIVE_OK, boot, 0),
		     MSK_SM_ENOATTEMPT);
	check_status("machine/arm-null", msk_machine_arm(NULL, &attempt),
		     MSK_SM_EINVAL);
	check_status("machine/arm-null-attempt", msk_machine_arm(&machine, NULL),
		     MSK_SM_EINVAL);

	memset(&attempt, 0, sizeof(attempt));
	attempt.boot_token = 0;
	attempt.method = "ghostlock";
	attempt.backend = "hook";
	attempt.one_shot_marker = 1u;
	check_status("machine/arm-boot-zero", msk_machine_arm(&machine, &attempt),
		     MSK_SM_EINVAL);

	attempt.boot_token = boot;
	attempt.method = "dirtyfrag";
	check_status("machine/arm-method", msk_machine_arm(&machine, &attempt),
		     MSK_SM_EMETHOD);
	attempt.method = "ghostlock ";
	check_status("machine/arm-method-suffix",
		     msk_machine_arm(&machine, &attempt), MSK_SM_EMETHOD);
	attempt.method = "ghostlock";
	attempt.backend = "ir";
	check_status("machine/arm-backend", msk_machine_arm(&machine, &attempt),
		     MSK_SM_EBACKEND);
	attempt.backend = NULL;
	check_status("machine/arm-backend-null",
		     msk_machine_arm(&machine, &attempt), MSK_SM_EINVAL);
	attempt.backend = "hook";
	attempt.one_shot_marker = 0u;
	check_status("machine/arm-marker", msk_machine_arm(&machine, &attempt),
		     MSK_SM_EMARKER);
	attempt.one_shot_marker = 2u;
	check_status("machine/arm-marker-two",
		     msk_machine_arm(&machine, &attempt), MSK_SM_EMARKER);

	attempt.one_shot_marker = 1u;
	check_status("machine/arm-ok", msk_machine_arm(&machine, &attempt),
		     MSK_SM_OK);
	check_u64("machine/state-eligible", machine.state, MSK_STATE_ELIGIBLE);
	check_status("machine/arm-twice",
		     msk_machine_arm(&machine, &attempt), MSK_SM_EREENTRY);
	attempt.boot_token = boot + 1;
	check_status("machine/arm-other-boot",
		     msk_machine_arm(&machine, &attempt), MSK_SM_EBOOT);

	/* Wrong order is refused and does not change state. */
	check_status("machine/order-refused",
		     msk_machine_step(&machine, MSK_EV_SELINUX_OK, boot, 0),
		     MSK_SM_ESTATE);
	check_u64("machine/order-state", machine.state, MSK_STATE_ELIGIBLE);

	/* Happy path, including the restore gate before handover. */
	msk_machine_init(&machine);
	arm_attempt(&machine, boot);
	check_status("machine/e-primitive",
		     msk_machine_step(&machine, MSK_EV_PRIMITIVE_OK, boot, 0),
		     MSK_SM_OK);
	check_u64("machine/s-primitive", machine.state, MSK_STATE_PRIMITIVE);
	check_u64("machine/effect-before-w1", msk_machine_effect(&machine),
		  MSK_EFFECT_NONE);
	check_status("machine/e-selinux",
		     msk_machine_step(&machine, MSK_EV_SELINUX_OK, boot, 0),
		     MSK_SM_OK);
	check_u64("machine/effect-w1", msk_machine_effect(&machine),
		  MSK_EFFECT_KERNEL_WINDOW);
	check_status("machine/e-cred",
		     msk_machine_step(&machine, MSK_EV_CRED_OK, boot, 0), MSK_SM_OK);
	check_status("machine/e-seccomp",
		     msk_machine_step(&machine, MSK_EV_SECCOMP_OK, boot, 0),
		     MSK_SM_OK);
	check_status("machine/skip-restore",
		     msk_machine_step(&machine, MSK_EV_HANDOVER_OK, boot, 0),
		     MSK_SM_ESTATE);
	check_status("machine/e-load-probe",
		     msk_machine_step(&machine, MSK_EV_LOAD_PROBE_OK, boot, 0),
		     MSK_SM_OK);
	check_u64("machine/s-restore", machine.state, MSK_STATE_RESTORE);
	check_status("machine/skip-restore-ready",
		     msk_machine_step(&machine, MSK_EV_READY_OK, boot, magic),
		     MSK_SM_ESTATE);
	check_status("machine/e-restore",
		     msk_machine_step(&machine, MSK_EV_RESTORE_OK, boot, 0),
		     MSK_SM_OK);
	check_u64("machine/s-handover", machine.state, MSK_STATE_HANDOVER);
	check_status("machine/e-handover",
		     msk_machine_step(&machine, MSK_EV_HANDOVER_OK, boot, 0),
		     MSK_SM_OK);
	check_u64("machine/effect-handover", msk_machine_effect(&machine),
		  MSK_EFFECT_HANDED_OVER);
	check_status("machine/e-ready",
		     msk_machine_step(&machine, MSK_EV_READY_OK, boot, magic),
		     MSK_SM_OK);
	check_u64("machine/s-done", machine.state, MSK_STATE_DONE);
	CHECK(msk_machine_succeeded(&machine), "machine/succeeded");
	check_u64("machine/effect-ready", msk_machine_effect(&machine),
		  MSK_EFFECT_READY);
	check_u64("machine/failure-none", msk_machine_failure(&machine),
		  MSK_FAILURE_NONE);
	check_status("machine/step-after-done",
		     msk_machine_step(&machine, MSK_EV_READY_OK, boot, magic),
		     MSK_SM_ETERMINAL);
	attempt.boot_token = boot;
	check_status("machine/arm-after-done",
		     msk_machine_arm(&machine, &attempt), MSK_SM_EREENTRY);
	attempt.boot_token = boot + 5;
	check_status("machine/arm-after-done-new-boot",
		     msk_machine_arm(&machine, &attempt), MSK_SM_ETERMINAL);

	/* Token verdicts. */
	msk_machine_init(&machine);
	run_to_handover(&machine, boot);
	check_status("machine/ready-zero-magic",
		     msk_machine_step(&machine, MSK_EV_READY_OK, boot, 0),
		     MSK_SM_OK);
	check_u64("machine/ready-zero-state", machine.state, MSK_STATE_ABORTED);
	check_u64("machine/ready-zero-failure", msk_machine_failure(&machine),
		  MSK_FAILURE_READY_WRONG_MAGIC);
	check_u64("machine/ready-zero-effect", msk_machine_effect(&machine),
		  MSK_EFFECT_HANDED_OVER);

	msk_machine_init(&machine);
	run_to_handover(&machine, boot);
	check_status("machine/ready-wrong-boot",
		     msk_machine_step(&machine, MSK_EV_READY_OK, boot + 1, magic),
		     MSK_SM_OK);
	check_u64("machine/wrong-boot-failure", msk_machine_failure(&machine),
		  MSK_FAILURE_READY_WRONG_BOOT);

	msk_machine_init(&machine);
	run_to_handover(&machine, boot);
	check_status("machine/ready-absent",
		     msk_machine_step(&machine, MSK_EV_READY_FAIL, boot, 0),
		     MSK_SM_OK);
	check_u64("machine/absent-failure", msk_machine_failure(&machine),
		  MSK_FAILURE_READY_ABSENT);
	check_u64("machine/absent-effect", msk_machine_effect(&machine),
		  MSK_EFFECT_HANDED_OVER);

	/* Failure before W1 goes through restore but proves no kernel window. */
	msk_machine_init(&machine);
	arm_attempt(&machine, boot);
	check_status("machine/primitive-fail",
		     msk_machine_step(&machine, MSK_EV_PRIMITIVE_FAIL, boot, 0),
		     MSK_SM_OK);
	check_u64("machine/primitive-fail-state", machine.state,
		  MSK_STATE_RESTORE);
	check_u64("machine/primitive-fail-rollback",
		  (machine.flags & MSK_SM_F_RESTORE_ROLLBACK) != 0, 1u);
	check_u64("machine/primitive-fail-effect", msk_machine_effect(&machine),
		  MSK_EFFECT_KERNEL_WINDOW);
	check_status("machine/primitive-fail-restore",
		     msk_machine_step(&machine, MSK_EV_RESTORE_OK, boot, 0),
		     MSK_SM_OK);
	check_u64("machine/primitive-fail-aborted", machine.state,
		  MSK_STATE_ABORTED);
	check_u64("machine/primitive-fail-failure", msk_machine_failure(&machine),
		  MSK_FAILURE_PROVIDER);

	/* Failure after W1 is a kernel window and requires restore first. */
	{
		struct msk_machine probes[3];
		size_t index;

		for (index = 0; index < 3; ++index) {
			msk_machine_init(&probes[index]);
			arm_attempt(&probes[index], boot);
			check_status("machine/pre-w1",
				     msk_machine_step(&probes[index],
						      MSK_EV_PRIMITIVE_OK, boot, 0),
				     MSK_SM_OK);
			check_status("machine/w1",
				     msk_machine_step(&probes[index],
						      MSK_EV_SELINUX_OK, boot, 0),
				     MSK_SM_OK);
		}
		check_status("machine/cred-fail",
			     msk_machine_step(&probes[0], MSK_EV_CRED_FAIL, boot,
					      0),
			     MSK_SM_OK);
		check_u64("machine/cred-fail-state", probes[0].state,
			  MSK_STATE_RESTORE);
		check_u64("machine/cred-fail-effect",
			  msk_machine_effect(&probes[0]),
			  MSK_EFFECT_KERNEL_WINDOW);
		check_u64("machine/cred-fail-restore",
			  msk_failure_needs_restore(
				  msk_machine_failure(&probes[0])),
			  1u);

		check_status("machine/seccomp-fail",
			     msk_machine_step(&probes[1], MSK_EV_CRED_OK, boot, 0),
			     MSK_SM_OK);
		check_status("machine/seccomp-fail-2",
			     msk_machine_step(&probes[1], MSK_EV_SECCOMP_FAIL,
					      boot, 0),
			     MSK_SM_OK);
		check_u64("machine/seccomp-fail-failure",
			  msk_machine_failure(&probes[1]), MSK_FAILURE_SECCOMP);

		check_status("machine/probe-fail",
			     msk_machine_step(&probes[2], MSK_EV_CRED_OK, boot, 0),
			     MSK_SM_OK);
		check_status("machine/probe-fail-2",
			     msk_machine_step(&probes[2], MSK_EV_SECCOMP_OK, boot,
					      0),
			     MSK_SM_OK);
		check_status("machine/probe-fail-3",
			     msk_machine_step(&probes[2],
					      MSK_EV_LOAD_PROBE_FAIL, boot, 0),
			     MSK_SM_OK);
		check_u64("machine/probe-fail-failure",
			  msk_machine_failure(&probes[2]),
			  MSK_FAILURE_LOAD_PROBE);
	}

	/* Restore failure is terminal and marked. */
	msk_machine_init(&machine);
	arm_attempt(&machine, boot);
	check_status("machine/f-restore",
		     msk_machine_step(&machine, MSK_EV_PRIMITIVE_OK, boot, 0),
		     MSK_SM_OK);
	check_status("machine/f-restore-2",
		     msk_machine_step(&machine, MSK_EV_SELINUX_OK, boot, 0),
		     MSK_SM_OK);
	check_status("machine/f-restore-3",
		     msk_machine_step(&machine, MSK_EV_CRED_FAIL, boot, 0),
		     MSK_SM_OK);
	check_status("machine/restore-fail",
		     msk_machine_step(&machine, MSK_EV_RESTORE_FAIL, boot, 0),
		     MSK_SM_OK);
	check_u64("machine/restore-fail-state", machine.state, MSK_STATE_ABORTED);
	/* The original cause is retained; the flag records the restore failure. */
	check_u64("machine/restore-fail-failure", msk_machine_failure(&machine),
		  MSK_FAILURE_CRED);
	check_u64("machine/restore-fail-flag",
		  (machine.flags & MSK_SM_F_RESTORE_FAILED) != 0, 1u);
	check_u64("machine/restore-fail-effect", msk_machine_effect(&machine),
		  MSK_EFFECT_KERNEL_WINDOW);

	/* Handover failure: no consumer dispatched, W1 window still touched. */
	msk_machine_init(&machine);
	arm_attempt(&machine, boot);
	check_status("machine/hf-1",
		     msk_machine_step(&machine, MSK_EV_PRIMITIVE_OK, boot, 0),
		     MSK_SM_OK);
	check_status("machine/hf-2",
		     msk_machine_step(&machine, MSK_EV_SELINUX_OK, boot, 0),
		     MSK_SM_OK);
	check_status("machine/hf-3",
		     msk_machine_step(&machine, MSK_EV_CRED_OK, boot, 0), MSK_SM_OK);
	check_status("machine/hf-4",
		     msk_machine_step(&machine, MSK_EV_SECCOMP_OK, boot, 0),
		     MSK_SM_OK);
	check_status("machine/hf-5",
		     msk_machine_step(&machine, MSK_EV_LOAD_PROBE_OK, boot, 0),
		     MSK_SM_OK);
	check_status("machine/hf-6",
		     msk_machine_step(&machine, MSK_EV_RESTORE_OK, boot, 0),
		     MSK_SM_OK);
	check_u64("machine/hf-effect-before-dispatch",
		  msk_machine_effect(&machine), MSK_EFFECT_KERNEL_WINDOW);
	check_status("machine/handover-fail",
		     msk_machine_step(&machine, MSK_EV_HANDOVER_FAIL, boot, 0),
		     MSK_SM_OK);
	check_u64("machine/handover-fail-failure", msk_machine_failure(&machine),
		  MSK_FAILURE_HANDOVER);
	check_u64("machine/handover-fail-effect", msk_machine_effect(&machine),
		  MSK_EFFECT_KERNEL_WINDOW);

	/* Planned restore failure (no earlier failure) is still fatal. */
	msk_machine_init(&machine);
	arm_attempt(&machine, boot);
	check_status("machine/planned-restore-fail",
		     msk_machine_step(&machine, MSK_EV_PRIMITIVE_OK, boot, 0),
		     MSK_SM_OK);
	check_status("machine/planned-restore-fail-2",
		     msk_machine_step(&machine, MSK_EV_SELINUX_OK, boot, 0),
		     MSK_SM_OK);
	check_status("machine/planned-restore-fail-3",
		     msk_machine_step(&machine, MSK_EV_CRED_OK, boot, 0),
		     MSK_SM_OK);
	check_status("machine/planned-restore-fail-4",
		     msk_machine_step(&machine, MSK_EV_SECCOMP_OK, boot, 0),
		     MSK_SM_OK);
	check_status("machine/planned-restore-fail-5",
		     msk_machine_step(&machine, MSK_EV_LOAD_PROBE_OK, boot, 0),
		     MSK_SM_OK);
	check_status("machine/planned-restore-fail-6",
		     msk_machine_step(&machine, MSK_EV_RESTORE_FAIL, boot, 0),
		     MSK_SM_OK);
	check_u64("machine/planned-restore-fail-state", machine.state,
		  MSK_STATE_ABORTED);
	check_u64("machine/planned-restore-fail-failure",
		  msk_machine_failure(&machine), MSK_FAILURE_RESTORE_FAILED);

	/* Reset discipline: one attempt per boot, forever. */
	msk_machine_init(&machine);
	run_to_handover(&machine, boot);
	check_status("machine/reset-nonterminal",
		     msk_machine_reset(&machine, boot + 1), MSK_SM_ETERMINAL);
	check_status("machine/reset-ready",
		     msk_machine_step(&machine, MSK_EV_READY_OK, boot, magic),
		     MSK_SM_OK);
	check_status("machine/reset-same-boot", msk_machine_reset(&machine, boot),
		     MSK_SM_EREENTRY);
	check_status("machine/reset-zero", msk_machine_reset(&machine, 0),
		     MSK_SM_EINVAL);
	check_status("machine/reset-new-boot",
		     msk_machine_reset(&machine, boot + 2), MSK_SM_OK);
	check_u64("machine/reset-state", machine.state, MSK_STATE_IDLE);
	check_u64("machine/reset-cleared-flags", machine.flags, 0u);
	check_status("machine/reset-step",
		     msk_machine_step(&machine, MSK_EV_PRIMITIVE_OK, boot + 2, 0),
		     MSK_SM_ENOATTEMPT);
	attempt.boot_token = boot + 2;
	check_status("machine/reset-arm", msk_machine_arm(&machine, &attempt),
		     MSK_SM_OK);
	check_status("machine/reset-arm-twice",
		     msk_machine_arm(&machine, &attempt), MSK_SM_EREENTRY);
	attempt.boot_token = boot + 3;
	check_status("machine/reset-arm-old-boot",
		     msk_machine_arm(&machine, &attempt), MSK_SM_EBOOT);

	/* Names are stable and never NULL. */
	msk_machine_init(&other);
	CHECK(msk_state_name(MSK_STATE_DONE) != NULL, "machine/state-name");
	CHECK(msk_event_name(MSK_EV_READY_OK) != NULL, "machine/event-name");
	CHECK(strcmp(msk_state_name(MSK_STATE_ABORTED), "aborted") == 0,
	      "machine/state-name-value");
}

static int dummy_read_enforce(void *context, int32_t *observed)
{
	(void)context;
	(void)observed;
	return 0;
}

static int dummy_read_checkreqprot(void *context, int32_t *observed)
{
	(void)context;
	(void)observed;
	return 0;
}

static int dummy_dispatch(void *context, const char *script)
{
	(void)context;
	(void)script;
	return 0;
}

static int dummy_token(void *context, char *line, size_t capacity, size_t *used)
{
	(void)context;
	(void)line;
	(void)capacity;
	(void)used;
	return 0;
}

static void section_ops(void)
{
	struct msk_ops ops;

	memset(&ops, 0, sizeof(ops));
	check_status("ops/null", msk_ops_ready(NULL), MSK_ENOTIMPL);
	check_status("ops/empty", msk_ops_ready(&ops), MSK_ENOTIMPL);
	ops.read_enforce = dummy_read_enforce;
	check_status("ops/partial", msk_ops_ready(&ops), MSK_ENOTIMPL);
	ops.read_checkreqprot = dummy_read_checkreqprot;
	ops.dispatch_consumer = dummy_dispatch;
	check_status("ops/partial-two", msk_ops_ready(&ops), MSK_ENOTIMPL);
	ops.read_ready_token = dummy_token;
	check_status("ops/complete", msk_ops_ready(&ops), MSK_OK);
}

static const char MSK_RESTORE_BODY[] =
	"# MSK-RESTORE:begin\n"
	"# MSK-RESTORE:baseline\n"
	"# MSK-RESTORE:policy\n"
	"# MSK-RESTORE:enforce\n"
	"# MSK-RESTORE:readback\n"
	"printf '%s:%s\\n' \"$BASELINE_ENFORCING\" \"$BASELINE_CHECKREQPROT\"\n"
	"# MSK-RESTORE:end";

static const char MSK_WEAK_BODY[] =
	"exec '/host/bin/consumer'";

static void golden_input(struct msk_handoff_input *input,
			 const char *const *argv)
{
	memset(input, 0, sizeof(*input));
	input->interpreter = "/bin/sh";
	input->home_dir = "/host/home/attempt-1";
	input->attempt_id = "attempt-0001";
	input->consumer_path = "/host/bin/msk-consumer";
	input->consumer_argv = argv;
	input->consumer_argc = 2;
	input->restore_body = MSK_RESTORE_BODY;
	input->restore_body_length = sizeof(MSK_RESTORE_BODY) - 1U;
	input->baseline_enforcing = 1;
	input->baseline_checkreqprot = 0;
	input->origin = 'o';
}

static void section_handoff(void)
{
	struct msk_binding binding;
	struct msk_plan plan;
	struct msk_plan tampered;
	struct msk_handoff_input input;
	struct msk_handoff_input changed;
	static const char *const argv[2] = { "--handover", "--attempt=one" };
	char script[MSK_HANDOFF_SCRIPT_MAX];
	char small[64];
	size_t used = 0;
	size_t required;
	int status;

	parse_golden(&binding);
	msk_plan_build(&binding, &plan);
	golden_input(&input, argv);

	memset(script, 0, sizeof(script));
	status = msk_handoff_render(&plan, &input, script, sizeof(script), &used);
	check_status("handoff/render", status, MSK_HANDOFF_OK);
	check_u64("handoff/used", used, strlen(script));
	CHECK(strstr(script, "RESTORE_OUT=\"$(\n") != NULL,
	      "handoff/restore-subshell");
	CHECK(strstr(script, "READBACK_OK=0\n") != NULL, "handoff/readback-flag");
	CHECK(strstr(script, "|| RESTORE_RC=79\n") != NULL,
	      "handoff/readback-enforced");
	CHECK(strstr(script, "|| exit 80\n") != NULL, "handoff/no-exec-on-failure");
	CHECK(strstr(script, "EXPECT_ENFORCE=1\n") != NULL,
	      "handoff/expected-enforce");
	CHECK(strstr(script, "FRAME=\"r${RESTORE_RC}:${ENF:-u}:${CRP:-u}:o\"") !=
		      NULL,
	      "handoff/frame-shape");
	CHECK(strstr(script,
		     "exec '/host/bin/msk-consumer' '--handover' '--attempt=one' \"$FRAME\"\n") !=
		      NULL,
	      "handoff/exec-line");
	CHECK(strstr(script, "MSK-RESTORE:readback") != NULL,
	      "handoff/body-included");
	CHECK(strstr(script, "#! /bin/sh") == NULL, "handoff/shebang-no-space");
	CHECK(strstr(script, "#!") == script, "handoff/shebang-first");
	CHECK(script[0] == '#' && script[1] == '!', "handoff/shebang-prefix");
	CHECK(strstr(script, "# msk-handoff v1 attempt=attempt-0001 plan=") != NULL,
	      "handoff/header");
	CHECK(strstr(script, "plan=") != NULL && strstr(script, " spec=") != NULL,
	      "handoff/digests-in-header");

	/* Capacity contract: exact fit, one short, zero, and NULL. */
	required = used + 1U;
	memset(small, 0x7F, sizeof(small));
	status = msk_handoff_render(&plan, &input, small, used, &used);
	check_status("handoff/exact-minus-one", status, MSK_EOVERFLOW);
	check_u64("handoff/overflow-required", used, required);
	check_u64("handoff/overflow-nul", (unsigned char)small[0], 0u);

	memset(small, 0x7F, sizeof(small));
	status = msk_handoff_render(&plan, &input, small, 0, &used);
	check_status("handoff/capacity-zero", status, MSK_EOVERFLOW);
	check_u64("handoff/capacity-zero-required", used, required);
	check_status("handoff/buffer-null",
		     msk_handoff_render(&plan, &input, NULL, 128, &used),
		     MSK_HANDOFF_EINVAL);
	check_status("handoff/used-null",
		     msk_handoff_render(&plan, &input, script, sizeof(script),
					NULL),
		     MSK_HANDOFF_EINVAL);

	{
		char *exact = script;

		memset(exact, 0, sizeof(script));
		status = msk_handoff_render(&plan, &input, exact, required, &used);
		check_status("handoff/exact-fit", status, MSK_HANDOFF_OK);
		CHECK(exact[required - 1U] == '\0', "handoff/exact-fit-nul");
	}

	/* The plan gate is the restore gate: a mutated plan renders nothing. */
	tampered = plan;
	tampered.steps[6].verify = (uint8_t)MSK_VERIFY_NONE;
	check_status("handoff/tampered-plan",
		     msk_handoff_render(&tampered, &input, script, sizeof(script),
					&used),
		     MSK_HANDOFF_EPLAN);

	/* Reference-like body (no restore stages) is refused. */
	changed = input;
	changed.restore_body = MSK_WEAK_BODY;
	changed.restore_body_length = sizeof(MSK_WEAK_BODY) - 1U;
	check_status("handoff/non-restore-body",
		     msk_handoff_render(&plan, &changed, script, sizeof(script),
					&used),
		     MSK_HANDOFF_ERESTORE_WEAK);

	{
		static const char reordered[] =
			"# MSK-RESTORE:baseline\n"
			"# MSK-RESTORE:begin\n"
			"# MSK-RESTORE:policy\n"
			"# MSK-RESTORE:enforce\n"
			"# MSK-RESTORE:readback\n"
			"# MSK-RESTORE:end";
		static const char duplicated[] =
			"# MSK-RESTORE:begin\n"
			"# MSK-RESTORE:baseline\n"
			"# MSK-RESTORE:policy\n"
			"# MSK-RESTORE:enforce\n"
			"# MSK-RESTORE:readback\n"
			"# MSK-RESTORE:readback\n"
			"# MSK-RESTORE:end";
		static const char truncated[] =
			"# MSK-RESTORE:begin\n"
			"# MSK-RESTORE:baseline\n"
			"# MSK-RESTORE:policy\n"
			"# MSK-RESTORE:enforce\n"
			"# MSK-RESTORE:readback";
		static const char binary_body[] =
			"# MSK-RESTORE:begin\n"
			"# MSK-RESTORE:baseline\n"
			"# MSK-RESTORE:policy\n"
			"# MSK-RESTORE:enforce\n"
			"# MSK-RESTORE:readback\n"
			"\001\n"
			"# MSK-RESTORE:end";

		changed = input;
		changed.restore_body = reordered;
		changed.restore_body_length = sizeof(reordered) - 1U;
		check_status("handoff/reordered-body",
			     msk_handoff_render(&plan, &changed, script,
						sizeof(script), &used),
			     MSK_HANDOFF_ERESTORE_WEAK);
		changed.restore_body = duplicated;
		changed.restore_body_length = sizeof(duplicated) - 1U;
		check_status("handoff/duplicated-body",
			     msk_handoff_render(&plan, &changed, script,
						sizeof(script), &used),
			     MSK_HANDOFF_ERESTORE_WEAK);
		changed.restore_body = truncated;
		changed.restore_body_length = sizeof(truncated) - 1U;
		check_status("handoff/truncated-body",
			     msk_handoff_render(&plan, &changed, script,
						sizeof(script), &used),
			     MSK_HANDOFF_ERESTORE_WEAK);
		changed.restore_body = binary_body;
		changed.restore_body_length = sizeof(binary_body) - 1U;
		check_status("handoff/binary-body",
			     msk_handoff_render(&plan, &changed, script,
						sizeof(script), &used),
			     MSK_HANDOFF_EINVAL);
	}

	/* String grammars. */
	changed = input;
	changed.interpreter = "bin/sh";
	check_status("handoff/relative-interpreter",
		     msk_handoff_render(&plan, &changed, script, sizeof(script),
					&used),
		     MSK_HANDOFF_ESTRING);
	changed = input;
	changed.home_dir = "/host/../etc";
	check_status("handoff/dotdot-home",
		     msk_handoff_render(&plan, &changed, script, sizeof(script),
					&used),
		     MSK_HANDOFF_ESTRING);
	changed = input;
	changed.consumer_path = "host/bin/consumer";
	check_status("handoff/relative-consumer",
		     msk_handoff_render(&plan, &changed, script, sizeof(script),
					&used),
		     MSK_HANDOFF_ESTRING);
	changed = input;
	changed.attempt_id = "bad/id";
	check_status("handoff/bad-attempt-id",
		     msk_handoff_render(&plan, &changed, script, sizeof(script),
					&used),
		     MSK_HANDOFF_ESTRING);
	changed.attempt_id = "";
	check_status("handoff/empty-attempt-id",
		     msk_handoff_render(&plan, &changed, script, sizeof(script),
					&used),
		     MSK_HANDOFF_ESTRING);
	changed = input;
	changed.consumer_argc = MSK_HANDOFF_ARGC_MAX + 1U;
	check_status("handoff/too-many-args",
		     msk_handoff_render(&plan, &changed, script, sizeof(script),
					&used),
		     MSK_HANDOFF_ECONSUMER);
	changed.consumer_argc = 1;
	changed.consumer_argv = NULL;
	check_status("handoff/null-argv",
		     msk_handoff_render(&plan, &changed, script, sizeof(script),
					&used),
		     MSK_HANDOFF_ECONSUMER);
	{
		static const char *const bad_argv[1] = { "line\nbreak" };
		static const char *const empty_argv[1] = { "" };

		changed.consumer_argv = bad_argv;
		check_status("handoff/bad-arg",
			     msk_handoff_render(&plan, &changed, script,
						sizeof(script), &used),
			     MSK_HANDOFF_ECONSUMER);
		changed.consumer_argv = empty_argv;
		check_status("handoff/empty-arg",
			     msk_handoff_render(&plan, &changed, script,
						sizeof(script), &used),
			     MSK_HANDOFF_ECONSUMER);
	}

	/* Baseline/origin contract. */
	changed = input;
	changed.baseline_enforcing = 2;
	check_status("handoff/baseline-range",
		     msk_handoff_render(&plan, &changed, script, sizeof(script),
					&used),
		     MSK_HANDOFF_EINVAL);
	changed = input;
	changed.origin = 'x';
	check_status("handoff/origin",
		     msk_handoff_render(&plan, &changed, script, sizeof(script),
					&used),
		     MSK_HANDOFF_EINVAL);
	changed = input;
	changed.origin = 'o';
	changed.baseline_enforcing = -1;
	check_status("handoff/origin-observed-unreadable",
		     msk_handoff_render(&plan, &changed, script, sizeof(script),
					&used),
		     MSK_HANDOFF_EINVAL);

	changed = input;
	changed.origin = 'd';
	changed.baseline_enforcing = -2;
	changed.baseline_checkreqprot = -1;
	status = msk_handoff_render(&plan, &changed, script, sizeof(script),
				    &used);
	check_status("handoff/document-baseline", status, MSK_HANDOFF_OK);
	CHECK(strstr(script, "EXPECT_ENFORCE=1\n") != NULL,
	      "handoff/document-baseline-enforce");
	CHECK(strstr(script, ":d\"") != NULL, "handoff/document-baseline-frame");

	/* Quoting matches the existing adapter's single-quote escape. */
	changed = input;
	changed.consumer_path = "/host/bin/msk consumer's";
	status = msk_handoff_render(&plan, &changed, script, sizeof(script),
				    &used);
	check_status("handoff/quoting", status, MSK_HANDOFF_OK);
	CHECK(strstr(script, "'/host/bin/msk consumer'\\''s'") != NULL,
	      "handoff/quoting-value");

	/* The frame is emitted twice (log line + exec argument), never more. */
	{
		const char *first = strstr(script, "\"$FRAME\"");
		const char *second =
			first != NULL ? strstr(first + 1, "\"$FRAME\"") : NULL;
		const char *third =
			second != NULL ? strstr(second + 1, "\"$FRAME\"") : NULL;

		CHECK(first != NULL && second != NULL && third == NULL,
		      "handoff/frame-twice");
	}
}

static void build_ready_line(char *buffer, size_t capacity, unsigned long long magic,
			    unsigned long long boot, const char *suffix)
{
	snprintf(buffer, capacity, "MSK-READY/1 %016llx %016llx%s", magic, boot,
		 suffix);
}

static void section_ready(void)
{
	char line[128];
	uint32_t magic = 0;
	const uint64_t boot = 0x0102030405060708ULL;

	build_ready_line(line, sizeof(line), MSK_READY_MAGIC, boot, "");
	check_status("ready/ok",
		     msk_ready_parse(line, strlen(line), boot, &magic), MSK_READY_OK);
	check_u64("ready/magic", magic, MSK_READY_MAGIC);
	build_ready_line(line, sizeof(line), MSK_READY_MAGIC, boot, "\n");
	check_status("ready/lf",
		     msk_ready_parse(line, strlen(line), boot, &magic), MSK_READY_OK);
	build_ready_line(line, sizeof(line), MSK_READY_MAGIC, boot, "\r\n");
	check_status("ready/crlf",
		     msk_ready_parse(line, strlen(line), boot, &magic), MSK_READY_OK);
	build_ready_line(line, sizeof(line), 0x4d534b52ULL, boot, "");
	check_status("ready/lowercase",
		     msk_ready_parse(line, strlen(line), boot, &magic), MSK_READY_OK);

	/* The reference implementation's magic is not ours. */
	build_ready_line(line, sizeof(line), 0x12345ULL, boot, "");
	check_status("ready/reference-magic",
		     msk_ready_parse(line, strlen(line), boot, &magic),
		     MSK_READY_WRONG_MAGIC);
	build_ready_line(line, sizeof(line), 0ULL, boot, "");
	check_status("ready/zero-magic",
		     msk_ready_parse(line, strlen(line), boot, &magic),
		     MSK_READY_WRONG_MAGIC);

	build_ready_line(line, sizeof(line), MSK_READY_MAGIC, boot + 1, "");
	check_status("ready/wrong-boot",
		     msk_ready_parse(line, strlen(line), boot, &magic),
		     MSK_READY_WRONG_BOOT);

	build_ready_line(line, sizeof(line), MSK_READY_MAGIC, boot, "");
	CHECK(msk_ready_parse(line, 5, boot, &magic) != MSK_READY_OK,
	      "ready/truncated-length");
	check_status("ready/wrong-version",
		     msk_ready_parse("MSK-READY/2 4d534b52 0000000000000001",
				    strlen("MSK-READY/2 4d534b52 0000000000000001"),
				    boot, &magic),
		     MSK_READY_MALFORMED);
	check_status("ready/short-hex",
		     msk_ready_parse("MSK-READY/1 4d534b52 00000000",
				    strlen("MSK-READY/1 4d534b52 00000000"), boot,
				    &magic),
		     MSK_READY_MALFORMED);
	check_status("ready/non-hex",
		     msk_ready_parse(
			     "MSK-READY/1 zzzzzzzzzzzzzzzz 0000000000000000",
			     strlen("MSK-READY/1 zzzzzzzzzzzzzzzz 0000000000000000"),
			     boot, &magic),
		     MSK_READY_MALFORMED);
	check_status("ready/trailing",
		     msk_ready_parse(
			     "MSK-READY/1 4d534b52 0000000000000001!",
			     strlen("MSK-READY/1 4d534b52 0000000000000001!"),
			     boot, &magic),
		     MSK_READY_MALFORMED);
	check_status("ready/garbage",
		     msk_ready_parse("kernel log without token", 24, boot, &magic),
		     MSK_READY_ABSENT);
	check_status("ready/empty", msk_ready_parse("", 0, boot, &magic),
		     MSK_READY_ABSENT);
	check_status("ready/blank", msk_ready_parse("\n", 1, boot, &magic),
		     MSK_READY_ABSENT);
	check_status("ready/null", msk_ready_parse(NULL, 0, boot, &magic),
		     MSK_EINVAL);
	check_status("ready/null-out",
		     msk_ready_parse("MSK-READY/1", 11, boot, NULL), MSK_EINVAL);
	{
		char long_line[128];

		memset(long_line, 'a', sizeof(long_line));
		long_line[sizeof(long_line) - 1] = '\0';
		check_status("ready/too-long",
			     msk_ready_parse(long_line, sizeof(long_line) - 1, boot,
					     &magic),
			     MSK_READY_MALFORMED);
	}
}

static void section_taxonomy(void)
{
	static const struct {
		int status;
		enum msk_failure failure;
		enum msk_effect effect;
	} mappings[] = {
		{ MSK_OK, MSK_FAILURE_NONE, MSK_EFFECT_NONE },
		{ MSK_EUNSUPPORTED, MSK_FAILURE_SPEC_UNSUPPORTED,
		  MSK_EFFECT_NONE },
		{ MSK_EBADVERSION, MSK_FAILURE_SPEC_UNSUPPORTED,
		  MSK_EFFECT_NONE },
		{ MSK_EINCOMPLETE, MSK_FAILURE_SPEC_INVALID, MSK_EFFECT_NONE },
		{ MSK_EUNKNOWNKEY, MSK_FAILURE_SPEC_INVALID, MSK_EFFECT_NONE },
		{ MSK_ERELATION, MSK_FAILURE_SPEC_INVALID, MSK_EFFECT_NONE },
		{ MSK_PLAN_TAMPERED, MSK_FAILURE_HANDOVER, MSK_EFFECT_NONE },
		{ MSK_SM_EREENTRY, MSK_FAILURE_ELIGIBILITY, MSK_EFFECT_NONE },
		{ MSK_SM_EREADY, MSK_FAILURE_READY_WRONG_MAGIC,
		  MSK_EFFECT_KERNEL_WINDOW },
		{ MSK_HANDOFF_ERESTORE_WEAK, MSK_FAILURE_RESTORE_WEAK,
		  MSK_EFFECT_NONE },
		{ MSK_ENOTIMPL, MSK_FAILURE_NO_OPS, MSK_EFFECT_NONE },
		{ MSK_READY_WRONG_BOOT, MSK_FAILURE_READY_WRONG_BOOT,
		  MSK_EFFECT_KERNEL_WINDOW },
		{ MSK_READY_ABSENT, MSK_FAILURE_READY_ABSENT,
		  MSK_EFFECT_KERNEL_WINDOW }
	};
	size_t index;

	for (index = 0; index < sizeof(mappings) / sizeof(mappings[0]); ++index) {
		enum msk_failure failure =
			msk_failure_from_status(mappings[index].status);
		enum msk_effect expected =
			msk_failure_effect(mappings[index].failure);

		check_u64("taxonomy/from-status", failure,
			  mappings[index].failure);
		check_u64("taxonomy/effect", expected, mappings[index].effect);
	}

	for (index = 0; index < (size_t)MSK_FAILURE_COUNT; ++index) {
		enum msk_failure failure = (enum msk_failure)index;
		const char *name = msk_failure_name(failure);
		enum msk_effect effect = msk_failure_effect(failure);

		CHECK(name != NULL && strcmp(name, "unknown") != 0,
		      "taxonomy/name");
		check_u64("taxonomy/needs-restore",
			  msk_failure_needs_restore(failure),
			  effect == MSK_EFFECT_KERNEL_WINDOW ? 1U : 0U);
	}
	check_u64("taxonomy/none-effect",
		  msk_failure_effect(MSK_FAILURE_NONE), MSK_EFFECT_NONE);
	check_u64("taxonomy/out-of-range",
		  msk_failure_effect((enum msk_failure)999), MSK_EFFECT_NONE);
	check_u64("taxonomy/unknown-status", msk_failure_from_status(-9999),
		  MSK_FAILURE_NONE);
}

static int run_selftest(void)
{
	section_digest();
	section_schema();
	section_parse();
	section_binding_digest();
	section_plan();
	section_machine();
	section_ops();
	section_handoff();
	section_ready();
	section_taxonomy();
	printf("TOTAL %d FAILED %d\n", g_total, g_failed);
	return g_failed == 0 ? 0 : 1;
}

static void build_golden_plan(struct msk_binding *binding, struct msk_plan *plan)
{
	if (msk_spec_parse(MSK_GOLDEN_SPEC, strlen(MSK_GOLDEN_SPEC), binding) !=
	    MSK_OK) {
		fprintf(stderr, "golden spec failed to parse\n");
		return;
	}
	if (msk_plan_build(binding, plan) != MSK_PLAN_OK)
		fprintf(stderr, "golden plan failed to build\n");
}

int main(int argc, char **argv)
{
#if defined(_WIN32)
	/* Byte-exact output: the golden-script comparison must not see CRLF. */
	_setmode(_fileno(stdout), _O_BINARY);
	_setmode(_fileno(stderr), _O_BINARY);
#endif
	if (argc > 1 && strcmp(argv[1], "--list-keys") == 0) {
		size_t index;

		for (index = 0; index < msk_spec_key_count(); ++index)
			printf("%s\n", msk_spec_key_name(index));
		return 0;
	}
	if (argc > 1 && strcmp(argv[1], "--print-digest") == 0) {
		struct msk_binding binding;
		uint8_t digest[MSK_SPEC_DIGEST_BYTES];

		memset(&binding, 0, sizeof(binding));
		if (msk_spec_parse(MSK_GOLDEN_SPEC, strlen(MSK_GOLDEN_SPEC),
				   &binding) != MSK_OK) {
			fprintf(stderr, "golden spec failed to parse\n");
			return 2;
		}
		msk_spec_digest(&binding, digest);
		print_hex(digest, sizeof(digest));
		printf("\n");
		return 0;
	}
	if (argc > 1 && strcmp(argv[1], "--render-golden") == 0) {
		struct msk_binding binding;
		struct msk_plan plan;
		struct msk_handoff_input input;
		static const char *const argument_vector[2] = { "--handover",
							       "--attempt=one" };
		char script[MSK_HANDOFF_SCRIPT_MAX];
		size_t used = 0;

		memset(&binding, 0, sizeof(binding));
		memset(&plan, 0, sizeof(plan));
		build_golden_plan(&binding, &plan);
		golden_input(&input, argument_vector);
		if (msk_handoff_render(&plan, &input, script, sizeof(script),
				       &used) != MSK_HANDOFF_OK) {
			fprintf(stderr, "golden render failed\n");
			return 2;
		}
		fwrite(script, 1, used, stdout);
		return 0;
	}
	if (argc > 1 && strcmp(argv[1], "--render-weak") == 0) {
		struct msk_binding binding;
		struct msk_plan plan;
		struct msk_handoff_input input;
		static const char *const argument_vector[2] = { "--handover",
							       "--attempt=one" };
		char script[MSK_HANDOFF_SCRIPT_MAX];
		size_t used = 0;
		int status;

		memset(&binding, 0, sizeof(binding));
		memset(&plan, 0, sizeof(plan));
		build_golden_plan(&binding, &plan);
		golden_input(&input, argument_vector);
		input.restore_body = MSK_WEAK_BODY;
		input.restore_body_length = sizeof(MSK_WEAK_BODY) - 1U;
		status = msk_handoff_render(&plan, &input, script, sizeof(script),
					    &used);
		printf("RESULT=%d\n", status);
		return 0;
	}
	if (argc > 1 && strcmp(argv[1], "--selftest") == 0)
		return run_selftest();
	if (argc > 1 && strcmp(argv[1], "--help") == 0) {
		printf("usage: %s [--selftest|--list-keys|--print-digest|"
		       "--render-golden|--render-weak]\n",
		       argv[0]);
		return 0;
	}
	return run_selftest();
}
