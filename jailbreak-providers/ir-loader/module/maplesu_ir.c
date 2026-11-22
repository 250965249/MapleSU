/*
 * maplesu_ir — MapleSU's in-kernel root installer (IR).
 *
 * Shape, not ancestry: this is our own module. It imports no kernel symbol at
 * all (see build_ir_module.py), so it does not depend on which exports a given
 * GKI build happens to keep, and it cannot drag a KernelSU/Magisk symbol set in
 * with it. Everything it needs to find in the kernel arrives in the per-release
 * spec that is patched into the .ir_spec section of this very file before load.
 *
 * What it does, in order:
 *   1. parse the embedded spec (the same text file the offline verifier checks);
 *   2. establish the kernel image base (spec #kbase=, else VBAR_EL1 - vectors);
 *   3. verify EVERY block's original bytes first, and refuse the whole set if any
 *      block disagrees (IR orig-byte contract; no partial patching, ever);
 *   4. patch through aarch64_insn_patch_text, which owns the text-mapping dance;
 *   5. read every block back and refuse if the new bytes are not there.
 *
 * It returns 0 only when all three of (3), (4), (5) succeeded. The module then
 * stays live for the rest of the boot: that is the read-only readiness marker
 * ("maplesu_ir" in /proc/modules) the post-reboot takeover probes for, and the
 * patches themselves are kernel text, which outlives this process.
 *
 * Freestanding on purpose: no libc, no kernel headers, no imported symbols.
 */

typedef unsigned char u8;
typedef unsigned short u16;
typedef unsigned int u32;
typedef unsigned long long u64;

#ifndef IR_BUILD
#define IR_BUILD "unversioned"
#endif

#define IR_SPEC_LIMIT 4096
#define IR_MAX_BLOCKS 16
#define IR_MAX_BLOCK 128
#define IR_BATCH 24

/* Patched into the .ko before finit_module(); see ir_glue.S and ir.spec. */
extern u8 __ir_spec[];

/* Module result codes. These are the contract with the bootstrap; they are
 * negative errno values so init_module() can return them directly. */
#define IR_OK 0
#define IR_ERR_NO_FN (-19)        /* ENODEV: spec carries no usable patch function */
#define IR_ERR_SPEC (-95)         /* EOPNOTSUPP: spec unparseable / limits exceeded */
#define IR_ERR_ORIG (-129)        /* EKEYREJECTED: an original byte did not match */
#define IR_ERR_APPLY (-5)         /* EIO: patch call failed or read-back disagreed */

struct ir_block {
	u64 offset;
	u32 orig_len;
	u32 patched_len;
	u8 orig[IR_MAX_BLOCK];
	u8 patched[IR_MAX_BLOCK];
};

struct ir_ctx {
	u64 kbase;
	u64 vectors_offset;
	u64 vectors_sig;
	u64 fn_patch;
	u64 fn_printk;
	u32 block_count;
	u32 bytes_written;
	struct ir_block blocks[IR_MAX_BLOCKS];
};

/* ------------------------------------------------------------------ */
/* Tiny freestanding helpers. No libc, no compiler-emitted memset calls. */
/* ------------------------------------------------------------------ */

static void ir_memzero(void *dst, u32 len)
{
	u8 *p = (u8 *)dst;
	for (u32 i = 0; i < len; ++i)
		p[i] = 0;
}

static int ir_key_is(const char *key, u32 key_len, const char *want)
{
	u32 i = 0;
	for (; i < key_len; ++i) {
		if (want[i] == 0 || key[i] != want[i])
			return 0;
	}
	return want[i] == 0;
}

static int ir_hex_nibble(char c)
{
	if (c >= '0' && c <= '9')
		return c - '0';
	if (c >= 'a' && c <= 'f')
		return c - 'a' + 10;
	if (c >= 'A' && c <= 'F')
		return c - 'A' + 10;
	return -1;
}

/* Decimal, or 0x-prefixed hex. Digits only between start and end. */
static int ir_parse_u64(const char *s, u32 start, u32 end, u64 *out)
{
	u64 value = 0;
	u32 i = start;
	int base = 10;
	if (end <= start)
		return 0;
	if (end - start > 2 && s[start] == '0' && (s[start + 1] == 'x' || s[start + 1] == 'X')) {
		base = 16;
		i += 2;
	}
	if (i >= end)
		return 0;
	for (; i < end; ++i) {
		int digit = base == 16 ? ir_hex_nibble(s[i]) : (s[i] >= '0' && s[i] <= '9' ? s[i] - '0' : -1);
		if (digit < 0)
			return 0;
		value = value * (u64)base + (u64)digit;
	}
	*out = value;
	return 1;
}

static int ir_parse_hex_bytes(const char *s, u32 start, u32 end, u8 *out, u32 cap, u32 *len)
{
	u32 digits = end - start;
	u32 bytes;
	if (digits == 0 || (digits & 1))
		return 0;
	bytes = digits / 2;
	if (bytes > cap)
		return 0;
	for (u32 i = 0; i < bytes; ++i) {
		int hi = ir_hex_nibble(s[start + i * 2]);
		int lo = ir_hex_nibble(s[start + i * 2 + 1]);
		if (hi < 0 || lo < 0)
			return 0;
		out[i] = (u8)((hi << 4) | lo);
	}
	*len = bytes;
	return 1;
}

/* ------------------------------------------------------------------ */
/* Kernel entry points, called by address.                              */
/* ------------------------------------------------------------------ */

typedef int (*ir_patch_fn)(void *addrs[], u32 insns[], int cnt);
typedef int (*ir_printk_fn)(const char *fmt, ...);

/*
 * The call site must not be CFI-checked: the target was resolved from the spec,
 * so the compiler has no type to emit a matching KCFI hash for. This attribute
 * removes the check at the call site only; init_module keeps its own KCFI hash,
 * which is what the kernel checks before it enters us.
 */
#define IR_NOCFI __attribute__((no_sanitize("cfi")))

/*
 * Last live userspace-visible byte of a block, one cache line at a time: reading
 * text is legal, writing to it via the direct map is not, so verification always
 * goes through the mapping the kernel itself uses to fetch instructions.
 */
static u8 ir_read_byte(u64 address)
{
	return *(const volatile u8 *)(unsigned long)address;
}

IR_NOCFI static void ir_print_str(struct ir_ctx *ctx, const char *fmt,
				  const char *text, u64 value)
{
#ifdef IR_NO_PRINTK
	/* Bring-up control: every log line is a call through an address taken from the
	 * spec. If the device survives with printing compiled out and dies with it in,
	 * that address is what kills it. */
	(void)ctx; (void)fmt; (void)text; (void)value;
	return;
#endif
	if (ctx->fn_printk == 0)
		return;
	((ir_printk_fn)(unsigned long)ctx->fn_printk)(fmt, text,
						      (unsigned long long)value);
}

IR_NOCFI static void ir_print(struct ir_ctx *ctx, const char *fmt, u64 a, u64 b)
{
#ifdef IR_NO_PRINTK
	(void)ctx; (void)fmt; (void)a; (void)b;
	return;
#endif
	if (ctx->fn_printk == 0)
		return;
	((ir_printk_fn)(unsigned long)ctx->fn_printk)(fmt, (unsigned long long)a,
						      (unsigned long long)b);
}

IR_NOCFI static int ir_call_patch(struct ir_ctx *ctx, void *addrs[], u32 insns[], int cnt)
{
	return ((ir_patch_fn)(unsigned long)ctx->fn_patch)(addrs, insns, cnt);
}

static u32 ir_le32(const u8 *p)
{
	return (u32)p[0] | ((u32)p[1] << 8) | ((u32)p[2] << 16) | ((u32)p[3] << 24);
}

/* ------------------------------------------------------------------ */
/* Spec parsing.                                                       */
/* ------------------------------------------------------------------ */

/*
 * Returns 1 when the line was consumed, or a negative IR_ERR_* when a value we
 * depend on is malformed.
 *
 * Descriptive meta (#kernel=, #key=) is consumed WITHOUT being parsed as a number.
 * Treating #key's printable placeholder as a failed number used to abort the whole
 * parse before a single block was read, which surfaced on device as IR_ERR_NO_FN.
 */
static int ir_parse_meta(struct ir_ctx *ctx, const char *key, u32 key_len,
			 const char *value, u32 value_len)
{
	u64 parsed = 0;
	u64 *slot = 0;

	if (ir_key_is(key, key_len, "kbase"))
		slot = &ctx->kbase;
	else if (ir_key_is(key, key_len, "sym.aarch64_insn_patch_text"))
		slot = &ctx->fn_patch;
	else if (ir_key_is(key, key_len, "sym._printk") || ir_key_is(key, key_len, "sym.printk"))
		slot = &ctx->fn_printk;
	else if (ir_key_is(key, key_len, "sym.vectors"))
		slot = &ctx->vectors_offset;
	else if (ir_key_is(key, key_len, "sig.vectors"))
		slot = &ctx->vectors_sig;

	if (slot == 0)
		return 1;   /* descriptive: kept for the tooling, ignored here */
	if (!ir_parse_u64(value, 0, value_len, &parsed))
		return IR_ERR_SPEC;
	*slot = parsed;
	return 1;
}

static int ir_parse_block(struct ir_ctx *ctx, const char *line, u32 len)
{
	u32 bar1 = 0, bar2 = 0;
	int seen1 = 0, seen2 = 0;
	struct ir_block *block;
	u64 offset = 0;

	for (u32 i = 0; i < len; ++i) {
		if (line[i] != '|')
			continue;
		if (!seen1) {
			bar1 = i;
			seen1 = 1;
		} else if (!seen2) {
			bar2 = i;
			seen2 = 1;
		} else {
			return IR_ERR_SPEC;   /* a third separator is a malformed line */
		}
	}
	if (!seen1 || !seen2 || ctx->block_count >= IR_MAX_BLOCKS)
		return IR_ERR_SPEC;
	if (!ir_parse_u64(line, 0, bar1, &offset))
		return IR_ERR_SPEC;

	block = &ctx->blocks[ctx->block_count];
	ir_memzero(block, (u32)sizeof(*block));
	block->offset = offset;
	if (!ir_parse_hex_bytes(line, bar1 + 1, bar2, block->orig, IR_MAX_BLOCK, &block->orig_len))
		return IR_ERR_SPEC;
	if (!ir_parse_hex_bytes(line, bar2 + 1, len, block->patched, IR_MAX_BLOCK, &block->patched_len))
		return IR_ERR_SPEC;
	if (block->orig_len == 0 || block->orig_len != block->patched_len)
		return IR_ERR_SPEC;
	/* Text patches are instruction-sized; a tail that is not a whole number of
	 * instructions cannot be applied through the instruction patcher. */
	if ((block->patched_len & 3) != 0)
		return IR_ERR_SPEC;
	ctx->block_count++;
	return IR_OK;
}

static int ir_parse_spec(struct ir_ctx *ctx)
{
	const char *text = (const char *)__ir_spec;
	u32 cursor = 0;

	while (cursor < IR_SPEC_LIMIT && text[cursor] != 0) {
		u32 start = cursor;
		u32 len;
		int rc;

		while (cursor < IR_SPEC_LIMIT && text[cursor] != 0 && text[cursor] != '\n')
			++cursor;
		len = cursor - start;
		if (cursor < IR_SPEC_LIMIT && text[cursor] == '\n')
			++cursor;
		if (len == 0)
			continue;
		if (text[start] == '#') {
			u32 eq = 0;
			int seen = 0;
			for (u32 i = 1; i < len; ++i) {
				if (text[start + i] == '=') {
					eq = i;
					seen = 1;
					break;
				}
			}
			if (seen)
				rc = ir_parse_meta(ctx, text + start + 1, eq - 1,
						   text + start + eq + 1, len - eq - 1);
			else
				rc = 1;
			if (rc == 1)
				continue;
			return rc;
		}
		rc = ir_parse_block(ctx, text + start, len);
		if (rc != IR_OK)
			return rc;
	}
	if (ctx->block_count == 0)
		return IR_ERR_SPEC;
	return IR_OK;
}

/* ------------------------------------------------------------------ */
/* Kernel image base.                                                  */
/* ------------------------------------------------------------------ */

/*
 * With CONFIG_RANDOMIZE_BASE the image is slid by a page-aligned offset, so
 * VBAR_EL1 (which the kernel keeps pointing at its own `vectors` while running
 * at EL1) minus the spec's `sym.vectors` is the slide-free image base. The
 * spec may instead carry an explicit #kbase= measured by the privileged caller;
 * that always wins.
 */
static u64 ir_read_vbar(void)
{
	u64 value;
	__asm__ __volatile__("mrs %0, vbar_el1" : "=r"(value));
	return value;
}

static int ir_resolve_base(struct ir_ctx *ctx)
{
	if (ctx->kbase != 0)
		return IR_OK;
	if (ctx->vectors_offset == 0)
		return IR_ERR_NO_FN;
	{
		const u64 vbar = ir_read_vbar();
		if (vbar == 0)
			return IR_ERR_NO_FN;
		/*
		 * Reading VBAR_EL1 is safe by construction, so comparing its contents
		 * with the image's own `vectors` prologue proves whether
		 * `vbar - vectors_offset` is really the image base - without touching a
		 * possibly unmapped address. A silent wrong base would make every later
		 * read an oops that takes the module mutex with it, which is exactly the
		 * hang this check replaces.
		 */
		if (ctx->vectors_sig != 0) {
			u64 observed = 0;
			for (u32 i = 0; i < 4; ++i)
				observed |= (u64)ir_read_byte(vbar + i) << (8 * i);
			if (observed != (ctx->vectors_sig & 0xFFFFFFFFULL)) {
				ir_print(ctx, "maplesu_ir: VBAR_SIG_MISMATCH seen=%llu want=%llu\n",
					 observed, ctx->vectors_sig & 0xFFFFFFFFULL);
				return IR_ERR_NO_FN;
			}
		}
		ctx->kbase = vbar - ctx->vectors_offset;
		ir_print(ctx, "maplesu_ir: vbar=%llu kbase=%llu\n", vbar, ctx->kbase);
	}
	return ctx->kbase != 0 ? IR_OK : IR_ERR_NO_FN;
}

/* ------------------------------------------------------------------ */
/* Verify, patch, verify.                                              */
/* ------------------------------------------------------------------ */

static int ir_verify_original(struct ir_ctx *ctx)
{
	for (u32 i = 0; i < ctx->block_count; ++i) {
		struct ir_block *block = &ctx->blocks[i];
		for (u32 j = 0; j < block->orig_len; ++j) {
			u64 address = ctx->kbase + block->offset + j;
			if (ir_read_byte(address) != block->orig[j]) {
				/* Named exactly as the contract requires; the offset is the
				 * image-relative one from the spec, not a runtime address. */
				ir_print(ctx, "maplesu_ir: IR_ORIG_MISMATCH:%llu\n",
					 block->offset + j, 0);
				return IR_ERR_ORIG;
			}
		}
	}
	return IR_OK;
}

static int ir_apply(struct ir_ctx *ctx)
{
	for (u32 i = 0; i < ctx->block_count; ++i) {
		struct ir_block *block = &ctx->blocks[i];
		void *addrs[IR_BATCH];
		u32 insns[IR_BATCH];
		u32 batch = 0;

		for (u32 j = 0; j < block->patched_len; j += 4) {
			addrs[batch] = (void *)(unsigned long)(ctx->kbase + block->offset + j);
			insns[batch] = ir_le32(block->patched + j);
			if (++batch == IR_BATCH) {
				if (ir_call_patch(ctx, addrs, insns, (int)batch) != 0)
					return IR_ERR_APPLY;
				batch = 0;
			}
		}
		if (batch != 0 && ir_call_patch(ctx, addrs, insns, (int)batch) != 0)
			return IR_ERR_APPLY;
		ctx->bytes_written += block->patched_len;
	}
	return IR_OK;
}

static int ir_verify_patched(struct ir_ctx *ctx)
{
	for (u32 i = 0; i < ctx->block_count; ++i) {
		struct ir_block *block = &ctx->blocks[i];
		for (u32 j = 0; j < block->patched_len; ++j) {
			u64 address = ctx->kbase + block->offset + j;
			if (ir_read_byte(address) != block->patched[j]) {
				ir_print(ctx, "maplesu_ir: IR_READBACK_MISMATCH:%llu\n",
					 block->offset + j, 0);
				return IR_ERR_APPLY;
			}
		}
	}
	return IR_OK;
}

/* ------------------------------------------------------------------ */
/* Module entry.                                                       */
/* ------------------------------------------------------------------ */

/*
 * Everything below runs once. `noinline` keeps the KCFI-instrumented entry from
 * being folded into a helper, so the 4-byte type hash in front of it is the one
 * the kernel's do_one_initcall checks for.
 */
#ifdef IR_CANARY
/*
 * Bring-up canary (build_ir_module.py --canary): the smallest module that has our
 * exact loader-visible structure but none of our code, no .ir_spec reference and no
 * data relocations. It exists to separate "our ELF/loader contract is refused" from
 * "something in our code or relocations is refused", because the kernel denies us
 * dmesg and both cases surface as the same ENOEXEC.
 *
 * It returns an error on purpose so the module unloads itself immediately.
 */
__attribute__((section(".init.text"))) __attribute__((noinline))
int init_module(void)
{
	return -19;  /* ENODEV: loaded fine, now go away */
}
#else
__attribute__((section(".init.text"))) __attribute__((noinline))
int init_module(void)
{
	static struct ir_ctx ctx;
	int rc;

	ir_memzero(&ctx, (u32)sizeof(ctx));
	rc = ir_parse_spec(&ctx);
	if (rc != IR_OK)
		goto out;
#ifdef IR_PARSE_ONLY
	/* Bring-up stage 0: parse the spec and stop. If the kernel survives this and
	 * dies in the full build, the fault is in the base/log/patch steps, not the
	 * parser or the section contents. */
	return -95;
#endif
	rc = ir_resolve_base(&ctx);
	if (rc != IR_OK)
		goto out;
	if (ctx.fn_patch == 0) {
		rc = IR_ERR_NO_FN;
		goto out;
	}

	ir_print_str(&ctx, "maplesu_ir: build=%s blocks=%llu\n", IR_BUILD,
		     (u64)ctx.block_count);
	ir_print(&ctx, "maplesu_ir: base=%llu patch_text=%llu\n", ctx.kbase,
		 ctx.fn_patch);
#ifdef IR_STOP_AFTER_BASE
	/* Bring-up: stop before touching any kernel text. */
	return -95;
#endif

	/* Phase 1: all-or-nothing. Nothing is written until every block matched. */
	rc = ir_verify_original(&ctx);
	if (rc != IR_OK)
		goto out;

#ifdef IR_STOP_AFTER_VERIFY
	/* Bring-up: every original byte matched; stop before patching. */
	(void)ir_print(&ctx, "maplesu_ir: verified blocks=%llu\n",
		       (u64)ctx.block_count, 0);
	return -95;
#endif

	/* Phase 2: apply through the kernel's own text patcher. */
	rc = ir_apply(&ctx);
	if (rc != IR_OK)
		goto out;

	/* Phase 3: read it back; a patch we cannot observe is not a patch. */
	rc = ir_verify_patched(&ctx);
	if (rc != IR_OK)
		goto out;

	ir_print(&ctx, "maplesu_ir: ready blocks=%llu bytes=%llu\n",
		 (u64)ctx.block_count, (u64)ctx.bytes_written);
	return IR_OK;

out:
	ir_print(&ctx, "maplesu_ir: failed rc=%llu blocks=%llu\n", (u64)(unsigned int)(-rc),
		 (u64)ctx.block_count);
	return rc;
}

#endif  /* IR_CANARY */

/* Unloading is optional for the first version (U6): the patches are text and
 * outlive the module, and the reload path re-verifies originals, so a second load
 * in the same boot is refused by phase 1 rather than double-applied. */
__attribute__((section(".exit.text")))
void cleanup_module(void)
{
}
