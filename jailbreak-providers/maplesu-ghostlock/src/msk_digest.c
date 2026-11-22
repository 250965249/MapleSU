/*
 * SHA-256 (FIPS 180-4), freestanding, no libc.
 *
 * Kept in its own translation unit so the spec binding digest and the plan
 * digest cannot drift into two different constructs.
 */
#include "msk_digest.h"

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

static uint32_t msk_rotr(uint32_t value, unsigned int count)
{
	return (value >> count) | (value << (32U - count));
}

static uint32_t msk_load_be32(const uint8_t *bytes)
{
	return ((uint32_t)bytes[0] << 24) | ((uint32_t)bytes[1] << 16) |
	       ((uint32_t)bytes[2] << 8) | (uint32_t)bytes[3];
}

static void msk_store_be32(uint8_t *bytes, uint32_t value)
{
	bytes[0] = (uint8_t)(value >> 24);
	bytes[1] = (uint8_t)(value >> 16);
	bytes[2] = (uint8_t)(value >> 8);
	bytes[3] = (uint8_t)value;
}

static void msk_store_be64(uint8_t *bytes, uint64_t value)
{
	bytes[0] = (uint8_t)(value >> 56);
	bytes[1] = (uint8_t)(value >> 48);
	bytes[2] = (uint8_t)(value >> 40);
	bytes[3] = (uint8_t)(value >> 32);
	bytes[4] = (uint8_t)(value >> 24);
	bytes[5] = (uint8_t)(value >> 16);
	bytes[6] = (uint8_t)(value >> 8);
	bytes[7] = (uint8_t)value;
}

static const uint32_t MSK_SHA256_K[64] = {
	0x428a2f98U, 0x71374491U, 0xb5c0fbcfU, 0xe9b5dba5U,
	0x3956c25bU, 0x59f111f1U, 0x923f82a4U, 0xab1c5ed5U,
	0xd807aa98U, 0x12835b01U, 0x243185beU, 0x550c7dc3U,
	0x72be5d74U, 0x80deb1feU, 0x9bdc06a7U, 0xc19bf174U,
	0xe49b69c1U, 0xefbe4786U, 0x0fc19dc6U, 0x240ca1ccU,
	0x2de92c6fU, 0x4a7484aaU, 0x5cb0a9dcU, 0x76f988daU,
	0x983e5152U, 0xa831c66dU, 0xb00327c8U, 0xbf597fc7U,
	0xc6e00bf3U, 0xd5a79147U, 0x06ca6351U, 0x14292967U,
	0x27b70a85U, 0x2e1b2138U, 0x4d2c6dfcU, 0x53380d13U,
	0x650a7354U, 0x766a0abbU, 0x81c2c92eU, 0x92722c85U,
	0xa2bfe8a1U, 0xa81a664bU, 0xc24b8b70U, 0xc76c51a3U,
	0xd192e819U, 0xd6990624U, 0xf40e3585U, 0x106aa070U,
	0x19a4c116U, 0x1e376c08U, 0x2748774cU, 0x34b0bcb5U,
	0x391c0cb3U, 0x4ed8aa4aU, 0x5b9cca4fU, 0x682e6ff3U,
	0x748f82eeU, 0x78a5636fU, 0x84c87814U, 0x8cc70208U,
	0x90befffaU, 0xa4506cebU, 0xbef9a3f7U, 0xc67178f2U
};

static void msk_sha256_transform(struct msk_sha256 *context, const uint8_t block[64])
{
	uint32_t schedule[64];
	uint32_t a, b, c, d, e, f, g, h;
	size_t index;

	for (index = 0; index < 16; ++index)
		schedule[index] = msk_load_be32(block + index * 4U);
	for (index = 16; index < 64; ++index) {
		uint32_t s0 = msk_rotr(schedule[index - 15], 7) ^
			      msk_rotr(schedule[index - 15], 18) ^
			      (schedule[index - 15] >> 3);
		uint32_t s1 = msk_rotr(schedule[index - 2], 17) ^
			      msk_rotr(schedule[index - 2], 19) ^
			      (schedule[index - 2] >> 10);

		schedule[index] = schedule[index - 16] + s0 +
				  schedule[index - 7] + s1;
	}

	a = context->state[0];
	b = context->state[1];
	c = context->state[2];
	d = context->state[3];
	e = context->state[4];
	f = context->state[5];
	g = context->state[6];
	h = context->state[7];

	for (index = 0; index < 64; ++index) {
		uint32_t s1 = msk_rotr(e, 6) ^ msk_rotr(e, 11) ^ msk_rotr(e, 25);
		uint32_t choice = (e & f) ^ ((~e) & g);
		uint32_t temp1 = h + s1 + choice + MSK_SHA256_K[index] + schedule[index];
		uint32_t s0 = msk_rotr(a, 2) ^ msk_rotr(a, 13) ^ msk_rotr(a, 22);
		uint32_t majority = (a & b) ^ (a & c) ^ (b & c);
		uint32_t temp2 = s0 + majority;

		h = g;
		g = f;
		f = e;
		e = d + temp1;
		d = c;
		c = b;
		b = a;
		a = temp1 + temp2;
	}

	context->state[0] += a;
	context->state[1] += b;
	context->state[2] += c;
	context->state[3] += d;
	context->state[4] += e;
	context->state[5] += f;
	context->state[6] += g;
	context->state[7] += h;
}

void msk_sha256_init(struct msk_sha256 *context)
{
	static const uint32_t initial[8] = {
		0x6a09e667U, 0xbb67ae85U, 0x3c6ef372U, 0xa54ff53aU,
		0x510e527fU, 0x9b05688cU, 0x1f83d9abU, 0x5be0cd19U
	};
	size_t index;

	if (context == 0)
		return;
	for (index = 0; index < 8; ++index)
		context->state[index] = initial[index];
	context->total_bytes = 0;
	context->used = 0;
	msk_zero(context->block, sizeof(context->block));
}

void msk_sha256_update(struct msk_sha256 *context, const void *data, size_t length)
{
	const unsigned char *bytes = (const unsigned char *)data;

	if (context == 0)
		return;
	if (length == 0)
		return;
	if (bytes == 0)
		return;

	context->total_bytes += (uint64_t)length;

	if (context->used > 0) {
		size_t room = MSK_SHA256_BLOCK_BYTES - context->used;
		size_t take = length < room ? length : room;

		msk_copy(context->block + context->used, bytes, take);
		context->used += take;
		bytes += take;
		length -= take;
		if (context->used == MSK_SHA256_BLOCK_BYTES) {
			msk_sha256_transform(context, context->block);
			context->used = 0;
		}
	}

	while (length >= MSK_SHA256_BLOCK_BYTES) {
		msk_sha256_transform(context, bytes);
		bytes += MSK_SHA256_BLOCK_BYTES;
		length -= MSK_SHA256_BLOCK_BYTES;
	}

	if (length > 0) {
		msk_copy(context->block, bytes, length);
		context->used = length;
	}
}

void msk_sha256_final(struct msk_sha256 *context, uint8_t out[MSK_DIGEST_BYTES])
{
	uint64_t bits;
	size_t index;

	if (context == 0 || out == 0)
		return;

	bits = context->total_bytes * 8U;
	context->block[context->used] = 0x80U;
	context->used += 1;
	if (context->used > 56U) {
		msk_zero(context->block + context->used, MSK_SHA256_BLOCK_BYTES - context->used);
		msk_sha256_transform(context, context->block);
		context->used = 0;
	}
	msk_zero(context->block + context->used, 56U - context->used);
	msk_store_be64(context->block + 56, bits);
	msk_sha256_transform(context, context->block);

	for (index = 0; index < 8; ++index)
		msk_store_be32(out + index * 4U, context->state[index]);
	msk_zero(context, sizeof(*context));
}

void msk_sha256(const void *data, size_t length, uint8_t out[MSK_DIGEST_BYTES])
{
	struct msk_sha256 context;

	msk_sha256_init(&context);
	msk_sha256_update(&context, data, length);
	msk_sha256_final(&context, out);
}
