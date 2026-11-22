/*
 * MSK1 content digest (SHA-256), freestanding.
 *
 * Used for two identities only:
 *   - a binding digest, so one attempt is tied to one exact spec;
 *   - a plan digest, so one carrier is tied to one ordered hop plan.
 *
 * This is a content digest, NOT a signature and NOT an authenticator: there is
 * no key material here and none may be added (design R-1/R-2 forbid porting the
 * reference implementation's authorisation key). It answers "are these the same
 * bytes", never "did an authority bless these bytes".
 *
 * No libc: no allocation, no stdio, no clock. Safe for a freestanding target.
 */
#ifndef MSK_DIGEST_H
#define MSK_DIGEST_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define MSK_DIGEST_BYTES 32
#define MSK_SHA256_BLOCK_BYTES 64

struct msk_sha256 {
	uint32_t state[8];
	uint64_t total_bytes;
	uint8_t block[MSK_SHA256_BLOCK_BYTES];
	size_t used;
};

void msk_sha256_init(struct msk_sha256 *context);
void msk_sha256_update(struct msk_sha256 *context, const void *data, size_t length);
void msk_sha256_final(struct msk_sha256 *context, uint8_t out[MSK_DIGEST_BYTES]);

/* One-shot helper; equivalent to init/update/final. */
void msk_sha256(const void *data, size_t length, uint8_t out[MSK_DIGEST_BYTES]);

#ifdef __cplusplus
}
#endif
#endif /* MSK_DIGEST_H */
