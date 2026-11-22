// SPDX-License-Identifier: GPL-3.0-only
#include "manager_apk_identity.h"

#define MSU_APK_V2 0x7109871aU
#define MSU_APK_V3 0xf05368c0U
#define MSU_APK_V31 0x1b93ad61U
#define MSU_APK_PADDING 0x42726577U
#define MSU_APK_STRIPPING_PROTECTION 0xbeeff00dU
#define MSU_APK_CERT_LIMIT 1024U
#define MSU_APK_NAME_LIMIT 512U

struct msu_apk_directory {
    msu_apk_u64 offset;
    msu_apk_u64 end;
    msu_apk_u32 count;
};

static msu_apk_u32 msu_le16(const msu_apk_u8 *p)
{
    return (msu_apk_u32)p[0] | (msu_apk_u32)p[1] << 8;
}

static msu_apk_u32 msu_le32(const msu_apk_u8 *p)
{
    return msu_le16(p) | msu_le16(p + 2) << 16;
}

static msu_apk_u64 msu_le64(const msu_apk_u8 *p)
{
    return (msu_apk_u64)msu_le32(p) | (msu_apk_u64)msu_le32(p + 4) << 32;
}

static int msu_equal(const msu_apk_u8 *a, const msu_apk_u8 *b, size_t count)
{
    msu_apk_u8 difference = 0;
    size_t i;
    for (i = 0; i < count; ++i)
        difference |= a[i] ^ b[i];
    return difference == 0;
}

static int msu_read(const struct msu_apk_source *s, msu_apk_u64 at,
                    void *out, size_t count, msu_apk_u64 end)
{
    return end <= s->length && at <= end && count <= end - at &&
           s->read_at(s->context, at, out, count) == 0;
}

static int msu_length(const struct msu_apk_source *s, msu_apk_u64 *at,
                      msu_apk_u64 end, msu_apk_u64 *value_end)
{
    msu_apk_u8 bytes[4];
    msu_apk_u32 length;
    if (!msu_read(s, *at, bytes, sizeof(bytes), end))
        return 0;
    *at += sizeof(bytes);
    length = msu_le32(bytes);
    if (length > 0x7fffffffU || length > end - *at)
        return 0;
    *value_end = *at + length;
    return 1;
}

static int msu_directory(const struct msu_apk_source *s, struct msu_apk_directory *cd)
{
    msu_apk_u8 tail[512];
    msu_apk_u8 locator[4];
    msu_apk_u64 lower, window_end;
    if (s->length < 22 || s->length > 0xffffffffU)
        return 0;
    lower = s->length > 65557 ? s->length - 65557 : 0;
    window_end = s->length;
    for (;;) {
        msu_apk_u64 start = window_end - lower > sizeof(tail) ?
                            window_end - sizeof(tail) : lower;
        size_t count = (size_t)(window_end - start);
        size_t i;
        if (!msu_read(s, start, tail, count, s->length))
            return 0;
        for (i = count - 21; i > 0; --i) {
            const msu_apk_u8 *e = tail + i - 1;
            msu_apk_u64 at = start + i - 1;
            if (msu_le32(e) != 0x06054b50U || msu_le16(e + 20) != s->length - at - 22)
                continue;
            if (msu_le16(e + 4) || msu_le16(e + 6) ||
                msu_le16(e + 8) != msu_le16(e + 10) ||
                !msu_le16(e + 10) || msu_le16(e + 10) == 0xffffU)
                return 0;
            cd->offset = msu_le32(e + 16);
            cd->end = at;
            cd->count = msu_le16(e + 10);
            if (cd->offset < 32 || cd->offset > at || msu_le32(e + 12) != at - cd->offset)
                return 0;
            if (at >= 20 && (!msu_read(s, at - 20, locator, sizeof(locator), at) ||
                             msu_le32(locator) == 0x07064b50U))
                return 0;
            return 1;
        }
        if (start == lower)
            return 0;
        window_end = start + 21;
    }
}

/* Both digest and signature sequences contain algorithm + length-prefixed
 * bytes. Their cryptographic validity belongs to Android's install verifier. */
static int msu_algorithm_records(const struct msu_apk_source *s,
                                 msu_apk_u64 start, msu_apk_u64 end)
{
    unsigned int count = 0;
    while (start < end) {
        msu_apk_u64 record_end, value_end;
        msu_apk_u8 algorithm[4];
        if (!msu_length(s, &start, end, &record_end) ||
            !msu_read(s, start, algorithm, sizeof(algorithm), record_end))
            return 0;
        start += sizeof(algorithm);
        if (!msu_le32(algorithm) || !msu_length(s, &start, record_end, &value_end) ||
            value_end == start || value_end != record_end)
            return 0;
        start = record_end;
        ++count;
    }
    return count != 0 && start == end;
}

static __attribute__((__noinline__)) int msu_signer(const struct msu_apk_source *s, msu_apk_u64 at,
                      msu_apk_u64 end, const struct msu_manager_apk_pin *pin,
                      unsigned int scheme, int installed, int *matches)
{
    msu_apk_u64 signers_end, signer_end, data_end, digests_end, certs_end;
    msu_apk_u64 cert_end, attrs_end, signatures_at, signatures_end, public_key_end;
    msu_apk_u8 certificate[MSU_APK_CERT_LIMIT];
    msu_apk_u8 digest[32], sdk[8], outer_sdk[8];
    msu_apk_u64 certificate_size;
    *matches = 0;
    if (!msu_length(s, &at, end, &signers_end) || signers_end != end ||
        !msu_length(s, &at, signers_end, &signer_end) || signer_end != signers_end ||
        !msu_length(s, &at, signer_end, &data_end))
        return 0;
    signatures_at = data_end;
    if (!msu_length(s, &at, data_end, &digests_end) ||
        !msu_algorithm_records(s, at, digests_end))
        return 0;
    at = digests_end;
    if (!msu_length(s, &at, data_end, &certs_end) ||
        !msu_length(s, &at, certs_end, &cert_end))
        return 0;
    certificate_size = cert_end - at;
    if (!certificate_size || certificate_size > sizeof(certificate) ||
        !msu_read(s, at, certificate, (size_t)certificate_size, cert_end) ||
        s->sha256(s->context, certificate, (size_t)certificate_size, digest)) return 0;
    *matches = certificate_size == pin->certificate_size &&
        msu_equal(digest, pin->certificate_sha256, sizeof(digest));
    /* Extra certificates form the same signer's chain, not extra signers. */
    at = cert_end;
    while (at < certs_end) {
        if (!msu_length(s, &at, certs_end, &cert_end) || cert_end == at)
            return 0;
        at = cert_end;
    }
    if (scheme >= 3) {
        if (!msu_read(s, at, sdk, sizeof(sdk), data_end) ||
            msu_le32(sdk) > msu_le32(sdk + 4) ||
            !msu_read(s, signatures_at, outer_sdk, sizeof(outer_sdk), signer_end) ||
            !msu_equal(sdk, outer_sdk, sizeof(sdk))) return 0;
        at += sizeof(sdk); signatures_at += sizeof(sdk);
    }
    if (!msu_length(s, &at, data_end, &attrs_end))
        return 0;
    while (at < attrs_end) {
        msu_apk_u64 attr_end;
        msu_apk_u8 attribute[4];
        if (!msu_length(s, &at, attrs_end, &attr_end) ||
            !msu_read(s, at, attribute, sizeof(attribute), attr_end))
            return 0;
        if (scheme == 2 && msu_le32(attribute) == MSU_APK_STRIPPING_PROTECTION &&
            (!msu_read(s, at + 4, attribute, sizeof(attribute), attr_end) ||
             (!installed && msu_le32(attribute) == 3)))
            return 0;
        at = attr_end;
    }
    /* AOSP's v2 signer emits an additional empty length-prefixed field.
     * Accept the documented three fields and that exact emitted form. */
    if (at < data_end) {
        msu_apk_u64 reserved_end;
        if (scheme != 2) return 0;
        if (!msu_length(s, &at, data_end, &reserved_end) ||
            reserved_end != at || at != data_end)
            return 0;
    }
    at = signatures_at;
    if (!msu_length(s, &at, signer_end, &signatures_end) ||
        !msu_algorithm_records(s, at, signatures_end))
        return 0;
    at = signatures_end;
    return msu_length(s, &at, signer_end, &public_key_end) &&
           public_key_end > at && public_key_end == signer_end;
}

static int msu_signing_block(const struct msu_apk_source *s,
                             const struct msu_apk_directory *cd,
                             const struct msu_manager_apk_pin *pin,
                             msu_apk_u64 *block_start, int installed)
{
    static const msu_apk_u8 magic[16] = "APK Sig Block 42";
    msu_apk_u8 footer[24], bytes[12];
    msu_apk_u64 length, at, pairs_end;
    unsigned int signers = 0, v2 = 0, v3 = 0, v31 = 0;
    if (!msu_read(s, cd->offset - 24, footer, sizeof(footer), cd->offset) ||
        !msu_equal(footer + 8, magic, sizeof(magic)))
        return 0;
    length = msu_le64(footer);
    if (length < 24 || length > 0x7fffffffU || length > cd->offset - 8)
        return 0;
    *block_start = cd->offset - length - 8;
    if (!msu_read(s, *block_start, bytes, 8, cd->offset) || msu_le64(bytes) != length)
        return 0;
    at = *block_start + 8;
    pairs_end = cd->offset - 24;
    while (at < pairs_end) {
        msu_apk_u64 pair_end;
        msu_apk_u32 id;
        if (!msu_read(s, at, bytes, 12, pairs_end))
            return 0;
        length = msu_le64(bytes);
        at += 8;
        if (length < 4 || length > 0x7fffffffU || length > pairs_end - at)
            return 0;
        pair_end = at + length;
        id = msu_le32(bytes + 8);
        if (id == MSU_APK_V2 || (installed && (id == MSU_APK_V3 || id == MSU_APK_V31))) {
            int matches;
            unsigned int scheme = id == MSU_APK_V2 ? 2 : 3;
            unsigned int *seen = id == MSU_APK_V2 ? &v2 : id == MSU_APK_V3 ? &v3 : &v31;
            if (++*seen != 1 || !msu_signer(s, at + 4, pair_end, pin, scheme, installed, &matches))
                return 0;
            signers += (unsigned int)matches;
        } else if (id != MSU_APK_PADDING) {
            return 0;
        }
        at = pair_end;
    }
    /* Installed PM current signer must occur in at least one scheme. V2/V3
     * may repeat it; the protected PM record rules out multiple actual signers. */
    return at == pairs_end && signers >= 1 && (installed || signers == 1);
}

static msu_apk_u32 msu_generation(const msu_apk_u8 *name, size_t length)
{
    static const msu_apk_u8 prefix[] = "assets/ksu_manager_gen";
    const size_t prefix_length = sizeof(prefix) - 1;
    msu_apk_u32 value = 0;
    size_t i;
    if (length <= prefix_length || !msu_equal(name, prefix, prefix_length))
        return 0;
    for (i = prefix_length; i < length; ++i) {
        if (name[i] < '0' || name[i] > '9' || value > 100000U)
            return 0;
        value = value * 10 + name[i] - '0';
    }
    return value <= 1000000U ? value : 0;
}

static int msu_generation_entry(const struct msu_apk_source *s, const msu_apk_u8 *cd,
                                const msu_apk_u8 *name, size_t name_length,
                                msu_apk_u64 block_start)
{
    msu_apk_u8 header[30], local_name[MSU_APK_NAME_LIMIT];
    msu_apk_u64 offset = msu_le32(cd + 42), data;
    if (!msu_read(s, offset, header, sizeof(header), block_start) ||
        msu_le32(header) != 0x04034b50U || msu_le16(header + 26) != name_length ||
        msu_le16(header + 6) != msu_le16(cd + 8) ||
        msu_le16(header + 8) != msu_le16(cd + 10))
        return 0;
    offset += sizeof(header);
    if (!msu_read(s, offset, local_name, name_length, block_start) ||
        !msu_equal(name, local_name, name_length))
        return 0;
    data = offset + name_length + msu_le16(header + 28);
    return data <= block_start && msu_le32(cd + 20) <= block_start - data;
}

struct msu_apk_directory_window {
    msu_apk_u64 offset;
    size_t length;
    msu_apk_u8 bytes[MSU_APK_NAME_LIMIT];
};

static int msu_directory_read(const struct msu_apk_source *s,
    struct msu_apk_directory_window *window, msu_apk_u64 at,
    void *out, size_t count, msu_apk_u64 end)
{
    size_t i;
    if (end > s->length || at > end || count > end - at ||
        count > sizeof(window->bytes))
        return 0;
    if (at < window->offset || at - window->offset > window->length ||
        count > window->length - (size_t)(at - window->offset)) {
        size_t available = (size_t)(end - at);
        if (available > sizeof(window->bytes))
            available = sizeof(window->bytes);
        window->length = 0;
        if (!msu_read(s, at, window->bytes, available, end))
            return 0;
        window->offset = at;
        window->length = available;
    }
    for (i = 0; i < count; ++i)
        ((msu_apk_u8 *)out)[i] = window->bytes[(size_t)(at - window->offset) + i];
    return 1;
}

static __attribute__((__noinline__)) int msu_scan_generation(const struct msu_apk_source *s,
                               const struct msu_apk_directory *cd,
                               msu_apk_u64 block_start, msu_apk_u32 *generation)
{
    msu_apk_u64 at = cd->offset;
    msu_apk_u32 index, found = 0;
    struct msu_apk_directory_window window;
    window.offset = 0;
    window.length = 0;
    for (index = 0; index < cd->count; ++index) {
        msu_apk_u8 header[46], name[MSU_APK_NAME_LIMIT];
        msu_apk_u32 name_length, value;
        msu_apk_u64 extra;
        if (!msu_directory_read(s, &window, at, header, sizeof(header), cd->end) ||
            msu_le32(header) != 0x02014b50U || msu_le16(header + 34) ||
            msu_le32(header + 20) == 0xffffffffU || msu_le32(header + 24) == 0xffffffffU ||
            msu_le32(header + 42) >= block_start)
            return 0;
        at += sizeof(header);
        name_length = msu_le16(header + 28);
        if (!name_length || name_length > sizeof(name) ||
            !msu_directory_read(s, &window, at, name, name_length, cd->end))
            return 0;
        at += name_length;
        extra = (msu_apk_u64)msu_le16(header + 30) + msu_le16(header + 32);
        if (extra > cd->end - at)
            return 0;
        at += extra;
        value = msu_generation(name, name_length);
        if (value) {
            if (found || !msu_generation_entry(s, header, name, name_length, block_start))
                return 0;
            found = value;
        }
    }
    if (at != cd->end || !found)
        return 0;
    *generation = found;
    return 1;
}

static int msu_apk_identity(const struct msu_apk_source *source,
                             const struct msu_manager_apk_pin *pin,
                             msu_apk_u32 *generation, int installed)
{
    struct msu_apk_directory directory;
    msu_apk_u64 block_start;
    msu_apk_u32 found;
    if (generation)
        *generation = 0;
    if (!source || !pin || !generation || !source->read_at || !source->sha256 ||
        !pin->certificate_size || pin->certificate_size > MSU_APK_CERT_LIMIT ||
        !pin->minimum_generation ||
        !msu_directory(source, &directory) ||
        !msu_signing_block(source, &directory, pin, &block_start, installed) ||
        !msu_scan_generation(source, &directory, block_start, &found) ||
        found < pin->minimum_generation)
        return 0;
    *generation = found;
    return 1;
}

int msu_manager_apk_identity(const struct msu_apk_source *source,
    const struct msu_manager_apk_pin *pin, msu_apk_u32 *generation)
{ return msu_apk_identity(source, pin, generation, 0); }

int msu_manager_installed_apk_identity(const struct msu_apk_source *source,
    const struct msu_manager_apk_pin *verified_current, msu_apk_u32 *generation)
{ return msu_apk_identity(source, verified_current, generation, 1); }
