// SPDX-License-Identifier: GPL-3.0-only
#include "../ultra/identity/kernel/manager_apk_identity.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct fixture {
    const unsigned char *bytes;
    size_t size;
    const unsigned char *certificate;
    size_t certificate_size;
    size_t reads;
    size_t fail_read;
    int fail_hash;
};

static int read_at(void *context, msu_apk_u64 at, void *out, size_t count)
{
    struct fixture *f = context;
    assert(at <= f->size && count <= f->size - at);
    if (++f->reads == f->fail_read)
        return -1;
    memcpy(out, f->bytes + at, count);
    return 0;
}

/* The Python pass independently uses hashlib. This sanitizer pass compares
 * the entire fixture leaf certificate rather than duplicating a hash library. */
static int digest(void *context, const void *bytes, size_t count, msu_apk_u8 out[32])
{
    struct fixture *f = context;
    memset(out, 0, 32);
    if (f->fail_hash)
        return -1;
    if (count == f->certificate_size && !memcmp(bytes, f->certificate, count))
        memset(out, 0xa5, 32);
    return 0;
}

static unsigned char *read_file(const char *path, size_t *length)
{
    FILE *file = fopen(path, "rb");
    unsigned char *bytes;
    long end;
    assert(file && !fseek(file, 0, SEEK_END));
    end = ftell(file);
    assert(end >= 0 && !fseek(file, 0, SEEK_SET));
    *length = (size_t)end;
    bytes = malloc(*length ? *length : 1);
    assert(bytes && fread(bytes, 1, *length, file) == *length);
    assert(!fclose(file));
    return bytes;
}

int main(int argc, char **argv)
{
    FILE *manifest;
    char filename[256], path[512];
    unsigned int expected, tests = 0;
    size_t certificate_size;
    unsigned char *certificate;
    struct msu_manager_apk_pin pin = {0};
    assert(argc == 4);
    certificate = read_file(argv[1], &certificate_size);
    assert(certificate_size > 0 && certificate_size <= 1024);
    pin.certificate_size = (msu_apk_u32)certificate_size;
    memset(pin.certificate_sha256, 0xa5, sizeof(pin.certificate_sha256));
    pin.minimum_generation = 2;
    manifest = fopen(argv[2], "r");
    assert(manifest);
    while (fscanf(manifest, "%255s %u", filename, &expected) == 2) {
        struct fixture f = {0};
        struct msu_apk_source source = {0};
        msu_apk_u32 generation = 123;
        unsigned char *bytes;
        int result;
        assert(snprintf(path, sizeof(path), "%s/%s", argv[3], filename) > 0);
        bytes = read_file(path, &f.size);
        f.bytes = bytes;
        f.certificate = certificate;
        f.certificate_size = certificate_size;
        source.context = &f;
        source.length = f.size;
        source.read_at = read_at;
        source.sha256 = digest;
        result = msu_manager_apk_identity(&source, &pin, &generation);
        if ((result ? generation : 0) != expected || (!result && generation)) {
            fprintf(stderr, "%s expected=%u actual=%u result=%d\n", filename, expected, generation, result);
            abort();
        }
        ++tests;
        if (expected) {
            size_t count = f.reads, i;
            f.fail_hash = 1;
            assert(!msu_manager_apk_identity(&source, &pin, &generation) && !generation);
            f.fail_hash = 0;
            ++tests;
            /* Exhaustive read interruption for small structural fixtures. */
            if (f.size < 4096) {
                for (i = 1; i <= count; ++i) {
                    f.reads = 0;
                    f.fail_read = i;
                    assert(!msu_manager_apk_identity(&source, &pin, &generation) && !generation);
                    ++tests;
                }
            }
        }
        free(bytes);
    }
    assert(feof(manifest) && !fclose(manifest));
    assert(!msu_manager_apk_identity(NULL, &pin, NULL));
    free(certificate);
    printf("native parser assertions: %u\n", tests);
    return 0;
}
