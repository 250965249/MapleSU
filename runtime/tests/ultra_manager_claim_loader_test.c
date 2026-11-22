// SPDX-License-Identifier: GPL-3.0-only
#include "../ultra/identity/kernel/manager_claim_loader.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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

static void check_filled(const unsigned char *bytes, size_t length, unsigned char value)
{
    size_t i;

    for (i = 0; i < length; i++)
        assert(bytes[i] == value);
}

static void compact_replay(const char *manifest_path)
{
    FILE *manifest;
    char path[1024];
    struct msu_loader_binding binding;
    unsigned int capacity, mode, import_offset, tests = 0;
    int expected;

    manifest = fopen(manifest_path, "r");
    assert(manifest);
    while (fscanf(manifest, "%1023s %u %u %u %u %u %u %u %d %u %u", path,
                  &binding.image_bytes, &binding.descriptor_offset, &binding.descriptor_bytes,
                  &binding.descriptor_crc, &binding.loader_offset, &binding.loader_bytes,
                  &capacity, &expected, &mode, &import_offset) == 11) {
        size_t length;
        unsigned char *image = read_file(path, &length);
        unsigned char *destination = malloc((size_t)capacity + 128);
        unsigned char *target;
        unsigned char *original;
        int result;

        assert(destination && length == binding.image_bytes);
        memset(destination, 0xa5, (size_t)capacity + 128);
        target = destination + 64;
        original = malloc(length);
        assert(original);
        memcpy(original, image, length);
        if (mode == 2) {
            assert(length >= 64 + capacity);
            target = image + 64;
        }
        result = msu_manager_claim_materialize(&binding, image, target, capacity);
        if (result != expected) {
            fprintf(stderr, "%s expected=%d actual=%d\n", path, expected, result);
            abort();
        }
        check_filled(destination, 64, 0xa5);
        check_filled(destination + 64 + capacity, 64, 0xa5);
        if (result < 0)
            check_filled(destination, (size_t)capacity + 128, 0xa5);
        assert(!memcmp(original, image, length));
        if (mode == 1) {
            static const unsigned char text[8] = {0xc0,0x03,0x5f,0xd6,0x1f,0x20,0x03,0xd5};
            msu_loader_u64 relative, imported;

            assert(result == 1 && capacity == 48 && !memcmp(target, text, sizeof(text)));
            check_filled(target + 8, 8, 0);
            memcpy(&relative, target + 16, sizeof(relative));
            memcpy(&imported, target + 24, sizeof(imported));
            assert(relative == (msu_loader_uptr)target);
            assert(imported == (msu_loader_uptr)image + import_offset);
            check_filled(target + 32, 16, 0);
        }
        free(original);
        free(destination);
        free(image);
        tests++;
    }
    assert(feof(manifest) && !fclose(manifest));
    printf("manager claim materializer sanitizer replay: %u cases passed\n", tests);
}

static void full_replay(const char *manifest_path, const char *image_root, const char *carrier_root)
{
    FILE *manifest = fopen(manifest_path, "r");
    unsigned int index, capacity, count = 0;
    int expected_result;
    struct msu_loader_binding binding;
    assert(manifest);
    while (fscanf(manifest, "%u%u%u%u%u%u%u%u%d", &index, &binding.image_bytes,
                  &binding.descriptor_offset, &binding.descriptor_bytes, &binding.descriptor_crc,
                  &binding.loader_offset, &binding.loader_bytes, &capacity, &expected_result) == 9) {
        char path[256], role[64];
        size_t image_bytes, patch_bytes, expected_bytes, cursor = 0;
        unsigned int at, length, kind, value, i;
        FILE *writes, *relocs;
        unsigned char *image, *patches, *expected, *destination, *target, *before;
        snprintf(path, sizeof(path), "%s/image-%u/Image", image_root, index);
        image = read_file(path, &image_bytes);
        assert(image_bytes == binding.image_bytes);
        snprintf(path, sizeof(path), "%s/image-%u/resolver-carrier-patches.bin", carrier_root, index);
        patches = read_file(path, &patch_bytes);
        snprintf(path, sizeof(path), "%s/image-%u/resolver-carrier-writes.tsv", carrier_root, index);
        writes = fopen(path, "r");
        assert(writes);
        while (fscanf(writes, "%u%u%63s", &at, &length, role) == 3) {
            assert(at <= image_bytes && length <= image_bytes - at);
            assert(cursor <= patch_bytes && length <= patch_bytes - cursor);
            memcpy(image + at, patches + cursor, length);
            cursor += length;
        }
        assert(feof(writes) && !fclose(writes) && cursor == patch_bytes);
        before = malloc(image_bytes);
        destination = malloc((size_t)capacity + 128);
        assert(before && destination);
        memcpy(before, image, image_bytes);
        memset(destination, 0xa5, (size_t)capacity + 128);
        target = destination + 64;
        assert(msu_manager_claim_materialize(&binding, image, target, capacity) == expected_result);
        assert(!memcmp(before, image, image_bytes));
        for (i = 0; i < 64; i++)
            assert(destination[i] == 0xa5 && target[capacity + i] == 0xa5);
        snprintf(path, sizeof(path), "%s/image-%u/resolver-expected.bin", carrier_root, index);
        expected = read_file(path, &expected_bytes);
        assert(expected_bytes == capacity);
        snprintf(path, sizeof(path), "%s/image-%u/resolver-relocations.tsv", carrier_root, index);
        relocs = fopen(path, "r");
        assert(relocs);
        while (fscanf(relocs, "%u%u%u", &at, &kind, &value) == 3) {
            msu_loader_u64 pointer;
            assert(at <= capacity && 8 <= capacity - at && (kind == 1 || kind == 2));
            if (kind == 1) {
                pointer = (msu_loader_uptr)target + value;
            } else {
                const struct msu_loader_header *h = (const void *)(image + binding.descriptor_offset);
                const msu_loader_u32 *imports = (const void *)(image + binding.descriptor_offset +
                    sizeof(*h) + h->section_count * sizeof(struct msu_loader_section));
                assert(value < h->import_count);
                pointer = (msu_loader_uptr)image + imports[value];
            }
            memcpy(expected + at, &pointer, 8);
        }
        assert(feof(relocs) && !fclose(relocs) && !memcmp(target, expected, capacity));
        free(expected);
        free(destination);
        free(before);
        free(patches);
        free(image);
        count++;
    }
    assert(feof(manifest) && !fclose(manifest) && count == 17);
    printf("ASan/UBSan full-resolver v2 replay: %u carriers, all output bytes and relocations checked\n", count);
}

int main(int argc, char **argv)
{
    if (argc == 2) {
        compact_replay(argv[1]);
    } else {
        assert(argc == 5 && !strcmp(argv[1], "--full"));
        full_replay(argv[2], argv[3], argv[4]);
    }
    return 0;
}
