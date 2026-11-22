// SPDX-License-Identifier: GPL-3.0-only
#include <linux/types.h>

#define MSU_PRIVATE __attribute__((visibility("hidden")))
MSU_PRIVATE void *memcpy(void *destination, const void *source, size_t count);
MSU_PRIVATE void *memset(void *destination, int value, size_t count);
MSU_PRIVATE int memcmp(const void *left, const void *right, size_t count);
MSU_PRIVATE int bcmp(const void *left, const void *right, size_t count);
MSU_PRIVATE size_t strlen(const char *text);
MSU_PRIVATE size_t strnlen(const char *text, size_t limit);
MSU_PRIVATE int strcmp(const char *left, const char *right);
MSU_PRIVATE int strncmp(const char *left, const char *right, size_t count);

/* Volatile byte accesses prevent these bodies becoming recursive libcalls. */
MSU_PRIVATE void *memcpy(void *destination, const void *source, size_t count)
{
    volatile unsigned char *to = destination;
    const volatile unsigned char *from = source;
    while (count--) *to++ = *from++;
    return destination;
}

MSU_PRIVATE void *memset(void *destination, int value, size_t count)
{
    volatile unsigned char *to = destination;
    while (count--) *to++ = (unsigned char)value;
    return destination;
}

MSU_PRIVATE int memcmp(const void *left, const void *right, size_t count)
{
    const volatile unsigned char *a = left, *b = right;
    while (count--) {
        unsigned char x = *a++, y = *b++;
        if (x != y) return (int)x - (int)y;
    }
    return 0;
}

MSU_PRIVATE int bcmp(const void *left, const void *right, size_t count)
{
    return memcmp(left, right, count);
}

MSU_PRIVATE size_t strlen(const char *text)
{
    const volatile unsigned char *bytes = (const void *)text;
    size_t length = 0;
    while (bytes[length]) ++length;
    return length;
}

MSU_PRIVATE size_t strnlen(const char *text, size_t limit)
{
    const volatile unsigned char *bytes = (const void *)text;
    size_t length = 0;
    while (length < limit && bytes[length]) ++length;
    return length;
}

MSU_PRIVATE int strcmp(const char *left, const char *right)
{
    const volatile unsigned char *a = (const void *)left, *b = (const void *)right;
    for (;;) {
        unsigned char x = *a++, y = *b++;
        if (x != y || !x) return (int)x - (int)y;
    }
}

MSU_PRIVATE int strncmp(const char *left, const char *right, size_t count)
{
    const volatile unsigned char *a = (const void *)left, *b = (const void *)right;
    while (count--) {
        unsigned char x = *a++, y = *b++;
        if (x != y || !x) return (int)x - (int)y;
    }
    return 0;
}
